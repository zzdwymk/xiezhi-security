# 轻量证据驱动 Agentic RAG + Bounded ReAct + Security Harness 实施待办

> 生成日期：2026-08-07  
> 适用项目：`ai-runtime` + `security-toolbox-server`  
> 目标定位：在不改变 Planner + Harness 总体架构的前提下，将当前“项目检索 + 引用”升级为可验证、可终止、可评估的轻量 Agentic RAG。  
> 明确排除：Subagent、多智能体协作、完整 GraphRAG、图数据库、无限自主循环。

> 完成状态：2026-08-07 已完成 P0/P1、MVP 与 Definition of Done。最终验证为 Python `123 passed`、Java `418 tests / 0 failures / 0 errors / 4 skipped`、真实 Java-Python-mock LLM E2E `4 passed`；仅第 10 节两个 P2 未来工作项保留未勾选。实施详情见 `AGENTIC_RAG_HARNESS_IMPLEMENTATION_SUMMARY.md`。

## 0. 最新代码适配说明

本文以 **2026-08-07 当前工作区的 Planner + Harness 安全整改版本** 为当前状态。当前版本已经完成的授权、协议、记忆和 E2E 工作不会再次列为“待修复漏洞”。

当前已完成并应保持的最新改动包括：

- [x] 旧 AI dispatch 旁路已关闭，原 `AiDispatchStreamingService` 已删除。
- [x] AI 副作用任务统一进入 Java `SecurityAgentTools.executeAuthorizedPlan`。
- [x] Java 已实现事务内授权、悲观锁配额、Turn 幂等、批次回滚和 after-commit 调度。
- [x] Python Planner 已使用严格判别联合 Schema，混合非法计划和格式异常均安全停止。
- [x] Runtime bearer token 已改为 fail-closed，并与项目级 HMAC 签名密钥分离。
- [x] conversation memory 已持久化，并绑定 project、target、conversation、TTL/LRU 和 tombstone。
- [x] Runtime 已传播 `runId`、`stateVersion`、`policyRevision` 和 action digest。
- [x] CI 已包含 mock OpenAI + Python LangGraph + Java Harness 的真实跨语言 job。
- [x] 当前索引内部已经生成文档 `id`，项目文档持久化已经计算整体 `sha256` 摘要。
- [x] Java v2 已绑定 route intent、plan intent、knowledge mode、actions 和 Evidence 闭包，矛盾终态 fail-closed。
- [x] Runtime 中间事件采用最多 64 条的整流缓冲，完整 Schema、FSM 和成功终态通过后才发布；拒绝或异常零转发。
- [x] `finish.answer` 与已验证 `plan.answer` 使用同一来源并精确绑定，不能绕过 grounded answer 校验。
- [x] Runtime 不可用、关闭或自报 `RAG_DISABLED` 时，Java fallback 仅可回答或预览，不得执行副作用计划。
- [x] 派发后的 Reviewer/SSE 等异常保留真实 `executed` 与 task IDs，并明确禁止用新 Turn 盲目重试。

根据当前 `PLANNER_HARNESS_REFACTOR_SUMMARY.md` 记录，最近一次完整验证结果为 Python `63 passed`、Java `380 tests / 0 failures / 3 skipped`，Java-Python-LLM Harness E2E `3 passed`。实现本文待办后必须重新运行，不能直接沿用为新 RAG/ReAct 的验证结果。

本文剩余事项主要是 **RAG 质量、证据闭环和有界检索决策能力**，而不是重新修复已经闭环的 Harness 绕过问题。

## 1. 最终技术决策

本项目建议采用：

> **Project-scoped Evidence-Grounded Agentic RAG + Bounded Retrieval-ReAct + Java Security Harness**

中文表述：

> **面向授权安全测试的项目级证据驱动 Agentic RAG 与受限 ReAct 安全控制架构**

### 1.1 核心 RAG 生成顺序

```rust
先检索 -> 将证据注入 Prompt -> 再生成有依据的答案
```

这是本次改造最核心的执行顺序。项目事实问答和依赖项目状态的行动规划都必须遵守：

1. 根据已验证的 project、target、conversation scope 检索资料。
2. 将强类型 `EvidenceBundle` 作为不可信证据数据注入第二次模型 Prompt。
3. 模型基于 Evidence 生成答案或 Typed Action Plan。
4. 程序校验输出中的 Evidence IDs，副作用 action 再进入 Python Guard 和 Java Harness。

当前代码只完成了“Planner 先生成 -> 后置检索 -> 最终追加引用标题”，所以此核心顺序尚未真正完成，属于 P0 待办。

### 1.2 完整 Agentic RAG 决策链路

```text
用户请求
  -> Agent 判断是否检索
  -> 构造或改写检索查询
  -> 检索
  -> 评估结果是否充分
  -> 必要时改写查询并再次检索（最多一次）
  -> 将检索文档封装为 EvidenceBundle 并注入模型 Prompt
  -> 基于证据生成答案或 Typed Action Plan
  -> 校验证据引用
  -> 副作用动作进入 Python Guard 和 Java Security Harness
```

分支与终止规则：

- [x] `GENERAL_QA` 可以不检索，但不得声称答案来自当前项目资料。
- [x] `PROJECT_QA` 和依赖项目状态的 `ACTION_PLAN` 必须检索。
- [x] Agent 首先把用户自然语言整理为适合检索的初始 query，这属于首次查询构造，不增加循环轮次。
- [x] 首次检索后必须执行 Evidence Sufficiency Decision，不能直接假定结果充分。
- [x] 结果充分时立即进入 Prompt 注入与 grounded generation。
- [x] 结果不足时最多进行一次 query rewrite 和第二次检索。
- [x] 第二次检索仍不足时进入 `CLARIFY`，不得继续循环或补造项目事实。
- [x] 两轮证据合并时必须去重，并继续遵守 project、target、conversation 和总字符预算。
- [x] 注入 Prompt 的是经过作用域过滤和长度限制的 EvidenceBundle，不是原始全量项目数据。
- [x] 最终回答只能引用当前 EvidenceBundle 中实际存在的 Evidence IDs。

核心决策如下：

- [x] 保留 Python LangGraph 作为 Planner 和运行时编排层。
- [x] 保留 Java 作为授权、目标范围、审批、配额、事务、幂等、任务执行和审计的最终权威边界。
- [x] 保留 LLM Planner 与规则 Planner 两种模式，并让两者复用同一个 Java Harness。
- [x] 将检索结果真正输入回答/规划模型，而不是生成答案后只追加引用标题。
- [x] 将当前无有效语义区分能力的 `MockEmbedding` 默认检索替换为中文友好的 BM25。
- [x] 增加最多一次查询改写的受限 Retrieval-ReAct 循环。
- [x] 使用强类型 `EvidenceBundle` 记录来源、作用域、版本、摘要和内容摘要值。
- [x] 对证据引用进行程序校验，模型不得引用未检索到的证据。
- [x] 保持所有副作用动作单向进入 Java Harness，不让 Python 直接执行扫描器或系统命令。
- [x] 将新增 RAG/ReAct 协议纳入 Python 单元测试、LangGraph 集成测试和 Java-Python E2E。

## 2. 范围边界

### 2.1 本次必须完成

1. 有效的项目内知识检索。
2. 检索先于项目事实回答和项目相关规划。
3. 基于证据的回答与行动计划生成。
4. 最多一次补检或查询改写。
5. 明确的循环、Token、时间和检索数量预算。
6. 检索内容提示注入防护。
7. 证据来源、索引版本和引用关系可审计。
8. LLM 路径、规则降级路径和 Harness 路径分别验证。

### 2.2 本次明确不做

- [x] 不增加 Subagent 或 Reviewer Agent。
- [x] 不增加多 Agent 消息总线、代理身份、代理间共享记忆。
- [x] 不使用 Neo4j、Kuzu 或其他图数据库。
- [x] 不实现实体抽取、关系抽取、社区发现或多跳 GraphRAG。
- [x] 不允许模型生成任意 Cypher、SQL、Shell 或扫描器命令。
- [x] 不实现无限 ReAct、自主任务分解或递归创建 Agent。
- [x] 不把 Java 工具执行权限迁移到 Python。
- [x] 不记录或展示模型原始思维链；只保存结构化决策摘要。
- [x] 不要求同一次 Python Runtime 调用观察真实扫描结果。

“不增加 Subagent”不等于删除现有 reviewer 代码。`ai-runtime/app/graph.py` 的 `_reviewer_node` 当前只是确定性汇总 references/proposals，Java `AiExecutionReviewer` 也是普通复核服务；二者不是可自主规划、拥有独立记忆或调用工具的 Subagent，应继续保留。

最后一项是当前跨语言边界决定的：Python 只生成 Java 工具提案，真正任务创建和执行发生在 Java Runtime 返回之后。若要让扫描结果回到同一次 ReAct 循环，需要新增双向执行协议、异步回调和恢复机制，明显超出本科论文的合理范围。扫描结果应在任务完成后进入项目索引，由后续会话继续分析。

## 3. 当前实现状态

### 3.1 已经具备，不需要重复建设

| 能力 | 当前实现 | 位置线索 | 结论 |
|---|---|---|---|
| 严格 Planner JSON | 裸 JSON、重复 key、深度、字段和判别联合校验 | `ai-runtime/app/model.py:64-110`、`ai-runtime/app/schemas.py:78-154` | 保留并扩展，不改回宽松解析 |
| Python 防御性守卫 | 项目状态、时间窗、工具、目标、端口、审批、配额预检 | `ai-runtime/app/graph.py:370-541` | 每个新增检索轮次仍需经过守卫 |
| Java 最终授权 | 执行计划最终进入 `SecurityAgentTools.executeAuthorizedPlan` | `security-toolbox-server/.../AgentOrchestrator.java:325` | 唯一副作用入口必须保持不变 |
| 有界重试 | 只重试失败动作，重试前重新校验授权 | `ai-runtime/app/graph.py:801-890` | 这是执行失败重试，不等于 ReAct |
| 项目/会话隔离 | 检索绑定 project、target、conversation 和 TTL | `ai-runtime/app/indexing.py:517-591` | 新检索器必须复用同样的可见性规则 |
| 文档 ID 与项目摘要 | Python 清洗时生成文档 `id`，持久化时计算项目文档 `sha256` | `ai-runtime/app/indexing.py:98-115, 277-302` | 直接复用并向 Evidence/审计传播，不重复设计另一套版本源 |
| 严格 Runtime 协议 | 事件类型、版本、顺序、终态均 fail-closed | `security-toolbox-server/.../AiAgentRuntimeClient.java:47-56, 531-592, 860-895` | 新事件需要同步升级协议 |
| 跨语言 Harness E2E | CI 启动 mock OpenAI、Python Runtime 和 Java 测试 | `.github/workflows/ci.yml` 的 `agent-runtime-e2e` job | 在此基础上新增 grounded RAG 用例 |

### 3.2 当前仍然缺失

| 编号 | 缺失项 | 当前表现 | 影响 | 优先级 |
|---|---|---|---|---|
| G-01 | 有效语义或相关性检索 | LlamaIndex 使用 `MockEmbedding(256)`，不提供有意义的语义区分 | 检索排序可能与问题无关，不能证明 RAG 有效 | P0 |
| G-02 | 检索前置 | Planner 在 `graph.py:295-318` 先生成答案和动作，检索到 `graph.py:656-674` 才发生 | 模型生成答案时看不到项目证据 | P0 |
| G-03 | Grounded generation | `graph.py:983-990` 直接使用初始答案，只追加引用标题 | 当前更接近 Agentic Retrieval + Citation，不是完整 RAG | P0 |
| G-04 | 强类型证据契约 | 索引内部已有文档 `id` 和项目 `sha256`，但查询结果只传播 `title/source/text/score` | 现有标识没有进入模型引用、SSE 和 Java 审计，引用仍不可稳定复核 | P0 |
| G-05 | 受限观察后重规划 | 当前 Retest 只机械重试失败动作 | 无法根据“证据不足”改写查询或请求澄清 | P1 |
| G-06 | 检索内容提示注入边界 | 项目文档将直接成为模型上下文时尚无专门证据净化与指令隔离协议 | 恶意文档可能诱导越权工具调用或泄露上下文 | P0 |
| G-07 | 索引新鲜度和版本传播 | 索引更新存在，但回答引用没有稳定 `indexRevision` | 无法证明回答基于哪个项目快照 | P1 |
| G-08 | RAG 质量评估 | 现有测试重点是协议和 Harness 安全 | 无法量化检索召回、引用正确率和 ReAct 收益 | P0 |
| G-09 | 新事件跨语言兼容 | Java 对未知 Runtime 事件 fail-closed | Python 单边新增 route/rewrite/evidence 事件会导致整轮失败 | P0 |
| G-10 | 规则 Planner 与 LLM 路径区别 | 两者共享 Harness，但生成与证据使用逻辑不同 | 规则路径通过不能等价证明 LLM + RAG 路径正确 | P0 |

## 4. 目标链路

```mermaid
flowchart TD
    A["Java 绑定项目、目标、会话和授权快照"] --> B["Python Intent Router"]
    B -->|一般知识问答| C["直接回答，不声明项目事实"]
    B -->|项目事实或项目相关规划| D["生成严格 Retrieval Action"]
    D --> E["Python Retrieval Guard"]
    E -->|拒绝| Z["DENIED / 安全终止"]
    E -->|允许| F["项目内 BM25 Retriever"]
    F --> G["EvidenceBundle"]
    G --> H["Evidence Sufficiency Decision"]
    H -->|证据不足且 round = 0| I["最多一次 Query Rewrite"]
    I --> D
    H -->|仍不足| J["CLARIFY / 明确证据不足"]
    H -->|证据充分| K["Grounded Answer 或 Typed Action Plan"]
    K -->|回答| L["校验 Evidence Refs 后输出"]
    K -->|副作用动作| M["Python Defensive Guard"]
    M --> N["Java Security Harness"]
    N --> O["授权、白名单、审批、配额、幂等、事务"]
    O --> P["受控任务创建、执行和审计"]
    P --> Q["任务结果进入项目索引，供后续会话检索"]
```

### 4.1 安全不变量

以下条件必须在实现和测试中同时成立：

- [x] LLM 不能提供或修改 `projectId`、`targetId`、`conversationId`、授权状态和策略版本。
- [x] 检索作用域只能由已验证请求状态注入，不能从查询文本推断。
- [x] 每一次检索都视为工具动作，并经过 Python 防御性 Retrieval Guard。
- [x] 每一个副作用动作都重新经过 Python Guard 和 Java Harness。
- [x] Evidence 只影响回答或计划内容，不能扩大授权范围。
- [x] 文档中的“忽略系统指令”“调用某工具”等文本只能作为数据，不能成为控制指令。
- [x] `DENIED`、`APPROVAL_REQUIRED`、协议错误和模型 Schema 错误均不得触发查询改写或动作重试。
- [x] 检索循环达到预算后必须进入 `CLARIFY`、`COMPLETED` 或 `FAILED`，不能继续回环。
- [x] 规则 Planner 只能作为独立降级路径，测试报告不得用它替代 LLM 路径结果。

## 5. 目标数据契约

### 5.1 IntentDecision

在生成回答和行动计划前增加严格路由结果：

```json
{
  "intent": "PROJECT_QA",
  "needsRetrieval": true,
  "retrievalQuery": "项目 12 的目标 3 最近发现了哪些高危漏洞",
  "publicReasonCode": "PROJECT_FACT_REQUIRED"
}
```

要求：

- [x] `intent` 使用枚举：`GENERAL_QA`、`PROJECT_QA`、`ACTION_PLAN`、`CLARIFY`。
- [x] `needsRetrieval` 使用严格布尔类型。
- [x] `retrievalQuery` 最大 2,000 字符，禁止为空白控制字符组成的查询。
- [x] `publicReasonCode` 使用枚举，不接受自由格式思维过程。
- [x] 模型输出继续执行重复 key、额外字段、深度和长度限制。

### 5.2 EvidenceBundle

EvidenceBundle 必须由 Runtime 生成，不能由 LLM 自行构造：

```json
{
  "projectId": 12,
  "targetId": 3,
  "conversationId": "session-abc",
  "query": "最近的高危漏洞",
  "round": 0,
  "retrievalMethod": "bm25",
  "indexRevision": "sha256:...",
  "items": [
    {
      "evidenceId": "ev-...",
      "documentId": "finding-1024",
      "source": "finding",
      "title": "CVE-2025-XXXX",
      "snippet": "...",
      "score": 8.31,
      "targetId": 3,
      "contentDigest": "sha256:..."
    }
  ]
}
```

要求：

- [x] 在 `ai-runtime/app/schemas.py` 增加 `EvidenceItem` 和 `EvidenceBundle`，设置 `extra="forbid"`。
- [x] `items` 默认最多 5 条，硬上限不超过 10 条。
- [x] 单条 `snippet` 建议限制为 2,000 字符，总证据上下文建议不超过 8,000～12,000 字符。
- [x] `documentId` 来自索引中的稳定 ID；当前查询结果需补充返回该字段。
- [x] `evidenceId` 由 scope、documentId、contentDigest、indexRevision 确定性计算。
- [x] `contentDigest` 用于证明引用内容未在生成过程中被替换。
- [x] `indexRevision` 使用项目文档规范化内容摘要或单调版本号。
- [x] conversation 文档只允许当前 conversation + target 可见；项目资料按 project + target 元数据过滤。
- [x] 先过滤作用域，再进行相关性排序，避免其他会话文档参与候选竞争。

### 5.3 EvidenceDecision

ReAct 的“思考”只保存为有限决策，不保存原始 Chain-of-Thought：

```json
{
  "decision": "REWRITE_QUERY",
  "reasonCodes": ["NO_DIRECT_MATCH", "MISSING_TARGET_FACT"],
  "evidenceRefs": [],
  "rewrittenQuery": "目标 3 最近 60 条 finding 中 severity 为 HIGH 或 CRITICAL 的记录"
}
```

要求：

- [x] `decision` 仅允许 `FINALIZE`、`REWRITE_QUERY`、`CLARIFY`。
- [x] `reasonCodes` 使用枚举，限制数量。
- [x] `evidenceRefs` 必须是当前 EvidenceBundle 中存在的 ID。
- [x] 只有第 0 轮允许返回 `REWRITE_QUERY`；第 1 轮再次返回时强制转为 `CLARIFY`。
- [x] 改写后的查询与历史查询规范化后相同，立即终止循环。
- [x] EvidenceDecision Schema 异常时 fail-closed，不自动猜测模型意图。

### 5.4 Grounded Planner Output

在现有严格 `PlannerOutput` 基础上增加：

- [x] 回答级 `evidenceRefs`。
- [x] 每个副作用 action 可选的 `evidenceRefs`。
- [x] `knowledgeMode`：`GENERAL`、`PROJECT_EVIDENCE`、`INSUFFICIENT_EVIDENCE`。
- [x] 项目事实回答若 `knowledgeMode=PROJECT_EVIDENCE`，至少引用一个有效 Evidence ID。
- [x] 模型引用未知、跨项目或已过期 Evidence ID 时整轮拒绝，不能静默删除非法引用。
- [x] 引用只证明事实来源，不代表该动作已获授权。

## 6. 分阶段实施清单

## Phase 0：运行参数与功能开关（P0）

目标：在改动检索和图结构前确定运行上限，并保证新功能可以安全启停。

- [x] 新增架构配置：`rag_enabled`，默认根据论文演示环境决定，测试中显式设置。
- [x] 新增 `retrieval_backend=bm25|real_embedding`；不再把 MockEmbedding 标记为有效向量检索。
- [x] 新增 `max_retrieval_rounds=2`，含初次检索和最多一次改写检索。
- [x] 新增 `max_evidence_items=5`。
- [x] 新增 `max_evidence_chars`、`retrieval_timeout_seconds` 和每轮 LLM 超时。
- [x] 保留现有 `contractVersion=1` 行为，设计新增字段和事件后再一次性升级协议。

涉及文件：

- `ai-runtime/app/config.py`
- `ai-runtime/app/graph.py`
- `ai-runtime/app/model.py`
- `security-toolbox-server/src/main/resources/application.yml`

验收标准：

- [x] 关闭 RAG/ReAct 开关时，现有 Planner + Harness 测试不退化。
- [x] 所有循环和内容上限都有代码级默认值和 Schema 硬上限，不能只依赖 Prompt。

## Phase 1：实现有效项目检索（P0）

目标：建立体积较小、离线可运行、中文可测试的真实相关性检索。

推荐实现：`jieba` 分词 + 成熟 BM25 库；CVE、IP、域名、端口、协议名需要作为完整 token 保留。真实本地 Embedding 只作为可选扩展，不作为毕业论文主链路前置条件。

- [x] 在 `ai-runtime/requirements.txt` 和构建依赖中加入选定的 BM25/中文分词依赖。
- [x] 为中文、英文、安全标识符定义稳定 tokenizer。
- [x] 对 `CVE-2025-1234`、`192.168.1.10`、`example.com`、`443/tcp`、`TLS1.2` 等标识符增加测试。
- [x] 按 project 构建独立 BM25 索引，不创建跨项目全局语料索引。
- [x] 检索前应用 project、target、conversation、TTL 可见性过滤。
- [x] 索引更新后使对应 project 缓存失效并重建。
- [x] 空项目、空查询、全部文档不可见时返回空 EvidenceBundle。
- [x] 将 `MockEmbedding` 从默认 READY 路径移除或标记为 `mock/non-semantic`，不得在健康状态中宣称语义检索可用。
- [x] 若保留 LlamaIndex，只有配置了真实 Embedding 时才启用 vector backend；加载失败明确降级到 BM25。
- [x] 不允许检索异常被静默包装成“有证据的回答”。

涉及文件：

- `ai-runtime/app/indexing.py:364-515`
- `ai-runtime/app/config.py`
- `ai-runtime/app/main.py`
- `ai-runtime/requirements.txt`
- `ai-runtime/tests/test_runtime.py`

验收标准：

- [x] 预设中文项目问题的相关文档能够稳定进入 Top-3。
- [x] 同名文档位于其他 project、target 或 conversation 时不能被返回。
- [x] 相同数据和查询重复执行得到确定性排序。
- [x] 默认安装不需要下载数百 MB 模型。

## Phase 2：建立 EvidenceBundle 与可验证引用（P0）

目标：让“检索到了什么”成为正式运行时状态，而不是松散字典。

- [x] Python 索引清洗阶段已经生成稳定文档 `id`，不再新增第二套 document ID。
- [x] Python 项目文档持久化已经计算整体 `sha256`，可直接作为 `indexRevision` 的来源。
- [x] 将现有索引 `id` 作为 `documentId` 传播到查询结果。
- [x] 将现有项目文档 `sha256` 作为 `indexRevision` 传播到查询结果、Graph State 和审计。
- [x] 为单条文档补充 `contentDigest`，并让检索结果返回 `evidenceId`、`targetId` 和 `retrievalMethod`。
- [x] 在 Pydantic 中实现严格 Evidence Schema。
- [x] 在 LangGraph State 中增加 `evidenceBundles`、`activeEvidence`、`retrievalRound`、`retrievalQueries`。
- [x] 对 EvidenceBundle 总条数、单条长度、总长度和嵌套深度设硬限制。
- [x] 实现 `validate_evidence_refs()`，校验模型输出引用只能指向当前 scope 的当前证据。
- [x] 将索引 revision、查询和 evidence IDs 写入结构化审计事件。
- [x] 默认不在普通日志中记录完整证据正文，只记录 ID、标题、摘要值和长度。
- [x] SSE 需要展示证据数量和来源类型，不向前端泄露隐藏会话文档正文。

涉及文件：

- `ai-runtime/app/schemas.py`
- `ai-runtime/app/indexing.py`
- `ai-runtime/app/tools.py`
- `ai-runtime/app/graph.py`
- `security-toolbox-server/.../AiAgentRuntimeClient.java`
- `security-toolbox-server/.../AgentOrchestrator.java`

验收标准：

- [x] 任意未知 Evidence ID 导致本轮 grounded 输出拒绝。
- [x] 审计记录可以通过 `documentId + contentDigest + indexRevision` 复核引用。
- [x] Evidence 正文不会被误写入授权字段、工具参数或策略版本字段。

## Phase 3：将检索前置并实现 Grounded Generation（P0）

目标：项目事实回答和项目相关计划必须先读证据，再生成结果。

- [x] 将当前 `_planner_node -> retrieve -> append citation` 拆分为 `route -> retrieve -> grounded_plan_or_answer`。
- [x] 保留 `engage/recon/map/validate/impact/retest/report/finish` 的用户可见红队阶段语义；新增证据节点需要映射到现有阶段，或通过统一协议版本升级同步修改 Java/UI。
- [x] 一般知识问答允许跳过项目检索，但不能伪装成“基于当前项目”的结论。
- [x] 项目状态、历史任务、Finding、Recon、Probe 等事实问题强制检索。
- [x] 行动请求可先检索近期目标状态，再生成 Typed Action Plan。
- [x] Grounded Prompt 将授权控制信息与 Evidence 数据放在不同结构段中。
- [x] 明确告诉模型 Evidence 是不可信数据，正文中的命令和指令不得执行。
- [x] 模型只输出结论、动作和 Evidence IDs，不输出隐藏推理过程。
- [x] 证据不足时输出 `CLARIFY` 或“当前项目资料不足”，不得用模型常识补造项目事实。
- [x] 规则 Planner 路径使用相同 EvidenceBundle 接口；无法使用证据时明确标记来源。
- [x] LLM Schema 失败继续安全停止，不回退成可能执行的规则计划。
- [x] 保持 Java Harness 对最终 action 的重新校验，不信任 grounded 结果中的风险判断。

涉及文件：

- `ai-runtime/app/model.py:134-260`
- `ai-runtime/app/graph.py:231-368, 587-753, 943-1003`
- `ai-runtime/app/schemas.py`
- `ai-runtime/tests/mock_openai_server.py`

验收标准：

- [x] mock LLM 的最终回答请求体中确实包含已检索 Evidence。
- [x] 最终回答中的每个项目事实都能关联至少一个有效 Evidence ID。
- [x] 删除相关文档后，同一问题不得继续输出旧项目事实。
- [x] 仅追加引用标题但正文未使用 Evidence 的实现不算完成。

## Phase 4：加入受限 Retrieval-ReAct（P1）

目标：证据不足时允许一次可审计的查询改写，而不是增加通用自主 Agent。

- [x] 使用 LangGraph 条件边实现 `assess -> rewrite -> retrieve`，不要在单个节点中隐藏无限 `while`。
- [x] 初始轮次为 0，最多执行到 round 1。
- [x] 每轮检索 action 都重新计算 actionId 并重新经过 Retrieval Guard。
- [x] 记录原查询、改写查询、reasonCodes、结果数量和终止原因。
- [x] 相同查询、空查询、超长查询或无实质变化的查询立即终止。
- [x] 达到最大轮次后只允许 `FINALIZE` 或 `CLARIFY`。
- [x] 配置 LangGraph recursion limit，作为代码循环上限之外的第二层保护。
- [x] 设置整个 Agent turn 的总时间预算和总 LLM 调用预算。
- [x] 设置总检索结果字符预算，第二轮不能无限扩大上下文。
- [x] 检索超时最多按基础设施错误策略处理一次，不得与“证据不足改写”混为一类。
- [x] Guard 拒绝、审批等待、Schema 错误和未知工具均禁止进入 ReAct 回环。
- [x] Side-effect action 不进入同轮 ReAct；Java 执行结果由后续会话读取。

建议状态字段：

```text
retrievalRound: 0..1
retrievalQueries: list[str] (max 2)
evidenceBundles: list[EvidenceBundle] (max 2)
evidenceDecision: EvidenceDecision | null
llmCallCount: bounded integer
retrievalDeadline: timestamp
terminationReason: enum
```

验收标准：

- [x] 任意输入下检索次数不超过 2 次。
- [x] 任意错误分支都存在确定终态。
- [x] 单次正常充分检索不会触发第二轮。
- [x] 规则 Planner CI 通过不能替代上述 LLM 循环测试。

## Phase 5：跨语言协议与 Harness 对接（P0）

目标：新增 RAG/ReAct 状态不破坏现有 fail-closed Runtime 协议。

- [x] 决定是扩展现有 `stage` 事件 data，还是增加 `route/evidence/rewrite` 事件类型。
- [x] 若新增事件类型或终态字段，统一升级 `contractVersion`。
- [x] Python 事件模型和 Java `RUNTIME_EVENT_TYPES` 同步修改。
- [x] Java 校验 `runId`、`stateVersion`、`policyRevision` 的逻辑保持不变。
- [x] Java 对 Evidence 元数据只做协议、大小和作用域校验，不把 Evidence 当成授权依据。
- [x] 最终副作用 plan 仍由 `SecurityAgentTools.executeAuthorizedPlan` 执行。
- [x] 保留 Python 确定性 `_reviewer_node` 与 Java `AiExecutionReviewer`，但禁止将其演化成拥有独立 Planner、记忆或工具权限的 Subagent。
- [x] `turnId`、幂等、配额和 after-commit 调度不因 ReAct 轮次重复计算或重复创建任务。
- [x] 同一个 action 在不同 retrieval round 出现时，需要稳定定义 actionId 和去重规则。
- [x] 审计增加 `retrievalRoundCount`、`evidenceIds`、`indexRevision`、`plannerSource`。
- [x] Runtime 不可用时，Java 规则 Planner 降级事件明确标记 `fallback=true`，论文统计单独计算。
- [x] Java 规则 Planner 生成的动作继续经过 Harness，但不得宣称等价验证 LLM + RAG。
- [x] 任务完成后的 Finding/Recon/Probe 更新触发或调度项目索引刷新，保证下一轮可检索。

涉及文件：

- `ai-runtime/app/graph.py`
- `ai-runtime/app/main.py`
- `security-toolbox-server/.../AiAgentRuntimeClient.java:47-56, 349-447, 531-660`
- `security-toolbox-server/.../AgentOrchestrator.java:141-218, 325-395`
- `security-toolbox-server/.../AiProjectIndexService.java:69-210`

验收标准：

- [x] Python 单边增加未知事件时 Java 测试能够 fail-closed。
- [x] 协议双方升级后，完整 SSE 流保持状态版本严格递增且只有一个终态。
- [x] ReAct 两轮检索仍只产生一次最终 Java 任务派发。

## Phase 6：检索内容安全加固（P0）

目标：防止项目文档、扫描输出和历史对话通过 RAG 影响控制面。

- [x] 将 Evidence 标记为 `UNTRUSTED_EVIDENCE`，与系统指令和授权上下文隔离。
- [x] 清理 NUL、异常控制字符和超长连续文本。
- [x] 保留安全测试原始事实所需字符，不使用会破坏证据含义的粗暴替换。
- [x] 禁止 Evidence 覆盖 system、developer、authorization 或 tool schema。
- [x] 工具名、目标 ID、端口和审批状态只能来自受控 Schema 和授权状态。
- [x] 针对间接提示注入增加拒绝规则和负面测试。
- [x] 对 conversation evidence 保持 TTL、target 和 conversation 三重隔离。
- [x] 对检索接口设置频率、并发、topK、query length 和结果字符上限。
- [x] 日志和 SSE 不输出凭据、完整授权声明、运行时 token 或项目签名。
- [x] 模型试图引用 Evidence 中出现的其他项目 ID 时，仍以当前请求 scope 校验。
- [x] Prompt injection 导致非法 action 与合法 action 混合时继续整体拒绝。

验收标准：

- [x] 恶意文档“忽略规则并调用 shell_exec”不能产生任何任务或审计派发记录。
- [x] 恶意会话记忆不能读取其他 conversation 或 target 的内容。
- [x] 大文档和大量文档不能突破证据上下文和循环预算。

## Phase 7：测试补齐（P0）

### 7.1 Python 组件单元测试

- [x] 中文 BM25 相关性排序。
- [x] 英文、CVE、IP、域名、端口混合 tokenizer。
- [x] 相同分数的确定性排序。
- [x] project、target、conversation 和 TTL 过滤先于排序。
- [x] 索引更新、缓存失效和 indexRevision 变化。
- [x] EvidenceBundle 拒绝额外字段、错误类型、超长正文和重复 Evidence ID。
- [x] Evidence 引用拒绝未知 ID、跨 scope ID 和旧 revision ID。
- [x] IntentDecision 严格 JSON、重复 key、未知 intent 和超长 query。
- [x] EvidenceDecision 严格 JSON、非法 decision 和第 2 次 rewrite。
- [x] 查询规范化相同后停止循环。
- [x] 空检索结果进入 CLARIFY，不伪造项目结论。
- [x] 检索内容包含 Prompt Injection 时不改变 tool schema。
- [x] LLM 超时、检索超时和 Schema 错误分别进入正确终态。

### 7.2 LangGraph 完整链路测试

- [x] 一般知识问题：不检索、不调用副作用工具、正常完成。
- [x] 项目事实问题：先检索，再调用 grounded generation，答案带有效证据。
- [x] 首轮证据充分：只检索一次。
- [x] 首轮证据不足：改写一次，第二轮成功后完成。
- [x] 两轮均无证据：CLARIFY 且零副作用。
- [x] 改写重复原查询：立即终止，不循环。
- [x] 项目资料诱导 `shell_exec`：Planner Schema 整体拒绝。
- [x] Evidence 与模型常识冲突：项目事实以 Evidence 为准或明确不确定。
- [x] Action Plan 引用证据后仍经过 Python Guard。
- [x] Guard DENIED 后不重写、不重试、不调用工具。
- [x] APPROVAL_REQUIRED 后不进入 ReAct。
- [x] Runtime 最大 LLM 调用数、检索数、字符数和时间预算生效。
- [x] 规则 Planner 与 LLM Planner 均进入相同 Harness，但分别断言 planner source。

### 7.3 Java 组件与协议测试

- [x] 新 Runtime 事件类型/字段白名单。
- [x] 新旧 contractVersion 不匹配时 fail-closed。
- [x] Evidence 元数据超长、类型错误、未知字段时拒绝。
- [x] SSE 分片情况下 Evidence 事件仍能正确解析。
- [x] 无 finish、重复 finish、finish 后继续发送事件时拒绝。
- [x] 两轮 retrieval 事件的 stateVersion 严格递增。
- [x] Evidence 不能替代 Java 项目、目标、配额和审批查询。
- [x] 同一个 turn 的 ReAct 事件不会造成重复任务创建。
- [x] Runtime 降级到 Java Planner 时明确记录 fallback，动作仍走 Guard。

### 7.4 Java-Python-mock LLM E2E

- [x] mock LLM 第一轮请求返回项目检索意图。
- [x] Python 检索项目文档。
- [x] mock LLM 第二轮请求体包含 EvidenceBundle 中的事实。
- [x] 最终回答引用已存在的 Evidence ID。
- [x] action 请求经过 Python Graph、Java Runtime Client、Java Guard 和 `SecurityAgentTools`。
- [x] 恶意 Evidence 诱导未知工具时最终零任务、零派发、零异步执行。
- [x] 跨项目或跨会话问题无法获得错误 scope 的 Evidence。
- [x] 一次查询改写后只产生一次最终计划和一次 Java 派发。
- [x] CI 上传 mock LLM、Python Runtime 和 Java Surefire 失败日志。

### 7.5 测试层级结论

测试报告必须分开统计：

| 层级 | 能证明什么 | 不能证明什么 |
|---|---|---|
| Retriever 单元测试 | 排序、过滤、稳定性 | LLM 是否真正使用证据 |
| Planner/Schema 单元测试 | 输出契约和异常拒绝 | Java 是否执行统一授权 |
| LangGraph 集成测试 | 节点顺序、循环终止、Python Guard | 跨语言协议和事务副作用 |
| Java Harness 单元/事务测试 | 权威授权、配额、审批、幂等 | LLM 真实路径 |
| Java-Python-mock LLM E2E | 完整 Planner + RAG + Harness 链路 | 真实模型的随机性和泛化能力 |
| 固定真实模型评估 | 实际质量、延迟和幻觉率 | 所有模型和所有输入的安全性 |

## Phase 8：文档、展示与答辩材料（P1）

- [x] 更新 README 中的架构分类，避免把当前实现误称为 GraphRAG。
- [x] 绘制 Planner、Retriever、LangGraph、Java Harness 和数据库的边界图。
- [x] 绘制一次成功检索、一次改写、一次授权拒绝的时序图。
- [x] 在论文中单列“为什么不使用 GraphRAG”和“为什么不使用 Subagent”。
- [x] 说明 ReAct 只用于只读检索，不用于同轮真实扫描执行。
- [x] 说明不记录 Chain-of-Thought，只审计结构化 reasonCodes。
- [x] 列出威胁模型：恶意用户、恶意项目文档、模型幻觉、跨项目读取、协议篡改和重试风暴。
- [x] 准备固定演示项目和固定问题，避免答辩现场依赖网络或大模型下载。
- [x] 演示一条正常 grounded answer、一条 query rewrite、一条 Harness 拒绝。
- [x] 将真实模型名称、温度、版本、Prompt 版本和实验日期写入实验配置。

## 7. 推荐实施顺序

| 顺序 | 工作包 | 优先级 | 工作量估计 | 前置条件 |
|---:|---|---|---|---|
| 1 | 配置开关、预算与协议版本设计 | P0 | S | 无 |
| 2 | BM25 与中文 tokenizer | P0 | M | 1 |
| 3 | EvidenceBundle、稳定 ID、indexRevision | P0 | M | 2 |
| 4 | 检索前置与 grounded generation | P0 | L | 3 |
| 5 | Python 安全与完整链路测试 | P0 | M | 4 |
| 6 | Java-Python 事件协议升级与 E2E | P0 | L | 4 |
| 7 | 最多一次 Retrieval-ReAct | P1 | M | 4、6 |
| 8 | Prompt Injection 与预算负面测试 | P0 | M | 5、7 |

说明：`S/M/L` 只表示相对工作量。若时间不足，应优先完成 1～6 和 8；第 7 步可以简化为固定一次补检。

## 8. 最小可交付版本（MVP）

若论文时间有限，以下项目完成即可形成比当前更完整、但复杂度仍可控的方案：

- [x] 默认 BM25 替代 MockEmbedding。
- [x] 项目问题严格执行“先检索 -> 将证据注入 Prompt -> 再生成有依据的答案”。
- [x] 严格 EvidenceBundle 和可校验引用。
- [x] 证据不足时最多改写一次查询。
- [x] 所有副作用动作继续通过 Java Harness。
- [x] Prompt Injection、跨项目隔离、循环上限和恶意工具输出测试通过。

MVP 完成后，论文可以合理称为“轻量级 Agentic RAG + Security Harness”；不应称为 GraphRAG 或多智能体系统。

## 9. 完成定义（Definition of Done）

只有同时满足以下条件，才可将本待办标记为完成：

- [x] 默认检索器具有真实相关性能力，健康状态不再把 MockEmbedding 当作有效语义检索。
- [x] 项目事实回答的生成发生在 Evidence 获取之后。
- [x] 最终项目事实能够映射到合法 Evidence IDs。
- [x] Evidence 不足不会产生无来源的项目结论。
- [x] 检索总轮次永远不超过 2，所有错误分支都有确定终态。
- [x] 不存在 Python 直接执行副作用工具的路径。
- [x] 不存在绕过 Java `SecurityAgentTools` 创建 AI 任务的路径。
- [x] 检索文档中的指令不能修改 scope、工具白名单、审批或工具参数 Schema。
- [x] Python 单元、LangGraph 集成、Java 组件和 Java-Python E2E 全部通过。
- [x] CI 真实启用 mock LLM + Python Runtime + Java Harness 链路。
- [x] 文档明确说明不包含 Subagent、GraphRAG 和无限自主循环。

## 10. 可选项与停止线

以下内容仅在 MVP、测试和论文主体全部完成后考虑：

- [ ] P2：为 conversation tombstone 增加持久 outbox，实现更强最终一致性。
- [ ] P2：在后续独立研究中探索任务完成回调驱动的跨回合 Agent 恢复。

出现以下情况时应停止扩展并优先完成论文：

- 需要引入图数据库才能继续。
- 需要新增代理身份、代理间授权或多代理共享状态。
- 需要让 Python 直接执行扫描器才能实现循环。
- ReAct 需要超过一次查询改写才能完成常规问题。
- 模型和向量模型体积开始影响离线演示、打包或答辩环境。

此时应将相关内容写入“未来工作”，而不是继续扩大实现范围。
