# Planner + Harness AI Agent 专项安全代码审查报告

> 审查对象：Python `ai-runtime` 与 Java `security-toolbox-server`  
> 审查日期：2026-08-07  
> 审查基线：本地工作区当前代码  
> 审查方式：静态代码审查、调用链分析、现有测试与 CI 覆盖分析

> 整改状态（2026-08-07）：本文第 1～8 节保留的是整改前基线，不再代表当前风险状态。原 R-01～R-11 及 Agentic RAG v2 终审新增问题均已闭环，最终状态与验证见第 9 节和 `AGENTIC_RAG_HARNESS_IMPLEMENTATION_SUMMARY.md`。

## 1. 总体结论

Planner + Harness 的架构思路成立，前提是 Java 任务创建层是唯一、不可绕过且具备原子配额控制的执行安全边界。当前 Python Runtime 不直接执行外部扫描器或 Shell，仅执行项目资料检索并生成 `executed=false` 的 Java 工具提案，这一方向合理。

但当前实现尚未满足“所有工具调用统一经过同一套 Harness”的目标：

1. 旧的 `/api/ai/dispatches` 和 `/api/ai/dispatches/stream` 可绕过 `AgentOrchestrator`、`AiAuthorizationGuard`、显式审批和 Agent 配额。
2. Python 咨询分支可在 Graph 授权守卫之前读取项目索引。
3. Python 与 Java 同时维护授权、审批、配额和生命周期逻辑，已经产生语义分叉。
4. Planner 输出到 Harness 没有统一的强 JSON Schema，异常输出会被宽松归一化或切换到规则 Planner。
5. Java 会话窗口、Python 持久索引和 LangGraph 单次状态之间没有统一版本及会话级同步协议。
6. 默认部署启用 Python Runtime，但 CI 明确关闭该路径，完整跨语言主链路没有自动化证明。

**综合风险等级：高。**

该等级表示存在确定的 Harness 绕过路径、数据隔离缺口和并发配额问题；并不表示 Python 当前能够直接执行任意系统命令。Java `TaskService` 对项目状态、授权时间窗和目标仍保留最终校验，可缓解部分外部执行风险。

## 2. 架构与工具调用链路

### 2.1 正常 Agent 路径

```text
POST /api/ai/agent 或 /api/ai/agent/stream
  -> Spring Security: ADMIN
  -> AgentOrchestrator
  -> 项目/目标成员关系检查 + Java 会话记忆
  -> Python Runtime Planner，或 Java Planner 降级
  -> AiAuthorizationGuard
  -> SecurityAgentTools.executeAuthorizedPlan
  -> AiAuthorizationGuard 再校验
  -> AiTaskDispatchService.prepare
  -> TaskService.create
  -> 异步工具执行 + Audit + Reviewer
```

这条路径对外部扫描工具执行进行了两次 Agent Guard 校验，并在 `TaskService` 再次检查项目、授权时间窗、目标和工具注册表。

### 2.2 旧派发路径

```text
POST /api/ai/dispatches 或 /api/ai/dispatches/stream
  -> Spring Security: authenticated
  -> Java Planner
  -> AiTaskDispatchService.prepare
  -> TaskService.create
```

这条路径不经过 `AgentOrchestrator`、`AiAuthorizationGuard`、Agent 审批状态和活动任务配额，是已确认的 Harness 逃逸分支。

### 2.3 Python 本地检索路径

受控路径：

```text
Planner action: retrieve_project_context
  -> graph._guard_node
  -> graph._executor_node
  -> index_store.query(projectId)
```

无守卫路径：

```text
Planner/规则判断为咨询
  -> AgentPlanner._local_answer
  -> index_store.query(projectId)
  -> graph 因 actions=[] 跳过授权守卫
```

Python 的其他安全工具仅生成 Java 提案，不直接启动扫描器。

## 3. 安全守卫点位清单

| 层级 | 代码位置 | 守卫内容 | 结论 |
|---|---|---|---|
| Python API | [`schemas.py:65`](ai-runtime/app/schemas.py#L65) | 请求字段、长度、类型、extra 字段 | 仅覆盖入站请求，不覆盖 Planner 输出 |
| Python API | [`security.py:9`](ai-runtime/app/security.py#L9) | Runtime 全局令牌 | token 为空时 fail-open |
| Python Graph | [`graph.py:336`](ai-runtime/app/graph.py#L336) | 项目、状态、时间窗、目标、端口、工具、审批、配额 | 依赖调用方提供的授权快照 |
| Python Executor | [`graph.py:500`](ai-runtime/app/graph.py#L500) | 检查 state 中是否已有 violation/approval | 底层 tool 不重新验证决策 |
| Java HTTP | [`SecurityConfig.java:76`](security-toolbox-server/src/main/java/com/bachelor/toolbox/auth/SecurityConfig.java#L76) | `/agent*` 要求 ADMIN | `/dispatches*` 未纳入同一角色要求 |
| Java 项目访问 | [`ProjectAuthorizationService.java:23`](security-toolbox-server/src/main/java/com/bachelor/toolbox/project/ProjectAuthorizationService.java#L23) | 项目所有者/管理员访问 | 正常 Java 入口的跨项目隔离有效 |
| Java 项目状态 | [`AssessmentProjectService.java:126`](security-toolbox-server/src/main/java/com/bachelor/toolbox/project/AssessmentProjectService.java#L126) | 成员关系、ACTIVE、项目授权时间窗 | 预览与执行使用不同严格度 |
| Java Agent Guard | [`AiAuthorizationGuard.java:45`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiAuthorizationGuard.java#L45) | 成员关系、白名单、参数、审批、活动任务配额 | 配额检查非原子 |
| Java Tool | [`SecurityAgentTools.java:116`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/SecurityAgentTools.java#L116) | 工具调用前重新进入 Agent Guard | 正常 Agent 路径有效 |
| Java Dispatcher | [`AiTaskDispatchService.java:100`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiTaskDispatchService.java#L100) | 固定工具白名单、参数键、协议、端口子集 | 被 Agent 与旧派发路径共同使用 |
| Java 最终执行 | [`TaskService.java:76`](security-toolbox-server/src/main/java/com/bachelor/toolbox/task/TaskService.java#L76) | 项目 ACTIVE、授权时间窗、目标当前授权、工具注册 | 未执行 Agent 审批或 Agent 配额 |
| Java Reviewer | [`AiExecutionReviewer.java:21`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiExecutionReviewer.java#L21) | 任务项目/目标归属复核 | 只读，不自动重试 |

## 4. 风险清单

### R-01 旧 AI 派发接口绕过 Agent Harness

- **风险等级：高**
- **代码位置：**[`AiController.java:165`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiController.java#L165)、[`AiDispatchStreamingService.java:21`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiDispatchStreamingService.java#L21)、[`AiTaskDispatchService.java:67`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiTaskDispatchService.java#L67)、[`SecurityConfig.java:76`](security-toolbox-server/src/main/java/com/bachelor/toolbox/auth/SecurityConfig.java#L76)
- **风险描述：**旧 `/dispatches*` 入口直接调用 Planner 和 Dispatcher，不经过 `AgentOrchestrator`、`AiAuthorizationGuard`、执行确认和活动任务配额。该入口只受默认 `authenticated` 约束，而 `/agent*` 要求 ADMIN。
- **潜在后果：**项目所有者可绕过 Agent 审批与配额直接创建受控工具任务；两条 AI 执行路径的审计语义不同。
- **缓解因素：**`TaskService.create` 仍检查项目 ACTIVE、授权时间窗、目标当前授权和工具注册表，因此不是完全绕过项目授权。

### R-02 配额检查非原子，可被并发穿透

- **风险等级：高**
- **代码位置：**[`AiAuthorizationGuard.java:67`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiAuthorizationGuard.java#L67)、[`AiTaskDispatchService.java:77`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiTaskDispatchService.java#L77)、[`TaskService.java:76`](security-toolbox-server/src/main/java/com/bachelor/toolbox/task/TaskService.java#L76)
- **风险描述：**Guard 先统计 `PENDING/RUNNING`，Dispatcher 随后逐条创建任务。检查与创建之间没有数据库锁、事务配额预留或原子计数。
- **潜在后果：**两个并发 Agent 请求可同时看到相同余额并超额创建任务；批量创建中途失败会留下部分任务；旧派发路径完全跳过该配额。

### R-03 Python 咨询分支绕过 Graph 守卫读取项目资料

- **风险等级：高**
- **代码位置：**[`model.py:269`](ai-runtime/app/model.py#L269)、[`model.py:281`](ai-runtime/app/model.py#L281)、[`graph.py:249`](ai-runtime/app/graph.py#L249)
- **风险描述：**`_local_answer` 可直接按请求中的 `projectId` 查询索引；无 action 计划在 Graph 中跳过完整授权守卫。Python `AuthorizationContext` 也没有可与请求绑定校验的授权项目 ID。
- **潜在后果：**持有 Runtime 令牌的本机调用方可任选 `projectId` 读取项目索引，即使授权状态暂停或时间窗失效。
- **缓解因素：**正常 Java Agent 入口会先校验当前用户对项目的访问权；主要风险来自直接 Runtime 调用、令牌泄露或开发模式无令牌。

### R-04 Runtime 认证默认 fail-open，索引接口缺少项目级授权

- **风险等级：中**
- **代码位置：**[`config.py:17`](ai-runtime/app/config.py#L17)、[`security.py:9`](ai-runtime/app/security.py#L9)、[`main.py:102`](ai-runtime/app/main.py#L102)、[`run.ps1:10`](ai-runtime/run.ps1#L10)
- **风险描述：**Runtime 默认监听回环地址，但 token 默认空；空 token 时所有敏感端点直接允许。索引管理接口只验证进程级 bearer token，不验证调用主体对具体项目的访问权。
- **潜在后果：**同机恶意进程可伪造授权快照、读取、覆盖或删除任意项目索引，并触发无守卫的本地咨询检索。
- **缓解因素：**打包入口限制为回环地址；风险主要位于本机威胁模型和开发启动方式。

### R-05 Java、Python 与 LangGraph 状态源不一致

- **风险等级：高**
- **代码位置：**[`AiConversationMemoryService.java:32`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiConversationMemoryService.java#L32)、[`AgentOrchestrator.java:117`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AgentOrchestrator.java#L117)、[`AgentOrchestrator.java:497`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AgentOrchestrator.java#L497)、[`indexing.py:323`](ai-runtime/app/indexing.py#L323)、[`indexing.py:411`](ai-runtime/app/indexing.py#L411)
- **风险描述：**Java 会话窗口是进程内 Map，重启即丢失；LangGraph state 只存在于单次请求；Python 对话摘要则持久化在项目索引。`conversationId` 没有参与 Python 查询，Java 清会话也不会删除 Python 摘要。
- **潜在后果：**同项目会话 B 可能检索到会话 A 的持久摘要；Java 已淘汰或清除的记忆仍留在 Python；重启前后上下文行为不一致。Planner 失败时 Java 已写入 user turn、但未写 assistant turn，也会留下半个会话状态。
- **边界结论：**未发现正常 Java 入口下的跨项目读取，但 Python 持久记忆不具备会话隔离。

### R-06 Planner 到 Harness 缺少统一强 Schema

- **风险等级：中**
- **代码位置：**[`model.py:68`](ai-runtime/app/model.py#L68)、[`model.py:188`](ai-runtime/app/model.py#L188)、[`model.py:322`](ai-runtime/app/model.py#L322)、[`AiPlanningService.java:275`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiPlanningService.java#L275)、[`AiAgentRuntimeClient.java:451`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiAgentRuntimeClient.java#L451)
- **风险描述：**Python 通过正则从 Markdown 或任意文本中提取 JSON；参数被统一转为字符串；未知 action 被静默丢弃。解析失败会自动切规则 Planner。Java Runtime 客户端使用通用 `JsonNode/Map`，允许 actions/steps、SSE/NDJSON 等多种宽松格式，没有事件版本、必填字段和终态 Schema。
- **潜在后果：**合法与非法 action 混合时只执行合法子集；错误类型被重写；缺失 finish 的中间 plan 仍可能被接受；畸形 LLM 输出可能切规则 Planner 后生成另一套可执行计划，而不是 fail closed。

### R-07 Python 端口守卫存在 fail-open 解析

- **风险等级：中**
- **代码位置：**[`authorization.py:21`](ai-runtime/app/authorization.py#L21)、[`authorization.py:42`](ai-runtime/app/authorization.py#L42)、[`graph.py:414`](ai-runtime/app/graph.py#L414)
- **风险描述：**非法端口 token 被静默忽略；跨度超过 1024 的范围只展开首尾；空解析结果被当作没有端口要求。
- **潜在后果：**授权仅含 `1,65535` 时，请求 `1-65535` 可在 Python 被误判为允许；混入非法 token 的端口请求也可能通过 Python Guard。
- **缓解因素：**Java Dispatcher 会重新规范化并验证端口全集，通常可以阻止外部扫描越界，但 Python 守卫结论和审计事件不可信。

### R-08 安全政策分散且语义已经分叉

- **风险等级：中**
- **代码位置：**[`graph.py:343`](ai-runtime/app/graph.py#L343)、[`model.py:42`](ai-runtime/app/model.py#L42)、[`AiAuthorizationGuard.java:45`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiAuthorizationGuard.java#L45)、[`AiTaskDispatchService.java:27`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiTaskDispatchService.java#L27)
- **风险描述：**Python 和 Java 分别维护工具集合、项目状态、目标、端口、审批和配额规则。Python 仅对高风险 action 要求审批；Java 对任何工具执行都要求 `execute=true`。Python 重试使用旧授权快照，Java 使用数据库当前状态。
- **潜在后果：**两端对同一计划产生 `AUTHORIZED`、`APPROVAL_REQUIRED` 或 `DENIED` 的不同结论；前端阶段状态和最终执行结果不一致；政策更新时容易漏改一端。

### R-09 重试有界但可能重复成功动作

- **风险等级：中**
- **代码位置：**[`graph.py:581`](ai-runtime/app/graph.py#L581)、[`graph.py:612`](ai-runtime/app/graph.py#L612)、[`graph.py:674`](ai-runtime/app/graph.py#L674)、[`graph.py:767`](ai-runtime/app/graph.py#L767)
- **风险描述：**同组 `asyncio.gather` 任一 action 异常后，整个阶段 actions 都被加入失败集合；重试会重复已经成功的 sibling。重试计数在调用方和 `_retry_node` 各增加一次，事件值与最终 state 不一致。
- **潜在后果：**当前仅会重复检索或提案，但未来接入有副作用工具后会形成放大的重复执行；审计重试次数不准确。
- **循环结论：**Python `maxRetries` 被限制在 0-3，未发现无限循环。Java Agent 本身不自动重试，但系统级手工重试入口没有 Agent 配额和 lineage 总次数限制。

### R-10 Executor 信任普通 state，缺少不可伪造的 Guard 决策

- **风险等级：中**
- **代码位置：**[`graph.py:500`](ai-runtime/app/graph.py#L500)、[`graph.py:699`](ai-runtime/app/graph.py#L699)、[`tools.py:25`](ai-runtime/app/tools.py#L25)
- **风险描述：**`_executor_node` 接受普通字典 `actions_override`，只检查 state 中的 violation/approval 列表；底层工具不重新校验 action digest 或策略版本。
- **潜在后果：**当前公共 `stream()` 路径尚无直接外部注入点，但未来引入 checkpoint、resume、动态节点或直接调用 Executor 时容易形成结构性绕过。

### R-11 Python 与 Java 同时承担 Agent 执行循环

- **风险等级：中**
- **代码位置：**[`graph.py:218`](ai-runtime/app/graph.py#L218)、[`AgentOrchestrator.java:52`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AgentOrchestrator.java#L52)
- **风险描述：**Python Graph 管理阶段、守卫、审批、Executor、Retry 和 Reviewer；Java Orchestrator 同时管理规划、阶段事件、守卫、派发、Reviewer 和重试提示。
- **潜在后果：**同一 Agent turn 存在两套阶段和状态解释；某一侧新增重试、审批或恢复能力时，另一侧可能仍按旧语义继续执行。

## 5. 不改变整体架构的修复建议

| 对应风险 | 修复建议 |
|---|---|
| R-01 | 废弃 `/dispatches*`，或将其改为只生成计划；所有任务创建统一进入 `AiAuthorizationGuard -> SecurityAgentTools -> TaskService`。同时统一 ADMIN/项目角色要求。 |
| R-02 | 使用数据库事务实现 `quota reserve -> batch create -> consume/release`；为 Agent turn 增加幂等键，批量失败整体回滚。 |
| R-03/R-04 | 所有 RAG 读取也作为受控 action；Runtime 启动必须生成强随机 token。项目索引接口增加由 Java 签发的项目级短期凭据。 |
| R-05 | 将项目知识库与会话记忆分集合；检索强制 `(projectId, conversationId)` metadata filter；清会话和 TTL 淘汰时发送幂等 tombstone。 |
| R-06 | 建立共享的判别联合 JSON Schema，每个工具拥有独立参数模型，`additionalProperties=false`；模型使用 structured output。执行请求的解析异常必须 fail closed。 |
| R-07 | 使用区间包含算法验证请求范围完全属于授权区间并集；出现任何非法 token 时拒绝整个参数。 |
| R-08 | Java 保持唯一业务授权判定源；Python 只验证带版本的授权决策，或将共享政策生成成两端代码，禁止手工维护两份常量。 |
| R-09 | 逐 action 收集结果，只重试失败项；统一一处递增 retry count；加入 action 幂等键和整个 lineage 的执行预算。 |
| R-10 | Executor 只接受绑定 action digest、项目、目标、参数、策略版本和过期时间的 decision token，移除裸 `actions_override`。 |
| R-11 | 保留现有部署形态但指定一个生命周期事实源；统一 `runId`、`stateVersion`、`policyRevision` 和终态协议。 |

## 6. 测试覆盖分析

### 6.1 已有覆盖

- Python：30 个测试通过，主要覆盖授权 helper、规则 Planner、索引、审批、一次失败重试和 Graph 组件。
- Java AI 包：13 个测试类、52 个测试通过，主要覆盖 Java Planner、Dispatcher、AuthorizationGuard、ModelClient 和旧派发流。
- Java 单体集成测试覆盖 `/api/ai/plans`、`/api/ai/dispatches`、`/api/ai/dispatches/stream`。

以上结果只能证明组件和规则降级路径的当前行为。

### 6.2 关键缺口

1. Python 唯一 mock-LLM Graph 测试 [`test_runtime.py:120`](ai-runtime/tests/test_runtime.py#L120) 返回 `actions=[]`，没有 actionable plan 穿过 Guard、Executor、Retry 和 Java proposal。
2. 未发现 `AiAgentRuntimeClientTests`，没有真实 SSE/NDJSON 契约测试。
3. 未发现 `AiConversationMemoryServiceTests`，没有会话跨项目、跨目标、TTL、并发淘汰和重启测试。
4. 未覆盖 `/api/ai/agent` 或 `/api/ai/agent/stream` 的完整 Spring + Python 链路。
5. 没有恶意幻觉、提示注入、未知工具、错误参数和混合计划的端到端负面测试。
6. 没有规则 Planner 与 LLM Planner 的安全结论差分测试。
7. Java AuthorizationGuard 单测大量 mock `dispatcher.prepare` 和授权目标对象，未验证真实组合守卫链。

### 6.3 必须新增的测试

#### 组件单元测试

- Planner Schema：未知字段、未知工具、错误类型、重复 key、围栏 JSON、超长/嵌套参数、缺失字段、非法枚举。
- 端口守卫：不连续授权区间、大范围、非法 token 混入、数组、空值、端口别名。
- Guard：项目暂停/过期、目标撤销、审批过期、配额不足、混合合法与非法 action 必须整体拒绝。
- Memory：同 session 跨项目/目标拒绝；同项目不同 conversation 不可互读；TTL、容量淘汰、清除和重启语义。
- Retry：永久失败严格最多 `1 + maxRetries`；成功 sibling 不重试；事件计数等于最终 state。

#### 完整 Harness 测试

- mock LLM 输出合法 actionable plan，完整经过 Python Graph、授权、提案、SSE、Java Guard、任务落库、Audit 和 Reviewer。
- mock LLM 输出高风险伪装 SAFE、Shell/命令参数、越权目标/端口和混合计划，断言无任务创建。
- Runtime 中途撤销授权、目标停用或消耗最后一个配额，重试必须获取新 policy revision 并拒绝旧决策。

#### 跨语言端到端测试

- 同时启动 Java 和 Python，测试 SSE 分片、断流、超时、无 finish、未知事件类型、NDJSON 适配和错误状态。
- 验证 Java 发送的项目、会话、目标、审批和配额与 Python 返回的 plan/finish 字段一一对应。
- 并发提交多个 Agent turn，验证原子配额、幂等派发和审计关联 ID。

#### 降级模式差分测试

- 对否定句、短确认、历史执行意图、模糊请求、项目介绍和高风险幻觉，同时运行规则 Planner 与 mock LLM Planner。
- 两种 Planner 可以生成不同业务计划，但必须得到相同的授权、审批、端口、配额和最终执行结论。

## 7. CI 与降级模式结论

默认配置启用 Runtime：[`AiAgentRuntimeClient.java:57`](security-toolbox-server/src/main/java/com/bachelor/toolbox/ai/AiAgentRuntimeClient.java#L57)。但 CI 在 [`.github/workflows/ci.yml:95`](.github/workflows/ci.yml#L95) 显式设置：

```yaml
AI_ENABLED: "false"
AI_RUNTIME_ENABLED: "false"
```

Python 测试又在独立作业中运行，没有启动 Java。发布工作流同样关闭 Runtime 后执行 Java 测试。

因此当前 CI 结论只能表明：

- Java 规则 Planner 和旧派发路径在测试环境中可运行；
- Python 组件测试可独立运行；
- 不能证明默认部署使用的 `LLM/Runtime -> LangGraph -> SSE -> Java AgentOrchestrator -> SecurityAgentTools -> TaskService` 路径正确；
- 更不能证明恶意 Planner 输出、跨语言异常、并发配额和记忆隔离满足安全要求。

**规则 Planner 通过 CI 不等价于 LLM + Harness 路径通过验证。当前完整跨语言主路径的自动化验证数量为 0。**

## 8. 最终审查意见

建议在继续扩充 Agent 工具前，优先完成以下三项：

1. 关闭旧派发入口对 Harness 的绕过，并将配额改为原子预留。
2. 建立统一强 Schema 和 Java 签发的版本化授权决策，消除 Python 业务政策副本。
3. 将默认启用的 Java-Python Agent 主路径纳入 CI，并加入 actionable mock-LLM、恶意输入和并发负面测试。

完成以上项目后，当前架构可以在不改变 Planner + Harness 总体设计的前提下，形成可证明、可审计且难以绕过的执行边界。

## 9. 2026-08-07 整改完成复核

本节记录整改后的最终状态；第 1～8 节作为原始审查证据保留，不删除、不改写历史结论。

### 9.1 原报告问题闭环

- R-01：旧 AI dispatch 旁路已删除，AI 副作用任务统一进入 `SecurityAgentTools.executeAuthorizedPlan`。
- R-02/R-07：Java 使用事务内授权、项目/目标悲观锁、区间包含、原子配额、Turn 幂等、批次回滚和 after-commit 派发。
- R-03/R-04/R-05：Runtime token fail-closed，项目签名密钥分离；检索和记忆绑定 project、target、conversation、TTL/LRU 与 tombstone。
- R-06：Python Planner、Grounded Planner 和 Java v2 Client 均使用严格判别联合、字段白名单、重复 key/深度/长度/枚举校验。
- R-08/R-10：Python 只执行只读检索和生成 Java proposal；授权字段由签名请求注入，所有副作用仍由 Java 数据库事实与 Guard 决定。
- R-09/R-11：检索循环、重试、事件版本和终态均有硬上限；跨语言统一 `runId/stateVersion/policyRevision/contractVersion=2`。
- CI 已真实启动 mock OpenAI、Python LangGraph Runtime 和 Java Harness，不再用规则 Planner 替代主链路证明。

### 9.2 v2 终审新增问题闭环

| 终审问题 | 最终控制 |
|---|---|
| route 可被矛盾 final plan 覆盖 | Java 绑定 route intent 与 plan intent、knowledge mode、actions、Evidence 和终态语义 |
| 未验证中间事件提前外泄 | 最多 64 条整流缓冲；完整 Schema/FSM/成功终态通过后发布，拒绝和异常零转发 |
| Runtime 异常或 `RAG_DISABLED` 降级可执行 | fallback 仅允许只读回答或预览，`execute=true` 在 Java Guard 前 fail-closed |
| `finish.answer` 未绑定 grounded plan | Python 使用单一 answer 来源；Java 精确比较 `finish.answer == plan.answer` |
| 派发后异常记录为未执行 | 持久保留真实 `executed/taskIds`，失败事件禁止新 Turn 盲目重试 |

### 9.3 最终验证

- Python 全量：`123 passed`。
- Java v2 Client + Orchestrator 安全定向：`49 passed`。
- Java 全量：`418 tests`，`0 failures`，`0 errors`，`4 skipped`。
- 真实 Java + Python + mock LLM E2E：`4 passed`。
- 前端 JSON/离线边界测试与生产构建：通过。
- `pip check`、Python AST、CI YAML 和 `git diff --check`：通过。

当前仍保留两个明确的未来工作，不属于本轮 P0/P1 完成定义：conversation tombstone 持久 outbox，以及任务完成回调驱动的跨回合 Agent 恢复。
