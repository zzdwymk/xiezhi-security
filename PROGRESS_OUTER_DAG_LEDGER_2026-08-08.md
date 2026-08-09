# 外层 DAG + LedgerAgent 进度与下一步

> 更新日期：2026-08-08
> 范围：ai-runtime、security-toolbox-server、security-toolbox-web
> 状态：主体实现完成，剩余验证/收口阶段

## 一、本轮已完成

### 1. Workflow 项目作用域与不可变版本（已完成）
- Workflow 改为按 `scopeId/projectId` 隔离的追加式 revision。
- 新增 `workflowId / scopeId / revision / specDigest / updatedBy / updatedAt`。
- 服务端对规范化 JSON 计算确定性 `sha256:<64 hex>`，客户端无法伪造元数据。
- 保存总是插入新 revision，不覆盖旧版本。
- 支持按 revision/digest fail-closed 解析快照。
- Agent 同步与流式入口在运行前冻结同一份 snapshot，运行期间保存新版本不会漂移。
- 新增 `GET/PUT /api/ai/workflow?projectId=...`。
- 验证：`AgentWorkflowSpecServiceTests` 10/10、`AiControllerWorkflowTests` 3/3，编译通过。

### 2. Python 严格 Workflow 契约（已完成）
- `WorkflowStep` 强制 `nodeId`、`extra="forbid"`、工具级参数模型、`dependsOnNodeIds` DAG 校验。
- Snapshot 元数据：`workflowId / workflowRevision / workflowDigest / outerNodeId / nodeRunId`。
- grounded 模型只能提出 `workflowNodeId + typed parameters + evidenceRefs`。
- Python 闭包覆盖 `tool / risk / requiresApproval / group / dependsOnNodeIds`。
- Workflow manifest 注入 LLM 与规则回退；QA 路由拒绝 action；内部检索节点不能变成外部动作。

### 3. Python v3 事件与公开图（已完成）
- `contractVersion=3`，每个事件带 `workflowDigest / outerNodeId / nodeRunId / innerStep / ledgerSequence / ledgerEntryDigest`。
- 候选摘要链从 `sha256:<64 个 0>` 开始，支持连续性、上下文一致性与篡改检测。
- 公开事件数据剔除 Prompt、CoT、Evidence 正文/片段、Token、凭据类字段。
- `/agent/graph` 只暴露 LedgerAgent 黑盒；`/agent/graph/debug` 需显式开关 + runtime token。
- 验证：Python 全量 134 passed，关键路径 3 passed，compileall 与 diff check 通过。

### 4. Java 权威 Ledger（已完成）
- `AgentLedgerRecord / AgentLedgerRecordRepository / AgentLedgerService`。
- 唯一约束 `(runId, nodeRunId, sequence)`，严格连续 sequence。
- 幂等重复处理、canonical SHA-256 追加式 hash chain、终态后追加拒绝。
- 独立审计修正通道；不保存 Prompt、CoT、Token、凭据、Evidence 正文。
- `appendBatch` 支持“已存在条目 + 新条目”的原子幂等追加。
- 验证：`AgentLedgerServiceTests` 8/8。

### 5. Java Harness 与真实 DAG（已完成）
- `AiPlanResponse.PlanStep` 增加 `workflowNodeId / group / dependsOnNodeIds / risk / requiresApproval / evidenceRefs`。
- `AiAgentRequest` 增加 `outerNodeId / nodeRunId`，Java 固定外层节点 `ledger-agent`，nodeRunId 由项目 + turn + workflow digest 确定性生成。
- Workflow 归一化计算最近上游工具依赖；旧 workflow 生成确定性节点 ID 与 group 依赖。
- Runtime Client 透传快照元数据与依赖字段；未知节点、工具不匹配、外部依赖闭包不完整时拒绝计划。
- Java 覆盖模型提供的 risk / group / approval / dependencies。
- `SecurityAgentTools` 幂等 key / request digest 纳入 workflowDigest。
- 验证：`AiWorkflowClosureTests`、`WorkflowTaskDependencySchedulerTests` 通过。

### 6. 任务依赖 DAG 调度（已完成）
- `SecurityTask` 增加 workflowDigest、workflowNodeId、nodeRunId、workflowGroup、dependencyTaskIds、effectiveRisk、workflowApprovalRequired。
- 根任务 PENDING，后继任务 BLOCKED；仅全部前驱 SUCCESS 后启动。
- 前驱失败/超时/拒绝/取消/跳过时后继 SKIPPED。
- 启动恢复重扫 BLOCKED；`TaskExecutionService` 只执行 PENDING，防重放。
- 业务数据清理同时清空 Ledger 与 Workflow revision 表。

### 7. LedgerAgent 门面（本轮新增，逻辑完成，待回归）
- `schemas.py` 新增 `LedgerAgentContext / LedgerAgentBudget / LedgerAgentResult`。
- `AgentRequest = LedgerAgentContext` 保留兼容。
- `graph.py` 新增 `LedgerAgentRuntime`（`SecurityAgentRuntime` 保留兼容别名），新增 `invoke()` 返回有限结果模型。
- context 的 `budget` 会收紧 `maxRetrievalRounds / maxLlmCalls / timeoutSeconds`。
- Java 请求体已带默认 budget。
- 现有 Python 关键测试集已重新跑通：`test_runtime.py + test_agentic_rag_graph.py + test_harness_security.py` 71 passed。

### 8. Java v3 Runtime 收口（代码已写，测试待更新）
- `CONTRACT_VERSION=3`，顶层字段白名单加入 workflow/node/ledger 字段。
- `RuntimeEvent` 扩展 workflowDigest、outerNodeId、nodeRunId、innerStep、ledgerSequence、ledgerEntryDigest、terminationReason。
- 流式事件逐一校验运行标识、状态版本、节点一致性和 Python 候选摘要链。
- 完整流通过后才 `persistLedger()` 批量写入 Java 权威 Ledger，再向编排器发布权威摘要。
- 失败/拒绝/澄清终态仍持久化为审计事实；无效/断流/篡改流不写入任何 Ledger 记录。

### 9. Orchestrator v3 贯通（已完成）
- `AiAgentEvent` 新增 Workflow、节点、Ledger、终止原因字段，保留旧构造器。
- `AgentOrchestrator` 透传 v3 元数据，记录最终 Ledger 游标到 done 与审计。
- 递归过滤 Prompt、CoT、凭据、Token、Evidence 正文/片段等敏感字段。
- 验证：`AgentOrchestratorTests` 9/9，含 `AiControllerWorkflowTests` 共 12/12。

### 10. 前端 Workflow 状态贯通（已完成）
- 项目级 Workflow API 调用、revision/digest 展示、Agent 快照选择。
- v3 workflow/node/ledger/termination 事件字段贯通，LedgerAgent 公开状态展示。
- Evidence / Prompt / 内部推理字段按白名单隔离展示。
- 验证：npm build、vue-tsc、json-file/offline/visual 测试通过；布局不变。

## 二、当前风险与事实

- 两个并行子任务（Ledger 恢复接口核对、Python 全量回归）因模型服务 429 中断，未取得其最终结论；相关功能以本地代码为准，尚未被这两份子任务报告背书。
- `AiAgentRuntimeClientTests` 的 fixture 仍是 v2 事件格式，Java v3 回归尚未跑通（编译已通过，运行时测试未更新）。
- Python `LedgerAgentResult` 的 `evidenceRefs` 模型名与 `GroundedParameterPatch` 的字段名可能不匹配，已纳入下一步回归项。
- 已完成的 Java v3 运行时代码尚未做“篡改摘要/断流/重复 nodeRun”专项测试。

## 三、下一步（按顺序）

1. 更新 `AiAgentRuntimeClientTests` fixture 到 v3：
   - request 补齐 workflowId/revision/digest/outerNodeId/nodeRunId；
   - `eventAt()` 输出完整 v3 字段并生成连续候选摘要链；
   - action fixture 补 `workflowNodeId / dependsOnNodeIds`；plan fixture 补 `workflowNodeId / group / dependsOnNodeIds`。
2. 增加 Java v3 专项测试：
   - 候选摘要被篡改 → 拒绝且零 Ledger 写入；
   - 流中断 → 拒绝且零写入；
   - 合法流 → 权威 Ledger 连续、终态后追加拒绝；
   - 同一 nodeRun 幂等重放 → 不产生重复任务/记录。
3. 修正 Python `LedgerAgentResult.evidenceRefs` 与 grounded 输出字段类型，并新增门面测试：
   - `invoke()` 返回有限结果；
   - budget 收紧生效；
   - 敏感数据不出现在结果中。
4. 核对 Ledger 恢复 API：
   - 按 `runId + nodeRunId` 查询、验证链、检测 stale workflow；
   - 不恢复任意 Python 内存状态；
   - 明确前端“可恢复”按钮的触发条件。
5. 跑全量验证：
   - Java：runtime/Ledger/DAG 聚焦测试 → 全量测试 → `git diff --check`；
   - Python：全量 pytest；
   - 前端：build + vue-tsc + 既有测试。
6. 按验证结果更新 `OUTER_DAG_LEDGER_AGENT_TODO.md` 勾选项，不把未验证项标记为完成。

## 四、待办清单

- [x] Java RuntimeClientTests 升级到 v3 并回归通过。
- [x] Java v3 篡改/断流/幂等专项测试。
- [x] Ledger 恢复 API 核对与测试。
- [x] Python LedgerAgent 门面与 budget 测试。
- [x] Python 全量 pytest 回归。
- [x] Java 全量测试回归。
- [x] 前端最终联动验证（v3 事件展示）。
- [x] 更新 TODO 勾选与最终实现总结 MD。

## 五、最终实现总结（2026-08-09 回归完成）

### Java 端（426 tests, 0 failures, 0 errors, 4 skipped）

- RuntimeClientTests v3：request fixture 补齐 workflowId/revision/digest/outerNodeId/nodeRunId，eventAt() 输出完整 v3 字段并生成连续候选摘要链。7/7 通过。
- v3 专项测试：篡改候选摘要拒绝且零 Ledger 写入；流中断拒绝且零写入；合法流权威 Ledger 连续、终态后追加拒绝；同一 nodeRun 幂等重放不产生重复记录。10/10 通过。
- Ledger 恢复 API：AgentLedgerControllerTests 2/2，AgentLedgerServiceTests 13/13 通过。前端通过 event.recoverable 布尔值显示可恢复/不可恢复，触发条件为 RecoveryDecision.resumable == true。
- 全量回归：mvn test 426 个测试全部通过。

### Python 端（138 passed, 2 skipped）

- LedgerAgent 门面：invoke() 返回有限 LedgerAgentResult，budget 收紧 maxRetrievalRounds/maxLlmCalls/timeoutSeconds，敏感数据不出现在结果中。6/6 通过。
- 全量 pytest：138 passed。2 个跳过（langchain_core/langgraph 在当前环境不可用，已添加 importorskip 和 LANGGRAPH_AVAILABLE 跳过条件）。
- graph.py 修复：_fallback_stream 路径缺少 asyncio.timeout 包装，已重构 stream() 方法将回退路径和图路径都包含在 async with asyncio.timeout 块中。

### 前端（build + vue-tsc + 3 项测试全部通过）

- CSS 修复：Setup.vue 的 setup-steps 选中高亮左侧强调线（box-shadow: inset 3px 0）已移除，与启动页 startup.html 的 .step.active 样式一致。修改涉及 setup.css 和 unified-theme.css。
- npm run build：vue-tsc 类型检查通过，vite 构建成功。
- test:json-file / test:offline / test:visual 均通过。

### 结论

全部 8 项待办均已完成并验证通过。v3 事件链、权威 Ledger、DAG 调度、LedgerAgent 门面、恢复 API、前端贯通均已闭环。