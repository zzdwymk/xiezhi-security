# Planner + Harness 重构与安全整改总结

> 完成日期：2026-08-07  
> 对应审查：`PLANNER_HARNESS_SECURITY_REVIEW.md`  
> 涉及模块：`ai-runtime`、`security-toolbox-server`、`security-toolbox-web`、CI

## 1. 本轮目标

本轮工作围绕以下目标展开：

1. 确认项目真正采用 `LLM + Harness`，而不是仅调用 LLM 或保留可绕过 Harness 的执行入口。
2. 在保持现有界面布局和业务功能的前提下，收敛 Planner、授权、执行、审计和记忆边界。
3. 修复 `PLANNER_HARNESS_SECURITY_REVIEW.md` 中 R-01 至 R-11 指出的问题。
4. 补充严格 Schema、并发事务、记忆隔离和真实跨语言 Harness 测试。
5. 将默认启用的 Java + Python + LLM 主链路纳入 CI。

## 2. 最终架构

当前 Agent 主链路为：

```text
OpenAI-compatible LLM
  -> ChatOpenAI
  -> strict Planner schema
  -> LangGraph Harness
  -> versioned SSE/NDJSON contract
  -> Java Runtime Client
  -> Java Authorization Guard
  -> SecurityAgentTools transaction
  -> Task persistence + Audit
  -> after-commit asynchronous execution
```

架构边界如下：

- Python 负责 LLM 规划、受控项目检索、防御性预检、重试和 Java 工具提案。
- Python 不执行 Shell、扫描器或其他外部副作用。
- Java 是项目授权、目标授权、审批、配额、幂等、任务、审计和执行状态的唯一事实源。
- 所有 AI 任务创建统一进入 `SecurityAgentTools.executeAuthorizedPlan`。
- Java Guard 会在事务内基于数据库当前状态重新校验，不信任 Python 提供的授权快照。

## 3. 主要整改

### 3.1 关闭 Harness 绕过入口

- 旧 `/api/ai/dispatches` 和 `/api/ai/dispatches/stream` 统一返回 `410 Gone`。
- 删除 `AiDispatchStreamingService` 及其测试。
- `AiTaskDispatchService` 收缩为纯计划校验和规范化组件，不再公开任务创建能力。
- AI 任务只能由 `SecurityAgentTools` 在 Guard 和事务边界内创建。

### 3.2 原子授权、配额和幂等

- 对项目和目标使用固定顺序的悲观锁，避免并发请求穿透活动任务配额。
- Guard、配额检查、批量任务创建、Audit 和 dispatch 幂等记录位于同一事务。
- 批量创建任一环节失败时整体回滚，不留下部分任务。
- `turnId` 改为执行请求必填，不再使用 `sessionId + prompt` 作为降级幂等键。
- 同一个 Turn 重试返回已有任务，不重复创建或重复入队。
- 异步执行只在事务成功提交后启动。

### 3.3 严格 Planner 与协议

- Planner 使用严格判别联合 Schema，每个工具拥有独立参数模型。
- 禁止未知字段、未知工具、错误参数类型、重复 JSON key、Markdown 围栏和宽松文本提取。
- 合法与非法 action 混合时整体拒绝，不静默保留合法子集。
- 协议违规、HTTP 4xx、未知事件、状态版本跳跃、无 finish、`DENIED` 和 `FAILED` 全部 fail-closed。
- `execute=true` 时，带 actionable plan 的 `APPROVAL_REQUIRED` 终态不能进入 Java 执行。
- 外层事件传播 `contractVersion`、`runId`、`stateVersion` 和 `policyRevision`。

### 3.4 Runtime 与项目级认证

- Runtime bearer token 从默认 fail-open 改为必须配置。
- Runtime token 与项目 HMAC 签名密钥完全分离。
- Java 为每个项目、scope 和短有效期签发项目凭据。
- Electron 分别生成并保存两种凭据，使用权限受限文件传给 Java 和 Python。
- 已验证仅获得 Runtime bearer token 的调用方无法伪造项目授权签名。

### 3.5 检索和 Executor 边界

- 所有项目检索统一建模为 `retrieve_project_context` action，必须经过 Graph Guard。
- 检索绑定 `projectId`、`targetId` 和 `conversationId`，避免跨项目或跨会话读取。
- 端口参数使用严格区间包含算法；非法 token、超大范围或部分越界整体拒绝。
- Executor 只接受绑定 action digest、项目、目标、策略版本和过期时间的 HMAC 决策。
- 重试只包含失败 action，不重复已经成功的 sibling；计数集中在一个位置且总预算有界。

### 3.6 会话记忆持久化与生命周期

- Java 会话记忆从进程内 Map 扩展为 JPA 持久化，服务重建后可以恢复 transcript。
- 会话严格绑定项目和目标，禁止复用同一 session 访问其他 scope。
- clear 使用 tombstone 同步删除 Python conversation 文档。
- open、clear、TTL 和 LRU 使用统一 `lifecycleMonitor -> session.monitor` 锁顺序。
- TTL/LRU 淘汰会在持有 session 锁后重新检查状态，避免与并发 persist 竞争并复活旧记录。
- LRU 在并发 save 后重新读取实际最老记录，只删除最终确认的候选会话。
- 单条记忆删除在 Python project lock 内原子校验 `source=conversation`；不能借记忆接口删除普通项目资料。

### 3.7 CI 与真实 Harness

- 新增本地 OpenAI-compatible mock 服务，并校验 Bearer、模型和 messages 请求体。
- CI 真实启用 `AI_RUNTIME_LLM_ENABLED=true`。
- 健康检查解析 JSON 字段，不依赖字符串空格格式。
- E2E 失败时同时上传 Runtime、mock OpenAI 和 Java Surefire 日志。
- CI 已证明以下正向链路：

```text
mock OpenAI
  -> ChatOpenAI
  -> strict Planner
  -> LangGraph Harness
  -> Java Runtime Client
  -> Java Guard
  -> SecurityAgentTools transaction
  -> Task + Audit + after-commit queue
```

- CI 还覆盖恶意混合计划：LLM 同时返回合法扫描和 `shell_exec` 时，严格 Schema 将其整体转换为安全停止空计划，最终无任务、无派发审计、无异步执行。

## 4. 安全审查闭环

| 风险 | 最终状态 | 处理结果 |
|---|---|---|
| R-01 | 已关闭 | 旧派发入口返回 410，任务创建统一进入 Java Harness。 |
| R-02 | 已关闭 | 悲观锁、事务配额、批量回滚和 Turn 幂等。 |
| R-03 | 已关闭 | 项目检索成为 Guard action，并绑定项目、目标和会话。 |
| R-04 | 已关闭 | Runtime fail-closed，项目签名密钥与 bearer token 分离。 |
| R-05 | 已关闭主要风险 | 会话持久化、隔离、TTL/LRU 并发和原子 source 删除。 |
| R-06 | 已关闭 | 严格 Planner、事件和终态 Schema，协议异常不降级执行。 |
| R-07 | 已关闭 | 严格端口区间解析和完整包含校验。 |
| R-08 | 接受低风险残余 | Python 仅保留防御性预检，Java 是最终授权源。 |
| R-09 | 已关闭主要风险 | 失败项重试、计数一致、预算有界和 Turn 防重复。 |
| R-10 | 已关闭 | Executor 使用绑定 action 和 policy 的签名决策。 |
| R-11 | 接受低风险残余 | Python 仅生成提案，唯一副作用和生命周期事实源在 Java。 |

最终复核未发现 R-01 至 R-11 的剩余安全阻断项。

## 5. 新增和增强的测试

测试覆盖包括：

- Planner 重复 key、未知字段、未知工具、错误参数类型和混合计划。
- 项目暂停、授权过期、目标撤销、审批不足、配额不足和端口越界。
- SSE 分片、NDJSON 分片、未知事件、无 finish、状态版本和终态拒绝。
- `DENIED`、`FAILED`、actionable `APPROVAL_REQUIRED` 的 fail-closed 行为。
- Runtime 不可用时 Java Planner 仍必须经过 Guard，Guard 拒绝时零工具调用。
- 原子配额、并发 Turn、批次回滚、幂等任务和 after-commit 调度。
- 会话跨项目/目标隔离、TTL、LRU、clear、持久恢复和 tombstone。
- TTL/LRU 与正在进行的 persist 并发时不会误删或复活会话。
- 普通项目资料不能通过记忆删除 API 删除。
- 真实 LLM + LangGraph + Java Harness 正向 E2E。
- 恶意混合 LLM 计划的跨语言零副作用 E2E。

## 6. 最终验证结果

| 验证项 | 结果 |
|---|---|
| Python `python -m pytest -q` | 63 passed |
| Java `mvn -B -ntp verify` | 380 tests，0 failures，0 errors，3 skipped |
| 真实 Java/Python/LLM Harness E2E | 3 passed，0 skipped |
| 会话持久化和并发定向测试 | 10 passed；并发用例额外重复 3 轮通过 |
| 前端 `npm run test:json-file` | 通过 |
| 前端 `npm run test:offline` | 通过 |
| 前端 `npm run build` | 通过 |
| CI YAML 和 mock Python 语法 | 通过 |
| `git diff --check` | 通过，仅有本地 LF/CRLF 提示 |

验证结束后已关闭本轮 mock OpenAI 和 Python Runtime 测试进程，端口 `18091`、`18092` 无监听，临时凭据启动脚本已删除。

## 7. 当前保留的低风险事项

以下事项不构成本轮安全阻断：

1. Runtime 连接失败、超时或 HTTP 5xx 时仍可使用 Java Planner；降级计划仍必须重新经过 Java Guard 和 `SecurityAgentTools`，不能绕过 Harness。
2. Runtime 不可用时 conversation tombstone 为 best-effort；如需严格的跨进程最终一致性，可增加持久 outbox 和重试消费者。
3. 失败 Agent turn 会保留 user 消息，用户重试时可能出现重复上下文，但不会扩大授权范围。
4. 普通任务的手工重试没有计入 Agent lineage 总预算，但每次仍会重新校验项目、目标和任务授权。

## 8. 后续建议

当前不建议继续进行大规模架构重写。现有结构已经形成清晰的 Planner、Harness 和 Java 执行边界。后续优化应按实际部署需求选择：

1. 多实例部署前，为会话 tombstone 增加数据库 outbox、重试和消费幂等。
2. 如果产品要求 Python LangGraph 绝对必经，可将 `execute=true` 下的 Runtime 网络故障从 Java Planner 降级改为直接 fail-closed。
3. 后续新增 Agent 工具时，必须同时补齐严格参数 Schema、Java Guard、事务执行和恶意输出测试，禁止直接调用 `TaskService.create`。

