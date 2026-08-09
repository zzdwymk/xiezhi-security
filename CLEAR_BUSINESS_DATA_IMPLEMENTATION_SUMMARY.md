# 业务数据清空功能实现总结

## 功能入口

- 设置页新增“危险操作”区域和“清空业务数据”按钮。
- 仅 `ADMIN` 角色可调用后端接口。前端使用风险说明和手输 `CLEAR` 的两步确认，后端仍会严格校验。
- 接口：`DELETE /api/settings/data`，请求体为 `{"confirmation":"CLEAR"}`。
- 成功响应包含 `clearedAt`、`deletedRecords`、`auditLogRetained`，并返回清理项目数和 Runtime 索引文档数。

## 清理范围

数据库使用一次 `SERIALIZABLE` 事务，按依赖顺序删除：

- AI 派发记录、AI 对话会话。
- 流量建议、流量包、流量会话。
- 安全动作、后扫描路径、发现、扫描计划、项目审批、信息收集结果、指纹探测结果。
- 清理旧审计日志后，在同一事务中保留一条 `CLEAR_BUSINESS_DATA` 成功审计记录。
- 有任一表删除或审计写入失败，数据库事务回滚。

## 保留范围

`app_users` 、`agent_workflow_spec` 、`detection_rules` 、`vulnerability_definitions` 、`traffic_capture_filters` 以及桌面 AI/API/外观/导航设置不受影响。成功后前端另外清理 AI 对话、Copilot 草稿、流量聊天和仪表盘目标缓存，保留登录令牌和应用偏好。

## 安全与并发

- 存在 `PENDING/RUNNING` 任务，或存在实例/数据库状态为 `STARTING/RUNNING` 的流量会话时拒绝清空。
- 引入业务数据操作读写栅栏：普通 API 写入、扫描计划调度、任务工作线程和 AI Agent 共享读锁，清空操作获取独占写锁。
- Runtime 索引按项目和 `project/target/task/finding/recon/probe/conversation` 来源逐一清理。每次请求必须返回非负整数 `deleted`，不完整回执会失败并保留数据库记录以便重试。

## 测试验证

- Java 全量：`433 tests`, `0 failures`, `0 errors`, `4 skipped`。
- 前端：`npm run build`、`npm run test:json-file` 、`npm run test:offline` 通过。
- 设置页视觉冒烟：`npm run test:visual` 通过，包含桌面和窄屏多尺寸。
- `git diff --check` 通过；工作区中的 CRLF 提示为既有换行风格警告。
