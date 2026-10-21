# 獬豸（Xiezhi）授权安全测试平台

獬豸是一个面向自建靶场、局域网资产和已书面授权目标的本地 Web/Electron 安全测试平台。系统围绕“先确认授权边界，再执行受控测试”设计，覆盖项目、授权目标、信息收集、受控检测、漏洞复测、流量分析、审计和报告。

## 快速启动

环境要求：Windows 10/11 x64、JDK 17、Maven、Node.js、Python 3.11+。

首次安装前端依赖：

```powershell
npm --prefix .\security-toolbox-web ci
```

启动桌面版：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-desktop.ps1
```

启动浏览器开发模式：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-all.ps1
```

停止服务和查看状态：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\stop-all.ps1
powershell -ExecutionPolicy Bypass -File scripts\status-all.ps1
```

浏览器开发模式默认访问 `http://localhost:5173`，后端 API 默认使用 `http://localhost:8080/api`。桌面版只监听本机回环地址。

### 数据库模式（自动切换）

后端默认使用内置 H2 数据库（`./data/security-toolbox`）。`start-all.ps1` 启动时会自动探测本机 PostgreSQL：

- 检测到 `127.0.0.1:5432`（可用 `DB_HOST`/`DB_PORT` 覆盖）有可用 PostgreSQL，**且**设置了 `POSTGRES_PASSWORD` 环境变量，则自动以 `postgres` profile 启动，连接 `security_toolbox` 数据库。
- 未检测到 PostgreSQL 或未提供 `POSTGRES_PASSWORD`，则回退使用内置 H2，不阻塞启动。
- 设 `$env:TOOLBOX_USE_POSTGRES='0'` 可强制禁用 PostgreSQL，始终使用 H2。

需要数据库实例时，用仓库根目录的 `compose.yaml` 启动：

```powershell
docker compose up -d postgres
```

务必保证 `compose.yaml` 中的 `POSTGRES_PASSWORD` 与启动脚本读取的 `POSTGRES_PASSWORD` 一致。

依赖检测页面会显示「当前数据库：PostgreSQL / H2」，方便确认后端实际使用的存储。

## 主要能力

- 项目和授权目标治理，包括授权声明、有效期、状态和端口范围。
- DNS、HTTP、TLS、指纹、Nmap、Nuclei、Afrog、Xray 等受控检测。
- 异步任务、取消、重试、依赖 DAG、授权快照和执行前复核。
- Finding 管理、复测、扫描 Diff、审计和 HTML/PDF 报告。
- HTTP(S) 回环代理、MITM、流量分析、脱敏和受控重放。
- AI 项目资料检索、证据化问答、结构化计划和 Java 授权执行。
- 浏览器本地离线编码、哈希、报文、文件和授权测试辅助工具。

## AI 方案与执行确认

项目中的“执行确认与审计”统一管理 AI 方案、管理员确认和执行记录。用户向 AI 提出检测需求后，可执行方案先保存为待确认记录；管理员查看目标、工具和参数后选择“确认并执行”或“拒绝执行”。聊天中的执行请求不会直接创建任务，纯咨询仍只返回解释或建议。

确认后执行服务端保存的原计划，不重新调用模型生成另一份方案；执行前再次核验项目、目标授权和有效期。拒绝或关闭确认窗口不会创建任务，重复恢复同一条记录不会重复派发。

同一会话中可以明确要求追加检测、移除步骤或调整参数，例如“加上目录扫描”。修订后的方案需要重新确认，不会修改或继承旧审批的决定。仅要求修改方案、不执行时只交付新方案；随后确认执行会核对最新成功交付的版本，不允许模型在确认时自行更改工具或参数。引用材料和历史消息中的修改指令不作为本轮授权。

旧的“申请审批”和“申请高风险行动”人工入口已停用。历史审批及人工行动记录保留用于审计，历史人工行动的开始、完成和回滚只登记状态与证据，并不自动执行检测或利用。AI 服务账号仅表示方案来源，没有登录或确认执行权限。

## 使用要求

- 只测试自有或明确获得授权的目标。
- 默认限制回环、链路本地和局域网目标，不支持任意公网扫描。
- 当前版本不提供漏洞利用、爆破、钓鱼、横向移动或破坏性自动化能力。
