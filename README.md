# 獬豸（Xiezhi）授权安全测试平台

面向自建靶场、局域网资产和已书面授权目标的本地安全测试平台。核心设计原则：**先确认授权边界，再执行受控测试**。

## 目录

- [功能特性](#功能特性)
- [技术栈](#技术栈)
- [目录结构](#目录结构)
- [快速开始](#快速开始)
- [数据库](#数据库)
- [端口一览](#端口一览)
- [AI 执行确认](#ai-执行确认)
- [使用限制](#使用限制)

## 功能特性

| 模块 | 能力 |
|------|------|
| 授权治理 | 项目与授权目标管理，授权声明、有效期、状态、端口范围 |
| 信息收集 | DNS、HTTP、TLS、指纹、Nmap、Nuclei、Afrog、Xray 等受控检测 |
| 任务编排 | 异步任务、取消、重试、依赖 DAG、授权快照、执行前复核 |
| 漏洞管理 | Finding 管理、复测、扫描 Diff、审计、HTML/PDF 报告 |
| 流量分析 | HTTP(S) 回环代理、MITM、流量分析、脱敏、受控重放 |
| AI 助手 | 项目资料检索、证据化问答、结构化计划、Java 授权执行 |
| 离线工具 | 浏览器本地编码、哈希、报文、文件、授权测试辅助 |

## 技术栈

| 层 | 技术 |
|----|------|
| 后端 | Spring Boot 3.5、Java 17、Spring Data JPA、Spring Security、JJWT |
| 前端 | Vue 3.5、Vue Router、Vite 6、TypeScript、Electron 43 |
| AI 运行时 | FastAPI、Uvicorn、LangGraph、LangChain、BM25 |
| 存储 | H2（默认）/ PostgreSQL 16（可选） |
| 工具链 | Maven、npm、pytest、GitHub Actions |

## 目录结构

```text
├── security-toolbox-server/    Spring Boot 后端（API、任务执行、AI 编排）
├── security-toolbox-web/       Vue 3 + Electron 前端
├── ai-runtime/                 FastAPI + LangGraph AI 运行时
├── web_fingerprint_db/         自维护 Web 指纹库数据
├── scripts/                    启动、构建、发布脚本
├── docs/                       设计文档与报告
├── reports/                    运行产物、证据与报告
├── data/                       本地数据（H2、MITM CA 等）
└── .github/workflows/          CI 与发布流水线
```

## 快速开始

### 环境要求

Windows 10/11 x64、JDK 17、Maven、Node.js、Python 3.11+。

### 安装前端依赖

```powershell
npm --prefix .\security-toolbox-web ci
```

### 启动方式

两种模式任选其一，也可以直接双击仓库根目录对应的 `.cmd` 文件。

**桌面版**（推荐，自动构建后端并拉起 AI 运行时）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-desktop.ps1
```

**浏览器开发模式**（后端 + 前端分离，便于调试）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start-all.ps1
powershell -ExecutionPolicy Bypass -File scripts\status-all.ps1   # 查看运行状态
powershell -ExecutionPolicy Bypass -File scripts\stop-all.ps1     # 停止服务
```

浏览器模式下 AI 功能需要单独启动 AI 运行时：

```powershell
powershell -ExecutionPolicy Bypass -File ai-runtime\run.ps1
```

启动脚本会打印管理员登录账号和密码（首次运行自动生成，存放在 `.run/development-secrets-v2.json`）。

## 数据库

后端默认使用内置 H2 数据库，数据落在 `./data/security-toolbox`，开箱即用无需配置。

`start-all.ps1` 启动时会自动探测本机 PostgreSQL：

- 检测到 `127.0.0.1:5432`（可用 `DB_HOST`/`DB_PORT` 覆盖）有可用实例，**且**设置了 `POSTGRES_PASSWORD` 环境变量，则自动以 `postgres` profile 连接 `security_toolbox` 数据库。
- 未检测到 PostgreSQL 或未提供 `POSTGRES_PASSWORD`，则回退 H2，不阻塞启动。
- 设 `$env:TOOLBOX_USE_POSTGRES='0'` 可强制禁用 PostgreSQL，始终使用 H2。

需要数据库实例时用仓库根目录的 `compose.yaml` 启动：

```powershell
docker compose up -d postgres
```

务必保证 `compose.yaml` 中的 `POSTGRES_PASSWORD` 与启动脚本读取的环境变量一致。依赖检测页面会显示「当前数据库：PostgreSQL / H2」以便确认后端实际使用的存储。

`compose.yaml` 还提供一个 Juice Shop 靶场（`lab` profile，监听 `127.0.0.1:3000`），可作为自建测试目标：

```powershell
docker compose --profile lab up -d juice-shop
```

## 端口一览

| 服务 | 默认端口 | 说明 |
|------|---------|------|
| 前端 Vite | 5173 | 仅浏览器开发模式 |
| 后端 API | 8080 | Spring Boot，接口前缀 `/api` |
| AI 运行时 | 8090 | FastAPI + LangGraph，桌面版自动拉起 |
| PostgreSQL | 5432 | 可选，未启用时不监听 |
| Juice Shop | 3000 | 可选靶场，需 `lab` profile |

桌面版所有服务只监听本机回环地址，不对局域网暴露。

## AI 执行确认

项目中的「执行确认与审计」统一管理 AI 方案、管理员确认和执行记录：

1. 用户向 AI 提出检测需求后，可执行方案先保存为**待确认**记录。
2. 管理员查看目标、工具和参数后选择「确认并执行」或「拒绝执行」。
3. 确认后执行服务端保存的原计划，不重新调用模型生成另一份方案，并在执行前再次核验项目、目标授权和有效期。

补充规则：

- 聊天中的执行请求不会直接创建任务，纯咨询只返回解释或建议。
- 拒绝或关闭确认窗口不会创建任务；重复恢复同一条记录不会重复派发。
- 同一会话中可要求追加检测、移除步骤或调整参数，修订后的方案需重新确认，不继承旧审批决定。
- 仅要求修改方案时只交付新方案；确认执行时核对最新成功交付的版本，模型不能在确认时自行更改工具或参数。
- 引用材料和历史消息中的修改指令不作为本轮授权。

旧的「申请审批」和「申请高风险行动」人工入口已停用，历史记录仅保留用于审计。AI 服务账号只表示方案来源，没有登录或确认执行权限。

## 使用限制

- 只测试自有或明确获得授权的目标。
- 默认限制回环、链路本地和局域网目标，不支持任意公网扫描。
- 当前版本不提供漏洞利用、爆破、钓鱼、横向移动或破坏性自动化能力。
