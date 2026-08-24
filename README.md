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

## 主要能力

- 项目和授权目标治理，包括授权声明、有效期、状态和端口范围。
- DNS、HTTP、TLS、指纹、Nmap、Nuclei、Afrog、Xray 等受控检测。
- 异步任务、取消、重试、依赖 DAG、授权快照和执行前复核。
- Finding 管理、复测、扫描 Diff、审计和 HTML/PDF 报告。
- HTTP(S) 回环代理、MITM、流量分析、脱敏和受控重放。
- AI 项目资料检索、证据化问答、结构化计划和 Java 授权执行。
- 浏览器本地离线编码、哈希、报文、文件和授权测试辅助工具。

## 使用要求

- 只测试自有或明确获得授权的目标。
- 默认限制回环、链路本地和局域网目标，不支持任意公网扫描。
- 当前版本不提供漏洞利用、爆破、钓鱼、横向移动或破坏性自动化能力。
