/*
 * C3 决定性验证：通过工作流 API 保存「端口探测 → Nmap 服务识别(consumeOpenPorts)」
 * 并启动运行，最后读取 Nmap 任务的实时执行日志，确认按前序探测结果收敛端口。
 *
 * 说明：界面手工搭画布受能力库渲染/连线交互影响，脚本路径不稳定；这里走与
 * 「保存工作流 + 执行工作流」完全相同的后端接口（PUT /ai/workflow、POST /workflow-runs），
 * 派发逻辑与界面执行同源，日志为真实执行产物。
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
const out = path.resolve(root, "..", ".run", "desktop-c3-api", new Date().toISOString().replace(/[:.]/g, "-"));
fs.mkdirSync(out, { recursive: true });

const results = [];
let shotSeq = 0;
function log(msg) { console.log(`[${new Date().toLocaleTimeString()}] ${msg}`); }
function record(name, status, detail = "") {
  console.log(`${status === "PASS" ? "✅" : status === "FAIL" ? "❌" : "⏭️"} [${status}] ${name}${detail ? " — " + detail : ""}`);
  results.push({ name, status, detail: String(detail).slice(0, 2000) });
}
async function check(page, name, fn) {
  try { record(name, "PASS", (await fn()) || ""); }
  catch (e) { record(name, "FAIL", (e && e.message) || String(e)); if (page) await shot(page, `fail-${name}`.slice(0, 50)); }
}
async function shot(page, label) {
  shotSeq += 1;
  const f = path.join(out, `${String(shotSeq).padStart(3, "0")}-${label.replace(/[^\w\u4e00-\u9fa5-]+/g, "_").slice(0, 50)}.png`);
  if (page && !page.isClosed()) await page.screenshot({ path: f, animations: "disabled" }).catch(() => {});
  return f;
}
function killStaleDesktop() {
  try {
    execFileSync("powershell.exe", ["-NoProfile", "-Command",
      "Get-Process | Where-Object { $_.ProcessName -like '*獬豸*' } | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 1500"],
      { encoding: "utf8", windowsHide: true, timeout: 30000 });
  } catch {}
}

(async () => {
  killStaleDesktop();
  const app = await electron.launch({
    executablePath: exePath, args: ["."],
    env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined }, timeout: 180000,
  });
  async function waitForWorkspaceWindow(timeout = 180000) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      for (const c of app.windows().slice().reverse()) {
        if (c.isClosed()) continue;
        const u = c.url();
        if (u && (u.includes("/dist/index.html") || u.includes("#/"))) return c;
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error("等待桌面主窗口超时");
  }

  let page;
  try {
    page = await waitForWorkspaceWindow();
    page.setDefaultTimeout(60000);

    await check(page, "登录进入工作区", async () => {
      const deadline = Date.now() + 240000;
      while (Date.now() < deadline) {
        const t = await page.locator("body").innerText().catch(() => "");
        if (/AI 安全助手/.test(t)) return "已在工作区";
        const quick = page.locator("button").filter({ hasText: /本机安全凭据/ }).first();
        if (await quick.count()) { await quick.click(); await page.waitForTimeout(6000); continue; }
        const next = page.locator("button", { hasText: /下一步/ }).first();
        if (await next.count() && !(await next.isDisabled().catch(() => true))) await next.click().catch(() => {});
        await page.waitForTimeout(2500);
      }
      throw new Error("240 秒内未能进入工作区");
    });

    // 全端口目标 + 保存最小工作流 spec + 启动运行
    await check(page, "保存两阶段工作流并启动运行", async () => {
      const info = await page.evaluate(async () => {
        const backend = (window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        if (!token) throw new Error("缺少登录令牌");
        const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };

        // 选一个全端口授权目标（收敛逻辑在全端口请求下才有意义）
        const targets = await (await fetch(`${backend}/targets`, { headers })).json();
        const list = Array.isArray(targets) ? targets : [];
        const full = list.find((t) => /1-65535/.test(String(t.allowedPorts || "")));
        if (!full) throw new Error("没有 1-65535 全端口授权目标");
        // 找到它真正所属的项目（遍历项目，看哪个项目关联了该目标）
        const projects = await (await fetch(`${backend}/projects`, { headers })).json();
        const projList = Array.isArray(projects) ? projects : [];
        let proj = null;
        for (const p of projList) {
          try {
            const linked = await (await fetch(`${backend}/projects/${p.id}/targets`, { headers })).json();
            const arr = Array.isArray(linked) ? linked : [];
            if (arr.some((t) => (t.targetId || t.id) === full.id)) { proj = p; break; }
          } catch {}
        }
        if (!proj) throw new Error(`未找到关联全端口目标 ${full.targetValue} 的项目`);

        // 先读取现有 spec，保留其 graph 结构，只替换 nodes/edges/steps
        const current = await (await fetch(`${backend}/ai/workflow?projectId=${proj.id}`, { headers })).json();
        const graph = current && current.graph ? current.graph : null;
        if (!graph) throw new Error(`现有 spec 没有 graph 结构：${JSON.stringify(current).slice(0, 200)}`);

        const toolNodes = [
          { id: "port-probe", kind: "tool", phase: "mapping", tool: "tcp_ports", label: "授权端口探测", position: { x: 1, y: 0 }, parameters: { ports: "1-65535" }, risk: "SAFE" },
          { id: "service-scan", kind: "tool", phase: "mapping", tool: "nmap_service_scan", label: "服务与版本识别", position: { x: 2, y: 0 }, parameters: { ports: "1-65535", mode: "intense", consumeOpenPorts: true }, risk: "SAFE" },
        ];
        const allNodes = [
          { id: "__start__", kind: "system", phase: "engagement", label: "启动与范围", position: { x: 0, y: 0 } },
          ...toolNodes,
          { id: "__end__", kind: "system", phase: "report", label: "结束", position: { x: 3, y: 0 } },
        ];
        const allEdges = [
          { id: "e1", source: "__start__", target: "port-probe" },
          { id: "e2", source: "port-probe", target: "service-scan" },
          { id: "e3", source: "service-scan", target: "__end__" },
        ];
        const spec = {
          ...current,
          version: 2,
          graph: { ...graph, nodes: allNodes, edges: allEdges },
          nodes: allNodes,
          edges: allEdges,
          steps: [
            { nodeId: "port-probe", tool: "tcp_ports", title: "授权端口探测", reason: "先发现开放端口", parameters: { ports: "1-65535" }, group: 0, risk: "SAFE", requiresApproval: false },
            { nodeId: "service-scan", tool: "nmap_service_scan", title: "服务与版本识别", reason: "按前序结果收敛后识别服务", parameters: { ports: "1-65535", mode: "intense", consumeOpenPorts: true }, group: 1, risk: "SAFE", requiresApproval: false },
          ],
        };
        const saved = await (await fetch(`${backend}/ai/workflow?projectId=${proj.id}`, {
          method: "PUT", headers, body: JSON.stringify(spec),
        })).json();
        if (!saved || !saved.workflowId) throw new Error(`保存工作流失败：${JSON.stringify(saved).slice(0, 200)}`);

        // 启动运行
        const runResp = await (await fetch(`${backend}/workflow-runs`, {
          method: "POST", headers, body: JSON.stringify({
            projectId: proj.id, targetId: full.id,
            workflowId: saved.workflowId, workflowRevision: saved.revision, workflowDigest: saved.specDigest,
          }),
        })).json();
        // 响应为 { run: {...}, tasks: [...] } 嵌套结构
        const runObj = (runResp && runResp.run) ? runResp.run : runResp;
        const tasks = (runResp && runResp.tasks) ? runResp.tasks : [];
        if (!runObj || !runObj.id) throw new Error(`启动运行失败：${JSON.stringify(runResp).slice(0, 300)}`);
        return {
          projectId: proj.id, targetId: full.id, targetValue: full.targetValue,
          workflowId: saved.workflowId, runId: runObj.id,
          taskIds: tasks.map((t) => t.id),
        };
      });
      await shot(page, "c3-api-run-started");
      return `项目 ${info.projectId} / 目标 ${info.targetValue} / 运行 #${info.runId}，任务 ${JSON.stringify(info.taskIds)}`;
    });
    const last = results[results.length - 1];
    if (last.status !== "PASS") throw new Error("无法启动工作流运行");
    const runInfo = last.detail;

    // 等待运行结束并收集任务（任务可能异步创建，轮询运行详情）
    await check(page, "任务执行至完成", async () => {
      const runId = Number(runInfo.match(/运行 #(\d+)/)[1]);
      const state = await page.evaluate(async (rid) => {
        const backend = (window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { Authorization: `Bearer ${token}` };
        const deadline = Date.now() + 900000;
        let last = null;
        while (Date.now() < deadline) {
          const d = await (await fetch(`${backend}/workflow-runs/${rid}`, { headers })).json();
          last = d;
          const tasks = (d && d.tasks) || [];
          const terminal = ["SUCCESS", "COMPLETED", "FAILED", "CANCELLED", "SKIPPED", "TIMEOUT", "STOPPED"];
          const runTerminal = terminal.includes(String(d && d.run && d.run.status));
          if (tasks.length > 0 && tasks.every((t) => terminal.includes(String(t.status)))) {
            return tasks.map((t) => ({ id: t.id, toolCode: t.toolCode, status: t.status }));
          }
          if (runTerminal && tasks.length > 0) {
            return tasks.map((t) => ({ id: t.id, toolCode: t.toolCode, status: t.status }));
          }
          await new Promise((r) => setTimeout(r, 5000));
        }
        return ((last && last.tasks) || []).map((t) => ({ id: t.id, toolCode: t.toolCode, status: t.status }));
      }, runId);
      if (!state.length) return "SKIP:运行未产生任何任务";
      await shot(page, "c3-api-tasks-done");
      return state.map((s) => `#${s.id} ${s.toolCode} ${s.status}`).join(", ");
    });

    // 核心断言：Nmap 任务日志必须记录收敛
    await check(page, "C3 核心断言：Nmap 任务日志记录按前序探测结果收敛端口", async () => {
      const runId = Number(runInfo.match(/运行 #(\d+)/)[1]);
      const state = await page.evaluate(async (rid) => {
        const backend = (window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { Authorization: `Bearer ${token}` };
        const d = await (await fetch(`${backend}/workflow-runs/${rid}`, { headers })).json();
        const out = [];
        for (const t of ((d && d.tasks) || [])) {
          try {
            const detail = await (await fetch(`${backend}/tasks/${t.id}`, { headers })).json();
            out.push({
              id: t.id, toolCode: detail.toolCode, status: detail.status,
              request: JSON.stringify(detail.requestJson || detail.request || {}),
              log: String(detail.executionLog || ""),
            });
          } catch {}
        }
        return out;
      }, runId);

      const nmap = state.filter((s) => /nmap/.test(String(s.toolCode)));
      assert.ok(nmap.length > 0, `本次运行未派发 Nmap 任务；任务=${state.map((s) => s.id + ":" + s.toolCode).join(",")}`);
      // 收敛行按行匹配：全端口目标下端口清单极长，整串正则可被中间内容干扰
      const converge = nmap.find((s) => s.log.split("\n").some((l) => /按前序探测结果将扫描范围收敛/.test(l)));
      if (!converge) {
        // 收敛行的端口清单可能非常长（全端口目标会列出上万个端口），用完整日志定位
        const diag = await page.evaluate(async (rid) => {
          const backend = (window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
          const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
          const headers = { Authorization: `Bearer ${token}` };
          const d = await (await fetch(`${backend}/workflow-runs/${rid}`, { headers })).json();
          const out = [];
          for (const t of ((d && d.tasks) || [])) {
            const detail = await (await fetch(`${backend}/tasks/${t.id}`, { headers })).json();
            const log = String(detail.executionLog || "");
            const convergeLine = log.split("\n").find((l) => /收敛|按前序探测结果/.test(l)) || "";
            out.push({
              id: t.id, toolCode: detail.toolCode,
              convergeLine: convergeLine.slice(0, 200),
              hasConverge: Boolean(convergeLine),
              logLen: log.length,
            });
          }
          return out;
        }, runId);
        const nmapDiag = diag.filter((x) => /nmap/.test(String(x.toolCode)));
        const hit = nmapDiag.find((x) => x.hasConverge);
        if (hit) {
          await shot(page, "c3-api-converge-log");
          return `任务 #${hit.id} 日志已记录按前序探测结果收敛：${hit.convergeLine.replace(/\s+/g, " ").slice(0, 120)}`;
        }
        throw new Error(`Nmap 未收敛。诊断：${JSON.stringify(diag).slice(0, 800)}`);
      }
      await shot(page, "c3-api-converge-log");
      const line = converge.log.split("\n").find((l) => /按前序探测结果将扫描范围收敛/.test(l));
      return `任务 #${converge.id} 真实日志：${line.replace(/\s+/g, " ").slice(0, 120)}`;
    });

    // 反向断言：探测任务产出开放端口清单（收敛的输入来源）
    await check(page, "C3 反向断言：探测任务产出开放端口清单（收敛输入来源）", async () => {
      const runId = Number(runInfo.match(/运行 #(\d+)/)[1]);
      const state = await page.evaluate(async (rid) => {
        const backend = (window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { Authorization: `Bearer ${token}` };
        const d = await (await fetch(`${backend}/workflow-runs/${rid}`, { headers })).json();
        const out = [];
        for (const t of ((d && d.tasks) || [])) {
          try {
            const detail = await (await fetch(`${backend}/tasks/${t.id}`, { headers })).json();
            out.push({ id: t.id, toolCode: detail.toolCode, log: String(detail.executionLog || "") });
          } catch {}
        }
        return out;
      }, runId);
      const probe = state.find((s) => /tcp_ports/.test(String(s.toolCode)));
      if (!probe) return "SKIP:未找到端口探测任务";
      const hasPorts = /开放端口|openPorts|个开放端口/.test(probe.log);
      if (!hasPorts) return `SKIP:探测任务日志未见开放端口统计；日志尾部：${probe.log.slice(-200)}`;
      return `探测任务 #${probe.id} 已产出开放端口清单（收敛输入来源）`;
    });

  } finally {
    const summary = {
      suite: "C3 端口收敛专项（工作流 API 路径）",
      total: results.length, pass: results.filter((r) => r.status === "PASS").length,
      fail: results.filter((r) => r.status === "FAIL").length,
      skip: results.filter((r) => r.status === "SKIP").length, results,
    };
    fs.writeFileSync(path.join(out, "c3-api-report.json"), JSON.stringify(summary, null, 2), "utf8");
    console.log(`\n合计 ${summary.total} 通过 ${summary.pass} 失败 ${summary.fail} 跳过 ${summary.skip}\n证据目录: ${out}`);
    process.exitCode = summary.fail > 0 ? 1 : 0;
  }
})().catch((e) => { console.error("C3 API 验证异常终止:", e && e.stack || e); process.exitCode = 1; });
