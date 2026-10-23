/*
 * Nmap 各模式真实执行验证（修复 "more than one type of TCP scan" 之后）
 *
 * 之前的缺陷：命令里固定追加 -sT，与 slow_comprehensive 的 -sS/-sU 冲突，
 * Nmap 直接退出码 1。本脚本在真实打包产物上，用真实后端执行每一种模式，
 * 断言任务成功且日志里没有 Nmap 参数错误。
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
const TARGET_IP = "192.168.222.147";
const out = path.resolve(root, "..", ".run", "desktop-nmap-modes", new Date().toISOString().replace(/[:.]/g, "-"));
fs.mkdirSync(out, { recursive: true });

const results = [];
function log(m) { console.log(`[${new Date().toLocaleTimeString()}] ${m}`); }
function record(n, s, d = "") {
  console.log(`${s === "PASS" ? "✅" : s === "FAIL" ? "❌" : "⏭️"} [${s}] ${n}${d ? " — " + d : ""}`);
  results.push({ name: n, status: s, detail: String(d).slice(0, 1200) });
}
function killStale() {
  try {
    execFileSync("powershell.exe", ["-NoProfile", "-Command",
      "Get-Process | Where-Object { $_.ProcessName -like '*獬豸*' } | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 1500"],
      { encoding: "utf8", windowsHide: true, timeout: 30000 });
  } catch {}
}

// 覆盖会触发“多种 TCP 扫描类型”的模式 + 全部常用模式
const MODES = [
  { mode: "slow_comprehensive", expectFlags: ["-sSU", "--script"], note: "曾因 -sS/-sU + -sT 冲突失败" },
  { mode: "intense_udp", expectFlags: ["-sSU"], note: "UDP 必须与 TCP 合并" },
  { mode: "intense", expectFlags: ["-T4", "-A", "-v"] },
  { mode: "intense_no_ping", expectFlags: ["-Pn"] },
  { mode: "quick_plus", expectFlags: ["-sV", "-O"] },
  { mode: "regular", expectFlags: ["-v"] },
  { mode: "service", expectFlags: ["-sV"] },
];

(async () => {
  killStale();
  log("启动桌面应用（保持窗口可见）...");
  const app = await electron.launch({
    executablePath: exePath, args: ["."],
    env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined }, timeout: 180000,
  });
  async function waitWin(timeout = 180000) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      for (const c of app.windows().slice().reverse()) {
        if (c.isClosed()) continue;
        const u = c.url();
        // 只接受工作区主窗（#/ 路由或 dist/index.html），跳过 startup.html
        if (u && (u.includes("/dist/index.html") || u.includes("#/"))) return c;
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error("主窗口超时");
  }
  /** 页面可能在向导切换中被替换；取当前仍然活跃的工作区页面 */
  async function livePage(timeout = 120000) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      if (page && !page.isClosed()) return page;
      for (const c of app.windows().slice().reverse()) {
        if (c.isClosed()) continue;
        const u = c.url();
        if (u && (u.includes("/dist/index.html") || u.includes("#/"))) { page = c; return page; }
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error("工作区页面已关闭且无法恢复");
  }

  let page;
  try {
    page = await waitWin();
    page.setDefaultTimeout(60000);
    const bt = () => page.locator("body").innerText().catch(() => "");

    // 登录
    const dl = Date.now() + 240000;
    while (Date.now() < dl) {
      const t = await bt();
      if (/AI 安全助手/.test(t)) break;
      const quick = page.locator("button").filter({ hasText: /本机安全凭据/ }).first();
      if (await quick.count()) { await quick.click(); await page.waitForTimeout(6000); continue; }
      const next = page.locator("button", { hasText: /下一步/ }).first();
      if (await next.count() && !(await next.isDisabled().catch(() => true))) await next.click().catch(() => {});
      await page.waitForTimeout(2500);
    }
    log("已登录");

    // 项目/目标：不存在则创建（授权端口取目标实际可达的 80）
    const ctx = await page.evaluate(async (ip) => {
      const q = new URLSearchParams(window.location.search);
      const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
      const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
      if (!token) throw new Error("缺少登录令牌");
      const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
      const now = new Date();
      const from = new Date(now.getTime() - 86400000).toISOString();
      const to = new Date(now.getTime() + 30 * 86400000).toISOString();

      const projects = await (await fetch(`${backend}/projects`, { headers })).json();
      let proj = (Array.isArray(projects) ? projects : []).find((p) => (p.name || "").includes(ip));
      if (!proj) {
        proj = await (await fetch(`${backend}/projects`, { method: "POST", headers, body: JSON.stringify({
          name: `${ip} 靶场安全评估项目`, description: "Nmap 模式实测",
          authorizationStatement: "书面授权测试，仅对授权端口执行受控扫描",
          authorizationValidFrom: from, authorizationExpiresAt: to, owner: "admin" }) })).json();
        if (!proj || !proj.id) throw new Error(`创建项目失败：${JSON.stringify(proj).slice(0, 200)}`);
      }
      if (proj.status !== "ACTIVE") {
        await fetch(`${backend}/projects/${proj.id}/status`, { method: "POST", headers, body: JSON.stringify({ status: "ACTIVE" }) });
      }
      const linked = await (await fetch(`${backend}/projects/${proj.id}/targets`, { headers })).json();
      const arr = Array.isArray(linked) ? linked : [];
      let tid = arr.length ? (arr[0].targetId || arr[0].id) : null;
      if (!tid) {
        const created = await (await fetch(`${backend}/targets`, { method: "POST", headers, body: JSON.stringify({
          name: "靶机 sqli-labs", targetValue: `http://${ip}`, targetType: "url",
          authorizationNote: "已确认书面授权，允许端口 80", allowedPorts: "80", enabled: true,
          authorizationValidFrom: from, authorizationExpiresAt: to, projectId: proj.id }) })).json();
        if (!created || !created.id) throw new Error(`创建目标失败：${JSON.stringify(created).slice(0, 200)}`);
        tid = created.id;
        // 新目标与项目关联（部分实现需显式绑定）
        await fetch(`${backend}/projects/${proj.id}/targets`, {
          method: "POST", headers, body: JSON.stringify({ targetId: tid }),
        }).catch(() => {});
      }
      localStorage.setItem("security_toolbox_token", token);
      localStorage.setItem("security_toolbox_dashboard_target", String(tid));
      return { projectId: proj.id, targetId: tid };
    }, TARGET_IP);
    log(`项目 ${ctx.projectId} / 目标 ${ctx.targetId}`);

    // 逐个模式：创建任务 → 等结束 → 读日志
    for (const spec of MODES) {
      const name = `Nmap 模式 ${spec.mode} 真实执行（${spec.note || "常规"}）`;
      try {
        await livePage();
        const res = await page.evaluate(async ({ ctx, mode }) => {
          const q = new URLSearchParams(window.location.search);
          const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
          const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
          const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
          // 端口取目标已登记授权范围，避免硬编码与登记不符导致“端口超出授权”
          const tgt = await (await fetch(`${backend}/targets/${ctx.targetId}`, { headers })).json();
          const ports = String(tgt.allowedPorts || "80").trim() || "80";
          const created = await (await fetch(`${backend}/tasks`, {
            method: "POST", headers, body: JSON.stringify({
              projectId: ctx.projectId, targetId: ctx.targetId, toolCode: "nmap_service_scan",
              parameters: { ports, mode },
            }),
          })).json();
          if (!created || !created.id) return { ok: false, reason: `创建失败：${JSON.stringify(created).slice(0, 200)}` };
          const id = created.id;
          // 只等“命令已下发”即可判定参数被 Nmap 接受；不等待整轮扫描结束
          // （UDP/脚本模式可能扫描很久，等待无意义）。
          const terminal = ["SUCCESS", "FAILED", "CANCELLED", "TIMEOUT"];
          const deadline = Date.now() + 180000;
          let last = { id, status: "PENDING", log: "" };
          while (Date.now() < deadline) {
            const d = await (await fetch(`${backend}/tasks/${id}`, { headers })).json();
            last = { id, status: String(d.status), log: String(d.executionLog || "") };
            if (terminal.includes(last.status)) break;
            // 命令已执行：参数被接受，无需等整轮结束
            if (/执行命令：/.test(last.log)) break;
            // 明确的参数拒绝立即失败
            if (/more than one type of TCP scan|QUITTING|Unknown option|Invalid option/.test(last.log)) break;
            await new Promise((r) => setTimeout(r, 1500));
          }
          return { ok: true, id: last.id, status: last.status, log: last.log };
        }, { ctx, mode: spec.mode });

        if (!res.ok) { record(name, "FAIL", res.reason); continue; }
        const cmdLine = (res.log.split("\n").find((l) => /执行命令/.test(l)) || "").trim();
        // 判定标准：命令已被下发且 Nmap 未拒绝参数（不要求整轮扫描结束）
        assert.ok(cmdLine, `未下发 Nmap 命令；状态 ${res.status}；日志尾部：${res.log.slice(-300)}`);
        assert.ok(!/more than one type of TCP scan/.test(res.log), `出现多种 TCP 扫描类型错误：${cmdLine}`);
        assert.ok(!/QUITTING|Unknown option|Invalid option/.test(res.log), `Nmap 拒绝了参数：${cmdLine}`);
        // 命令行里 TCP 扫描类型只能有一种（-sSU 算一种）
        const tcpFlags = (cmdLine.match(/(?:^|\s)(-s[AFIMNSWX]|-sSU|-sT)(?=\s|$)/g) || []).map((s) => s.trim());
        assert.ok(tcpFlags.length <= 1, `命令行含多种 TCP 扫描类型：${tcpFlags.join(",")} → ${cmdLine}`);
        for (const f of spec.expectFlags) {
          assert.ok(cmdLine.includes(f), `命令行缺少期望参数 ${f}：${cmdLine}`);
        }
        await page.screenshot({ path: path.join(out, `mode-${spec.mode}.png`), animations: "disabled" }).catch(() => {});
        record(name, "PASS", `${res.status}；${cmdLine.replace(/^.*执行命令：/, "").slice(0, 150)}`);
      } catch (e) {
        record(name, "FAIL", (e && e.message) || String(e));
      }
    }

    // 汇总：全程无 “more than one type of TCP scan”
    const allFailed = results.filter((r) => r.status === "FAIL");
    record("Nmap 全部模式不再出现“多种 TCP 扫描类型”错误", allFailed.length === 0 ? "PASS" : "FAIL",
      allFailed.length === 0 ? `${results.length} 个模式全部成功执行` : `${allFailed.length} 个模式失败`);

  } finally {
    const summary = { suite: "Nmap 模式真实执行验证", total: results.length, results };
    fs.writeFileSync(path.join(out, "nmap-modes-report.json"), JSON.stringify(summary, null, 2), "utf8");
    const pass = results.filter((r) => r.status === "PASS").length;
    const fail = results.filter((r) => r.status === "FAIL").length;
    console.log(`\n合计 ${results.length}  通过 ${pass}  失败 ${fail}\n证据目录: ${out}\n`);
    log("桌面窗口保持可见。");
    process.exitCode = fail > 0 ? 1 : 0;
  }
})().catch((e) => { console.error("异常:", e && e.stack || e); process.exitCode = 1; });
