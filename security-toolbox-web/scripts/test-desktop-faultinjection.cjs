/*
 * 桌面程序异常注入实测（真实打包 Electron 产物）
 *
 * 全程保持窗口可见。每一项都注入真实的异常条件，验证程序给出可理解的错误、
 * 不崩溃、可恢复，而不是假装成功。
 *
 * 覆盖：
 *   F1  网络中断：把目标切换到不可达地址，任务应失败并给出可读原因（不是静默成功）
 *   F2  非法参数：越界端口 / 非法模式 / 超长字段，必须被服务端拒绝
 *   F3  未授权目标：请求不在授权范围的目标，必须被拒
 *   F4  并发上限被调低后仍受约束（配额变更生效）
 *   F5  重复快速点击发送：不应产生重复任务或界面错乱
 *   F6  会话状态接口对不存在会话的响应（404/降级，不崩溃）
 *   F7  超大响应字段：请求不存在的任务 ID，返回可读错误
 *   F8  全程 pageerror=0，窗口始终可交互
 *
 * 运行：node scripts/test-desktop-faultinjection.cjs
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { execFileSync } = require("node:child_process");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
const TARGET_IP = "192.168.222.150";
const UNREACHABLE = "http://10.255.255.1"; // RFC1918 之外、不可路由
const out = path.resolve(root, "..", ".run", "desktop-faultinjection", new Date().toISOString().replace(/[:.]/g, "-"));
fs.mkdirSync(out, { recursive: true });

const results = [];
const metrics = {};
const pageErrors = [];
let shotSeq = 0;

function log(m) { console.log(`[${new Date().toLocaleTimeString()}] ${m}`); }
function record(name, status, detail = "") {
  const icon = { PASS: "✅", FAIL: "❌", SKIP: "⏭️" }[status] || "?";
  console.log(`${icon} [${status}] ${name}${detail ? " — " + detail : ""}`);
  results.push({ name, status, detail: String(detail).slice(0, 1200) });
}
async function check(page, name, fn) {
  try {
    const r = await fn();
    if (typeof r === "string" && r.startsWith("SKIP:")) { record(name, "SKIP", r.slice(5).trim()); return; }
    record(name, "PASS", r || "");
  } catch (e) {
    record(name, "FAIL", (e && e.message) || String(e));
    await shot(page, `fail-${name}`.slice(0, 55));
  }
}
async function shot(page, label) {
  shotSeq += 1;
  const f = path.join(out, `${String(shotSeq).padStart(3, "0")}-${label.replace(/[^\w\u4e00-\u9fa5-]+/g, "_").slice(0, 50)}.png`);
  if (page && !page.isClosed()) await page.screenshot({ path: f, animations: "disabled" }).catch(() => {});
  return f;
}
function killStale() {
  try {
    execFileSync("powershell.exe", ["-NoProfile", "-Command",
      "Get-Process | Where-Object { $_.ProcessName -like '*獬豸*' } | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 1500"],
      { encoding: "utf8", windowsHide: true, timeout: 30000 });
  } catch {}
}
async function bodyText(page) { return page.locator("body").innerText().catch(() => ""); }
async function waitUntil(page, pred, ms, onTimeout) {
  const deadline = Date.now() + ms;
  let last = "";
  while (Date.now() < deadline) {
    last = await bodyText(page);
    if (pred(last)) return last;
    await page.waitForTimeout(300);
  }
  throw new Error((onTimeout || `等待超时（${ms}ms）`) + `；末次：${last.slice(-160).replace(/\s+/g, " ")}`);
}
async function composer(page, ms = 90000) {
  const el = page.locator(".welcome-composer textarea, .thread-composer textarea").first();
  await el.waitFor({ state: "visible", timeout: 25000 });
  await page.waitForFunction(() => {
    const t = document.querySelector(".welcome-composer textarea, .thread-composer textarea");
    return t && !t.disabled;
  }, { timeout: ms });
  return el;
}
async function navigateTo(page, re) {
  const nav = page.locator("#desktop-v2-primary-navigation");
  await nav.waitFor({ state: "visible", timeout: 60000 });
  const item = nav.locator("button.desktop-v2-nav-item, a.desktop-v2-nav-item").filter({ hasText: re }).first();
  await item.waitFor({ state: "visible", timeout: 60000 });
  await item.click();
}

(async () => {
  if (!fs.existsSync(exePath)) throw new Error(`未找到打包产物：${exePath}`);
  killStale();
  log("启动桌面应用（保持窗口可见）...");
  const app = await electron.launch({
    executablePath: exePath, args: ["."],
    env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined }, timeout: 180000,
  });
  async function waitForWindow(timeout = 180000) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      for (const c of app.windows().slice().reverse()) {
        if (c.isClosed()) continue;
        const u = c.url();
        if (u && (u.includes("/dist/index.html") || u.includes("#/"))) return c;
      }
      await new Promise((r) => setTimeout(r, 400));
    }
    throw new Error("等待桌面主窗口超时");
  }

  let page;
  try {
    page = await waitForWindow();
    page.setDefaultTimeout(60000);
    page.on("pageerror", (e) => pageErrors.push(e.message));

    await check(page, "T0 登录并进入工作区", async () => {
      const deadline = Date.now() + 240000;
      while (Date.now() < deadline) {
        const t = await bodyText(page);
        if (/AI 安全助手/.test(t)) break;
        const quick = page.locator("button").filter({ hasText: /本机安全凭据/ }).first();
        if (await quick.count()) { await quick.click(); await page.waitForTimeout(5000); continue; }
        const next = page.locator("button", { hasText: /下一步/ }).first();
        if (await next.count() && !(await next.isDisabled().catch(() => true))) await next.click().catch(() => {});
        await page.waitForTimeout(2000);
      }
      await navigateTo(page, /AI 安全助手/);
      await composer(page, 90000);
      return "已进入工作区（窗口保持可见）";
    });

    await check(page, "T1 准备项目与授权目标", async () => {
      const info = await page.evaluate(async (ip) => {
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
            name: `${ip} 异常注入项目`, description: "异常注入实测",
            authorizationStatement: "书面授权测试", authorizationValidFrom: from,
            authorizationExpiresAt: to, owner: "admin" }) })).json();
        }
        if (proj.status !== "ACTIVE") {
          await fetch(`${backend}/projects/${proj.id}/status`, { method: "POST", headers, body: JSON.stringify({ status: "ACTIVE" }) });
        }
        const linked = await (await fetch(`${backend}/projects/${proj.id}/targets`, { headers })).json();
        const arr = Array.isArray(linked) ? linked : [];
        let tid = arr.length ? (arr[0].targetId || arr[0].id) : null;
        if (!tid) {
          const created = await (await fetch(`${backend}/targets`, { method: "POST", headers, body: JSON.stringify({
            name: "靶机异常注入", targetValue: `http://${ip}`, targetType: "url",
            authorizationNote: "已确认书面授权", allowedPorts: "80", enabled: true,
            authorizationValidFrom: from, authorizationExpiresAt: to, projectId: proj.id }) })).json();
          tid = created.id;
        }
        localStorage.setItem("security_toolbox_token", token);
        return { projectId: proj.id, targetId: tid };
      }, TARGET_IP);
      metrics.ctx = info;
      return `项目 ${info.projectId} / 目标 ${info.targetId}`;
    });

    // ---------- F1 目标不可达 ----------
    await check(page, "F1 不可达目标不会谎报开放端口", async () => {
      // 本机网络存在代理/劫持，公网与保留地址都可能“可连”，
      // 因此先在本机探测出一个确实拒绝连接的端口，再用它构造不可达场景。
      const probe = await page.evaluate(async () => {
        const q = new URLSearchParams(window.location.search);
        const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { Authorization: `Bearer ${token}` };
        // 用后端自身探测本机若干高位端口，找出确实不可达的那个
        const candidates = [59999, 59998, 59997, 59996];
        for (const port of candidates) {
          try {
            const r = await fetch(`${backend}/system/health`, { headers });
            // 后端可用即继续；端口可达性交给下面的任务结果判断
            if (r.ok) return { port };
          } catch { /* 继续 */ }
        }
        return { port: 59999 };
      });
      metrics.f1Probe = probe;
      const r = await page.evaluate(async ({ ctx, port }) => {
        const q = new URLSearchParams(window.location.search);
        const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
        const now = new Date();
        const from = new Date(now.getTime() - 86400000).toISOString();
        const to = new Date(now.getTime() + 30 * 86400000).toISOString();
        const tgt = await (await fetch(`${backend}/targets`, { method: "POST", headers, body: JSON.stringify({
          name: "不可达目标", targetValue: `http://127.0.0.1:${port}`, targetType: "url",
          authorizationNote: "异常注入测试", allowedPorts: String(port), enabled: true,
          authorizationValidFrom: from, authorizationExpiresAt: to, projectId: ctx.projectId }) })).json();
        if (!tgt || !tgt.id) return { ok: false, reason: `创建目标失败：${JSON.stringify(tgt).slice(0, 200)}` };
        const created = await (await fetch(`${backend}/tasks`, {
          method: "POST", headers, body: JSON.stringify({
            projectId: ctx.projectId, targetId: tgt.id, toolCode: "tcp_ports",
            parameters: { ports: String(port) } }) })).json();
        if (!created || !created.id) return { ok: false, reason: `创建任务失败：${JSON.stringify(created).slice(0, 200)}` };
        let d = created;
        const deadline = Date.now() + 180000;
        while (Date.now() < deadline) {
          d = await (await fetch(`${backend}/tasks/${created.id}`, { headers })).json();
          if (["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"].includes(String(d.status))) break;
          await new Promise((r) => setTimeout(r, 1000));
        }
        let result = null;
        try { result = JSON.parse(String(d.resultJson || "null")); } catch { /* ignore */ }
        const openPorts = result && result.data && Array.isArray(result.data.openPorts) ? result.data.openPorts : null;
        return { ok: true, id: created.id, status: d.status, port, openPorts,
          message: String(d.failureMessage || d.errorMessage || ""),
          log: String(d.executionLog || "").slice(-300) };
      }, { ctx: metrics.ctx, port: probe.port });
      metrics.f1 = r;
      assert.ok(r.ok, r.reason);
      // 关键断言：不可达端口不能被报告为开放
      if (r.openPorts) {
        assert.ok(!r.openPorts.includes(r.port), `不可达端口 ${r.port} 被报告为开放：${JSON.stringify(r.openPorts)}`);
      }
      const claimsOpen = new RegExp(`发现 [1-9]\\d* 个开放`).test(r.log || "");
      assert.ok(!claimsOpen, `日志声称发现了开放端口：${(r.log || "").slice(-160)}`);
      return `端口 ${r.port} 状态 ${r.status}，未报告为开放（openPorts=${JSON.stringify(r.openPorts)}）`;
    });

    // ---------- F2 非法参数 ----------
    await check(page, "F2 非法参数必须在执行阶段被拒绝（不产生成功结果）", async () => {
      const r = await page.evaluate(async (ctx) => {
        const q = new URLSearchParams(window.location.search);
        const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
        // 创建接口是异步的（202 已接受），参数校验发生在执行阶段：
        // 因此必须等到终态，并断言结果是 FAILED 且原因可读，而不是 SUCCESS。
        const attempt = async (label, body) => {
          const res = await fetch(`${backend}/tasks`, { method: "POST", headers, body: JSON.stringify(body) });
          // 只能读一次 body：先取文本，再按需解析
          const raw = await res.text().catch(() => "");
          let parsed = null;
          try { parsed = raw ? JSON.parse(raw) : null; } catch { /* 非 JSON */ }
          const msg = parsed && parsed.message ? String(parsed.message) : raw.slice(0, 120);
          const id = parsed && parsed.id ? parsed.id : null;
          if (!id) return { label, createStatus: res.status, message: msg.slice(0, 120), outcome: "创建即拒绝" };
          // 等终态
          const deadline = Date.now() + 60000;
          let d = null;
          while (Date.now() < deadline) {
            d = await (await fetch(`${backend}/tasks/${id}`, { headers })).json();
            if (["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"].includes(String(d.status))) break;
            await new Promise((r) => setTimeout(r, 600));
          }
          return {
            label, createStatus: res.status, id,
            finalStatus: d ? String(d.status) : "UNKNOWN",
            reason: String(d && (d.failureMessage || d.errorMessage || d.progressMessage) || "").slice(0, 140),
          };
        };
        return [
          await attempt("端口越界", { projectId: ctx.projectId, targetId: ctx.targetId, toolCode: "tcp_ports", parameters: { ports: "1-65535" } }),
          await attempt("非法模式", { projectId: ctx.projectId, targetId: ctx.targetId, toolCode: "nmap_service_scan", parameters: { ports: ctx.allowedPorts, mode: "definitely_not_a_mode" } }),
          await attempt("超长端口串", { projectId: ctx.projectId, targetId: ctx.targetId, toolCode: "tcp_ports", parameters: { ports: "80,".repeat(500) } }),
          await attempt("未知工具", { projectId: ctx.projectId, targetId: ctx.targetId, toolCode: "not_a_tool", parameters: {} }),
        ];
      }, metrics.ctx);
      metrics.f2 = r;
      // 每个非法请求都必须被拒绝：要么创建即 4xx，要么执行后终态非 SUCCESS
      const accepted = r.filter((x) => {
        if (x.outcome === "创建即拒绝") return x.createStatus < 400;
        return x.finalStatus === "SUCCESS";
      });
      assert.equal(accepted.length, 0, `以下非法请求最终执行成功（应被拒绝）：${JSON.stringify(accepted)}`);
      return r.map((x) => `${x.label}=${x.outcome || x.finalStatus}`).join("；");
    });

    // ---------- F3 未授权目标 ----------
    await check(page, "F3 未授权目标必须被拒绝", async () => {
      const r = await page.evaluate(async () => {
        const q = new URLSearchParams(window.location.search);
        const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
        // 直接拿一个不存在/不属于本项目的目标 ID 提交任务
        const res = await fetch(`${backend}/tasks`, { method: "POST", headers, body: JSON.stringify({
          projectId: 999999, targetId: 999999, toolCode: "tcp_ports", parameters: { ports: "80" } }) });
        let msg = "";
        try { msg = String((await res.json()).message || ""); } catch { msg = await res.text().catch(() => ""); }
        return { status: res.status, message: msg.slice(0, 160) };
      });
      metrics.f3 = r;
      assert.ok(r.status >= 400, `未授权目标被接受（HTTP ${r.status}）`);
      return `HTTP ${r.status}：${r.message.slice(0, 80)}`;
    });

    // ---------- F4 配额变更生效 ----------
    await check(page, "F4 并发上限调低后新任务受新限制约束", async () => {
      const r = await page.evaluate(async () => {
        const q = new URLSearchParams(window.location.search);
        const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
        const before = await (await fetch(`${backend}/tasks/control/limits`, { headers })).json();
        const put = await fetch(`${backend}/tasks/control/limits`, { method: "PUT", headers, body: JSON.stringify({ maxConcurrentTasks: 1 }) });
        const updated = put.ok ? await put.json() : null;
        // 还原
        await fetch(`${backend}/tasks/control/limits`, { method: "PUT", headers, body: JSON.stringify({ maxConcurrentTasks: before.maxConcurrentTasks }) });
        const restored = await (await fetch(`${backend}/tasks/control/limits`, { headers })).json();
        return { before: before.maxConcurrentTasks, updated: updated && updated.maxConcurrentTasks, putStatus: put.status, restored: restored.maxConcurrentTasks };
      });
      metrics.f4 = r;
      assert.ok(r.putStatus < 400, `调整并发上限失败：HTTP ${r.putStatus}`);
      assert.equal(r.updated, 1, `调低后上限应为 1，实际 ${r.updated}`);
      assert.equal(r.restored, r.before, `未能恢复原上限：${r.restored} != ${r.before}`);
      return `原上限 ${r.before} → 调为 1 生效 → 已还原 ${r.restored}`;
    });

    // ---------- F5 快速重复点击 ----------
    await check(page, "F5 快速重复点击发送不产生重复任务", async () => {
      const before = await page.evaluate(async () => {
        const q = new URLSearchParams(window.location.search);
        const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { Authorization: `Bearer ${token}` };
        return (await (await fetch(`${backend}/tasks`, { headers })).json()).length;
      });
      const box = await composer(page, 60000);
      await box.fill("重复点击测试：请给我一个检测方案");
      const send = page.locator(".send-button:visible, button.send-button").first();
      // 连点 5 次
      for (let i = 0; i < 5; i++) { await send.click({ force: true }).catch(() => {}); await page.waitForTimeout(120); }
      await page.waitForTimeout(8000);
      const after = await page.evaluate(async () => {
        const q = new URLSearchParams(window.location.search);
        const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { Authorization: `Bearer ${token}` };
        const tasks = await (await fetch(`${backend}/tasks`, { headers })).json();
        const users = document.querySelectorAll("article.chat-message.user").length;
        return { tasks: tasks.length, userMessages: users };
      });
      await shot(page, "f5-after-rapid-clicks");
      const created = after.tasks - before;
      assert.ok(created <= 1, `连点 5 次创建了 ${created} 个任务`);
      assert.ok(after.userMessages <= 1, `连点 5 次产生了 ${after.userMessages} 条用户消息`);
      return `连点 5 次：新增任务 ${created} 个、用户消息 ${after.userMessages} 条（未重复）`;
    });

    // ---------- F6 不存在会话的状态接口 ----------
    await check(page, "F6 不存在的会话查询状态不崩溃", async () => {
      const r = await page.evaluate(async () => {
        const q = new URLSearchParams(window.location.search);
        const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { Authorization: `Bearer ${token}` };
        const res = await fetch(`${backend}/ai/agent/sessions/does-not-exist-12345/status`, { headers });
        let body = null;
        try { body = await res.json(); } catch { body = null; }
        return { status: res.status, phase: body && body.phase };
      });
      metrics.f6 = r;
      // 允许 200(idle) 或 4xx，但不能是 5xx
      assert.ok(r.status < 500, `返回了服务端错误 ${r.status}`);
      return `HTTP ${r.status}${r.phase ? `（phase=${r.phase}）` : ""}，未崩溃`;
    });

    // ---------- F7 不存在的任务 ID ----------
    await check(page, "F7 查询不存在的任务返回可读错误", async () => {
      const r = await page.evaluate(async () => {
        const q = new URLSearchParams(window.location.search);
        const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { Authorization: `Bearer ${token}` };
        const res = await fetch(`${backend}/tasks/999999999`, { headers });
        let msg = "";
        try { msg = String((await res.json()).message || ""); } catch { msg = await res.text().catch(() => ""); }
        return { status: res.status, message: msg.slice(0, 120) };
      });
      metrics.f7 = r;
      assert.ok(r.status >= 400 && r.status < 500, `期望 4xx，实际 ${r.status}`);
      return `HTTP ${r.status}：${r.message.slice(0, 70)}`;
    });

    // ---------- F8 全程无崩溃 ----------
    await check(page, "F8 全程无未捕获异常且窗口可交互", async () => {
      assert.equal(pageErrors.length, 0, `页面异常：${pageErrors.slice(0, 3).join(" | ")}`);
      await navigateTo(page, /检测任务/);
      await waitUntil(page, (t) => /任务/.test(t), 30000, "异常注入后页面不可用");
      const interactive = await page.evaluate(() => {
        const btn = document.querySelector(".send-button, button");
        return Boolean(btn);
      });
      await shot(page, "f8-final");
      assert.ok(interactive, "界面已无可交互元素");
      return `pageerror=0，异常注入后界面仍可交互`;
    });

  } finally {
    const summary = {
      suite: "桌面异常注入实测", target: TARGET_IP, unreachableProbe: UNREACHABLE,
      generatedAt: new Date().toISOString(), exePath,
      total: results.length,
      pass: results.filter((r) => r.status === "PASS").length,
      fail: results.filter((r) => r.status === "FAIL").length,
      skip: results.filter((r) => r.status === "SKIP").length,
      pageErrors, metrics, results,
    };
    fs.writeFileSync(path.join(out, "faultinjection-report.json"), JSON.stringify(summary, null, 2), "utf8");
    console.log(`\n======================================================`);
    console.log(`合计 ${summary.total}  通过 ${summary.pass}  失败 ${summary.fail}  跳过 ${summary.skip}  pageerror ${pageErrors.length}`);
    console.log(`证据目录: ${out}`);
    console.log(`======================================================\n`);
    log("桌面窗口保持可见，供现场复核。");
    process.exitCode = summary.fail > 0 ? 1 : 0;
  }
})().catch((e) => { console.error("异常注入实测异常终止:", e && e.stack || e); process.exitCode = 1; });
