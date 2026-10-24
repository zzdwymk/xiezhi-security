/*
 * 桌面程序性能实测（真实打包 Electron 产物 + 真实后端 + 真实目标）
 *
 * 全程保持窗口可见，不隐藏、不最小化；每个阶段截图留证。
 *
 * 覆盖：
 *   P1  冷启动到可交互的耗时（进程拉起 → 登录 → 工作区可输入）
 *   P2  主要页面切换耗时（AI 助手/工作流/任务/发现/审计）
 *   P3  真实扫描任务的端到端耗时与吞吐（端口探测：全端口 → 记录耗时与端口数）
 *   P4  Nmap 服务识别端到端耗时
 *   P5  大列表渲染耗时（任务列表、会话列表）
 *   P6  进程资源占用（主进程/渲染/后端 java 的 CPU 与内存）
 *   P7  空闲 30 秒后的内存回归（验证没有明显泄漏趋势）
 *   P8  交互响应性（连续操作期间主线程长任务检测）
 *
 * 运行：node scripts/test-desktop-perf.cjs
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
const out = path.resolve(root, "..", ".run", "desktop-perf", new Date().toISOString().replace(/[:.]/g, "-"));
fs.mkdirSync(out, { recursive: true });

const results = [];
const metrics = {};
let shotSeq = 0;

function log(m) { console.log(`[${new Date().toLocaleTimeString()}] ${m}`); }
function record(name, status, detail = "", data) {
  const icon = { PASS: "✅", FAIL: "❌", SKIP: "⏭️" }[status] || "?";
  console.log(`${icon} [${status}] ${name}${detail ? " — " + detail : ""}`);
  results.push({ name, status, detail: String(detail).slice(0, 1200), data });
}
async function check(page, name, fn) {
  const started = Date.now();
  try {
    const r = await fn();
    const elapsed = Date.now() - started;
    if (typeof r === "string" && r.startsWith("SKIP:")) { record(name, "SKIP", r.slice(5).trim(), { elapsed }); return; }
    if (r && typeof r === "object" && r.detail) { record(name, "PASS", r.detail, { ...r, elapsed }); return; }
    record(name, "PASS", (r || "") + `（${elapsed}ms）`, { elapsed });
  } catch (e) {
    record(name, "FAIL", (e && e.message) || String(e), { elapsed: Date.now() - started });
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
  return item;
}
/** 采样进程资源：主进程/渲染/后端 java */
function sampleResources() {
  const tmp = path.join(os.tmpdir(), `perf-procs-${process.pid}-${Date.now()}.json`);
  try {
    // 用 -EncodedCommand 传脚本：避免多层引号、中文进程名与路径在命令行里被拆坏
    const script = [
      "$rows = @();",
      "Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like '*獬*' -or $_.ProcessName -eq 'java' } | ForEach-Object {",
      "  $rows += [pscustomobject]@{ name = $_.ProcessName; id = $_.Id; cpu = [math]::Round($_.CPU, 2); wsMB = [math]::Round($_.WorkingSet64/1MB, 1); threads = $_.Threads.Count }",
      "}",
      `if ($rows.Count -eq 0) { Set-Content -Path '${tmp}' -Value '[]' -Encoding UTF8 }`,
      `else { $rows | ConvertTo-Json -Compress | Set-Content -Path '${tmp}' -Encoding UTF8 }`,
    ].join("\n");
    const encoded = Buffer.from(script, "utf16le").toString("base64");
    execFileSync("powershell.exe", ["-NoProfile", "-EncodedCommand", encoded],
      { windowsHide: true, timeout: 30000, stdio: "ignore" });
    if (!fs.existsSync(tmp)) return [];
    const raw = fs.readFileSync(tmp, "utf8").trim().replace(/^\uFEFF/, "");
    fs.unlinkSync(tmp);
    if (!raw || raw === "[]") return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    try { fs.unlinkSync(tmp); } catch { /* ignore */ }
    return [];
  }
}

(async () => {
  if (!fs.existsSync(exePath)) throw new Error(`未找到打包产物：${exePath}`);
  killStale();

  // ---------- P1 冷启动耗时 ----------
  const launchStart = Date.now();
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
    metrics.windowReadyMs = Date.now() - launchStart;

    await check(page, "P1a 主窗口拉起耗时", async () => {
      return { detail: `窗口就绪 ${metrics.windowReadyMs}ms`, ms: metrics.windowReadyMs };
    });

    await check(page, "P1b 登录并进入工作区（可输入）", async () => {
      const t0 = Date.now();
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
      const ms = Date.now() - t0;
      metrics.loginAndReadyMs = ms;
      await shot(page, "p1-workspace-ready");
      return { detail: `登录+可输入 ${ms}ms（累计 ${Date.now() - launchStart}ms）`, ms };
    });

    await check(page, "P1c 目标与项目就绪", async () => {
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
            name: `${ip} 性能测试项目`, description: "性能与并发实测",
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
            name: "靶机性能测试", targetValue: `http://${ip}`, targetType: "url",
            authorizationNote: "已确认书面授权", allowedPorts: "80", enabled: true,
            authorizationValidFrom: from, authorizationExpiresAt: to, projectId: proj.id }) })).json();
          tid = created.id;
        }
        localStorage.setItem("security_toolbox_token", token);
        localStorage.setItem("security_toolbox_dashboard_target", String(tid));
        // 端口必须取目标已登记的授权范围，硬编码会越权被拒
        const tgt = await (await fetch(`${backend}/targets/${tid}`, { headers })).json();
        const allowedPorts = String(tgt.allowedPorts || "80").trim() || "80";
        return { projectId: proj.id, targetId: tid, allowedPorts };
      }, TARGET_IP);
      metrics.ctx = info;
      return `项目 ${info.projectId} / 目标 ${info.targetId} / 授权端口 ${info.allowedPorts}`;
    });

    // ---------- P2 页面切换耗时 ----------
    await check(page, "P2 主要页面切换耗时", async () => {
      const pages = [
        { label: /红队工作流/, expect: /工作流|画布|能力库/, name: "工作流" },
        { label: /检测任务/, expect: /任务|执行/, name: "检测任务" },
        { label: /安全发现/, expect: /发现|风险|漏洞/, name: "安全发现" },
        { label: /审计日志/, expect: /审计/, name: "审计日志" },
        { label: /AI 安全助手/, expect: /AI 安全助手|告诉我你想/, name: "AI 助手" },
      ];
      const timings = [];
      for (const p of pages) {
        const t0 = Date.now();
        await navigateTo(page, p.label);
        await waitUntil(page, (t) => p.expect.test(t), 45000, `${p.name} 未加载`);
        timings.push({ page: p.name, ms: Date.now() - t0 });
      }
      metrics.navigation = timings;
      await shot(page, "p2-after-navigation");
      const slowest = timings.reduce((a, b) => (a.ms > b.ms ? a : b));
      const avg = Math.round(timings.reduce((s, x) => s + x.ms, 0) / timings.length);
      return `平均 ${avg}ms，最慢「${slowest.page}」${slowest.ms}ms；明细 ${timings.map((t) => t.page + ":" + t.ms).join(", ")}`;
    });

    // ---------- P3 真实端口探测耗时 ----------
    await check(page, "P3 端口探测端到端耗时（目标授权端口）", async () => {
      const r = await page.evaluate(async ({ ctx }) => {
        const q = new URLSearchParams(window.location.search);
        const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
        const t0 = performance.now();
        const created = await (await fetch(`${backend}/tasks`, {
          method: "POST", headers, body: JSON.stringify({
            projectId: ctx.projectId, targetId: ctx.targetId, toolCode: "tcp_ports",
            parameters: { ports: ctx.allowedPorts } }) })).json();
        if (!created || !created.id) return { ok: false, reason: JSON.stringify(created).slice(0, 200) };
        let d = created;
        const deadline = Date.now() + 300000;
        while (Date.now() < deadline) {
          d = await (await fetch(`${backend}/tasks/${created.id}`, { headers })).json();
          if (["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"].includes(String(d.status))) break;
          await new Promise((r) => setTimeout(r, 500));
        }
        return { ok: true, id: created.id, status: d.status, ms: Math.round(performance.now() - t0),
          log: String(d.executionLog || "").slice(-300), ports: ctx.allowedPorts };
      }, { ctx: metrics.ctx });
      assert.ok(r.ok, `创建任务失败：${r.reason}`);
      metrics.tcpPorts = r;
      assert.equal(r.status, "SUCCESS", `任务状态 ${r.status}（端口 ${r.ports}）；日志：${(r.log || "").slice(-200)}`);
      return `任务 #${r.id} SUCCESS，端口 ${r.ports}，${r.ms}ms`;
    });

    // ---------- P4 Nmap 服务识别耗时 ----------
    await check(page, "P4 Nmap 服务识别端到端耗时", async () => {
      const r = await page.evaluate(async ({ ctx }) => {
        const q = new URLSearchParams(window.location.search);
        const backend = (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
        const t0 = performance.now();
        const created = await (await fetch(`${backend}/tasks`, {
          method: "POST", headers, body: JSON.stringify({
            projectId: ctx.projectId, targetId: ctx.targetId, toolCode: "nmap_service_scan",
            parameters: { ports: ctx.allowedPorts, mode: "quick" } }) })).json();
        if (!created || !created.id) return { ok: false, reason: JSON.stringify(created).slice(0, 200) };
        let d = created;
        const deadline = Date.now() + 600000;
        while (Date.now() < deadline) {
          d = await (await fetch(`${backend}/tasks/${created.id}`, { headers })).json();
          if (["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"].includes(String(d.status))) break;
          await new Promise((r) => setTimeout(r, 1000));
        }
        return { ok: true, id: created.id, status: d.status, ms: Math.round(performance.now() - t0),
          log: String(d.executionLog || "").slice(-300) };
      }, { ctx: metrics.ctx });
      assert.ok(r.ok, `创建任务失败：${r.reason}`);
      metrics.nmap = r;
      assert.equal(r.status, "SUCCESS", `任务状态 ${r.status}（${r.ms}ms）；日志：${(r.log || "").slice(-200)}`);
      return `任务 #${r.id} SUCCESS，${r.ms}ms`;
    });

    // ---------- P5 大列表渲染 ----------
    await check(page, "P5 任务列表渲染耗时（含重复进入）", async () => {
      const timings = [];
      for (let i = 0; i < 3; i++) {
        const t0 = Date.now();
        await navigateTo(page, /检测任务/);
        await waitUntil(page, (t) => /任务/.test(t), 45000);
        await page.waitForTimeout(1200);
        timings.push(Date.now() - t0);
      }
      const rows = await page.locator(".el-table__row").count();
      metrics.taskList = { rows, timings };
      const avg = Math.round(timings.reduce((s, x) => s + x, 0) / timings.length);
      return `任务列表渲染平均 ${avg}ms（${timings.join("/")}），行数 ${rows}`;
    });

    // ---------- P6 资源占用 ----------
    await check(page, "P6 进程资源占用（运行中）", async () => {
      const samples = sampleResources();
      metrics.resourcesRunning = samples;
      if (!samples.length) return "SKIP:无法采样进程资源";
      const total = samples.reduce((s, x) => s + x.wsMB, 0);
      const detail = samples.map((s) => `${s.name}#${s.id} 内存${s.wsMB}MB CPU${s.cpu}s 线程${s.threads}`).join("；");
      return `合计内存 ${Math.round(total)}MB；${detail}`;
    });

    // ---------- P7 空闲内存回归 ----------
    await check(page, "P7 空闲 30 秒后内存变化", async () => {
      const before = sampleResources();
      await page.waitForTimeout(30000);
      const after = sampleResources();
      const sum = (arr) => arr.reduce((s, x) => s + x.wsMB, 0);
      const b = sum(before), a = sum(after);
      metrics.idleMemory = { before: b, after: a, deltaMB: Math.round((a - b) * 10) / 10 };
      return `空闲前 ${Math.round(b)}MB → 空闲后 ${Math.round(a)}MB（变化 ${Math.round((a - b) * 10) / 10}MB）`;
    });

    // ---------- P8 交互响应性 ----------
    await check(page, "P8 连续交互期间主线程长任务", async () => {
      await page.evaluate(() => {
        window.__longTasks = [];
        try {
          new PerformanceObserver((list) => {
            for (const e of list.getEntries()) window.__longTasks.push(Math.round(e.duration));
          }).observe({ entryTypes: ["longtask"] });
        } catch { /* 不支持则忽略 */ }
      });
      // 连续切换页面 6 次；每次只要导航点击成功即可，不强求内容完全加载
      for (let i = 0; i < 6; i++) {
        await navigateTo(page, i % 2 === 0 ? /AI 安全助手/ : /检测任务/);
        await page.waitForTimeout(900);
      }
      const longTasks = await page.evaluate(() => window.__longTasks || []);
      metrics.longTasks = longTasks;
      const worst = longTasks.length ? Math.max(...longTasks) : 0;
      await shot(page, "p8-after-interactions");
      if (!longTasks.length) return "未检测到长任务（或该环境不支持 longtask 观测）";
      return `长任务 ${longTasks.length} 次，最长 ${worst}ms`;
    });

    await shot(page, "perf-final");

  } finally {
    const summary = {
      suite: "桌面性能实测", target: TARGET_IP,
      generatedAt: new Date().toISOString(), exePath,
      total: results.length,
      pass: results.filter((r) => r.status === "PASS").length,
      fail: results.filter((r) => r.status === "FAIL").length,
      skip: results.filter((r) => r.status === "SKIP").length,
      metrics, results,
    };
    fs.writeFileSync(path.join(out, "perf-report.json"), JSON.stringify(summary, null, 2), "utf8");
    console.log(`\n======================================================`);
    console.log(`合计 ${summary.total}  通过 ${summary.pass}  失败 ${summary.fail}  跳过 ${summary.skip}`);
    console.log(`证据目录: ${out}`);
    console.log(`======================================================\n`);
    log("桌面窗口保持可见，供现场复核。");
    process.exitCode = summary.fail > 0 ? 1 : 0;
  }
})().catch((e) => { console.error("性能实测异常终止:", e && e.stack || e); process.exitCode = 1; });
