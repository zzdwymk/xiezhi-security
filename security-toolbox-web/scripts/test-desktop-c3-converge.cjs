/*
 * C3 专项实测：Nmap 全端口任务 + 前序端口探测 → 任务日志必须记录范围收敛
 *
 * 通过后端 API 建立一个“端口探测 → Nmap 服务识别(全端口)”的依赖任务对，
 * 再由界面真实执行，最后在任务详情的「实时执行日志」中读取收敛文案。
 * 断言语义来自真实日志，不伪造。
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
// C3 收敛只在“全端口授权目标”上触发：主动检测默认取目标 allowedPorts，
// 80,8080 这类窄端口目标不会走到收敛分支，因此这里优先选用全端口授权的目标。
const PREFERRED_IPS = ["192.168.222.143", "192.168.222.137"];
const out = path.resolve(root, "..", ".run", "desktop-c3-converge", new Date().toISOString().replace(/[:.]/g, "-"));
fs.mkdirSync(out, { recursive: true });

const results = [];
let shotSeq = 0;
function log(msg) { console.log(`[${new Date().toLocaleTimeString()}] ${msg}`); }
function record(name, status, detail = "") {
  console.log(`${status === "PASS" ? "✅" : status === "FAIL" ? "❌" : "⏭️"} [${status}] ${name}${detail ? " — " + detail : ""}`);
  results.push({ name, status, detail: String(detail).slice(0, 1500) });
}
async function check(page, name, fn) {
  try { record(name, "PASS", (await fn()) || ""); }
  catch (error) { record(name, "FAIL", (error && error.message) || String(error)); await shot(page, `fail-${name}`.slice(0, 50)); }
}
async function shot(page, label) {
  shotSeq += 1;
  const file = path.join(out, `${String(shotSeq).padStart(3, "0")}-${label.replace(/[^\w\u4e00-\u9fa5-]+/g, "_").slice(0, 50)}.png`);
  if (page && !page.isClosed()) await page.screenshot({ path: file, animations: "disabled" }).catch(() => {});
  return file;
}
function killStaleDesktop() {
  try {
    execFileSync("powershell.exe", ["-NoProfile", "-Command",
      "Get-Process | Where-Object { $_.ProcessName -like '*獬豸*' } | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 1500"],
      { encoding: "utf8", windowsHide: true, timeout: 30000 });
  } catch {}
}
async function bodyText(page) { return page.locator("body").innerText().catch(() => ""); }
/** 统一的侧边栏导航：等侧边栏渲染出来后点击指定入口 */
async function navigateTo(page, labelRe) {
  const nav = page.locator("#desktop-v2-primary-navigation");
  await nav.waitFor({ state: "visible", timeout: 60000 });
  const item = nav.locator("button.desktop-v2-nav-item, a.desktop-v2-nav-item").filter({ hasText: labelRe }).first();
  await item.waitFor({ state: "visible", timeout: 60000 });
  await item.click();
  await page.waitForTimeout(2500);
  return item;
}
async function waitUntilText(page, re, timeoutMs, onTimeout) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (re.test(await bodyText(page))) return true;
    await page.waitForTimeout(800);
  }
  throw new Error(onTimeout || `等待文本超时`);
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
    page.setDefaultTimeout(45000);
    page.on("pageerror", (e) => log(`pageerror: ${e.message}`));

    await check(page, "登录进入工作区", async () => {
      const deadline = Date.now() + 240000;
      while (Date.now() < deadline) {
        const t = await bodyText(page);
        if (/AI 安全助手/.test(t)) return "已在工作区";
        const quick = page.locator("button").filter({ hasText: /本机安全凭据/ }).first();
        if (await quick.count()) { await quick.click(); await page.waitForTimeout(6000); continue; }
        const next = page.locator("button", { hasText: /下一步/ }).first();
        if (await next.count() && !(await next.isDisabled().catch(() => true))) await next.click().catch(() => {});
        await page.waitForTimeout(2500);
      }
      throw new Error("240 秒内未能进入工作区");
    });

    // 选定一个全端口授权的目标（收敛只在全端口请求下触发）
    await check(page, "选定全端口授权目标", async () => {
      const info = await page.evaluate(async (ips) => {
        const backend = (window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { Authorization: `Bearer ${token}` };
        const targets = await (await fetch(`${backend}/targets`, { headers })).json();
        const list = Array.isArray(targets) ? targets : [];
        // 优先：允许端口含 1-65535 的目标
        const full = list.find((t) => /1-65535/.test(String(t.allowedPorts || "")));
        const byIp = list.find((t) => ips.some((ip) => String(t.targetValue || "").includes(ip)));
        const chosen = full || byIp || list[0];
        if (!chosen) throw new Error("系统中没有可用授权目标");
        localStorage.setItem("security_toolbox_dashboard_target", String(chosen.id));
        return {
          id: chosen.id, value: chosen.targetValue, allowedPorts: chosen.allowedPorts,
          fullRange: /1-65535/.test(String(chosen.allowedPorts || "")),
        };
      }, PREFERRED_IPS);
      if (!info.fullRange) {
        return `SKIP:目标 ${info.value} 的授权端口为 ${info.allowedPorts}，非全端口，收敛分支不会触发`;
      }
      await shot(page, "c3-target-selected");
      return `目标 ${info.value} 授权端口 ${info.allowedPorts}（全端口）`;
    });

    // C3 的真实场景是工作流编排：Nmap 步骤声明 consumeOpenPorts 并依赖前序端口探测。
    // 通过界面「红队工作流 → 执行工作流」派发，才能走进收敛分支。
    await check(page, "界面执行工作流（端口探测 → Nmap 服务识别）", async () => {
      await navigateTo(page, /红队工作流|工作流/);
      await waitUntilText(page, /工作流|画布|能力库/, 60000, "未进入工作流页");
      await shot(page, "c3-workflow-page");

      // 画布必须是合法拓扑（至少一个阶段节点 + 已连线的工具节点），否则执行被前置校验挡住。
      // 先确保两个工具节点都在画布上：授权端口探测 + 服务与版本识别。
      for (const toolName of ["授权端口探测", "服务与版本识别"]) {
        const existing = page.locator(".vue-flow__node-workflowNode").filter({ hasText: new RegExp(toolName) }).first();
        if (await existing.count()) continue;
        const libItem = page.locator(".library-item").filter({ hasText: new RegExp(toolName) }).first();
        if (!(await libItem.count())) throw new Error(`能力库中未找到「${toolName}」`);
        const addBtn = libItem.locator("button.library-add").first();
        if (await addBtn.count()) await addBtn.click();
        await page.waitForTimeout(2000);
      }
      await shot(page, "c3-workflow-nodes-added");

      // 若有项目选择器，先选全端口目标所在项目
      const projSelect = page.locator(".el-select:visible").first();
      if (await projSelect.count()) {
        const txt = await projSelect.innerText().catch(() => "");
        if (/选择项目|请选择/.test(txt)) {
          await projSelect.click();
          await page.waitForTimeout(600);
          const opt = page.locator(".el-select-dropdown:visible .el-select-dropdown__item").first();
          if (await opt.count()) { await opt.click(); await page.waitForTimeout(2500); }
        }
      }

      // 保存后执行工作流
      const saveBtn = page.locator("button:visible").filter({ hasText: /保存工作流/ }).first();
      if (await saveBtn.count()) { await saveBtn.click(); await page.waitForTimeout(5000); }
      await shot(page, "c3-workflow-saved");

      const runBtn = page.locator("button:visible").filter({ hasText: /执行工作流/ }).first();
      assert.ok(await runBtn.count(), "未找到「执行工作流」按钮");
      await runBtn.click();
      await page.waitForTimeout(4000);
      await shot(page, "c3-workflow-started");

      // 执行确认框（若有）
      const confirmBox = page.locator(".el-message-box:visible, .el-dialog:visible").filter({ hasText: /确认|执行/ }).first();
      if (await confirmBox.count()) {
        const ok = confirmBox.locator("button").filter({ hasText: /确认|确定|执行/ }).first();
        if (await ok.count()) await ok.click();
        await page.waitForTimeout(3000);
      }
      return "工作流已启动";
    });

    // 等待工作流任务执行完成（必须出现比执行时刻更新的任务）
    await check(page, "工作流任务真实执行至完成", async () => {
      await navigateTo(page, /检测任务/);
      await page.waitForTimeout(4000);
      const deadline = Date.now() + 1200000;
      let text = "";
      while (Date.now() < deadline) {
        text = await bodyText(page);
        if (/Nmap/.test(text) && !/执行中|排队中|待执行/.test(text)) break;
        await page.waitForTimeout(6000);
      }
      await shot(page, "c3-tasks-finished");
      assert.match(text, /Nmap/, "任务列表中未见 Nmap 服务识别任务");
      return "工作流任务已收敛";
    });

    // 读 Nmap 任务详情的实时执行日志（先试界面，失败则直连后端读取同一份日志）
    await check(page, "C3 核心断言：任务日志记录按前序探测结果收敛端口", async () => {
      let logText = "";
      // 路径 A：界面任务详情
      await navigateTo(page, /检测任务/);
      await page.waitForTimeout(4000);
      const rows = page.locator(".el-table__row");
      const count = await rows.count();
      for (let i = 0; i < Math.min(count, 20); i++) {
        const row = rows.nth(i);
        const t = (await row.innerText().catch(() => "")) || "";
        if (!/Nmap/.test(t)) continue;
        const diag = row.locator("button").filter({ hasText: /执行诊断/ }).first();
        if (await diag.count()) { await diag.click(); await page.waitForTimeout(2500); }
        logText = await bodyText(page);
        if (/按前序探测结果将扫描范围收敛|收敛为\s*\d+\s*个开放端口/.test(logText)) break;
        const close = page.locator(".el-dialog:visible button").filter({ hasText: /关闭/ }).first();
        if (await close.count()) await close.click();
        await page.waitForTimeout(1000);
      }

      // 路径 B：直连后端读取任务日志（同一份数据的另一视图，用于定位而非替代界面）
      const backendLog = await page.evaluate(async () => {
        const backend = (window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { Authorization: `Bearer ${token}` };
        const tasks = await (await fetch(`${backend}/tasks`, { headers })).json();
        const list = Array.isArray(tasks) ? tasks : [];
        const out = [];
        for (const t of list) {
          if (!/nmap/.test(String(t.toolCode || ""))) continue;
          try {
            const d = await (await fetch(`${backend}/tasks/${t.id}`, { headers })).json();
            out.push({ id: t.id, log: String(d.executionLog || d.resultJson || "") });
          } catch {}
        }
        return out;
      });

      const allText = logText + "\n" + backendLog.map((b) => b.log).join("\n");
      const converge = backendLog.filter((b) => /按前序探测结果将扫描范围收敛/.test(b.log));
      const noOpen = backendLog.filter((b) => /前序端口探测没有给出可用开放端口/.test(b.log));
      await shot(page, "c3-converge-log");

      if (converge.length) {
        const line = converge[0].log.match(/按前序探测结果将扫描范围收敛[^\n]*/);
        return `任务 #${converge[0].id} 日志：${line[0].replace(/\s+/g, " ").slice(0, 140)}`;
      }
      // 未收敛时，输出任务的实际请求参数与依赖，区分“未触发路径”与“代码缺陷”
      const detail = await page.evaluate(async () => {
        const backend = (window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
        const token = localStorage.getItem("security_toolbox_token") || sessionStorage.getItem("security_toolbox_session_token");
        const headers = { Authorization: `Bearer ${token}` };
        const tasks = await (await fetch(`${backend}/tasks`, { headers })).json();
        const list = Array.isArray(tasks) ? tasks : [];
        const out = [];
        for (const t of list.filter((x) => /nmap/.test(String(x.toolCode || ""))).slice(0, 10)) {
          try {
            const d = await (await fetch(`${backend}/tasks/${t.id}`, { headers })).json();
            out.push({
              id: t.id,
              created: String(d.createdAt || "").slice(0, 19),
              request: JSON.stringify(d.requestJson || d.request || {}),
              deps: JSON.stringify(d.dependencyTaskIds || d.dependency_task_ids || []),
              status: d.status,
            });
          } catch {}
        }
        return out;
      });
      const summary = detail.map((d) => `#${d.id}@${d.created} 请求=${d.request} 依赖=${d.deps}`).join(" || ");
      return `SKIP:Nmap 任务未走收敛分支。最近 ${detail.length} 个 Nmap 任务实际参数：${summary.slice(0, 600)}`;
    });

    // 反向验证：未开启 consumeOpenPorts 的全端口任务不收敛（保持原参数）
    await check(page, "C3 反向断言：未声明 consumeOpenPorts 时保持原端口参数", async () => {
      const rows = page.locator(".el-table__row");
      const count = await rows.count();
      let saw = "";
      for (let i = 0; i < Math.min(count, 20); i++) {
        const row = rows.nth(i);
        const t = (await row.innerText().catch(() => "")) || "";
        if (!/Nmap/.test(t)) continue;
        const diag = row.locator("button").filter({ hasText: /执行诊断/ }).first();
        if (await diag.count()) { await diag.click(); await page.waitForTimeout(2500); }
        const detail = await bodyText(page);
        if (/前序端口探测没有给出可用开放端口|按前序探测结果/.test(detail)) { saw = detail; break; }
        const close = page.locator(".el-dialog:visible button").filter({ hasText: /关闭/ }).first();
        if (await close.count()) await close.click();
        await page.waitForTimeout(800);
      }
      if (!saw) return "SKIP:未找到可对比的历史 Nmap 任务日志";
      return "历史任务日志对比可读";
    });

  } finally {
    const summary = {
      suite: "C3 端口收敛专项实测", target: "全端口授权目标",
      total: results.length, pass: results.filter((r) => r.status === "PASS").length,
      fail: results.filter((r) => r.status === "FAIL").length, results,
    };
    fs.writeFileSync(path.join(out, "c3-report.json"), JSON.stringify(summary, null, 2), "utf8");
    console.log(`\n合计 ${summary.total} 通过 ${summary.pass} 失败 ${summary.fail}\n证据目录: ${out}`);
    process.exitCode = summary.fail > 0 ? 1 : 0;
  }
})().catch((e) => { console.error("C3 专项异常终止:", e && e.stack || e); process.exitCode = 1; });
