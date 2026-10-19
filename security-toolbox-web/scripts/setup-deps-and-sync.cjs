/*
 * 依赖安装（Nuclei / httpx / sqlmap / fscan 等）→ 知识库同步 前置脚本
 * 通过真实 UI 完成：启动向导/依赖页逐项安装可选安全工具，再同步漏洞知识库。
 * 运行：node scripts/setup-deps-and-sync.cjs
 */
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
const out = path.resolve(root, "..", ".run", "desktop-deps-sync", new Date().toISOString().replace(/[:.]/g, "-"));
fs.mkdirSync(out, { recursive: true });

function log(msg) { console.log(`[${new Date().toLocaleTimeString()}] ${msg}`); }
async function shot(page, label) {
  const safe = String(label).replace(/[^\w\u4e00-\u9fa5-]+/g, "_").slice(0, 60);
  const file = path.join(out, `${safe}.png`);
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
async function waitUntil(page, predicate, timeoutMs, onTimeout) {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    last = await bodyText(page);
    if (predicate(last)) return last;
    await page.waitForTimeout(1000);
  }
  throw new Error((onTimeout || "超时") + `；末次片段：${last.slice(-150).replace(/\s+/g, " ")}`);
}

// 目标：安装 Nuclei（漏扫主引擎）、sqlmap（注入验证）、fscan（内网综合扫描）。
// httpx/xray/afrog 可选，装得动就装。
const WANTED = ["Nuclei", "sqlmap", "fscan", "httpx", "Afrog", "Xray"];

(async () => {
  log("清理遗留进程...");
  killStaleDesktop();
  const app = await electron.launch({
    executablePath: exePath, args: ["."],
    env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined }, timeout: 180000,
  });

  async function waitForWorkspaceWindow(timeout = 180000) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      for (const candidate of app.windows().slice().reverse()) {
        if (candidate.isClosed()) continue;
        const url = candidate.url();
        if (url && (url.includes("/dist/index.html") || url.includes("#/"))) return candidate;
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error("等待主窗口超时");
  }

  let page;
  try {
    page = await waitForWorkspaceWindow();
    page.setDefaultTimeout(60000);
    await page.waitForTimeout(2000);

    // 登录
    const text = await waitUntil(page, (t) => /AI 安全助手|用户名/.test(t), 90000);
    if (!/AI 安全助手/.test(text)) {
      const quick = page.locator("button").filter({ hasText: /本机安全凭据/ }).first();
      if (await quick.count()) { await quick.click(); await waitUntil(page, (t) => /AI 安全助手|安全评估项目/.test(t), 60000); }
    }
    log("已登录");

    // 打开依赖页：从侧边栏「设置」或用户菜单进入。先试侧边栏，再试头像下拉。
    let entered = false;
    const nav = page.locator("#desktop-v2-primary-navigation");
    if (await nav.count()) {
      const settingsBtn = nav.locator("button.desktop-v2-nav-item", { hasText: /设置|依赖/ }).first();
      if (await settingsBtn.count()) {
        await settingsBtn.click();
        await page.waitForTimeout(1500);
        entered = /依赖|运行环境/.test(await bodyText(page));
      }
    }
    if (!entered) {
      // 尝试直接路由
      await page.evaluate(() => { window.location.hash = "#/setup"; });
      await page.waitForTimeout(2500);
      entered = /依赖|运行环境/.test(await bodyText(page));
    }
    if (!entered) throw new Error("无法进入依赖检测页");
    log("已进入依赖检测页");
    await shot(page, "deps-page");

    // 逐个安装目标工具
    const installReport = [];
    for (const name of WANTED) {
      // 找到对应行里的安装按钮（行内含工具名，按钮文案为「安装」/「重新安装」/「更新」）
      const row = page.locator(".dependency-row, .el-table__row, tr, [class*='dependency']").filter({ hasText: name }).first();
      if (!(await row.count())) { log(`${name}: 未找到依赖行，跳过`); installReport.push({ name, status: "row-not-found" }); continue; }

      const installBtn = row.locator("button:visible").filter({ hasText: /^安装$|重新安装|^更新$/ }).first();
      if (!(await installBtn.count())) {
        const state = (await row.innerText()).replace(/\s+/g, " ").slice(0, 80);
        log(`${name}: 无安装按钮（可能已就绪）— ${state}`);
        installReport.push({ name, status: "already-ready" });
        continue;
      }

      log(`${name}: 开始安装（可能需要数分钟下载）...`);
      await installBtn.click();
      // 等待安装完成：按钮消失（变为已就绪）或行文本出现「可用/已安装」
      try {
        await waitUntil(page,
          (t) => {
            // 简化：整体页面出现「安装失败|超时」则报，否则等该行按钮消失
            return !t.includes(`${name} 安装中`) && !/正在安装|下载中/.test(t);
          },
          15 * 60 * 1000,
          `${name} 安装 15 分钟未完成`);
      } catch (e) { log(`  ${name} 安装等待异常: ${e.message.slice(0, 100)}`); }
      await page.waitForTimeout(2000);
      const rowText = (await row.innerText().catch(() => "")).replace(/\s+/g, " ");
      const ok = /可用|已安装/.test(rowText) || !(await row.locator("button:visible").filter({ hasText: /^安装$/ }).count());
      log(`${name}: 安装流程结束，行状态 — ${rowText.slice(0, 80)}`);
      installReport.push({ name, status: ok ? "installed" : "check-manually" });
      await shot(page, `installed-${name}`);
    }

    await shot(page, "deps-after-install");
    log("依赖安装阶段完成：" + JSON.stringify(installReport));

    // ---- 同步漏洞知识库 ----
    log("进入「主动检测」同步漏洞知识库...");
    const nav2 = page.locator("#desktop-v2-primary-navigation");
    await nav2.locator("button.desktop-v2-nav-item", { hasText: "主动检测" }).first().click();
    await waitUntil(page, (t) => /漏洞知识库/.test(t), 30000);
    await page.waitForTimeout(1500);

    const syncLink = page.locator("button:visible, a:visible").filter({ hasText: /^同步$/ }).first();
    await syncLink.waitFor({ state: "visible", timeout: 15000 });
    await syncLink.click();
    await page.waitForTimeout(1200);
    await shot(page, "sync-dialog-after-install");

    // 现在依赖已装，点「同步全部」
    const syncAll = page.locator("button:visible, li:visible").filter({ hasText: /同步全部/ }).first();
    if (await syncAll.count()) {
      await syncAll.click();
      log("已点击「同步全部」，等待模板下载与导入（最长 20 分钟）...");
      await waitUntil(page,
        (t) => /Nuclei\s*[1-9][\d,]*\s*条|同步完成|同步失败/.test(t),
        20 * 60 * 1000,
        "同步 20 分钟未收敛");
    } else {
      // 逐个同步
      for (const src of ["Nuclei", "Metasploit"]) {
        const item = page.locator("li:visible, button:visible").filter({ hasText: src }).first();
        if (await item.count()) {
          await item.click();
          log(`点击 ${src} 同步...`);
          await page.waitForTimeout(5000);
        }
      }
      await waitUntil(page, (t) => /Nuclei\s*[1-9]/.test(t), 20 * 60 * 1000, "同步 20 分钟后 Nuclei 仍为 0 条");
    }
    await page.waitForTimeout(3000);
    await shot(page, "sync-done");
    const finalText = await bodyText(page);
    const countMatch = finalText.match(/(\d+)\s*条\s*·\s*Nuclei\s*(\d+)/);
    log(`知识库同步结果：${countMatch ? `总 ${countMatch[1]} 条，Nuclei ${countMatch[2]}` : finalText.slice(0, 120)}`);
    log("保持窗口可见。");
    process.exitCode = 0;
  } catch (error) {
    console.error("依赖安装/同步失败:", error && error.message);
    if (page) await shot(page, "fail");
    process.exitCode = 1;
  }
})();
