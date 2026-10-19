/*
 * 知识库同步 + 漏洞挖掘 + 模糊测试 前置脚本
 * 通过真实 UI 完成漏洞知识库（Nuclei/Afrog/Xray/Msf）同步，再交给主测试脚本。
 * 运行：node scripts/sync-vuln-catalog-ui.cjs
 */
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
const out = path.resolve(root, "..", ".run", "desktop-vuln-sync", new Date().toISOString().replace(/[:.]/g, "-"));
fs.mkdirSync(out, { recursive: true });

function log(msg) { console.log(`[${new Date().toLocaleTimeString()}] ${msg}`); }
async function shot(page, label) {
  const safe = String(label).replace(/[^\w\u4e00-\u9fa5-]+/g, "_").slice(0, 50);
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
    await page.waitForTimeout(800);
  }
  throw new Error((onTimeout || "超时") + `；末次片段：${last.slice(-150).replace(/\s+/g, " ")}`);
}

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

    // 导航到「主动检测」（漏洞知识库所在页）
    const nav = page.locator("#desktop-v2-primary-navigation");
    await nav.locator("button.desktop-v2-nav-item", { hasText: "主动检测" }).first().click();
    await waitUntil(page, (t) => /漏洞知识库|检测规则/.test(t), 30000);
    await page.waitForTimeout(2000);
    await shot(page, "vuln-page");

    const before = await bodyText(page);
    log(`同步前页面含「未同步」: ${/未同步/.test(before)}，含「同步漏洞」按钮: ${/同步/.test(before)}`);

    // 右上角「同步」链接按钮：打开同步下拉菜单（Nuclei/Afrog/Xray/Metasploit/同步全部）
    const syncLink = page.locator("button:visible, a:visible").filter({ hasText: /^同步$/ }).first();
    await syncLink.waitFor({ state: "visible", timeout: 15000 });
    await syncLink.click();
    log("已打开同步菜单...");
    await page.waitForTimeout(1200);
    await shot(page, "sync-menu");

    // 直接点「同步全部」下拉项（el-dropdown-item 渲染为 li）
    const syncAll = page.locator("li.el-dropdown-menu__item:visible, .el-dropdown-menu__item:visible").filter({ hasText: /同步全部/ }).first();
    await syncAll.waitFor({ state: "visible", timeout: 10000 });
    await syncAll.click();
    log("已点击「同步全部」...");

    // 会出现确认框「同步漏洞目录」→ 点「检查并同步」
    const confirmBtn = page.locator("button:visible").filter({ hasText: /检查并同步/ }).first();
    await confirmBtn.waitFor({ state: "visible", timeout: 15000 });
    await confirmBtn.click();
    log("已确认「检查并同步」，等待模板下载与导入（最长 25 分钟）...");
    await shot(page, "sync-started");

    // 等待知识库条数 > 0（页头 "X 条 · Nuclei Y"）
    await waitUntil(page,
      (t) => /Nuclei\s*[1-9][\d,]*/.test(t.replace(/\s+/g, " ")),
      25 * 60 * 1000,
      "同步 25 分钟后 Nuclei 条数仍为 0");
    log("知识库已导入条目");
    process.exitCode = 0;
  } catch (error) {
    console.error("知识库同步失败:", error && error.message);
    if (page) await shot(page, "fail");
    process.exitCode = 1;
  }
})();
