/**
 * 桌面实测：验证本轮 AI 续接相关改动。
 *
 * 覆盖点（不依赖真实模型的"聪明程度"，只验证链路与 UI 契约）：
 *   1. 打包版能启动、推进向导、进入工作区
 *   2. 会话头部存在「停止自动续接」按钮，且点击不报错
 *   3. 无模型/有模型时发送一条执行请求，界面不会崩溃
 *   4. 页面无未捕获的 JS 错误
 *
 * 运行：node scripts/test-desktop-continuation-smoke.cjs
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
const out = path.resolve(root, "..", ".run", "desktop-continuation-smoke",
  new Date().toISOString().replace(/[:.]/g, "-"));
fs.mkdirSync(out, { recursive: true });

const results = [];
const pageErrors = [];
let shotSeq = 0;

function log(msg) { console.log(`[${new Date().toLocaleTimeString()}] ${msg}`); }
function record(name, status, detail = "") {
  const icon = { PASS: "✅ [PASS]", FAIL: "❌ [FAIL]", SKIP: "⏭️ [SKIP]" }[status] || "[????]";
  console.log(`${icon} ${name}${detail ? " — " + detail : ""}`);
  results.push({ name, status, detail: String(detail).slice(0, 1500) });
}
async function shot(page, label) {
  shotSeq += 1;
  const safe = String(label).replace(/[^\w\u4e00-\u9fa5-]+/g, "_").slice(0, 50);
  const file = path.join(out, `${String(shotSeq).padStart(2, "0")}-${safe}.png`);
  try { await page.screenshot({ path: file, fullPage: false }); } catch {}
}
async function bodyText(page) { return (await page.locator("body").innerText().catch(() => "")) || ""; }
async function check(page, name, fn) {
  try {
    const detail = await fn();
    record(name, "PASS", detail || "");
  } catch (e) {
    record(name, "FAIL", e && e.message ? e.message : String(e));
    await shot(page, name);
  }
}
async function waitUntil(page, pred, timeoutMs, onTimeout) {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    last = await bodyText(page);
    if (pred(last)) return last;
    await page.waitForTimeout(500);
  }
  if (onTimeout) throw new Error(onTimeout);
  return last;
}

function killStaleDesktop() {
  try {
    const { execSync } = require("node:child_process");
    execSync('taskkill /IM "獬豸安全测试平台.exe" /F /T', { stdio: "ignore" });
  } catch {}
}

(async () => {
  if (!fs.existsSync(exePath)) throw new Error(`未找到打包产物：${exePath}`);
  log("清理遗留桌面进程...");
  killStaleDesktop();
  log("启动打包版桌面应用...");
  const app = await electron.launch({
    executablePath: exePath,
    args: ["."],
    env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined },
    timeout: 180000,
  });

  async function waitForWindow(timeout = 180000) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      for (const c of app.windows().slice().reverse()) {
        if (c.isClosed()) continue;
        const url = c.url();
        if (url && (url.includes("/dist/index.html") || url.includes("#/"))) return c;
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error("等待桌面主窗口超时");
  }

  let page;
  try {
    page = await waitForWindow();
    page.setDefaultTimeout(45000);
    page.on("pageerror", (e) => pageErrors.push(e.message));

    await check(page, "1. 主窗口就绪", async () => {
      const title = await page.title();
      assert.match(title, /獬豸/);
      return `title=${title}`;
    });

    await check(page, "2. 完成向导/登录进入工作区", async () => {
      let text = await bodyText(page);
      if (/AI 安全助手/.test(text)) return "已在工作区";
      const nextBtn = page.locator("button", { hasText: /下一步/ }).first();
      const deadline = Date.now() + 90000;
      while (Date.now() < deadline) {
        const cur = await bodyText(page);
        if (/AI 安全助手/.test(cur)) return "已进入工作区";
        if (cur.includes("用户名") && cur.includes("密码")) break;
        if (await nextBtn.count()) {
          const disabled = await nextBtn.isDisabled().catch(() => true);
          if (!disabled) { await nextBtn.click(); await page.waitForTimeout(1500); }
        }
        await page.waitForTimeout(800);
      }
      const quick = page.locator("button").filter({ hasText: /本机安全凭据/ }).first();
      if (await quick.count()) {
        await quick.click();
        await waitUntil(page, (t) => /AI 安全助手|安全评估项目/.test(t), 60000);
        return "通过本机安全凭据登录";
      }
      return "已登录";
    });
    await shot(page, "workspace");

    await check(page, "3. 页面无未捕获 JS 错误（启动阶段）", async () => {
      assert.equal(pageErrors.length, 0, `pageErrors=${JSON.stringify(pageErrors)}`);
      return "0 errors";
    });

    // 创建一个会话，让会话头部出现（停止续接按钮依赖 selectedThread）。
    await check(page, "4. 发送一条消息以进入会话", async () => {
      const composer = page.locator(".welcome-composer textarea, .thread-composer textarea").first();
      await composer.waitFor({ state: "visible", timeout: 30000 });
      await composer.fill("请扫描本机授权目标的端口");
      await composer.press("Enter");
      // 只要界面切换到会话视图即可，不要求模型一定返回方案。
      await page.waitForTimeout(4000);
      return "已发送";
    });
    await shot(page, "after-send");

    await check(page, "5. 会话头部存在「停止自动续接」按钮", async () => {
      const stop = page.locator('button[aria-label="停止自动续接"]').first();
      // 允许稍等会话视图完成渲染
      const deadline = Date.now() + 20000;
      while (Date.now() < deadline) {
        if (await stop.count()) return "按钮存在";
        await page.waitForTimeout(500);
      }
      const txt = await bodyText(page);
      throw new Error(`未找到停止按钮；页面片段=${txt.slice(0, 200)}`);
    });

    await check(page, "6. 点击「停止自动续接」不报错", async () => {
      const stop = page.locator('button[aria-label="停止自动续接"]').first();
      await stop.click();
      await page.waitForTimeout(2500);
      const txt = await bodyText(page);
      // 无论后端返回 cancelled>0 还是 0，都应给出可读反馈，而不是静默或崩溃。
      const ok = /停止|没有待执行|已停止/.test(txt);
      assert.ok(ok, `未见停止反馈；片段=${txt.slice(0, 300)}`);
      return "点击有可读反馈";
    });
    await shot(page, "after-stop");

    await check(page, "7. 页面无未捕获 JS 错误（全流程）", async () => {
      assert.equal(pageErrors.length, 0, `pageErrors=${JSON.stringify(pageErrors)}`);
      return "0 errors";
    });
  } finally {
    const summary = results.reduce(
      (acc, r) => { acc[r.status] = (acc[r.status] || 0) + 1; return acc; }, {});
    fs.writeFileSync(path.join(out, "summary.json"),
      JSON.stringify({ results, pageErrors, summary }, null, 2), "utf8");
    console.log("\n===== 汇总 =====");
    console.log(JSON.stringify(summary));
    console.log(`截图与报告：${out}`);
    await app.close().catch(() => {});
    killStaleDesktop();
  }
})().catch((e) => { console.error("FATAL:", e); process.exit(1); });
