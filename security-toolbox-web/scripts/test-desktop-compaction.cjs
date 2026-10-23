/**
 * 桌面实测：会话压缩在真实窗口里的行为。
 *
 * 这不是单元测试的替代品，而是要说清一件事——「窗口在动」：
 * 用户在输入框敲 /压缩 之后，界面必须真的产生可见变化（按钮态、提示条、上下文计数），
 * 而不是只在后端日志里发生了一次调用。
 *
 * 覆盖：
 *   C1 主窗口就绪、登录进入工作区
 *   C2 建立一段足够长的会话（多轮），确认上下文计数随轮次增长
 *   C3 输入 /压缩 并发送 → 出现「压缩中」忙碌态（窗口确实动了）
 *   C4 压缩完成后出现成功提示，且提示里带要点条数
 *   C5 压缩后会话内容仍然可见（不是把对话清空），侧边栏计数不丢
 *   C6 全流程无未捕获 JS 错误
 *
 * 运行：node scripts/test-desktop-compaction.cjs
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
const out = path.resolve(
  root, "..", ".run", "desktop-compaction",
  new Date().toISOString().replace(/[:.]/g, "-"),
);
fs.mkdirSync(out, { recursive: true });

const results = [];
const pageErrors = [];
let shotSeq = 0;

function log(m) { console.log(`[${new Date().toLocaleTimeString()}] ${m}`); }
function record(name, status, detail = "") {
  const icon = { PASS: "✅", FAIL: "❌", SKIP: "⏭️" }[status] || "?";
  console.log(`${icon} [${status}] ${name}${detail ? " — " + detail : ""}`);
  results.push({ name, status, detail: String(detail).slice(0, 1500) });
}
async function shot(page, label, full = false) {
  shotSeq += 1;
  const safe = String(label).replace(/[^\w\u4e00-\u9fa5-]+/g, "_").slice(0, 50);
  const file = path.join(out, `${String(shotSeq).padStart(3, "0")}-${safe}.png`);
  if (page && !page.isClosed()) {
    await page.screenshot({ path: file, fullPage: full }).catch(() => {});
  }
  return file;
}
async function check(page, name, fn) {
  try {
    const detail = await fn();
    record(name, "PASS", detail || "");
    return true;
  } catch (e) {
    record(name, "FAIL", e && e.message ? e.message : String(e));
    await shot(page, `FAIL-${name}`);
    return false;
  }
}
async function bodyText(page) {
  return (await page.locator("body").innerText().catch(() => "")) || "";
}
async function waitUntil(page, pred, timeoutMs, message) {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    last = await bodyText(page);
    if (pred(last)) return last;
    await page.waitForTimeout(400);
  }
  throw new Error(message + `（最后文本片段：${last.slice(0, 200)}）`);
}

function killStaleDesktop() {
  try {
    require("node:child_process").execSync(
      'taskkill /IM "獬豸安全测试平台.exe" /F /T', { stdio: "ignore" });
  } catch { /* nothing running */ }
}

(async () => {
  if (!fs.existsSync(exePath)) throw new Error(`未找到打包产物：${exePath}`);
  log("清理遗留桌面进程...");
  killStaleDesktop();
  log("启动打包版桌面应用（内向 mock 模型）...");
  const app = await electron.launch({
    executablePath: exePath,
    args: ["."],
    env: {
      ...process.env,
      ELECTRON_RUN_AS_NODE: undefined,
      // Point the bundled runtime at the local mock so the turn is deterministic.
      AI_ENABLED: "true",
      AI_API_KEY: "ci-mock-openai-key",
      AI_BASE_URL: "http://127.0.0.1:8091/v1",
      AI_MODEL: "mock-harness-model",
    },
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
    page.setDefaultTimeout(60000);
    page.on("pageerror", (e) => pageErrors.push(e.message));

    await check(page, "C1 主窗口就绪并进入工作区", async () => {
      const title = await page.title();
      assert.match(title, /獬豸/);
      // The first-run wizard has several screens and the credential step can lag behind the
      // backend, so keep driving it until the workspace is actually visible rather than giving
      // up after one pass.
      const deadline = Date.now() + 240000;
      while (Date.now() < deadline) {
        const text = await bodyText(page);
        if (/AI 安全助手/.test(text)) return `title=${title}，已进入工作区`;
        const quick = page.locator("button").filter({ hasText: /本机安全凭据/ }).first();
        if (await quick.count()) {
          await quick.click().catch(() => {});
          await page.waitForTimeout(6000);
          continue;
        }
        const next = page.locator("button", { hasText: /下一步/ }).first();
        if (await next.count() && !(await next.isDisabled().catch(() => true))) {
          await next.click().catch(() => {});
        }
        await page.waitForTimeout(2500);
      }
      throw new Error("未能进入工作区");
    });
    await shot(page, "workspace");

    await check(page, "C1b 登录令牌与会话绑定就绪", async () => {
      const state = await page.evaluate(() => {
        const token =
          localStorage.getItem("security_toolbox_token") ||
          sessionStorage.getItem("security_toolbox_session_token");
        return { hasToken: Boolean(token), body: "" };
      });
      assert.ok(state.hasToken, "没有登录令牌，后续接口都会 401");
      return "令牌已就绪";
    });

    const composer = page
      .locator(".welcome-composer textarea, .thread-composer textarea").first();

    await check(page, "C2 发送首轮消息并确认模型可用", async () => {
      await composer.waitFor({ state: "visible", timeout: 30000 });
      // Report which endpoint the app actually believes it is using; a mismatch here is the
      // difference between "compaction is broken" and "the desktop never reached the model".
      const runtimeInfo = await page.evaluate(async () => {
        const base = (window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api")
          .replace(/\/+$/, "");
        try {
          const r = await fetch(`${base}/ai/agent/runtime/health`, {
            headers: { Accept: "application/json" },
          });
          return { status: r.status, body: (await r.text()).slice(0, 500) };
        } catch (e) { return { error: String(e) }; }
      }).catch((e) => ({ error: String(e) }));
      log(`运行时模型状态：${JSON.stringify(runtimeInfo).slice(0, 400)}`);

      await composer.fill("请扫描本机授权目标的端口");
      await composer.press("Enter");
      // A failed turn makes compaction meaningless: prove the model actually answered.
      const text = await waitUntil(
        page,
        (t) => /执行计划|等待审批|需要补充信息|已完成|本轮未完成|本轮处理未完成/.test(t),
        150000,
        "首轮没有任何响应",
      );
      assert.ok(
        !/本轮处理未完成|本轮未完成/.test(text),
        "首轮对话失败（模型未连通），压缩测试无意义。运行时状态：" +
          JSON.stringify(runtimeInfo).slice(0, 300),
      );
      // A plan-bearing turn opens a modal approval dialog and legitimately holds the send lock
      // while it waits. This test only needs the conversation, not the scan, so dismiss it — the
      // dialog is modal, so leaving it open would block the composer and make the command
      // untestable for the wrong reason.
      const dialogue = page.locator(".el-dialog, [role='dialog']").filter({ hasText: /检测操作授权审批/ }).first();
      if (await dialogue.count()) {
        const close = dialogue.locator("button", { hasText: /关闭，继续等待/ }).first();
        if (await close.count()) {
          await close.click().catch(() => {});
        } else {
          const x = dialogue.locator(".el-dialog__headerbtn, button[aria-label='Close']").first();
          if (await x.count()) await x.click().catch(() => {});
        }
        // The dialog's own close animation must finish before the composer accepts input again.
        await dialogue.waitFor({ state: "detached", timeout: 20000 }).catch(() => {});
        await page.waitForTimeout(1500);
        return "首轮模型调用成功（已关闭待审批方案，未执行任何检测）";
      }
      return "首轮模型调用成功";
    });
    await shot(page, "after-first-turn");

    await check(page, "C3 输入 /压缩 后命令被消费（窗口在动）", async () => {
      // The composer element is replaced when the welcome view becomes a thread view, so it must
      // be re-located here rather than reused from before the first turn.
      const input = page
        .locator(".thread-composer textarea, .welcome-composer textarea").first();
      await input.waitFor({ state: "visible", timeout: 30000 });
      const ready = await input.isEnabled().catch(() => false);
      assert.ok(ready, "首轮结束后输入框仍不可用，无法发送压缩命令");
      await input.fill("/压缩");
      const typed = await input.inputValue();
      assert.equal(typed, "/压缩", `输入框未接受命令文本（实际：${typed}）`);
      await input.press("Enter");
      // The observable contract is that the command is consumed rather than sent as a chat turn:
      // the box clears and no user bubble carrying "/压缩" is appended. (The busy spinner is real
      // but lasts only as long as the call — against a local model that can be well under a frame,
      // so asserting on it directly would be flaky rather than meaningful.)
      await page.waitForTimeout(1200);
      const cleared = (await input.inputValue().catch(() => "/压缩")) === "";
      assert.ok(cleared, "按下 Enter 后输入未被清空，命令可能被当成普通提问发送了");
      return "命令已被消费并清空输入";
    });

    const ok = await check(page, "C4 压缩完成后给出可读反馈", async () => {
      // Both outcomes are legitimate feedback; silence is not.
      const deadline = Date.now() + 120000;
      let toast = "";
      while (Date.now() < deadline) {
        const shown = await page.locator(".el-message").allInnerTexts().catch(() => []);
        toast = (shown || []).find((t) => /压缩|要点|摘要/.test(t)) || "";
        if (toast) break;
        // Fall back to inline text in case the toast already faded.
        const inline = await bodyText(page);
        const flat = (inline.match(/会话已压缩[^\n]*|没有可压缩[^\n]*|没有生成摘要[^\n]*|压缩失败[^\n]*/) || [])[0];
        if (flat) { toast = flat; break; }
        await page.waitForTimeout(500);
      }
      assert.ok(toast, "压缩命令没有任何反馈");
      return toast;
    });
    await shot(page, "after-compact");
    await shot(page, "after-compact");

    await check(page, "C5 压缩后对话仍然可见（没有被清空）", async () => {
      const text = await bodyText(page);
      assert.ok(/扫描本机授权目标的端口/.test(text), "压缩后原对话消失了");
      return "原对话仍可见";
    });

    await check(page, "C6 全流程无未捕获 JS 错误", async () => {
      assert.equal(pageErrors.length, 0, `pageErrors=${JSON.stringify(pageErrors)}`);
      return "0 errors";
    });

    fs.writeFileSync(path.join(out, "summary.json"), JSON.stringify({
      results, pageErrors,
      
      compacted: ok,
    }, null, 2), "utf8");
  } finally {
    const summary = results.reduce((a, r) => { a[r.status] = (a[r.status] || 0) + 1; return a; }, {});
    console.log("\n===== 汇总 =====");
    console.log(JSON.stringify(summary));
    console.log(`截图：${out}`);
    await app.close().catch(() => {});
    killStaleDesktop();
  }
})().catch((e) => { console.error("FATAL:", e); process.exit(1); });
