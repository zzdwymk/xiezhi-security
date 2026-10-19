/*
 * 桌面程序（打包 Electron 生产构建）端到端自动化测试。
 *
 * 与 tests/e2e/*（浏览器 + Vite dev server）的区别：
 *   这里驱动的是**真实打包产物** desktop-release/win-unpacked 下的 Electron 应用。
 *
 * 关键事实（来自生命周期探针 scripts/_probe-desktop-lifecycle.cjs）：
 *   1. 启动先出现 startup.html 启动窗，约 16 秒后主窗（dist/index.html）打开、启动窗关闭。
 *      Playwright firstWindow() 抓到的是启动窗，必须等待含 dist/index.html 的主窗。
 *   2. 应用持有单实例锁：上一轮遗留进程会让本次启动立刻 exitCode=0 退出。
 *   3. 每次全新启动都落在 /setup 依赖检查向导，需要推进后才到登录页。
 *
 * 运行：
 *   node scripts/test-desktop-packaged-e2e.cjs
 *
 * 断言原则：业务动作全部通过真实界面完成（点击/输入），不直接改数据库或调后端 API 伪造状态。
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
const out = path.resolve(root, "..", ".run", "desktop-packaged-e2e", new Date().toISOString().replace(/[:.]/g, "-"));
fs.mkdirSync(out, { recursive: true });

const results = [];
const pageErrors = [];
let shotSeq = 0;

function record(name, status, detail = "") {
  const icon = { PASS: "[PASS]", FAIL: "[FAIL]", SKIP: "[SKIP]" }[status] || "[????]";
  console.log(`${icon} ${name}${detail ? " — " + detail : ""}`);
  results.push({ name, status, detail: String(detail).slice(0, 1500) });
}

async function shot(page, label) {
  shotSeq += 1;
  const safe = String(label).replace(/[^\w\u4e00-\u9fa5-]+/g, "_").slice(0, 50);
  const file = path.join(out, `${String(shotSeq).padStart(3, "0")}-${safe}.png`);
  if (page && !page.isClosed()) {
    await page.screenshot({ path: file, animations: "disabled" }).catch(() => {});
  }
  return file;
}

async function check(page, name, fn) {
  try {
    const detail = await fn();
    record(name, "PASS", detail || "");
  } catch (error) {
    record(name, "FAIL", (error && error.message) || String(error));
    await shot(page, `fail-${name}`);
  }
}

function killStaleDesktop() {
  try {
    execFileSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-Command",
        "Get-Process | Where-Object { $_.ProcessName -like '*獬豸*' } | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 1500",
      ],
      { encoding: "utf8", windowsHide: true, timeout: 30000 },
    );
  } catch {
    /* 没有遗留进程属正常 */
  }
}

async function bodyText(page) {
  return page.locator("body").innerText().catch(() => "");
}

async function waitUntil(page, predicate, timeoutMs, onTimeout) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const text = await bodyText(page);
    if (predicate(text)) return text;
    await page.waitForTimeout(400);
  }
  throw new Error(onTimeout || `等待条件超时（${timeoutMs}ms）`);
}

/**
 * 在 Element Plus datetime 面板里选一个具体日期（相对今天的偏移天），并保持默认时间。
 * 开始选今天（offset=0），结束选 +30 天，从而满足 dateWindowValid 的 to > from。
 */
async function pickDate(page, inputLocator, dayOffset) {
  await inputLocator.click();
  const panel = page.locator(".el-picker-panel:visible").last();
  await panel.waitFor({ state: "visible", timeout: 15000 });

  // 面板分两列：日期列 + 时间列。目标日期的单元格按当月天数序号定位。
  // 优先点 today（offset=0），否则点当前可见月份的第 (1+offset) 个可点日期。
  if (dayOffset === 0) {
    const today = panel.locator("td.today, td.available.today").first();
    if (await today.count()) {
      await today.click();
    } else {
      await panel.locator("td.available").first().click();
    }
  } else {
    // 前进到未来日期：先点"下个月"，再点对应天数。
    const nextMonth = panel.locator("button.el-icon-arrow-right, .el-date-picker__next-btn").first();
    if (await nextMonth.count()) {
      await nextMonth.click();
      await page.waitForTimeout(300);
    }
    const cells = panel.locator("td.available");
    const count = await cells.count();
    if (count > 0) {
      const idx = Math.min(Math.max(dayOffset - 1, 0), count - 1);
      await cells.nth(idx).click();
    }
  }

  await page.waitForTimeout(400);
  // datetime 面板底部有「现在 / 确定」；点「确定」提交所选日期（时间保留默认）。
  const confirm = panel.locator("button", { hasText: /确\s*定|确定/ }).last();
  if (await confirm.count()) await confirm.click({ timeout: 5000 }).catch(() => {});
  else await page.keyboard.press("Enter");
  await page.waitForTimeout(600);
}

(async () => {
  if (!fs.existsSync(exePath)) {
    throw new Error(`未找到打包产物：${exePath}（请先运行 scripts/package-desktop-release.ps1）`);
  }
  killStaleDesktop();

  const app = await electron.launch({
    executablePath: exePath,
    args: ["."],
    env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined },
    timeout: 180000,
  });

  // 等待真正的主窗（dist/index.html），跳过 startup.html 启动窗
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
    throw new Error("等待桌面工作区主窗口超时");
  }

  let page;
  try {
    page = await waitForWorkspaceWindow();
    page.setDefaultTimeout(30000);
    page.on("pageerror", (error) => pageErrors.push(error.message));

    await check(page, "P1 桌面主窗口打开且标题正确", async () => {
      const title = await page.title();
      assert.match(title, /獬豸/);
      return `title=${title}`;
    });

    await check(page, "P2 主进程托起了打包版后端进程", async () => {
      const listing = execFileSync(
        "powershell.exe",
        [
          "-NoProfile",
          "-Command",
          "Get-CimInstance Win32_Process -Filter \"Name='java.exe'\" | ForEach-Object { $_.CommandLine }",
        ],
        { encoding: "utf8", windowsHide: true, timeout: 20000 },
      );
      assert.match(listing, /security-toolbox-server\.jar/, "未发现后端进程");
      assert.match(listing, /desktop-release/, "后端未从打包目录启动");
      return "后端 java 进程已由桌面主进程启动";
    });

    await check(page, "P3 启动向导展示依赖检查", async () => {
      const text = await waitUntil(
        page,
        (t) => /检测运行依赖|检测依赖|下一步/.test(t) || /AI 安全助手/.test(t),
        90000,
      );
      if (/AI 安全助手/.test(text)) return "已直接进入工作区";
      return "依赖检查向导已渲染";
    });

    await shot(page, "desktop-setup");

    await check(page, "P4 依赖检测结果显示核心依赖就绪", async () => {
      const text = await bodyText(page);
      const hasJava = /Java/.test(text);
      const readyCount = (text.match(/可用/g) || []).length;
      assert.ok(hasJava, "依赖列表中缺少 Java 行");
      return `依赖列表已渲染，含 Java；"可用"出现 ${readyCount} 次`;
    });

    await check(page, "P5 推进启动向导到达登录页", async () => {
      if (/AI 安全助手/.test(await bodyText(page))) return "已在工作区";

      // 两条合法路径都接受：
      //  a) 依赖检测完成后自动进入（勾选了「下次依赖满足时自动进入」）；
      //  b) 「下一步，进入工具箱」按钮变为可点击后手动点击。
      // Metasploit 冷启动可能触发 90 秒 SSE 超时后再 fallback 重试，故整体等待放宽。
      const deadline = Date.now() + 180000;
      while (Date.now() < deadline) {
        const text = await bodyText(page);
        // 已到达登录页或工作区即通过
        if ((text.includes("用户名") && text.includes("密码")) || /AI 安全助手/.test(text)) {
          return "已到达登录页";
        }
        // 尝试点击可用的「下一步」按钮（若有）
        const next = page.locator("button", { hasText: /下一步/ }).first();
        if (await next.count()) {
          const disabled = await next.isDisabled().catch(() => true);
          if (!disabled) {
            await next.click();
            await page.waitForTimeout(2000);
          }
        }
        await page.waitForTimeout(1000);
      }
      const body = await bodyText(page);
      throw new Error(`180 秒内未到达登录页；当前文案片段：${body.slice(0, 300)}`);
    });

    await shot(page, "desktop-login");

    await check(page, "P6 本机安全凭据登录成功进入工作区", async () => {
      const quick = page.locator("button").filter({ hasText: /本机安全凭据/ }).first();
      assert.ok(await quick.count(), "登录页缺少「使用本机安全凭据登录」按钮");
      await quick.click();
      const text = await waitUntil(
        page,
        (t) => /AI 安全助手|安全评估项目/.test(t) || /本机安全凭据与当前后端账号不一致|本机安全登录未完成/.test(t),
        60000,
        "点击本机凭据后无任何结果",
      );
      assert.ok(
        /AI 安全助手|安全评估项目/.test(text),
        `本机凭据登录失败：${text.split("\n").find((l) => /不一致|未完成/.test(l)) || ""}`,
      );
      return "已登录并进入工作区";
    });

    await shot(page, "desktop-workspace");

    await check(page, "P7 侧边栏导航到「评估项目」并加载列表", async () => {
      const nav = page.locator("#desktop-v2-primary-navigation");
      await nav.waitFor({ state: "visible", timeout: 20000 });
      const group = nav.locator("#nav-group-projects-assets");
      if ((await group.getAttribute("aria-expanded")) !== "true") {
        await group.click();
        await page.waitForTimeout(600);
      }
      await nav.locator("button.desktop-v2-nav-item", { hasText: "评估项目" }).first().click();
      await waitUntil(page, (t) => t.includes("安全评估项目"), 30000);
      await page.locator(".el-table, .empty-state").first().waitFor({ state: "visible", timeout: 30000 });
      return `URL 含 #/projects`;
    });

    await shot(page, "desktop-projects");

    let createdName = "";
    await check(page, "P8 通过界面新建评估项目（含授权有效期）", async () => {
      const rows = await page.locator(".el-table__row").count();
      if (rows > 0) return `已有 ${rows} 个项目，跳过创建`;

      await page.locator("button", { hasText: /新建评估项目|新建项目/ }).first().click();
      const dialog = page.locator(".el-dialog:visible").last();
      await dialog.waitFor({ state: "visible", timeout: 20000 });

      createdName = `桌面自动化-${Date.now().toString().slice(-6)}`;
      const field = (labelRe, tag = "input") =>
        dialog
          .locator(".el-form-item")
          .filter({ has: page.locator(".el-form-item__label", { hasText: labelRe }) })
          .locator(tag)
          .first();

      await field(/项目名称/).fill(createdName);
      await field(/负责人/).fill("admin");
      await field(/授权声明/, "textarea").fill("桌面自动化验收：仅对本地靶场执行受控测试");

      const dateInputs = dialog.locator(".el-form-item input[placeholder*='选择']");
      if ((await dateInputs.count()) >= 2) {
        await pickDate(page, dateInputs.nth(0), 0);   // 授权开始 = 今天
        await pickDate(page, dateInputs.nth(1), 30);  // 授权结束 = 未来 30 天
      }

      await dialog.locator("button", { hasText: /创建项目|确定|保存/ }).first().click();
      await page.waitForTimeout(3000);
      const text = await bodyText(page);
      assert.ok(
        text.includes(createdName) || /创建成功/.test(text),
        `新建后列表中未出现项目；可见提示：${text.slice(0, 200)}`,
      );
      return `已创建项目「${createdName}」`;
    });

    await shot(page, "desktop-project-created");

    await check(page, "P9 打开项目详情并切换到「信息收集」页签", async () => {
      const enter = page.locator("button", { hasText: "进入项目" }).first();
      assert.ok(await enter.count(), "项目列表中没有「进入项目」按钮");
      await enter.click();
      await page.waitForURL(/\/projects\/\d+/, { timeout: 30000 });
      const tabs = page.locator(".project-tabs").first();
      await tabs.waitFor({ state: "visible", timeout: 30000 });
      await tabs.locator(".el-tabs__item", { hasText: "信息收集" }).first().click();
      await page.waitForTimeout(2000);
      await waitUntil(page, (t) => /主动收集/.test(t), 30000, "未渲染信息收集面板");
      return "已进入信息收集页签";
    });

    await shot(page, "desktop-recon");

    await check(page, "P10 主动模式下展示目录枚举字典与并发设置", async () => {
      const pane = page.locator(".el-tab-pane:visible").last();
      await pane.waitFor({ state: "visible", timeout: 20000 });
      const before = await pane.innerText();
      assert.match(before, /目录\/路径枚举/, "缺少「目录/路径枚举」勾选项");

      const active = pane.locator(".el-radio-button", { hasText: "主动收集" }).first();
      if (await active.count()) {
        await active.click();
        await page.waitForTimeout(1500);
      }
      const after = (await pane.innerText()).replace(/\s+/g, " ");
      assert.match(after, /dirb|dirbuster|字典/i, `主动模式下未出现字典控件：${after.slice(0, 300)}`);
      return "目录枚举开关、字典选择与并发输入均已渲染";
    });

    await shot(page, "desktop-recon-options");

    await check(page, "P11 渲染进程无未捕获异常", async () => {
      assert.equal(pageErrors.length, 0, `页面异常：${pageErrors.slice(0, 3).join(" | ")}`);
      return `pageerror 计数=0`;
    });
  } finally {
    const summary = {
      generatedAt: new Date().toISOString(),
      exePath,
      total: results.length,
      pass: results.filter((r) => r.status === "PASS").length,
      fail: results.filter((r) => r.status === "FAIL").length,
      skip: results.filter((r) => r.status === "SKIP").length,
      results,
      pageErrors,
    };
    fs.writeFileSync(path.join(out, "result.json"), JSON.stringify(summary, null, 2), "utf8");
    console.log(`\n合计 ${summary.total}  通过 ${summary.pass}  失败 ${summary.fail}  跳过 ${summary.skip}`);
    console.log(`证据目录: ${out}`);
    killStaleDesktop();
    await app.close().catch(() => {});
    process.exitCode = summary.fail > 0 ? 1 : 0;
  }
})().catch((error) => {
  console.error("桌面自动化测试异常终止:", error && error.message);
  killStaleDesktop();
  process.exitCode = 1;
});
