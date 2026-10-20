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
    // 用例可通过返回 "SKIP: ..." 表示"不适用（不是失败）"
    if (typeof detail === "string" && detail.startsWith("SKIP:")) {
      record(name, "SKIP", detail.slice(5).trim());
      return;
    }
    if (detail === "FAILED_MARKER") {
      record(name, "FAIL", "进入了非预期状态");
      await shot(page, `fail-${name}`);
      return;
    }
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

/** 从任意页面回到"某个项目"的详情页（通过侧边栏 + 项目列表的「进入项目」） */
async function navigateToProjectDetail(page, projectName) {
  const nav = page.locator("#desktop-v2-primary-navigation");
  await nav.waitFor({ state: "visible", timeout: 20000 });
  const group = nav.locator("#nav-group-projects-assets");
  if ((await group.getAttribute("aria-expanded")) !== "true") {
    await group.click();
    await page.waitForTimeout(600);
  }
  await nav.locator("button.desktop-v2-nav-item", { hasText: "评估项目" }).first().click();
  await page.waitForTimeout(2500);
  await page.locator(".el-table, .empty-state").first().waitFor({ state: "visible", timeout: 30000 });

  const row = projectName
    ? page.locator(".el-table__row").filter({ hasText: projectName }).first()
    : page.locator(".el-table__row").first();
  assert.ok(await row.count(), `项目列表中未找到「${projectName || "任意项目"}」`);
  await row.locator("button", { hasText: "进入项目" }).first().click();
  await page.waitForURL(/\/projects\/\d+/, { timeout: 30000 });
  await page.locator(".project-tabs").first().waitFor({ state: "visible", timeout: 30000 });
  await page.waitForTimeout(1500);
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
    let targetProjectName = "";
    await check(page, "P8 通过界面新建评估项目（含授权有效期）", async () => {
      const rows = await page.locator(".el-table__row").count();
      if (rows > 0) {
        // 复用已有项目时，记录第一行的项目名，供后续"进入项目"定位
        const firstRowText = (await page.locator(".el-table__row").first().innerText())
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean);
        targetProjectName = firstRowText[0] || "";
        return `已有 ${rows} 个项目，复用「${targetProjectName}」`;
      }

      await page.locator("button", { hasText: /新建评估项目|新建项目/ }).first().click();
      const dialog = page.locator(".el-dialog:visible").last();
      await dialog.waitFor({ state: "visible", timeout: 20000 });

      createdName = `桌面自动化-${Date.now().toString().slice(-6)}`;
      targetProjectName = createdName;
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
      const afterCreate = await bodyText(page);
      assert.ok(
        afterCreate.includes(createdName) || /创建成功/.test(afterCreate),
        `新建后列表中未出现项目；可见提示：${afterCreate.slice(0, 200)}`,
      );

      // 新建的项目是 DRAFT（草稿），无法发起信息收集/检测；必须通过编辑对话框激活为 ACTIVE。
      const row = page.locator(".el-table__row").filter({ hasText: createdName }).first();
      await row.locator("button", { hasText: "编辑" }).first().click();
      const editDialog = page.locator(".el-dialog:visible").filter({ hasText: /编辑评估项目/ }).last();
      await editDialog.waitFor({ state: "visible", timeout: 20000 });

      const statusItem = editDialog
        .locator(".el-form-item")
        .filter({ has: page.locator(".el-form-item__label", { hasText: /项目状态/ }) })
        .first();
      await statusItem.locator(".el-select").first().click();
      await page.waitForTimeout(600);
      await page
        .locator(".el-select-dropdown:visible .el-select-dropdown__item")
        .filter({ hasText: "进行中" })
        .first()
        .click();
      await page.waitForTimeout(600);

      await editDialog.locator("button", { hasText: "保存修改" }).first().click();
      // 状态变更会弹确认框（影响授权范围提示）
      await page.waitForTimeout(1500);
      const confirmBox = page.locator(".el-message-box:visible").last();
      if (await confirmBox.isVisible().catch(() => false)) {
        const confirmBtn = confirmBox.locator("button", { hasText: /确认并保存|确定/ }).last();
        if (await confirmBtn.count()) await confirmBtn.click();
      }
      await page.waitForTimeout(2500);

      const afterActivate = await row.innerText().catch(() => "");
      assert.match(
        afterActivate,
        /进行中|ACTIVE/,
        `项目未激活为「进行中」；行内容：${afterActivate.replace(/\s+/g, " ").slice(0, 150)}`,
      );
      return `已创建并激活项目「${createdName}」`;
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

    // ================================================================
    // 轨道 A：在真实窗口内登记授权目标并真正执行一次 dir_scan
    // ================================================================
    const TARGET_IP = process.env.E2E_TARGET || "192.168.222.139";
    const TARGET_PORTS = process.env.E2E_TARGET_PORTS || "80,443";
    let scanWebPaths = [];
    let scanEvidence = [];

    let targetCreated = false;
    await check(page, "A1 通过界面为项目登记授权目标", async () => {
      const nav = page.locator("#desktop-v2-primary-navigation");
      const group = nav.locator("#nav-group-projects-assets");
      if ((await group.getAttribute("aria-expanded")) !== "true") {
        await group.click();
        await page.waitForTimeout(600);
      }
      await nav.locator("button.desktop-v2-nav-item", { hasText: "授权目标" }).first().click();
      await page.waitForTimeout(2500);
      await page.locator(".el-table, .empty-state").first().waitFor({ state: "visible", timeout: 30000 });

      // 已存在同地址目标时直接复用，保证脚本可重复运行
      const existing = page.locator(".el-table__row").filter({ hasText: TARGET_IP });
      if ((await existing.count()) > 0) {
        return `已存在目标 ${TARGET_IP}，直接复用`;
      }

      await page.locator("button", { hasText: /新增授权目标|新增目标/ }).first().click();
      const dialog = page.locator(".el-dialog:visible").last();
      await dialog.waitFor({ state: "visible", timeout: 20000 });

      const itemByLabel = (re) =>
        dialog
          .locator(".el-form-item")
          .filter({ has: page.locator(".el-form-item__label", { hasText: re }) })
          .first();

      // 归属项目
      const projectSelect = itemByLabel(/归属评估项目/).locator(".el-select").first();
      await projectSelect.click();
      await page.waitForTimeout(600);
      const projectOption = page
        .locator(".el-select-dropdown:visible .el-select-dropdown__item")
        .filter({ hasText: targetProjectName || "目标" })
        .first();
      if (await projectOption.count()) await projectOption.click();
      else await page.locator(".el-select-dropdown:visible .el-select-dropdown__item").first().click();
      await page.waitForTimeout(800);

      await itemByLabel(/^名称/).locator("input").first().fill(`靶机 ${TARGET_IP}`);
      await itemByLabel(/授权记录/).locator("textarea").first().fill("桌面自动化验收：已确认本机靶场授权");
      await itemByLabel(/地址/).locator("input").first().fill(TARGET_IP);
      await page.waitForTimeout(500);

      // 端口：关闭全端口开关，改为指定端口
      const fullPortSwitch = dialog.locator(".full-port-option .el-switch").first();
      if (await fullPortSwitch.count()) {
        const checked = await fullPortSwitch.getAttribute("class").then((c) => c?.includes("is-checked"));
        if (checked) await fullPortSwitch.click();
        await page.waitForTimeout(600);
      }
      const portSelect = itemByLabel(/端口授权模式/).locator(".el-select").first();
      if (await portSelect.count()) {
        await portSelect.click();
        await page.waitForTimeout(500);
        const portInput = page.locator(".el-select-dropdown:visible input").first();
        if (await portInput.count()) {
          await portInput.fill(TARGET_PORTS);
          await page.keyboard.press("Enter");
          await page.waitForTimeout(500);
        }
        await page.keyboard.press("Escape");
      }

      const save = page.locator(".el-dialog:visible").last().locator("button", { hasText: /保存|确定|新增/ }).last();
      await save.click();
      await page.waitForTimeout(3000);

      const rows = await page.locator(".el-table__row").filter({ hasText: TARGET_IP }).count();
      assert.ok(rows > 0, `保存后目标列表未出现 ${TARGET_IP}`);
      targetCreated = true;
      return `已登记目标 ${TARGET_IP}（端口 ${TARGET_PORTS}）`;
    });

    await shot(page, "desktop-target-created");

    await check(page, "A2 信息收集页选中该目标并配置目录枚举", async () => {
      // 回到项目详情 → 信息收集
      await navigateToProjectDetail(page, targetProjectName);
      const tabs = page.locator(".project-tabs").first();
      await tabs.locator(".el-tabs__item", { hasText: "信息收集" }).first().click();
      await page.waitForTimeout(2000);

      const pane = page.locator(".el-tab-pane:visible").last();
      await pane.waitFor({ state: "visible", timeout: 20000 });

      // 选目标
      const targetSelect = pane.locator(".recon-controls-row--primary .el-select").first();
      await targetSelect.click();
      await page.waitForTimeout(800);
      const targetOption = page
        .locator(".el-select-dropdown:visible .el-select-dropdown__item")
        .filter({ hasText: TARGET_IP })
        .first();
      assert.ok(await targetOption.count(), `目标下拉中未找到 ${TARGET_IP}`);
      await targetOption.click();
      await page.waitForTimeout(1500);

      // 主动收集
      await pane.locator(".el-radio-button", { hasText: "主动收集" }).first().click();
      await page.waitForTimeout(1500);

      const text = (await pane.innerText()).replace(/\s+/g, " ");
      assert.match(text, /目录\/路径枚举/, "未出现目录/路径枚举勾选项");
      return "已选中目标并切到主动收集";
    });

    await shot(page, "desktop-recon-target-selected");

    await check(page, "A3 选择字典与并发数后点击开始收集", async () => {
      const pane = page.locator(".el-tab-pane:visible").last();

      // 目录/路径枚举 勾选
      const enumCheckbox = pane.locator(".el-checkbox", { hasText: "目录/路径枚举" }).first();
      const cls = (await enumCheckbox.getAttribute("class")) || "";
      if (!cls.includes("is-checked")) {
        await enumCheckbox.click();
        await page.waitForTimeout(800);
      }

      // 字典：选 dirb common（含 index.html 与靶场 Less-[1-65] 模板，能稳定命中真实路径）
      const dictSelect = pane.locator(".recon-controls-row--options .el-select").first();
      await dictSelect.click();
      await page.waitForTimeout(800);
      const commonOption = page
        .locator(".el-select-dropdown:visible .el-select-dropdown__item")
        .filter({ hasText: /dirb common/i })
        .first();
      if (await commonOption.count()) await commonOption.click();
      else await page.locator(".el-select-dropdown:visible .el-select-dropdown__item").first().click();
      await page.waitForTimeout(800);

      // 并发数
      const concurrency = pane.locator(".recon-controls-row--options .el-input-number input").first();
      if (await concurrency.count()) {
        await concurrency.fill("20");
        await concurrency.press("Enter");
        await page.waitForTimeout(500);
      }

      const before = await pane.innerText();
      assert.match(before.replace(/\s+/g, " "), /dirb common/i, "字典未切换到 dirb common");
      return "字典=dirb common，并发=20";
    });

    await shot(page, "desktop-recon-configured");

    await check(page, "A4 开始收集并在确认框后完成真实目录扫描", async () => {
      const pane = page.locator(".el-tab-pane:visible").last();
      const startBtn = pane.locator("button", { hasText: "开始收集" }).first();
      assert.ok(await startBtn.count(), "未找到开始收集按钮");

      // 用网络响应判断完成，避免依赖文案（文案可能被前一屏残留覆盖而误判）
      const responsePromise = page
        .waitForResponse(
          (resp) => /\/recon\/collect$/.test(new URL(resp.url()).pathname),
          { timeout: Number(process.env.E2E_SCAN_TIMEOUT_MS || 600000) },
        )
        .catch(() => null);

      await startBtn.click();

      // 确认框
      const confirmBox = page.locator(".el-message-box:visible").last();
      await confirmBox.waitFor({ state: "visible", timeout: 15000 });
      const confirmBtn = confirmBox.locator("button", { hasText: /确认执行|确认/ }).last();
      await confirmBtn.click();

      const startedAt = Date.now();
      const resp = await responsePromise;
      assert.ok(resp, "等待 recon/collect 响应超时（扫描可能仍未在时限内返回）");
      assert.equal(resp.status(), 200, `recon/collect 返回 ${resp.status()}`);
      const payload = await resp.json().catch(() => null);
      assert.ok(payload, "recon 响应无法解析为 JSON");
      // 后端把 webPaths / sourceEvidence 序列化为 JSON 字符串存储
      let paths = payload.webPaths;
      if (typeof paths === "string") {
        try { paths = JSON.parse(paths); } catch { paths = []; }
      }
      assert.ok(Array.isArray(paths), "recon 响应缺少 webPaths");
      scanWebPaths = paths;
      scanEvidence = payload.sourceEvidence;

      // 等 UI 渲染结果
      await page.waitForTimeout(2500);
      return `扫描完成（${Math.round((Date.now() - startedAt) / 1000)}s），webPaths=${scanWebPaths.length}`;
    });

    await shot(page, "desktop-recon-scanned");

    await check(page, "A5 扫描结果中确有发现的路径（非空且为真实 URL）", async () => {
      const pane = page.locator(".el-tab-pane:visible").last();

      // 先看接口返回的语义结果（sourceEvidence 是 JSON 字符串）
      let evidenceList = scanEvidence;
      if (typeof evidenceList === "string") {
        try { evidenceList = JSON.parse(evidenceList); } catch { evidenceList = []; }
      }
      const enumEvidence = Array.isArray(evidenceList)
        ? evidenceList.find((e) => e && e.source === "PATH_ENUM")
        : null;
      const discovered = (scanWebPaths || []).filter((u) => /^https?:\/\//.test(String(u)));

      // 结果区必须出现记录
      const collapse = pane.locator(".recon-results .el-collapse-item").first();
      assert.ok(await collapse.count(), "结果区没有渲染任何信息收集记录");

      const title = collapse.locator(".el-collapse-item__header").first();
      if ((await title.getAttribute("aria-expanded")) !== "true") {
        await title.click();
        await page.waitForTimeout(2000);
      }
      const body = (await collapse.innerText()).replace(/\s+/g, " ");
      assert.match(body, /已发现路径/, `结果详情中没有「已发现路径」区块：${body.slice(0, 400)}`);

      // 语义断言：本次扫描确实发现了可达路径
      assert.ok(
        discovered.length > 0,
        `本次扫描未发现路径（dictionary=${enumEvidence?.dictionary}, candidates=${enumEvidence?.candidates}, found=${enumEvidence?.found}）；` +
          `请确认靶机 ${TARGET_IP} 上存在该字典覆盖的路径`,
      );

      // 结果区文本里也要能看到 URL（证明前端确实渲染了，而不是只存在接口里）
      const urls = (await collapse.locator(".recon-text-entry .recon-item-text").allInnerTexts())
        .map((t) => t.trim())
        .filter((t) => /^https?:\/\//.test(t));
      assert.ok(urls.length > 0, "结果区未渲染任何 URL");
      return `发现 ${discovered.length} 条路径；示例：${discovered.slice(0, 3).join("、")}`;
    });

    await shot(page, "desktop-recon-paths");

    // ================================================================
    // 轨道 B：LLM 规划 → HITL 人工审批 → 执行（全部在真实窗口内完成）
    // ================================================================
    await check(page, "B1 打开 AI 安全助手并新建项目绑定对话", async () => {
      const nav = page.locator("#desktop-v2-primary-navigation");
      const group = nav.locator("#nav-group-ai-workspace");
      if ((await group.getAttribute("aria-expanded")) !== "true") {
        await group.click();
        await page.waitForTimeout(500);
      }
      await nav.locator("button.desktop-v2-nav-item", { hasText: "AI 安全助手" }).first().click();
      await page.waitForTimeout(3000);

      // 新建对话
      const newChat = page.locator("button", { hasText: /新建对话/ }).first();
      if (await newChat.count()) {
        await newChat.click();
        await page.waitForTimeout(2500);
      }
      const text = await bodyText(page);
      assert.match(text, /AI 安全助手|比如|例如/, `未进入 AI 工作区：${text.slice(0, 200)}`);
      return "已进入 AI 安全助手";
    });

    await shot(page, "desktop-ai-workspace");

    await check(page, "B2 选择项目授权目标并发送一条检测需求", async () => {
      // 欢迎页输入框与目标选择器
      const textarea = page.locator(".welcome-composer textarea, .thread-composer textarea").first();
      await textarea.waitFor({ state: "visible", timeout: 20000 });

      // 目标选择器（欢迎页 composer-footer 里的 el-select）
      const picker = page.locator(".composer-footer .target-picker, .composer-footer .el-select").first();
      if (await picker.count()) {
        await picker.click();
        await page.waitForTimeout(1000);
        const opt = page
          .locator(".el-select-dropdown:visible .el-select-dropdown__item")
          .filter({ hasText: TARGET_IP })
          .first();
        if (await opt.count()) {
          await opt.click();
          await page.waitForTimeout(1200);
        } else {
          await page.locator(".el-select-dropdown:visible .el-select-dropdown__item").first().click();
          await page.waitForTimeout(1200);
        }
      }

      // 关键：要触发 HITL 审批链，用户必须明确要求"执行"。
      // 说"先给方案"只会得到 PLAN_ONLY（纯规划，不提交审批），这是产品正确行为。
      const prompt =
        process.env.E2E_AI_PROMPT ||
        `请立即对这个授权目标执行一次目录扫描，用小字典和 20 并发。`;
      await textarea.fill(prompt);
      await page.waitForTimeout(500);

      const send = page.locator(".welcome-composer .send-button, .thread-composer .send-button, .composer-footer .send-button").first();
      assert.ok(await send.count(), "未找到发送按钮");
      await send.click();
      await page.waitForTimeout(3000);
      return `已发送：${prompt.slice(0, 40)}…`;
    });

    await shot(page, "desktop-ai-sent");

    let aiApprovalReached = false;
    await check(page, "B3 LLM 返回包含目录扫描的执行方案", async () => {
      // 等待助手回答完成（流式输出结束后页面出现"已完成 X 秒"），真实 LLM 给足 5 分钟
      const deadline = Date.now() + Number(process.env.E2E_AI_TIMEOUT_MS || 300000);
      let last = "";
      let finished = false;
      while (Date.now() < deadline) {
        last = await bodyText(page);
        // 终态：回答完成/失败，或审批区块已出现
        if (/等待管理员确认后执行|查看方案详情/.test(last)) {
          finished = true;
          break;
        }
        // 明确终态（流结束后才会出现"已完成 X 秒/失败"）；"正在等待/回答中"是中间态，继续等
        if (/已完成 \d|失败|未获得模型回答/.test(last) && !/正在等待|回答中/.test(last)) {
          finished = true;
          break;
        }
        await page.waitForTimeout(3000);
      }
      assert.ok(finished, `等待 LLM 回复超时；最后页面片段：${last.slice(-400)}`);

      if (/未获得模型回答|本轮处理未完成/.test(last)) {
        throw new Error(`AI 规划失败（模型未返回）：${last.slice(-300)}`);
      }
      assert.match(
        last,
        /执行计划|本轮已核对的方案参数/,
        `LLM 回复中没有执行方案：${last.slice(-300)}`,
      );
      // 明确要求了"执行"，正常应进入待审批
      aiApprovalReached = /等待管理员确认后执行|查看方案详情/.test(last);
      return aiApprovalReached
        ? "LLM 返回方案并进入待审批状态"
        : "LLM 返回方案（PLAN_ONLY，未提交审批）";
    });

    await shot(page, "desktop-ai-plan");

    /** 审批对话框可能随方案生成自动弹出；若未弹出则点「查看方案详情」打开。 */
    async function openApprovalDialog() {
      const existing = page
        .locator(".ai-approval-modal:visible, .el-dialog:visible")
        .filter({ hasText: /检测操作授权审批/ })
        .first();
      if (await existing.isVisible().catch(() => false)) {
        return existing;
      }
      const detailBtn = page.locator("button", { hasText: /查看方案详情/ }).first();
      if (!(await detailBtn.count())) {
        return null;
      }
      await detailBtn.click();
      const dialog = page
        .locator(".ai-approval-modal:visible, .el-dialog:visible")
        .filter({ hasText: /检测操作授权审批/ })
        .first();
      await dialog.waitFor({ state: "visible", timeout: 20000 });
      return dialog;
    }

    await check(page, "B4 HITL：审批卡片展示方案且默认不执行", async () => {
      const dialog = await openApprovalDialog();
      if (!dialog) {
        return aiApprovalReached
          ? "FAILED_MARKER"
          : "SKIP: LLM 判定为仅规划（PLAN_ONLY），产品按设计不提交审批申请；如需覆盖审批链请设置 E2E_AI_PROMPT 明确要求执行";
      }
      await dialog.waitFor({ state: "visible", timeout: 20000 });

      const body = (await dialog.innerText()).replace(/\s+/g, " ");
      // 卡片必须展示工具/参数/风险，供管理员核对
      assert.match(body, /方案 #\d+/, `审批卡片缺少方案编号：${body.slice(0, 300)}`);
      assert.match(body, /允许执行/, "审批卡片缺少「允许执行」");
      assert.match(body, /拒绝执行/, "审批卡片缺少「拒绝执行」");

      // 关闭卡片：此时必须仍未创建任务
      const closeBtn = dialog.locator("button", { hasText: /关闭，继续等待/ }).first();
      assert.ok(await closeBtn.count(), "审批卡片缺少「关闭，继续等待」");
      await closeBtn.click();
      await page.waitForTimeout(1500);

      const afterClose = await bodyText(page);
      assert.match(afterClose, /等待管理员确认后执行|查看方案详情/, "关闭卡片后应仍处于待审批状态");
      return "审批卡片展示了待确认方案，关闭后仍未执行";
    });

    await shot(page, "desktop-ai-approval-card");

    await check(page, "B5 管理员确认后按原计划派发任务（HITL 放行）", async () => {
      const dialog = await openApprovalDialog();
      if (!dialog) {
        return "SKIP: 无待审批方案（PLAN_ONLY 路径不产生审批申请）";
      }

      // 按钮内含图标节点，innerText 可能有空白；用模糊匹配并排除"拒绝"项
      const approve = dialog
        .locator("button")
        .filter({ hasText: /允许执行/ })
        .filter({ hasNotText: /拒绝/ })
        .first();
      assert.ok(await approve.count(), "审批卡片缺少「允许执行」按钮");
      await approve.click();

      // 确认后应出现已派发提示
      const deadline = Date.now() + 120000;
      let last = "";
      while (Date.now() < deadline) {
        last = await bodyText(page);
        if (/已按原计划派发|已关联 \d+ 个任务|任务已创建|确认记录 #\d+/.test(last)) {
          return "管理员已批准，任务已按原计划派发";
        }
        if (/执行失败|派发失败/.test(last)) {
          throw new Error(`派发失败：${last.slice(-300)}`);
        }
        await page.waitForTimeout(2500);
      }
      throw new Error(`等待派发结果超时；页面片段：${last.slice(-400)}`);
    });

    await shot(page, "desktop-ai-approved");

    await check(page, "B6 审批通过后产生真实检测任务", async () => {
      const b5 = results.find((r) => r.name.startsWith("B5"));
      if (b5 && b5.status !== "PASS") {
        return "SKIP: B5 未放行（无审批方案），不产生检测任务";
      }
      // 到「检测任务」页核实任务确实创建
      const nav = page.locator("#desktop-v2-primary-navigation");
      const group = nav.locator("#nav-group-detection-analysis");
      if ((await group.getAttribute("aria-expanded")) !== "true") {
        await group.click();
        await page.waitForTimeout(600);
      }
      await nav.locator("button.desktop-v2-nav-item", { hasText: "检测任务" }).first().click();
      await page.waitForTimeout(3000);
      await page.locator(".el-table, .empty-state").first().waitFor({ state: "visible", timeout: 30000 });

      const rows = await page.locator(".el-table__row").count();
      assert.ok(rows > 0, "审批通过后检测任务列表仍为空");
      const firstRow = (await page.locator(".el-table__row").first().innerText()).replace(/\s+/g, " ");
      return `任务列表有 ${rows} 条记录；最新一条：${firstRow.slice(0, 120)}`;
    });

    await shot(page, "desktop-ai-tasks");

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
