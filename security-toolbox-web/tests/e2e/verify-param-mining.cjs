/*
 * 漏报率改进验证 —— 参数探测(param-mining)全链路 UI 验证
 *
 * 目标：证明「站点存在注入参数、但自动发现只拿到无参目录 → sqlmap 漏报」这一漏报链
 * 被新加的 recon 参数探测阶段修复。全部由真实浏览器点击/输入触发，不直接调后端造数据。
 *
 * 步骤：
 *   1. 登录
 *   2. 打开指定项目 → 「信息收集」标签 → 选 URL 目标 → 主动收集(勾选站点爬取) → 开始收集
 *   3. 打开「主动检测」→ 选同一 URL 目标 → 读「已发现子路径」下拉
 *   4. 断言下拉里出现带 ?id= 的可注入候选(如 /Less-2/?id=1)，即参数探测已把它补进来
 *
 * 运行：
 *   E2E_BASE_URL=http://127.0.0.1:5173 E2E_PROJECT_ID=290 E2E_TARGET_LABEL=136.132 \
 *     HEADLESS=1 node tests/e2e/verify-param-mining.cjs
 */
const path = require("node:path");
const fs = require("node:fs");
const { chromium } = require(path.resolve(__dirname, "..", "..", "node_modules", "playwright-core"));
const { Harness, loadCredentials } = require("./lib/harness.cjs");
const {
  sleep, settle, navigate, confirmBoxIfPresent, lastMessage, clearMessages,
} = require("./lib/ui.cjs");

const BASE_URL = process.env.E2E_BASE_URL || "http://127.0.0.1:5173";
const PROJECT_ID = process.env.E2E_PROJECT_ID || "290";
// 用于在下拉里挑选 132 的 URL 目标（名称含该片段即可）。
const TARGET_LABEL = process.env.E2E_TARGET_LABEL || "136.132";

function browserPath() {
  if (process.env.E2E_BROWSER && fs.existsSync(process.env.E2E_BROWSER)) return process.env.E2E_BROWSER;
  const paths = process.platform === "win32" ? [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  ] : [];
  for (const p of paths) if (fs.existsSync(p)) return p;
  throw new Error("未找到 Edge 或 Chrome");
}

// 选择 el-select：点击打开，等待下拉项，点含关键字的 option（URL 类型优先）。
async function pickSelect(page, selectLocator, keyword, { preferType = null } = {}) {
  await selectLocator.click();
  await sleep(600);
  const options = page.locator(".el-select-dropdown:visible .el-select-dropdown__item");
  await options.first().waitFor({ state: "visible", timeout: 8000 });
  const n = await options.count();
  let chosen = -1;
  for (let i = 0; i < n; i++) {
    const t = (await options.nth(i).textContent().catch(() => "")) || "";
    if (!t.includes(keyword)) continue;
    if (preferType && t.includes(preferType)) { chosen = i; break; }
    if (chosen < 0) chosen = i;
  }
  if (chosen < 0) throw new Error(`下拉中未找到含「${keyword}」的选项（共 ${n} 项）`);
  const label = (await options.nth(chosen).textContent().catch(() => "")).trim();
  await options.nth(chosen).click();
  await sleep(400);
  return label;
}

(async () => {
  const creds = loadCredentials();
  const H = new Harness(process.env.E2E_RUN_ID || "verify-param-mining");
  const browser = await chromium.launch({ headless: process.env.HEADLESS === "1", executablePath: browserPath() });
  const context = await browser.newContext({ viewport: { width: 1600, height: 1000 }, ignoreHTTPSErrors: true });
  const page = await context.newPage();
  H.attach(page);

  try {
    H.phase("参数探测漏报修复验证");

    // ---------- 登录 ----------
    await H.run("V-01", "登录平台", async () => {
      await page.goto(BASE_URL, { waitUntil: "domcontentloaded", timeout: 30000 });
      await settle(page, 1200);
      // 若停在依赖检查页，点“下一步”
      if (page.url().includes("/setup")) {
        const next = page.locator("button", { hasText: "下一步" }).first();
        for (let i = 0; i < 40 && (await next.isDisabled().catch(() => true)); i++) await sleep(1000);
        await next.click().catch(() => {});
        await settle(page, 1500);
      }
      await page.waitForURL(/\/login/, { timeout: 15000 }).catch(() => {});
      await page.locator('input[placeholder="请输入用户名"]').fill(creds.username);
      await page.locator('input[placeholder="请输入密码"]').type(creds.password, { delay: 5 });
      await page.locator("button.login-button").first().click();
      await page.waitForURL((u) => !u.toString().includes("/login"), { timeout: 20000 });
      await settle(page, 1500);
      return `已登录，进入 ${page.url()}`;
    }, { page });

    // ---------- 打开项目 → 信息收集 ----------
    await H.run("V-02", "打开项目并进入「信息收集」标签", async () => {
      await page.goto(`${BASE_URL}/projects/${PROJECT_ID}`, { waitUntil: "domcontentloaded", timeout: 30000 });
      await settle(page, 1500);
      const reconTab = page.locator('.el-tabs__item', { hasText: "信息收集" }).first();
      await reconTab.waitFor({ state: "visible", timeout: 15000 });
      await reconTab.click();
      await settle(page, 1200);
      const controls = await page.locator(".recon-controls").first().isVisible().catch(() => false);
      if (!controls) throw new Error("信息收集控件未渲染");
      return "已进入信息收集工作区";
    }, { page });

    // ---------- 选目标 + 主动收集 ----------
    await H.run("V-03", "选择 URL 目标并切到「主动收集」，勾选站点爬取", async () => {
      const targetSelect = page.locator(".recon-controls .el-select").first();
      const label = await pickSelect(page, targetSelect, TARGET_LABEL, { preferType: "http://" });
      // 切到主动收集
      const activeBtn = page.locator(".recon-controls .el-radio-button", { hasText: "主动收集" }).first();
      await activeBtn.click();
      await sleep(500);
      // 确保「站点爬取」勾选（主动模式下才可用）
      const crawl = page.locator(".recon-controls .el-checkbox", { hasText: "站点爬取" }).first();
      const checked = await crawl.locator("input").isChecked().catch(() => false);
      if (!checked) await crawl.click();
      return `目标=${label}；已切主动收集+站点爬取`;
    }, { page, shotOnPass: true });

    await H.run("V-04", "点击「开始收集」并确认，等待完成", async () => {
      await clearMessages(page);
      const startBtn = page.locator(".recon-controls button", { hasText: "开始收集" }).first();
      await startBtn.click();
      // 主动收集确认框
      await confirmBoxIfPresent(page, "确认执行", { timeout: 6000 });
      // 等待完成提示（收集含目录枚举+爬取+参数探测，给足时间）
      const msg = await lastMessage(page, { timeout: 90000 });
      if (!msg) throw new Error("未出现收集完成提示");
      if (msg.type === "error") throw new Error(`收集失败：${msg.text}`);
      await settle(page, 1500);
      return `收集完成提示="${msg.text}"`;
    }, { page, shotOnPass: true });

    // ---------- 主动检测：读已发现路径 ----------
    let minedCandidate = null;
    await H.run("V-05", "进入「主动检测」并选择同一 URL 目标", async () => {
      await navigate(page, "主动检测");
      await settle(page, 1500);
      // 「授权目标」下拉：紧跟在文本为“授权目标”的 label 之后的 el-select。
      const targetSelect = page
        .locator('.scan-form label:has-text("授权目标") + .el-select')
        .first();
      await targetSelect.waitFor({ state: "visible", timeout: 10000 });
      // URL 目标名形如「靶机Web-192.168.136.132-XXXX」，含 136.132；优先带 http:// 的那条。
      const label = await pickSelect(page, targetSelect, TARGET_LABEL, { preferType: "Web" });
      await settle(page, 1800); // 触发 watch → 拉取 discovered-paths
      return `已选目标=${label}`;
    }, { page });

    await H.run("V-06", "「已发现子路径」中出现参数探测补入的可注入候选(?id=)", async () => {
      // 路径选择器仅在有已发现路径时渲染；标题含「扫描路径范围」
      const label = page.locator("label", { hasText: "扫描路径范围" }).first();
      const shown = await label.isVisible({ timeout: 8000 }).catch(() => false);
      if (!shown) throw new Error("未渲染「扫描路径范围」——目标没有任何已发现路径");
      // 路径多选下拉紧跟在「扫描路径范围」label 之后。
      const select = page
        .locator('.scan-form label:has-text("扫描路径范围") + .el-select')
        .first();
      await select.waitFor({ state: "visible", timeout: 8000 });
      await select.scrollIntoViewIfNeeded().catch(() => {});
      await select.click();
      await sleep(700);
      const opts = page.locator(".el-select-dropdown:visible .el-select-dropdown__item");
      await opts.first().waitFor({ state: "visible", timeout: 8000 });
      const n = await opts.count();
      const texts = [];
      for (let i = 0; i < n; i++) texts.push(((await opts.nth(i).textContent().catch(() => "")) || "").trim());
      const withParam = texts.filter((t) => /\?\s*\w+=/.test(t));
      const idCandidate = texts.find((t) => /\?id=/.test(t));
      minedCandidate = idCandidate || withParam[0] || null;
      await page.keyboard.press("Escape").catch(() => {});
      if (!withParam.length) {
        throw new Error(`已发现路径中没有任何带查询参数的候选。全部候选：\n${texts.join("\n")}`);
      }
      return `带参候选 ${withParam.length} 条，示例：${withParam.slice(0, 5).join(" | ")}`;
    }, { page, shotOnPass: true });

    // ---------- 用 sqlmap 对挖掘出的路径发起检测，闭环证明漏报被消除 ----------
    await H.run("V-07", "勾选 sqlmap 规则并选中挖掘出的可注入路径", async () => {
      // 勾选检测规则里的 sqlmap（rule.name = “sqlmap SQL 注入检测”）
      const sqlmapRule = page
        .locator(".rule-list .el-checkbox", { hasText: "sqlmap" })
        .first();
      await sqlmapRule.waitFor({ state: "visible", timeout: 10000 });
      await sqlmapRule.scrollIntoViewIfNeeded().catch(() => {});
      if (!(await sqlmapRule.locator("input").isChecked().catch(() => false))) {
        await sqlmapRule.click();
      }
      await sleep(400);
      // 在路径多选里勾选带 ?id= 的候选
      const select = page
        .locator('.scan-form label:has-text("扫描路径范围") + .el-select')
        .first();
      await select.scrollIntoViewIfNeeded().catch(() => {});
      await select.click();
      await sleep(600);
      const opts = page.locator(".el-select-dropdown:visible .el-select-dropdown__item");
      await opts.first().waitFor({ state: "visible", timeout: 8000 });
      const n = await opts.count();
      let picked = null;
      for (let i = 0; i < n; i++) {
        const t = ((await opts.nth(i).textContent().catch(() => "")) || "").trim();
        if (/\?id=/.test(t)) { await opts.nth(i).click(); picked = t; break; }
      }
      await page.keyboard.press("Escape").catch(() => {});
      if (!picked) throw new Error("未能在下拉勾选 ?id= 候选");
      return `已勾选 sqlmap 规则 + 路径「${picked}」`;
    }, { page, shotOnPass: true });

    await H.run("V-08", "点击「开始主动检测」并确认发起 sqlmap 任务", async () => {
      await clearMessages(page);
      const startBtn = page.locator("button.scan-button", { hasText: "开始主动检测" }).first();
      await startBtn.scrollIntoViewIfNeeded().catch(() => {});
      await startBtn.click();
      // 确认框「开始检测」
      await confirmBoxIfPresent(page, "开始检测", { timeout: 8000 });
      const msg = await lastMessage(page, { timeout: 20000 });
      if (!msg) throw new Error("未出现任务创建提示");
      if (msg.type === "error") throw new Error(`发起失败：${msg.text}`);
      return `发起提示="${msg.text}"`;
    }, { page, shotOnPass: true });

    await H.run("V-09", "等待 sqlmap 任务完成并在「结果中心」确认 HIGH SQL 注入发现", async () => {
      await navigate(page, "结果中心");
      await settle(page, 1500);
      // sqlmap 可能耗时较长；在结果中心轮询含 SQL 注入的 HIGH 记录（最多 ~6 分钟）。
      const deadline = Date.now() + 6 * 60 * 1000;
      let hit = null;
      while (Date.now() < deadline) {
        // 刷新列表
        const refresh = page.locator("button", { hasText: "刷新" }).first();
        if (await refresh.isVisible().catch(() => false)) { await refresh.click().catch(() => {}); }
        await settle(page, 1200);
        const rows = page.locator(".el-table__row");
        const rc = await rows.count().catch(() => 0);
        for (let i = 0; i < rc; i++) {
          const txt = ((await rows.nth(i).textContent().catch(() => "")) || "");
          if (/SQL\s*注入/i.test(txt) && /HIGH|高危/i.test(txt)) { hit = txt.replace(/\s+/g, " ").trim(); break; }
        }
        if (hit) break;
        await sleep(5000);
      }
      if (!hit) throw new Error("超时未在结果中心看到 HIGH 级 SQL 注入发现");
      return `发现命中：${hit.slice(0, 90)}`;
    }, { page, shotOnPass: true });

    H.record("V-INFO", "参数探测候选", "PASS", minedCandidate ? `可注入候选：${minedCandidate}` : "（见 V-06 列表）");
  } catch (err) {
    H.record("V-FATAL", "验证过程异常终止", "FAIL", String(err && err.stack ? err.stack : err));
  } finally {
    await H.shot(page, "V-最终状态");
    H.save();
    await browser.close();
  }
})();
