/*
 * 獬豸授权安全测试平台 — 全量 PoC 扫描（纯 UI 驱动）
 *
 * 模拟真实用户在界面上：
 *   1. 登录（通过登录表单）
 *   2. 进入「主动检测」页
 *   3. 依次选择 131 / 132 的两个 Web 目标
 *   4. 在规则清单中勾选 Nuclei / Afrog / Xray 扫描规则
 *   5. 将每个扫描器的 PoC 选择方式设回「全部已同步」（= 全选 PoC，allPocSources）
 *   6. 点击「开始主动检测」→ 二次确认 → 校验任务创建成功
 *
 * 全程不发任何业务 API 请求，全部由真实点击/输入触发。
 */
const path = require("node:path");
const { chromium } = require(path.resolve(__dirname, "..", "..", "node_modules", "playwright-core"));
const { Harness, loadCredentials } = require("./lib/harness.cjs");
const {
  sleep, settle, navigate, pageTitle, selectOn, lastMessage, clearMessages,
} = require("./lib/ui.cjs");

const BASE_URL = process.env.E2E_BASE_URL || "http://127.0.0.1:5173";

// 每台靶机的 Web URL 目标名片段 → 用于在目标下拉中匹配
// 131 → http://192.168.136.131:8000
// 132 → 该机器开放 5357（Microsoft-HTTPAPI），Web 目标地址依据实际登记的小字 targetValue
const TARGETS = [
  { label: "靶机 131 Web", ip: "192.168.136.131", url: "http://192.168.136.131:8000" },
  { label: "靶机 132 Web", ip: "192.168.136.132" },
];

function browserPath() {
  if (process.env.E2E_BROWSER && fs.existsSync(process.env.E2E_BROWSER)) return process.env.E2E_BROWSER;
  const standardPaths = [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  ];
  for (const sp of standardPaths) if (require("node:fs").existsSync(sp)) return sp;
  throw new Error("未找到浏览器");
}

/** 在目标下拉中把符合地址的关键词全部打印出来，便于匹配 */
async function listTargetOptions(page, selectLocator) {
  await selectLocator.click();
  await sleep(600);
  const dropdown = page.locator(".el-select-dropdown:visible").last();
  await dropdown.waitFor({ state: "visible", timeout: 8000 }).catch(() => {});
  const items = dropdown.locator("li.el-select-dropdown__item");
  const n = await items.count();
  const list = [];
  for (let i = 0; i < n; i++) {
    const t = ((await items.nth(i).textContent()) || "").replace(/\s+/g, " ").trim();
    const cls = (await items.nth(i).getAttribute("class")) || "";
    list.push({ text: t, selected: cls.includes("is-selected") });
  }
  await page.keyboard.press("Escape").catch(() => {});
  await sleep(300);
  return list;
}

/** 读取规则清单所有复选框 */
async function readRules(launcher) {
  const boxes = launcher.locator(".rule-list .el-checkbox");
  const n = await boxes.count();
  const out = [];
  for (let i = 0; i < n; i++) {
    const b = boxes.nth(i);
    const text = ((await b.textContent()) || "").replace(/\s+/g, " ").trim();
    const cls = (await b.getAttribute("class")) || "";
    out.push({ i, text, disabled: cls.includes("is-disabled"), checked: cls.includes("is-checked") });
  }
  return out;
}

/** 取消所有勾选 */
async function clearRules(launcher) {
  for (let g = 0; g < 30; g++) {
    const checked = launcher.locator(".rule-list .el-checkbox.is-checked");
    if ((await checked.count()) === 0) return;
    await checked.first().click().catch(() => {});
    await sleep(250);
  }
}

/** 在片段选择器中确保选中「全部已同步」（ALL 模式） */
async function ensureAllPocMode(page) {
  // 每个已选扫描器都会渲染一个 .poc-selection-mode
  const segs = page.locator(".poc-selection-mode");
  const n = await segs.count();
  const done = [];
  for (let i = 0; i < n; i++) {
    const seg = segs.nth(i);
    // 判断当前选中项：优先按 aria-selected，其次按 is-active 类
    const items = seg.locator(".el-segmented__item");
    const count = await items.count();
    let currentText = "";
    for (let j = 0; j < count; j++) {
      const item = items.nth(j);
      const aria = await item.getAttribute("aria-selected").catch(() => null);
      const cls = (await item.getAttribute("class")) || "";
      const active = aria === "true" || cls.includes("is-active") || cls.includes("--active");
      if (active) currentText = ((await item.textContent()) || "").replace(/\s+/g, " ").trim();
    }
    if (currentText && currentText.includes("全部")) {
      done.push("全部已同步");
    } else {
      const allBtn = seg.locator(".el-segmented__item", { hasText: "全部" }).first();
      await allBtn.waitFor({ state: "visible", timeout: 8000 });
      await allBtn.click();
      await sleep(600);
      done.push("已切换为全部已同步");
    }
  }
  return done;
}

/** 读取摘要中的 PoC 数 */
async function summaryPocCount(launcher) {
  const t = ((await launcher.locator(".scan-summary").first().textContent()) || "").replace(/\s+/g, " ");
  const m = t.match(/(\d+)\s*个\s*PoC/);
  return m ? Number(m[1]) : 0;
}

(async () => {
  const H = new Harness(process.env.E2E_RUN_ID || "POC-FULL-UI");
  const creds = loadCredentials();
  const headless = process.env.HEADLESS === "1";
  const browser = await chromium.launch({
    executablePath: browserPath(),
    headless,
    args: ["--start-maximized", "--disable-features=Translate"],
  });
  const context = await browser.newContext({
    viewport: headless ? { width: 1680, height: 1000 } : null,
    locale: "zh-CN",
    ignoreHTTPSErrors: true,
  });
  const page = await context.newPage();
  page.setDefaultTimeout(25000);
  H.attach(page);

  console.log(`\n獬豸平台 — 全量 PoC 扫描（纯 UI 驱动）`);
  console.log(`运行编号 : ${H.runId}\n`);

  // ---------- 登录 ----------
  H.phase("阶段 A — 登录");
  await page.goto(BASE_URL, { waitUntil: "domcontentloaded", timeout: 30000 });
  await settle(page, 1500);

  // 全新会话会先进入「环境依赖检查」页，需点击「下一步」进入登录
  if (page.url().includes("/setup")) {
    console.log("[setup] 进入环境依赖检查页，等待就绪…");
    const next = page.locator("button", { hasText: "下一步" }).first();
    await next.waitFor({ state: "visible", timeout: 60000 });
    for (let i = 0; i < 30; i++) {
      if (!(await next.isDisabled().catch(() => true))) break;
      await sleep(1000);
    }
    await next.click();
    await settle(page, 2000);
  }

  // 确保落在登录页
  await page.waitForURL(/\/login/, { timeout: 20000 }).catch(() => {});
  if (!page.url().includes("/login")) {
    // 若非登录页，可能已是工作区，直接继续
    console.log("[登录] 当前已在", page.url(), "，跳过表单");
  } else {
    await page.locator('input[placeholder="请输入用户名"]').waitFor({ state: "visible", timeout: 10000 });
    await page.locator('input[placeholder="请输入用户名"]').fill(creds.username);
    await page.locator('input[placeholder="请输入密码"]').type(creds.password, { delay: 5 });
    await page.locator("button.login-button").first().click();
    await page.waitForURL((u) => !u.toString().includes("/login"), { timeout: 20000 });
    await settle(page, 2000);
    console.log("[登录] 成功进入", page.url());
  }

  // ---------- 进入主动检测 ----------
  H.phase("阶段 B — 主动检测页");
  const ok = await H.run("P-01", "通过侧边栏进入「主动检测」页面", async () => {
    await navigate(page, "主动检测");
    const t = await pageTitle(page);
    if (!page.url().includes("/vulnerabilities")) throw new Error(`URL 异常: ${page.url()}`);
    return `标题="${t}"`;
  }, { page });

  await sleep(2000);
  await H.shot(page, "debug-after-navigate");
  const paneProbe = await page.locator(".vuln-workbench").count();
  const asideProbe = await page.locator("aside").count();
  console.log(`[DEBUG] .vuln-workbench=${paneProbe}, <aside>=${asideProbe}, url=${page.url()}`);
  const launcher = page.locator("aside.scan-launcher-pane").first();
  await launcher.waitFor({ state: "visible", timeout: 30000 });
  await clearMessages(page);

  // ---------- 发现所有候选目标 ----------
  H.phase("目标发现");
  const select = launcher.locator(".el-select").first();
  const allTargets = await listTargetOptions(page, select);
  console.log("\n下拉中的目标：");
  for (const t of allTargets) console.log(`  - ${t.selected ? "[已选]" : "[    ]"} ${t.text}`);

  // ---------- 对每台 Web 目标执行全量 PoC 扫描 ----------
  for (const t of TARGETS) {
    H.phase(`目标 ${t.label}`);
    // 挑一个下拉项：文本含目标 IP；优先 URL 型（文本含 http://）
    const withIp = allTargets.filter((x) => x.text.includes(t.ip));
    // 优先选择该 IP 的 Web(URL) 目标，其次任意包含该 IP 的目标
    let candidate = withIp.find((x) => x.text.includes("http://")) || withIp[0];
    if (!candidate) {
      H.skip("P-SKIP", t.label, "下拉中未找到该靶机目标，跳过");
      continue;
    }
    // 用勾选下去完整选项文本进行选择
    const pickText = candidate.text;

    await H.run(`P-${t.label}-T1`, `选择目标：${t.label}`, async () => {
      const opt = page.locator("li.el-select-dropdown__item", { hasText: pickText }).first();
      // 直接点目标下拉并点选该项
      await select.click();
      await sleep(500);
      const dropdown = page.locator(".el-select-dropdown:visible").last();
      await dropdown.waitFor({ state: "visible", timeout: 8000 });
      await opt.waitFor({ state: "visible", timeout: 8000 });
      await opt.click();
      await sleep(1800);
      const txt = ((await select.textContent()) || "").replace(/\s+/g, " ").trim();
      if (!txt.includes(t.ip)) throw new Error(`目标未选中: ${txt.slice(0, 120)}`);
      return `已选择 ${txt.slice(0, 100)}`;
    }, { page });

    await sleep(1200);

    const rules = await readRules(launcher);
    const scannerRules = rules.filter((r) => !r.disabled && /Nuclei|Afrog|Xray|扫描/.test(r.text) && !/安全头|响应|Cookie|CORS|方法|泄露|信息|TLS|端口/.test(r.text));
    // 更精确：优先匹配包含 "Nuclei"/"Afrog"/"Xray"（来源名）的规则
    const named = rules.filter((r) => !r.disabled && /Nuclei|Afrog|Xray/.test(r.text));
    const target = named.length ? named : scannerRules;

    await H.run(`P-${t.label}-T2`, `全部核选 PoC 扫描规则`, async () => {
      await clearRules(launcher);
      const checked = [];
      for (const r of target) {
        await launcher.locator(".rule-list .el-checkbox").nth(r.i).click();
        await sleep(350);
        checked.push(r.text.slice(0, 20));
      }
      if (checked.length === 0) throw new Error("没有可勾选的 PoC 扫描规则");
      return `已勾选 ${checked.length} 条：${checked.join("、")}`;
    }, { page });

    await H.shot(page, `${t.label}-规则已全选`);

    // 每个扫描器 PoC 选自「全部已全部」
    const modes = await ensureAllPocMode(page);

    const pocCount = await summaryPocCount(launcher);

    await H.run(`P-${t.label}-T3`, `摘要显示全量 PoC 计数`, async () => {
      const actual = (await readRules(launcher)).filter((x) => x.checked && /Nuclei|Afrog|Xray/.test(x.text)).length;
      if (pocCount === 0) throw new Error("摘要 PoC 计数为 0（可能未同步 PoC 或未启用扫描源）");
      return `已全选 ${actual} 条扫描规则，全量 PoC≈${pocCount} 个，选择方式=${modes.join("、")}`;
    }, { page });

    await clearMessages(page);
    await page.keyboard.press("Escape").catch(() => {});
    await sleep(400);

    await H.run(`P-${t.label}-T5`, `点击「开始主动检测」并二次确认`, async () => {
      const btn = launcher.locator(".scan-button").first();
      await btn.scrollIntoViewIfNeeded().catch(() => {});
      await btn.click({ timeout: 15000 });
      await sleep(1200);
      const box = page.locator(".el-message-box").last();
      if (!(await box.isVisible({ timeout: 8000 }).catch(() => false))) throw new Error("未弹出二次确认框");
      return `确认框已弹出（含全量 PoC 风险提示）`;
    }, { page });

    await H.shot(page, `${t.label}-确认框`);

    await H.run(`P-${t.label}-T6`, `确认后创建全量 PoC 检测任务`, async () => {
      const box = page.locator(".el-message-box").last();
      if (await box.isVisible().catch(() => false)) {
        await box.locator("button", { hasText: "开始检测" }).last().click();
        await sleep(1000);
      }
      const msg = await lastMessage(page, { timeout: 25000 });
      if (!msg) throw new Error("未出现任何反馈");
      if (msg.type !== "success") throw new Error(`未创建成功（${msg.type}）: ${msg.text}`);
      const m = msg.text.match(/已创建\s*(\d+)\s*个检测任务/);
      if (!m) throw new Error(`成功提示格式异常: ${msg.text}`);
      return `提示="${msg.text}"`;
    }, { page, shotOnPass: true });

    await sleep(3000);
  }

  H.save();
  if (!process.env.E2E_KEEP_OPEN) {
    await context.close().catch(() => {});
    await browser.close().catch(() => {});
  }
  process.exit(H.summary.fail > 0 ? 1 : 0);
})();