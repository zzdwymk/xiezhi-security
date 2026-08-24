/*
 * UI 交互原语层。
 *
 * 本层的每个函数都对应一次"真实用户动作"：点击、输入、选择、确认。
 * 严禁在此层或调用方直接发起 HTTP API 请求来制造业务数据。
 * 页面跳转一律通过点击侧边栏/按钮完成，仅在断言"直达 URL 受保护"等
 * 少数场景才允许 page.goto（并在用例中显式说明）。
 */

const SIDEBAR = {
  // 分组 → 该组下的菜单项
  "AI 工作区": ["AI 安全助手", "红队工作流"],
  "项目与资产": ["评估项目", "授权目标"],
  "检测与分析": ["主动检测", "检测任务", "结果中心", "流量分析"],
  "系统与审计": ["审计日志", "离线工具集"],
};

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** 等待 Element Plus 的遮罩/loading 消失，避免点击被拦截 */
async function settle(page, ms = 400) {
  await page.waitForLoadState("domcontentloaded").catch(() => {});
  await sleep(ms);
}

/* ------------------------------------------------------------------ */
/* 导航                                                                */
/* ------------------------------------------------------------------ */

// 分组 id 映射，用于判断分组展开状态
const GROUP_IDS = {
  "AI 工作区": "ai-workspace",
  "项目与资产": "projects-assets",
  "检测与分析": "detection-analysis",
  "系统与审计": "system-audit",
};

/**
 * 通过点击侧边栏导航到指定页面。
 *
 * 注意：折叠分组的菜单项在 DOM 中仍报告 visible=true 且有尺寸，
 * 但其容器带 inert 且 pointer-events:none，点击会超时。
 * 因此必须以分组切换按钮的 aria-expanded 判断展开状态。
 */
async function navigate(page, itemLabel) {
  const group = Object.keys(SIDEBAR).find((g) => SIDEBAR[g].includes(itemLabel));
  if (!group) throw new Error(`未知的侧边栏菜单项: ${itemLabel}`);
  const groupId = GROUP_IDS[group];

  const nav = page.locator("#desktop-v2-primary-navigation");
  await nav.waitFor({ state: "visible", timeout: 15000 });

  const toggle = nav.locator(`#nav-group-${groupId}`);
  await toggle.waitFor({ state: "visible", timeout: 10000 });

  const expanded = await toggle.getAttribute("aria-expanded");
  if (expanded !== "true") {
    await toggle.click();
    // 应用 CSP 禁用 unsafe-eval，不能使用 waitForFunction，改为轮询属性
    let ok = false;
    for (let i = 0; i < 30; i++) {
      if ((await toggle.getAttribute("aria-expanded")) === "true") { ok = true; break; }
      await sleep(200);
    }
    if (!ok) throw new Error(`分组「${group}」展开失败`);
    await sleep(400);
  }

  const item = nav.locator("button.desktop-v2-nav-item", { hasText: itemLabel }).first();
  await item.click();
  await settle(page, 1200);
}

/** 通过用户下拉菜单进入系统设置（唯一入口） */
async function openSettings(page) {
  await page.locator("button.desktop-v2-user").first().click();
  await sleep(600);
  const menu = page.locator(".desktop-v2-user-menu");
  await menu.waitFor({ state: "visible", timeout: 8000 });
  await menu.locator("text=系统设置").first().click();
  await settle(page, 1200);
}

/** 当前页面标题（顶栏） */
async function pageTitle(page) {
  return (await page.locator(".desktop-v2-title > strong").first().textContent().catch(() => "") || "").trim();
}

/* ------------------------------------------------------------------ */
/* 表单控件                                                            */
/* ------------------------------------------------------------------ */

/**
 * 按标签精确定位 Element Plus 表单项。
 *
 * 必须匹配 .el-form-item__label 的完整文本，不能用整个表单项的 hasText：
 * 例如「地址」是「IP 地址」的子串，用 hasText 会错误命中「目标类型」那一项。
 */
function formItem(scope, page, label) {
  const re = new RegExp(`^\\s*\\*?\\s*${escapeRe(label)}\\s*[:：]?\\s*$`);
  return scope
    .locator(".el-form-item")
    .filter({ has: page.locator(".el-form-item__label").filter({ hasText: re }) })
    .first();
}

/** 在对话框/容器内按标签定位输入框并填值 */
async function fillByLabel(scope, page, label, value) {
  const item = formItem(scope, page, label);
  await item.waitFor({ state: "visible", timeout: 10000 });
  const input = item.locator("input.el-input__inner, textarea.el-textarea__inner").first();
  await input.click();
  await input.fill("");
  await input.type(String(value), { delay: 12 });
  return input;
}

/** 选择 Element Plus 下拉框选项（popper 渲染在 body 层） */
async function selectOption(scope, page, label, optionText, { exact = false } = {}) {
  const item = formItem(scope, page, label);
  await item.waitFor({ state: "visible", timeout: 10000 });
  await item.locator(".el-select").first().click();
  await sleep(500);
  const dropdown = page.locator(".el-select-dropdown:visible").last();
  await dropdown.waitFor({ state: "visible", timeout: 8000 });
  const opt = exact
    ? dropdown.locator("li.el-select-dropdown__item").filter({ hasText: new RegExp(`^\\s*${escapeRe(optionText)}\\s*$`) }).first()
    : dropdown.locator("li.el-select-dropdown__item", { hasText: optionText }).first();
  await opt.waitFor({ state: "visible", timeout: 8000 });
  await opt.click();
  await sleep(400);
}

/** 直接对某个 el-select 元素选择选项（无表单标签时使用） */
async function selectOn(page, selectLocator, optionText, { exact = false } = {}) {
  await selectLocator.click();
  await sleep(500);
  const dropdown = page.locator(".el-select-dropdown:visible").last();
  await dropdown.waitFor({ state: "visible", timeout: 8000 });
  const opt = exact
    ? dropdown.locator("li.el-select-dropdown__item").filter({ hasText: new RegExp(`^\\s*${escapeRe(optionText)}\\s*$`) }).first()
    : dropdown.locator("li.el-select-dropdown__item", { hasText: optionText }).first();
  await opt.waitFor({ state: "visible", timeout: 8000 });
  await opt.click();
  await sleep(400);
}

/**
 * 日期时间选择器操作。
 *
 * Element Plus 的 el-date-picker 输入框不接受 fill()/type() 直接赋值
 * （输入会被组件丢弃），且按 Escape 会连带关闭外层对话框。
 * 因此统一通过面板控件完成选择——这也更贴近真实用户操作。
 */

/** 打开指定标签的日期面板 */
async function openDatePanel(scope, page, label) {
  const item = formItem(scope, page, label);
  await item.waitFor({ state: "visible", timeout: 10000 });
  const input = item.locator("input").first();
  await input.click();
  await sleep(800);
  const panel = page.locator(".el-picker-panel:visible").first();
  await panel.waitFor({ state: "visible", timeout: 8000 });
  return { input, panel };
}

/** 选择「此刻」（当前时间）并确定 */
async function pickDateTimeNow(scope, page, label) {
  const { input, panel } = await openDatePanel(scope, page, label);
  await panel.locator("button, a").filter({ hasText: /^\s*此刻\s*$/ }).first().click();
  await sleep(400);
  const ok = panel.locator("button, a").filter({ hasText: /^\s*确定\s*$/ }).last();
  if (await ok.isVisible().catch(() => false)) { await ok.click(); await sleep(600); }
  const v = await input.inputValue();
  if (!v) throw new Error(`「${label}」选择「此刻」后取值为空`);
  return v;
}

/** 向后翻 monthsAhead 个月并选择某一天 */
async function pickDateTimeFuture(scope, page, label, { monthsAhead = 2, day = 15 } = {}) {
  const { input, panel } = await openDatePanel(scope, page, label);
  const header = panel.locator(".el-date-picker__header").first();
  for (let i = 0; i < monthsAhead; i++) {
    await header.locator("button.arrow-right").first().click();
    await sleep(450);
  }
  await panel.locator("td.available", { hasText: new RegExp(`^${day}$`) }).first().click();
  await sleep(500);
  const ok = panel.locator("button, a").filter({ hasText: /^\s*确定\s*$/ }).last();
  if (await ok.isVisible().catch(() => false)) { await ok.click(); await sleep(600); }
  const v = await input.inputValue();
  if (!v) throw new Error(`「${label}」选择未来日期后取值为空`);
  return v;
}

/** 读取日期输入框当前值 */
async function dateValue(scope, page, label) {
  return await formItem(scope, page, label).locator("input").first().inputValue();
}

/* ------------------------------------------------------------------ */
/* 对话框与确认                                                        */
/* ------------------------------------------------------------------ */

/** 等待标题匹配的对话框出现并返回其定位器 */
async function dialog(page, titleText, timeout = 12000) {
  const d = page.locator(".el-dialog", { hasText: titleText }).filter({ has: page.locator(".el-dialog__body") }).last();
  await d.waitFor({ state: "visible", timeout });
  await sleep(400);
  return d;
}

/** 点击对话框底部按钮 */
async function dialogButton(dlg, text) {
  const btn = dlg.locator("button", { hasText: text }).last();
  await btn.waitFor({ state: "visible", timeout: 8000 });
  await btn.click();
}

/**
 * 处理 ElMessageBox 确认框。
 * buttonText 可为字符串或候选数组——不同确认框的确认按钮文案不同
 * （如"确定"/"删除"/"确认并保存"/"全部清空"），传数组可按顺序匹配存在的那个。
 */
async function confirmBox(page, buttonText, { timeout = 10000 } = {}) {
  const box = page.locator(".el-message-box").last();
  await box.waitFor({ state: "visible", timeout });
  await sleep(300);
  const candidates = Array.isArray(buttonText) ? buttonText : [buttonText];
  for (const label of candidates) {
    const btn = box.locator("button", { hasText: label }).last();
    if (await btn.count()) {
      await btn.click({ timeout: 8000 });
      await sleep(600);
      return label;
    }
  }
  const available = (await box.locator("button").allTextContents()).map((s) => s.trim()).filter(Boolean);
  throw new Error(`确认框中未找到按钮 ${candidates.join("/")}，实际按钮: ${available.join(" | ")}`);
}

/** 若存在 ElMessageBox 则点击指定按钮（支持候选数组），不存在则忽略 */
async function confirmBoxIfPresent(page, buttonText, { timeout = 3000 } = {}) {
  const box = page.locator(".el-message-box").last();
  const shown = await box.isVisible().catch(() => false);
  if (!shown) {
    try { await box.waitFor({ state: "visible", timeout }); }
    catch { return false; }
  }
  await sleep(250);
  const candidates = Array.isArray(buttonText) ? buttonText : [buttonText];
  for (const label of candidates) {
    const btn = box.locator("button", { hasText: label }).last();
    if (await btn.count()) {
      await btn.click({ timeout: 8000 }).catch(() => {});
      await sleep(600);
      return label;
    }
  }
  return false;
}

/* ------------------------------------------------------------------ */
/* 消息提示                                                            */
/* ------------------------------------------------------------------ */

/**
 * 等待并读取最近一条 el-message 提示（成功/失败）。
 * 注意：Element Plus 的 ElMessage 默认 3 秒后自动消失，
 * 因此必须使用 waitFor 主动等待，不能用 isVisible 瞬时判断。
 */
async function lastMessage(page, { timeout = 8000 } = {}) {
  const any = page.locator(".el-message").first();
  try {
    await any.waitFor({ state: "visible", timeout });
  } catch {
    return null;
  }
  const text = (await any.textContent().catch(() => "")) || "";
  const cls = (await any.getAttribute("class").catch(() => "")) || "";
  const type = /--error/.test(cls) ? "error" : /--success/.test(cls) ? "success" : /--warning/.test(cls) ? "warning" : "info";
  return { text: text.trim(), type };
}

/** 等待出现指定类型的提示消息 */
async function waitMessage(page, type, { timeout = 10000 } = {}) {
  const sel = `.el-message--${type}`;
  await page.locator(sel).first().waitFor({ state: "visible", timeout });
  const text = (await page.locator(sel).first().textContent().catch(() => "")) || "";
  return text.trim();
}

/** 清掉当前所有提示，避免影响后续断言 */
async function clearMessages(page) {
  await page.evaluate(() => {
    document.querySelectorAll(".el-message").forEach((n) => n.remove());
  }).catch(() => {});
}

/* ------------------------------------------------------------------ */
/* 表格                                                                */
/* ------------------------------------------------------------------ */

/** 表格行数（可指定容器） */
async function rowCount(scope) {
  return await scope.locator(".el-table__row").count();
}

/** 找到包含指定文本的表格行 */
function rowContaining(scope, text) {
  return scope.locator(".el-table__row", { hasText: text }).first();
}

/** 等待表格中出现包含指定文本的行 */
async function waitRow(scope, text, timeout = 15000) {
  const row = rowContaining(scope, text);
  await row.waitFor({ state: "visible", timeout });
  return row;
}

/* ------------------------------------------------------------------ */
/* 工具                                                                */
/* ------------------------------------------------------------------ */

function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** 格式化为 el-date-picker 接受的 "YYYY-MM-DD HH:mm:ss" */
function fmtDateTime(d) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/* ------------------------------------------------------------------ */
/* 文件下载                                                            */
/* ------------------------------------------------------------------ */

/**
 * 读取应用实际收到的报告下载响应记录（由 run-all.cjs 注入的 XHR 包裹器写入）。
 *
 * 不要用 Playwright 的 download 事件来断言报告接口：这些响应带
 * Content-Disposition: attachment，会被 Chromium 下载管理器拦截，
 * 发起请求的 XHR 只会拿到一个空的合成响应，据此断言会把环境行为误判为缺陷。
 */
async function downloadRecords(page, pattern) {
  const all = await page.evaluate(() => window.__xhrDownloads || []);
  if (!pattern) return all;
  const re = pattern instanceof RegExp ? pattern : new RegExp(escapeRe(String(pattern)));
  return all.filter((r) => re.test(r.url));
}

/** 清空下载记录，便于隔离单个用例 */
async function clearDownloadRecords(page) {
  await page.evaluate(() => { window.__xhrDownloads = []; }).catch(() => {});
}

/** 等待匹配的下载响应出现并返回最后一条 */
async function waitDownloadRecord(page, pattern, timeout = 60000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const hits = await downloadRecords(page, pattern);
    if (hits.length) return hits[hits.length - 1];
    await sleep(500);
  }
  return null;
}

module.exports = {
  SIDEBAR,
  sleep,
  settle,
  navigate,
  openSettings,
  pageTitle,
  formItem,
  fillByLabel,
  selectOption,
  selectOn,
  openDatePanel,
  pickDateTimeNow,
  pickDateTimeFuture,
  dateValue,
  downloadRecords,
  clearDownloadRecords,
  waitDownloadRecord,
  dialog,
  dialogButton,
  confirmBox,
  confirmBoxIfPresent,
  lastMessage,
  waitMessage,
  clearMessages,
  rowCount,
  rowContaining,
  waitRow,
  escapeRe,
  fmtDateTime,
};
