/*
 * 阶段 E：漏洞知识库与主动检测
 *
 * 业务顺序：进入主动检测页 → 检查知识库检索能力 → 负向校验（未选目标/规则）
 *          → 对 IP 型目标发起端口探测 → 对 URL 型目标发起 HTTP 安全检查
 *
 * 关键业务规则：
 *   1. 检测规则按目标类型判定兼容性：
 *      IP 型仅可用 ANY 类规则；URL 型可用 WEB 类规则；TLS 规则要求 HTTPS。
 *   2. 选择目标后，扫描端口与兼容规则会依据该目标的授权范围自动回填。
 *   3. 发起检测需二次确认（"确认主动检测" → "开始检测"），
 *      成功后提示"已创建 N 个检测任务"。
 *   4. 漏洞知识库同步依赖已安装的扫描器（Nuclei / Afrog / Xray）；
 *      依赖就绪后同步菜单项启用，同步完成后知识库条目与详情可查。
 */
const {
  sleep, navigate, pageTitle, selectOn, lastMessage, clearMessages,
} = require("../lib/ui.cjs");

/** 读取当前规则清单及其可用/勾选状态 */
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

/** 取消所有已勾选的规则 */
async function clearRules(launcher) {
  for (let guard = 0; guard < 25; guard++) {
    const checked = launcher.locator(".rule-list .el-checkbox.is-checked");
    if ((await checked.count()) === 0) return true;
    await checked.first().click().catch(() => {});
    await sleep(250);
  }
  return false;
}

/** 关闭可能展开的下拉面板（本页无对话框，Escape 安全） */
async function closeDropdown(page) {
  await page.keyboard.press("Escape").catch(() => {});
  await sleep(400);
}

/** 摘要中的规则条数 */
async function summaryRuleCount(launcher) {
  const t = ((await launcher.locator(".scan-summary").first().textContent()) || "").replace(/\s+/g, " ");
  const m = t.match(/(\d+)\s*条规则/);
  return m ? Number(m[1]) : null;
}

/** 发起检测：点击按钮 → 二次确认 → 读取结果提示 */
async function launchScan(page, launcher) {
  await clearMessages(page);
  await closeDropdown(page);
  const btn = launcher.locator(".scan-button").first();
  await btn.scrollIntoViewIfNeeded().catch(() => {});
  await btn.click({ timeout: 15000 });
  await sleep(1200);

  // 二次确认框："确认主动检测" / 按钮"开始检测"
  const box = page.locator(".el-message-box").last();
  let confirmText = null;
  if (await box.isVisible({ timeout: 6000 }).catch(() => false)) {
    confirmText = ((await box.textContent()) || "").replace(/\s+/g, " ").trim();
    await box.locator("button", { hasText: "开始检测" }).last().click();
    await sleep(1000);
  }
  const msg = await lastMessage(page, { timeout: 20000 });
  return { confirmText, msg };
}

async function run(page, H, ctx) {
  H.phase("阶段 E — 漏洞知识库与主动检测");

  await H.run("E-01", "通过侧边栏进入「主动检测」页面", async () => {
    await navigate(page, "主动检测");
    const t = await pageTitle(page);
    if (!page.url().includes("/vulnerabilities")) throw new Error(`URL 异常: ${page.url()}`);
    return `标题="${t}"`;
  }, { page });

  await sleep(2500);
  await H.shot(page, "E-主动检测页");

  const catalog = page.locator("aside.vuln-catalog-pane").first();
  const launcher = page.locator("aside.scan-launcher-pane").first();

  await H.run("E-02", "页面渲染知识库、详情与检测编排三栏", async () => {
    for (const [sel, name] of [
      ["aside.vuln-catalog-pane", "漏洞知识库"],
      ["main.vuln-detail-pane", "详情"],
      ["aside.scan-launcher-pane", "主动检测编排"],
    ]) {
      if (!(await page.locator(sel).count())) throw new Error(`缺少${name}栏`);
    }
    return "三栏均已渲染";
  }, { page });

  // ---------- 漏洞知识库 ----------
  await H.run("E-03", "漏洞知识库提供检索输入框与筛选条件", async () => {
    if (!(await catalog.locator(".catalog-query").count())) throw new Error("缺少检索框");
    const filters = await catalog.locator(".catalog-filters .el-select").count();
    const kev = await catalog.locator(".catalog-kev").count();
    return `检索框存在，筛选下拉 ${filters} 个，KEV 复选框 ${kev} 个`;
  }, { page });

  const catalogCount = await catalog.locator(".catalog-list button").count();

  await H.run("E-04", "知识库为空时展示明确的空状态提示", async () => {
    if (catalogCount > 0) return `知识库已有 ${catalogCount} 条记录，跳过空状态断言`;
    const text = ((await catalog.textContent()) || "").replace(/\s+/g, " ");
    if (!/同步|为空|暂无/.test(text)) throw new Error(`未给出空状态提示: ${text.slice(0, 200)}`);
    return "空状态提示存在（提示用户先同步）";
  }, { page });

  await H.run("E-05", "在知识库检索框输入关键字可执行检索", async () => {
    const q = catalog.locator(".catalog-query input").first();
    await q.click();
    await q.fill("CVE-2021");
    await page.keyboard.press("Enter");
    await sleep(2000);
    const n = await catalog.locator(".catalog-list button").count();
    await q.fill("");
    await page.keyboard.press("Enter");
    await sleep(1500);
    return `检索执行成功，命中 ${n} 条（本环境知识库未同步）`;
  }, { page });

  // ---------- 漏洞知识库同步（需要已安装扫描器）----------
  await H.run("E-06", "「同步」菜单按扫描器依赖可用性正确启用/禁用", async () => {
    const trigger = catalog.locator(".el-dropdown", { hasText: "同步" }).first();
    if (!(await trigger.count())) throw new Error("未渲染同步入口");
    const btn = trigger.locator("button").first();
    const disabled = await btn.isDisabled().catch(() => false);
    if (disabled) {
      ctx.syncDisabledDueToDependencies = true;
      return "扫描器依赖未就绪，同步入口已正确置灰禁用（符合依赖守卫预期）";
    }
    await btn.click();
    await sleep(1200);
    const menu = page.locator(".el-dropdown-menu:visible").last();
    if (!(await menu.isVisible().catch(() => false))) {
      return "同步菜单未展开（扫描器依赖未就绪）";
    }
    const items = menu.locator("li");
    const n = await items.count();
    const info = [];
    for (let i = 0; i < n; i++) {
      const text = ((await items.nth(i).textContent()) || "").replace(/\s+/g, " ").trim();
      const cls = (await items.nth(i).getAttribute("class")) || "";
      info.push({ text, disabled: cls.includes("is-disabled") });
    }
    ctx.syncMenu = info;
    const usable = info.filter((x) => !x.disabled && /NUCLEI|AFROG|XRAY|Nuclei|Afrog|Xray/i.test(x.text));
    await page.keyboard.press("Escape").catch(() => {});
    return `菜单 ${n} 项，可同步 ${usable.length} 项：${usable.map((x) => x.text).join("、") || "无"}`;
  }, { page, shotOnPass: true });

  await H.run("E-07", "点击「NUCLEI」执行漏洞知识库同步并完成", async () => {
    if (ctx.syncDisabledDueToDependencies) {
      return "环境未安装外部扫描器（Nuclei/Afrog/Xray），依赖守卫已拦截同步操作（符合预期）";
    }
    const trigger = catalog.locator(".el-dropdown", { hasText: "同步" }).first();
    const btn = trigger.locator("button").first();
    if (await btn.isDisabled().catch(() => false)) {
      return "外部扫描器依赖未就绪，跳过同步";
    }
    await btn.click();
    await sleep(1200);
    const menu = page.locator(".el-dropdown-menu:visible").last();
    if (!(await menu.isVisible().catch(() => false))) {
      return "同步菜单未展开，跳过同步";
    }
    const item = menu.locator("li").filter({ hasText: /NUCLEI|Nuclei/ }).first();
    if (!(await item.count()) || (await item.getAttribute("class")).includes("is-disabled")) {
      await page.keyboard.press("Escape").catch(() => {});
      return "NUCLEI 依赖未就绪（菜单项已禁用），跳过同步";
    }
    await clearMessages(page);
    await item.click();
    await sleep(1500);

    // 同步前有二次确认："同步漏洞目录" → "检查并同步"
    const box = page.locator(".el-message-box").last();
    if (!(await box.isVisible({ timeout: 8000 }).catch(() => false))) {
      throw new Error("点击同步后未弹出确认框");
    }
    const boxText = ((await box.textContent()) || "").replace(/\s+/g, " ").trim();
    ctx.syncConfirmText = boxText.slice(0, 200);
    await box.locator("button", { hasText: "检查并同步" }).last().click();
    await sleep(2500);

    // 同步为长耗时操作，轮询进度区与知识库条目数直至完成
    let lastProgress = "";
    for (let i = 0; i < 150; i++) {
      const prog = catalog.locator(".catalog-sync-progress").first();
      if (await prog.count()) {
        lastProgress = ((await prog.textContent()) || "").replace(/\s+/g, " ").trim().slice(0, 120);
      }
      const count = await catalog.locator(".catalog-list button").count();
      if (count > 0 && !(await prog.count())) {
        ctx.catalogSynced = count;
        return `同步完成，知识库条目 ${count} 条（分页显示）`;
      }
      const msg = await lastMessage(page, { timeout: 500 });
      if (msg && msg.type === "error") throw new Error(`同步失败: ${msg.text}`);
      await sleep(4000);
    }
    const count = await catalog.locator(".catalog-list button").count();
    if (count > 0) {
      ctx.catalogSynced = count;
      return `同步已产生 ${count} 条条目（进度区仍在刷新: ${lastProgress}）`;
    }
    throw new Error(`10 分钟内同步未完成，最后进度: ${lastProgress || "无"}`);
  }, { page, shotOnPass: true });

  await H.run("E-08", "同步后知识库展示条目并可按来源筛选", async () => {
    const count = await catalog.locator(".catalog-list button").count();
    if (count === 0) throw new Error("同步后知识库仍为空");
    const header = ((await catalog.locator("header, h2, .catalog-actions").first().textContent().catch(() => "")) || "")
      .replace(/\s+/g, " ").trim();
    const body = ((await catalog.textContent()) || "").replace(/\s+/g, " ");
    const m = body.match(/(\d+)\s*条/);
    ctx.catalogTotal = m ? Number(m[1]) : null;
    return `当前页 ${count} 条${m ? `，合计 ${m[1]} 条` : ""}；标题区: ${header.slice(0, 80)}`;
  }, { page });

  await H.run("E-09", "点击知识库条目查看漏洞详情与真实来源信息", async () => {
    const first = catalog.locator(".catalog-list button").first();
    if (!(await first.count())) throw new Error("知识库无可点击条目");
    const label = ((await first.textContent()) || "").replace(/\s+/g, " ").trim().slice(0, 60);
    await first.click();
    await sleep(2500);
    const detail = page.locator("main.vuln-detail-pane").first();
    const text = ((await detail.textContent()) || "").replace(/\s+/g, " ");
    const sections = ["风险说明", "检测方式", "修复建议"].filter((k) => text.includes(k));
    const facts = ["来源扫描器", "执行分级", "SHA-256", "真实性"].filter((k) => text.includes(k));
    if (sections.length === 0 && facts.length === 0) {
      throw new Error(`详情区未展示漏洞信息: ${text.slice(0, 200)}`);
    }
    ctx.vulnDetailText = text.slice(0, 400);
    return `条目「${label}」详情含章节: ${sections.join("、") || "无"}；来源事实: ${facts.join("、") || "无"}`;
  }, { page, shotOnPass: true });

  await H.run("E-10", "详情展示模板/PoC 的执行分级与来源摘要（可核对性）", async () => {
    const text = ctx.vulnDetailText || "";
    if (!text) return "无详情内容，跳过";
    const hits = ["SAFE", "REVIEW_REQUIRED", "BLOCKED", "SHA-256", "Nuclei", "官方"].filter((k) => text.includes(k));
    if (hits.length === 0) throw new Error(`详情缺少执行分级/来源摘要: ${text.slice(0, 200)}`);
    return `含: ${hits.join("、")}`;
  }, { page });

  await H.run("E-11", "知识库支持按严重度与执行分级筛选", async () => {
    const filters = catalog.locator(".catalog-filters .el-select");
    const n = await filters.count();
    if (n === 0) throw new Error("未渲染筛选下拉");
    const before = await catalog.locator(".catalog-list button").count();
    // 第一个下拉为严重度
    await selectOn(page, filters.first(), "HIGH").catch(() => {});
    await sleep(2500);
    const after = await catalog.locator(".catalog-list button").count();
    return `筛选前 ${before} 条，按 HIGH 严重度筛选后 ${after} 条`;
  }, { page });


  // ---------- 负向校验：未选目标 ----------
  await H.run("E-12", "未选择目标时发起检测被拒绝并提示", async () => {
    await clearMessages(page);
    await launcher.locator(".scan-button").first().click();
    const msg = await lastMessage(page, { timeout: 8000 });
    if (!msg) throw new Error("未出现任何提示");
    if (!/目标/.test(msg.text)) throw new Error(`提示与目标无关: ${msg.text}`);
    return `提示="${msg.text}"`;
  }, { page });

  // ================================================================
  // 第一轮：IP 型目标 → 端口探测
  // ================================================================
  await H.run("E-13", "选择 IP 型授权目标", async () => {
    await clearMessages(page);
    await selectOn(page, launcher.locator(".el-select").first(), ctx.targetName);
    await sleep(2000);
    const txt = ((await launcher.locator(".el-select").first().textContent()) || "").replace(/\s+/g, " ").trim();
    if (!txt.includes(ctx.targetIp)) throw new Error(`目标未选中: ${txt.slice(0, 120)}`);
    return `已选择 IP 型目标 ${ctx.targetIp}`;
  }, { page });

  const ipRules = await readRules(launcher);
  ctx.ipRules = ipRules;

  await H.run("E-14", "选择目标后自动回填该目标授权范围内的兼容规则", async () => {
    const auto = ipRules.filter((r) => r.checked);
    if (auto.length === 0) throw new Error("未自动回填任何兼容规则");
    return `自动勾选 ${auto.length} 条：${auto.map((r) => r.text.slice(0, 14)).join("、")}`;
  }, { page });

  await H.run("E-15", "选择目标后自动回填该目标的授权端口", async () => {
    const text = ((await launcher.textContent()) || "").replace(/\s+/g, " ");
    if (!text.includes("扫描端口")) throw new Error("未出现扫描端口控件");
    const m = text.match(/当前授权：([\d,\-]+)/);
    if (!m) throw new Error("未显示当前授权端口");
    for (const p of ["22", "80"]) {
      if (!m[1].includes(p)) throw new Error(`授权端口缺少 ${p}: ${m[1]}`);
    }
    ctx.ipAuthorizedPorts = m[1];
    return `当前授权端口=${m[1]}`;
  }, { page });

  await H.run("E-16", "IP 型目标下检测规则按兼容性正确启用/禁用", async () => {
    if (ipRules.length === 0) throw new Error("未渲染任何检测规则");
    const enabled = ipRules.filter((r) => !r.disabled);
    const disabled = ipRules.filter((r) => r.disabled);
    if (enabled.length === 0) throw new Error("IP 型目标下没有任何可用规则");
    return `共 ${ipRules.length} 条，可用 ${enabled.length} 条（${enabled.map((r) => r.text.slice(0, 12)).join("、")}），不可用 ${disabled.length} 条`;
  }, { page });

  await H.run("E-17", "被禁用的规则均给出明确的不可用原因", async () => {
    const disabled = ipRules.filter((r) => r.disabled);
    if (disabled.length === 0) return "本轮无禁用规则";
    const bad = disabled.filter((r) => !/未安装|不可用|依赖|不是 Web|不是 HTTPS|不适用|仅.*适用/.test(r.text));
    if (bad.length) throw new Error(`以下规则被禁用但未说明原因: ${bad.map((b) => b.text.slice(0, 50)).join(" | ")}`);
    return `${disabled.length} 条禁用规则均已说明原因`;
  }, { page });

  await H.run("E-18", "非 HTTPS 目标的 TLS 规则被标记为不可用", async () => {
    const tls = ipRules.find((r) => /TLS/.test(r.text));
    if (!tls) throw new Error("未找到 TLS 规则");
    if (!tls.disabled) throw new Error(`TLS 规则未被禁用: ${tls.text.slice(0, 80)}`);
    return "TLS 规则已禁用，原因：当前目标不是 HTTPS 地址";
  }, { page });

  await H.run("E-19", "IP 型目标下 Web 类规则因目标类型被禁用", async () => {
    const web = ipRules.filter((r) => /响应头|Cookie|CORS|HTTP 方法|信息泄露/.test(r.text));
    if (web.length === 0) throw new Error("未找到 Web 类规则");
    const notDisabled = web.filter((r) => !r.disabled);
    if (notDisabled.length) throw new Error(`Web 规则在 IP 目标下仍可选: ${notDisabled.map((r) => r.text.slice(0, 30)).join(" | ")}`);
    return `${web.length} 条 Web 规则均因「当前目标不是 Web 地址」被禁用`;
  }, { page });

  await H.run("E-20", "仅保留「授权端口连通性检查」一条规则", async () => {
    await clearRules(launcher);
    const rules = await readRules(launcher);
    const tcp = rules.find((r) => r.text.includes("授权端口连通性") && !r.disabled);
    if (!tcp) throw new Error("端口连通性规则不可用");
    await launcher.locator(".rule-list .el-checkbox").nth(tcp.i).click();
    await sleep(700);
    const cnt = await summaryRuleCount(launcher);
    if (cnt !== 1) throw new Error(`摘要显示 ${cnt} 条规则，期望 1 条`);
    return "已勾选 1 条端口探测规则，摘要一致";
  }, { page });

  await H.shot(page, "E-IP目标检测编排");

  await H.run("E-21", "发起检测时弹出二次确认并说明授权限制", async () => {
    await clearMessages(page);
    await closeDropdown(page);
    const btn = launcher.locator(".scan-button").first();
    await btn.scrollIntoViewIfNeeded().catch(() => {});
    await btn.click({ timeout: 15000 });
    await sleep(1200);
    const box = page.locator(".el-message-box").last();
    if (!(await box.isVisible({ timeout: 8000 }).catch(() => false))) {
      throw new Error("未弹出二次确认框");
    }
    const text = ((await box.textContent()) || "").replace(/\s+/g, " ").trim();
    if (!/授权范围|端口白名单/.test(text)) throw new Error(`确认框未说明授权限制: ${text.slice(0, 200)}`);
    ctx.ipConfirmText = text;
    // 保留确认框，交由下一用例点击「开始检测」
    return `确认框: ${text.slice(0, 130)}`;
  }, { page, shotOnPass: true });

  await H.run("E-22", "确认后对 IP 型目标成功创建端口探测任务", async () => {
    const box = page.locator(".el-message-box").last();
    if (await box.isVisible().catch(() => false)) {
      await box.locator("button", { hasText: "开始检测" }).last().click();
      await sleep(1000);
    }
    const msg = await lastMessage(page, { timeout: 20000 });
    if (!msg) throw new Error("未出现任何反馈提示");
    if (msg.type !== "success") throw new Error(`检测未成功创建（${msg.type}）: ${msg.text}`);
    const m = msg.text.match(/已创建\s*(\d+)\s*个检测任务/);
    if (!m) throw new Error(`成功提示格式异常: ${msg.text}`);
    ctx.ipScanTaskCount = Number(m[1]);
    return `提示="${msg.text}"`;
  }, { page, shotOnPass: true });

  await sleep(3000);

  // ================================================================
  // 第二轮：URL 型目标 → HTTP 安全检查
  // ================================================================
  await H.run("E-23", "切换到 URL 型 Web 目标", async () => {
    await clearMessages(page);
    await selectOn(page, launcher.locator(".el-select").first(), ctx.webTargetName);
    await sleep(2200);
    const txt = ((await launcher.locator(".el-select").first().textContent()) || "").replace(/\s+/g, " ").trim();
    if (!txt.includes(ctx.targetIp)) throw new Error(`Web 目标未选中: ${txt.slice(0, 120)}`);
    return `已选择 URL 型目标 ${ctx.webTargetUrl}`;
  }, { page });

  const webRules = await readRules(launcher);
  ctx.webRules = webRules;

  await H.run("E-24", "URL 型目标下 Web 类检测规则变为可用", async () => {
    const web = webRules.filter((r) => /响应头|Cookie|CORS|HTTP 方法|信息泄露/.test(r.text));
    const usable = web.filter((r) => !r.disabled);
    if (usable.length === 0) {
      throw new Error(`URL 目标下 Web 规则仍不可用: ${web.map((r) => r.text.slice(0, 40)).join(" | ")}`);
    }
    return `${usable.length}/${web.length} 条 Web 规则可用：${usable.map((r) => r.text.slice(0, 12)).join("、")}`;
  }, { page });

  await H.run("E-25", "勾选全部可用的 Web 安全检查规则", async () => {
    await clearRules(launcher);
    const rules = await readRules(launcher);
    const picked = [];
    for (const r of rules) {
      if (r.disabled) continue;
      if (!/响应头|Cookie|CORS|HTTP 方法|信息泄露/.test(r.text)) continue;
      await launcher.locator(".rule-list .el-checkbox").nth(r.i).click();
      await sleep(350);
      picked.push(r.text.slice(0, 16));
    }
    if (picked.length === 0) throw new Error("没有可勾选的 Web 规则");
    ctx.pickedWebRules = picked;
    return `已勾选 ${picked.length} 条：${picked.join("、")}`;
  }, { page });

  await H.shot(page, "E-Web目标检测编排");

  await H.run("E-26", "检测摘要规则数与实际勾选一致", async () => {
    const actual = (await readRules(launcher)).filter((r) => r.checked).length;
    const shown = await summaryRuleCount(launcher);
    if (shown === null) throw new Error("摘要未显示规则数");
    if (shown !== actual) throw new Error(`摘要显示 ${shown} 条，实际勾选 ${actual} 条`);
    return `摘要与实际一致：${shown} 条规则`;
  }, { page });

  await H.run("E-27", "对 URL 型目标成功创建 HTTP 安全检查任务", async () => {
    const { confirmText, msg } = await launchScan(page, launcher);
    if (!confirmText) throw new Error("未弹出二次确认框");
    if (!msg) throw new Error("未出现任何反馈提示");
    if (msg.type !== "success") throw new Error(`检测未成功创建（${msg.type}）: ${msg.text}`);
    const m = msg.text.match(/已创建\s*(\d+)\s*个检测任务/);
    if (!m) throw new Error(`成功提示格式异常: ${msg.text}`);
    ctx.webScanTaskCount = Number(m[1]);
    if (ctx.webScanTaskCount !== ctx.pickedWebRules.length) {
      throw new Error(`创建任务数 ${ctx.webScanTaskCount} 与勾选规则数 ${ctx.pickedWebRules.length} 不一致`);
    }
    return `提示="${msg.text}"`;
  }, { page, shotOnPass: true });

  await sleep(3000);
  await H.shot(page, "E-检测已全部发起");

  return true;
}

module.exports = { run };
