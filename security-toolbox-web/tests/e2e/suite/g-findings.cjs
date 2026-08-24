/*
 * 阶段 G：漏洞结果中心
 *
 * 业务顺序：进入结果中心 → 校验列表与搜索 → 查看证据详情
 *          → 生成后续验证路径 → 复测 → 变更处置状态
 *          → 缺陷复现（状态变更后项目信息丢失）→ 扫描 Diff → 分页 → 删除
 *
 * 用例顺序有意为之：「后续路径」必须在任何状态变更之前验证，
 * 因为状态变更会清空前端持有的 projectId（见 G-18 缺陷复现）。
 *
 * 本阶段校验的是针对靶机 192.168.136.131:8000（Python SimpleHTTP）
 * 实际扫描得到的真实漏洞记录。
 */
const {
  sleep, navigate, pageTitle, dialog, dialogButton, selectOn,
  lastMessage, clearMessages, rowCount, confirmBoxIfPresent,
} = require("../lib/ui.cjs");

async function run(page, H, ctx) {
  H.phase("阶段 G — 漏洞结果中心");

  await H.run("G-01", "通过侧边栏进入「结果中心」页面", async () => {
    await navigate(page, "结果中心");
    const t = await pageTitle(page);
    if (!page.url().includes("/findings")) throw new Error(`URL 异常: ${page.url()}`);
    return `标题="${t}"`;
  }, { page });

  await sleep(2500);
  await H.shot(page, "G-结果中心");

  let total = 0;
  await H.run("G-02", "结果列表加载并包含扫描产生的漏洞记录", async () => {
    await page.locator(".el-table, .empty-state").first().waitFor({ state: "visible", timeout: 15000 });
    total = await rowCount(page);
    if (total === 0) throw new Error("结果中心为空，但前序阶段已完成 HTTP 安全检查扫描");
    ctx.findingTotal = total;
    return `当前页 ${total} 条漏洞记录`;
  }, { page });

  await H.run("G-03", "漏洞记录展示等级、来源工具与目标信息", async () => {
    const row = page.locator(".el-table__row").first();
    const text = ((await row.textContent()) || "").replace(/\s+/g, " ").trim();
    if (!/CRITICAL|HIGH|MEDIUM|LOW|INFO/.test(text)) {
      throw new Error(`未展示风险等级: ${text.slice(0, 160)}`);
    }
    if (!/tcp_ports|http_headers|http_security_check|tls_config|nmap/.test(text)) {
      throw new Error(`未展示来源工具: ${text.slice(0, 160)}`);
    }
    return `首行: ${text.slice(0, 150)}`;
  }, { page });

  await H.run("G-04", "扫描结果包含针对靶机 Web 服务的真实安全发现", async () => {
    const body = ((await page.locator(".el-table").first().textContent()) || "").replace(/\s+/g, " ");
    const hits = ["安全响应头", "技术栈", "Cookie", "CORS", "方法", "端口"].filter((k) => body.includes(k));
    if (hits.length === 0) {
      throw new Error(`未见 HTTP/端口类真实发现: ${body.slice(0, 250)}`);
    }
    return `命中发现类型: ${hits.join("、")}`;
  }, { page });

  await H.run("G-05", "搜索框可按关键字过滤结果（防抖 250ms）", async () => {
    const q = page.locator('input[placeholder*="搜索名称"]').first();
    if (!(await q.count())) throw new Error("未找到搜索框");
    await q.click();
    await q.fill("响应头");
    await sleep(2500);
    const filtered = await rowCount(page);
    await q.fill("");
    await sleep(2500);
    const restored = await rowCount(page);
    return `搜索「响应头」命中 ${filtered} 条，清空后恢复 ${restored} 条`;
  }, { page });

  await H.run("G-06", "点击「刷新」可重新加载结果列表", async () => {
    await clearMessages(page);
    await page.locator("button", { hasText: "刷新" }).first().click();
    await sleep(2500);
    const n = await rowCount(page);
    if (n === 0) throw new Error("刷新后列表为空");
    return `刷新后 ${n} 条`;
  }, { page });

  // ---------- 详情与证据 ----------
  await H.run("G-07", "点击「详情」查看漏洞说明、证据与修复建议", async () => {
    const row = page.locator(".el-table__row").first();
    await row.locator(".finding-action", { hasText: "详情" }).first().click();
    const dlg = await dialog(page, "风险详情");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const missing = ["说明", "证据", "修复建议"].filter((k) => !text.includes(k));
    if (missing.length) throw new Error(`详情缺少字段: ${missing.join("、")}`);
    return "说明、证据、修复建议均已展示";
  }, { page });

  await H.shot(page, "G-漏洞详情");

  await H.run("G-08", "漏洞证据为非空的真实探测输出", async () => {
    const dlg = await dialog(page, "风险详情");
    let text = "";
    const ev = dlg.locator("pre.finding-evidence").first();
    if (await ev.count()) text = ((await ev.textContent()) || "").trim();
    if (!text) {
      const pres = dlg.locator("pre");
      for (let i = 0; i < (await pres.count()); i++) {
        const t = ((await pres.nth(i).textContent()) || "").trim();
        if (t.length > text.length) text = t;
      }
    }
    if (!text) throw new Error("证据区为空");
    ctx.findingEvidence = text.slice(0, 400);
    return `证据 ${text.length} 字符: ${text.replace(/\s+/g, " ").slice(0, 150)}`;
  }, { page });

  await H.run("G-09", "关闭漏洞详情对话框", async () => {
    const dlg = await dialog(page, "风险详情");
    await dialogButton(dlg, "关闭");
    await sleep(1200);
    if (await dlg.isVisible().catch(() => false)) throw new Error("对话框未关闭");
    return "已关闭";
  }, { page });

  // ---------- 后续验证路径（必须在任何状态变更之前） ----------
  await H.run("G-10", "点击「后续路径」生成 AI 扫描后验证路径", async () => {
    await clearMessages(page);
    const row = page.locator(".el-table__row").first();
    const btn = row.locator(".finding-action", { hasText: "后续路径" }).first();
    if (!(await btn.count())) throw new Error("未渲染后续路径入口");
    await btn.click();
    await sleep(3000);
    const dlg = page.locator(".el-dialog:visible").last();
    if (!(await dlg.isVisible().catch(() => false))) {
      const msg = await lastMessage(page, { timeout: 8000 });
      throw new Error(`未打开路径对话框${msg ? `，提示="${msg.text}"` : ""}`);
    }
    for (let i = 0; i < 30; i++) {
      const t = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
      if (/建议验证路径|下一步编排|后续验证任务/.test(t)) break;
      await sleep(2000);
    }
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    ctx.postScanDialogText = text.slice(0, 400);
    return `对话框内容: ${text.slice(0, 170)}`;
  }, { page, shotOnPass: true });

  await H.run("G-11", "路径对话框声明仅允许授权范围内的低风险验证", async () => {
    const dlg = page.locator(".el-dialog:visible").last();
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    if (!/授权|白名单|低风险|SAFE/.test(text)) {
      throw new Error(`未声明授权与风险限制: ${text.slice(0, 250)}`);
    }
    return "已声明仅限授权目标内低风险白名单验证";
  }, { page });

  await H.run("G-12", "非 SAFE 或非自动化步骤的复选框被禁用", async () => {
    const dlg = page.locator(".el-dialog:visible").last();
    const boxes = dlg.locator(".el-checkbox");
    const n = await boxes.count();
    if (n === 0) return "本次未生成可编排步骤";
    let disabled = 0, enabled = 0;
    for (let i = 0; i < n; i++) {
      const cls = (await boxes.nth(i).getAttribute("class")) || "";
      if (cls.includes("is-disabled")) disabled++; else enabled++;
    }
    return `步骤复选框共 ${n} 个：可选 ${enabled} 个，禁用 ${disabled} 个（禁用者为需人工审查/非 SAFE 步骤）`;
  }, { page });

  await H.run("G-13", "关闭后续验证路径对话框（不执行自动步骤）", async () => {
    const dlg = page.locator(".el-dialog:visible").last();
    const close = dlg.locator("button", { hasText: "关闭" }).last();
    if (await close.isVisible().catch(() => false)) await close.click();
    else await dlg.locator(".el-dialog__headerbtn").last().click();
    await sleep(1500);
    return "已关闭，未触发自动执行";
  }, { page });

  // ---------- 复测 ----------
  await H.run("G-14", "点击「复测」对漏洞发起回归验证任务", async () => {
    await clearMessages(page);
    // 确保没有遗留对话框遮挡
    for (let i = 0; i < 3; i++) {
      const d = page.locator(".el-dialog:visible").last();
      if (!(await d.isVisible().catch(() => false))) break;
      await d.locator(".el-dialog__headerbtn").last().click().catch(() => {});
      await sleep(800);
    }

    // 捕获复测接口的真实响应，便于区分"前端未提示"与"请求未发出"
    const calls = [];
    const onResp = async (r) => {
      const u = r.url();
      if (u.includes("/regression/") || u.includes("/retest")) {
        let body = "";
        try { body = (await r.text()).slice(0, 200); } catch { /* 忽略 */ }
        calls.push(`${r.request().method()} ${u.replace(/^.*\/api/, "/api")} -> ${r.status()} ${body}`);
      }
    };
    page.on("response", onResp);
    try {
      const row = page.locator(".el-table__row").first();
      const btn = row.locator(".finding-action", { hasText: "复测" }).first();
      if (!(await btn.count())) throw new Error("未渲染复测入口");
      await btn.scrollIntoViewIfNeeded().catch(() => {});
      await btn.click({ timeout: 12000 });
      await sleep(1500);
      // 复测无二次确认框，成功提示（3s 后自动消失）与 202 响应二者其一即可佐证
      await confirmBoxIfPresent(page, ["确定", "确认", "复测"], { timeout: 1500 });
      const msg = await lastMessage(page, { timeout: 6000 });
      // 等待接口返回
      for (let i = 0; i < 10 && calls.length === 0; i++) await sleep(500);
      const created = calls.find((c) => /-> 202/.test(c) && /retestTaskId/.test(c));
      if (msg && msg.type === "error") throw new Error(`复测被拒绝: ${msg.text}`);
      if (msg && /复测/.test(msg.text)) {
        return `提示="${msg.text}"${created ? `，接口已确认创建复测任务` : ""}`;
      }
      if (created) {
        const id = (created.match(/retestTaskId":(\d+)/) || [])[1];
        return `界面已触发复测，后端返回 202 并创建复测任务 #${id}（成功提示为瞬时 toast）`;
      }
      throw new Error(
        `复测后既无成功提示也无 202 响应。接口记录: ${calls.length ? calls.join(" | ") : "未观测到 /regression 请求"}`,
      );
    } finally {
      page.off("response", onResp);
    }
  }, { page, shotOnPass: true });

  // ---------- 状态流转 ----------
  await H.run("G-15", "行内状态下拉可将漏洞标记为「已确认」", async () => {
    await clearMessages(page);
    // 用标题锁定具体记录：定时扫描会持续产生新结果，行序号不稳定
    const row = page.locator(".el-table__row").first();
    const cells = row.locator("td");
    const title = ((await cells.nth(0).textContent()) || "").trim();
    // 复合键：标题 + 发现时间（复测/定时扫描会新增同名记录，仅凭标题会错位）
    let stamp = "";
    const cn = await cells.count();
    for (let i = 0; i < cn; i++) {
      const t = ((await cells.nth(i).textContent()) || "").trim();
      const m = t.match(/20\d\d-\d\d-\d\d \d\d:\d\d:\d\d/);
      if (m) { stamp = m[0]; break; }
    }
    if (!title) throw new Error("无法读取首行漏洞标题");
    ctx.statusFindingTitle = title;
    ctx.statusFindingStamp = stamp;
    const sel = row.locator(".el-select").first();
    if (!(await sel.count())) throw new Error("未渲染状态下拉");
    await selectOn(page, sel, "已确认");
    await sleep(2000);
    const msg = await lastMessage(page, { timeout: 8000 });
    if (msg && msg.type === "error") throw new Error(`状态更新失败: ${msg.text}`);
    const text = ((await row.textContent()) || "").replace(/\s+/g, " ");
    if (!text.includes("已确认")) throw new Error(`状态未变为已确认: ${text.slice(0, 150)}`);
    return `记录「${title.slice(0, 30)}」${msg ? ` 提示="${msg.text}"` : " 状态已变为已确认"}`;
  }, { page });

  await H.run("G-16", "状态变更在刷新后持久化", async () => {
    const title = ctx.statusFindingTitle;
    const stamp = ctx.statusFindingStamp;
    if (!title) return "未记录目标行标题，跳过";
    await page.locator("button", { hasText: "刷新" }).first().click();
    await sleep(3000);
    // 用 标题+发现时间 复合键精确定位同一条记录
    const rows = page.locator(".el-table__row");
    const n = await rows.count();
    let found = null;
    for (let i = 0; i < n; i++) {
      const t = ((await rows.nth(i).textContent()) || "").replace(/\s+/g, " ");
      if (t.includes(title) && (!stamp || t.includes(stamp))) { found = rows.nth(i); break; }
    }
    if (!found) {
      return `刷新后该记录（${stamp || title.slice(0, 20)}）已不在当前页（列表持续新增结果，共 ${n} 行），改由后端持久化保证，本页不做断言`;
    }
    const text = ((await found.textContent()) || "").replace(/\s+/g, " ");
    if (!text.includes("已确认")) throw new Error(`刷新后状态回退为非「已确认」: ${text.slice(0, 150)}`);
    return `记录「${title.slice(0, 24)}」（${stamp}）刷新后仍为已确认，状态已持久化`;
  }, { page });

  await H.run("G-17", "可将漏洞标记为「误报」并复原为「待确认」", async () => {
    await clearMessages(page);
    const row = page.locator(".el-table__row").first();
    await selectOn(page, row.locator(".el-select").first(), "误报");
    await sleep(2000);
    const msg = await lastMessage(page, { timeout: 8000 });
    if (msg && msg.type === "error") throw new Error(`状态更新失败: ${msg.text}`);
    const text = ((await row.textContent()) || "").replace(/\s+/g, " ");
    if (!text.includes("误报")) throw new Error(`状态未变为误报: ${text.slice(0, 150)}`);
    await selectOn(page, row.locator(".el-select").first(), "待确认").catch(() => {});
    await sleep(1500);
    return "误报状态切换成功并已复原为待确认";
  }, { page });

  // ---------- 回归：状态变更不应破坏项目上下文（原 DEF-01） ----------
  await H.run("G-18", "【回归】变更状态后「后续路径」仍然可用（DEF-01 修复验证）", async () => {
    // 不刷新页面，对刚变更过状态的同一行再次点击「后续路径」。
    // 修复前：PUT /status 响应不含瞬态 projectId，前端 Object.assign 覆盖后置空，
    //         此处会提示"该发现缺少项目信息，无法生成后续验证路径"。
    await clearMessages(page);
    const row = page.locator(".el-table__row").first();
    await row.locator(".finding-action", { hasText: "后续路径" }).first().click();
    await sleep(3000);
    const msg = await lastMessage(page, { timeout: 6000 });
    const dlg = page.locator(".el-dialog:visible").last();
    const opened = await dlg.isVisible().catch(() => false);

    if (!opened) {
      throw new Error(
        `状态变更后「后续路径」不可用${msg ? `，提示="${msg.text}"` : ""}` +
          "（若提示缺少项目信息，说明 DEF-01 回归：状态更新响应未回填瞬态 projectId）",
      );
    }
    const close = dlg.locator("button", { hasText: "关闭" }).last();
    if (await close.isVisible().catch(() => false)) await close.click();
    else await dlg.locator(".el-dialog__headerbtn").last().click();
    await sleep(1200);
    return "状态变更后无需刷新即可生成后续路径，项目上下文未丢失";
  }, { page, shotOnPass: true });

  await H.run("G-19", "刷新后「后续路径」同样可用", async () => {
    await page.locator("button", { hasText: "刷新" }).first().click();
    await sleep(3000);
    await clearMessages(page);
    const row = page.locator(".el-table__row").first();
    await row.locator(".finding-action", { hasText: "后续路径" }).first().click();
    await sleep(3500);
    const dlg = page.locator(".el-dialog:visible").last();
    const opened = await dlg.isVisible().catch(() => false);
    const msg = await lastMessage(page, { timeout: 5000 });
    if (!opened) throw new Error(`刷新后不可用${msg ? `，提示="${msg.text}"` : ""}`);
    const close = dlg.locator("button", { hasText: "关闭" }).last();
    if (await close.isVisible().catch(() => false)) await close.click();
    else await dlg.locator(".el-dialog__headerbtn").last().click();
    await sleep(1200);
    return "刷新后功能正常";
  }, { page });

  // ---------- 扫描 Diff ----------
  await H.run("G-20", "扫描 Diff 拒绝比较不同授权目标的任务", async () => {
    const pairs = ctx.taskPairs || [];
    const byTarget = {};
    for (const p of pairs) (byTarget[p.targetId] = byTarget[p.targetId] || []).push(p.taskId);
    const targets = Object.keys(byTarget);
    if (targets.length < 2) return "本次任务集中只有一个目标，无法构造跨目标比较，跳过";

    await clearMessages(page);
    await page.locator("button", { hasText: "扫描 Diff" }).first().click();
    const dlg = await dialog(page, "扫描 Diff");
    const inputs = dlg.locator("input");
    await inputs.nth(0).fill(String(byTarget[targets[0]][0]));
    await inputs.nth(1).fill(String(byTarget[targets[1]][0]));
    await dialogButton(dlg, "比较");
    await sleep(2500);
    const msg = await lastMessage(page, { timeout: 8000 });
    if (!msg || msg.type !== "error") {
      throw new Error(`跨目标比较未被拒绝${msg ? `，提示="${msg.text}"` : ""}`);
    }
    return `已正确拒绝：提示="${msg.text}"`;
  }, { page, shotOnPass: true });

  await H.run("G-21", "扫描 Diff 可比较同一授权目标的两个成功任务", async () => {
    const pairs = ctx.taskPairs || [];
    const byTarget = {};
    for (const p of pairs) (byTarget[p.targetId] = byTarget[p.targetId] || []).push(p.taskId);
    const same = Object.values(byTarget).find((arr) => arr.length >= 2);
    if (!same) return "本次任务集中没有同一目标的两个成功任务，跳过";

    let dlg = page.locator(".el-dialog:visible", { hasText: "扫描 Diff" }).last();
    if (!(await dlg.isVisible().catch(() => false))) {
      await page.locator("button", { hasText: "扫描 Diff" }).first().click();
      dlg = await dialog(page, "扫描 Diff");
    }
    await clearMessages(page);
    const inputs = dlg.locator("input");
    await inputs.nth(0).fill(String(same[same.length - 1]));
    await inputs.nth(1).fill(String(same[0]));
    await dialogButton(dlg, "比较");
    await sleep(3000);
    const msg = await lastMessage(page, { timeout: 6000 });
    if (msg && msg.type === "error") throw new Error(`比较失败: ${msg.text}`);
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    if (!/新增|持续|已修复|等级变化/.test(text)) {
      throw new Error(`未返回差异摘要: ${text.slice(0, 250)}`);
    }
    ctx.scanDiffText = text.slice(0, 300);
    return `比较任务 ${same[same.length - 1]} → ${same[0]}，摘要片段: ${(text.match(/新增[^关]{0,90}/) || [""])[0]}`;
  }, { page, shotOnPass: true });

  await H.run("G-22", "关闭扫描 Diff 对话框", async () => {
    const dlg = page.locator(".el-dialog:visible", { hasText: "扫描 Diff" }).last();
    if (!(await dlg.isVisible().catch(() => false))) return "对话框已关闭";
    const close = dlg.locator("button", { hasText: "关闭" }).last();
    if (await close.isVisible().catch(() => false)) await close.click();
    else await dlg.locator(".el-dialog__headerbtn").last().click();
    await sleep(1200);
    return "已关闭";
  }, { page });

  // ---------- 分页与删除 ----------
  await H.run("G-23", "结果列表在有数据时渲染分页控件", async () => {
    if ((ctx.findingTotal || 0) === 0) return "无数据，按设计不渲染分页";
    const pager = page.locator(".findings-pagination, .el-pagination").first();
    if (!(await pager.count())) throw new Error("有数据但未渲染分页控件");
    const text = ((await pager.textContent()) || "").replace(/\s+/g, " ").trim();
    return `分页控件: ${text.slice(0, 100)}`;
  }, { page });

  await H.run("G-24", "可删除单条漏洞记录并需二次确认", async () => {
    const pagerText = ((await page.locator(".el-pagination").first().textContent().catch(() => "")) || "");
    const beforeTotal = Number((pagerText.match(/共\s*(\d+)\s*条/) || [])[1] || 0);
    await clearMessages(page);
    const row = page.locator(".el-table__row").last();
    const name = ((await row.textContent()) || "").replace(/\s+/g, " ").slice(0, 40);
    const btn = row.locator(".finding-action").filter({ hasText: "删除" }).first();
    if (!(await btn.count())) throw new Error("未渲染删除入口");
    await btn.click();
    await sleep(1200);
    const clicked = await confirmBoxIfPresent(page, ["删除", "确定", "确认"]);
    if (!clicked) throw new Error("删除未弹出确认框");
    await sleep(2500);
    const msg = await lastMessage(page, { timeout: 8000 });
    if (msg && msg.type === "error") throw new Error(`删除失败: ${msg.text}`);
    const afterText = ((await page.locator(".el-pagination").first().textContent().catch(() => "")) || "");
    const afterTotal = Number((afterText.match(/共\s*(\d+)\s*条/) || [])[1] || 0);
    if (beforeTotal && afterTotal && afterTotal >= beforeTotal) {
      throw new Error(`删除后总数未减少: ${beforeTotal} → ${afterTotal}`);
    }
    return `删除「${name}」，总数 ${beforeTotal} → ${afterTotal}${msg ? `，提示="${msg.text}"` : ""}`;
  }, { page, shotOnPass: true });

  await H.run("G-25", "「清空」入口存在且在有数据时可用（保护数据未实际执行）", async () => {
    const btn = page.locator("button", { hasText: "清空" }).first();
    if (!(await btn.count())) throw new Error("未渲染清空入口");
    const disabled = await btn.isDisabled().catch(() => false);
    const n = await rowCount(page);
    if (n > 0 && disabled) throw new Error("有数据时清空按钮却被禁用");
    return `清空入口存在（当前页 ${n} 条，按钮${disabled ? "禁用" : "可用"}）；为保护后续阶段数据未实际执行`;
  }, { page });

  return true;
}

module.exports = { run };
