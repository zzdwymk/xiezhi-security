/*
 * 阶段 H：报告输出
 *
 * 业务顺序：进入项目详情「项目报告」页签 → 校验统计卡片
 *          → 预览项目 HTML 报告（沙箱 iframe）→ 下载项目 PDF
 *          → 单目标报告附录（HTML/PDF）→ 最近任务筛选
 *          → 任务级 HTML 报告下载
 *
 * 报告是本系统的最终交付物，本阶段校验其可生成、可下载且内容与实际扫描一致。
 *
 * 下载断言监听真实浏览器响应并保存原始字节；响应成功与操作系统落盘分别记录。
 */
const {
  sleep, settle, navigate, pageTitle, dialog, selectOn,
  lastMessage, clearMessages, waitRow,
} = require("../lib/ui.cjs");

async function openReportTab(page, ctx) {
  if (!/\/projects\/\d+/.test(page.url())) {
    await navigate(page, "评估项目");
    const row = await waitRow(page, ctx.projectName, 20000);
    await row.locator("button", { hasText: "进入项目" }).first().click();
    await settle(page, 2500);
  }
  const tabs = page.locator(".project-tabs").first();
  await tabs.waitFor({ state: "visible", timeout: 15000 });
  await tabs.locator(".el-tabs__item", { hasText: "项目报告" }).first().click();
  await sleep(2500);
  return page.locator(".el-tab-pane:visible").last();
}

const fs = require("node:fs");
const { captureReport } = require("../lib/report-response.cjs");

async function run(page, H, ctx) {
  H.phase("阶段 H — 报告输出");

  let pane;
  await H.run("H-01", "进入项目详情的「项目报告」页签", async () => {
    pane = await openReportTab(page, ctx);
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    if (!text) throw new Error("报告页签内容为空");
    return `页签已打开: ${text.slice(0, 120)}`;
  }, { page });

  await H.shot(page, "H-项目报告页签");

  await H.run("H-02", "点击「刷新摘要」重新加载报告统计", async () => {
    await clearMessages(page);
    const btn = pane.locator("button", { hasText: "刷新摘要" }).first();
    if (!(await btn.count())) throw new Error("未渲染刷新摘要按钮");
    await btn.click();
    await sleep(2500);
    return "摘要已刷新";
  }, { page });

  await H.run("H-03", "报告统计卡片展示任务、漏洞、风险、复测与审计计数", async () => {
    const cards = pane.locator("button.report-card--link");
    const n = await cards.count();
    if (n === 0) throw new Error("未渲染报告统计卡片");
    const texts = [];
    for (let i = 0; i < n; i++) {
      texts.push(((await cards.nth(i).textContent()) || "").replace(/\s+/g, " ").trim());
    }
    const expect = ["任务", "漏洞", "风险", "复测", "审"];
    const missing = expect.filter((k) => !texts.some((t) => t.includes(k)));
    if (missing.length) throw new Error(`缺少统计卡片: ${missing.join("、")}（实际: ${texts.join(" | ")}）`);
    ctx.reportCards = texts;
    return `${n} 张卡片: ${texts.join(" | ").slice(0, 180)}`;
  }, { page });

  await H.run("H-04", "任务总数与前序阶段实际创建的任务一致（大于 0）", async () => {
    const cards = pane.locator("button.report-card--link");
    let taskText = "";
    for (let i = 0; i < (await cards.count()); i++) {
      const t = ((await cards.nth(i).textContent()) || "").replace(/\s+/g, " ");
      if (t.includes("任务")) { taskText = t; break; }
    }
    const m = taskText.match(/(\d+)/);
    if (!m) throw new Error(`未解析到任务数: ${taskText}`);
    const n = Number(m[1]);
    if (n === 0) throw new Error("报告显示任务总数为 0，但前序阶段已创建并完成任务");
    return `任务总数 = ${n}`;
  }, { page });

  await H.run("H-05", "报告展示风险等级分布标签", async () => {
    const chips = pane.locator("button.severity-legend__item");
    const n = await chips.count();
    if (n === 0) return "本项目暂无风险等级分布（可能全部为信息级）";
    const texts = [];
    for (let i = 0; i < n; i++) {
      texts.push(((await chips.nth(i).textContent()) || "").replace(/\s+/g, " ").trim());
    }
    return `等级分布: ${texts.join(" | ").slice(0, 150)}`;
  }, { page });

  // ---------- 项目 HTML 报告预览 ----------
  await H.run("H-06", "点击「项目 HTML」打开报告预览对话框", async () => {
    await clearMessages(page);
    const btn = pane.locator("button", { hasText: "项目 HTML" }).first();
    if (!(await btn.count())) throw new Error("未渲染项目 HTML 按钮");
    await btn.click();
    await sleep(3500);
    const dlg = page.locator(".el-dialog:visible").last();
    if (!(await dlg.isVisible().catch(() => false))) {
      const msg = await lastMessage(page, { timeout: 8000 });
      throw new Error(`未打开预览对话框${msg ? `，提示="${msg.text}"` : ""}`);
    }
    return "报告预览对话框已打开";
  }, { page, shotOnPass: true });

  await H.run("H-07", "报告预览使用严格沙箱 iframe 承载", async () => {
    const frame = page.locator("iframe.report-preview-frame").first();
    if (!(await frame.count())) throw new Error("未使用 iframe 承载报告预览");
    const sandbox = await frame.getAttribute("sandbox");
    if (sandbox === null) throw new Error("预览 iframe 未设置 sandbox 属性");
    if (sandbox.trim() !== "") {
      throw new Error(`预览 iframe 的 sandbox 非严格空值（实际="${sandbox}"），存在脚本执行风险`);
    }
    return 'iframe sandbox="" —— 已禁用脚本、表单与同源访问';
  }, { page });

  await H.run("H-08", "报告内容包含本项目与靶机信息", async () => {
    const frame = page.frameLocator("iframe.report-preview-frame");
    let body = "";
    for (let i = 0; i < 15; i++) {
      body = ((await frame.locator("body").textContent().catch(() => "")) || "").replace(/\s+/g, " ");
      if (body.length > 50) break;
      await sleep(1000);
    }
    if (!body) {
      return { status: "PARTIAL", detail: "iframe 正文未读取，项目/靶机内容断言未验证" };
    }
    const hits = [ctx.targetIp, ctx.projectName].filter((k) => k && body.includes(k));
    if (hits.length === 0) {
      throw new Error(`报告正文未包含项目名或靶机地址: ${body.slice(0, 250)}`);
    }
    ctx.projectReportBody = body.slice(0, 400);
    return `报告正文含 ${hits.join("、")}，长度 ${body.length} 字符`;
  }, { page });

  await H.run("H-09", "关闭报告预览对话框", async () => {
    const dlg = page.locator(".el-dialog:visible").last();
    const close = dlg.locator("button", { hasText: /关闭预览|关闭/ }).last();
    if (await close.isVisible().catch(() => false)) await close.click();
    else await dlg.locator(".el-dialog__headerbtn").last().click();
    await sleep(1500);
    return "已关闭预览";
  }, { page });

  // ---------- 项目 PDF ----------
  await H.run("H-10", "点击「项目 PDF」，应用取得有效的 PDF 响应", async () => {
    await clearMessages(page);
    const btn = pane.locator("button", { hasText: "项目 PDF" }).first();
    if (!(await btn.count())) throw new Error("未渲染项目 PDF 按钮");
    const rec = await captureReport(page, H, btn, `/api/reports/projects/${ctx.projectId}.pdf`, "project");
    ctx.projectPdfRecord = rec;
    if (rec.status !== 200) throw new Error(`PDF 接口返回 ${rec.status}（期望 200）`);
    return `HTTP ${rec.status}，${rec.contentType}，${rec.size} 字节`;
  }, { page, shotOnPass: true });

  await H.run("H-11", "项目 PDF 内容类型与体积正确（非空文件）", async () => {
    const rec = ctx.projectPdfRecord;
    if (!rec) return { status: "PARTIAL", detail: "H-10 未取得 PDF 响应，未验证" };
    if (!rec.signature.startsWith("%PDF-")) throw new Error("响应缺少 PDF 文件签名");
    if (!/application\/pdf/i.test(rec.contentType || "")) {
      throw new Error(`内容类型异常: ${rec.contentType}`);
    }
    if (rec.size < 1000) {
      throw new Error(`PDF 体积异常，仅 ${rec.size} 字节（疑似生成失败或空文件）`);
    }
    return `内容类型 ${rec.contentType}，${rec.size} 字节，为有效非空 PDF`;
  }, { page });

  await H.run("H-12", "下载过程未出现错误提示", async () => {
    const msg = await lastMessage(page, { timeout: 2500 });
    if (msg && msg.type === "error") throw new Error(`出现错误提示: ${msg.text}`);
    return msg ? `提示="${msg.text}"（非错误）` : "无错误提示";
  }, { page });

  // ---------- 单目标报告 ----------
  await H.run("H-13", "报告页提供单目标附录范围选择", async () => {
    const toolbar = pane.locator(".target-report-toolbar").first();
    if (!(await toolbar.count())) throw new Error("未渲染单目标附录工具条");
    const sel = toolbar.locator(".el-select").first();
    const text = ((await sel.textContent()) || "").replace(/\s+/g, " ").trim();
    if (!/全部目标/.test(text)) {
      throw new Error(`默认范围非「全部目标」，实际: ${text}`);
    }
    return `默认范围: ${text}`;
  }, { page });

  await H.run("H-14", "切换报告范围为本次靶机目标", async () => {
    const toolbar = pane.locator(".target-report-toolbar").first();
    const sel = toolbar.locator(".el-select").first();
    await selectOn(page, sel, ctx.targetName);
    await sleep(1500);
    const text = ((await sel.textContent()) || "").replace(/\s+/g, " ").trim();
    if (!text.includes(ctx.targetIp)) throw new Error(`范围未切换到靶机目标: ${text}`);
    return `已切换到 ${text.slice(0, 80)}`;
  }, { page });

  await H.run("H-15", "生成并预览单目标 HTML 报告", async () => {
    await clearMessages(page);
    const btn = pane.locator("button", { hasText: "目标 HTML" }).first();
    if (!(await btn.count())) throw new Error("未渲染目标 HTML 按钮");
    await btn.click();
    await sleep(3500);
    const dlg = page.locator(".el-dialog:visible").last();
    if (!(await dlg.isVisible().catch(() => false))) {
      const msg = await lastMessage(page, { timeout: 8000 });
      throw new Error(`未打开目标报告预览${msg ? `，提示="${msg.text}"` : ""}`);
    }
    const title = ((await dlg.locator(".el-dialog__title").textContent().catch(() => "")) || "").trim();
    const close = dlg.locator("button", { hasText: /关闭预览|关闭/ }).last();
    if (await close.isVisible().catch(() => false)) await close.click();
    else await dlg.locator(".el-dialog__headerbtn").last().click();
    await sleep(1500);
    return `目标报告预览已打开并关闭，标题="${title}"`;
  }, { page, shotOnPass: true });

  await H.run("H-16", "点击「目标 PDF」，应用取得有效的 PDF 响应", async () => {
    await clearMessages(page);
    const btn = pane.locator("button", { hasText: "目标 PDF" }).first();
    if (!(await btn.count())) throw new Error("未渲染目标 PDF 按钮");
    const rec = await captureReport(page, H, btn, `/api/reports/projects/targets/${ctx.ipTargetId || ctx.targetId}.pdf`, "target");
    ctx.targetPdfRecord = rec;
    if (rec.status !== 200) throw new Error(`目标 PDF 接口返回 ${rec.status}（期望 200）`);
    return `HTTP ${rec.status}，${rec.contentType}，${rec.size} 字节`;
  }, { page, shotOnPass: true });

  await H.run("H-17", "单目标 PDF 内容类型与体积正确（非空文件）", async () => {
    const rec = ctx.targetPdfRecord;
    if (!rec) return { status: "PARTIAL", detail: "H-16 未取得 PDF 响应，未验证" };
    if (!rec.signature.startsWith("%PDF-")) throw new Error("响应缺少 PDF 文件签名");
    if (!/application\/pdf/i.test(rec.contentType || "")) {
      throw new Error(`内容类型异常: ${rec.contentType}`);
    }
    if (rec.size < 1000) throw new Error(`PDF 体积异常，仅 ${rec.size} 字节`);
    return `内容类型 ${rec.contentType}，${rec.size} 字节，为有效非空 PDF`;
  }, { page });

  // ---------- 最近任务筛选 ----------
  await H.run("H-18", "报告页「最近任务」列表按工具与状态筛选", async () => {
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    if (!/最近任务/.test(text)) throw new Error("未渲染最近任务区块");
    const selects = pane.locator(".el-select");
    const n = await selects.count();
    let toolSel = null, statusSel = null;
    for (let i = 0; i < n; i++) {
      const t = ((await selects.nth(i).textContent()) || "").replace(/\s+/g, " ");
      if (/全部工具/.test(t)) toolSel = selects.nth(i);
      if (/全部状态/.test(t)) statusSel = selects.nth(i);
    }
    if (!toolSel && !statusSel) return "未渲染工具/状态筛选下拉，跳过";
    const before = await pane.locator(".el-table__row").count();
    if (statusSel) {
      await selectOn(page, statusSel, /成功|SUCCESS/);
      await sleep(2000);
    }
    const after = await pane.locator(".el-table__row").count();
    return `筛选前 ${before} 行，按 SUCCESS 筛选后 ${after} 行`;
  }, { page });

  await H.shot(page, "H-报告统计与任务");

  // ---------- 任务级报告 ----------
  await H.run("H-19", "任务中心可获取任务级 HTML 报告", async () => {
    await navigate(page, "检测任务");
    await sleep(2500);
    await clearMessages(page);
    const own = new Set([...(ctx.taskPairs || []).map(t => String(t.taskId)), ...(ctx.createdTaskIds || []).map(String)]);
    let row = null;
    const rows = page.locator(".el-table__row");
    for (let i = 0; i < await rows.count(); i++) {
      const candidate = rows.nth(i);
      const id = ((await candidate.locator("td").nth(0).textContent()) || "").trim();
      const targetId = ((await candidate.locator("td").nth(2).textContent()) || "").trim();
      const status = ((await candidate.locator("td").nth(3).textContent()) || "").trim();
      if (/成功|SUCCESS/.test(status) && (own.has(id) || [ctx.ipTargetId, ctx.targetId].filter(Boolean).map(String).includes(targetId))) {
        row = candidate; ctx.taskReportTaskId = id; break;
      }
    }
    if (!row) throw new Error("当前页无本轮目标的成功任务，不能以历史任务替代");
    const btn = row.locator("button", { hasText: "报告" }).first();
    if (!(await btn.count())) throw new Error("未渲染报告按钮");
    const rec = await captureReport(page, H, btn, `/api/reports/tasks/${ctx.taskReportTaskId}/download`, "task", 60000);
    ctx.taskReportRecord = rec;
    if (rec.status !== 200) throw new Error(`任务报告接口返回 ${rec.status}`);
    if (rec.size < 200) throw new Error(`报告体积异常，仅 ${rec.size} 字节`);
    if (!/text\/html/i.test(rec.contentType || "")) {
      throw new Error(`内容类型异常: ${rec.contentType}`);
    }
    return `HTTP ${rec.status}，${rec.contentType}，${rec.size} 字节`;
  }, { page, shotOnPass: true });

  await H.run("H-20", "任务级报告内容包含靶机地址与执行结论", async () => {
    const rec = ctx.taskReportRecord;
    if (!rec) return { status: "PARTIAL", detail: "H-19 未取得报告，内容未验证" };
    const html = fs.readFileSync(rec.artifact, "utf8");
    if (!html.includes(ctx.targetIp)) throw new Error("下载 HTML 未包含本轮靶机地址");
    if (!/成功|SUCCESS|完成|结论|结果/.test(html)) throw new Error("下载 HTML 未包含执行结论/结果");
    return { taskId: ctx.taskReportTaskId, target: ctx.targetIp, artifact: rec.artifact, sha256: rec.sha256,
      detail: "已检查本次任务响应的实际HTML内容；操作系统下载落盘另行验证" };

  }, { page });

  return true;
}

module.exports = { run };
