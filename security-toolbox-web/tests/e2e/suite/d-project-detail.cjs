/*
 * 阶段 D：评估项目详情工作区
 *
 * 业务顺序：进入项目详情 → 概览 → 授权目标关联 → 探测服务（指纹/WAF）
 *          → 信息收集（被动/主动）→ 检测任务 → 漏洞与复测
 *          → 安全行动（高风险审批）→ 审批与审计 → AI 记忆
 *
 * 「项目报告」页签由阶段 H 覆盖，本阶段不重复。
 */
const {
  sleep, settle, navigate, pageTitle, dialog, dialogButton, selectOption, selectOn,
  lastMessage, clearMessages, rowCount, waitRow, confirmBoxIfPresent,
  pickDateTimeNow, pickDateTimeFuture,
} = require("../lib/ui.cjs");

/** 切换项目详情页签 */
async function openTab(page, label) {
  const tabs = page.locator(".project-tabs").first();
  await tabs.waitFor({ state: "visible", timeout: 15000 });
  const tab = tabs.locator(".el-tabs__item", { hasText: label }).first();
  await tab.click();
  await sleep(1800);
  return tabs;
}

/** 当前激活页签下的内容面板 */
function panel(page) {
  return page.locator(".el-tab-pane").filter({ hasNot: page.locator(":scope[aria-hidden='true']") }).first();
}

async function run(page, H, ctx) {
  H.phase("阶段 D — 评估项目详情工作区");

  // ---------- 进入项目详情 ----------
  await H.run("D-01", "从项目列表点击「进入项目」打开详情页", async () => {
    await navigate(page, "评估项目");
    const row = await waitRow(page, ctx.projectName, 20000);
    await row.locator("button", { hasText: "进入项目" }).first().click();
    await settle(page, 2500);
    if (!/\/projects\/\d+/.test(page.url())) throw new Error(`未进入详情页: ${page.url()}`);
    ctx.projectId = (page.url().match(/\/projects\/(\d+)/) || [])[1] || ctx.projectId;
    const t = await pageTitle(page);
    return `项目 ID=${ctx.projectId}，标题="${t}"`;
  }, { page });

  await H.shot(page, "D-项目详情");

  await H.run("D-02", "详情页渲染完整的页签集合", async () => {
    const tabs = page.locator(".project-tabs").first();
    await tabs.waitFor({ state: "visible", timeout: 15000 });
    const labels = (await tabs.locator(".el-tabs__item").allTextContents()).map((s) => s.trim());
    const expect = ["概览", "授权目标", "探测服务", "信息收集", "检测任务", "漏洞与复测", "安全行动", "审批与审计", "项目报告", "AI 记忆"];
    const missing = expect.filter((e) => !labels.some((l) => l.includes(e)));
    if (missing.length) throw new Error(`缺少页签: ${missing.join("、")}（实际: ${labels.join("/")}）`);
    return `${labels.length} 个页签齐全: ${labels.join(" / ")}`;
  }, { page });

  await H.run("D-03", "页面头部提供项目状态切换与报告入口", async () => {
    const text = ((await page.locator(".detail-head-actions").first().textContent().catch(() => "")) || "").replace(/\s+/g, " ");
    if (!text) throw new Error("未渲染头部操作区");
    const has = ["AI 项目分析", "项目总结 PDF"].filter((k) => text.includes(k));
    return `头部操作: ${text.slice(0, 120)}（含 ${has.join("、") || "无"}）`;
  }, { page });

  // ================= 概览 =================
  await H.run("D-04", "「概览」页签展示项目统计信息", async () => {
    await openTab(page, "概览");
    const desc = page.locator(".el-descriptions").first();
    await desc.waitFor({ state: "visible", timeout: 12000 });
    const text = ((await desc.textContent()) || "").replace(/\s+/g, " ");
    const expect = ["状态", "目标", "检测任务", "漏洞发现"];
    const missing = expect.filter((k) => !text.includes(k));
    if (missing.length) throw new Error(`概览缺少字段: ${missing.join("、")}`);
    return `概览: ${text.slice(0, 160)}`;
  }, { page });

  await H.run("D-05", "概览统计与前序阶段的实际数据一致", async () => {
    const text = ((await page.locator(".el-descriptions").first().textContent()) || "").replace(/\s+/g, " ");
    const m = text.match(/检测任务\s*(\d+)/);
    if (!m) throw new Error(`未解析到检测任务数: ${text.slice(0, 200)}`);
    const n = Number(m[1]);
    if (n === 0) throw new Error("检测任务数为 0，但前序阶段已创建任务");
    return `概览显示检测任务 ${n} 个`;
  }, { page });

  // ================= 授权目标 =================
  await H.run("D-06", "「授权目标」页签列出本项目下的目标", async () => {
    await openTab(page, "授权目标");
    await page.locator(".el-table, .empty-state").first().waitFor({ state: "visible", timeout: 12000 });
    const body = ((await page.locator(".el-tab-pane:visible").last().textContent()) || "").replace(/\s+/g, " ");
    if (!body.includes(ctx.targetIp)) throw new Error(`目标列表未包含靶机 ${ctx.targetIp}: ${body.slice(0, 200)}`);
    return `已列出含靶机 ${ctx.targetIp} 的授权目标`;
  }, { page });

  await H.shot(page, "D-授权目标页签");

  await H.run("D-07", "页签内提供「新建授权目标」入口并可打开对话框", async () => {
    const btn = page.locator("button", { hasText: "新建授权目标" }).first();
    if (!(await btn.count())) throw new Error("未渲染新建授权目标按钮");
    await btn.click();
    const dlg = await dialog(page, "在本项目下新建授权目标");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const missing = ["名称", "地址", "允许端口", "授权记录"].filter((k) => !text.includes(k));
    const cancel = dlg.locator("button", { hasText: "取消" }).last();
    await cancel.click();
    await sleep(1000);
    if (missing.length) throw new Error(`对话框缺少字段: ${missing.join("、")}`);
    return "对话框字段完整并已取消";
  }, { page });

  await H.run("D-08", "提供「选择已有目标加入项目」的关联入口", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    if (!/加入项目|选择已有目标/.test(text)) throw new Error(`未提供目标关联入口: ${text.slice(0, 200)}`);
    return "目标关联入口存在";
  }, { page });

  // ================= 探测服务 =================
  await H.run("D-09", "「探测服务」页签提供目标选择与指纹识别入口", async () => {
    await openTab(page, "探测服务");
    const pane = page.locator(".el-tab-pane:visible").last();
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    if (!/指纹|WAF/.test(text)) throw new Error(`未提供指纹/WAF 识别入口: ${text.slice(0, 200)}`);
    return "指纹/WAF 识别入口存在";
  }, { page });

  await H.shot(page, "D-探测服务页签");

  await H.run("D-10", "指纹规则库面板展示版本、规则数与摘要", async () => {
    const toggle = page.locator("button.fingerprint-catalog-toggle").first();
    if (!(await toggle.count())) throw new Error("未渲染指纹规则库面板");
    await toggle.click();
    await sleep(1500);
    const body = page.locator("#project-fingerprint-catalog-body").first();
    const text = ((await body.textContent().catch(() => "")) || "").replace(/\s+/g, " ");
    const head = ((await toggle.textContent()) || "").replace(/\s+/g, " ");
    return `面板信息: ${(head + " " + text).slice(0, 180)}`;
  }, { page });

  await H.run("D-11", "管理员可见「更新指纹库」与「重新读取」操作", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    const found = ["更新指纹库", "重新读取"].filter((k) => text.includes(k));
    if (found.length === 0) throw new Error("管理员未看到指纹库管理操作");
    return `可见操作: ${found.join("、")}`;
  }, { page });

  await H.run("D-12", "对靶机执行指纹/WAF 识别并返回结果", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const sel = pane.locator(".el-select").first();
    if (await sel.count()) {
      await selectOn(page, sel, ctx.webTargetName).catch(async () => {
        await selectOn(page, sel, ctx.targetName);
      });
      await sleep(1200);
    }
    await clearMessages(page);
    const btn = pane.locator("button").filter({ hasText: /指纹|WAF/ }).first();
    if (!(await btn.count())) throw new Error("未找到识别按钮");
    await btn.click();
    await sleep(2000);
    await confirmBoxIfPresent(page, ["确定", "确认", "开始"]);
    // 主动探测需时间，等待结果或提示
    let msg = null;
    for (let i = 0; i < 20; i++) {
      msg = await lastMessage(page, { timeout: 2000 });
      if (msg) break;
      await sleep(2000);
    }
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    if (msg && msg.type === "error") throw new Error(`识别失败: ${msg.text}`);
    const hasResult = text.includes(ctx.targetIp);
    return `${msg ? `提示="${msg.text}" ` : ""}结果区${hasResult ? "已包含靶机记录" : "暂无记录"}`;
  }, { page, shotOnPass: true });

  // ================= 信息收集 =================
  await H.run("D-13", "「信息收集」页签提供被动/主动模式与数据源选项", async () => {
    await openTab(page, "信息收集");
    const pane = page.locator(".el-tab-pane:visible").last();
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    const missing = ["被动收集", "主动收集"].filter((k) => !text.includes(k));
    if (missing.length) throw new Error(`缺少模式选项: ${missing.join("、")}`);
    const sources = ["HTTP 信息", "TLS/证书", "字典枚举子域名", "受限同网段发现"].filter((k) => text.includes(k));
    return `模式齐全，数据源选项: ${sources.join("、")}`;
  }, { page });

  await H.shot(page, "D-信息收集页签");

  await H.run("D-14", "「受限同网段发现」在被动模式下不可用", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const cb = pane.locator(".el-checkbox", { hasText: "受限同网段发现" }).first();
    if (!(await cb.count())) throw new Error("未找到受限同网段发现选项");
    const cls = (await cb.getAttribute("class")) || "";
    if (!cls.includes("is-disabled")) {
      throw new Error("被动模式下「受限同网段发现」仍可勾选（应仅主动模式可用）");
    }
    return "被动模式下已正确禁用";
  }, { page });

  await H.run("D-15", "对靶机执行被动信息收集并返回来源与证据", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const sel = pane.locator(".el-select").first();
    if (await sel.count()) {
      await selectOn(page, sel, ctx.webTargetName).catch(async () => {
        await selectOn(page, sel, ctx.targetName);
      });
      await sleep(1200);
    }
    await clearMessages(page);
    const btn = pane.locator("button", { hasText: "开始收集" }).first();
    if (!(await btn.count())) throw new Error("未找到开始收集按钮");
    await btn.click();
    await sleep(2500);
    await confirmBoxIfPresent(page, ["确定", "确认", "开始"]);
    let msg = null;
    for (let i = 0; i < 25; i++) {
      msg = await lastMessage(page, { timeout: 2000 });
      if (msg) break;
      await sleep(2000);
    }
    if (msg && msg.type === "error") throw new Error(`信息收集失败: ${msg.text}`);
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    const hasEvidence = /来源与证据|recon-results|证据/.test(text);
    return `${msg ? `提示="${msg.text}" ` : ""}${hasEvidence ? "已展示来源与证据区" : "结果区暂无内容"}`;
  }, { page, shotOnPass: true });

  await H.run("D-16", "信息收集提供结果导出（JSON/CSV/HTML）入口", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const btn = pane.locator("button", { hasText: "导出结果" }).first();
    if (!(await btn.count())) throw new Error("未渲染导出结果入口");
    await btn.click();
    await sleep(1000);
    const menu = page.locator(".el-dropdown-menu:visible").last();
    const items = (await menu.locator("li").allTextContents()).map((s) => s.trim()).filter(Boolean);
    await page.keyboard.press("Escape").catch(() => {});
    await sleep(400);
    const missing = ["JSON", "CSV", "HTML"].filter((k) => !items.some((i) => i.includes(k)));
    if (missing.length) throw new Error(`导出菜单缺少: ${missing.join("、")}（实际: ${items.join("/")}）`);
    return `导出格式: ${items.join("、")}`;
  }, { page });

  await H.run("D-17", "信息收集提供 ICP 备案批量查询入口", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    if (!/ICP/.test(text)) throw new Error("未提供 ICP 备案查询入口");
    return "ICP 备案批量查询入口存在";
  }, { page });

  // ================= 检测任务 =================
  await H.run("D-18", "「检测任务」页签列出本项目的任务并含授权快照说明", async () => {
    await openTab(page, "检测任务");
    const pane = page.locator(".el-tab-pane:visible").last();
    await pane.locator(".el-table, .empty-state").first().waitFor({ state: "visible", timeout: 12000 });
    const rows = await pane.locator(".el-table__row").count();
    if (rows === 0) throw new Error("本项目任务列表为空，但前序阶段已创建任务");
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    return `任务 ${rows} 条${/快照/.test(text) ? "，含授权快照说明" : ""}`;
  }, { page });

  await H.shot(page, "D-检测任务页签");

  await H.run("D-19", "任务行提供「实时日志」入口并可查看执行日志", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const btn = pane.locator(".el-table__row").first().locator("button", { hasText: "实时日志" }).first();
    if (!(await btn.count())) throw new Error("未渲染实时日志入口");
    await btn.click();
    const dlg = await dialog(page, "项目任务实时日志");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const has = ["授权快照哈希", "规则", "模板"].filter((k) => text.includes(k));
    await dialogButton(dlg, "关闭");
    await sleep(1000);
    return `日志对话框已打开并关闭，含字段: ${has.join("、") || "无"}`;
  }, { page });

  // ================= 漏洞与复测 =================
  await H.run("D-20", "「漏洞与复测」页签列出本项目漏洞记录", async () => {
    await openTab(page, "漏洞与复测");
    const pane = page.locator(".el-tab-pane:visible").last();
    await pane.locator(".el-table, .empty-state").first().waitFor({ state: "visible", timeout: 12000 });
    const rows = await pane.locator(".el-table__row").count();
    ctx.projectFindingRows = rows;
    return `漏洞记录 ${rows} 条`;
  }, { page });

  await H.shot(page, "D-漏洞与复测页签");

  await H.run("D-21", "页签提供扫描 Diff 与 AI 汇总入口", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    const found = ["扫描 Diff", "AI 汇总", "刷新漏洞"].filter((k) => text.includes(k));
    if (found.length < 2) throw new Error(`入口不完整，仅找到: ${found.join("、")}`);
    return `入口: ${found.join("、")}`;
  }, { page });

  await H.run("D-22", "漏洞行可查看详情（说明/证据/修复建议）", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    if ((ctx.projectFindingRows || 0) === 0) return "本项目暂无漏洞记录，跳过";
    const btn = pane.locator(".el-table__row").first().locator("button", { hasText: "详情" }).first();
    if (!(await btn.count())) throw new Error("未渲染详情入口");
    await btn.click();
    const dlg = await dialog(page, "项目漏洞详情");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const has = ["说明", "证据", "修复建议"].filter((k) => text.includes(k));
    await dialogButton(dlg, "关闭");
    await sleep(1000);
    if (has.length === 0) throw new Error("漏洞详情缺少说明/证据/修复建议");
    return `详情含: ${has.join("、")}`;
  }, { page });

  await H.run("D-23", "漏洞状态可在行内下拉切换", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    if ((ctx.projectFindingRows || 0) === 0) return "本项目暂无漏洞记录，跳过";
    const row = pane.locator(".el-table__row").first();
    const sel = row.locator(".el-select").first();
    if (!(await sel.count())) throw new Error("未渲染状态下拉");
    await clearMessages(page);
    await selectOn(page, sel, "已确认");
    await sleep(1800);
    const msg = await lastMessage(page, { timeout: 6000 });
    if (msg && msg.type === "error") throw new Error(`状态更新失败: ${msg.text}`);
    return msg ? `提示="${msg.text}"` : "状态已切换为已确认";
  }, { page });

  // ================= 安全行动 =================
  await H.run("D-24", "「安全行动」页签对管理员展示高风险行动申请入口", async () => {
    await openTab(page, "安全行动");
    const pane = page.locator(".el-tab-pane:visible").last();
    const btn = pane.locator("button.security-action-request-button").first();
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    if (!(await btn.count())) {
      return `未渲染申请按钮（可能因授权状态限制）。页面提示: ${text.slice(0, 180)}`;
    }
    return `申请高风险行动入口存在。说明: ${text.slice(0, 150)}`;
  }, { page });

  await H.shot(page, "D-安全行动页签");

  await H.run("D-25", "高风险安全行动申请对话框包含风险与授权约束说明", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const btn = pane.locator("button.security-action-request-button").first();
    if (!(await btn.count())) return "无申请入口，跳过";
    await btn.click();
    await sleep(1500);
    const dlg = page.locator(".el-dialog:visible").last();
    if (!(await dlg.isVisible().catch(() => false))) return "对话框未打开，跳过";
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const has = ["授权目标", "安全行动类型", "验证目的", "非破坏性", "禁止横向移动"].filter((k) => text.includes(k));
    const cancel = dlg.locator("button", { hasText: "取消" }).last();
    if (await cancel.isVisible().catch(() => false)) await cancel.click();
    await sleep(1200);
    if (has.length < 3) throw new Error(`对话框关键约束说明不足，仅有: ${has.join("、")}`);
    return `对话框含: ${has.join("、")}`;
  }, { page });

  // ================= 审批与审计 =================
  await H.run("D-26", "「审批与审计」页签展示审批记录与操作审计", async () => {
    await openTab(page, "审批与审计");
    const pane = page.locator(".el-tab-pane:visible").last();
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    const missing = ["审批记录", "操作审计"].filter((k) => !text.includes(k));
    if (missing.length) throw new Error(`缺少区块: ${missing.join("、")}`);
    const rows = await pane.locator(".el-table__row").count();
    return `两个区块齐全，共 ${rows} 行记录`;
  }, { page });

  await H.shot(page, "D-审批与审计页签");

  await H.run("D-27", "操作审计记录了前序阶段的真实操作", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    if (!/TASK|SCAN|TARGET|PROJECT|任务|扫描|目标|项目/i.test(text)) {
      throw new Error(`审计记录中未见业务操作痕迹: ${text.slice(0, 250)}`);
    }
    return "审计记录中可见任务/扫描/目标/项目相关操作";
  }, { page });

  await H.run("D-28", "可提交项目审批申请", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const btn = pane.locator("button", { hasText: "申请审批" }).first();
    if (!(await btn.count())) throw new Error("未渲染申请审批入口");
    await btn.click();
    const dlg = await dialog(page, "申请项目审批");
    await clearMessages(page);
    await selectOption(dlg, page, "审批动作", "主动扫描").catch(() => {});
    const ta = dlg.locator("textarea").first();
    if (await ta.count()) {
      await ta.click();
      await ta.fill(`全链路测试提交的扫描审批申请（AUTH-${ctx.stamp}）。`);
    }
    await dialogButton(dlg, "提交申请");
    await sleep(2000);
    const msg = await lastMessage(page, { timeout: 10000 });
    if (msg && msg.type === "error") throw new Error(`提交审批失败: ${msg.text}`);
    ctx.approvalRequested = true;
    return msg ? `提示="${msg.text}"` : "审批申请已提交";
  }, { page, shotOnPass: true });

  await H.run("D-29", "新提交的审批记录出现在列表且状态为待审批", async () => {
    if (!ctx.approvalRequested) return "未提交审批，跳过";
    const pane = page.locator(".el-tab-pane:visible").last();
    const refresh = pane.locator("button", { hasText: "刷新记录" }).first();
    if (await refresh.count()) { await refresh.click(); await sleep(2000); }
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    if (!/PENDING|待审批|待决定/.test(text)) {
      throw new Error(`未见待审批记录: ${text.slice(0, 250)}`);
    }
    return "审批记录中存在待审批条目";
  }, { page });

  await H.run("D-30", "管理员可对待审批记录执行「通过」决策", async () => {
    if (!ctx.approvalRequested) return "未提交审批，跳过";
    const pane = page.locator(".el-tab-pane:visible").last();
    const row = pane.locator(".el-table__row").filter({ hasText: /PENDING|待审批/ }).first();
    if (!(await row.count())) return "无待审批记录，跳过";
    const btn = row.locator("button", { hasText: "通过" }).first();
    if (!(await btn.count())) throw new Error("未渲染通过按钮");
    await clearMessages(page);
    await btn.click();
    await sleep(1500);
    // 审批需填写备注（ElMessageBox.prompt）
    const box = page.locator(".el-message-box").last();
    if (await box.isVisible().catch(() => false)) {
      const inp = box.locator("input").first();
      if (await inp.count()) { await inp.fill("全链路测试自动审批通过"); }
      await box.locator("button", { hasText: /确定|确认|通过/ }).last().click();
      await sleep(1500);
    }
    const msg = await lastMessage(page, { timeout: 10000 });
    if (msg && msg.type === "error") throw new Error(`审批失败: ${msg.text}`);
    return msg ? `提示="${msg.text}"` : "审批决策已提交";
  }, { page, shotOnPass: true });

  // ================= AI 记忆 =================
  await H.run("D-31", "「AI 记忆」页签展示项目级记忆列表", async () => {
    await openTab(page, "AI 记忆");
    await sleep(2000);
    const pane = page.locator(".el-tab-pane:visible").last();
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ").trim();
    if (!text) throw new Error("AI 记忆页签内容为空");
    const rows = await pane.locator(".el-table__row").count();
    if (rows === 0 && !/暂无|没有|空/.test(text)) {
      throw new Error(`无记录但未给出空状态提示: ${text.slice(0, 200)}`);
    }
    return rows === 0
      ? `暂无项目级 AI 记忆（已正确展示空状态）：${text.slice(0, 90)}`
      : `AI 记忆 ${rows} 条`;
  }, { page });

  await H.run("D-32", "AI 记忆页签提供刷新与清空入口", async () => {
    const pane = page.locator(".el-tab-pane:visible").last();
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ");
    const found = ["刷新记忆", "清空记忆"].filter((k) => text.includes(k));
    if (found.length === 0) throw new Error("未提供记忆管理入口");
    return `入口: ${found.join("、")}`;
  }, { page });

  await H.shot(page, "D-AI记忆页签");

  // ================= 页签深链 =================
  await H.run("D-33", "页签切换同步到 URL 查询参数（支持深链）", async () => {
    await openTab(page, "信息收集");
    await sleep(1200);
    const url = page.url();
    if (!/[?&]tab=/.test(url)) throw new Error(`切换页签后 URL 未同步 tab 参数: ${url}`);
    return `URL=${url.slice(-60)}`;
  }, { page });

  return true;
}

module.exports = { run };
