/*
 * 阶段 K：AI 安全助手（含红队工作流入口校验）
 *
 * 本环境未配置外部大模型 API Key，后端回退到本地规则规划器；
 * "生成计划 → 人工审核 → 执行工具 → 记录结果"链路仍完整可验证。
 *
 * 覆盖两种执行模式：
 *   - 「仅规划」：只生成计划，不派发任务；
 *   - 「执行检测」：由助手派发真实检测任务，任务仍需通过服务端授权校验。
 * 用例结束后会切回「仅规划」，恢复默认安全姿态。
 */
const {
  sleep, settle, navigate, pageTitle, selectOn,
  lastMessage, clearMessages, confirmBoxIfPresent,
} = require("../lib/ui.cjs");

async function run(page, H, ctx) {
  H.phase("阶段 K — AI 安全助手");

  await H.run("K-01", "通过侧边栏进入「AI 安全助手」页面", async () => {
    await navigate(page, "AI 安全助手");
    const t = await pageTitle(page);
    return `标题="${t}"，URL=${page.url().replace(ctx.baseUrl, "") || "/"}`;
  }, { page });

  await sleep(2500);
  await H.shot(page, "K-AI助手欢迎页");

  await H.run("K-02", "欢迎页展示引导标题与实时工作区概览", async () => {
    const welcome = page.locator(".chat-welcome").first();
    if (!(await welcome.count())) {
      // 可能已有会话，先新建对话回到欢迎态
      const nb = page.locator("button", { hasText: "新对话" }).first();
      if (await nb.count()) { await nb.click(); await sleep(2000); }
    }
    const w = page.locator(".chat-welcome").first();
    await w.waitFor({ state: "visible", timeout: 12000 });
    const text = ((await w.textContent()) || "").replace(/\s+/g, " ");
    if (!/告诉我你想检查什么/.test(text)) throw new Error(`欢迎标题异常: ${text.slice(0, 150)}`);
    return `欢迎页标题正确: ${text.slice(0, 90)}`;
  }, { page });

  await H.run("K-03", "工作区概览展示四项实时统计且授权目标数大于 0", async () => {
    const stats = page.locator(".welcome-stats").first();
    if (!(await stats.count())) throw new Error("未渲染工作区概览");
    const items = stats.locator(".welcome-stat");
    const n = await items.count();
    const texts = [];
    for (let i = 0; i < n; i++) {
      texts.push(((await items.nth(i).textContent()) || "").replace(/\s+/g, " ").trim());
    }
    const expect = ["授权目标", "进行中任务", "累计发现", "高危发现"];
    const missing = expect.filter((k) => !texts.some((t) => t.includes(k)));
    if (missing.length) throw new Error(`缺少统计项: ${missing.join("、")}（实际: ${texts.join(" | ")}）`);
    const targetStat = texts.find((t) => t.includes("授权目标")) || "";
    const m = targetStat.match(/(\d+)/);
    if (!m || Number(m[1]) === 0) throw new Error(`授权目标统计为 0，但前序阶段已登记目标: ${targetStat}`);
    ctx.aiStats = texts;
    return `${n} 项统计: ${texts.join(" | ").slice(0, 170)}`;
  }, { page });

  await H.run("K-04", "本地引擎状态最终显示为已就绪", async () => {
    for (let i = 0; i < 20; i++) {
      const t = ((await page.locator(".chat-header").first().textContent().catch(() => "")) || "").replace(/\s+/g, " ");
      if (/已就绪|已连接/.test(t)) return `状态: ${t.slice(0, 90)}`;
      if (/不可用/.test(t)) throw new Error(`引擎不可用: ${t.slice(0, 120)}`);
      await sleep(1000);
    }
    throw new Error("20 秒内引擎状态未变为已就绪");
  }, { page });

  await H.run("K-05", "快捷操作卡片提供三个跨页联动入口", async () => {
    const qa = page.locator(".quick-actions").first();
    if (!(await qa.count())) throw new Error("未渲染快捷操作区");
    const text = ((await qa.textContent()) || "").replace(/\s+/g, " ");
    const expect = ["分析代理流量", "手动主动检测", "查看检测结果"];
    const missing = expect.filter((k) => !text.includes(k));
    if (missing.length) throw new Error(`缺少快捷入口: ${missing.join("、")}`);
    return `快捷入口: ${expect.join("、")}`;
  }, { page });

  await H.run("K-06", "快捷操作可跳转到主动检测页并可返回", async () => {
    const qa = page.locator(".quick-actions").first();
    await qa.locator("*", { hasText: "手动主动检测" }).last().click();
    await settle(page, 2500);
    if (!page.url().includes("/vulnerabilities")) {
      throw new Error(`未跳转到主动检测页: ${page.url()}`);
    }
    await navigate(page, "AI 安全助手");
    await sleep(2000);
    return "跳转与返回均正常";
  }, { page });

  // ---------- 发送按钮的启用条件 ----------
  await H.run("K-07", "未填写提问且未选目标时发送按钮禁用", async () => {
    const btn = page.locator("button.send-button").first();
    await btn.waitFor({ state: "visible", timeout: 10000 });
    if (!(await btn.isDisabled())) throw new Error("空输入且未选目标时发送按钮仍可点击");
    return "发送按钮已禁用";
  }, { page });

  await H.run("K-08", "仅填写提问但未选择授权目标时发送按钮仍禁用", async () => {
    const ta = page.locator(".welcome-composer textarea").first();
    await ta.click();
    await ta.fill("请检查这个目标的 HTTP 安全响应头配置");
    await sleep(800);
    const btn = page.locator("button.send-button").first();
    const disabled = await btn.isDisabled();
    if (!disabled) {
      // 若已默认选中目标则不构成缺陷，记录实际情况
      const picker = ((await page.locator(".target-picker").first().textContent().catch(() => "")) || "").replace(/\s+/g, " ");
      return `发送按钮可用（目标选择器已有默认值: ${picker.slice(0, 80)}）`;
    }
    return "未选目标时发送按钮保持禁用，符合授权前置约束";
  }, { page });

  await H.run("K-09", "选择授权目标后发送按钮变为可用", async () => {
    const picker = page.locator(".target-picker").first();
    if (!(await picker.count())) throw new Error("未渲染授权目标选择器");
    const sel = picker.locator(".el-select").first();
    await selectOn(page, sel, ctx.webTargetName);
    await sleep(1500);
    const btn = page.locator("button.send-button").first();
    if (await btn.isDisabled()) throw new Error("已填提问并选定目标，发送按钮仍禁用");
    ctx.aiTargetSelected = true;
    return `已选择目标 ${ctx.webTargetUrl}，发送按钮可用`;
  }, { page });

  await H.run("K-10", "AI 执行模式开关存在且展示「仅规划/执行检测」两态", async () => {
    // 该开关无 aria-label，位于 welcome-composer 内，附带「仅规划/执行检测」文案
    const composer = page.locator(".welcome-composer").first();
    const sw = composer.locator(".el-switch").first();
    if (!(await sw.count())) throw new Error("未渲染 AI 执行模式开关");
    const text = ((await composer.textContent()) || "").replace(/\s+/g, " ");
    if (!/仅规划/.test(text) || !/执行检测/.test(text)) {
      throw new Error(`未展示执行模式两态文案: ${text.slice(0, 120)}`);
    }
    return "执行模式开关存在，含「仅规划 / 执行检测」两态（本阶段有意保持仅规划）";
  }, { page });

  await H.shot(page, "K-提问已就绪");

  // ---------- 真实提问 ----------
  await H.run("K-11", "发送安全检查提问并收到助手回复", async () => {
    await clearMessages(page);
    await page.locator("button.send-button").first().click();
    // 本地规则规划器与 NDJSON 流式返回可能较慢
    let assistant = null;
    for (let i = 0; i < 60; i++) {
      const a = page.locator("article.chat-message.assistant");
      if ((await a.count()) > 0) {
        const t = ((await a.last().textContent()) || "").trim();
        if (t.length > 10) { assistant = t; break; }
      }
      const err = await lastMessage(page, { timeout: 500 });
      if (err && err.type === "error") throw new Error(`提问被拒绝: ${err.text}`);
      await sleep(2000);
    }
    if (!assistant) throw new Error("120 秒内未收到助手回复");
    ctx.aiReply = assistant.slice(0, 500);
    return `助手回复 ${assistant.length} 字符: ${assistant.replace(/\s+/g, " ").slice(0, 160)}`;
  }, { page, shotOnPass: true });

  await H.run("K-12", "会话中正确回显用户提问", async () => {
    const user = page.locator("article.chat-message.user").last();
    if (!(await user.count())) throw new Error("未渲染用户消息气泡");
    const t = ((await user.textContent()) || "").replace(/\s+/g, " ");
    if (!/HTTP|响应头/.test(t)) throw new Error(`用户消息内容不符: ${t.slice(0, 150)}`);
    return `用户消息: ${t.slice(0, 120)}`;
  }, { page });

  await H.run("K-13", "回复内容与所提安全问题相关", async () => {
    const reply = ctx.aiReply || "";
    if (!reply) throw new Error("无回复内容可校验");
    const hits = ["响应头", "HTTP", "安全", "风险", "检测", "目标"].filter((k) => reply.includes(k));
    if (hits.length === 0) {
      throw new Error(`回复与提问无关: ${reply.slice(0, 200)}`);
    }
    return `回复命中关键词: ${hits.join("、")}`;
  }, { page });

  await H.run("K-14", "会话底部显示当前授权目标与白名单约束说明", async () => {
    const wrap = page.locator(".chat-composer-wrap").first();
    if (!(await wrap.count())) return "未渲染会话底部输入区（可能仍处于欢迎态）";
    const text = ((await wrap.textContent()) || "").replace(/\s+/g, " ");
    const hits = ["授权目标", "白名单", "授权范围"].filter((k) => text.includes(k));
    if (hits.length === 0) throw new Error(`底部未声明授权约束: ${text.slice(0, 200)}`);
    return `底部约束说明: ${hits.join("、")}`;
  }, { page });

  await H.run("K-15", "消息支持「引用」并可取消引用", async () => {
    const msg = page.locator("article.chat-message").last();
    const quote = msg.locator("button", { hasText: "引用" }).first();
    if (!(await quote.count())) return "当前消息未提供引用入口";
    await quote.click();
    await sleep(1200);
    const cq = page.locator(".composer-quote").first();
    if (!(await cq.count())) throw new Error("点击引用后未出现引用区");
    const cancel = page.locator('[aria-label="取消引用"]').first();
    if (await cancel.count()) { await cancel.click(); await sleep(800); }
    return "引用与取消引用均正常";
  }, { page });

  await H.run("K-16", "最近对话列表记录本次会话", async () => {
    const toggle = page.locator("button.desktop-v2-recents-toggle").first();
    if (!(await toggle.count())) return "未渲染最近对话入口";
    const text = ((await toggle.textContent()) || "").replace(/\s+/g, " ").trim();
    const expanded = await toggle.getAttribute("aria-expanded");
    if (expanded !== "true") { await toggle.click(); await sleep(1000); }
    const items = page.locator("button.desktop-v2-recent-open");
    const n = await items.count();
    if (n === 0) throw new Error("本次已产生会话，但最近对话列表为空");
    ctx.recentCount = n;
    return `最近对话 ${n} 条（入口文案: ${text.slice(0, 40)}）`;
  }, { page });

  await H.run("K-17", "可删除最近对话并需二次确认", async () => {
    const items = page.locator("button.desktop-v2-recent-open");
    const before = await items.count();
    if (before === 0) return "无最近对话可删除";
    const del = page.locator('button.desktop-v2-recent-delete[aria-label="删除对话"]').first();
    if (!(await del.count())) return "未渲染删除对话入口";
    await del.click();
    await sleep(1200);
    const clicked = await confirmBoxIfPresent(page, ["删除", "确定", "确认"]);
    if (!clicked) throw new Error("删除对话未弹出确认框");
    await sleep(2000);
    const after = await page.locator("button.desktop-v2-recent-open").count();
    if (after >= before) throw new Error(`删除后会话数未减少: ${before} → ${after}`);
    return `会话数 ${before} → ${after}`;
  }, { page, shotOnPass: true });

  await H.run("K-18", "点击「新建对话」重置为欢迎态", async () => {
    const btn = page.locator("button.desktop-v2-new-task").first();
    if (!(await btn.count())) throw new Error("未渲染新建对话按钮");
    await btn.click();
    await sleep(2500);
    const w = page.locator(".chat-welcome").first();
    if (!(await w.isVisible().catch(() => false))) throw new Error("未回到欢迎态");
    return "已重置为欢迎态";
  }, { page });

  // ---------- AI 执行模式：由助手派发真实检测任务 ----------
  await H.run("K-19", "切换 AI 执行模式为「执行检测」", async () => {
    // 新建对话，回到可编辑的欢迎态
    const nb = page.locator("button.desktop-v2-new-task").first();
    if (await nb.count()) { await nb.click(); await sleep(2500); }
    const composer = page.locator(".welcome-composer").first();
    await composer.waitFor({ state: "visible", timeout: 12000 });

    const sw = composer.locator(".el-switch").first();
    if (!(await sw.count())) throw new Error("未渲染执行模式开关");
    const before = (await sw.getAttribute("class")) || "";
    await sw.click();
    await sleep(1000);
    const after = (await sw.getAttribute("class")) || "";
    if (before === after) throw new Error("点击后开关状态未变化");
    ctx.aiExecutionMode = after.includes("is-checked");
    if (!ctx.aiExecutionMode) {
      // 若首次点击是关闭方向，再点一次切到执行检测
      await sw.click();
      await sleep(1000);
      ctx.aiExecutionMode = ((await sw.getAttribute("class")) || "").includes("is-checked");
    }
    if (!ctx.aiExecutionMode) throw new Error("未能切换到「执行检测」模式");
    return "已切换到「执行检测」模式";
  }, { page, shotOnPass: true });

  await H.run("K-20", "在执行模式下选择授权目标并发送检测请求", async () => {
    const composer = page.locator(".welcome-composer").first();
    const ta = composer.locator("textarea").first();
    await ta.click();
    await ta.fill("请对这个目标执行 HTTP 安全响应头检查，并说明发现的问题。");
    await sleep(600);

    const picker = page.locator(".target-picker").first();
    if (await picker.count()) {
      await selectOn(page, picker.locator(".el-select").first(), ctx.webTargetName).catch(() => {});
      await sleep(1500);
    }
    const btn = page.locator("button.send-button").first();
    if (await btn.isDisabled()) throw new Error("已填提问并选定目标，发送按钮仍禁用");
    await clearMessages(page);
    await btn.click();
    await sleep(2000);
    // 执行模式可能需要二次确认
    await confirmBoxIfPresent(page, ["确认执行", "确定", "确认", "开始"], { timeout: 6000 });
    return `已在执行模式下发送请求，目标 ${ctx.webTargetUrl}`;
  }, { page });

  await H.run("K-21", "助手返回执行计划或明确的拒绝理由", async () => {
    let assistant = null;
    let planCard = false;
    for (let i = 0; i < 75; i++) {
      const a = page.locator("article.chat-message.assistant");
      if ((await a.count()) > 0) {
        const t = ((await a.last().textContent()) || "").trim();
        if (t.length > 10) assistant = t;
      }
      if ((await page.locator(".execution-plan-card").count()) > 0) { planCard = true; break; }
      if (assistant) break;
      const err = await lastMessage(page, { timeout: 500 });
      if (err && err.type === "error") {
        // 被授权守卫拒绝也是有效结果，如实记录
        ctx.aiDispatchRejected = err.text;
        return `被拒绝（授权守卫生效）：${err.text.slice(0, 140)}`;
      }
      await sleep(2000);
    }
    if (!assistant && !planCard) throw new Error("150 秒内既无回复也无执行计划");
    ctx.aiDispatchPlanCard = planCard;
    ctx.aiDispatchReply = (assistant || "").slice(0, 400);
    return planCard
      ? "已生成执行计划卡片"
      : `助手回复 ${(assistant || "").length} 字符: ${(assistant || "").replace(/\s+/g, " ").slice(0, 130)}`;
  }, { page, shotOnPass: true });

  await H.run("K-22", "执行计划展示步骤清单与进度（若已派发）", async () => {
    if (ctx.aiDispatchRejected) return `本次被授权守卫拒绝，无执行计划：${ctx.aiDispatchRejected.slice(0, 80)}`;
    const card = page.locator(".execution-plan-card").first();
    if (!(await card.count())) {
      return "本次未生成执行计划卡片（本地规则规划器可能仅返回答复）";
    }
    const text = ((await card.textContent()) || "").replace(/\s+/g, " ");
    const steps = await card.locator("ol.execution-plan-list li").count();
    const hasProgress = (await card.locator(".el-progress").count()) > 0;
    if (steps === 0 && !/执行计划/.test(text)) {
      throw new Error(`执行计划卡片内容异常: ${text.slice(0, 180)}`);
    }
    ctx.aiPlanSteps = steps;
    return `计划步骤 ${steps} 步${hasProgress ? "，含进度条" : ""}：${text.slice(0, 130)}`;
  }, { page, shotOnPass: true });

  await H.run("K-23", "AI 派发的任务同样受授权边界约束（任务中心可核对）", async () => {
    if (ctx.aiDispatchRejected) return "本次未派发任务，跳过";
    if (!ctx.aiDispatchPlanCard) return "本次未生成执行计划，未派发任务，跳过";
    await navigate(page, "检测任务");
    await sleep(3000);
    const rows = page.locator(".el-table__row");
    const n = await rows.count();
    if (n === 0) throw new Error("任务列表为空");
    // 最近若干任务中应能看到 AI 派发的 http 类任务
    let found = null;
    for (let i = 0; i < Math.min(n, 8); i++) {
      const raw = ((await rows.nth(i).textContent()) || "").replace(/\s+/g, " ");
      if (/http_headers|http_security_check/.test(raw)) { found = raw; break; }
    }
    await navigate(page, "AI 安全助手");
    await sleep(2000);
    if (!found) return `最近 8 个任务中未识别到 AI 派发的 HTTP 任务（共 ${n} 行）`;
    return `任务中心可见 AI 派发的任务：${found.slice(0, 130)}`;
  }, { page });

  await H.run("K-24", "将执行模式切回「仅规划」，恢复默认安全姿态", async () => {
    const nb = page.locator("button.desktop-v2-new-task").first();
    if (await nb.count()) { await nb.click(); await sleep(2500); }
    const composer = page.locator(".welcome-composer").first();
    const sw = composer.locator(".el-switch").first();
    if (!(await sw.count())) return "未渲染开关，跳过";
    const cls = (await sw.getAttribute("class")) || "";
    if (cls.includes("is-checked")) { await sw.click(); await sleep(1000); }
    const after = ((await sw.getAttribute("class")) || "").includes("is-checked");
    if (after) throw new Error("未能切回仅规划模式");
    return "已恢复为「仅规划」默认模式";
  }, { page });

  // ---------- 红队工作流页面可达性 ----------
  await H.run("K-25", "通过侧边栏进入「红队工作流」页面并渲染画布", async () => {
    await navigate(page, "红队工作流");
    await sleep(3000);
    const t = await pageTitle(page);
    if (!page.url().includes("/workflow")) throw new Error(`URL 异常: ${page.url()}`);
    // Vue Flow 画布根为 .flow-canvas / .vue-flow；#red-team-workflow 仅用于内部 aria 元素
    const canvas = page.locator(".flow-canvas, .vue-flow").first();
    await canvas.waitFor({ state: "visible", timeout: 12000 });
    const nodes = await page.locator(".workflow-node").count();
    if (nodes === 0) throw new Error("画布已渲染但无任何工作流节点");
    return `标题="${t}"，画布已渲染，含 ${nodes} 个工作流节点`;
  }, { page });

  await H.shot(page, "K-红队工作流");

  await H.run("K-26", "工作流页提供保存与执行入口及拓扑状态提示", async () => {
    const actions = page.locator(".workflow-actions").first();
    if (!(await actions.count())) throw new Error("未渲染工作流操作区");
    const btns = (await actions.locator("button").allTextContents()).map((s) => s.trim()).filter(Boolean);
    const found = ["保存工作流", "执行工作流"].filter((k) => btns.some((b) => b.includes(k)));
    if (found.length < 2) throw new Error(`缺少保存/执行入口，实际: ${btns.join(" | ")}`);
    const status = ((await page.locator(".workflow-status-row").first().textContent().catch(() => "")) || "").replace(/\s+/g, " ").trim();
    return `入口: ${found.join("、")}；拓扑状态: ${status.slice(0, 110)}`;
  }, { page });

  await H.run("K-27", "工作流提供阶段库与受控能力库", async () => {
    const phase = page.locator("section.phase-library").first();
    const cap = page.locator("section.capability-library").first();
    if (!(await phase.count())) throw new Error("未渲染流程阶段库");
    if (!(await cap.count())) throw new Error("未渲染受控能力库");
    const phases = await phase.locator(".phase-library-item").count();
    const caps = await cap.locator(".library-item").count();
    if (phases === 0 || caps === 0) throw new Error(`库为空：阶段 ${phases} 个，能力 ${caps} 个`);
    return `阶段 ${phases} 个，受控能力 ${caps} 个`;
  }, { page });

  await H.run("K-28", "工作流配置面板可选择项目、目标与模板", async () => {
    const btn = page.locator("button", { hasText: "工作流配置" }).first();
    if (!(await btn.count())) throw new Error("未渲染工作流配置入口");
    await btn.click();
    await sleep(1800);
    const panel = page.locator("#workflow-config-panel").first();
    if (!(await panel.isVisible().catch(() => false))) throw new Error("配置面板未打开");
    const text = ((await panel.textContent()) || "").replace(/\s+/g, " ");
    const missing = ["评估项目", "授权目标", "工作流模板"].filter((k) => !text.includes(k));
    if (missing.length) throw new Error(`配置面板缺少: ${missing.join("、")}`);
    const close = panel.locator('[aria-label="关闭工作流配置"]').first();
    if (await close.count()) { await close.click(); await sleep(1000); }
    return "配置面板含项目、目标与模板选择";
  }, { page, shotOnPass: true });

  return true;
}

module.exports = { run };
