/*
 * 阶段 B：安全评估项目管理
 *
 * 业务顺序：进入项目页 → 新建项目（DRAFT）→ 校验必填 → 编辑改为 ACTIVE
 * 只有项目处于 ACTIVE 且授权窗口有效，后续才允许创建检测任务。
 */
const {
  sleep, settle, navigate, pageTitle, dialog, dialogButton,
  fillByLabel, selectOption, pickDateTimeNow, pickDateTimeFuture, confirmBoxIfPresent,
  lastMessage, clearMessages, rowCount, waitRow,
} = require("../lib/ui.cjs");

async function run(page, H, ctx) {
  H.phase("阶段 B — 安全评估项目管理");

  ctx.projectName = `全链路测试项目-${ctx.stamp}`;

  await H.run("B-01", "通过侧边栏进入「评估项目」页面", async () => {
    await navigate(page, "评估项目");
    const t = await pageTitle(page);
    if (!t.includes("安全评估项目")) throw new Error(`页面标题异常: ${t}`);
    if (!page.url().includes("/projects")) throw new Error(`URL 异常: ${page.url()}`);
    return `标题="${t}"`;
  }, { page });

  await H.shot(page, "B-项目列表");

  await H.run("B-02", "项目列表正常加载", async () => {
    await page.locator(".el-table, .empty-state").first().waitFor({ state: "visible", timeout: 15000 });
    const n = await rowCount(page);
    ctx.projectRowsBefore = n;
    return `现有项目 ${n} 个`;
  }, { page });

  await H.run("B-03", "点击「新建评估项目」打开创建对话框", async () => {
    await page.locator("button", { hasText: "新建评估项目" }).first().click();
    const dlg = await dialog(page, "新建安全评估项目");
    if (!(await dlg.isVisible())) throw new Error("对话框未显示");
    return "对话框已打开";
  }, { page });

  await H.shot(page, "B-新建项目对话框");

  await H.run("B-04", "未填写必填项时无法创建（表单校验）", async () => {
    const dlg = await dialog(page, "新建安全评估项目");
    const btn = dlg.locator("button", { hasText: "创建项目" }).last();
    const disabled = await btn.isDisabled().catch(() => false);
    if (disabled) return "创建按钮在必填项为空时禁用";
    // 若按钮未禁用，则点击后应出现校验错误且对话框不关闭
    await btn.click();
    await sleep(1200);
    const stillOpen = await dlg.isVisible().catch(() => false);
    const errs = await page.locator(".el-form-item__error").count();
    const msg = await lastMessage(page, { timeout: 2500 });
    if (!stillOpen) throw new Error("必填项为空竟然创建成功");
    return `对话框保持打开，校验错误 ${errs} 条${msg ? `，提示="${msg.text}"` : ""}`;
  }, { page });

  await H.run("B-05", "填写项目名称、负责人、授权声明与授权有效期", async () => {
    const dlg = await dialog(page, "新建安全评估项目");
    await clearMessages(page);

    await fillByLabel(dlg, page, "项目名称", ctx.projectName);
    await fillByLabel(dlg, page, "负责人", "测试负责人");
    await fillByLabel(dlg, page, "授权声明",
      `已获得书面授权，允许对 ${ctx.targetIp} 进行端口探测、服务识别、HTTP 安全检查与受控漏洞检测。授权编号 AUTH-${ctx.stamp}。`);

    // 授权开始：选择「此刻」；授权结束：向后翻 2 个月并选 15 日
    ctx.projectValidFrom = await pickDateTimeNow(dlg, page, "授权开始");
    ctx.projectExpiresAt = await pickDateTimeFuture(dlg, page, "授权结束", { monthsAhead: 2, day: 15 });

    const desc = dlg.locator(".el-form-item", { hasText: "项目说明" }).first();
    if (await desc.isVisible().catch(() => false)) {
      await fillByLabel(dlg, page, "项目说明", "全链路 UI 端到端测试自动创建的评估项目。");
    }
    return `名称="${ctx.projectName}" 授权窗口 ${ctx.projectValidFrom} ~ ${ctx.projectExpiresAt}`;
  }, { page });

  await H.shot(page, "B-项目表单已填写");

  await H.run("B-06", "点击「创建项目」成功创建", async () => {
    const dlg = await dialog(page, "新建安全评估项目");
    await clearMessages(page);
    await dialogButton(dlg, "创建项目");
    await sleep(1500);
    await confirmBoxIfPresent(page, "确认并保存");
    await sleep(2000);
    const stillOpen = await dlg.isVisible().catch(() => false);
    if (stillOpen) {
      const errs = await page.locator(".el-form-item__error").allTextContents();
      throw new Error(`对话框未关闭，校验错误: ${errs.join("; ") || "无"}`);
    }
    return "项目创建请求已提交";
  }, { page });

  await H.run("B-07", "新建项目出现在列表中且初始状态为草稿", async () => {
    const row = await waitRow(page, ctx.projectName, 20000);
    const text = (await row.textContent()) || "";
    if (!/草稿|DRAFT/.test(text)) {
      throw new Error(`初始状态应为草稿，实际行内容: ${text.replace(/\s+/g, " ").slice(0, 200)}`);
    }
    return "状态=草稿";
  }, { page });

  await H.shot(page, "B-项目已创建");

  await H.run("B-08", "列表显示项目负责人与授权有效期", async () => {
    const row = await waitRow(page, ctx.projectName, 10000);
    const text = ((await row.textContent()) || "").replace(/\s+/g, " ");
    if (!text.includes("测试负责人")) throw new Error(`未显示负责人: ${text.slice(0, 200)}`);
    const year = new Date().getFullYear();
    if (!text.includes(String(year))) throw new Error(`未显示授权有效期: ${text.slice(0, 200)}`);
    return "负责人与授权有效期均已显示";
  }, { page });

  // ---------- 编辑：草稿 → 进行中 ----------
  await H.run("B-09", "点击「编辑」打开项目编辑对话框", async () => {
    const row = await waitRow(page, ctx.projectName, 10000);
    await row.locator("button", { hasText: "编辑" }).first().click();
    const dlg = await dialog(page, "编辑评估项目");
    if (!(await dlg.isVisible())) throw new Error("编辑对话框未显示");
    return "编辑对话框已打开";
  }, { page });

  await H.run("B-10", "将项目状态由「草稿」改为「进行中」", async () => {
    const dlg = await dialog(page, "编辑评估项目");
    await selectOption(dlg, page, "项目状态", "进行中");
    return "已选择进行中";
  }, { page });

  await H.shot(page, "B-项目状态改为进行中");

  await H.run("B-11", "保存状态变更并确认授权范围变更提示", async () => {
    const dlg = await dialog(page, "编辑评估项目");
    await clearMessages(page);
    await dialogButton(dlg, "保存修改");
    await sleep(1200);
    const confirmed = await confirmBoxIfPresent(page, "确认并保存");
    await sleep(2000);
    const stillOpen = await dlg.isVisible().catch(() => false);
    if (stillOpen) throw new Error("保存后编辑对话框未关闭");
    return confirmed ? "出现授权范围变更确认框并已确认" : "直接保存成功";
  }, { page });

  await H.run("B-12", "列表中项目状态更新为「进行中」", async () => {
    for (let i = 0; i < 15; i++) {
      const row = await waitRow(page, ctx.projectName, 10000);
      const text = ((await row.textContent()) || "").replace(/\s+/g, " ");
      if (/进行中|ACTIVE/.test(text)) return "状态=进行中";
      await sleep(1000);
    }
    throw new Error("15 秒内状态未变为进行中");
  }, { page });

  await H.shot(page, "B-项目已激活");

  await H.run("B-13", "点击「进入项目」跳转到项目详情页", async () => {
    const row = await waitRow(page, ctx.projectName, 10000);
    await row.locator("button", { hasText: "进入项目" }).first().click();
    await settle(page, 2500);
    if (!/\/projects\/\d+/.test(page.url())) throw new Error(`未跳转到详情页: ${page.url()}`);
    const m = page.url().match(/\/projects\/(\d+)/);
    ctx.projectId = m ? m[1] : null;
    const t = await pageTitle(page);
    return `项目 ID=${ctx.projectId}，标题="${t}"`;
  }, { page });

  await H.shot(page, "B-项目详情页");

  return true;
}

module.exports = { run };
