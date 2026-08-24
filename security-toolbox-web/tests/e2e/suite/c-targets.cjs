/*
 * 阶段 C：授权目标登记与管理
 *
 * 业务顺序：进入目标页 → 新增目标（归属项目 / 类型 / 地址 / 授权记录 / 端口）
 *          → 校验列表展示 → 编辑目标 → 授权范围变更确认
 *
 * 目标固定为靶机 192.168.136.131，授权端口覆盖 SSH(22) 与 Web(8000)。
 */
const {
  sleep, settle, navigate, pageTitle, dialog, dialogButton,
  fillByLabel, selectOption, confirmBoxIfPresent, confirmBox,
  lastMessage, clearMessages, rowCount, waitRow,
} = require("../lib/ui.cjs");

async function run(page, H, ctx) {
  H.phase("阶段 C — 授权目标登记与管理");

  ctx.targetName = `靶机-${ctx.targetIp}-${ctx.stamp}`;
  ctx.allowedPorts = `22,80,443,8000,8080`;

  await H.run("C-01", "通过侧边栏进入「授权目标」页面", async () => {
    await navigate(page, "授权目标");
    const t = await pageTitle(page);
    if (!t.includes("授权目标")) throw new Error(`页面标题异常: ${t}`);
    return `标题="${t}"`;
  }, { page });

  await H.shot(page, "C-目标列表");

  await H.run("C-02", "目标列表正常加载", async () => {
    await page.locator(".el-table, .empty-state").first().waitFor({ state: "visible", timeout: 15000 });
    const n = await rowCount(page);
    return `现有目标 ${n} 个`;
  }, { page });

  await H.run("C-03", "点击「新增目标」打开登记对话框", async () => {
    await page.locator("button", { hasText: "新增目标" }).first().click();
    await sleep(1200);
    // 若没有项目会先弹出引导确认框，此处应直接打开对话框
    const guard = await page.locator(".el-message-box").isVisible().catch(() => false);
    if (guard) throw new Error("出现「需要先创建评估项目」引导框，说明项目未就绪");
    const dlg = await dialog(page, "新增授权目标");
    if (!(await dlg.isVisible())) throw new Error("对话框未显示");
    return "对话框已打开";
  }, { page });

  await H.shot(page, "C-新增目标对话框");

  await H.run("C-04", "选择归属评估项目为本次测试项目", async () => {
    const dlg = await dialog(page, "新增授权目标");
    await selectOption(dlg, page, "归属评估项目", ctx.projectName);
    return `已选择「${ctx.projectName}」`;
  }, { page });

  await H.run("C-05", "填写目标名称并选择目标类型为「IP 地址」", async () => {
    const dlg = await dialog(page, "新增授权目标");
    await fillByLabel(dlg, page, "名称", ctx.targetName);
    await selectOption(dlg, page, "目标类型", "IP 地址");
    return `名称="${ctx.targetName}" 类型=IP 地址`;
  }, { page });

  await H.run("C-06", "填写目标地址为靶机 IP 与授权记录", async () => {
    const dlg = await dialog(page, "新增授权目标");
    await fillByLabel(dlg, page, "地址", ctx.targetIp);
    await fillByLabel(dlg, page, "授权记录",
      `靶机 ${ctx.targetIp} 已获书面授权，允许探测 ${ctx.allowedPorts} 端口。授权编号 AUTH-${ctx.stamp}。`);
    return `地址=${ctx.targetIp}`;
  }, { page });

  await H.run("C-07", "通过端口选择器授权 SSH(22) 与 Web(8000) 等端口", async () => {
    const dlg = await dialog(page, "新增授权目标");
    const picker = dlg.locator(".port-picker").first();
    await picker.waitFor({ state: "visible", timeout: 8000 });

    // 常用端口多选：SSH·22 / HTTP·80 / HTTPS·443 / HTTP 备用·8080
    const sel = picker.locator(".el-select").first();
    for (const label of ["SSH", "HTTP·80", "HTTPS·443", "HTTP 备用"]) {
      await sel.click();
      await sleep(400);
      const dd = page.locator(".el-select-dropdown:visible").last();
      const opt = dd.locator("li.el-select-dropdown__item", { hasText: label }).first();
      if (await opt.count()) { await opt.click(); await sleep(300); }
    }
    await page.keyboard.press("Escape").catch(() => {});
    await sleep(300);

    // 自定义端口补充 8000
    const custom = picker.locator('input[placeholder*="手动填写"]').first();
    if (await custom.count()) {
      await custom.click();
      await custom.fill("8000");
      await page.keyboard.press("Enter");
      await sleep(500);
    }
    const hint = ((await picker.textContent()) || "").replace(/\s+/g, " ");
    return `端口选择器内容: ${hint.slice(0, 160)}`;
  }, { page });

  await H.shot(page, "C-目标表单已填写");

  await H.run("C-08", "点击「保存目标」成功登记授权目标", async () => {
    const dlg = await dialog(page, "新增授权目标");
    await clearMessages(page);
    await dialogButton(dlg, "保存目标");
    await sleep(1500);
    await confirmBoxIfPresent(page, "确认并保存");
    await sleep(2000);
    const stillOpen = await dlg.isVisible().catch(() => false);
    if (stillOpen) {
      const err = ((await dlg.locator(".target-save-error").textContent().catch(() => "")) || "").trim();
      const errs = await page.locator(".el-form-item__error").allTextContents();
      throw new Error(`对话框未关闭。错误提示="${err}" 校验=${errs.join(";") || "无"}`);
    }
    return "目标登记请求已提交";
  }, { page });

  await H.run("C-09", "新目标出现在列表中且显示正确地址与类型", async () => {
    const row = await waitRow(page, ctx.targetName, 20000);
    const text = ((await row.textContent()) || "").replace(/\s+/g, " ");
    if (!text.includes(ctx.targetIp)) throw new Error(`未显示目标地址: ${text.slice(0, 200)}`);
    if (!/IP/i.test(text)) throw new Error(`未显示目标类型: ${text.slice(0, 200)}`);
    return `行内容: ${text.slice(0, 160)}`;
  }, { page });

  await H.shot(page, "C-目标已登记");

  await H.run("C-10", "列表显示授权端口范围", async () => {
    const row = await waitRow(page, ctx.targetName, 10000);
    const text = ((await row.textContent()) || "").replace(/\s+/g, " ");
    for (const p of ["22", "8000"]) {
      if (!text.includes(p)) throw new Error(`端口 ${p} 未显示在列表中: ${text.slice(0, 200)}`);
    }
    return "22 与 8000 均已授权";
  }, { page });

  await H.run("C-11", "列表显示目标授权有效期及其来源", async () => {
    const row = await waitRow(page, ctx.targetName, 10000);
    const win = row.locator(".target-authorization-window").first();
    if (!(await win.count())) throw new Error("未渲染授权有效期列");
    const text = ((await win.textContent()) || "").replace(/\s+/g, " ").trim();
    return `授权有效期列: ${text.slice(0, 120)}`;
  }, { page });

  await H.run("C-12", "列表显示目标状态为「启用」", async () => {
    const row = await waitRow(page, ctx.targetName, 10000);
    const text = ((await row.textContent()) || "").replace(/\s+/g, " ");
    if (!text.includes("启用")) throw new Error(`状态非启用: ${text.slice(0, 200)}`);
    return "状态=启用";
  }, { page });

  // ---------- 编辑目标 ----------
  await H.run("C-13", "点击「编辑」打开目标编辑对话框", async () => {
    const row = await waitRow(page, ctx.targetName, 10000);
    await row.locator("button", { hasText: "编辑" }).first().click();
    const dlg = await dialog(page, "编辑授权目标");
    if (!(await dlg.isVisible())) throw new Error("编辑对话框未显示");
    return "编辑对话框已打开";
  }, { page });

  await H.shot(page, "C-编辑目标对话框");

  await H.run("C-14", "编辑对话框回显已授权端口", async () => {
    const dlg = await dialog(page, "编辑授权目标");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    if (!text.includes("22")) throw new Error("未回显端口 22");
    if (!text.includes("8000")) throw new Error("未回显端口 8000");
    return "端口回显正确";
  }, { page });

  await H.run("C-15", "修改授权记录并保存，触发授权范围变更确认", async () => {
    const dlg = await dialog(page, "编辑授权目标");
    await clearMessages(page);
    await fillByLabel(dlg, page, "授权记录",
      `靶机 ${ctx.targetIp} 授权记录已于测试中更新。授权编号 AUTH-${ctx.stamp}-R2。`);
    await dialogButton(dlg, "保存修改");
    await sleep(1200);
    const confirmed = await confirmBoxIfPresent(page, "确认并保存");
    await sleep(2000);
    const stillOpen = await dlg.isVisible().catch(() => false);
    if (stillOpen) throw new Error("保存后编辑对话框未关闭");
    return confirmed ? "出现授权范围变更确认框并已确认" : "直接保存成功";
  }, { page });

  await H.run("C-16", "目标仍在列表中且保持启用状态", async () => {
    const row = await waitRow(page, ctx.targetName, 15000);
    const text = ((await row.textContent()) || "").replace(/\s+/g, " ");
    if (!text.includes("启用")) throw new Error(`状态异常: ${text.slice(0, 200)}`);
    return "目标状态正常";
  }, { page });

  await H.shot(page, "C-目标编辑完成");

  // ================================================================
  // 追加登记 URL 型目标：IP 型目标无法使用 HTTP 类检测规则
  // （规则兼容性按目标类型判定，Web 规则要求目标为 Web 地址）
  // ================================================================
  ctx.webTargetName = `靶机Web-${ctx.targetIp}-${ctx.stamp}`;
  ctx.webTargetUrl = `http://${ctx.targetIp}:${ctx.targetWebPort}`;

  await H.run("C-17", "再次点击「新增目标」登记 URL 型 Web 目标", async () => {
    await page.locator("button", { hasText: "新增目标" }).first().click();
    await sleep(1200);
    const dlg = await dialog(page, "新增授权目标");
    if (!(await dlg.isVisible())) throw new Error("对话框未显示");
    return "对话框已打开";
  }, { page });

  await H.run("C-18", "填写 URL 型目标的项目归属、名称与类型", async () => {
    const dlg = await dialog(page, "新增授权目标");
    await selectOption(dlg, page, "归属评估项目", ctx.projectName);
    await fillByLabel(dlg, page, "名称", ctx.webTargetName);
    await selectOption(dlg, page, "目标类型", "URL");
    return `名称="${ctx.webTargetName}" 类型=URL`;
  }, { page });

  await H.run("C-19", "填写 Web 目标地址与授权记录", async () => {
    const dlg = await dialog(page, "新增授权目标");
    await fillByLabel(dlg, page, "地址", ctx.webTargetUrl);
    await fillByLabel(dlg, page, "授权记录",
      `靶机 Web 服务 ${ctx.webTargetUrl} 已获书面授权，允许执行 HTTP 安全检查。授权编号 AUTH-${ctx.stamp}-WEB。`);
    return `地址=${ctx.webTargetUrl}`;
  }, { page });

  await H.run("C-20", "为 Web 目标授权 8000 端口", async () => {
    const dlg = await dialog(page, "新增授权目标");
    const picker = dlg.locator(".port-picker").first();
    await picker.waitFor({ state: "visible", timeout: 8000 });
    const custom = picker.locator('input[placeholder*="手动填写"]').first();
    await custom.click();
    await custom.fill(`80,443,${ctx.targetWebPort}`);
    await page.keyboard.press("Enter");
    await sleep(600);
    return `已授权端口 80,443,${ctx.targetWebPort}`;
  }, { page });

  await H.run("C-21", "保存 URL 型目标", async () => {
    const dlg = await dialog(page, "新增授权目标");
    await clearMessages(page);
    await dialogButton(dlg, "保存目标");
    await sleep(1500);
    await confirmBoxIfPresent(page, "确认并保存");
    await sleep(2000);
    if (await dlg.isVisible().catch(() => false)) {
      const err = ((await dlg.locator(".target-save-error").textContent().catch(() => "")) || "").trim();
      throw new Error(`对话框未关闭，错误="${err}"`);
    }
    return "URL 型目标登记成功";
  }, { page });

  await H.run("C-22", "URL 型目标出现在列表中并显示完整地址", async () => {
    const row = await waitRow(page, ctx.webTargetName, 20000);
    const text = ((await row.textContent()) || "").replace(/\s+/g, " ");
    if (!text.includes(ctx.webTargetUrl)) throw new Error(`未显示完整 URL: ${text.slice(0, 200)}`);
    if (!/URL/i.test(text)) throw new Error(`未显示 URL 类型: ${text.slice(0, 200)}`);
    return `行内容: ${text.slice(0, 150)}`;
  }, { page });

  await H.shot(page, "C-两个目标均已登记");

  return true;
}

module.exports = { run };
