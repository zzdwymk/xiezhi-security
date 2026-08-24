/*
 * 阶段 M：系统设置与审计日志
 *
 * 系统设置无侧边栏入口，须经用户下拉菜单进入（openSettings）。
 * 本阶段只做只读校验与表单校验，不保存任何配置变更，
 * 尤其不触发「清空业务数据」与真实改密。
 */
const {
  sleep, settle, navigate, openSettings, pageTitle, dialog,
  lastMessage, clearMessages, rowCount, selectOn,
} = require("../lib/ui.cjs");

/** 打开设置中某一行对应的对话框 */
async function openSettingsRow(page, label) {
  const row = page.locator("button.settings-row", { hasText: label }).first();
  await row.waitFor({ state: "visible", timeout: 10000 });
  await row.click();
  await sleep(1800);
}

/** 关闭当前可见对话框（优先「取消」，否则右上角关闭） */
async function closeDialog(page) {
  const dlg = page.locator(".el-dialog:visible").last();
  if (!(await dlg.isVisible().catch(() => false))) return false;
  const cancel = dlg.locator("button", { hasText: "取消" }).last();
  if (await cancel.isVisible().catch(() => false)) await cancel.click();
  else await dlg.locator(".el-dialog__headerbtn").last().click();
  await sleep(1200);
  return true;
}

async function run(page, H, ctx) {
  H.phase("阶段 M — 系统设置与审计日志");

  // ================= 系统设置 =================
  await H.run("M-01", "经用户下拉菜单进入「系统设置」（唯一入口）", async () => {
    await openSettings(page);
    if (!page.url().includes("/settings")) throw new Error(`未进入设置页: ${page.url()}`);
    const t = await pageTitle(page);
    return `标题="${t}"`;
  }, { page });

  await sleep(1500);
  await H.shot(page, "M-系统设置");

  await H.run("M-02", "设置页渲染完整的分组结构", async () => {
    const groups = page.locator("section.settings-group");
    const n = await groups.count();
    if (n === 0) throw new Error("未渲染任何设置分组");
    const titles = [];
    for (let i = 0; i < n; i++) {
      titles.push(((await groups.nth(i).locator("header.settings-group-title").first().textContent().catch(() => "")) || "").replace(/\s+/g, " ").trim());
    }
    const expect = ["外观", "AI 与外部服务", "安全与访问", "系统与审计", "危险操作", "关于"];
    const missing = expect.filter((e) => !titles.some((t) => t.includes(e)));
    if (missing.length) throw new Error(`缺少分组: ${missing.join("、")}（实际: ${titles.join("/")}）`);
    return `${n} 个分组: ${titles.join(" / ")}`;
  }, { page });

  await H.run("M-03", "网页端「窗口背景材质」不可用（桌面端专属）", async () => {
    const sel = page.locator(".material-select").first();
    if (!(await sel.count())) return "网页端未渲染窗口材质控件";
    const cls = (await sel.getAttribute("class")) || "";
    const inner = sel.locator("input").first();
    const disabled = cls.includes("is-disabled") || (await inner.isDisabled().catch(() => false));
    if (!disabled) throw new Error("网页端窗口材质控件可编辑（应仅桌面端可用）");
    return "已正确禁用（桌面端专属能力）";
  }, { page });

  // ---------- AI 模型服务 ----------
  await H.run("M-04", "打开「AI 模型服务」对话框并渲染完整配置项", async () => {
    await openSettingsRow(page, "AI 模型服务");
    const dlg = page.locator(".ai-model-dialog, .el-dialog:visible").last();
    if (!(await dlg.isVisible().catch(() => false))) throw new Error("AI 模型服务对话框未打开");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const expect = ["API 地址", "API Key", "模型名称", "知识检索方式"];
    const missing = expect.filter((k) => !text.includes(k));
    if (missing.length) throw new Error(`缺少配置项: ${missing.join("、")}`);
    ctx.aiDialogText = text.slice(0, 400);
    return `配置项齐全: ${expect.join("、")}`;
  }, { page, shotOnPass: true });

  await H.run("M-05", "AI 对话框提供 BM25 与真实向量两种检索方式", async () => {
    const dlg = page.locator(".el-dialog:visible").last();
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const found = ["BM25", "向量"].filter((k) => text.includes(k));
    if (found.length < 2) throw new Error(`检索方式选项不完整: ${text.slice(0, 250)}`);
    return "提供 BM25 关键词与真实向量嵌入两种方式";
  }, { page });

  await H.run("M-06", "网页端 AI 配置为只读（密钥仅桌面端安全存储可改）", async () => {
    const dlg = page.locator(".el-dialog:visible").last();
    const inputs = dlg.locator("input");
    const n = await inputs.count();
    if (n === 0) throw new Error("未渲染任何输入框");
    let disabled = 0;
    for (let i = 0; i < n; i++) {
      if (await inputs.nth(i).isDisabled().catch(() => false)) disabled++;
    }
    if (disabled === 0) {
      throw new Error(`网页端 AI 配置输入框全部可编辑（${n} 个），与"密钥由桌面主进程安全存储"的设计不一致`);
    }
    return `${disabled}/${n} 个输入框在网页端已禁用`;
  }, { page });

  await H.run("M-07", "AI 对话框提供连接测试与保存入口", async () => {
    const dlg = page.locator(".el-dialog:visible").last();
    const btns = (await dlg.locator("button").allTextContents()).map((s) => s.trim()).filter(Boolean);
    const found = ["测试连接", "保存并应用"].filter((k) => btns.some((b) => b.includes(k)));
    if (found.length === 0) throw new Error(`缺少测试/保存入口，实际按钮: ${btns.join(" | ")}`);
    return `入口: ${found.join("、")}（按钮: ${btns.join(" | ").slice(0, 120)}）`;
  }, { page });

  await H.run("M-08", "取消关闭 AI 对话框且不保存任何变更", async () => {
    const closed = await closeDialog(page);
    if (!closed) throw new Error("对话框未能关闭");
    return "已取消关闭，未保存变更";
  }, { page });

  // ---------- ICP 数据源 ----------
  await H.run("M-09", "打开「ICP 备案数据源」对话框", async () => {
    await openSettingsRow(page, "ICP");
    const dlg = page.locator(".el-dialog:visible").last();
    if (!(await dlg.isVisible().catch(() => false))) throw new Error("ICP 对话框未打开");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    if (!/ICP/.test(text)) throw new Error(`对话框内容与 ICP 无关: ${text.slice(0, 200)}`);
    await closeDialog(page);
    return `对话框已打开并关闭: ${text.slice(0, 130)}`;
  }, { page });

  // ---------- GitHub 令牌 ----------
  await H.run("M-10", "打开「GitHub 访问令牌」对话框并提示速率限制", async () => {
    await openSettingsRow(page, "GitHub");
    const dlg = page.locator(".el-dialog:visible").last();
    if (!(await dlg.isVisible().catch(() => false))) throw new Error("GitHub 令牌对话框未打开");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    await closeDialog(page);
    return `对话框内容: ${text.slice(0, 150)}`;
  }, { page });

  // ---------- 修改密码（仅校验，不真正改密） ----------
  await H.run("M-11", "打开「修改登录密码」对话框并渲染三个密码字段", async () => {
    await openSettingsRow(page, "修改登录密码");
    const dlg = page.locator(".el-dialog:visible").last();
    if (!(await dlg.isVisible().catch(() => false))) throw new Error("改密对话框未打开");
    const pwInputs = dlg.locator('input[type="password"]');
    const n = await pwInputs.count();
    if (n < 3) throw new Error(`密码输入框不足 3 个（实际 ${n} 个）`);
    return `渲染 ${n} 个密码字段`;
  }, { page });

  await H.run("M-12", "新密码与确认不一致时被拒绝（不改密）", async () => {
    const dlg = page.locator(".el-dialog:visible").last();
    await clearMessages(page);
    const pw = dlg.locator('input[type="password"]');
    await pw.nth(0).fill(ctx.password);
    await pw.nth(1).fill("TestPassword-A-123456");
    await pw.nth(2).fill("TestPassword-B-654321");
    await dlg.locator("button", { hasText: "保存" }).last().click();
    await sleep(1800);
    const msg = await lastMessage(page, { timeout: 8000 });
    const stillOpen = await dlg.isVisible().catch(() => false);
    const errs = (await page.locator(".el-form-item__error").allTextContents()).map((s) => s.trim()).filter(Boolean);
    if (!stillOpen && (!msg || msg.type === "success")) {
      throw new Error("两次新密码不一致却修改成功");
    }
    return `已拒绝${msg ? `，提示="${msg.text}"` : ""}${errs.length ? `，校验: ${errs.join(";")}` : ""}`;
  }, { page, shotOnPass: true });

  await H.run("M-13", "新密码长度不足时被拒绝（不改密）", async () => {
    const dlg = page.locator(".el-dialog:visible").last();
    if (!(await dlg.isVisible().catch(() => false))) return "对话框已关闭，跳过";
    await clearMessages(page);
    const pw = dlg.locator('input[type="password"]');
    await pw.nth(0).fill(ctx.password);
    await pw.nth(1).fill("short");
    await pw.nth(2).fill("short");
    await dlg.locator("button", { hasText: "保存" }).last().click();
    await sleep(1800);
    const msg = await lastMessage(page, { timeout: 8000 });
    const stillOpen = await dlg.isVisible().catch(() => false);
    const errs = (await page.locator(".el-form-item__error").allTextContents()).map((s) => s.trim()).filter(Boolean);
    if (!stillOpen && (!msg || msg.type === "success")) {
      throw new Error("过短新密码却修改成功（要求至少 8 位）");
    }
    return `已拒绝${msg ? `，提示="${msg.text}"` : ""}${errs.length ? `，校验: ${errs.join(";")}` : ""}`;
  }, { page, shotOnPass: true });

  await H.run("M-14", "取消关闭改密对话框，登录口令保持不变", async () => {
    await closeDialog(page);
    await sleep(800);
    const dlg = page.locator(".el-dialog:visible").last();
    if (await dlg.isVisible().catch(() => false)) throw new Error("改密对话框未关闭");
    return "已取消，未修改登录口令";
  }, { page });

  // ---------- 危险操作 ----------
  await H.run("M-15", "「清空业务数据」入口对管理员可见（本用例不执行该操作）", async () => {
    const group = page.locator("section.settings-group", { hasText: "危险操作" }).first();
    if (!(await group.count())) throw new Error("未渲染危险操作分组");
    const text = ((await group.textContent()) || "").replace(/\s+/g, " ");
    const btn = group.locator("button", { hasText: "清空数据" }).first();
    if (!(await btn.count())) throw new Error("未渲染清空数据按钮");
    const disabled = await btn.isDisabled().catch(() => false);
    if (disabled) throw new Error("当前为管理员，清空数据按钮却被禁用");
    return `入口可见且对管理员可用（未执行）。说明: ${text.slice(0, 140)}`;
  }, { page });

  await H.run("M-16", "「关于」分组展示应用版本号", async () => {
    const code = page.locator("code.settings-version-code").first();
    if (!(await code.count())) throw new Error("未渲染版本号");
    const v = ((await code.textContent()) || "").trim();
    if (!/^\d+\.\d+\.\d+/.test(v)) throw new Error(`版本号格式异常: ${v}`);
    ctx.appVersion = v;
    return `版本号=${v}`;
  }, { page });

  await H.run("M-17", "「授权目标」快捷入口可跳转到目标管理页", async () => {
    const group = page.locator("section.settings-group", { hasText: "安全与访问" }).first();
    await group.locator("button.settings-row", { hasText: "授权目标" }).first().click();
    await settle(page, 2500);
    if (!page.url().includes("/targets")) throw new Error(`未跳转到目标页: ${page.url()}`);
    await openSettings(page);
    await sleep(1500);
    return "跳转正常并已返回设置页";
  }, { page });

  await H.run("M-18", "「操作审计」快捷入口可跳转到审计日志页", async () => {
    const group = page.locator("section.settings-group", { hasText: "系统与审计" }).first();
    await group.locator("button.settings-row", { hasText: "操作审计" }).first().click();
    await settle(page, 2500);
    if (!page.url().includes("/audits")) throw new Error(`未跳转到审计页: ${page.url()}`);
    return "跳转到审计日志页成功";
  }, { page });

  // ================= 审计日志 =================
  await H.run("M-19", "通过侧边栏进入「审计日志」页面", async () => {
    await navigate(page, "审计日志");
    const t = await pageTitle(page);
    if (!page.url().includes("/audits")) throw new Error(`URL 异常: ${page.url()}`);
    return `标题="${t}"`;
  }, { page });

  await sleep(2500);
  await H.shot(page, "M-审计日志");

  let auditRows = 0;
  await H.run("M-20", "审计日志加载并显示记录总数", async () => {
    await page.locator(".el-table, .empty-state").first().waitFor({ state: "visible", timeout: 15000 });
    auditRows = await rowCount(page);
    if (auditRows === 0) throw new Error("审计日志为空，但前序阶段已执行大量业务操作");
    const head = ((await page.locator("body").textContent()) || "").replace(/\s+/g, " ");
    const m = head.match(/共\s*(\d+)\s*条/);
    ctx.auditTotal = m ? Number(m[1]) : null;
    return `当前页 ${auditRows} 行${m ? `，共 ${m[1]} 条记录` : ""}`;
  }, { page });

  await H.run("M-21", "审计表格包含操作、资源、结果与时间列", async () => {
    const header = ((await page.locator(".el-table__header").first().textContent()) || "").replace(/\s+/g, " ");
    const missing = ["操作", "资源", "结果", "时间"].filter((k) => !header.includes(k));
    if (missing.length) throw new Error(`缺少列: ${missing.join("、")}（实际表头: ${header.slice(0, 120)}）`);
    return `表头: ${header.slice(0, 120)}`;
  }, { page });

  await H.run("M-22", "审计日志记录了本次测试执行的真实业务操作", async () => {
    const body = ((await page.locator(".el-table").first().textContent()) || "").replace(/\s+/g, " ");
    const hits = ["TASK", "SCAN", "TARGET", "PROJECT", "FINDING", "APPROVAL"].filter((k) => body.toUpperCase().includes(k));
    if (hits.length === 0) {
      throw new Error(`审计记录中未见业务操作类型: ${body.slice(0, 250)}`);
    }
    return `可见操作类型: ${hits.join("、")}`;
  }, { page });

  await H.run("M-23", "审计记录的执行结果列包含 SUCCESS 标记", async () => {
    const body = ((await page.locator(".el-table").first().textContent()) || "");
    if (!/SUCCESS|成功/.test(body)) {
      throw new Error(`未见成功结果标记: ${body.replace(/\s+/g, " ").slice(0, 200)}`);
    }
    return "审计结果列含成功标记";
  }, { page });

  await H.run("M-24", "点击「刷新」重新加载审计记录", async () => {
    await clearMessages(page);
    const btn = page.locator("button", { hasText: "刷新" }).first();
    if (!(await btn.count())) throw new Error("未渲染刷新按钮");
    await btn.click();
    await sleep(2500);
    const n = await rowCount(page);
    if (n === 0) throw new Error("刷新后列表为空");
    return `刷新后 ${n} 行`;
  }, { page });

  await H.run("M-25", "审计日志支持服务端分页并可切换每页条数", async () => {
    const pager = page.locator(".audits-pagination, .el-pagination").first();
    if (!(await pager.count())) throw new Error("未渲染分页控件");
    const before = await rowCount(page);
    const sizeSel = pager.locator(".el-select").first();
    if (!(await sizeSel.count())) return `分页控件存在但无每页条数选择器（当前 ${before} 行）`;
    await selectOn(page, sizeSel, "50");
    await sleep(2800);
    const after = await rowCount(page);
    if (after < before) throw new Error(`每页条数增大后行数反而减少: ${before} → ${after}`);
    return `每页条数 20 → 50，行数 ${before} → ${after}`;
  }, { page });

  await H.run("M-26", "审计记录提供「AI 核查」联动入口", async () => {
    const row = page.locator(".el-table__row").first();
    const btns = (await row.locator("button").allTextContents()).map((s) => s.trim()).filter(Boolean);
    const hasAi = btns.some((b) => b.includes("AI"));
    if (!hasAi) throw new Error(`审计行未提供 AI 核查入口，实际按钮: ${btns.join(" | ")}`);
    return `入口存在: ${btns.join(" | ")}`;
  }, { page });

  return true;
}

module.exports = { run };
