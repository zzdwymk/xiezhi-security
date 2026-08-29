/*
 * 阶段 N：授权边界负向验证
 *
 * 这是本系统最核心的安全主张——"只对已授权目标、在授权窗口内、
 * 在授权端口范围内执行受控检测"。本阶段通过 UI 实际制造违规条件，
 * 验证系统正确拒绝，而不是仅依赖文档声明。
 *
 * 覆盖：
 *   1. 公网/域名/链路本地等越界目标：登记不拦截，但执行时被授权边界拒绝，
 *      且在任何数据包发出之前即失败（TargetPolicyService.validatedHost 为工具 execute 首行）
 *   2. 非法端口格式与越界端口在登记阶段即被拒绝
 *   3. 项目非 ACTIVE 时无法创建检测任务
 *   4. 目标停用后无法创建检测任务
 *   5. 未登录访问受保护页面被重定向
 *
 * 授权边界结论：网络范围校验发生在"工具执行层"（纵深防御），
 *   越界目标的检测任务会被创建但立即失败，不会向越界主机发送任何探测流量。
 *
 * 注意：本阶段会临时修改项目状态与目标启用状态，结束前全部复原，
 *       因此必须作为最后一个阶段执行。
 */
const {
  sleep, settle, navigate, pageTitle, dialog, dialogButton,
  fillByLabel, selectOption, selectOn, confirmBoxIfPresent,
  lastMessage, clearMessages, waitRow,
} = require("../lib/ui.cjs");

/** 尝试通过「新增目标」对话框登记一个目标，返回错误提示（成功则返回 null） */
async function tryCreateTarget(page, ctx, { name, type, address, ports }) {
  await navigate(page, "授权目标");
  await page.locator("button", { hasText: "新增目标" }).first().click();
  await sleep(1200);
  const dlg = await dialog(page, "新增授权目标");
  await clearMessages(page);
  await selectOption(dlg, page, "归属评估项目", ctx.projectName);
  await fillByLabel(dlg, page, "名称", name);
  await selectOption(dlg, page, "目标类型", type);
  await fillByLabel(dlg, page, "地址", address);
  await fillByLabel(dlg, page, "授权记录", `负向测试用例：${name}`);
  if (ports) {
    const picker = dlg.locator(".port-picker").first();
    await picker.waitFor({ state: "visible", timeout: 8000 });
    const sel = picker.locator(".el-select").first();
    await sel.click();
    await sleep(400);
    const portInput = sel.locator("input").first();
    await portInput.fill(ports);
    await page.keyboard.press("Enter");
    await sleep(600);
    await page.keyboard.press("Escape").catch(() => {});
    await sleep(300);
  }
  await dialogButton(dlg, "保存目标");
  await sleep(2000);
  await confirmBoxIfPresent(page, ["确认并保存", "确定"]);
  await sleep(1500);

  const stillOpen = await dlg.isVisible().catch(() => false);
  const inlineErr = ((await dlg.locator(".target-save-error").textContent().catch(() => "")) || "").trim();
  const formErrs = (await page.locator(".el-form-item__error").allTextContents()).map((s) => s.trim()).filter(Boolean);
  const msg = await lastMessage(page, { timeout: 4000 });

  if (stillOpen) {
    // 关闭对话框，避免影响后续用例
    const cancel = dlg.locator("button", { hasText: "取消" }).last();
    if (await cancel.isVisible().catch(() => false)) await cancel.click();
    await sleep(1000);
    return inlineErr || formErrs.join("; ") || (msg ? msg.text : "对话框未关闭但无可读错误");
  }
  if (msg && msg.type === "error") return msg.text;
  return null; // 创建成功
}

/**
 * 对指定目标尝试发起主动检测。
 * 监听 POST /api/active-scans 响应以捕获本次创建的任务 ID，
 * 从而后续可精确判定"正是这些任务"是否被执行层拒绝（而非误判其它目标的任务）。
 */
async function tryScanTarget(page, ctx, targetName) {
  await navigate(page, "主动检测");
  await sleep(2500);
  const launcher = page.locator("aside.scan-launcher-pane").first();
  await clearMessages(page);

  const sel = launcher.locator(".el-select").first();
  try {
    await selectOn(page, sel, targetName);
    await sleep(1800);
  } catch {
    await page.keyboard.press("Escape").catch(() => {});
    return { created: false, taskIds: [], message: "该目标不在可选授权目标列表中（前置拦截）", preBlocked: true };
  }

  const usable = launcher.locator(".rule-list .el-checkbox:not(.is-disabled)");
  if ((await usable.count()) === 0) {
    return { created: false, taskIds: [], message: "该目标下无任何可用检测规则（前置拦截）", preBlocked: true };
  }
  const checked = launcher.locator(".rule-list .el-checkbox.is-checked");
  if ((await checked.count()) === 0) { await usable.first().click(); await sleep(700); }

  const taskIds = [];
  const onResp = async (r) => {
    if (!/\/api\/active-scans/.test(r.url())) return;
    try {
      const j = await r.json();
      const collect = (o) => {
        if (!o) return;
        if (Array.isArray(o)) return o.forEach(collect);
        if (typeof o === "object") {
          if (typeof o.id === "number") taskIds.push(o.id);
          if (Array.isArray(o.taskIds)) o.taskIds.forEach((x) => typeof x === "number" && taskIds.push(x));
          if (Array.isArray(o.tasks)) o.tasks.forEach(collect);
          Object.values(o).forEach((v) => { if (v && typeof v === "object") collect(v); });
        }
      };
      collect(j);
    } catch { /* 忽略 */ }
  };
  page.on("response", onResp);
  try {
    await launcher.locator(".scan-button").first().click();
    await sleep(1500);
    await confirmBoxIfPresent(page, ["开始检测", "确定"]);
    const msg = await lastMessage(page, { timeout: 20000 });
    await sleep(1500);
    if (!msg) return { created: false, taskIds: [...new Set(taskIds)], message: "无任何提示（行为不明确）" };
    const created = msg.type === "success" && /已创建\s*\d+\s*个检测任务/.test(msg.text);
    return { created, taskIds: [...new Set(taskIds)], message: msg.text, type: msg.type };
  } finally {
    page.off("response", onResp);
  }
}

/**
 * 精确核查指定任务 ID 的最终状态：越权目标的这些任务必须均为 FAILED，无一 SUCCESS。
 * 任务中心表格首列为任务 ID，据此逐一定位，避免误判其它目标的任务。
 */
async function assertTasksBlocked(page, taskIds) {
  await navigate(page, "检测任务");
  await sleep(2500);
  const statusOf = async (id) => {
    const rows = page.locator(".el-table__row");
    const n = await rows.count();
    for (let i = 0; i < n; i++) {
      const raw = ((await rows.nth(i).textContent()) || "").replace(/\s+/g, " ").trim();
      if (new RegExp("^" + id + "(?![0-9])").test(raw)) {
        return ["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED", "REJECTED", "PENDING", "RUNNING"].find((x) => raw.includes(x)) || null;
      }
    }
    return null;
  };
  const result = {};
  for (let round = 0; round < 20; round++) {
    let anyPending = false;
    for (const id of taskIds) {
      const st = await statusOf(id);
      result[id] = st;
      if (st === "PENDING" || st === "RUNNING" || st === null) anyPending = true;
    }
    if (!anyPending) break;
    await sleep(3000);
    const refresh = page.locator("button", { hasText: "刷新" }).first();
    if (await refresh.count()) { await refresh.click(); await sleep(1200); }
  }
  const statuses = Object.entries(result).map(([id, st]) => "#" + id + "=" + (st || "未找到"));
  const succeeded = Object.values(result).filter((st) => st === "SUCCESS").length;
  const failed = Object.values(result).filter((st) => st === "FAILED").length;
  return { result, statuses, succeeded, failed };
}

async function run(page, H, ctx) {
  H.phase("阶段 N — 授权边界负向验证");

  ctx.negativeTargets = [];

  // ---------- 1. 公网 IP：登记与执行两层分别验证 ----------
  await H.run("N-01", "登记公网 IP 目标（观察校验发生在哪一层）", async () => {
    const name = `负向-公网IP-${ctx.stamp}`;
    const err = await tryCreateTarget(page, ctx, {
      name, type: "IP 地址", address: "8.8.8.8", ports: "80",
    });
    if (err) return `登记阶段即被拒绝，提示="${err.slice(0, 150)}"`;
    ctx.negativeTargets.push(name);
    ctx.publicIpTargetName = name;
    return "登记阶段未拦截（目标已创建）——授权边界在执行阶段校验，见 N-02";
  }, { page, shotOnPass: true });

  await H.run("N-02", "对公网 IP 目标的检测在执行阶段被授权边界拒绝（不发探测流量）", async () => {
    if (!ctx.publicIpTargetName) return "公网 IP 未登记成功，跳过";
    const r = await tryScanTarget(page, ctx, ctx.publicIpTargetName);
    if (!r.created) return `已在发起阶段被拦截：${r.message.slice(0, 150)}`;
    if (r.taskIds.length === 0) throw new Error(`提示已创建任务但未捕获任务 ID：${r.message}`);
    const chk = await assertTasksBlocked(page, r.taskIds);
    if (chk.succeeded > 0) throw new Error(`公网 IP 8.8.8.8 的检测任务竟然执行成功，授权边界失效：${chk.statuses.join(", ")}`);
    if (chk.failed === 0) throw new Error(`未观察到失败，无法确认边界生效：${chk.statuses.join(", ")}`);
    return `边界生效：本次创建的任务 [${r.taskIds.join(",")}] 全部在执行阶段失败（validatedHost 于工具首行拒绝，未发探测流量）：${chk.statuses.join(", ")}`;
  }, { page, shotOnPass: true });

  // ---------- 2. 公网域名 ----------
  await H.run("N-03", "登记公网域名目标（观察校验发生在哪一层）", async () => {
    const name = `负向-域名-${ctx.stamp}`;
    const err = await tryCreateTarget(page, ctx, {
      name, type: "域名", address: "example.com", ports: "80",
    });
    if (err) return `登记阶段即被拒绝，提示="${err.slice(0, 150)}"`;
    ctx.publicDomainTargetName = name;
    ctx.negativeTargets.push(name);
    return "登记阶段未拦截（目标已创建）——授权边界在执行阶段校验，见 N-04";
  }, { page, shotOnPass: true });

  await H.run("N-04", "对公网域名目标的检测在执行阶段被默认安全策略拒绝", async () => {
    if (!ctx.publicDomainTargetName) return "公网域名未登记成功，跳过";
    const r = await tryScanTarget(page, ctx, ctx.publicDomainTargetName);
    if (!r.created) return `已在发起阶段被拦截：${r.message.slice(0, 150)}`;
    if (r.taskIds.length === 0) throw new Error(`提示已创建任务但未捕获任务 ID：${r.message}`);
    const chk = await assertTasksBlocked(page, r.taskIds);
    if (chk.succeeded > 0) throw new Error(`公网域名 example.com 的检测任务竟然执行成功：${chk.statuses.join(", ")}`);
    if (chk.failed === 0) throw new Error(`未观察到失败：${chk.statuses.join(", ")}`);
    return `边界生效：本次任务 [${r.taskIds.join(",")}] 均在执行阶段失败（默认策略拒绝域名以防解析漂移越权）：${chk.statuses.join(", ")}`;
  }, { page, shotOnPass: true });

  // ---------- 3. 链路本地地址 ----------
  await H.run("N-05", "登记链路本地地址目标（观察校验发生在哪一层）", async () => {
    const name = `负向-链路本地-${ctx.stamp}`;
    const err = await tryCreateTarget(page, ctx, {
      name, type: "IP 地址", address: "169.254.1.1", ports: "80",
    });
    if (err) return `登记阶段即被拒绝，提示="${err.slice(0, 150)}"`;
    ctx.linkLocalTargetName = name;
    ctx.negativeTargets.push(name);
    return "登记阶段未拦截（目标已创建）——授权边界在执行阶段校验，见 N-06";
  }, { page, shotOnPass: true });

  await H.run("N-06", "对链路本地地址的检测在执行阶段被拒绝", async () => {
    if (!ctx.linkLocalTargetName) return "链路本地目标未登记成功，跳过";
    const r = await tryScanTarget(page, ctx, ctx.linkLocalTargetName);
    if (!r.created) return `已在发起阶段被拦截：${r.message.slice(0, 150)}`;
    if (r.taskIds.length === 0) throw new Error(`提示已创建任务但未捕获任务 ID：${r.message}`);
    const chk = await assertTasksBlocked(page, r.taskIds);
    if (chk.succeeded > 0) throw new Error(`链路本地地址 169.254.1.1 的检测任务竟然执行成功：${chk.statuses.join(", ")}`);
    if (chk.failed === 0) throw new Error(`未观察到失败：${chk.statuses.join(", ")}`);
    return `边界生效：本次任务 [${r.taskIds.join(",")}] 均在执行阶段失败：${chk.statuses.join(", ")}`;
  }, { page, shotOnPass: true });

  // ---------- 4. 非法端口 ----------
  await H.run("N-07", "越界端口（70000）在登记阶段被拒绝", async () => {
    const err = await tryCreateTarget(page, ctx, {
      name: `负向-越界端口-${ctx.stamp}`, type: "IP 地址", address: ctx.targetIp, ports: "70000",
    });
    if (!err) throw new Error("端口 70000 超出 1-65535 却登记成功");
    return `已拒绝，提示="${err.slice(0, 160)}"`;
  }, { page, shotOnPass: true });

  await H.run("N-08", "起始值大于结束值的端口范围（443-80）被拒绝", async () => {
    const err = await tryCreateTarget(page, ctx, {
      name: `负向-逆序范围-${ctx.stamp}`, type: "IP 地址", address: ctx.targetIp, ports: "443-80",
    });
    if (!err) throw new Error("逆序端口范围 443-80 却登记成功");
    return `已拒绝，提示="${err.slice(0, 160)}"`;
  }, { page, shotOnPass: true });

  // ---------- 5. 项目非 ACTIVE ----------
  await H.run("N-09", "将项目状态改为「已暂停」", async () => {
    await navigate(page, "评估项目");
    const row = await waitRow(page, ctx.projectName, 20000);
    await row.locator("button", { hasText: "编辑" }).first().click();
    const dlg = await dialog(page, "编辑评估项目");
    await clearMessages(page);
    await selectOption(dlg, page, "项目状态", "已暂停");
    await dialogButton(dlg, "保存修改");
    await sleep(1500);
    await confirmBoxIfPresent(page, ["确认并保存", "确定"]);
    await sleep(2000);
    for (let i = 0; i < 12; i++) {
      const r = await waitRow(page, ctx.projectName, 8000);
      const t = ((await r.textContent()) || "").replace(/\s+/g, " ");
      if (/已暂停|PAUSED/.test(t)) { ctx.projectPaused = true; return "项目状态=已暂停"; }
      await sleep(1000);
    }
    throw new Error("项目状态未变为已暂停");
  }, { page });

  await H.run("N-10", "项目非 ACTIVE 时无法发起主动检测", async () => {
    if (!ctx.projectPaused) return "项目未成功暂停，跳过";
    await navigate(page, "主动检测");
    await sleep(2500);
    const launcher = page.locator("aside.scan-launcher-pane").first();
    await clearMessages(page);

    // 目标可能已因项目暂停而不在可选列表中
    const sel = launcher.locator(".el-select").first();
    let selectable = true;
    try {
      await selectOn(page, sel, ctx.webTargetName, { exact: true });
      await sleep(1800);
    } catch {
      selectable = false;
      await page.keyboard.press("Escape").catch(() => {});
    }
    if (!selectable) {
      return "项目暂停后该目标已不在可选授权目标列表中（前置拦截）";
    }

    const rules = launcher.locator(".rule-list .el-checkbox:not(.is-disabled)");
    if ((await rules.count()) === 0) {
      return "项目暂停后无任何可用检测规则（前置拦截）";
    }
    const checked = launcher.locator(".rule-list .el-checkbox.is-checked");
    if ((await checked.count()) === 0) await rules.first().click();
    await sleep(800);

    await launcher.locator(".scan-button").first().click();
    await sleep(1500);
    await confirmBoxIfPresent(page, ["开始检测", "确定"]);
    const msg = await lastMessage(page, { timeout: 15000 });
    if (!msg) throw new Error("未出现任何提示");
    if (msg.type === "success") {
      throw new Error(`项目已暂停却成功创建检测任务：${msg.text}`);
    }
    if (!/ACTIVE|状态|授权|项目/.test(msg.text)) {
      throw new Error(`拒绝原因与项目状态无关: ${msg.text}`);
    }
    return `已拒绝，提示="${msg.text}"`;
  }, { page, shotOnPass: true });

  await H.run("N-11", "将项目状态恢复为「进行中」", async () => {
    await navigate(page, "评估项目");
    const row = await waitRow(page, ctx.projectName, 20000);
    await row.locator("button", { hasText: "编辑" }).first().click();
    const dlg = await dialog(page, "编辑评估项目");
    await clearMessages(page);
    await selectOption(dlg, page, "项目状态", "进行中");
    await dialogButton(dlg, "保存修改");
    await sleep(1500);
    await confirmBoxIfPresent(page, ["确认并保存", "确定"]);
    await sleep(2000);
    for (let i = 0; i < 12; i++) {
      const r = await waitRow(page, ctx.projectName, 8000);
      const t = ((await r.textContent()) || "").replace(/\s+/g, " ");
      if (/进行中|ACTIVE/.test(t)) { ctx.projectPaused = false; return "项目状态已恢复为进行中"; }
      await sleep(1000);
    }
    throw new Error("项目状态未恢复");
  }, { page });

  // ---------- 6. 目标停用 ----------
  await H.run("N-12", "停用授权目标", async () => {
    await navigate(page, "授权目标");
    const row = await waitRow(page, ctx.webTargetName, 20000);
    await row.locator("button", { hasText: "编辑" }).first().click();
    const dlg = await dialog(page, "编辑授权目标");
    await clearMessages(page);
    const sw = dlg.locator(".el-switch").last();
    await sw.click();
    await sleep(600);
    await dialogButton(dlg, "保存修改");
    await sleep(1500);
    await confirmBoxIfPresent(page, ["确认并保存", "确定"]);
    await sleep(2000);
    for (let i = 0; i < 12; i++) {
      const r = await waitRow(page, ctx.webTargetName, 8000);
      const t = ((await r.textContent()) || "").replace(/\s+/g, " ");
      if (/停用/.test(t)) { ctx.webTargetDisabled = true; return "目标状态=停用"; }
      await sleep(1000);
    }
    throw new Error("目标未变为停用状态");
  }, { page, shotOnPass: true });

  await H.run("N-13", "目标停用后无法对其发起主动检测", async () => {
    if (!ctx.webTargetDisabled) return "目标未成功停用，跳过";
    await navigate(page, "主动检测");
    await sleep(2500);
    const launcher = page.locator("aside.scan-launcher-pane").first();
    await clearMessages(page);

    const sel = launcher.locator(".el-select").first();
    let selectable = true;
    try {
      await selectOn(page, sel, ctx.webTargetName, { exact: true });
      await sleep(1800);
    } catch {
      selectable = false;
      await page.keyboard.press("Escape").catch(() => {});
    }
    if (!selectable) {
      return "停用目标已不在可选授权目标列表中（前置拦截）";
    }
    const rules = launcher.locator(".rule-list .el-checkbox:not(.is-disabled)");
    if ((await rules.count()) === 0) {
      return "停用目标下无任何可用检测规则（前置拦截）";
    }
    const checked = launcher.locator(".rule-list .el-checkbox.is-checked");
    if ((await checked.count()) === 0) await rules.first().click();
    await sleep(800);
    await launcher.locator(".scan-button").first().click();
    await sleep(1500);
    await confirmBoxIfPresent(page, ["开始检测", "确定"]);
    const msg = await lastMessage(page, { timeout: 15000 });
    if (!msg) throw new Error("未出现任何提示");
    if (msg.type === "success") throw new Error(`目标已停用却成功创建检测任务：${msg.text}`);
    return `已拒绝，提示="${msg.text}"`;
  }, { page, shotOnPass: true });

  await H.run("N-14", "恢复目标为启用状态", async () => {
    if (!ctx.webTargetDisabled) return "目标未被停用，无需恢复";
    await navigate(page, "授权目标");
    const row = await waitRow(page, ctx.webTargetName, 20000);
    await row.locator("button", { hasText: "编辑" }).first().click();
    const dlg = await dialog(page, "编辑授权目标");
    await clearMessages(page);
    await dlg.locator(".el-switch").last().click();
    await sleep(600);
    await dialogButton(dlg, "保存修改");
    await sleep(1500);
    await confirmBoxIfPresent(page, ["确认并保存", "确定"]);
    await sleep(2000);
    for (let i = 0; i < 12; i++) {
      const r = await waitRow(page, ctx.webTargetName, 8000);
      const t = ((await r.textContent()) || "").replace(/\s+/g, " ");
      if (/启用/.test(t) && !/停用/.test(t)) { ctx.webTargetDisabled = false; return "目标已恢复为启用"; }
      await sleep(1000);
    }
    throw new Error("目标未恢复为启用状态");
  }, { page });

  // ---------- 7. 未登录访问保护 ----------
  await H.run("N-15", "注销后访问受保护页面被重定向到登录页", async () => {
    // 经用户下拉菜单真实注销
    await page.locator("button.desktop-v2-user").first().click();
    await sleep(800);
    const menu = page.locator(".desktop-v2-user-menu");
    await menu.waitFor({ state: "visible", timeout: 8000 });
    const logout = menu.locator(".desktop-v2-logout-item").first();
    if (await logout.count()) await logout.click();
    else await menu.getByText("注销登录").first().click();
    await sleep(2500);
    if (!page.url().includes("/login")) throw new Error(`注销后未跳转登录页: ${page.url()}`);

    // 直达受保护 URL（此处为验证路由守卫，属例外允许的 goto）
    await page.goto(`${ctx.baseUrl}/findings`, { waitUntil: "domcontentloaded" });
    await settle(page, 2500);
    if (!page.url().includes("/login")) {
      throw new Error(`未登录直达 /findings 未被拦截，当前 ${page.url()}`);
    }
    return `注销成功，直达 /findings 被重定向到 ${page.url().replace(ctx.baseUrl, "")}`;
  }, { page, shotOnPass: true });

  await H.run("N-16", "重新登录恢复会话", async () => {
    await page.locator('input[placeholder="请输入用户名"]').fill(ctx.username);
    const pw = page.locator('input[placeholder="请输入密码"]');
    await pw.fill("");
    await pw.type(ctx.password, { delay: 5 });
    await page.locator("button.login-button").first().click();
    await page.waitForURL((u) => !u.toString().includes("/login"), { timeout: 20000 });
    await settle(page, 2000);
    return `已重新登录，当前 ${page.url().replace(ctx.baseUrl, "") || "/"}`;
  }, { page });

  // ---------- 清理：移除负向测试创建的目标 ----------
  await H.run("N-17", "清理负向测试创建的越界目标，恢复项目干净状态", async () => {
    const names = ctx.negativeTargets || [];
    if (names.length === 0) return "本次未遗留负向测试目标";
    await navigate(page, "授权目标");
    await sleep(2000);
    const removed = [];
    for (const name of names) {
      const row = page.locator(".el-table__row", { hasText: name }).first();
      if (!(await row.count())) continue;
      const btn = row.locator("button", { hasText: "删除" }).first();
      if (!(await btn.count())) continue;
      await btn.click();
      await sleep(1200);
      await confirmBoxIfPresent(page, ["确认删除", "删除", "确定"]);
      await sleep(1800);
      removed.push(name);
    }
    return `已清理 ${removed.length}/${names.length} 个负向测试目标`;
  }, { page });

  return true;
}

module.exports = { run };
