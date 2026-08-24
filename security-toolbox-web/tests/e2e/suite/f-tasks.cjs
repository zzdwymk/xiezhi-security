/*
 * 阶段 F：任务控制中心
 *
 * 业务顺序：进入任务中心 → 校验配额概览 → 确认前序阶段创建的任务执行完成
 *          → 查看任务详情（授权快照、工具版本、实时日志）
 *          → 下载任务报告 → 定时任务管理
 *
 * 本阶段验证真实执行结果：任务针对靶机 192.168.136.131 实际发包。
 *
 * 注意：任务列表的「目标」列显示的是目标 ID（非 IP），状态列为英文枚举
 *       （PENDING/RUNNING/SUCCESS/FAILED/TIMEOUT/CANCELLED/REJECTED/SKIPPED），
 *       因此按「创建时间在本次运行窗口内」识别本次任务，并在详情中核对目标快照。
 */
const {
  sleep, navigate, pageTitle, dialog, dialogButton, selectOption,
  lastMessage, clearMessages, rowCount, confirmBoxIfPresent,
  clearDownloadRecords, waitDownloadRecord,
} = require("../lib/ui.cjs");

const TERMINAL = ["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED", "REJECTED", "SKIPPED"];

/** 解析任务表格行：ID、工具、状态、进度、创建时间 */
async function readTasks(page) {
  const rows = page.locator(".el-table__row");
  const n = await rows.count();
  const out = [];
  for (let i = 0; i < n; i++) {
    const raw = ((await rows.nth(i).textContent()) || "").replace(/\s+/g, " ").trim();
    const tool = (raw.match(/(tcp_ports|http_headers|http_security_check|tls_config|nmap_service_scan|nuclei_scan|afrog_scan|xray_scan)/) || [])[1] || null;
    const status = TERMINAL.concat(["PENDING", "RUNNING", "BLOCKED"]).find((s) => raw.includes(s)) || null;
    const time = (raw.match(/(20\d\d-\d\d-\d\d \d\d:\d\d:\d\d)/) || [])[1] || null;
    const progress = (raw.match(/(\d+)\s*%/) || [])[1] || null;
    // 行文本形如 "<任务ID><工具代码><目标ID><状态>..."，据此解析任务与目标 ID
    const taskId = (raw.match(/^(\d+)/) || [])[1] || null;
    let targetId = null;
    if (tool && status) {
      const m = raw.match(new RegExp(tool + "(\d+)" + status));
      if (m) targetId = m[1];
    }
    out.push({ i, raw, tool, status, time, taskId, targetId, progress: progress ? Number(progress) : null });
  }
  return out;
}

/** 本次运行窗口内创建的任务 */
function ownTasks(tasks, sinceMs) {
  return tasks.filter((t) => {
    if (!t.time) return false;
    const ts = new Date(t.time.replace(" ", "T")).getTime();
    return ts >= sinceMs;
  });
}

async function clickRefresh(page) {
  const btn = page.locator("button", { hasText: "刷新" }).first();
  if (await btn.isVisible().catch(() => false)) { await btn.click(); await sleep(1200); }
}

/** 关闭任何遗留的 ElMessageBox 遮罩，避免遮挡后续点击 */
async function dismissAnyBox(page) {
  for (let i = 0; i < 4; i++) {
    const box = page.locator(".el-message-box").last();
    if (!(await box.isVisible().catch(() => false))) return;
    const btn = box.locator("button").last();
    await btn.click().catch(() => {});
    await sleep(700);
  }
}

/** 确保定时任务对话框处于打开状态（创建成功后对话框会自动关闭） */
async function ensureScheduleDialog(page) {
  await dismissAnyBox(page);
  const existing = page.locator(".el-dialog:visible", { hasText: "定时任务管理" }).last();
  if (await existing.isVisible().catch(() => false)) return existing;
  await page.locator("button.schedule-trigger").first().click();
  await sleep(1500);
  return await dialog(page, "定时任务管理");
}

async function run(page, H, ctx) {
  H.phase("阶段 F — 任务控制中心");

  // 本次任务的时间下界：留 20 分钟余量
  const since = Date.now() - 20 * 60 * 1000;

  await H.run("F-01", "通过侧边栏进入「检测任务」页面", async () => {
    await navigate(page, "检测任务");
    const t = await pageTitle(page);
    if (!page.url().includes("/tasks")) throw new Error(`URL 异常: ${page.url()}`);
    return `标题="${t}"`;
  }, { page });

  await sleep(2500);
  await H.shot(page, "F-任务中心");

  await H.run("F-02", "任务中心展示并发配额概览", async () => {
    const sum = page.locator(".task-control-summary").first();
    if (!(await sum.count())) throw new Error("未渲染任务资源配额区");
    const t = ((await sum.textContent()) || "").replace(/\s+/g, " ").trim();
    for (const k of ["当前运行", "等待队列"]) {
      if (!t.includes(k)) throw new Error(`配额概览缺少「${k}」: ${t.slice(0, 150)}`);
    }
    return `配额概览: ${t.slice(0, 130)}`;
  }, { page });

  await H.run("F-03", "任务列表加载并包含本次创建的检测任务", async () => {
    await page.locator(".el-table").first().waitFor({ state: "visible", timeout: 15000 });
    const n = await rowCount(page);
    if (n === 0) throw new Error("任务列表为空");
    const mine = ownTasks(await readTasks(page), since);
    if (mine.length === 0) throw new Error(`未找到本次运行窗口内创建的任务（列表共 ${n} 行）`);
    ctx.taskRowsTotal = n;
    return `列表共 ${n} 行，本次创建 ${mine.length} 个（工具: ${[...new Set(mine.map((t) => t.tool))].join("、")}）`;
  }, { page });

  // ---------- 等待任务执行完成 ----------
  await H.run("F-04", "本次创建的检测任务全部执行至终态", async () => {
    const expected = (ctx.ipScanTaskCount || 0) + (ctx.webScanTaskCount || 0);
    let last = "";
    for (let round = 0; round < 60; round++) {
      const mine = ownTasks(await readTasks(page), since);
      const done = mine.filter((t) => TERMINAL.includes(t.status));
      last = `本次任务 ${mine.length} 个，终态 ${done.length} 个`;
      if (mine.length >= expected && done.length === mine.length) {
        ctx.ownTasks = done;
        ctx.taskPairs = done
          .filter((t) => t.taskId && t.targetId && t.status === "SUCCESS")
          .map((t) => ({ taskId: t.taskId, targetId: t.targetId, tool: t.tool }));
        const byStatus = {};
        for (const d of done) byStatus[d.status] = (byStatus[d.status] || 0) + 1;
        return `${last}（期望 ${expected} 个）状态分布: ${JSON.stringify(byStatus)}`;
      }
      await sleep(3000);
      await clickRefresh(page);
    }
    throw new Error(`180 秒内任务未全部到达终态：${last}`);
  }, { page });

  await H.shot(page, "F-任务已完成");

  await H.run("F-05", "端口探测任务（tcp_ports）执行成功", async () => {
    const mine = ownTasks(await readTasks(page), since);
    const tcp = mine.filter((t) => t.tool === "tcp_ports");
    if (tcp.length === 0) throw new Error("未找到 tcp_ports 任务");
    const ok = tcp.filter((t) => t.status === "SUCCESS");
    if (ok.length === 0) throw new Error(`tcp_ports 任务未成功: ${tcp.map((t) => t.status).join(",")}`);
    return `${ok.length}/${tcp.length} 个端口探测任务 SUCCESS`;
  }, { page });

  await H.run("F-06", "HTTP 安全检查任务执行成功", async () => {
    const mine = ownTasks(await readTasks(page), since);
    const http = mine.filter((t) => t.tool === "http_headers" || t.tool === "http_security_check");
    if (http.length === 0) throw new Error("未找到 HTTP 检查任务");
    const ok = http.filter((t) => t.status === "SUCCESS");
    if (ok.length !== http.length) {
      throw new Error(`部分 HTTP 任务未成功: ${http.map((t) => `${t.tool}=${t.status}`).join(", ")}`);
    }
    return `${ok.length}/${http.length} 个 HTTP 检查任务 SUCCESS`;
  }, { page });

  await H.run("F-07", "成功任务进度显示为 100%", async () => {
    const mine = ownTasks(await readTasks(page), since).filter((t) => t.status === "SUCCESS");
    if (mine.length === 0) throw new Error("无成功任务");
    const notFull = mine.filter((t) => t.progress !== 100);
    if (notFull.length) throw new Error(`${notFull.length} 个成功任务进度不是 100%`);
    return `${mine.length} 个成功任务进度均为 100%`;
  }, { page });

  // ---------- 任务详情 ----------
  let ownRowIndex = 0;
  await H.run("F-08", "点击「详情」打开任务详情对话框", async () => {
    const mine = ownTasks(await readTasks(page), since).filter((t) => t.status === "SUCCESS");
    if (mine.length === 0) throw new Error("无成功任务可查看");
    ownRowIndex = mine[0].i;
    await page.locator(".el-table__row").nth(ownRowIndex)
      .locator("button", { hasText: "详情" }).first().click();
    const dlg = await dialog(page, "任务详情");
    if (!(await dlg.isVisible())) throw new Error("详情对话框未显示");
    return `已打开第 ${ownRowIndex + 1} 行任务详情`;
  }, { page });

  await H.shot(page, "F-任务详情");

  await H.run("F-09", "任务详情的授权快照中包含本次靶机地址", async () => {
    const dlg = await dialog(page, "任务详情");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const missing = ["授权目标快照", "允许端口快照", "授权声明"].filter((k) => !text.includes(k));
    if (missing.length) throw new Error(`详情缺少字段: ${missing.join("、")}`);
    if (!text.includes(ctx.targetIp)) {
      throw new Error(`快照未包含靶机地址 ${ctx.targetIp}`);
    }
    return `快照含靶机 ${ctx.targetIp}，授权字段完整`;
  }, { page });

  await H.run("F-10", "任务详情展示工具版本与规则版本指纹", async () => {
    const dlg = await dialog(page, "任务详情");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const has = ["工具版本", "规则版本"].filter((k) => text.includes(k));
    if (has.length === 0) throw new Error("详情未展示工具版本或规则版本");
    return `已展示: ${has.join("、")}`;
  }, { page });

  await H.run("F-11", "任务详情展示执行结果与实时执行日志", async () => {
    const dlg = await dialog(page, "任务详情");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    if (!/执行日志|执行结果/.test(text)) throw new Error("详情未展示执行日志或结果");
    const pres = dlg.locator("pre");
    let sample = "";
    for (let i = 0; i < (await pres.count()); i++) {
      const t = ((await pres.nth(i).textContent()) || "").trim();
      if (t.length > sample.length) sample = t;
    }
    ctx.taskLogSample = sample.slice(0, 400);
    if (!sample) throw new Error("执行日志/结果区域为空");
    return `输出片段: ${sample.replace(/\s+/g, " ").slice(0, 150)}`;
  }, { page });

  await H.run("F-12", "任务详情中的执行结果包含针对靶机的真实探测输出", async () => {
    const sample = ctx.taskLogSample || "";
    if (!sample) throw new Error("无执行输出可校验");
    if (!(sample.includes(ctx.targetIp) || /port|端口|header|Header|http|HTTP/.test(sample))) {
      throw new Error(`执行输出与探测内容无关: ${sample.slice(0, 200)}`);
    }
    return `输出与靶机探测相关，长度 ${sample.length} 字符`;
  }, { page });

  await H.run("F-13", "关闭任务详情对话框", async () => {
    const dlg = await dialog(page, "任务详情");
    await dialogButton(dlg, "关闭");
    await sleep(1200);
    if (await dlg.isVisible().catch(() => false)) throw new Error("对话框未关闭");
    return "已关闭";
  }, { page });

  // ---------- 报告 ----------
  await H.run("F-14", "成功任务可获取 HTML 检测报告", async () => {
    await clearMessages(page);
    await clearDownloadRecords(page);
    const row = page.locator(".el-table__row").nth(ownRowIndex);
    const btn = row.locator("button", { hasText: "报告" }).first();
    if (!(await btn.count())) throw new Error("未找到报告按钮");
    if (await btn.isDisabled()) throw new Error("成功任务的报告按钮不可用");
    await btn.click();

    // 报告响应带 Content-Disposition，会被浏览器下载管理器拦截，
    // 故以应用实际收到的 XHR 响应为准，而非 download 事件
    const rec = await waitDownloadRecord(page, /\/reports\/tasks\/\d+/, 40000);
    if (!rec) {
      const msg = await lastMessage(page, { timeout: 5000 });
      throw new Error(`未观察到报告响应${msg ? `，提示="${msg.text}"` : ""}`);
    }
    if (rec.status !== 200) throw new Error(`报告接口返回 ${rec.status}`);
    if (rec.size < 200) throw new Error(`报告体积异常，仅 ${rec.size} 字节`);
    ctx.taskReportRecord = rec;
    return `HTTP ${rec.status}，${rec.contentType}，${rec.size} 字节`;
  }, { page });

  await H.run("F-15", "非成功状态任务的报告按钮被禁用", async () => {
    const tasks = await readTasks(page);
    const bad = tasks.filter((t) => t.status && t.status !== "SUCCESS");
    if (bad.length === 0) return "当前列表无非成功任务，跳过断言";
    for (const t of bad) {
      const btn = page.locator(".el-table__row").nth(t.i).locator("button", { hasText: "报告" }).first();
      if (!(await btn.count())) continue;
      if (!(await btn.isDisabled())) {
        throw new Error(`${t.status} 状态任务的报告按钮仍可用: ${t.raw.slice(0, 120)}`);
      }
      return `${t.status} 状态任务的报告按钮已正确禁用`;
    }
    return "未渲染报告按钮，跳过";
  }, { page });

  await H.run("F-16", "已完成任务不再提供取消操作", async () => {
    const row = page.locator(".el-table__row").nth(ownRowIndex);
    const cancel = row.locator("button", { hasText: "取消" });
    if ((await cancel.count()) === 0) return "成功任务未渲染取消按钮";
    if (!(await cancel.first().isDisabled())) throw new Error("成功任务的取消按钮仍可点击");
    return "成功任务的取消按钮已禁用";
  }, { page });

  await H.run("F-17", "任务行提供「AI 分析」联动入口", async () => {
    const row = page.locator(".el-table__row").nth(ownRowIndex);
    const ai = row.locator("button", { hasText: "AI 分析" });
    if ((await ai.count()) === 0) throw new Error("未渲染 AI 分析入口");
    return "AI 分析入口存在";
  }, { page });

  // ---------- 定时任务 ----------
  await H.run("F-18", "点击「定时任务」打开定时扫描管理对话框", async () => {
    await page.locator("button.schedule-trigger").first().click();
    const dlg = await dialog(page, "定时任务管理");
    if (!(await dlg.isVisible())) throw new Error("定时任务对话框未显示");
    return "定时任务对话框已打开";
  }, { page });

  await H.shot(page, "F-定时任务对话框");

  await H.run("F-19", "定时任务对话框提供项目、目标、工具与执行方式选择", async () => {
    const dlg = await dialog(page, "定时任务管理");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const missing = ["安全评估项目", "项目授权目标", "检测工具", "执行方式"].filter((k) => !text.includes(k));
    if (missing.length) throw new Error(`缺少控件: ${missing.join("、")}`);
    return "四类必需控件均已渲染";
  }, { page });

  await H.run("F-20", "创建每天定时执行的 TCP 端口探测计划", async () => {
    const dlg = await dialog(page, "定时任务管理");
    await clearMessages(page);
    await selectOption(dlg, page, "安全评估项目", ctx.projectName);
    await sleep(1200);
    await selectOption(dlg, page, "项目授权目标", ctx.targetName);
    await sleep(900);
    await selectOption(dlg, page, "检测工具", "TCP 端口探测");
    await sleep(900);

    const daily = dlg.locator(".schedule-mode-picker").locator("label, .el-radio", { hasText: "每天" }).first();
    if (await daily.count()) { await daily.click(); await sleep(600); }

    await dialogButton(dlg, "创建");
    await sleep(2500);
    const msg = await lastMessage(page, { timeout: 12000 });
    if (!msg) throw new Error("创建后无任何提示");
    if (msg.type === "error") throw new Error(`创建定时任务失败: ${msg.text}`);
    ctx.scheduleCreated = true;
    return `提示="${msg.text}"`;
  }, { page, shotOnPass: true });

  await H.run("F-21", "已创建的定时任务出现在计划列表中", async () => {
    if (!ctx.scheduleCreated) return "未成功创建定时任务，跳过";
    const dlg = await ensureScheduleDialog(page);
    const table = dlg.locator(".schedule-table").first();
    await table.waitFor({ state: "visible", timeout: 10000 });
    const rows = await table.locator(".el-table__row").count();
    if (rows === 0) throw new Error("计划列表为空");
    const text = ((await table.textContent()) || "").replace(/\s+/g, " ");
    if (!/tcp_ports|TCP/.test(text)) throw new Error(`计划列表未包含 TCP 工具: ${text.slice(0, 200)}`);
    ctx.scheduleRows = rows;
    return `计划列表 ${rows} 条，含 TCP 端口探测计划`;
  }, { page });

  await H.run("F-22", "可停用已创建的定时任务", async () => {
    if (!ctx.scheduleCreated) return "未成功创建定时任务，跳过";
    const dlg = await ensureScheduleDialog(page);
    const row = dlg.locator(".schedule-table .el-table__row").first();
    const btn = row.locator("button", { hasText: "停用" }).first();
    if (!(await btn.count())) return "该计划当前无停用按钮（可能已停用）";
    await clearMessages(page);
    await btn.click();
    await sleep(1500);
    await confirmBoxIfPresent(page, ["确定", "停用", "确认"]);
    const msg = await lastMessage(page, { timeout: 10000 });
    const text = ((await row.textContent()) || "").replace(/\s+/g, " ");
    if (!/已停用/.test(text) && (!msg || msg.type === "error")) {
      throw new Error(`停用失败: ${msg ? msg.text : text.slice(0, 120)}`);
    }
    return msg ? `提示="${msg.text}"` : "状态已变为已停用";
  }, { page });

  await H.run("F-23", "可删除定时任务", async () => {
    if (!ctx.scheduleCreated) return "未成功创建定时任务，跳过";
    const dlg = await ensureScheduleDialog(page);
    const row = dlg.locator(".schedule-table .el-table__row").first();
    const btn = row.locator("button", { hasText: "删除" }).first();
    if (!(await btn.count())) throw new Error("未找到删除按钮");
    await clearMessages(page);
    await btn.scrollIntoViewIfNeeded().catch(() => {});
    await btn.click({ timeout: 12000 });
    await sleep(1200);
    const clicked = await confirmBoxIfPresent(page, ["删除", "确定", "确认"]);
    if (!clicked) throw new Error("删除操作未弹出确认框");
    await sleep(1800);
    const msg = await lastMessage(page, { timeout: 10000 });
    if (msg && msg.type === "error") throw new Error(`删除失败: ${msg.text}`);
    return msg ? `提示="${msg.text}"` : "删除请求已提交";
  }, { page });

  await H.run("F-24", "关闭定时任务对话框", async () => {
    const dlg = await ensureScheduleDialog(page);
    const close = dlg.locator(".el-dialog__headerbtn").last();
    if (await close.isVisible().catch(() => false)) {
      await close.click({ timeout: 10000 });
    } else {
      const cancel = dlg.locator("button", { hasText: "取消" }).last();
      await cancel.click({ timeout: 10000 });
    }
    await sleep(1500);
    if (await dlg.isVisible().catch(() => false)) throw new Error("对话框未关闭");
    return "已关闭";
  }, { page });

  return true;
}

module.exports = { run };
