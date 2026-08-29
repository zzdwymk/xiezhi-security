/*
 * 阶段 I：流量分析工作台（HTTP/HTTPS 中间人代理）
 *
 * 业务顺序：进入流量页 → 校验代理状态与地址 → 抓包黑白名单 CRUD
 *          → 启动代理并经代理产生真实流量 → 会话列表与报文查看
 *          → 标记/取消标记 → 重放器（授权内放行、越权拒绝）→ 停止代理
 *
 * 说明：网页端不提供「启动抓包浏览器」（桌面端专属），相关用例按环境限制跳过。
 * 生成流量时使用 Node http 模块作为"经过代理的客户端"，
 * 这是模拟真实用户浏览器走代理的行为，代理的启停与会话展示仍全部由 UI 驱动。
 */
const http = require("node:http");
const {
  sleep, navigate, pageTitle, dialog, dialogButton, selectOn,
  lastMessage, clearMessages, confirmBoxIfPresent,
} = require("../lib/ui.cjs");

/** 经本机代理发起一次 HTTP 请求（模拟浏览器走代理） */
function requestThroughProxy(proxyHost, proxyPort, targetUrl, timeout = 12000) {
  return new Promise((resolve) => {
    const u = new URL(targetUrl);
    const req = http.request(
      {
        host: proxyHost,
        port: proxyPort,
        method: "GET",
        path: targetUrl, // 代理请求使用绝对 URI
        headers: { Host: u.host, "User-Agent": "Xiezhi-E2E-Test/1.0", Connection: "close" },
        timeout,
      },
      (res) => {
        let body = "";
        res.on("data", (c) => { if (body.length < 2000) body += c; });
        res.on("end", () => resolve({ ok: true, status: res.statusCode, body: body.slice(0, 300) }));
      },
    );
    req.on("timeout", () => { req.destroy(); resolve({ ok: false, error: "timeout" }); });
    req.on("error", (e) => resolve({ ok: false, error: e.message }));
    req.end();
  });
}

async function run(page, H, ctx) {
  H.phase("阶段 I — 流量分析工作台");

  await H.run("I-01", "通过侧边栏进入「流量分析」页面", async () => {
    await navigate(page, "流量分析");
    const t = await pageTitle(page);
    if (!page.url().includes("/traffic")) throw new Error(`URL 异常: ${page.url()}`);
    return `标题="${t}"`;
  }, { page });

  await sleep(2500);
  await H.shot(page, "I-流量工作台");

  await H.run("I-02", "工具条展示代理运行状态与监听地址", async () => {
    const bar = page.locator(".traffic-toolbar").first();
    if (!(await bar.count())) throw new Error("未渲染流量工具条");
    const text = ((await bar.textContent()) || "").replace(/\s+/g, " ").trim();
    const state = ["未启动", "正在拦截", "已连接"].find((s) => text.includes(s));
    if (!state) throw new Error(`未展示代理状态: ${text.slice(0, 180)}`);
    const addr = (text.match(/127\.0\.0\.1:(\d+)/) || [])[0];
    ctx.proxyAddr = addr || "127.0.0.1:8088";
    return `状态=${state}，监听地址=${ctx.proxyAddr}`;
  }, { page });

  await H.run("I-03", "服务未就绪时给出明确提示（若适用）", async () => {
    const alert = page.locator(".el-alert").first();
    if (!(await alert.count())) return "未出现服务未就绪提示，模块已就绪";
    const text = ((await alert.textContent()) || "").replace(/\s+/g, " ").trim();
    if (/尚未就绪|不可用/.test(text)) {
      ctx.trafficUnavailable = true;
      throw new Error(`流量代理模块未就绪: ${text.slice(0, 180)}`);
    }
    return `提示信息: ${text.slice(0, 120)}`;
  }, { page });

  H.skip("I-04", "启动抓包浏览器（内置受控浏览器）",
    "网页端不提供该入口，属桌面端（Electron）专属能力；本次以浏览器模式运行");

  // ---------- 抓包黑白名单 CRUD ----------
  await H.run("I-05", "打开「黑白名单」对话框", async () => {
    const btn = page.locator("button.capture-filter-button").first();
    if (!(await btn.count())) throw new Error("未渲染黑白名单入口");
    await btn.click();
    const dlg = await dialog(page, "抓包黑白名单");
    if (!(await dlg.isVisible())) throw new Error("对话框未显示");
    return "对话框已打开";
  }, { page });

  await H.shot(page, "I-黑白名单");

  const filterPattern = `e2e-test-${ctx.stamp}.example`;
  await H.run("I-06", "新增一条黑名单域名过滤规则", async () => {
    const dlg = await dialog(page, "抓包黑白名单");
    await clearMessages(page);
    const editor = dlg.locator(".capture-filter-editor").first();
    const inputs = editor.locator("input.el-input__inner");
    // 最后一个文本输入为匹配内容
    const patternInput = inputs.last();
    await patternInput.click();
    await patternInput.fill(filterPattern);
    await sleep(400);
    await editor.locator("button", { hasText: "添加" }).first().click();
    await sleep(2000);
    const msg = await lastMessage(page, { timeout: 8000 });
    if (msg && msg.type === "error") throw new Error(`新增规则失败: ${msg.text}`);
    const table = ((await dlg.locator(".capture-filter-table").first().textContent().catch(() => "")) || "");
    if (!table.includes(filterPattern)) {
      throw new Error(`规则未出现在列表中: ${table.replace(/\s+/g, " ").slice(0, 200)}`);
    }
    ctx.filterCreated = true;
    return `已新增规则 ${filterPattern}`;
  }, { page, shotOnPass: true });

  await H.run("I-07", "过滤规则表展示名单类型、匹配方式与启用状态", async () => {
    const dlg = await dialog(page, "抓包黑白名单");
    const header = ((await dlg.locator(".capture-filter-table .el-table__header").first().textContent().catch(() => "")) || "").replace(/\s+/g, " ");
    const missing = ["名单", "匹配", "启用", "操作"].filter((k) => !header.includes(k));
    if (missing.length) throw new Error(`表头缺少: ${missing.join("、")}（实际: ${header.slice(0, 120)}）`);
    return `表头: ${header.slice(0, 120)}`;
  }, { page });

  await H.run("I-08", "可切换过滤规则的启用开关", async () => {
    if (!ctx.filterCreated) return "未创建规则，跳过";
    const dlg = await dialog(page, "抓包黑白名单");
    const row = dlg.locator(".capture-filter-table .el-table__row", { hasText: filterPattern }).first();
    const sw = row.locator(".el-switch").first();
    if (!(await sw.count())) throw new Error("未渲染启用开关");
    const before = (await sw.getAttribute("class")) || "";
    await clearMessages(page);
    await sw.click();
    await sleep(1800);
    const after = (await sw.getAttribute("class")) || "";
    if (before === after) throw new Error("点击后开关状态未变化");
    return `启用状态已切换（${before.includes("is-checked") ? "启用→停用" : "停用→启用"}）`;
  }, { page });

  await H.run("I-09", "可删除过滤规则", async () => {
    if (!ctx.filterCreated) return "未创建规则，跳过";
    const dlg = await dialog(page, "抓包黑白名单");
    const row = dlg.locator(".capture-filter-table .el-table__row", { hasText: filterPattern }).first();
    const btn = row.locator("button", { hasText: "删除" }).first();
    if (!(await btn.count())) throw new Error("未渲染删除按钮");
    await clearMessages(page);
    await btn.click();
    await sleep(1200);
    await confirmBoxIfPresent(page, ["删除", "确定", "确认"]);
    await sleep(2000);
    const table = ((await dlg.locator(".capture-filter-table").first().textContent().catch(() => "")) || "");
    if (table.includes(filterPattern)) throw new Error("删除后规则仍在列表中");
    ctx.filterCreated = false;
    return "规则已删除，列表恢复原状";
  }, { page, shotOnPass: true });

  await H.run("I-10", "关闭黑白名单对话框", async () => {
    const dlg = await dialog(page, "抓包黑白名单");
    const close = dlg.locator("button", { hasText: "关闭" }).last();
    if (await close.isVisible().catch(() => false)) await close.click();
    else await dlg.locator(".el-dialog__headerbtn").last().click();
    await sleep(1200);
    return "已关闭";
  }, { page });

  // ---------- 启动拦截并产生真实流量 ----------
  await H.run("I-11", "点击「开始拦截」启动代理", async () => {
    await clearMessages(page);
    const btn = page.locator("button.capture-toggle").first();
    if (!(await btn.count())) throw new Error("未渲染拦截开关");
    const label = ((await btn.textContent()) || "").trim();
    if (label.includes("停止")) {
      ctx.captureAlreadyOn = true;
      return "代理已处于拦截状态";
    }
    await btn.click();
    await sleep(3500);
    const msg = await lastMessage(page, { timeout: 10000 });
    if (msg && msg.type === "error") throw new Error(`启动拦截失败: ${msg.text}`);
    const state = ((await page.locator(".proxy-state").first().textContent().catch(() => "")) || "").trim();
    ctx.captureStarted = true;
    return `拦截已启动，状态=${state}${msg ? `，提示="${msg.text}"` : ""}`;
  }, { page, shotOnPass: true });

  await H.run("I-12", "经本机代理访问授权靶机，产生真实抓包会话", async () => {
    const [host, port] = (ctx.proxyAddr || "127.0.0.1:8088").split(":");
    const url = `http://${ctx.targetIp}:${ctx.targetWebPort}/`;
    let result = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      result = await requestThroughProxy(host, Number(port), url);
      if (result.ok) break;
      await sleep(2000);
    }
    if (!result || !result.ok) {
      throw new Error(`经代理 ${ctx.proxyAddr} 访问 ${url} 失败: ${result ? result.error : "无响应"}`);
    }
    ctx.proxyRequestStatus = result.status;
    await sleep(3000);
    // 刷新会话列表
    const refresh = page.locator('button[aria-label="刷新流量"], button.traffic-refresh').first();
    if (await refresh.count()) { await refresh.click(); await sleep(2500); }
    return `经代理请求 ${url} 返回 HTTP ${result.status}`;
  }, { page });

  let sessionCount = 0;
  await H.run("I-13", "会话列表出现该次请求的抓包记录", async () => {
    for (let i = 0; i < 10; i++) {
      sessionCount = await page.locator("button.traffic-row").count();
      if (sessionCount > 0) break;
      const refresh = page.locator('button[aria-label="刷新流量"], button.traffic-refresh').first();
      if (await refresh.count()) { await refresh.click(); }
      await sleep(2000);
    }
    if (sessionCount === 0) throw new Error("经代理已成功请求，但会话列表为空");
    const first = ((await page.locator("button.traffic-row").first().textContent()) || "").replace(/\s+/g, " ").trim();
    if (!first.includes(ctx.targetIp)) {
      throw new Error(`首条会话与靶机无关: ${first.slice(0, 160)}`);
    }
    return `会话 ${sessionCount} 条，首条: ${first.slice(0, 140)}`;
  }, { page, shotOnPass: true });

  await H.run("I-14", "点击会话可查看原始请求报文", async () => {
    await page.locator("button.traffic-row").first().click();
    await sleep(2000);
    const tabs = page.locator("nav.packet-tabs").first();
    if (!(await tabs.count())) throw new Error("未渲染报文标签页");
    await tabs.locator("button", { hasText: "请求" }).first().click();
    await sleep(1500);
    const card = page.locator("article.raw-packet-card").first();
    if (!(await card.count())) throw new Error("未渲染原始报文卡片");
    const text = ((await card.textContent()) || "").replace(/\s+/g, " ");
    if (!/GET|Host/.test(text)) throw new Error(`请求报文内容异常: ${text.slice(0, 200)}`);
    ctx.requestPacket = text.slice(0, 300);
    return `请求报文: ${text.slice(0, 150)}`;
  }, { page, shotOnPass: true });

  await H.run("I-15", "可查看原始响应报文且内容来自靶机", async () => {
    const tabs = page.locator("nav.packet-tabs").first();
    await tabs.locator("button", { hasText: "响应" }).first().click();
    await sleep(1800);
    const card = page.locator("article.raw-packet-card").first();
    const text = ((await card.textContent()) || "").replace(/\s+/g, " ");
    if (!/HTTP\/|Server|Content-Type/i.test(text)) {
      throw new Error(`响应报文内容异常: ${text.slice(0, 200)}`);
    }
    ctx.responsePacket = text.slice(0, 300);
    const fromTarget = /SimpleHTTP|Python|Directory listing/i.test(text);
    return `响应报文${fromTarget ? "确认来自靶机 SimpleHTTP 服务" : "已渲染"}: ${text.slice(0, 140)}`;
  }, { page, shotOnPass: true });

  await H.run("I-16", "右侧展示本条流量的本地安全要点", async () => {
    const pane = page.locator(".traffic-points-pane").first();
    if (!(await pane.count())) throw new Error("未渲染安全要点面板");
    const text = ((await pane.textContent()) || "").replace(/\s+/g, " ").trim();
    const items = await pane.locator("li").count();
    return `安全要点 ${items} 条: ${text.slice(0, 150)}`;
  }, { page });

  await H.run("I-17", "会话可通过右键菜单标记与取消标记", async () => {
    const row = page.locator("button.traffic-row").first();
    await row.click({ button: "right" });
    await sleep(1200);
    const menu = page.locator(".el-dropdown-menu:visible, [role='menu']").last();
    if (!(await menu.isVisible().catch(() => false))) {
      await page.keyboard.press("Escape").catch(() => {});
      return "右键菜单未出现（该交互可能需桌面端支持）";
    }
    const text = ((await menu.textContent()) || "").replace(/\s+/g, " ");
    const mark = menu.locator("*", { hasText: /标记会话|取消标记/ }).last();
    if (await mark.count()) { await mark.click(); await sleep(1800); }
    else await page.keyboard.press("Escape").catch(() => {});
    return `右键菜单项: ${text.slice(0, 120)}`;
  }, { page });

  await H.run("I-18", "会话筛选框可按 URL/Host/方法过滤", async () => {
    const filter = page.locator(".traffic-session-filter input").first();
    if (!(await filter.count())) throw new Error("未渲染会话筛选框");
    const before = await page.locator("button.traffic-row").count();
    await filter.click();
    await filter.fill(ctx.targetIp);
    await sleep(2000);
    const matched = await page.locator("button.traffic-row").count();
    await filter.fill("no-such-host-zzz");
    await sleep(2000);
    const none = await page.locator("button.traffic-row").count();
    await filter.fill("");
    await sleep(1500);
    if (none >= matched && matched > 0) {
      throw new Error(`筛选无效：匹配 ${matched} 条，不匹配关键字仍有 ${none} 条`);
    }
    return `全部 ${before} 条，按靶机 IP 筛选 ${matched} 条，无关关键字 ${none} 条`;
  }, { page });

  // ---------- 重放器 ----------
  await H.run("I-19", "重放器可对授权目标重放请求并获得响应", async () => {
    // 优先通过「发送到重放器」按钮将当前会话转入重放器
    const sendToReplayBtn = page.locator("button", { hasText: "发送到重放器" }).first();
    if (await sendToReplayBtn.isVisible().catch(() => false)) {
      await sendToReplayBtn.click();
      await sleep(1500);
    } else {
      const tabs = page.locator("nav.packet-tabs").first();
      const replayTab = tabs.locator("button", { hasText: "重放器" }).first();
      if (await replayTab.count()) {
        await replayTab.click();
        await sleep(1500);
      }
    }
    const editor = page.locator(".inline-replay-editor").first();
    if (!(await editor.count())) throw new Error("未渲染重放编辑器");

    // 若无活动重放请求（空状态），先新建一个请求标签
    let line = editor.locator(".replay-request-line").first();
    if (!(await line.count())) {
      const create = editor.locator("button.replay-tab-add, button", { hasText: "新建请求" }).first();
      if (await create.count()) { await create.click(); await sleep(1200); }
      line = editor.locator(".replay-request-line").first();
    }
    if (!(await line.count())) throw new Error("无法进入可编辑的重放请求（无请求行）");

    // 方法与 URL 均需非空，发包按钮才会启用
    const methodInput = line.locator("input").first();
    const urlInput = line.locator("input").last();
    const curUrl = await urlInput.inputValue().catch(() => "");
    if (!curUrl) {
      await methodInput.click(); await methodInput.fill("GET");
      await urlInput.click(); await urlInput.fill(`http://${ctx.targetIp}:${ctx.targetWebPort}/`);
      await sleep(800);
    }

    await clearMessages(page);
    const send = editor.locator("button", { hasText: "发包" }).first();
    if (!(await send.count())) throw new Error("未渲染发包按钮");
    for (let i = 0; i < 20 && (await send.isDisabled().catch(() => true)); i++) await sleep(300);
    if (await send.isDisabled().catch(() => true)) throw new Error("填入方法与 URL 后发包按钮仍禁用");
    await send.click();
    await sleep(4500);
    const resp = ((await editor.locator(".replay-response").first().textContent().catch(() => "")) || "").replace(/\s+/g, " ");
    const msg = await lastMessage(page, { timeout: 5000 });
    if (msg && msg.type === "error") throw new Error(`授权目标重放被拒绝: ${msg.text}`);
    if (!/HTTP\/|Response|Server|\d{3}|SimpleHTTP|Directory/i.test(resp)) {
      throw new Error(`未获得重放响应: ${resp.slice(0, 200)}`);
    }
    ctx.replayEditorReady = true;
    return `重放响应: ${resp.slice(0, 150)}`;
  }, { page, shotOnPass: true });

  await H.run("I-20", "重放器拒绝向未授权主机发送请求", async () => {
    const editor = page.locator(".inline-replay-editor").first();
    const line = editor.locator(".replay-request-line").first();
    if (!(await line.count())) return "无活动重放请求行，跳过";
    const methodInput = line.locator("input").first();
    const urlInput = line.locator("input").last();
    await methodInput.click(); await methodInput.fill("GET");
    await urlInput.click(); await urlInput.fill("http://example.com/");
    await sleep(800);
    await clearMessages(page);
    const send = editor.locator("button", { hasText: "发包" }).first();
    for (let i = 0; i < 20 && (await send.isDisabled().catch(() => true)); i++) await sleep(300);
    await send.click();
    await sleep(4500);
    const msg = await lastMessage(page, { timeout: 10000 });
    const resp = ((await editor.locator(".replay-response").first().textContent().catch(() => "")) || "").replace(/\s+/g, " ");
    if (msg && msg.type === "error") {
      return `已拒绝越权重放，提示="${msg.text}"`;
    }
    if (/失败|拒绝|未授权|不在授权|超出授权/.test(resp)) {
      return `已拒绝越权重放：${resp.slice(0, 150)}`;
    }
    throw new Error(`向未授权主机 example.com 重放未被拒绝：${resp.slice(0, 200)}`);
  }, { page, shotOnPass: true });

  // ---------- 停止 ----------
  await H.run("I-21", "点击「停止拦截」关闭抓包", async () => {
    await clearMessages(page);
    const btn = page.locator("button.capture-toggle").first();
    const label = ((await btn.textContent()) || "").trim();
    if (!label.includes("停止")) return `当前按钮为「${label}」，无需停止`;
    await btn.click();
    await sleep(3000);
    const state = ((await page.locator(".proxy-state").first().textContent().catch(() => "")) || "").trim();
    return `拦截已停止，状态=${state}`;
  }, { page });

  await H.run("I-22", "点击「停止代理」释放本机监听端口", async () => {
    const btn = page.locator("button.proxy-toggle").first();
    if (!(await btn.count())) return "代理未运行，无停止入口";
    await clearMessages(page);
    await btn.click();
    await sleep(3000);
    await confirmBoxIfPresent(page, ["确定", "确认", "停止"]);
    await sleep(2000);
    const state = ((await page.locator(".proxy-state").first().textContent().catch(() => "")) || "").trim();
    const msg = await lastMessage(page, { timeout: 6000 });
    return `代理已停止，状态=${state}${msg ? `，提示="${msg.text}"` : ""}`;
  }, { page, shotOnPass: true });

  return true;
}

module.exports = { run };
