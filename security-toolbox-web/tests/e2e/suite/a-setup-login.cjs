/*
 * 阶段 A：环境依赖检查 → 登录
 *
 * 全部通过真实 UI 操作完成，不预置 localStorage 跳过依赖检查页。
 */
const {
  sleep, settle, pageTitle, lastMessage, clearMessages,
} = require("../lib/ui.cjs");

async function run(page, H, ctx) {
  H.phase("阶段 A — 环境依赖检查与登录");

  // ---------- A1 应用可达 ----------
  await H.run("A-01", "打开应用首页，前端服务可访问", async () => {
    await page.goto(ctx.baseUrl, { waitUntil: "domcontentloaded", timeout: 30000 });
    await settle(page, 1500);
    const title = await page.title();
    if (!title) throw new Error("页面标题为空");
    return `标题=${title}`;
  }, { page });

  await H.shot(page, "A-初始页面");

  // ---------- A2 依赖检查页 ----------
  const onSetup = page.url().includes("/setup");
  if (onSetup) {
    await H.run("A-02", "首次进入自动跳转到环境依赖检查页", async () => {
      const h = await page.locator(".setup-steps").first().isVisible({ timeout: 8000 }).catch(() => false);
      if (!h && !page.url().includes("/setup")) throw new Error(`未跳转到 /setup，当前 ${page.url()}`);
      return `URL=${page.url()}`;
    }, { page });

    await H.run("A-03", "依赖检查页展示核心依赖与可选工具分组", async () => {
      // 依赖探测是异步的，需等待列表渲染完成
      await page.locator(".dependency-row").first().waitFor({ state: "visible", timeout: 45000 });
      const groups = await page.locator(".dependency-group").count();
      if (groups < 1) throw new Error("未渲染依赖分组");
      const rows = await page.locator(".dependency-row").count();
      // 就绪状态由 .dep-status 上的 ready 修饰类表示，不能按文案匹配
      const available = await page.locator(".dependency-row .dep-status.ready").count();
      ctx.setupDependencyRows = rows;
      ctx.setupDependencyReady = available;
      return `分组 ${groups} 个，依赖项 ${rows} 条，就绪 ${available} 项`;
    }, { page });

    await H.shot(page, "A-依赖检查页");

    await H.run("A-04", "点击「重新检测」可重新执行依赖探测", async () => {
      const btn = page.locator("button", { hasText: "重新检测" }).first();
      if (!(await btn.isVisible().catch(() => false))) throw new Error("未找到重新检测按钮");
      await btn.click();
      await sleep(3500);
      return "已触发重新检测";
    }, { page });

    await H.run("A-05", "点击「下一步，进入工具箱」离开依赖检查页", async () => {
      const next = page.locator("button", { hasText: "下一步" }).first();
      await next.waitFor({ state: "visible", timeout: 10000 });
      const disabled = await next.isDisabled().catch(() => false);
      if (disabled) throw new Error("下一步按钮不可用（可能缺少核心依赖）");
      await next.click();
      await settle(page, 2000);
      if (page.url().includes("/setup")) throw new Error("点击后仍停留在依赖检查页");
      return `已进入 ${page.url()}`;
    }, { page });
  } else {
    H.skip("A-02", "首次进入自动跳转到环境依赖检查页", "本次会话依赖检查已完成，未触发跳转");
    H.skip("A-03", "依赖检查页展示核心依赖与可选工具分组", "同上");
    H.skip("A-04", "点击「重新检测」可重新执行依赖探测", "同上");
    H.skip("A-05", "点击「下一步，进入工具箱」离开依赖检查页", "同上");
  }

  // ---------- A6 登录页 ----------
  await H.run("A-06", "未登录访问工作区被重定向到登录页", async () => {
    await page.waitForURL(/\/login/, { timeout: 15000 }).catch(() => {});
    if (!page.url().includes("/login")) throw new Error(`未跳转登录页，当前 ${page.url()}`);
    await page.locator(".login-card").first().waitFor({ state: "visible", timeout: 10000 });
    return `URL=${page.url()}`;
  }, { page });

  await H.shot(page, "A-登录页");

  await H.run("A-07", "登录页渲染用户名、密码输入框与登录按钮", async () => {
    const u = page.locator('input[placeholder="请输入用户名"]');
    const p = page.locator('input[placeholder="请输入密码"]');
    const b = page.locator("button.login-button");
    await u.waitFor({ state: "visible", timeout: 8000 });
    await p.waitFor({ state: "visible", timeout: 8000 });
    await b.waitFor({ state: "visible", timeout: 8000 });
    return "三个关键控件均已渲染";
  }, { page });

  await H.run("A-08", "用户名密码为空时登录按钮禁用", async () => {
    const b = page.locator("button.login-button").first();
    const disabled = await b.isDisabled();
    if (!disabled) throw new Error("空表单时登录按钮仍可点击");
    return "按钮已禁用";
  }, { page });

  // ---------- A9 错误密码（负向） ----------
  await H.run("A-09", "错误密码登录被拒绝并提示", async () => {
    await clearMessages(page);
    await page.locator('input[placeholder="请输入用户名"]').fill(ctx.username);
    await page.locator('input[placeholder="请输入密码"]').fill("WrongPassword-" + Date.now());
    await page.locator("button.login-button").first().click();
    const msg = await lastMessage(page, { timeout: 12000 });
    if (!msg) throw new Error("未出现任何提示消息");
    if (msg.type !== "error") throw new Error(`期望错误提示，实际 ${msg.type}: ${msg.text}`);
    if (page.url().includes("/login") === false) throw new Error("错误密码竟然登录成功");
    return `提示="${msg.text}"`;
  }, { page, shotOnPass: true });

  // ---------- A10 正确密码 ----------
  await H.run("A-10", "正确账号密码登录成功并进入工作区", async () => {
    await clearMessages(page);
    await page.locator('input[placeholder="请输入密码"]').fill("");
    await page.locator('input[placeholder="请输入密码"]').type(ctx.password, { delay: 5 });
    await page.locator("button.login-button").first().click();
    await page.waitForURL((u) => !u.toString().includes("/login"), { timeout: 20000 });
    await settle(page, 2000);
    return `已进入 ${page.url()}`;
  }, { page });

  await H.shot(page, "A-登录后工作区");

  await H.run("A-11", "登录后侧边栏与顶栏正确渲染", async () => {
    await page.locator("#desktop-v2-sidebar").first().waitFor({ state: "visible", timeout: 12000 });
    await page.locator("#desktop-v2-primary-navigation").first().waitFor({ state: "visible", timeout: 8000 });
    const brand = (await page.locator(".desktop-v2-brand").first().textContent().catch(() => "")) || "";
    if (!brand.includes("獬豸")) throw new Error(`品牌区文本异常: ${brand.trim()}`);
    const t = await pageTitle(page);
    return `品牌="獬豸" 当前页面="${t}"`;
  }, { page });

  await H.run("A-12", "登录后显示当前用户角色为管理员", async () => {
    const chip = (await page.locator("button.desktop-v2-user").first().textContent().catch(() => "")) || "";
    if (!chip.includes("管理员")) throw new Error(`用户区未显示管理员，实际: ${chip.trim().slice(0, 60)}`);
    return "角色=管理员";
  }, { page });

  await H.run("A-13", "本地引擎状态显示已连接", async () => {
    const scope = page.locator(".desktop-v2-scope").first();
    await scope.waitFor({ state: "visible", timeout: 10000 });
    for (let i = 0; i < 20; i++) {
      const txt = (await scope.textContent().catch(() => "")) || "";
      if (txt.includes("已连接")) return `状态="${txt.trim().replace(/\s+/g, " ").slice(0, 60)}"`;
      if (txt.includes("不可用")) throw new Error(`引擎不可用: ${txt.trim()}`);
      await sleep(1000);
    }
    throw new Error("15 秒内引擎状态未变为已连接");
  }, { page });

  return true;
}

module.exports = { run };
