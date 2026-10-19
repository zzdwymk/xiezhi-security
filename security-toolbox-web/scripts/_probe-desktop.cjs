const { _electron: electron } = require("playwright-core");
(async () => {
  process.on("SIGINT", () => process.exit(0));
  const app = await electron.launch({ executablePath: process.env.EXE, args: ["."], env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined }, timeout: 180000 });
  const wait = (ms) => new Promise(r => setTimeout(r, ms));
  let page;
  for (let i = 0; i < 60; i++) { page = app.windows().find(w => !w.isClosed() && w.url().includes("#/")); if (page) break; await wait(2000); }
  for (let i = 0; i < 40; i++) {
    const be = await fetch("http://127.0.0.1:18080/api/auth/me").then(r => r.status).catch(() => "down");
    const rt = await fetch("http://127.0.0.1:18121/health").then(r => r.ok).catch(() => false);
    if (be === 401 && rt) break; await wait(3000);
  }
  for (let i = 0; i < 60; i++) { const b = await page.locator("body").innerText(); if (!/正在检测本地环境|检测中/.test(b)) break; await wait(5000); }
  await wait(3000);
  if (!/AI 安全助手/.test(await page.locator("body").innerText())) {
    const next = page.locator("button").filter({ hasText: /下一步/ }).first();
    if (await next.count() && !(await next.isDisabled().catch(()=>true))) { await next.click(); await wait(6000); }
    for (let i = 0; i < 30; i++) { await wait(2000); if (/用户名|本机安全凭据/.test(await page.locator("body").innerText())) break; }
    const q = page.locator("button, a, div[role=button]").filter({ hasText: /本机安全凭据/ }).first();
    if (await q.count()) { await q.click(); await wait(8000); }
  }
  const t = await page.locator("body").innerText();
  console.log("IN_WORKSPACE=" + /AI 安全助手/.test(t));
  const m = t.match(/连接已结束[^\n]*|回答中|已完成/);
  console.log("SIDEBAR_BADGE_SAMPLE=" + (m ? m[0] : "none"));
  await page.screenshot({ path: process.env.OUT, fullPage: true }).catch(() => {});
  console.log("SCREENSHOT_OK");
  process.exit(0);
})().catch(e => { console.error("FAIL " + e.message); process.exit(1); });
