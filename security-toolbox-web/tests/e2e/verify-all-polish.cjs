const path = require("node:path");
const fs = require("node:fs");
const { _electron: electron } = require("playwright-core");

const ROOT = path.resolve(__dirname, "..", "..");
const EXE_PATH = path.join(
  ROOT,
  "desktop-release",
  "win-unpacked",
  "獬豸安全测试平台.exe"
);

(async () => {
  let app;
  try {
    app = await electron.launch({
      executablePath: EXE_PATH,
      args: [],
      env: { ...process.env, TOOLBOX_DESKTOP: "true" },
      timeout: 60000,
    });

    let page;
    const deadline = Date.now() + 45000;
    while (Date.now() < deadline) {
      for (const w of app.windows()) {
        const u = w.url();
        if (u && !u.includes("startup.html")) {
          page = w;
          break;
        }
      }
      if (page) break;
      await new Promise((r) => setTimeout(r, 1000));
    }

    if (!page) {
      page = await app.waitForEvent("window", {
        predicate: (w) => !w.url().includes("startup.html"),
        timeout: 30000,
      });
    }

    await page.setViewportSize({ width: 1440, height: 900 });
    await page.waitForLoadState("domcontentloaded");
    await new Promise((r) => setTimeout(r, 2000));

    if (page.url().includes("/setup")) {
      const nextBtn = page.locator("button", { hasText: "下一步" }).first();
      await nextBtn.waitFor({ state: "visible", timeout: 30000 });
      for (let i = 0; i < 45; i++) {
        if (!(await nextBtn.isDisabled().catch(() => true))) break;
        await new Promise((r) => setTimeout(r, 1000));
      }
      await nextBtn.click();
      await new Promise((r) => setTimeout(r, 2000));
    }

    if (page.url().includes("/login")) {
      const desktopLoginBtn = page.locator("button", { hasText: "本机安全凭据一键登录" }).first();
      if (await desktopLoginBtn.isVisible().catch(() => false)) {
        await desktopLoginBtn.click();
        await new Promise((r) => setTimeout(r, 2000));
      }
    }

    const nav = page.locator("#desktop-v2-primary-navigation");
    await nav.waitFor({ state: "visible", timeout: 15000 });

    // 1. 验证左下角状态点颜色：必须是主题色（蓝色），不再是绿色！
    console.log("1. 核验左下角状态点颜色...");
    const dotEl = page.locator(".desktop-v2-online-dot").first();
    const dotBg = await dotEl.evaluate((el) => window.getComputedStyle(el).backgroundColor);
    console.log("左下角状态点计算出的背景色:", dotBg);

    // 2. 验证红队工作流保存
    console.log("2. 前往「红队工作流」测试保存功能...");
    const wfBtn = nav.locator("button.desktop-v2-nav-item", { hasText: "红队工作流" }).first();
    await wfBtn.click();
    await new Promise((r) => setTimeout(r, 3000));

    const saveBtn = page.locator("button", { hasText: "保存工作流" }).first();
    if (await saveBtn.isVisible().catch(() => false)) {
      await saveBtn.click();
      await new Promise((r) => setTimeout(r, 2000));

      const lastSuccessMsg = await page.locator(".el-message--success").textContent().catch(() => "");
      const lastErrorMsg = await page.locator(".el-message--error").textContent().catch(() => "");
      console.log("保存工作流执行结果: 成功提示=", lastSuccessMsg, " 错误提示=", lastErrorMsg);
    }

    // 3. 验证刷新页面（F5）无闪白屏
    console.log("3. 模拟页面刷新，验证深色底色连续性...");
    await page.reload();
    await page.waitForLoadState("domcontentloaded");
    const htmlBg = await page.evaluate(() => window.getComputedStyle(document.documentElement).backgroundColor);
    const bodyBg = await page.evaluate(() => window.getComputedStyle(document.body).backgroundColor);
    console.log("刷新后 HTML 背景色:", htmlBg, " Body 背景色:", bodyBg);

    console.log("=== 自动化核验完成！ ===");

  } catch (err) {
    console.error("执行出错:", err);
  }
})();
