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

    console.log("前往「资产拓扑」检查最新渲染...");
    const topoNavBtn = nav.locator("button.desktop-v2-nav-item", { hasText: "资产拓扑" }).first();
    await topoNavBtn.click();
    await new Promise((r) => setTimeout(r, 3000));

    // 1. 检查下拉框
    const projectPicker = page.locator(".project-picker").first();
    await projectPicker.click();
    await new Promise((r) => setTimeout(r, 500));
    const options = await page.locator(".el-select-dropdown:visible li.el-select-dropdown__item").allTextContents();
    console.log("下拉框选项:", options.map((s) => s.trim()));
    await page.locator(".el-select-dropdown:visible li.el-select-dropdown__item", { hasText: "全部项目" }).first().click();
    await new Promise((r) => setTimeout(r, 3000));

    // 2. 检查全部项目下的 Hub 数量与位置
    const hubs = await page.locator(".topology-hub-node").allTextContents();
    console.log(`全部项目模式下 Hub 数量: ${hubs.length}`);
    for (const h of hubs) {
      console.log("  - Hub:", h.replace(/\s+/g, " ").trim());
    }

    // 3. 检查左下角缩放条的文字和颜色
    const zoomText = await page.locator(".zoom-level").textContent();
    console.log("缩放级别文字:", zoomText);

    // 4. 打开抽屉查看卡片是否无厚左边条
    const nodeCard = page.locator(".node-card-group").first();
    if (await nodeCard.isVisible().catch(() => false)) {
      await nodeCard.click({ force: true });
      await new Promise((r) => setTimeout(r, 1500));
    }

    const shotPath = path.join(ROOT, "docs", "topo-final-verified.png");
    await page.screenshot({ path: shotPath, fullPage: true });
    console.log("最终核验截图已保存至: docs/topo-final-verified.png");

  } catch (err) {
    console.error("执行出错:", err);
  }
})();
