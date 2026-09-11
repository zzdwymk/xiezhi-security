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

    // 导航到评估项目
    const nav = page.locator("#desktop-v2-primary-navigation");
    await nav.waitFor({ state: "visible", timeout: 15000 });

    const toggle = nav.locator("#nav-group-projects-assets");
    if ((await toggle.getAttribute("aria-expanded")) !== "true") {
      await toggle.click();
      await new Promise((r) => setTimeout(r, 500));
    }
    await nav.locator("button.desktop-v2-nav-item", { hasText: "评估项目" }).first().click();
    await new Promise((r) => setTimeout(r, 2000));

    // 进入第一个项目
    const enterBtn = page.locator(".el-table__row").first().locator("button", { hasText: "进入项目" }).first();
    await enterBtn.click();
    await new Promise((r) => setTimeout(r, 2000));

    // 切换到“漏洞与复测”页签并查看
    const vulnTab = page.locator(".el-tabs__item", { hasText: "漏洞与复测" }).first();
    await vulnTab.click();
    await new Promise((r) => setTimeout(r, 2000));

    const rowsText = await page.locator(".el-table__row").allTextContents();
    console.log("=== 漏洞与复测 列表前 5 行 ===");
    for (let i = 0; i < Math.min(rowsText.length, 5); i++) {
      console.log(`  - 行 ${i+1}:`, rowsText[i].replace(/\s+/g, " ").trim());
    }

    // 切换到“项目报告”页签查看卡片
    const reportTab = page.locator(".el-tabs__item", { hasText: "项目报告" }).first();
    await reportTab.click();
    await new Promise((r) => setTimeout(r, 2000));

    const cardsAll = await page.locator(".report-cards .report-card").allTextContents();
    console.log("=== 全部目标 卡片指标 ===");
    console.log(cardsAll.map((s) => s.replace(/\s+/g, " ").trim()).join(" | "));

    const sevAll = await page.locator(".report-severity").textContent();
    console.log("=== 等级分布 ===", sevAll.replace(/\s+/g, " ").trim());

    // 切换目标到 Less-1
    const targetSelect = page.locator(".target-report-toolbar .el-select").first();
    await targetSelect.click();
    await new Promise((r) => setTimeout(r, 500));
    const dropdown = page.locator(".el-select-dropdown:visible").last();
    const less1Opt = dropdown.locator("li.el-select-dropdown__item", { hasText: "Less-1" }).first();
    if (await less1Opt.count()) {
      await less1Opt.click();
      await new Promise((r) => setTimeout(r, 1000));
      const cardsLess1 = await page.locator(".report-cards .report-card").allTextContents();
      console.log("=== Less-1 目标专属卡片指标 ===");
      console.log(cardsLess1.map((s) => s.replace(/\s+/g, " ").trim()).join(" | "));
    }

    const shotPath = path.join(ROOT, "docs", "sqlmap-vuln-verified.png");
    await page.screenshot({ path: shotPath, fullPage: true });
    console.log("验证截图已保存至:", shotPath);

  } catch (err) {
    console.error("执行出错:", err);
  }
  // 保持程序打开
})();
