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
    console.log("导航到评估项目列表...");
    const nav = page.locator("#desktop-v2-primary-navigation");
    await nav.waitFor({ state: "visible", timeout: 15000 });

    // 展开项目与资产
    const toggle = nav.locator("#nav-group-projects-assets");
    if ((await toggle.getAttribute("aria-expanded")) !== "true") {
      await toggle.click();
      await new Promise((r) => setTimeout(r, 500));
    }
    await nav.locator("button.desktop-v2-nav-item", { hasText: "评估项目" }).first().click();
    await new Promise((r) => setTimeout(r, 2000));

    // 点击进入第一个项目（最新项目）
    const enterBtn = page.locator(".el-table__row").first().locator("button", { hasText: "进入项目" }).first();
    await enterBtn.click();
    await new Promise((r) => setTimeout(r, 2000));

    // 切换到“项目报告”页签
    const reportTab = page.locator(".el-tabs__item", { hasText: "项目报告" }).first();
    await reportTab.click();
    await new Promise((r) => setTimeout(r, 2000));

    // 读文案
    const toolbarText = await page.locator(".target-report-toolbar").textContent().catch(() => "");
    console.log("=== 文案展示 ===");
    console.log(toolbarText.replace(/\s+/g, " ").trim());

    // 读取“全部目标”时的卡片指标
    const cardsAll = await page.locator(".report-cards .report-card").allTextContents();
    console.log("=== 全部目标 卡片指标 ===");
    console.log(cardsAll.map((s) => s.replace(/\s+/g, " ").trim()).join(" | "));

    const sevAll = await page.locator(".report-severity").textContent();
    console.log("=== 全部目标 等级分布 ===", sevAll.replace(/\s+/g, " ").trim());

    // 选择第一个单目标
    const targetSelect = page.locator(".target-report-toolbar .el-select").first();
    await targetSelect.click();
    await new Promise((r) => setTimeout(r, 500));

    const dropdown = page.locator(".el-select-dropdown:visible").last();
    const options = await dropdown.locator("li.el-select-dropdown__item").allTextContents();
    console.log("=== 下拉选项 ===", options.map((s) => s.replace(/\s+/g, " ").trim()));

    // 点击第二个选项（某个单目标，比如 192.168.136.132）
    if (options.length > 1) {
      await dropdown.locator("li.el-select-dropdown__item").nth(1).click();
      await new Promise((r) => setTimeout(r, 1000));

      const cardsSingle1 = await page.locator(".report-cards .report-card").allTextContents();
      console.log(`=== 目标 1 [${options[1].trim()}] 卡片指标 ===`);
      console.log(cardsSingle1.map((s) => s.replace(/\s+/g, " ").trim()).join(" | "));

      const sevSingle1 = await page.locator(".report-severity").textContent();
      console.log("=== 目标 1 等级分布 ===", sevSingle1.replace(/\s+/g, " ").trim());
    }

    // 点击第三个选项（另一个单目标，比如 Less-1）
    if (options.length > 2) {
      await targetSelect.click();
      await new Promise((r) => setTimeout(r, 500));
      await dropdown.locator("li.el-select-dropdown__item").nth(2).click();
      await new Promise((r) => setTimeout(r, 1000));

      const cardsSingle2 = await page.locator(".report-cards .report-card").allTextContents();
      console.log(`=== 目标 2 [${options[2].trim()}] 卡片指标 ===`);
      console.log(cardsSingle2.map((s) => s.replace(/\s+/g, " ").trim()).join(" | "));

      const sevSingle2 = await page.locator(".report-severity").textContent();
      console.log("=== 目标 2 等级分布 ===", sevSingle2.replace(/\s+/g, " ").trim());
    }

    // 截图保存
    const shotPath = path.join(ROOT, "docs", "report-target-filter-verified.png");
    await page.screenshot({ path: shotPath, fullPage: true });
    console.log("完整验证截图已保存至:", shotPath);

  } catch (err) {
    console.error("执行出错:", err);
  }
  // 保持窗口打开
})();
