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

    // 1. 切换到“漏洞与复测”页签，核验是否倒序排列
    const vulnTab = page.locator(".el-tabs__item", { hasText: "漏洞与复测" }).first();
    await vulnTab.click();
    await new Promise((r) => setTimeout(r, 2000));

    const rowsText = await page.locator(".el-table__row").allTextContents();
    console.log("=== 漏洞与复测（默认全部，按倒序排列）前 5 行 ===");
    for (let i = 0; i < Math.min(rowsText.length, 5); i++) {
      console.log(`  - [排名 ${i+1}]`, rowsText[i].replace(/\s+/g, " ").trim());
    }

    // 2. 切换到“项目报告”页签
    const reportTab = page.locator(".el-tabs__item", { hasText: "项目报告" }).first();
    await reportTab.click();
    await new Promise((r) => setTimeout(r, 2000));

    // 3. 点击“漏洞发现”卡片
    console.log("点击项目报告中的「漏洞发现」指标卡片...");
    const vulnCardBtn = page.locator(".report-cards button", { hasText: "漏洞发现" }).first();
    await vulnCardBtn.click();
    await new Promise((r) => setTimeout(r, 2000));

    // 核验是否跳转到了“漏洞与复测”并精确过滤出漏洞项
    console.log("当前活跃页签:", await page.locator(".el-tabs__item.is-active").textContent());
    const filterTagVal = await page.locator(".project-tab-filters .el-select").first().textContent();
    console.log("当前分类筛选下拉框选中的值:", filterTagVal.trim());

    const filteredRows = await page.locator(".el-table__row").allTextContents();
    console.log(`=== 点击「漏洞发现」后跳转展示的漏洞项 (共 ${filteredRows.length} 条) ===`);
    for (const r of filteredRows) {
      console.log("  ->", r.replace(/\s+/g, " ").trim());
    }

    // 4. 再切换回“项目报告”，点击“风险点”卡片测试
    await reportTab.click();
    await new Promise((r) => setTimeout(r, 1500));
    console.log("点击项目报告中的「风险点」指标卡片...");
    const riskCardBtn = page.locator(".report-cards button", { hasText: "风险点" }).first();
    await riskCardBtn.click();
    await new Promise((r) => setTimeout(r, 2000));

    const riskFilterVal = await page.locator(".project-tab-filters .el-select").first().textContent();
    console.log("当前分类筛选下拉框选中的值:", riskFilterVal.trim());
    const riskRowsCount = await page.locator(".el-table__row").count();
    console.log(`=== 点击「风险点」后跳转展示的风险项条数: ${riskRowsCount} 条 ===`);

    const shotPath = path.join(ROOT, "docs", "vuln-jump-verified.png");
    await page.screenshot({ path: shotPath, fullPage: true });
    console.log("核验截图已保存至:", shotPath);

  } catch (err) {
    console.error("执行出错:", err);
  }
})();
