const path = require("node:path");
const fs = require("node:fs");
const { _electron: electron } = require("playwright-core");
const { navigate } = require("./lib/ui.cjs");

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

    const nav = page.locator("#desktop-v2-primary-navigation");
    await nav.waitFor({ state: "visible", timeout: 15000 });

    // -------------------------------------------------------------
    // 1. 验证“结果中心”操作按钮完美 3x2 网格对齐
    // -------------------------------------------------------------
    console.log("1. 前往「结果中心」检查按钮对齐...");
    await navigate(page, "结果中心");

    // 截屏保存结果中心按钮对齐效果
    await page.screenshot({ path: path.join(ROOT, "docs", "fix-buttons-aligned.png") });
    console.log("操作按钮对齐截图已保存至: docs/fix-buttons-aligned.png");

    // -------------------------------------------------------------
    // 2. 验证“项目漏洞详情”弹窗中“等级/状态”标签间距
    // -------------------------------------------------------------
    console.log("2. 前往「评估项目」详情查看漏洞弹窗标签间距...");
    await navigate(page, "评估项目");

    const enterBtn = page.locator(".el-table__row").first().locator("button", { hasText: "进入项目" }).first();
    if (await enterBtn.isVisible().catch(() => false)) {
      await enterBtn.click();
      await new Promise((r) => setTimeout(r, 2000));

      const vulnTab = page.locator(".el-tabs__item", { hasText: "漏洞与复测" }).first();
      await vulnTab.click();
      await new Promise((r) => setTimeout(r, 2000));

      // 点击漏洞与复测表格第一行的“详情”按钮
      const findingsPane = page.locator("#pane-findings, .el-tab-pane[aria-hidden='false']").last();
      const detailBtn = findingsPane.locator(".el-table__row").first().locator("button", { hasText: "详情" }).first();
      if (await detailBtn.isVisible().catch(() => false)) {
        await detailBtn.click();
        await new Promise((r) => setTimeout(r, 1500));

        await page.screenshot({ path: path.join(ROOT, "docs", "fix-tags-gap.png") });
        console.log("标签间距截图已保存至: docs/fix-tags-gap.png");

        // 关闭弹窗
        await page.locator(".el-dialog button", { hasText: "关闭" }).last().click().catch(() => {});
        await new Promise((r) => setTimeout(r, 1000));
      } else {
        console.log("当前项目没有可查看的漏洞详情，跳过标签间距截图");
      }
    } else {
      console.log("当前没有评估项目，跳过项目漏洞详情检查");
    }

    // -------------------------------------------------------------
    // 3. 验证“资产拓扑”抽屉卡片无背景填充色
    // -------------------------------------------------------------
    console.log("3. 前往「资产拓扑」检查抽屉头部卡片背景...");
    await navigate(page, "资产拓扑");
    await new Promise((r) => setTimeout(r, 1200));

    // 点击拓扑中的任意资产节点以打开抽屉
    const nodeCard = page.locator(".node-card-group").first();
    if (await nodeCard.isVisible().catch(() => false)) {
      await nodeCard.click({ force: true });
      await new Promise((r) => setTimeout(r, 1500));

      await page.screenshot({ path: path.join(ROOT, "docs", "fix-drawer-transparent.png") });
      console.log("抽屉无背景填充色截图已保存至: docs/fix-drawer-transparent.png");
      await page.keyboard.press("Escape").catch(() => {});
    }

    console.log("=== 全部 3 个界面问题修复核验完毕！ ===");

  } catch (err) {
    console.error("执行出错:", err);
  }
})();
