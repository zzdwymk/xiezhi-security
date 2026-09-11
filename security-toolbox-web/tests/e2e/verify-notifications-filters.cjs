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

    // -------------------------------------------------------------
    // 1. 验证“结果中心”的多维筛选栏
    // -------------------------------------------------------------
    console.log("1. 测试结果中心多维筛选栏...");
    const findingsNavBtn = nav.locator("button.desktop-v2-nav-item", { hasText: "结果中心" }).first();
    await findingsNavBtn.click();
    await new Promise((r) => setTimeout(r, 2500));

    const toolbarVisible = await page.locator(".findings-filter-toolbar").isVisible();
    console.log("结果中心多维筛选栏是否可见:", toolbarVisible);

    // 测试选择分类：漏洞发现
    const catSelect = page.locator(".findings-filter-toolbar .el-select").nth(0);
    await catSelect.click();
    await new Promise((r) => setTimeout(r, 400));
    await page.locator(".el-select-dropdown:visible li", { hasText: "漏洞发现" }).last().click();
    await new Promise((r) => setTimeout(r, 1500));

    const vulnRows = await page.locator(".el-table__row").allTextContents();
    console.log(`筛选「漏洞发现」后的结果条数: ${vulnRows.length}`);
    for (const r of vulnRows) {
      console.log("  ->", r.replace(/\s+/g, " ").trim());
    }

    // 点击重置筛选
    const resetBtn = page.locator(".findings-filter-toolbar button", { hasText: "重置筛选" }).first();
    await resetBtn.click();
    await new Promise((r) => setTimeout(r, 1500));

    await page.screenshot({ path: path.join(ROOT, "docs", "findings-toolbar-verified.png") });
    console.log("结果中心筛选栏截图已保存至: docs/findings-toolbar-verified.png");

    // -------------------------------------------------------------
    // 2. 验证“扫描 Diff”弹窗表单间距与结构
    // -------------------------------------------------------------
    console.log("2. 测试「扫描 Diff」弹窗间距...");
    const diffBtn = page.locator("button", { hasText: "扫描 Diff" }).first();
    await diffBtn.click();
    await new Promise((r) => setTimeout(r, 1500));

    await page.screenshot({ path: path.join(ROOT, "docs", "diff-spacing-verified.png") });
    console.log("扫描 Diff 间距截图已保存至: docs/diff-spacing-verified.png");

    // 关闭 Diff
    await page.locator(".el-dialog button", { hasText: "关闭" }).last().click();
    await new Promise((r) => setTimeout(r, 1000));

    // -------------------------------------------------------------
    // 3. 验证触发任务后的“全局完成通知提醒”
    // -------------------------------------------------------------
    console.log("3. 下发快速检测任务以验证全局任务完成通知...");
    const scanNavBtn = nav.locator("button.desktop-v2-nav-item", { hasText: "主动检测" }).first();
    await scanNavBtn.click();
    await new Promise((r) => setTimeout(r, 2000));

    const launcher = page.locator("aside.scan-launcher-pane").first();
    const targetSelect = launcher.locator(".el-select").first();
    await targetSelect.click();
    await new Promise((r) => setTimeout(r, 400));
    await page.locator(".el-select-dropdown:visible li", { hasText: "192.168.136.132" }).first().click();
    await new Promise((r) => setTimeout(r, 1000));

    // 仅保留一个快速端口探测任务
    const cbs = launcher.locator(".rule-list .el-checkbox:not(.is-disabled)");
    const count = await cbs.count();
    for (let i = 0; i < count; i++) {
      const cb = cbs.nth(i);
      const txt = await cb.textContent();
      const isChecked = (await cb.locator(".el-checkbox__input.is-checked").count()) > 0;
      if (txt.includes("连通性") && !isChecked) {
        await cb.click();
      } else if (!txt.includes("连通性") && isChecked) {
        await cb.click();
      }
      await new Promise((r) => setTimeout(r, 200));
    }

    // 发起检测并切换到其他页面（例如流量分析）以验证跨页面全局通知
    await launcher.locator(".scan-button").first().click();
    await new Promise((r) => setTimeout(r, 1200));
    const confirmBtn = page.locator(".el-message-box button", { hasText: "开始检测" }).last();
    if (await confirmBtn.isVisible().catch(() => false)) {
      await confirmBtn.click();
    }

    console.log("任务已下发，切到其他页面等待完成弹窗通知...");
    const trafficNavBtn = nav.locator("button.desktop-v2-nav-item", { hasText: "流量分析" }).first();
    await trafficNavBtn.click();

    // 等待通知元素出现
    console.log("等待 ElNotification 浮窗弹出...");
    const notification = page.locator(".el-notification");
    await notification.waitFor({ state: "visible", timeout: 30000 });
    const notifyTitle = await notification.locator(".el-notification__title").textContent();
    const notifyContent = await notification.locator(".el-notification__content").textContent();
    console.log(`成功收到全局任务完成通知！\n  标题: ${notifyTitle}\n  内容: ${notifyContent}`);

    await page.screenshot({ path: path.join(ROOT, "docs", "notification-verified.png") });
    console.log("任务完成全局通知截图已保存至: docs/notification-verified.png");

  } catch (err) {
    console.error("执行出错:", err);
  }
  // 保持程序打开
})();
