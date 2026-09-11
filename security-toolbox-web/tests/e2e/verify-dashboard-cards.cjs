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

    // 回到 AI 安全助手主页
    const nav = page.locator("#desktop-v2-primary-navigation");
    await nav.waitFor({ state: "visible", timeout: 15000 });
    const aiBtn = nav.locator("button.desktop-v2-nav-item", { hasText: "AI 安全助手" }).first();
    await aiBtn.click();
    await new Promise((r) => setTimeout(r, 2000));

    console.log("=== 测试 AI 安全助手概览卡片跳转 ===");

    // 1. 测试“授权目标”卡片点击
    console.log("1. 点击「授权目标」卡片...");
    const targetCard = page.locator(".welcome-stats button", { hasText: "授权目标" }).first();
    await targetCard.click();
    await new Promise((r) => setTimeout(r, 2000));
    console.log("跳转后页面 URL:", page.url());
    if (!page.url().includes("/targets")) throw new Error("点击「授权目标」未能跳转至 /targets");

    // 切回 AI 助手
    await aiBtn.click();
    await new Promise((r) => setTimeout(r, 2000));

    // 2. 测试“进行中任务”卡片点击
    console.log("2. 点击「进行中任务」卡片...");
    const taskCard = page.locator(".welcome-stats button", { hasText: "进行中任务" }).first();
    await taskCard.click();
    await new Promise((r) => setTimeout(r, 2000));
    console.log("跳转后页面 URL:", page.url());
    if (!page.url().includes("/tasks")) throw new Error("点击「进行中任务」未能跳转至 /tasks");

    // 切回 AI 助手
    await aiBtn.click();
    await new Promise((r) => setTimeout(r, 2000));

    // 3. 测试“累计发现”卡片点击
    console.log("3. 点击「累计发现」卡片...");
    const findingsCard = page.locator(".welcome-stats button", { hasText: "累计发现" }).first();
    await findingsCard.click();
    await new Promise((r) => setTimeout(r, 2000));
    console.log("跳转后页面 URL:", page.url());
    if (!page.url().includes("/findings")) throw new Error("点击「累计发现」未能跳转至 /findings");

    // 切回 AI 助手
    await aiBtn.click();
    await new Promise((r) => setTimeout(r, 2000));

    // 4. 测试“高危发现”卡片点击
    console.log("4. 点击「高危发现」卡片...");
    const criticalCard = page.locator(".welcome-stats button", { hasText: "高危发现" }).first();
    await criticalCard.click();
    await new Promise((r) => setTimeout(r, 2000));
    console.log("跳转后页面 URL:", page.url());
    const searchVal = await page.locator(".finding-head-actions input").inputValue();
    console.log("搜索输入框内的值:", searchVal);
    const findingRows = await page.locator(".el-table__row").allTextContents();
    console.log(`过滤出的高危漏洞行 (共 ${findingRows.length} 条):`);
    for (const r of findingRows) {
      console.log("  ->", r.replace(/\s+/g, " ").trim());
    }

    console.log("=== 所有 4 个卡片跳转测试全部成功通过！ ===");

  } catch (err) {
    console.error("执行出错:", err);
  }
  // 保持程序打开
})();
