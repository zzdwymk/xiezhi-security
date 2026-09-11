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

    await page.waitForLoadState("domcontentloaded");
    await new Promise((r) => setTimeout(r, 2000));

    // 如果在 setup 或 login 页面，自动通过
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
      if (page.url().includes("/login")) {
        await page.locator("input[placeholder*='用户名'], input[type='text']").first().fill("admin");
        await page.locator("input[placeholder*='密码'], input[type='password']").first().fill("admin123");
        await page.locator("button", { hasText: "登录" }).first().click();
        await new Promise((r) => setTimeout(r, 2500));
      }
    }

    // 从页面渲染上下文中读取完整 Findings 数据
    const findingsData = await page.evaluate(async () => {
      const token =
        localStorage.getItem("security_toolbox_token") ||
        sessionStorage.getItem("security_toolbox_session_token") ||
        "";
      // 找到当前的后端 API 地址
      const backendUrl = "http://127.0.0.1:18080/api";
      const headers = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      // 读取目标列表
      const targetsRes = await fetch(`${backendUrl}/targets`, { headers });
      const targets = await targetsRes.json().catch(() => []);

      // 读取任务列表
      const tasksRes = await fetch(`${backendUrl}/tasks?page=0&size=50`, { headers });
      const tasks = await tasksRes.json().catch(() => ({}));

      // 读取漏洞发现列表
      const findingsRes = await fetch(`${backendUrl}/findings?page=0&size=100`, { headers });
      const findings = await findingsRes.json().catch(() => ({}));

      return {
        tokenPresent: Boolean(token),
        targets,
        tasks: tasks.content || tasks,
        findings: findings.content || findings,
      };
    });

    console.log("=== Token 状态 ===", findingsData.tokenPresent);
    console.log("=== 目标数据数量 ===", Array.isArray(findingsData.targets) ? findingsData.targets.length : "非数组");
    console.log("=== 任务数据数量 ===", Array.isArray(findingsData.tasks) ? findingsData.tasks.length : "非数组");
    console.log("=== 漏洞 Findings 数据数量 ===", Array.isArray(findingsData.findings) ? findingsData.findings.length : "非数组");

    const targetDocsDir = path.resolve(__dirname, "..", "..", "..", "docs");
    fs.writeFileSync(
      path.join(targetDocsDir, "findings-audit-raw.json"),
      JSON.stringify(findingsData, null, 2),
      "utf-8"
    );

    console.log("数据已写入 docs/findings-audit-raw.json");

  } catch (err) {
    console.error("执行出错:", err);
  }
  // 保持窗口打开，不退出
})();
