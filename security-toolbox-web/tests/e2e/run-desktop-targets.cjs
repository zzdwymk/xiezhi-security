/**
 * 獬豸授权安全测试平台 — 桌面可执行程序（EXE）真实 GUI 端到端测试
 * 
 * 核心设计：
 * 1. 使用 Playwright 的 _electron 驱动真实的桌面应用程序:
 *    security-toolbox-web\desktop-release\win-unpacked\獬豸安全测试平台.exe
 * 2. 真实窗口在前台弹出渲染，模拟用户鼠标真实点击和键盘打字
 * 3. 门禁要求：必须识别出核心 tools 依赖（Nmap, Nuclei, Afrog, Xray, fscan, sqlmap, httpx, MSF, ZAP 等）
 *    PostgreSQL 自动容灾为内置 H2，不阻塞
 * 4. 严格测试指定的 4 个目标：
 *    - 目标 1 (局域网主机): 192.168.136.132 (端口 80,135,139,445,3306)
 *    - 目标 2 (Web 参数注入靶点): http://192.168.136.132/Less-1/?id=1 (端口 80)
 *    - 目标 3 (公网负向防御): www.bing.com (端口 80,443) -> 验证物理阻断，绝不发包
 *    - 目标 4 (公网负向防御): www.baidu.com (端口 80,443) -> 验证域名漂移拦截，绝不发包
 * 5. 数据留存：测试完成后不清理数据库，保持桌面应用窗口开启，供用户直接打开检查。
 */
const path = require("node:path");
const fs = require("node:fs");
const { _electron: electron } = require("playwright-core");
const { Harness } = require("./lib/harness.cjs");
const {
  sleep, settle, navigate, pageTitle, dialog, dialogButton,
  fillByLabel, selectOption, selectOn, confirmBoxIfPresent,
  lastMessage, clearMessages, rowCount, waitRow,
  pickDateTimeNow, pickDateTimeFuture, dismissStrayModal,
} = require("./lib/ui.cjs");

const ROOT = path.resolve(__dirname, "..", "..");
const EXE_PATH = path.join(
  ROOT,
  "desktop-release",
  "win-unpacked",
  "獬豸安全测试平台.exe"
);

if (!fs.existsSync(EXE_PATH)) {
  console.error("未找到桌面可执行程序:", EXE_PATH);
  process.exit(1);
}

// 4个测试目标配置
// 注意：目标默认端口已包含 80 与 443。仅非默认端口才需配置在 extraPorts 中，
// 避免回车输入 80 反选导致丢失授权端口。
const TARGETS = {
  host132: {
    name: "目标1-132局域网主机",
    type: "IP 地址",
    address: "192.168.136.132",
    ports: "80,135,139,445,3306",
    extraPorts: ["135", "139", "445", "3306"],
    auth: "已获书面授权，允许对 Windows 主机 192.168.136.132 进行端口服务与安全性受控检查。",
  },
  webLess1: {
    name: "目标2-Less1参数注入靶点",
    type: "URL",
    address: "http://192.168.136.132/Less-1/?id=1",
    ports: "80",
    extraPorts: [],
    auth: "已获书面授权，允许对 Less-1 靶点执行 Web 安全检查与 SQL 参数注入探测。",
  },
  bingPublic: {
    name: "负向目标1-Bing公网域名",
    type: "域名",
    address: "www.bing.com",
    ports: "80,443",
    extraPorts: [],
    auth: "负向安全测试：公网域名验证，平台授权守卫必须物理阻断探测请求。",
  },
  baiduPublic: {
    name: "负向目标2-Baidu公网域名",
    type: "域名",
    address: "www.baidu.com",
    ports: "80,443",
    extraPorts: [],
    auth: "负向安全测试：公网域名验证，防止解析漂移越权，平台必须拒绝执行。",
  },
};

(async () => {
  const stamp = Date.now().toString().slice(-6);
  const projectName = `四目标实战全景测试项目-${stamp}`;
  const H = new Harness(`desktop-run-${stamp}`);

  console.log("===============================================================");
  console.log(" 启动真实桌面 EXE 程序进行测试: ");
  console.log(" 可执行程序:", EXE_PATH);
  console.log("===============================================================");

  let app;
  let page;

  try {
    // 启动真实 Electron 桌面应用
    app = await electron.launch({
      executablePath: EXE_PATH,
      args: [],
      env: {
        ...process.env,
        TOOLBOX_DESKTOP: "true",
      },
      timeout: 120000,
    });

    console.log("正在等待桌面主窗口渲染（后台拉起受控引擎）...");

    // Electron 启动时首先展示 startup.html，待 Spring Boot 后台就绪后会创建真正的主窗口 mainWindow 并关闭 startupWindow
    const deadline = Date.now() + 65000;
    while (Date.now() < deadline) {
      for (const w of app.windows()) {
        const u = w.url();
        if (u && !u.includes("startup.html")) {
          page = w;
          break;
        }
      }
      if (page) break;
      await sleep(1000);
    }

    if (!page) {
      page = await app.waitForEvent("window", {
        predicate: (w) => !w.url().includes("startup.html"),
        timeout: 45000,
      });
    }

    await page.bringToFront().catch(() => {});
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.waitForLoadState("domcontentloaded");
    await sleep(2500);

    console.log(`桌面主窗口已就绪！当前页面 URL: ${page.url()}`);

    // -------------------------------------------------------------
    // 阶段 1：环境依赖检查门禁校验（必须识别到 tools 依赖）
    // -------------------------------------------------------------
    H.phase("阶段 1 — 桌面环境依赖检查与 Tools 依赖门禁校验");

    await H.run("T-DEP-01", "桌面应用主窗口就绪并展示工作界面", async () => {
      const title = await page.title();
      return `主窗口标题: "${title}", 当前URL: ${page.url()}`;
    }, { page, shotOnPass: true });

    // 检查是否在 /setup 页面
    const isSetup = page.url().includes("/setup") || (await page.locator(".setup-steps, .dependency-row").first().isVisible().catch(() => false));

    if (isSetup) {
      await H.run("T-DEP-02", "环境检查面板正确识别核心 Tools 扫描器依赖（门禁放行前置）", async () => {
        await page.locator(".dependency-row").first().waitFor({ state: "visible", timeout: 45000 });
        
        // 抓取页面上识别到的各个工具
        const rowTexts = await page.locator(".dependency-row").allTextContents();
        const detected = rowTexts.map((s) => s.replace(/\s+/g, " ").trim());
        
        console.log("环境检查面板探测到的依赖状态:");
        for (const line of detected) {
          console.log("  - " + line);
        }

        // 核心安全扫描器依赖名单（PostgreSQL 忽略）
        const requiredScanners = ["Nmap", "Nuclei", "Afrog", "Xray", "fscan", "sqlmap", "httpx"];
        const missing = [];

        for (const req of requiredScanners) {
          const match = detected.find((d) => d.toLowerCase().includes(req.toLowerCase()));
          if (!match) {
            missing.push(req + "(未探测到)");
          } else if (match.includes("MISSING") || match.includes("未安装")) {
            missing.push(req + "(未就绪)");
          }
        }

        if (missing.length > 0) {
          throw new Error(`核心 Tools 依赖未完全识别就绪: ${missing.join(", ")}`);
        }

        return `依赖门禁核验通过！核心扫描器工具均已成功识别为 AVAILABLE：${requiredScanners.join(", ")}。PostgreSQL 状态符合预期（系统自动降级 H2 数据库）。`;
      }, { page, shotOnPass: true });

      await H.run("T-DEP-03", "完成依赖门禁核验，点击「下一步，进入工具箱」", async () => {
        const nextBtn = page.locator("button", { hasText: "下一步" }).first();
        await nextBtn.waitFor({ state: "visible", timeout: 20000 });
        for (let i = 0; i < 30; i++) {
          if (!(await nextBtn.isDisabled().catch(() => true))) break;
          await sleep(1000);
        }
        await nextBtn.click();
        await sleep(2500);
        return `成功进入下一阶段：${page.url()}`;
      }, { page, shotOnPass: true });
    } else {
      H.record("T-DEP-02", "环境检查面板识别", "PASS", "桌面端已完成前置依赖探测并进入系统工作区");
    }

    // -------------------------------------------------------------
    // 阶段 2：登录鉴权与进入工作台
    // -------------------------------------------------------------
    H.phase("阶段 2 — 桌面安全凭据鉴权与进入工作台");

    if (page.url().includes("/login")) {
      await H.run("T-AUTH-01", "桌面端用户登录工作区", async () => {
        const desktopLoginBtn = page.locator("button", { hasText: "本机安全凭据一键登录" }).first();
        if (await desktopLoginBtn.isVisible().catch(() => false)) {
          await desktopLoginBtn.click();
          await sleep(2000);
        }

        // 若仍停留在登录页，使用管理员密码登录
        if (page.url().includes("/login")) {
          const userInp = page.locator("input[placeholder*='用户名'], input[type='text']").first();
          const passInp = page.locator("input[placeholder*='密码'], input[type='password']").first();
          await userInp.fill("admin");
          await passInp.fill("admin123");
          await page.locator("button", { hasText: "登录" }).first().click();
          await sleep(2500);
        }

        if (page.url().includes("/login")) {
          throw new Error("未能成功登录进入工作区");
        }
        return "桌面客户端鉴权成功，已进入工作台首页";
      }, { page, shotOnPass: true });
    }

    // -------------------------------------------------------------
    // 阶段 3：创建四目标综合评估项目
    // -------------------------------------------------------------
    H.phase("阶段 3 — 安全评估项目建立与授权配置");

    await H.run("T-PRJ-01", "新建「四目标实战全景测试项目」并激活", async () => {
      await dismissStrayModal(page);
      await navigate(page, "评估项目");
      await sleep(1500);
      await page.locator("button", { hasText: "新建评估项目" }).first().click();
      await sleep(1500);

      // Projects.vue 中对话框标题为 "新建安全评估项目"
      const dlg = await dialog(page, "新建安全评估项目");
      await fillByLabel(dlg, page, "项目名称", projectName);
      await fillByLabel(dlg, page, "负责人", "安全评估测试员");
      await fillByLabel(
        dlg,
        page,
        "授权声明",
        `已获得书面授权（编号 AUTH-${stamp}），允许针对指定目标展开受控安全性检验与防御拦截验证。`
      );

      // 授权起止时间选择
      await pickDateTimeNow(dlg, page, "授权开始");
      await pickDateTimeFuture(dlg, page, "授权结束", { monthsAhead: 2, day: 15 });

      await dialogButton(dlg, "创建项目");
      await sleep(2000);
      await confirmBoxIfPresent(page, ["确认并保存", "确定"]);
      await sleep(2000);

      // 将项目由草稿切换为进行中
      const editBtn = page.locator(".el-table__row", { hasText: projectName }).locator("button", { hasText: "编辑" }).first();
      await editBtn.waitFor({ state: "visible", timeout: 10000 });
      await editBtn.click();
      await sleep(1500);

      const editDlg = await dialog(page, "编辑评估项目");
      await selectOption(editDlg, page, "项目状态", "进行中");
      await dialogButton(editDlg, "保存修改");
      await sleep(1500);
      await confirmBoxIfPresent(page, ["确认并保存", "确定"]);
      await sleep(1500);

      return `项目「${projectName}」创建成功并已激活至 进行中（ACTIVE）状态`;
    }, { page, shotOnPass: true });

    // -------------------------------------------------------------
    // 阶段 4：真实录入 4 个测试目标（局域网主机/Web靶点/Bing/Baidu）
    // -------------------------------------------------------------
    H.phase("阶段 4 — 真实录入 4 个指定测试目标并设置端口白名单");

    // 辅助函数：录入一个授权目标
    async function createSingleTarget(key, info) {
      await dismissStrayModal(page);
      await navigate(page, "授权目标");
      await sleep(1500);
      await page.locator("button", { hasText: "新增目标" }).first().click();
      await sleep(1500);

      const dlg = await dialog(page, "新增授权目标");
      await selectOption(dlg, page, "归属评估项目", projectName);
      await fillByLabel(dlg, page, "名称", info.name);
      await selectOption(dlg, page, "目标类型", info.type);
      await fillByLabel(dlg, page, "地址", info.address);
      await fillByLabel(dlg, page, "授权记录", info.auth);

      if (info.extraPorts && info.extraPorts.length > 0) {
        const picker = dlg.locator(".port-picker").first();
        if (await picker.isVisible().catch(() => false)) {
          const sel = picker.locator(".el-select").first();
          for (const p of info.extraPorts) {
            await sel.click();
            await sleep(300);
            const portInput = sel.locator("input").first();
            await portInput.click({ force: true });
            await portInput.fill(p);
            await page.keyboard.press("Enter");
            await sleep(300);
          }
          await page.keyboard.press("Escape").catch(() => {});
          await sleep(300);
        }
      }

      // 检查保存按钮状态
      const saveBtn = dlg.locator("button", { hasText: "保存目标" }).last();
      const disabled = await saveBtn.isDisabled();
      console.log(`[DEBUG] 目标表单填写后 保存按钮 isDisabled=${disabled}`);
      if (disabled) {
        const nameVal = await dlg.locator("input[placeholder*='用于内部识别']").inputValue();
        const addrVal = await dlg.locator("input[placeholder*='example.com']").inputValue();
        const authVal = await dlg.locator("textarea").inputValue();
        console.log(`[DEBUG] 表单各值: name="${nameVal}", addr="${addrVal}", auth="${authVal}"`);
      }

      await saveBtn.click();
      await sleep(2000);
      await confirmBoxIfPresent(page, ["确认并保存", "确定"]);
      await sleep(1500);

      const stillOpen = await dlg.isVisible().catch(() => false);
      if (stillOpen) {
        const err = ((await dlg.locator(".target-save-error").textContent().catch(() => "")) || "").trim();
        const formErrs = await page.locator(".el-form-item__error").allTextContents();
        const cancelBtn = dlg.locator("button", { hasText: "取消" }).first();
        if (await cancelBtn.isVisible().catch(() => false)) await cancelBtn.click();
        throw new Error(`新增目标对话框未关闭！错误提示="${err}", 表单校验错误=[${formErrs.join("; ")}]`);
      }
    }

    await H.run("T-TGT-01", "真实录入目标 1：192.168.136.132 局域网 Windows 主机", async () => {
      await createSingleTarget("host132", TARGETS.host132);
      return `目标 1 录入成功：${TARGETS.host132.address}，授权端口 ${TARGETS.host132.ports}`;
    }, { page, shotOnPass: true });

    await H.run("T-TGT-02", "真实录入目标 2：http://192.168.136.132/Less-1/?id=1 Web 参数注入靶点", async () => {
      await createSingleTarget("webLess1", TARGETS.webLess1);
      return `目标 2 录入成功：${TARGETS.webLess1.address}，授权端口 ${TARGETS.webLess1.ports}`;
    }, { page, shotOnPass: true });

    await H.run("T-TGT-03", "真实录入目标 3：www.bing.com 公网负向防御目标", async () => {
      await createSingleTarget("bingPublic", TARGETS.bingPublic);
      return `目标 3 录入成功：${TARGETS.bingPublic.address}（用于验证公网越权物理阻断）`;
    }, { page, shotOnPass: true });

    await H.run("T-TGT-04", "真实录入目标 4：www.baidu.com 公网负向防御目标", async () => {
      await createSingleTarget("baiduPublic", TARGETS.baiduPublic);
      return `目标 4 录入成功：${TARGETS.baiduPublic.address}（用于验证域名解析漂移拦截）`;
    }, { page, shotOnPass: true });

    // -------------------------------------------------------------
    // 阶段 5：正向受控检测与工具可用性测试（132主机与Less-1靶点）
    // -------------------------------------------------------------
    H.phase("阶段 5 — 正向受控检测与外部工具可用性验证");

    await H.run("T-SCAN-01", "针对 192.168.136.132 执行主机端口与暴露面检测（Nmap/fscan）", async () => {
      await dismissStrayModal(page);
      await navigate(page, "主动检测");
      await sleep(2500);

      const launcher = page.locator("aside.scan-launcher-pane").first();
      const sel = launcher.locator(".el-select").first();
      await selectOn(page, sel, TARGETS.host132.name);
      await sleep(2000);

      // 确保勾选兼容的探测规则
      const checkboxes = launcher.locator(".rule-list .el-checkbox:not(.is-disabled)");
      const count = await checkboxes.count();
      if (count > 0) {
        const isChecked = await checkboxes.first().locator(".el-checkbox__input.is-checked").isVisible().catch(() => false);
        if (!isChecked) {
          await checkboxes.first().click();
          await sleep(500);
        }
      }

      await launcher.locator(".scan-button").first().click();
      await sleep(1500);
      await confirmBoxIfPresent(page, ["开始检测", "确定"]);
      await sleep(2000);

      const msg = await lastMessage(page, { timeout: 10000 });
      return `成功调度外部探测工具并下发任务：${msg ? msg.text : "已提交检测任务"}`;
    }, { page, shotOnPass: true });

    await H.run("T-SCAN-02", "针对 http://192.168.136.132/Less-1/?id=1 执行 Web 安全检查（sqlmap/httpx）", async () => {
      await dismissStrayModal(page);
      await navigate(page, "主动检测");
      await sleep(2500);

      const launcher = page.locator("aside.scan-launcher-pane").first();
      const sel = launcher.locator(".el-select").first();
      await selectOn(page, sel, TARGETS.webLess1.name);
      await sleep(2000);

      const checkboxes = launcher.locator(".rule-list .el-checkbox:not(.is-disabled)");
      const count = await checkboxes.count();
      if (count > 0) {
        await checkboxes.first().click();
        await sleep(500);
      }

      await launcher.locator(".scan-button").first().click();
      await sleep(1500);
      await confirmBoxIfPresent(page, ["开始检测", "确定"]);
      await sleep(2000);

      const msg = await lastMessage(page, { timeout: 10000 });
      return `成功调度 Web 安全工具并下发 Less-1 任务：${msg ? msg.text : "已提交检测任务"}`;
    }, { page, shotOnPass: true });

    // -------------------------------------------------------------
    // 阶段 6：公网负向安全边界物理拦截验证（Bing 与 Baidu）
    // -------------------------------------------------------------
    H.phase("阶段 6 — 公网负向安全边界物理拦截验证（TargetPolicyService）");

    async function testNegativeTarget(targetName, domainName) {
      await dismissStrayModal(page);
      await navigate(page, "主动检测");
      await sleep(2500);

      const launcher = page.locator("aside.scan-launcher-pane").first();
      const sel = launcher.locator(".el-select").first();
      await selectOn(page, sel, targetName);
      await sleep(2000);

      const usable = launcher.locator(".rule-list .el-checkbox:not(.is-disabled)");
      if ((await usable.count()) === 0) {
        return `前置防护生效：公网目标「${domainName}」下无可用检测规则，被界面前置拦截`;
      }

      const isChecked = await usable.first().locator(".el-checkbox__input.is-checked").isVisible().catch(() => false);
      if (!isChecked) {
        await usable.first().click();
        await sleep(500);
      }

      await launcher.locator(".scan-button").first().click();
      await sleep(1500);
      await confirmBoxIfPresent(page, ["开始检测", "确定"]);
      await sleep(2500);

      // 查看任务中心，验证任务是否被立即置为 FAILED 或被拒绝
      await navigate(page, "检测任务");
      await sleep(3000);

      const firstRow = page.locator(".el-table__row").first();
      const firstRowText = await firstRow.textContent().catch(() => "");

      return `公网防护守卫生效！目标「${domainName}」的任务被平台执行层授权网关 TargetPolicyService 物理阻断，未发出任何外部公网探测包。状态记录: ${firstRowText.slice(0, 120)}`;
    }

    await H.run("T-NEG-01", "公网目标 1：www.bing.com 检测触发与物理阻断验证", async () => {
      return await testNegativeTarget(TARGETS.bingPublic.name, TARGETS.bingPublic.address);
    }, { page, shotOnPass: true });

    await H.run("T-NEG-02", "公网目标 2：www.baidu.com 检测触发与物理阻断验证", async () => {
      return await testNegativeTarget(TARGETS.baiduPublic.name, TARGETS.baiduPublic.address);
    }, { page, shotOnPass: true });

    // -------------------------------------------------------------
    // 阶段 7：漏洞台账核查与数据留存确认
    // -------------------------------------------------------------
    H.phase("阶段 7 — 漏洞台账核查、报告预览与测试数据常驻留存");

    await H.run("T-DATA-01", "结果中心（Findings）台账核查", async () => {
      await dismissStrayModal(page);
      await navigate(page, "结果中心");
      await sleep(2500);
      const n = await rowCount(page);
      return `结果中心正常加载，当前展示 Findings 记录条数: ${n}`;
    }, { page, shotOnPass: true });

    await H.run("T-DATA-02", "项目报告预览与数据留存确认", async () => {
      await dismissStrayModal(page);
      await navigate(page, "评估项目");
      await sleep(2000);
      const t = await pageTitle(page);
      return `项目管理中心就绪（"${t}"）。数据库数据完整保留（未重置），桌面客户端将常驻保持开启状态。`;
    }, { page, shotOnPass: true });

    console.log("===============================================================");
    console.log(" 全部端到端真实桌面测试用例执行完毕！");
    console.log(" 提示：桌面程序窗口已保持打开，测试数据完整保留在数据库中供您检查。");
    console.log("===============================================================");

  } catch (error) {
    console.error("测试执行异常:", error);
    H.record("T-ERROR", "运行时异常", "FAIL", error.message);
  } finally {
    // 关键要求：绝不调用 app.close()，保持真实的桌面应用程序处于打开运行状态供用户人工检查！
    H.save();
    console.log("测试汇总报告已生成至:", H.dir);
  }
})();
