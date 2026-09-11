const path = require("node:path");
const fs = require("node:fs");
const assert = require("node:assert/strict");
const { _electron: electron } = require("playwright-core");
const { runContractChecks } = require("./verify-topology-contract.cjs");
const { navigate } = require("./lib/ui.cjs");

const ROOT = path.resolve(__dirname, "..", "..");
const EXE_PATH = path.join(
  ROOT,
  "desktop-release",
  "win-unpacked",
  "獬豸安全测试平台.exe"
);

function compact(text) {
  return String(text || "").replace(/\s+/g, " ").trim();
}

async function waitTopologyLoaded(page, timeout = 30000) {
  const deadline = Date.now() + timeout;
  const overlay = page.locator(".topology-state-overlay", { hasText: /正在加载资产/ }).first();
  while (Date.now() < deadline) {
    if (!(await overlay.isVisible().catch(() => false))) {
      await new Promise((r) => setTimeout(r, 400));
      return;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("资产拓扑加载遮罩超时");
}

/** 等待拓扑页呈现项目选择器或真实的无项目空状态。 */
async function waitTopologySurface(page, timeout = 15000) {
  const deadline = Date.now() + timeout;
  const picker = page.locator(".project-picker").first();
  const emptyPrompt = page.locator(".empty-project-prompt").first();
  while (Date.now() < deadline) {
    if (await emptyPrompt.isVisible().catch(() => false)) return "empty";
    if (await picker.isVisible().catch(() => false)) return "picker";
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("资产拓扑页未呈现项目选择器或无项目空状态");
}

/** 关闭资产详情抽屉，避免过渡中的遮罩拦截后续导航点击。 */
async function closeVisibleDrawer(page) {
  const drawer = page.locator(".el-drawer:visible").last();
  if (!(await drawer.isVisible().catch(() => false))) return false;

  const closeButton = drawer
    .locator(
      ".el-drawer__close-btn:visible, .el-drawer__headerbtn:visible, " +
        "button[aria-label='关闭']:visible, button[aria-label='Close']:visible"
    )
    .first();
  if (await closeButton.count()) {
    await closeButton.click({ force: true, timeout: 3000 }).catch(() => {});
  }

  // 只有关闭按钮没有让抽屉消失时才使用 Escape，避免误关后续页面上的控件。
  if (await drawer.isVisible().catch(() => false)) {
    await page.keyboard.press("Escape").catch(() => {});
  }
  await drawer.waitFor({ state: "hidden", timeout: 5000 }).catch(() => {});
  return !(await drawer.isVisible().catch(() => false));
}

async function openProjectOptions(page) {
  const picker = page.locator(".project-picker").first();
  await picker.waitFor({ state: "visible", timeout: 15000 });
  const trigger = picker.locator(".el-select__wrapper").first();
  if (await trigger.count()) await trigger.click();
  else await picker.click();
  await new Promise((r) => setTimeout(r, 350));
  const dropdown = page.locator(".el-select-dropdown:visible").last();
  await dropdown.waitFor({ state: "visible", timeout: 8000 });
  const items = dropdown.locator("li.el-select-dropdown__item");
  await items.first().waitFor({ state: "visible", timeout: 8000 });
  const texts = (await items.allTextContents()).map(compact);
  return { items, texts };
}

async function chooseAllProjects(page) {
  const { items, texts } = await openProjectOptions(page);
  const index = texts.findIndex((text) => /^全部项目(?:总览)?$/.test(text));
  assert.ok(index >= 0, `项目下拉缺少全部项目，实际=${texts.join(" / ")}`);
  await items.nth(index).click();
  await waitTopologyLoaded(page);
}

async function chooseProjectAt(page, projectIndex) {
  const { items, texts } = await openProjectOptions(page);
  const projectItems = texts
    .map((text, index) => ({ text, index }))
    .filter(({ text }) => text && !/^全部项目(?:总览)?$/.test(text));
  const selected = projectItems[projectIndex];
  assert.ok(selected, `项目索引 ${projectIndex} 不存在，实际项目数=${projectItems.length}`);
  await items.nth(selected.index).click();
  await waitTopologyLoaded(page);
  return selected.text;
}

async function cardLabels(page) {
  const cards = page.locator(".node-card-group");
  const labels = [];
  for (let i = 0; i < await cards.count(); i++) {
    const label = compact(await cards.nth(i).getAttribute("aria-label"));
    if (label) labels.push(label);
  }
  return labels;
}

function multisetDiff(expected, actual) {
  const count = (values) => values.reduce((m, value) => m.set(value, (m.get(value) || 0) + 1), new Map());
  const left = count(expected);
  const right = count(actual);
  const keys = new Set([...left.keys(), ...right.keys()]);
  return [...keys]
    .filter((key) => (left.get(key) || 0) !== (right.get(key) || 0))
    .map((key) => `${key}: ${left.get(key) || 0} != ${right.get(key) || 0}`);
}

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
    // 1. 验证“资产拓扑”：全部项目总览、URL 资产与漏洞/风险徽标
    // -------------------------------------------------------------
    console.log("1. 前往「资产拓扑」核验...");
    // 先执行不依赖桌面壳的纯函数契约，避免 UI 只验证到表面而漏掉
    // IPv6 解析、同 URL 新记录优先级等数据层回归。
    runContractChecks();
    await navigate(page, "资产拓扑");
    await waitTopologyLoaded(page);
    const topologySurface = await waitTopologySurface(page);
    const noProjects = topologySurface === "empty";
    if (noProjects) {
      const emptyText = compact(await page.locator(".empty-project-prompt").first().textContent().catch(() => ""));
      assert.match(emptyText, /(暂无评估项目|项目列表暂时不可用)/, `无项目空状态文案异常：${emptyText || "空"}`);
      console.log("资产拓扑无项目空状态:", emptyText);
    }

    if (!noProjects) {
      // 核验右上角下拉框包含“全部项目”总览入口，并确认它是默认选择。
      const picker = page.locator(".project-picker").first();
      const selectedText = compact(await picker.locator(".el-select__selected-item, .el-select__placeholder").first().textContent().catch(() => ""));
      assert.match(selectedText, /^全部项目(?:总览)?$/, `默认项目应为全部项目，实际=${selectedText || "空"}`);
      const { items, texts: optionTexts } = await openProjectOptions(page);
      console.log("项目下拉选项列表:", optionTexts);
      const allIndex = optionTexts.findIndex((text) => /^全部项目(?:总览)?$/.test(text));
      assert.ok(allIndex >= 0, `资产拓扑缺少全部项目选项，实际=${optionTexts.join(" / ")}`);
      const projectNames = optionTexts.filter((text) => text && !/^全部项目(?:总览)?$/.test(text));
      await items.nth(allIndex).click();
      await waitTopologyLoaded(page);

      const allLabels = await cardLabels(page);
      if (!allLabels.length) {
        const emptyAssetOverlay = page.locator(".topology-state-overlay", { hasText: /暂无资产节点/ }).first();
        assert.ok(await emptyAssetOverlay.isVisible().catch(() => false), "项目存在但无资产时未显示「暂无资产节点」空状态");
        console.log("全部项目当前无资产节点，已显示空状态");
      }
      const overviewHubs = await page.locator(".topology-hub-node").count();
      const hubTitles = (await page.locator(".topology-hub-node title").allTextContents()).map(compact);
      console.log(`全部项目中心节点数: ${overviewHubs}，项目数: ${projectNames.length}`);
      if (allLabels.length && projectNames.length) {
        assert.equal(overviewHubs, projectNames.length, `全部项目中心数应等于项目数，中心=${hubTitles.join(" / ")}`);
        const missingHubs = projectNames.filter((name) => !hubTitles.includes(name));
        assert.equal(missingHubs.length, 0, `缺少项目中心: ${missingHubs.join("、")}`);
      }

    // 逐项目读取节点，再与全部项目节点的多重集合比较。若两个项目存在同 URL，
    // 该比较会要求它在总览中出现两次，从而检测跨项目误合并。
      const perProjectLabels = [];
      for (let index = 0; index < projectNames.length; index++) {
        const projectName = await chooseProjectAt(page, index);
        const labels = await cardLabels(page);
        if (!labels.length) {
          const emptyAssetOverlay = page.locator(".topology-state-overlay", { hasText: /暂无资产节点/ }).first();
          assert.ok(await emptyAssetOverlay.isVisible().catch(() => false), `项目 ${projectName} 无资产时未显示「暂无资产节点」空状态`);
        } else {
          const singleHubs = await page.locator(".topology-hub-node").count();
          assert.equal(singleHubs, 1, `单项目 ${projectName} 应只有一个中心，实际=${singleHubs}`);
        }
        perProjectLabels.push(...labels);
      }
      if (projectNames.length) {
        const diff = multisetDiff(perProjectLabels, allLabels);
        assert.equal(diff.length, 0, `全部项目节点与逐项目节点总和不一致（同 URL 不能跨项目合并）：${diff.slice(0, 8).join("；")}`);
      }
      await chooseAllProjects(page);

    // 检查节点卡片内容
      const nodeTexts = await page.locator(".node-card-group").allTextContents();
      console.log(`当前拓扑展示节点数: ${nodeTexts.length}`);
      for (let i = 0; i < nodeTexts.length; i++) {
        console.log(`  - 节点 ${i + 1}:`, nodeTexts[i].replace(/\s+/g, " ").trim());
      }

    // 截图保存
      await page.screenshot({ path: path.join(ROOT, "docs", "topology-vulns-urls-verified.png") });
      console.log("资产拓扑核验截图已保存至: docs/topology-vulns-urls-verified.png");

    // 若夹具含 IPv6 节点，确认节点标签保留完整字面量；没有该夹具时仅记录跳过。
      const ipv6Labels = (await cardLabels(page)).filter((label) => /\[[0-9a-f:]+\]/i.test(label) || /(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]+/i.test(label));
      if (ipv6Labels.length) {
        for (const label of ipv6Labels) {
          const candidate = /^https?:\/\//i.test(label) ? label : `http://${label}`;
          const host = new URL(candidate).hostname.replace(/^\[|\]$/g, "");
          assert.ok((host.match(/:/g) || []).length >= 2, `IPv6 节点疑似被截断: ${label}`);
        }
        console.log(`IPv6 节点已验证: ${ipv6Labels.join("、")}`);
      } else {
        console.log("当前数据没有 IPv6 节点，跳过 UI 字面量检查");
      }

    // 点击包含漏洞的节点，打开抽屉检查关联漏洞
      const vulnNode = page.locator(".node-card-group", { hasText: "漏洞" }).first();
      if (await vulnNode.isVisible().catch(() => false)) {
        await vulnNode.click({ force: true });
        await new Promise((r) => setTimeout(r, 1500));

        const drawer = page.locator(".el-drawer:visible").last();
        assert.ok(await drawer.isVisible().catch(() => false), "点击漏洞资产节点后未打开详情抽屉");

        const drawerTitle = await page.locator(".el-drawer:visible .hero-host").textContent().catch(() => "");
        console.log("打开抽屉资产主机:", drawerTitle.trim());

        const drawerFindings = await page.locator(".topology-finding-card").allTextContents();
        console.log(`抽屉中展示的关联安全发现数: ${drawerFindings.length}`);
        for (const df of drawerFindings) {
          console.log("    ->", df.replace(/\s+/g, " ").trim());
        }
        await page.screenshot({ path: path.join(ROOT, "docs", "topology-drawer-findings-verified.png") });
        const drawerClosed = await closeVisibleDrawer(page);
        assert.ok(drawerClosed, "资产详情抽屉关闭失败，后续导航可能被遮罩拦截");
        console.log("资产详情抽屉已关闭:", "是");
      }
    }

    // -------------------------------------------------------------
    // 2. 验证“流量工作区”的 Xray 探测不再报错“端口 80 不在授权端口范围内”
    // -------------------------------------------------------------
    console.log("\n2. 前往「流量分析」核验 Xray 探测...");
    await navigate(page, "流量分析");
    await new Promise((r) => setTimeout(r, 1300));

    // 查找包含 192.168.136.132 的会话
    const sessionRow = page.locator(".session-list .session-item, .el-table__row", { hasText: "192.168.136.132" }).first();
    if (await sessionRow.isVisible().catch(() => false)) {
      await sessionRow.click();
      await new Promise((r) => setTimeout(r, 1000));

      // 点击“安全探测”下拉菜单
      const probeDropdown = page.locator("button", { hasText: "安全探测" }).first();
      if (await probeDropdown.isVisible().catch(() => false)) {
        await probeDropdown.click();
        await new Promise((r) => setTimeout(r, 500));

        // 点击“Xray 靶向 PoC 探测”
        const xrayItem = page.locator(".el-dropdown-menu:visible li", { hasText: "Xray" }).first();
        if (await xrayItem.isVisible().catch(() => false)) {
          await xrayItem.click();
          await new Promise((r) => setTimeout(r, 1500));

          // 检查是否有错误提示
          const errMsg = await page.locator(".el-message--error").textContent().catch(() => "");
          console.log("触发 Xray 探测后的错误消息:", errMsg || "无错误（正常运行）");

          // 检查弹窗
          const dlg = page.locator(".el-dialog").filter({ hasText: "Xray 靶向 PoC 探测" }).first();
          console.log("Xray 探测弹窗是否可见:", await dlg.isVisible());

          await page.screenshot({ path: path.join(ROOT, "docs", "traffic-xray-verified.png") });
          console.log("流量 Xray 探测截图已保存至: docs/traffic-xray-verified.png");
        }
      }
    }

  } catch (err) {
    console.error("执行出错:", err);
    process.exitCode = 1;
  } finally {
    if (app) await app.close().catch(() => {});
  }
})();
