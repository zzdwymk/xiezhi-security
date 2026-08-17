const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright-core");

const baseUrl = process.env.VISUAL_BASE_URL || "http://127.0.0.1:4173";
const edgePath =
  process.env.EDGE_PATH ||
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const outputDir = path.resolve(__dirname, "..", "..", ".run", "visual-smoke");
const desktopViewports = [
  { width: 1000, height: 700 },
  { width: 1024, height: 768 },
  { width: 1280, height: 720 },
  { width: 1380, height: 860 },
  { width: 1440, height: 900 },
  { width: 1920, height: 1080 },
];
let showCatalogSyncProgress = false;

function pageResponse(content, page, size, total) {
  return {
    content,
    totalElements: total,
    totalPages: Math.ceil(total / size),
    number: page,
    size,
  };
}

function vulnerability(index) {
  return {
    id: index,
    vulnerabilityCode: `CVE-2026-${String(index).padStart(4, "0")}`,
    sourceExternalId: `CVE-2026-${String(index).padStart(4, "0")}`,
    name: `授权测试漏洞条目 ${index}`,
    severity: index % 2 ? "HIGH" : "MEDIUM",
    category: "Web 安全",
    description: "用于视觉回归的本地模拟条目。",
    detectionGuidance: "仅在授权范围内执行验证。",
    remediation: "升级受影响组件并复测。",
    sourceType: "BUILTIN",
      sourceName: "獬豸",
    sourceVersion: "visual-smoke",
    verificationStatus: "VERIFIED",
    scanSafety: "SAFE",
    knownExploited: false,
  };
}

function audit(index) {
  return {
    id: index,
    username: "admin",
    operator: "admin",
    action: `授权操作 ${index}`,
    resourceType: "PROJECT",
    resourceId: String(index),
    detail: "视觉回归记录",
    result: "SUCCESS",
    createdAt: "2026-07-31T10:00:00",
  };
}

function project(index) {
  return {
    id: index,
    name: `评估项目 ${index}`,
    description: "用于视觉回归的授权评估项目。",
    authorizationStatement: "已获得书面授权，仅限测试环境。",
    authorizationValidFrom: "2026-07-01T00:00:00",
    authorizationExpiresAt: "2026-12-31T23:59:59",
    status: "ACTIVE",
    owner: "admin",
    createdAt: "2026-07-01T10:00:00",
    updatedAt: "2026-07-31T10:00:00",
  };
}

function target(index, projectId = 1) {
  return {
    id: index,
    projectId,
    name: `授权目标 ${index}`,
    targetValue: `target-${index}.authorized.test`,
    targetType: "domain",
    authorizationNote: "视觉冒烟测试授权范围。",
    allowedPorts: "80,443",
    enabled: true,
    authorizationValidFrom: "2026-07-01T00:00:00",
    authorizationExpiresAt: "2026-12-31T23:59:59",
  };
}

function task(index, projectId = 1) {
  return {
    id: index,
    projectId,
    targetId: ((index - 1) % 41) + 1,
    toolCode: `project-task-${index}`,
    ruleCode: `SMOKE-${String(index).padStart(3, "0")}`,
    vulnerabilityCode: `CVE-2026-${String(index).padStart(4, "0")}`,
    status: "SUCCESS",
    progress: 100,
    progressDeterminate: true,
    progressCompleted: 1,
    progressTotal: 1,
    progressMessage: "已完成视觉冒烟测试",
    executionLog: "本地模拟执行记录",
    createdAt: "2026-07-31T10:00:00",
    startedAt: "2026-07-31T10:00:01",
    finishedAt: "2026-07-31T10:00:02",
  };
}

function finding(index, projectId = 1) {
  return {
    id: index,
    taskId: index,
    targetId: ((index - 1) % 41) + 1,
    title: `项目风险 ${index}`,
    severity: index % 2 ? "HIGH" : "MEDIUM",
    status: "OPEN",
    sourceTool: "visual-smoke",
    ruleCode: `SMOKE-${String(index).padStart(3, "0")}`,
    vulnerabilityCode: `CVE-2026-${String(index).padStart(4, "0")}`,
    description: "用于视觉回归的本地模拟风险。",
    evidence: "授权测试证据",
    remediation: "升级组件并复测。",
    projectId,
    createdAt: "2026-07-31T10:00:00",
  };
}

function approval(index, projectId = 1) {
  return {
    id: index,
    projectId,
    action: `审批 ${index}`,
    status: "APPROVED",
    requestedBy: "admin",
    approvedBy: "admin",
    comment: "视觉冒烟测试记录",
    authorizationSnapshotHash: `smoke-hash-${index}`,
    createdAt: "2026-07-31T10:00:00",
    decidedAt: "2026-07-31T10:01:00",
  };
}

function securityAction(index, projectId = 1) {
  return {
    id: index,
    projectId,
    targetId: ((index - 1) % 41) + 1,
    findingId: index,
    category: "VULNERABILITY_VALIDATION",
    title: `安全行动 ${index}`,
    purpose: "验证已授权目标上的已知风险。",
    riskLevel: "LOW",
    nonDestructive: true,
    lateralMovement: false,
    executionPlan: "仅执行白名单检查。",
    rollbackPlan: "无需回滚。",
    windowStart: "2026-07-31T10:00:00",
    windowEnd: "2026-07-31T18:00:00",
    status: "COMPLETED",
    requestedBy: "admin",
    approvedBy: "admin",
    createdAt: "2026-07-31T10:00:00",
  };
}

function memory(index, projectId = 1) {
  return {
    id: `memory-${index}`,
    title: `项目记忆 ${index}`,
    source: "visual-smoke",
    chars: 120 + index,
    conversationId: `conversation-${index}`,
    projectId,
    createdAt: "2026-07-31T10:00:00",
  };
}

function projectReport(id) {
  return {
    project: project(id),
    targets: fixtureTargets.map((item) => ({
      id: item.id,
      projectId: id,
      targetId: item.id,
    })),
    vulnerabilityDiscovery: fixtureTasks.map((item) => ({
      ...item,
      projectId: id,
    })),
    findings: fixtureFindings.map((item) => ({
      ...item,
      projectId: id,
    })),
    severityCounts: { HIGH: 21, MEDIUM: 20 },
    approvals: fixtureApprovals.map((item) => ({
      ...item,
      projectId: id,
    })),
    verification: { retestedFindings: 0, awaitingRetest: 41 },
    approvalAndAudit: { totalApprovals: 41, approved: 41, rejected: 0 },
    generatedAt: "2026-07-31T10:00:00",
  };
}

const fixtureProjects = Array.from({ length: 41 }, (_, index) =>
  project(index + 1),
);
const fixtureTargets = Array.from({ length: 41 }, (_, index) =>
  target(index + 1),
);
const fixtureTasks = Array.from({ length: 41 }, (_, index) =>
  task(index + 1),
);
const fixtureFindings = Array.from({ length: 41 }, (_, index) =>
  finding(index + 1),
);
const fixtureApprovals = Array.from({ length: 41 }, (_, index) =>
  approval(index + 1),
);
const fixtureSecurityActions = Array.from({ length: 41 }, (_, index) =>
  securityAction(index + 1),
);
const fixtureMemories = Array.from({ length: 41 }, (_, index) =>
  memory(index + 1),
);

function trafficSession(index) {
  return {
    id: index,
    method: index % 2 ? "GET" : "POST",
    url: `https://authorized.example.test/api/items/${index}`,
    host: "authorized.example.test",
    path: `/api/items/${index}`,
    statusCode: 200,
    protocol: "HTTP/2",
    riskLevel: "NONE",
    marked: false,
    requestHeaders: "Accept: application/json",
    responseHeaders: "Content-Type: application/json",
    requestBody: "",
    responseBody: '{"ok":true}',
    capturedAt: "2026-07-31T10:00:00",
  };
}

async function installApiMock(page) {
  await page.route("**/api/**", async (route) => {
    const requestUrl = new URL(route.request().url());
    const endpoint = requestUrl.pathname.replace(/^\/api/, "");
    let body = [];

    if (endpoint === "/auth/me") {
      body = { id: 1, username: "admin", role: "ADMIN" };
    } else if (endpoint === "/system/health") {
      body = { status: "UP" };
    } else if (endpoint === "/projects") {
      body = fixtureProjects;
    } else if (/^\/projects\/\d+$/.test(endpoint)) {
      const id = Number(endpoint.split("/").pop());
      body = project(id);
    } else if (/^\/projects\/\d+\/summary$/.test(endpoint)) {
      const id = Number(endpoint.split("/")[2]);
      body = projectReport(id);
    } else if (/^\/projects\/\d+\/targets$/.test(endpoint)) {
      const id = Number(endpoint.split("/")[2]);
      body = fixtureTargets.map((item) => ({
        id: item.id,
        projectId: id,
        targetId: item.id,
      }));
    } else if (/^\/projects\/\d+\/(approvals|security-actions)$/.test(endpoint)) {
      const id = Number(endpoint.split("/")[2]);
      body = endpoint.endsWith("approvals")
        ? fixtureApprovals.map((item) => ({ ...item, projectId: id }))
        : fixtureSecurityActions.map((item) => ({ ...item, projectId: id }));
    } else if (/^\/projects\/\d+\/(discovery|recon)\/results$/.test(endpoint)) {
      body = [];
    } else if (/^\/projects\/\d+\/security-actions$/.test(endpoint)) {
      body = fixtureSecurityActions;
    } else if (/^\/reports\/projects\/\d+\/summary$/.test(endpoint)) {
      const id = Number(endpoint.split("/")[3]);
      body = projectReport(id);
    } else if (endpoint === "/audits") {
      const pageNumber = Number(requestUrl.searchParams.get("page") || 0);
      const size = Number(requestUrl.searchParams.get("size") || 20);
      const start = pageNumber * size;
      const total = requestUrl.searchParams.has("projectId") ? 41 : 45;
      const content = Array.from(
        { length: Math.max(0, Math.min(size, total - start)) },
        (_, offset) =>
          requestUrl.searchParams.has("projectId")
            ? { ...audit(start + offset + 1), action: `项目审计 ${start + offset + 1}` }
            : audit(start + offset + 1),
      );
      body = pageResponse(content, pageNumber, size, total);
    } else if (endpoint === "/traffic/status") {
      body = {
        running: false,
        capturing: false,
        listenHost: "127.0.0.1",
        listenPort: 8080,
      };
    } else if (endpoint === "/traffic/sessions") {
      body = Array.from({ length: 45 }, (_, index) =>
        trafficSession(index + 1),
      );
    } else if (endpoint === "/traffic/filters") {
      body = [];
    } else if (endpoint === "/vulnerabilities") {
      const pageNumber = Number(requestUrl.searchParams.get("page") || 0);
      const size = Number(requestUrl.searchParams.get("size") || 20);
      const start = pageNumber * size;
      const content = Array.from(
        { length: Math.max(0, Math.min(size, 41 - start)) },
        (_, offset) => vulnerability(start + offset + 1),
      );
      body = pageResponse(content, pageNumber, size, 41);
    } else if (endpoint === "/vulnerabilities/stats") {
      body = {
        total: showCatalogSyncProgress ? 13550 : 41,
        builtin: 41,
        nuclei: showCatalogSyncProgress ? 13509 : 0,
        afrog: 0,
        xray: 0,
        knownExploited: 0,
        safeToScan: 41,
        templatesAvailable: showCatalogSyncProgress,
        syncing: showCatalogSyncProgress,
        afrogPocsAvailable: false,
        xrayPocsAvailable: false,
        afrogSyncing: false,
        xraySyncing: false,
      };
    } else if (endpoint === "/vulnerabilities/sync/status") {
      body = [
        {
          source: "NUCLEI",
          stage: showCatalogSyncProgress ? "IMPORTING" : "IDLE",
          processed: showCatalogSyncProgress ? 7420 : 0,
          total: showCatalogSyncProgress ? 13509 : 0,
          message: showCatalogSyncProgress ? "正在导入模板元数据" : "等待同步",
          startedAt: "2026-08-11T10:00:00Z",
          updatedAt: "2026-08-11T10:00:10Z",
          active: showCatalogSyncProgress,
        },
        {
          source: "AFROG",
          stage: "IDLE",
          processed: 0,
          total: 0,
          message: "等待同步",
          startedAt: "2026-08-11T10:00:00Z",
          updatedAt: "2026-08-11T10:00:00Z",
          active: false,
        },
        {
          source: "XRAY",
          stage: "IDLE",
          processed: 0,
          total: 0,
          message: "等待同步",
          startedAt: "2026-08-11T10:00:00Z",
          updatedAt: "2026-08-11T10:00:00Z",
          active: false,
        },
      ];
    } else if (endpoint === "/vulnerabilities/rules") {
      body = showCatalogSyncProgress
        ? [
            {
              id: 80,
              ruleCode: "RULE-NUCLEI-SAFE",
              vulnerabilityCode: "STB-NUCLEI-SAFE",
              name: "Nuclei 通用漏洞扫描",
              toolCode: "nuclei_scan",
              targetType: "ANY",
              riskLevel: "SAFE",
              enabled: true,
              sourceType: "NUCLEI",
              sourceName: "projectdiscovery/nuclei-templates",
            },
          ]
        : [];
    } else if (endpoint === "/system/dependencies") {
      body = {
        operatingSystem: "Windows",
        architecture: "amd64",
        dependencies: showCatalogSyncProgress
          ? [
              {
                name: "Nuclei",
                status: "AVAILABLE",
                installed: true,
                optional: true,
                category: "SCANNER",
              },
            ]
          : [],
      };
    } else if (endpoint === "/targets") {
      body = fixtureTargets;
    } else if (endpoint === "/tasks") {
      body = fixtureTasks;
    } else if (endpoint === "/tasks/control/status") {
      body = {
        maxConcurrentTasks: 4,
        availableConcurrentSlots: 4,
        maxConcurrentTasksPerTarget: 2,
        queueCapacity: 20,
        pendingTasks: 0,
        runningTasks: 0,
      };
    } else if (endpoint === "/ai/workflow/suggest") {
      const events = [
        {
          type: "suggestion",
          suggestion: {
            id: "coverage-gap-smoke",
            kind: "coverage_gap",
            severity: "warning",
            title: "缺少端口发现",
            detail: "当前直接进行服务识别，可能遗漏非默认端口上的服务。",
          },
        },
        {
          type: "suggestion",
          suggestion: {
            id: "orchestration-smoke",
            kind: "orchestration",
            severity: "info",
            title: "确保并行扫描汇聚后再进入漏洞发现",
            detail: "服务识别和 TLS 检查应全部完成后再触发 discovery。",
          },
        },
        {
          type: "suggestion",
          suggestion: {
            id: "retest-gap-smoke",
            kind: "retest_gap",
            severity: "info",
            title: "复测阶段缺少自动化检查",
            detail: "建议补充修复后的验证步骤。",
          },
        },
        { type: "done", source: "视觉冒烟数据", count: 3 },
      ];
      await route.fulfill({
        status: 200,
        contentType: "text/event-stream; charset=utf-8",
        body: events
          .map(
            (event) =>
              `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`,
          )
          .join(""),
      });
      return;
    } else if (endpoint === "/findings") {
      const pageNumber = Number(requestUrl.searchParams.get("page") || 0);
      const size = Number(requestUrl.searchParams.get("size") || 20);
      const start = pageNumber * size;
      body = pageResponse(
        fixtureFindings.slice(start, start + size),
        pageNumber,
        size,
        fixtureFindings.length,
      );
    } else if (/^\/ai\/memories$/.test(endpoint)) {
      body = fixtureMemories;
    } else if (/^\/fingerprints\/catalog$/.test(endpoint)) {
      body = { version: "visual-smoke", sha256: "smoke", ruleCount: 0 };
    } else if (endpoint === "/scan-schedules") {
      body = [];
    }

    await route.fulfill({
      status: 200,
      contentType: "application/json; charset=utf-8",
      body: JSON.stringify(body),
    });
  });
}

async function createPage(browser, viewport, reducedMotion = "reduce") {
  const context = await browser.newContext({
    viewport,
    colorScheme: "light",
    reducedMotion,
  });
  const page = await context.newPage();
  await installApiMock(page);
  await page.addInitScript(() => {
    localStorage.setItem("security_toolbox_setup_complete_v2", "true");
    localStorage.setItem("security_toolbox_token", "visual-smoke-token");
  });
  return { context, page };
}

async function verifyNavigationMotion(browser) {
  const { context, page } = await createPage(
    browser,
    { width: 1280, height: 800 },
    "no-preference",
  );
  await page.goto(`${baseUrl}/projects`, { waitUntil: "networkidle" });
  const indicator = page.locator(".desktop-v2-nav-indicator");
  await indicator.waitFor();
  await page.waitForTimeout(260);
  const readNavigationAlignment = async () => {
    const indicatorBox = await indicator.boundingBox();
    const activeBox = await page
      .locator(".desktop-v2-nav-item.active")
      .boundingBox();
    assert.ok(indicatorBox && activeBox, "主导航滑块与活动项应可测量");
    return {
      indicatorCenter: indicatorBox.y + indicatorBox.height / 2,
      activeCenter: activeBox.y + activeBox.height / 2,
    };
  };
  const before = await indicator.evaluate((element) => ({
    opacity: getComputedStyle(element).opacity,
    transform: getComputedStyle(element).transform,
    transitionProperty: getComputedStyle(element).transitionProperty,
    transitionDuration: getComputedStyle(element).transitionDuration,
    prefersReducedMotion: matchMedia("(prefers-reduced-motion: reduce)").matches,
  }));
  assert.equal(before.opacity, "1", "主导航滑动指示条应可见");
  assert.notEqual(
    before.transitionDuration,
    "0s",
    `主导航滑动指示条应启用过渡：${JSON.stringify(before)}`,
  );
  const initialAlignment = await readNavigationAlignment();
  assert.ok(
    Math.abs(initialAlignment.indicatorCenter - initialAlignment.activeCenter) <=
      1,
    `主导航滑块应与活动项垂直居中：${JSON.stringify(initialAlignment)}`,
  );

  const aiGroupToggle = page.locator('#nav-group-ai-workspace');
  await aiGroupToggle.click();
  await page.waitForTimeout(260);
  await aiGroupToggle.click();
  await page.waitForTimeout(110);
  const movingAlignment = await readNavigationAlignment();
  assert.ok(
    Math.abs(movingAlignment.indicatorCenter - movingAlignment.activeCenter) <=
      1,
    `其他分组折叠过程中滑块应持续居中：${JSON.stringify(movingAlignment)}`,
  );
  await page.waitForTimeout(180);

  await page
    .locator('.desktop-v2-nav-item:has-text("主动检测")')
    .evaluate((element) => element.click());
  await page.waitForURL(`${baseUrl}/vulnerabilities`);
  await page.waitForTimeout(110);
  const routeExpandedAlignment = await readNavigationAlignment();
  assert.ok(
    Math.abs(
      routeExpandedAlignment.indicatorCenter -
        routeExpandedAlignment.activeCenter,
    ) <= 1,
    `路由自动展开分组时滑块应持续居中：${JSON.stringify(routeExpandedAlignment)}`,
  );
  await page.waitForTimeout(180);
  await page
    .locator('.desktop-v2-nav-item:has-text("评估项目")')
    .click();
  await page.waitForURL(`${baseUrl}/projects`);
  await page.waitForTimeout(260);

  const projectsGroupToggle = page.locator(
    '#nav-group-projects-assets',
  );
  const projectsGroupItems = page.locator(
    '#nav-group-items-projects-assets',
  );
  const groupTransition = await projectsGroupItems.evaluate((element) => ({
    property: getComputedStyle(element).transitionProperty,
    duration: getComputedStyle(element).transitionDuration,
  }));
  assert.ok(
    groupTransition.property.includes("grid-template-rows"),
    `导航分组应按真实内容高度平滑折叠：${JSON.stringify(groupTransition)}`,
  );
  assert.notEqual(
    groupTransition.duration,
    "0s",
    `导航分组折叠动画应启用：${JSON.stringify(groupTransition)}`,
  );
  await projectsGroupToggle.click();
  await page.waitForTimeout(260);
  assert.equal(
    await indicator.evaluate((element) => getComputedStyle(element).opacity),
    "0",
    "活动项所在分组折叠后应隐藏主导航滑块",
  );
  await projectsGroupToggle.click();
  await page.waitForTimeout(460);
  const expandedAlignment = await readNavigationAlignment();
  assert.ok(
    Math.abs(
      expandedAlignment.indicatorCenter - expandedAlignment.activeCenter,
    ) <= 1,
    `导航分组展开后滑块应重新居中：${JSON.stringify(expandedAlignment)}`,
  );

  await page
    .locator('.desktop-v2-nav-item:has-text("授权目标")')
    .click();
  await page.waitForURL(`${baseUrl}/targets`);
  await page.waitForTimeout(260);
  const after = await indicator.evaluate((element) =>
    getComputedStyle(element).transform,
  );
  assert.notEqual(after, before.transform, "主导航指示条应移动到新路由");
  assert.equal(
    await page.locator(".desktop-v2-content").getAttribute("class"),
    "desktop-v2-content",
    "路由动画结束后应移除定位上下文，避免影响二级弹窗",
  );
  await context.close();
}

async function verifyOfflineToolIndicator(browser) {
  const { context, page } = await createPage(browser, {
    width: 1280,
    height: 800,
  });
  await page.goto(`${baseUrl}/offline-tools`, { waitUntil: "networkidle" });
  const indicator = page.locator(".offline-tool-indicator");
  const toolItems = page.locator(".offline-tool-item");
  await indicator.waitFor();
  await page.waitForTimeout(50);

  const readIndicatorState = async () => {
    const activeItem = page.locator(".offline-tool-item.active");
    const indicatorBox = await indicator.evaluate((element) => {
      const box = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return {
        opacity: style.opacity,
        left: box.left,
        width: box.width,
        top: box.top,
        height: box.height,
        transform: style.transform,
      };
    });
    const activeBox = await activeItem.evaluate((element) => {
      const box = element.getBoundingClientRect();
      return {
        label: element.textContent?.trim() || "",
        left: box.left,
        top: box.top,
        height: box.height,
      };
    });
    return { indicatorBox, activeBox };
  };

  const before = await readIndicatorState();
  assert.equal(before.indicatorBox.opacity, "1", "离线工具滑块应可见");
  assert.equal(before.indicatorBox.width, 3, "离线工具滑块应使用 3px Fluent 宽度");
  assert.ok(
    Math.abs(before.indicatorBox.left - before.activeBox.left) <= 1,
    `离线工具滑块应贴合活动项左边缘：${JSON.stringify(before)}`,
  );
  assert.ok(
    Math.abs(
      before.indicatorBox.top + before.indicatorBox.height / 2 -
        (before.activeBox.top + before.activeBox.height / 2),
    ) <= 1,
    `离线工具滑块应与活动项垂直居中：${JSON.stringify(before)}`,
  );

  await toolItems.nth(1).click();
  await page.waitForTimeout(260);
  const after = await readIndicatorState();
  assert.notEqual(after.activeBox.label, before.activeBox.label, "应切换活动离线工具");
  assert.notEqual(
    after.indicatorBox.transform,
    before.indicatorBox.transform,
    "离线工具滑块应移动到新活动项",
  );
  assert.ok(
    Math.abs(after.indicatorBox.left - after.activeBox.left) <= 1,
    `切换后滑块应贴合活动项左边缘：${JSON.stringify(after)}`,
  );
  assert.ok(
    Math.abs(
      after.indicatorBox.top + after.indicatorBox.height / 2 -
        (after.activeBox.top + after.activeBox.height / 2),
    ) <= 1,
    `切换后滑块应与活动项垂直居中：${JSON.stringify(after)}`,
  );
  await page.screenshot({
    path: path.join(outputDir, "offline-tool-indicator.png"),
  });
  await context.close();
}

async function verifySharedSelectionIndicators(browser) {
  const { context, page } = await createPage(
    browser,
    { width: 1440, height: 900 },
    "no-preference",
  );

  await page.goto(`${baseUrl}/traffic`, { waitUntil: "networkidle" });
  await page.locator(".traffic-row").first().waitFor();
  const trafficSelection = await page.locator(".traffic-row.active").evaluate((element) => ({
    background: getComputedStyle(element).backgroundColor,
    markerWidth: getComputedStyle(element, "::before").width,
    markerContent: getComputedStyle(element, "::before").content,
  }));
  assert.equal(trafficSelection.markerWidth, "3px", "流量列表应恢复固定 3px 选中边线");
  assert.notEqual(trafficSelection.markerContent, "none", "流量列表选中边线应可见");
  await page.locator(".traffic-row").nth(1).click();
  assert.equal(await page.locator(".traffic-row").nth(1).getAttribute("class"), "traffic-row active");

  const packetIndicator = page.locator(".packet-tabs-indicator");
  await packetIndicator.waitFor();
  await page.waitForTimeout(260);
  const packetBefore = await packetIndicator.evaluate(
    (element) => getComputedStyle(element).transform,
  );
  await page.locator(".packet-tabs button").nth(1).click();
  await page.waitForTimeout(260);
  const packetAfter = await packetIndicator.evaluate((element) => ({
    opacity: getComputedStyle(element).opacity,
    transform: getComputedStyle(element).transform,
  }));
  assert.equal(packetAfter.opacity, "1", "报文页签滑块应可见");
  assert.notEqual(packetAfter.transform, packetBefore, "切换报文页签时滑块应移动");

  await page.goto(`${baseUrl}/vulnerabilities`, { waitUntil: "networkidle" });
  await page.locator(".catalog-list button").first().waitFor();
  const catalogSelection = await page.locator(".catalog-list button.active").evaluate(
    (element) => getComputedStyle(element).boxShadow,
  );
  assert.match(catalogSelection, /inset/, "漏洞目录应恢复静态 inset 选中边线");
  await page.locator(".catalog-list button").nth(1).click();
  assert.equal(await page.locator(".catalog-list button").nth(1).getAttribute("class"), "active");

  await context.close();
}

async function verifyWorkflowStatusSummary(browser) {
  const { context, page } = await createPage(browser, {
    width: 1440,
    height: 900,
  });
  await page.goto(`${baseUrl}/workflow`, { waitUntil: "networkidle" });
  await page.locator(".workflow-status-row").waitFor();
  const chips = await page.locator(".workflow-status-row .status-chip").allTextContents();
  assert.equal(chips.length, 2, `工作流状态摘要应只保留两项：${chips.join(" | ")}`);
  assert.match(chips[0], /\d+ 个阶段 · \d+ 个能力 · \d+ 条连线/);
  assert.match(chips[1], /拓扑可保存|请修正拓扑后保存/);
  assert.doesNotMatch(
    chips.join(" "),
    /Workflow|Revision|Digest|固定入口|自动复核授权范围/,
    "工作流状态摘要不应重复展示持久化或说明性信息",
  );
  const actionRows = await page.locator(".workflow-actions > *").evaluateAll((items) =>
    items.map((item) => Math.round(item.getBoundingClientRect().top)),
  );
  assert.equal(
    new Set(actionRows).size,
    1,
    `桌面工作流操作区不应换行撑高页头：${actionRows.join(", ")}`,
  );
  const verticalGaps = await page.evaluate(() => {
    const status = document.querySelector(".workflow-status-row")?.getBoundingClientRect();
    const notice = document.querySelector(".graph-notice")?.getBoundingClientRect();
    const editor = document.querySelector(".workflow-editor-layout")?.getBoundingClientRect();
    return {
      statusToNotice: status && notice ? notice.top - status.bottom : null,
      noticeToEditor: notice && editor ? editor.top - notice.bottom : null,
    };
  });
  assert.ok(
    verticalGaps.statusToNotice !== null && verticalGaps.statusToNotice <= 6,
    `工作流状态与成功提示间距应保持紧凑：${JSON.stringify(verticalGaps)}`,
  );
  assert.ok(
    verticalGaps.noticeToEditor !== null && verticalGaps.noticeToEditor <= 6,
    `工作流成功提示与编辑区间距应保持紧凑：${JSON.stringify(verticalGaps)}`,
  );
  const nodeBoxes = await page.locator(".workflow-node").evaluateAll((nodes) =>
    nodes.map((node) => {
      const box = node.getBoundingClientRect();
      return {
        label: node.querySelector("strong")?.textContent?.trim() || "未命名节点",
        system: node.classList.contains("workflow-node--system"),
        x: box.x,
        y: box.y,
        width: box.width,
        height: box.height,
      };
    }),
  );
  assert.ok(nodeBoxes.length > 2, "工作流模板应渲染拓扑节点");
  assert.ok(
    nodeBoxes.every((box) => box.width >= (box.system ? 80 : 125)),
    `工作流默认缩放过小：${JSON.stringify(nodeBoxes.slice(0, 3))}`,
  );
  const phaseEntries = page.locator(".phase-library-item");
  assert.equal(
    await phaseEntries.count(),
    8,
    "右侧流程阶段区域应始终列出全部 8 个阶段",
  );
  const discoveryPhaseEntry = page.locator(
    '.phase-library-item[data-phase-code="discovery"]',
  );
  await discoveryPhaseEntry.waitFor();
  assert.match(
    await discoveryPhaseEntry.textContent(),
    /漏洞发现[\s\S]*流程阶段 · 用于组织能力和依赖/,
    "漏洞发现应作为流程阶段入口明确出现，不能混成能力卡",
  );
  assert.ok(
    await discoveryPhaseEntry.locator(".phase-library-action").isDisabled(),
    "默认工作流已包含漏洞发现时应显示已添加状态",
  );
  const mappingLibraryLabels = await page.locator(".library-copy strong").allTextContents();
  assert.deepEqual(
    mappingLibraryLabels,
    ["授权端口探测", "服务与版本识别", "Web 基础信息采集", "TLS 配置检查"],
    "资产发现阶段只应显示归属于该阶段的受控能力",
  );
  await page.locator('.capability-library-head .el-select').click();
  await page.getByRole("option", { name: "漏洞发现", exact: true }).click();
  const scannerNames = [
    "Nuclei 漏洞模板扫描",
    "Afrog PoC 漏洞扫描",
    "Xray PoC 漏洞扫描",
  ];
  const nodeLabels = nodeBoxes.map((box) => box.label);
  const libraryLabels = await page.locator(".library-copy strong").allTextContents();
  scannerNames.forEach((name) => {
    assert.ok(nodeLabels.includes(name), `默认工作流应包含独立的 ${name} 节点`);
    assert.ok(libraryLabels.includes(name), `漏洞发现阶段应包含独立的 ${name} 工具项`);
  });
  assert.ok(libraryLabels.includes("Web 风险检查"));
  assert.ok(
    libraryLabels.every((name) => !mappingLibraryLabels.includes(name)),
    `不同阶段不应显示相同能力卡：${libraryLabels.join("、")}`,
  );
  const discoveryNode = page.locator(
    ".workflow-node--phase.workflow-node--discovery",
  );
  await discoveryNode.locator(".node-remove").evaluate((button) => button.click());
  assert.equal(await discoveryNode.count(), 0, "漏洞发现阶段应能从画布删除");
  const restoreDiscoveryButton = discoveryPhaseEntry.locator(
    'button[aria-label="加回漏洞发现阶段"]',
  );
  assert.ok(
    await restoreDiscoveryButton.isEnabled(),
    "删除后漏洞发现阶段入口应允许加回画布",
  );
  await restoreDiscoveryButton.click();
  await discoveryNode.waitFor();
  assert.ok(
    await discoveryPhaseEntry.locator(".phase-library-action").isDisabled(),
    "加回后漏洞发现阶段应恢复为已添加状态",
  );
  assert.equal(
    await phaseEntries.count(),
    8,
    "阶段节点删除或恢复不应改变完整阶段入口数量",
  );
  await page.locator('.capability-library-head .el-select').click();
  await page.getByRole("option", { name: "被动侦察", exact: true }).click();
  assert.deepEqual(
    await page.locator(".library-copy strong").allTextContents(),
    ["项目情报检索"],
    "被动侦察阶段只应显示项目情报检索",
  );
  for (let first = 0; first < nodeBoxes.length; first += 1) {
    for (let second = first + 1; second < nodeBoxes.length; second += 1) {
      const a = nodeBoxes[first];
      const b = nodeBoxes[second];
      const overlapWidth = Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x);
      const overlapHeight = Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y);
      assert.ok(
        overlapWidth <= 1 || overlapHeight <= 1,
        `工作流节点不应重叠：${a.label} / ${b.label}`,
      );
    }
  }
  await page.screenshot({
    path: path.join(outputDir, "workflow-default-layout.png"),
  });

  await page.locator(".suggest-toggle").click();
  const suggestionTags = page.locator(".suggest-card .el-tag");
  await suggestionTags.first().waitFor();
  assert.deepEqual(
    await suggestionTags.allTextContents(),
    ["覆盖不足", "编排建议", "复测缺口"],
    "工作流建议类型应显示为通俗中文",
  );
  const suggestionCopy = await page.locator(".suggest-card").allTextContents();
  assert.doesNotMatch(
    suggestionCopy.join(" "),
    /coverage_gap|orchestration|retest_gap|\bdiscovery\b/i,
    "工作流建议不应暴露内部英文类型码或阶段码",
  );
  await page.screenshot({
    path: path.join(outputDir, "workflow-suggestions-localized.png"),
  });

  const editableNodes = page.locator(".workflow-node:not(.workflow-node--system)");
  const initialNodeCount = await page.locator(".workflow-node").count();
  await editableNodes.first().click();
  await page.keyboard.press("Delete");
  assert.equal(
    await page.locator(".workflow-node").count(),
    initialNodeCount - 1,
    "选中可删除节点后按 Delete 应删除节点",
  );

  const afterDeleteCount = await page.locator(".workflow-node").count();
  await page.locator(".workflow-node--system").first().click();
  await page.keyboard.press("Delete");
  assert.equal(
    await page.locator(".workflow-node").count(),
    afterDeleteCount,
    "开始和结束固定节点不应被键盘删除",
  );

  await editableNodes.first().click();
  await page.locator(".project-select input").focus();
  await page.keyboard.press("Delete");
  assert.equal(
    await page.locator(".workflow-node").count(),
    afterDeleteCount,
    "输入框聚焦时按 Delete 不应误删节点",
  );
  await context.close();
}

async function verifyDatePickerCorners(browser) {
  const { context, page } = await createPage(browser, {
    width: 1440,
    height: 900,
  });
  await page.goto(`${baseUrl}/projects`, { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "新建评估项目" }).click();
  const dialog = page.locator(".project-dialog");
  await dialog.waitFor();
  await dialog.locator(".el-date-editor").first().click();
  const picker = page.locator(".el-picker__popper:visible");
  await picker.waitFor();
  const corners = await picker.evaluate((element) => {
    const panel = element.querySelector(".el-picker-panel");
    return {
      popperRadius: getComputedStyle(element).borderRadius,
      popperOverflow: getComputedStyle(element).overflow,
      panelRadius: panel ? getComputedStyle(panel).borderRadius : "",
    };
  });
  assert.equal(
    corners.popperRadius,
    "8px",
    `日期弹层外框应使用 Fluent 圆角：${JSON.stringify(corners)}`,
  );
  assert.equal(corners.panelRadius, "8px", "日期面板应使用 Fluent 圆角");
  assert.equal(corners.popperOverflow, "hidden", "日期弹层应裁切直角背景");
  await page.screenshot({
    path: path.join(outputDir, "projects-date-picker.png"),
  });
  await context.close();
}

async function assertNoHorizontalOverflow(page, label) {
  const dimensions = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  assert.ok(
    dimensions.scrollWidth <= dimensions.clientWidth + 1,
    `${label} 出现横向溢出：${dimensions.scrollWidth}px > ${dimensions.clientWidth}px`,
  );
}

async function assertContainersDoNotOverflow(page, selectors, label) {
  for (const selector of selectors) {
    const locator = page.locator(selector).first();
    await locator.waitFor();
    const dimensions = await locator.evaluate((element) => ({
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
    }));
    assert.ok(
      dimensions.scrollWidth <= dimensions.clientWidth + 1,
      `${label} 的 ${selector} 出现横向裁切：${dimensions.scrollWidth}px > ${dimensions.clientWidth}px`,
    );
  }
}

async function assertFullyReachable(page, selector, label) {
  const locator = page.locator(selector).first();
  await locator.waitFor();
  await locator.scrollIntoViewIfNeeded();
  const geometry = await locator.evaluate((element) => {
    const rect = element.getBoundingClientRect();
    let left = Math.max(0, rect.left);
    let top = Math.max(0, rect.top);
    let right = Math.min(window.innerWidth, rect.right);
    let bottom = Math.min(window.innerHeight, rect.bottom);

    for (let ancestor = element.parentElement; ancestor; ancestor = ancestor.parentElement) {
      const style = getComputedStyle(ancestor);
      const ancestorRect = ancestor.getBoundingClientRect();
      if (["auto", "hidden", "scroll", "clip"].includes(style.overflowX)) {
        left = Math.max(left, ancestorRect.left);
        right = Math.min(right, ancestorRect.right);
      }
      if (["auto", "hidden", "scroll", "clip"].includes(style.overflowY)) {
        top = Math.max(top, ancestorRect.top);
        bottom = Math.min(bottom, ancestorRect.bottom);
      }
    }

    const visibleWidth = Math.max(0, right - left);
    const visibleHeight = Math.max(0, bottom - top);
    return {
      width: rect.width,
      height: rect.height,
      visibleWidth,
      visibleHeight,
    };
  });
  assert.ok(geometry.width > 0 && geometry.height > 0, `${label} 尺寸无效`);
  assert.ok(
    geometry.visibleWidth >= geometry.width - 1 &&
      geometry.visibleHeight >= geometry.height - 1,
    `${label} 未完整显示：可见 ${geometry.visibleWidth}x${geometry.visibleHeight}，实际 ${geometry.width}x${geometry.height}`,
  );
}

async function assertElementsDoNotOverlap(page, firstSelector, secondSelector, label) {
  const [first, second] = await Promise.all([
    page.locator(firstSelector).first().boundingBox(),
    page.locator(secondSelector).first().boundingBox(),
  ]);
  assert.ok(first && second, `${label} 无法读取元素边界`);
  const overlapWidth = Math.min(first.x + first.width, second.x + second.width) -
    Math.max(first.x, second.x);
  const overlapHeight = Math.min(first.y + first.height, second.y + second.height) -
    Math.max(first.y, second.y);
  assert.ok(
    overlapWidth <= 1 || overlapHeight <= 1,
    `${label} 出现遮挡：重叠 ${overlapWidth}x${overlapHeight}px`,
  );
}

async function gotoDesktopPage(page, route, readySelector) {
  await page.goto(`${baseUrl}${route}`, {
    waitUntil: "domcontentloaded",
  });
  await page.locator(".desktop-v2-app-frame").evaluate((element) => {
    element.classList.add("desktop-v2-native-frame");
  });
  await page.locator(readySelector).first().waitFor();
}

async function assertDialogBounds(page, label, native) {
  const overlay = page.locator(
    ".el-overlay:has(> .el-overlay-dialog):visible",
  );
  await overlay.waitFor();
  const [overlayBox, dialogBox, sidebarBox, mountedUnderBody, overlayRadius] = await Promise.all([
    overlay.boundingBox(),
    overlay.locator(".el-dialog").boundingBox(),
    page.locator("#desktop-v2-sidebar").boundingBox(),
    overlay.evaluate((element) => element.parentElement === document.body),
    overlay.evaluate((element) => parseFloat(getComputedStyle(element).borderTopLeftRadius)),
  ]);
  assert.ok(overlayBox && dialogBox, `${label} 无法读取对话框边界`);
  assert.equal(mountedUnderBody, true, `${label} 应挂载到 body 的统一弹层平面`);
  if (native) {
    assert.ok(overlayRadius >= 6, `${label} 遮罩左上角应跟随工作区圆角`);
  }
  const viewport = page.viewportSize();
  assert.ok(viewport, `${label} 无法读取视口尺寸`);
  const workspaceLeft = native ? sidebarBox?.width || 0 : 0;
  assert.ok(
    Math.abs(overlayBox.x - workspaceLeft) <= 1,
    `${label} 对话框遮罩起点错误：${overlayBox.x}px，应为 ${workspaceLeft}px`,
  );
  assert.ok(
    Math.abs(overlayBox.x + overlayBox.width - viewport.width) <= 1,
    `${label} 对话框遮罩右边界错误：${overlayBox.x + overlayBox.width}px，应为 ${viewport.width}px`,
  );
  assert.ok(
    Math.abs(overlayBox.width - (viewport.width - workspaceLeft)) <= 1,
    `${label} 对话框遮罩宽度错误：${overlayBox.width}px，应为 ${viewport.width - workspaceLeft}px`,
  );
  assert.ok(
    dialogBox.x >= workspaceLeft - 1 &&
      dialogBox.x + dialogBox.width <= viewport.width + 1 &&
      dialogBox.y >= -1 &&
      dialogBox.y + dialogBox.height <= viewport.height + 1,
    `${label} 对话框本体超出工作区或窗口：${JSON.stringify({
      dialogBox,
      overlayBox,
      sidebarBox,
      viewport,
      workspaceLeft,
    })}`,
  );
}

async function openSettingsDialogAndCheck(page, native, label, screenshotName) {
  await page
    .locator(".settings-row")
    .filter({ hasText: "AI 模型服务" })
    .click();
  await page.waitForTimeout(260);
  await assertDialogBounds(page, label, native);
  if (screenshotName) {
    await page.screenshot({
      path: path.join(outputDir, screenshotName),
    });
  }
  await page.keyboard.press("Escape");
  await page
    .locator(".el-overlay:has(> .el-overlay-dialog):visible")
    .waitFor({ state: "hidden" });
}

async function assertLastPage(page, paginationSelector, marker, label) {
  const pagination =
    typeof paginationSelector === "string"
      ? page.locator(paginationSelector).first()
      : paginationSelector.first();
  await pagination.waitFor();
  const lastPage = pagination.locator(".el-pager li.number").last();
  await lastPage.click();
  await page.getByText(marker, { exact: true }).first().waitFor();
  console.log(`${label} 已验证末页：${marker}`);
}

async function assertVisibleTabLastPage(page, tabName, marker, label) {
  await page.getByRole("tab", { name: tabName, exact: true }).click();
  await assertLastPage(
    page,
    page.locator(".el-tab-pane:visible .project-table-pagination"),
    marker,
    label,
  );
}

async function verifyResponsiveMatrix(browser) {
  for (const viewport of desktopViewports) {
    const size = `${viewport.width}x${viewport.height}`;
    const { context, page } = await createPage(browser, viewport);

    await gotoDesktopPage(page, "/settings", ".settings-page");
    await openSettingsDialogAndCheck(
      page,
      true,
      `${size} 原生设置对话框`,
      `responsive-settings-dialog-${size}.png`,
    );
    await assertNoHorizontalOverflow(page, `${size} 设置页`);
    await assertContainersDoNotOverflow(
      page,
      [".desktop-v2-workspace", ".desktop-v2-content", ".settings-page"],
      `${size} 设置页`,
    );
    await page.screenshot({
      path: path.join(outputDir, `responsive-settings-${size}.png`),
    });

    await gotoDesktopPage(page, "/traffic", ".traffic-row");
    await assertNoHorizontalOverflow(page, `${size} 流量工作区`);
    await assertContainersDoNotOverflow(
      page,
      [
        ".desktop-v2-workspace",
        ".desktop-v2-content",
        ".codex-traffic-page",
        ".codex-traffic-workbench",
      ],
      `${size} 流量工作区`,
    );
    await assertElementsDoNotOverlap(
      page,
      ".traffic-workspace-title",
      ".traffic-toolbar-actions",
      `${size} 流量工具栏`,
    );
    const trafficPaneWidths = await page.evaluate(() => ({
      sessions: document.querySelector(".traffic-session-rail")?.getBoundingClientRect().width || 0,
      detail: document.querySelector(".packet-editor-pane")?.getBoundingClientRect().width || 0,
    }));
    assert.ok(
      trafficPaneWidths.sessions >= 220,
      `${size} 流量会话栏过窄：${trafficPaneWidths.sessions}px`,
    );
    assert.ok(
      trafficPaneWidths.detail >= 320,
      `${size} 流量详情栏过窄：${trafficPaneWidths.detail}px`,
    );
    await page.screenshot({
      path: path.join(outputDir, `responsive-traffic-${size}.png`),
    });
    await assertFullyReachable(
      page,
      ".traffic-session-rail .el-pagination",
      `${size} 流量分页器`,
    );
    const deleteRow = page.locator(".traffic-row").last();
    await deleteRow.scrollIntoViewIfNeeded();
    await deleteRow.click({ button: "right" });
    await page
      .locator('.el-dropdown-menu__item:has-text("删除这条流量") >> visible=true')
      .first()
      .click();
    const overlay = page.locator("body > .el-overlay.is-message-box");
    await overlay.waitFor();
    const [overlayBox, sidebarBox, messageBox] = await Promise.all([
      overlay.boundingBox(),
      page.locator("#desktop-v2-sidebar").boundingBox(),
      page.locator(".el-message-box").boundingBox(),
    ]);
    assert.ok(overlayBox && sidebarBox && messageBox, `${size} 无法读取弹窗边界`);
    const messageOverlayRadius = await overlay.evaluate((element) =>
      parseFloat(getComputedStyle(element).borderTopLeftRadius),
    );
    assert.ok(messageOverlayRadius >= 6, `${size} 确认弹窗遮罩左上角应为圆角`);
    assert.ok(
      Math.abs(overlayBox.x - sidebarBox.width) <= 1,
      `${size} 弹窗遮罩没有从工作区开始`,
    );
    assert.ok(
      Math.abs(overlayBox.x + overlayBox.width - viewport.width) <= 1,
      `${size} 弹窗遮罩没有贴合工作区右边界`,
    );
    assert.ok(
      Math.abs(overlayBox.width - (viewport.width - sidebarBox.width)) <= 1,
      `${size} 弹窗遮罩宽度不是工作区宽度`,
    );
    assert.ok(
      messageBox.x >= sidebarBox.width &&
        messageBox.x + messageBox.width <= viewport.width + 1 &&
        messageBox.y >= 0 &&
        messageBox.y + messageBox.height <= viewport.height + 1,
      `${size} 确认弹窗超出工作区或窗口`,
    );
    await page.keyboard.press("Escape");
    await overlay.waitFor({ state: "hidden" });

    await gotoDesktopPage(page, "/audits", ".audits-pagination .el-pagination");
    await assertNoHorizontalOverflow(page, `${size} 审计日志`);
    await assertContainersDoNotOverflow(
      page,
      [".desktop-v2-workspace", ".desktop-v2-content", ".data-page"],
      `${size} 审计日志`,
    );
    await assertFullyReachable(
      page,
      ".audits-pagination .el-pagination",
      `${size} 审计分页器`,
    );
    await page.screenshot({
      path: path.join(outputDir, `responsive-audits-${size}.png`),
    });

    await gotoDesktopPage(
      page,
      "/vulnerabilities",
      ".catalog-pagination .el-pagination",
    );
    await assertNoHorizontalOverflow(page, `${size} 漏洞知识库`);
    await assertContainersDoNotOverflow(
      page,
      [
        ".desktop-v2-workspace",
        ".desktop-v2-content",
        ".vuln-workbench",
      ],
      `${size} 漏洞知识库`,
    );
    await assertFullyReachable(
      page,
      ".catalog-pagination .el-pagination",
      `${size} 漏洞分页器`,
    );
    const lastPage = page
      .locator(".catalog-pagination .el-pager li.number")
      .last();
    await lastPage.click();
    await page.getByText("CVE-2026-0041", { exact: true }).first().waitFor();
    await page.screenshot({
      path: path.join(outputDir, `responsive-vulnerabilities-${size}.png`),
    });

    await context.close();
  }
}

async function verifySettings(browser) {
  const { context, page } = await createPage(browser, {
    width: 1440,
    height: 900,
  });
  await page.goto(`${baseUrl}/settings`, { waitUntil: "networkidle" });
  await page.locator(".settings-page").waitFor();
  await openSettingsDialogAndCheck(page, false, "网页模式设置对话框");

  const titleStyles = await page
    .locator(".settings-group-title")
    .evaluateAll((elements) =>
      elements.map((element) => {
        const style = getComputedStyle(element);
        return {
          borderTop: style.borderTopWidth,
          borderRight: style.borderRightWidth,
          borderBottom: style.borderBottomWidth,
          borderLeft: style.borderLeftWidth,
          boxShadow: style.boxShadow,
        };
      }),
    );
  for (const style of titleStyles) {
    assert.deepEqual(
      [
        style.borderTop,
        style.borderRight,
        style.borderBottom,
        style.borderLeft,
      ],
      ["0px", "0px", "0px", "0px"],
      "设置页分组小标题不应带边框",
    );
    assert.equal(style.boxShadow, "none", "设置页分组小标题不应带阴影框");
  }
  await assertNoHorizontalOverflow(page, "桌面设置页");
  await page.screenshot({
    path: path.join(outputDir, "settings-desktop.png"),
    fullPage: true,
  });

  await page.setViewportSize({ width: 760, height: 900 });
  await page.waitForTimeout(100);
  await assertNoHorizontalOverflow(page, "窄屏设置页");
  await page.screenshot({
    path: path.join(outputDir, "settings-narrow.png"),
    fullPage: true,
  });
  await context.close();
}

async function verifyCatalogSyncProgress(browser) {
  const { context, page } = await createPage(browser, {
    width: 1440,
    height: 900,
  });
  try {
    await page.goto(`${baseUrl}/vulnerabilities`, { waitUntil: "networkidle" });
    const clearColor = await page
      .locator(".catalog-clear-action")
      .evaluate((element) => getComputedStyle(element).color);
    const colorParts = clearColor.match(/[\d.]+/g)?.map(Number) || [];
    assert.ok(
      colorParts.length >= 3 && colorParts[0] > colorParts[1] && colorParts[0] > colorParts[2],
      `漏洞库清空按钮应显式使用红色：${clearColor}`,
    );

    await page.locator(".catalog-filters .el-select").nth(1).click();
    const sourceOptions = await page.locator(".el-select-dropdown:visible .el-select-dropdown__item").allTextContents();
    assert.doesNotMatch(sourceOptions.join(" "), /獬豸内置/);
    await page.keyboard.press("Escape");

    showCatalogSyncProgress = true;
    await page.reload({ waitUntil: "networkidle" });
    const progress = page.locator(".catalog-sync-row");
    await progress.waitFor();
    assert.match(await progress.innerText(), /Nuclei.*正在导入模板元数据.*7420\/13509/s);

    await page.getByText("Nuclei 通用漏洞扫描", { exact: true }).click();
    await page.getByText("全部已同步", { exact: true }).waitFor();
    assert.match(
      await page.locator(".poc-help").filter({ hasText: "全部" }).innerText(),
      /13509 个 Nuclei PoC/,
    );
    await page.locator(".poc-selection-mode .el-segmented__item").nth(1).click();
    await page.locator(".poc-selector").waitFor();

    await page.screenshot({
      path: path.join(outputDir, "vulnerabilities-sync-progress.png"),
    });
  } finally {
    showCatalogSyncProgress = false;
    await context.close();
  }
}

async function verifyTraffic(browser) {
  const { context, page } = await createPage(browser, {
    width: 1440,
    height: 900,
  });
  await page.goto(`${baseUrl}/traffic`, { waitUntil: "networkidle" });
  await page.locator(".traffic-row").first().waitFor();
  await assertLastPage(
    page,
    ".traffic-session-rail .el-pagination",
    "/api/items/45",
    "流量会话",
  );

  const toolbarStyle = await page
    .locator(".codex-traffic-toolbar")
    .evaluate((element) => {
      const style = getComputedStyle(element);
      const pageStyle = getComputedStyle(element.parentElement);
      const pageBox = element.parentElement.getBoundingClientRect();
      const titleBox = element
        .querySelector(".traffic-workspace-title")
        .getBoundingClientRect();
      return {
        borderBottomWidth: style.borderBottomWidth,
        boxShadow: style.boxShadow,
        backgroundColor: style.backgroundColor,
        paddingInlineStart: style.paddingInlineStart,
        pagePaddingInlineStart: Number.parseFloat(pageStyle.paddingInlineStart),
        pagePaddingTop: Number.parseFloat(pageStyle.paddingTop),
        titleOffsetX: titleBox.x - pageBox.x,
        titleOffsetY: titleBox.y - pageBox.y,
      };
    });
  assert.equal(
    toolbarStyle.borderBottomWidth,
    "0px",
    "流量工作区标题栏不应叠加底部边框",
  );
  assert.equal(
    toolbarStyle.boxShadow,
    "none",
    "流量工作区标题栏不应使用独立阴影",
  );
  assert.equal(
    toolbarStyle.backgroundColor,
    "rgba(0, 0, 0, 0)",
    "流量工作区标题栏应沿用页面背景",
  );
  assert.equal(
    toolbarStyle.paddingInlineStart,
    "0px",
    "流量工作区标题栏不应叠加水平内边距",
  );
  assert.equal(
    toolbarStyle.titleOffsetX,
    toolbarStyle.pagePaddingInlineStart,
    "流量工作区标题应与页面左侧基线对齐",
  );
  assert.equal(
    toolbarStyle.titleOffsetY,
    toolbarStyle.pagePaddingTop,
    "流量工作区标题应与页面顶部基线对齐",
  );
  const trafficControlStyle = await page.evaluate(() => {
    const filter = document.querySelector(
      ".traffic-session-filter .el-input__wrapper",
    );
    const hint = document.querySelector(".traffic-points-foot > small");
    if (!filter || !hint) return null;
    const filterStyle = getComputedStyle(filter);
    const hintStyle = getComputedStyle(hint);
    const filterBox = filter.getBoundingClientRect();
    const hintBox = hint.getBoundingClientRect();
    const hintParentBox = hint.parentElement.getBoundingClientRect();
    const searchIcon = filter.querySelector(".el-input__prefix-inner");
    return {
      filterHeight: filterBox.height,
      filterRadius: filterStyle.borderRadius,
      filterBorderWidth: filterStyle.borderWidth,
      filterPaddingInlineStart: Number.parseFloat(filterStyle.paddingInlineStart),
      searchIconFontSize: searchIcon
        ? Number.parseFloat(getComputedStyle(searchIcon).fontSize)
        : 0,
      hintFontSize: Number.parseFloat(hintStyle.fontSize),
      hintLineHeight: Number.parseFloat(hintStyle.lineHeight),
      hintFits:
        hintBox.right <= hintParentBox.right + 1 &&
        hintBox.bottom <= hintParentBox.bottom + 1,
    };
  });
  assert.ok(trafficControlStyle, "无法读取流量筛选框或右侧提示样式");
  assert.equal(
    trafficControlStyle.filterHeight,
    32,
    "流量筛选框应使用 Fluent 2 的 32px 紧凑高度",
  );
  assert.equal(
    trafficControlStyle.filterRadius,
    "4px",
    "流量筛选框应使用 Fluent 2 的 4px 圆角",
  );
  assert.equal(
    trafficControlStyle.filterBorderWidth,
    "0px",
    "流量筛选框不应叠加实体边框与内描边",
  );
  assert.equal(
    trafficControlStyle.filterPaddingInlineStart,
    9,
    "流量筛选框应使用紧凑且清晰的左侧内边距",
  );
  assert.equal(
    trafficControlStyle.searchIconFontSize,
    14,
    "流量筛选框搜索图标应与正文保持协调",
  );
  const filterWrapper = page.locator(
    ".traffic-session-filter .el-input__wrapper",
  );
  const idleFilterShadow = await filterWrapper.evaluate(
    (element) => getComputedStyle(element).boxShadow,
  );
  await page.locator(".traffic-session-filter input").focus();
  await page.waitForTimeout(160);
  const focusedFilterShadow = await filterWrapper.evaluate(
    (element) => getComputedStyle(element).boxShadow,
  );
  assert.notEqual(
    focusedFilterShadow,
    idleFilterShadow,
    "流量筛选框聚焦时应显示 Fluent 底部强调线",
  );
  assert.match(
    focusedFilterShadow,
    /0px -2px 0px/,
    "流量筛选框聚焦态应使用 2px 底部强调线",
  );
  assert.ok(
    trafficControlStyle.hintFontSize >= 13,
    `右侧提示字号应清晰可读，实际 ${trafficControlStyle.hintFontSize}px`,
  );
  assert.ok(
    trafficControlStyle.hintLineHeight >= 19,
    `右侧提示行高应清晰可读，实际 ${trafficControlStyle.hintLineHeight}px`,
  );
  assert.ok(trafficControlStyle.hintFits, "右侧提示不应溢出底部提示区");
  await page.screenshot({
    path: path.join(outputDir, "traffic-workspace.png"),
    fullPage: true,
  });

  const sessionPagination = page.locator(
    ".traffic-session-rail .el-pagination",
  );
  await sessionPagination.scrollIntoViewIfNeeded();
  const [paginationBox, railBox] = await Promise.all([
    sessionPagination.boundingBox(),
    page.locator(".traffic-session-rail").boundingBox(),
  ]);
  assert.ok(paginationBox && railBox, "无法读取流量分页器或会话栏边界");
  assert.ok(
    paginationBox.y >= railBox.y &&
      paginationBox.y + paginationBox.height <= railBox.y + railBox.height + 1,
    "流量分页器滚动后仍应完整显示在会话栏内",
  );
  await page.screenshot({
    path: path.join(outputDir, "traffic-pagination.png"),
    fullPage: true,
  });

    await page
      .locator(".desktop-v2-app-frame")
      .evaluate((element) => element.classList.add("desktop-v2-native-frame"));
  await page
    .locator(".traffic-row")
    .first()
    .click({ button: "right" });
  await page
    .locator('.el-dropdown-menu__item:has-text("删除这条流量") >> visible=true')
    .first()
    .click();
  const overlay = page.locator("body > .el-overlay.is-message-box");
  await overlay.waitFor();
  const [overlayBox, sidebarBox] = await Promise.all([
    overlay.boundingBox(),
    page.locator("#desktop-v2-sidebar").boundingBox(),
  ]);
  assert.ok(overlayBox && sidebarBox, "无法读取弹窗遮罩或侧栏边界");
  assert.ok(
    Math.abs(overlayBox.x - sidebarBox.width) <= 1,
    `弹窗遮罩应从工作区开始：遮罩 ${overlayBox.x}px，侧栏 ${sidebarBox.width}px`,
  );
  const viewport = page.viewportSize();
  assert.ok(viewport, "无法读取流量页面视口尺寸");
  assert.ok(
    Math.abs(overlayBox.x + overlayBox.width - viewport.width) <= 1,
    `弹窗遮罩应贴合工作区右边界：实际 ${overlayBox.x + overlayBox.width}px，应为 ${viewport.width}px`,
  );
  assert.ok(
    Math.abs(overlayBox.width - (viewport.width - sidebarBox.width)) <= 1,
    `弹窗遮罩宽度应等于工作区宽度：实际 ${overlayBox.width}px，应为 ${viewport.width - sidebarBox.width}px`,
  );
  await page.screenshot({
    path: path.join(outputDir, "traffic-message-box-mask.png"),
    fullPage: true,
  });
  await context.close();
}

async function verifyPagination(browser) {
  const { context, page } = await createPage(browser, {
    width: 1280,
    height: 800,
  });

  await page.goto(`${baseUrl}/audits`, { waitUntil: "networkidle" });
  const auditPagination = page.locator(".audits-pagination .el-pagination");
  await auditPagination.waitFor();
  assert.match(await page.locator(".section-head p").innerText(), /45/);
  await assertLastPage(
    page,
    auditPagination,
    "授权操作 45",
    "审计日志",
  );
  await page.screenshot({
    path: path.join(outputDir, "audits-last-page.png"),
    fullPage: true,
  });

  await page.goto(`${baseUrl}/vulnerabilities`, { waitUntil: "networkidle" });
  const lastPage = page
    .locator(".catalog-pagination .el-pager li.number")
    .last();
  await lastPage.click();
  await page.getByText("CVE-2026-0041", { exact: true }).first().waitFor();
  await page.locator(".el-loading-mask:visible").waitFor({
    state: "hidden",
    timeout: 5_000,
  });
  await page.screenshot({
    path: path.join(outputDir, "vulnerabilities-last-page.png"),
    fullPage: true,
  });
  await context.close();
}

async function verifyFunctionalPagination(browser) {
  const { context, page } = await createPage(browser, {
    width: 1440,
    height: 900,
  });

  await page.goto(`${baseUrl}/traffic`, { waitUntil: "networkidle" });
  await page.locator(".traffic-row").first().waitFor();
  await assertLastPage(
    page,
    ".traffic-session-rail .el-pagination",
    "/api/items/45",
    "流量会话",
  );

  await page.goto(`${baseUrl}/tasks`, { waitUntil: "networkidle" });
  await page.locator(".tasks-page").waitFor();
  await assertLastPage(
    page,
    ".tasks-pagination .el-pagination",
    "project-task-41",
    "检测任务",
  );

  await page.goto(`${baseUrl}/findings`, { waitUntil: "networkidle" });
  await page.locator(".findings-page").waitFor();
  await assertLastPage(
    page,
    ".findings-pagination .el-pagination",
    "项目风险 41",
    "风险发现",
  );

  await page.goto(`${baseUrl}/targets`, { waitUntil: "networkidle" });
  await page.locator(".targets-page").waitFor();
  await assertLastPage(
    page,
    ".targets-pagination .el-pagination",
    "授权目标 41",
    "授权目标",
  );

  await page.goto(`${baseUrl}/projects`, { waitUntil: "networkidle" });
  await page.locator(".projects-page").waitFor();
  await assertLastPage(
    page,
    ".projects-pagination .el-pagination",
    "评估项目 41",
    "评估项目",
  );
  await page.getByText("进入项目", { exact: true }).first().click();
  await page.locator(".project-detail-page").waitFor();

  await assertVisibleTabLastPage(
    page,
    "授权目标",
    "授权目标 41",
    "项目详情授权目标",
  );
  await assertVisibleTabLastPage(
    page,
    "检测任务",
    "project-task-41",
    "项目详情检测任务",
  );
  await assertVisibleTabLastPage(
    page,
    "漏洞与复测",
    "项目风险 41",
    "项目详情漏洞",
  );
  await assertVisibleTabLastPage(
    page,
    "安全行动",
    "安全行动 41",
    "项目详情安全行动",
  );

  await page.getByRole("tab", { name: "审批与审计", exact: true }).click();
  const auditPagers = page.locator(
    ".el-tab-pane:visible .project-table-pagination",
  );
  await auditPagers.nth(0).waitFor();
  await auditPagers.nth(0).locator(".el-pager li.number").last().click();
  await page.getByText("审批 41", { exact: true }).first().waitFor();
  console.log("项目详情审批 已验证末页：审批 41");
  await auditPagers.nth(1).locator(".el-pager li.number").last().click();
  await page.getByText("项目审计 41", { exact: true }).first().waitFor();
  console.log("项目详情审计 已验证末页：项目审计 41");

  await assertVisibleTabLastPage(
    page,
    "AI 记忆",
    "项目记忆 41",
    "项目详情 AI 记忆",
  );
  await page.screenshot({
    path: path.join(outputDir, "functional-project-detail-last-pages.png"),
    fullPage: true,
  });
  await context.close();
}

async function main() {
  assert.ok(fs.existsSync(edgePath), `未找到 Edge：${edgePath}`);
  fs.mkdirSync(outputDir, { recursive: true });
  const browser = await chromium.launch({
    executablePath: edgePath,
    headless: true,
  });
  try {
    if (process.env.VISUAL_WORKFLOW_ONLY === "1") {
      await verifyWorkflowStatusSummary(browser);
    } else {
      await verifyNavigationMotion(browser);
      await verifyOfflineToolIndicator(browser);
      await verifySharedSelectionIndicators(browser);
      await verifyWorkflowStatusSummary(browser);
      await verifyDatePickerCorners(browser);
      await verifySettings(browser);
      await verifyCatalogSyncProgress(browser);
      await verifyTraffic(browser);
      await verifyPagination(browser);
      await verifyFunctionalPagination(browser);
      await verifyResponsiveMatrix(browser);
    }
  } finally {
    await browser.close();
  }
  console.log(`视觉冒烟测试通过，截图目录：${outputDir}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
