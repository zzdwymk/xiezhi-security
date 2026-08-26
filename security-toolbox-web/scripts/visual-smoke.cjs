const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright-core");

const baseUrl = process.env.VISUAL_BASE_URL || "http://127.0.0.1:4173";
function findBrowser() {
  if (process.env.EDGE_PATH && fs.existsSync(process.env.EDGE_PATH)) {
    return process.env.EDGE_PATH;
  }
  const names =
    process.platform === "win32"
      ? ["msedge.exe", "chrome.exe"]
      : ["microsoft-edge", "google-chrome", "chromium", "chromium-browser"];
  for (const directory of (process.env.PATH || "").split(path.delimiter)) {
    if (!directory) continue;
    for (const name of names) {
      const candidate = path.join(directory, name);
      if (fs.existsSync(candidate)) return candidate;
    }
  }
  return null;
}

const edgePath = findBrowser();
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

function scannerVulnerability(index, source) {
  const prefix = { NUCLEI: "NU", AFROG: "AF", XRAY: "XR" }[source];
  const code = `${prefix}-${index.toString(16).toUpperCase().padStart(24, "0")}`;
  return {
    ...vulnerability(index),
    vulnerabilityCode: code,
    sourceExternalId: `${source.toLowerCase()}-safe-${index}`,
    name: `${source} 安全 PoC ${index}`,
    sourceType: source,
    sourceName: `${source} 本地已复核目录`,
    scanSafety: "SAFE",
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
    controlledPostExploitation: {
      recordedTasks: 0,
      safetyBoundary:
        "高影响动作仅允许在审批通过的授权窗口内执行，并必须保留完整审计证据。",
    },
    approvalAndAudit: { totalApprovals: 41, approved: 41, rejected: 0 },
    generatedAt: "2026-07-31T10:00:00",
  };
}

const fixtureProjects = Array.from({ length: 41 }, (_, index) =>
  project(index + 1),
);
const fixtureTargets = Array.from({ length: 41 }, (_, index) => {
  const item = target(index + 1);
  if (index !== 1) return item;
  const {
    authorizationValidFrom: _authorizationValidFrom,
    authorizationExpiresAt: _authorizationExpiresAt,
    ...withoutTargetWindow
  } = item;
  return withoutTargetWindow;
});
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

async function installApiMock(page, role = "ADMIN") {
  let fingerprintCatalog = {
    version: "visual-smoke",
    sha256: "0".repeat(64),
    ruleCount: 409,
    source: "BUILTIN",
  };
  await page.route("**/api/**", async (route) => {
    const requestUrl = new URL(route.request().url());
    const endpoint = requestUrl.pathname.replace(/^\/api/, "");
    let body = [];

    if (endpoint === "/auth/me") {
      body = { id: 1, username: role === "ADMIN" ? "admin" : "analyst", role };
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
            ? start + offset === 0
              ? {
                  ...audit(1),
                  action: "AI_AGENT_TURN",
                  resourceType: "PROJECT",
                  resourceId: "1",
                  detail: JSON.stringify({ executed: false, taskIds: [] }),
                }
              : {
                  ...audit(start + offset + 1),
                  action: `项目审计 ${start + offset + 1}`,
                }
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
      const source = requestUrl.searchParams.get("source");
      if (["NUCLEI", "AFROG", "XRAY"].includes(source)) {
        const content = Array.from({ length: 3 }, (_, index) =>
          scannerVulnerability(index + 1, source),
        );
        body = pageResponse(content, 0, size, content.length);
      } else {
        const start = pageNumber * size;
        const content = Array.from(
          { length: Math.max(0, Math.min(size, 41 - start)) },
          (_, offset) => vulnerability(start + offset + 1),
        );
        body = pageResponse(content, pageNumber, size, 41);
      }
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
      if (route.request().method() === "PUT") {
        fingerprintCatalog = {
          version: "visual-upload",
          sha256: "a".repeat(64),
          ruleCount: 1,
          source: "MANAGED",
        };
      }
      body = fingerprintCatalog;
    } else if (endpoint === "/scan-schedules") {
      if (route.request().method() === "POST") {
        const payload = route.request().postDataJSON();
        body = {
          id: 99,
          ...payload,
          parametersJson: JSON.stringify(payload.parameters || {}),
          enabled: true,
          nextRunAt: "2026-08-21T03:00:00Z",
        };
      } else {
        body = [];
      }
    }

    await route.fulfill({
      status: 200,
      contentType: "application/json; charset=utf-8",
      body: JSON.stringify(body),
    });
  });
}

async function createPage(
  browser,
  viewport,
  reducedMotion = "reduce",
  role = "ADMIN",
) {
  const context = await browser.newContext({
    viewport,
    colorScheme: "light",
    reducedMotion,
  });
  const page = await context.newPage();
  await installApiMock(page, role);
  await page.addInitScript(() => {
    localStorage.setItem("security_toolbox_setup_complete_v2", "true");
    localStorage.setItem("security_toolbox_token", "visual-smoke-token");
  });
  return { context, page };
}

async function verifyNavigationMotion(browser) {
  // During a grid height transition the active row continues moving between
  // requestAnimationFrame and Playwright's geometry read. Allow the resulting
  // subpixel/one-frame sampling delta while still rejecting a visibly detached
  // Fluent selection indicator.
  const movingAlignmentTolerance = 2;
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
      movingAlignmentTolerance,
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
    ) <= movingAlignmentTolerance,
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
  }, "no-preference");
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
  assert.equal(
    await page.locator(".workflow-actions .el-select").count(),
    0,
    "项目、目标和模板选择器应移入拓扑配置面板",
  );
  assert.deepEqual(
    (await page.locator(".workflow-actions .el-button").allTextContents()).map((text) =>
      text.trim(),
    ),
    ["保存工作流", "执行工作流"],
    "页头只应保留工作流主操作",
  );
  const headerDescription = page.locator(".workflow-head-copy > p");
  assert.match(
    (await headerDescription.textContent()) || "",
    /从任务启动到报告交付的完整闭环[\s\S]*汇合表示等待上游全部完成/,
    "工作流页头说明应完整显示",
  );
  const headerDescriptionMetrics = await headerDescription.evaluate((element) => {
    const style = getComputedStyle(element);
    return {
      clientHeight: element.clientHeight,
      scrollHeight: element.scrollHeight,
      overflow: style.overflow,
      lineClamp: style.webkitLineClamp,
    };
  });
  assert.ok(
    headerDescriptionMetrics.scrollHeight <= headerDescriptionMetrics.clientHeight + 1,
    `工作流页头说明不应被裁切：${JSON.stringify(headerDescriptionMetrics)}`,
  );
  assert.equal(headerDescriptionMetrics.overflow, "visible");
  assert.match(headerDescriptionMetrics.lineClamp, /^(none|unset)$/);
  const workflowSummary = page.locator(".workflow-context-summary");
  const workflowSummaryText = (await workflowSummary.textContent()) || "";
  assert.match(workflowSummaryText, /项目\s*评估项目 1/);
  assert.match(
    workflowSummaryText,
    /授权目标\s*授权目标 1 · target-1\.authorized\.test/,
  );
  assert.match(workflowSummaryText, /模板\s*标准红队评估/);
  const summaryOverflow = await workflowSummary.locator("span").evaluateAll((items) =>
    items.map((item) => ({
      width: item.clientWidth,
      scrollWidth: item.scrollWidth,
      height: item.clientHeight,
      scrollHeight: item.scrollHeight,
    })),
  );
  assert.ok(
    summaryOverflow.every(
      (item) =>
        item.scrollWidth <= item.width + 1 && item.scrollHeight <= item.height + 1,
    ),
    `工作流配置摘要不应截断：${JSON.stringify(summaryOverflow)}`,
  );
  const workflowConfigButton = page
    .locator(".editor-head-actions")
    .getByRole("button", { name: "工作流配置", exact: true });
  await workflowConfigButton.click();
  const workflowConfigPanel = page.locator(".workflow-config-panel");
  await workflowConfigPanel.waitFor();
  assert.equal(await workflowConfigPanel.locator(".project-select").count(), 1);
  assert.equal(await workflowConfigPanel.locator(".target-select").count(), 1);
  assert.equal(await workflowConfigPanel.locator(".preset-select").count(), 1);
  const [configCanvasBox, configPanelBox] = await Promise.all([
    page.locator(".flow-canvas").boundingBox(),
    workflowConfigPanel.boundingBox(),
  ]);
  assert.ok(configCanvasBox && configPanelBox, "工作流配置面板应可见");
  assert.ok(
    configPanelBox.x >= configCanvasBox.x - 1 &&
      configPanelBox.y >= configCanvasBox.y - 1 &&
      configPanelBox.x + configPanelBox.width <=
        configCanvasBox.x + configCanvasBox.width + 1 &&
      configPanelBox.y + configPanelBox.height <=
        configCanvasBox.y + configCanvasBox.height + 1,
    `工作流配置面板应完整位于画布内：${JSON.stringify({ configCanvasBox, configPanelBox })}`,
  );
  await workflowConfigPanel
    .getByRole("button", { name: "关闭工作流配置", exact: true })
    .click();
  await assert.doesNotReject(workflowConfigPanel.waitFor({ state: "hidden" }));
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
  const phaseToggle = page.locator(".phase-library .library-section-toggle");
  const capabilityToggle = page.locator(
    ".capability-library .library-section-toggle",
  );
  const toggleChevronBoxes = [];
  for (const [name, toggle] of [
    ["流程阶段", phaseToggle],
    ["受控能力", capabilityToggle],
  ]) {
    const titleBox = await toggle.locator("h5").boundingBox();
    const chevronBox = await toggle
      .locator(".library-section-chevron")
      .boundingBox();
    assert.ok(titleBox && chevronBox, `${name}折叠标题和箭头应可见`);
    assert.ok(
      chevronBox.x < titleBox.x && titleBox.x - (chevronBox.x + chevronBox.width) <= 12,
      `${name}折叠箭头应紧邻标题左侧：${JSON.stringify({ titleBox, chevronBox })}`,
    );
    toggleChevronBoxes.push(chevronBox);
  }
  assert.ok(
    Math.abs(toggleChevronBoxes[0].x - toggleChevronBoxes[1].x) <= 2,
    `两个折叠箭头应纵向对齐：${JSON.stringify(toggleChevronBoxes)}`,
  );
  const capabilitySelectBox = await page
    .locator(".capability-library-head .el-select")
    .boundingBox();
  assert.ok(capabilitySelectBox, "受控能力阶段选择器应可见");
  assert.ok(
    toggleChevronBoxes[1].x + toggleChevronBoxes[1].width < capabilitySelectBox.x,
    `受控能力折叠箭头不应与阶段选择器重叠：${JSON.stringify({
      chevronBox: toggleChevronBoxes[1],
      capabilitySelectBox,
    })}`,
  );
  assert.equal(await phaseToggle.getAttribute("aria-expanded"), "true");
  assert.equal(await capabilityToggle.getAttribute("aria-expanded"), "true");
  await phaseToggle.click();
  await capabilityToggle.click();
  await page.waitForTimeout(180);
  assert.equal(await phaseToggle.getAttribute("aria-expanded"), "false");
  assert.equal(await capabilityToggle.getAttribute("aria-expanded"), "false");
  assert.equal(
    await page
      .locator("#workflow-phase-library-body")
      .getAttribute("aria-hidden"),
    "true",
  );
  assert.equal(
    await page
      .locator("#workflow-capability-library-body")
      .getAttribute("aria-hidden"),
    "true",
  );
  await page.screenshot({
    path: path.join(outputDir, "workflow-libraries-collapsed.png"),
  });
  const libraryScroll = page.locator(".library-scroll");
  await libraryScroll.evaluate((element) => {
    element.scrollTop = 0;
  });
  await discoveryNode.evaluate((node) =>
    node.dispatchEvent(
      new MouseEvent("click", { bubbles: true, cancelable: true }),
    ),
  );
  await page.waitForTimeout(520);
  assert.equal(
    await phaseToggle.getAttribute("aria-expanded"),
    "false",
    "点击阶段节点不应改变用户手动收起的流程阶段区",
  );
  assert.equal(
    await capabilityToggle.getAttribute("aria-expanded"),
    "true",
    "点击阶段节点应只展开受控能力区",
  );
  assert.ok(
    await discoveryPhaseEntry.evaluate((element) =>
      element.classList.contains("is-selected"),
    ),
    "点击阶段节点仍应同步受控能力的阶段筛选",
  );
  const firstDiscoveryCapability = page.locator(
    '.capability-library .library-item[data-tool="http_security_check"]',
  );
  await firstDiscoveryCapability.waitFor();
  assert.ok(
    await firstDiscoveryCapability.isVisible(),
    "点击阶段节点后应定位到该阶段的首个受控能力",
  );
  const xrayToolNode = page
    .locator(".workflow-node--tool")
    .filter({ hasText: "Xray PoC 漏洞扫描" })
    .first();
  await libraryScroll.evaluate((element) => {
    element.scrollTop = 0;
  });
  await xrayToolNode.evaluate((node) =>
    node.dispatchEvent(
      new MouseEvent("click", { bubbles: true, cancelable: true }),
    ),
  );
  await page.waitForTimeout(520);
  assert.equal(
    await capabilityToggle.getAttribute("aria-expanded"),
    "true",
    "点击工具节点应自动展开受控能力区",
  );
  assert.equal(
    await phaseToggle.getAttribute("aria-expanded"),
    "false",
    "点击工具节点也不应展开流程阶段区",
  );
  const nodeInputSpacing = await page.locator(".node-input-editor").evaluate((editor) => {
    const editorBox = editor.getBoundingClientRect();
    const titleBox = editor.querySelector("h5")?.getBoundingClientRect();
    return titleBox ? titleBox.top - editorBox.top : null;
  });
  assert.ok(
    nodeInputSpacing !== null && nodeInputSpacing >= 10 && nodeInputSpacing <= 16,
    `已选节点标题与区块上边缘应保留适度留白：${nodeInputSpacing}`,
  );
  const selectedXrayCapability = page.locator(
    '.library-item.is-selected[data-tool="xray_scan"]',
  );
  await selectedXrayCapability.waitFor();
  const selectedCapabilityIndicator = await selectedXrayCapability.evaluate(
    (element) => {
      const itemBox = element.getBoundingClientRect();
      const itemStyle = getComputedStyle(element);
      const indicatorStyle = getComputedStyle(element, "::before");
      const indicatorHeight = Number.parseFloat(indicatorStyle.height);
      const indicatorTop =
        itemBox.top + itemBox.height / 2 - indicatorHeight / 2;
      return {
        content: indicatorStyle.content,
        width: Number.parseFloat(indicatorStyle.width),
        height: indicatorHeight,
        radius: indicatorStyle.borderRadius,
        centerDelta:
          indicatorTop + indicatorHeight / 2 -
          (itemBox.top + itemBox.height / 2),
        boxShadow: itemStyle.boxShadow,
      };
    },
  );
  assert.notEqual(
    selectedCapabilityIndicator.content,
    "none",
    "选中能力卡应显示 Fluent 左侧指示条",
  );
  assert.equal(
    selectedCapabilityIndicator.width,
    3,
    `选中能力卡指示条应使用 Fluent 3px 宽度：${JSON.stringify(selectedCapabilityIndicator)}`,
  );
  assert.equal(
    selectedCapabilityIndicator.height,
    24,
    `选中能力卡指示条应使用与其他列表一致的 24px 短条：${JSON.stringify(selectedCapabilityIndicator)}`,
  );
  assert.ok(
    Math.abs(selectedCapabilityIndicator.centerDelta) <= 1,
    `选中能力卡指示条应垂直居中：${JSON.stringify(selectedCapabilityIndicator)}`,
  );
  assert.equal(selectedCapabilityIndicator.radius, "999px");
  assert.equal(
    selectedCapabilityIndicator.boxShadow,
    "none",
    "选中能力卡不应继续使用贯穿整高的 inset 蓝边",
  );
  const [selectedCapabilityBox, selectedLibraryBox, libraryMetrics] = await Promise.all([
    selectedXrayCapability.boundingBox(),
    libraryScroll.boundingBox(),
    libraryScroll.evaluate((element) => ({
      scrollTop: element.scrollTop,
      scrollHeight: element.scrollHeight,
      clientHeight: element.clientHeight,
    })),
  ]);
  assert.ok(
    libraryMetrics.scrollHeight > libraryMetrics.clientHeight,
    `工作流能力库应具有真实溢出内容：${JSON.stringify(libraryMetrics)}`,
  );
  assert.ok(
    libraryMetrics.scrollTop > 1,
    `点击低位工具节点后能力库应发生滚动：${JSON.stringify(libraryMetrics)}`,
  );
  assert.ok(
    selectedCapabilityBox &&
      selectedLibraryBox &&
      selectedCapabilityBox.y >= selectedLibraryBox.y - 1 &&
      selectedCapabilityBox.y + selectedCapabilityBox.height <=
        selectedLibraryBox.y + selectedLibraryBox.height + 1,
    `点击工具节点后对应能力卡应定位到右侧可视区：${JSON.stringify({
      selectedCapabilityBox,
      selectedLibraryBox,
    })}`,
  );
  assert.deepEqual(
    await page.locator(".library-copy strong").allTextContents(),
    [
      "Web 风险检查",
      "Nuclei 漏洞模板扫描",
      "Afrog PoC 漏洞扫描",
      "Xray PoC 漏洞扫描",
    ],
    "折叠并重新展开后应保留所选阶段和能力列表",
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

  const flowPane = page.locator(".vue-flow__pane");
  const flowPaneBox = await flowPane.boundingBox();
  assert.ok(flowPaneBox, "工作流画布交互层应可见");
  await flowPane.click({
    button: "right",
    position: { x: Math.max(2, flowPaneBox.width - 4), y: Math.max(2, flowPaneBox.height - 4) },
  });
  const workflowContextMenu = page.locator(".workflow-context-menu");
  await workflowContextMenu.waitFor();
  assert.deepEqual(
    (await workflowContextMenu.getByRole("menuitem").allTextContents()).map((text) =>
      text.trim(),
    ),
    ["工作流配置", "新增授权输入", "载入所选模板", "使用说明", "适应画布"],
    "空白画布右键菜单应提供完整配置入口",
  );
  const [menuCanvasBox, contextMenuBox] = await Promise.all([
    page.locator(".flow-canvas").boundingBox(),
    workflowContextMenu.boundingBox(),
  ]);
  assert.ok(menuCanvasBox && contextMenuBox, "画布右键菜单应可见");
  assert.ok(
    contextMenuBox.x >= menuCanvasBox.x - 1 &&
      contextMenuBox.y >= menuCanvasBox.y - 1 &&
      contextMenuBox.x + contextMenuBox.width <= menuCanvasBox.x + menuCanvasBox.width + 1 &&
      contextMenuBox.y + contextMenuBox.height <= menuCanvasBox.y + menuCanvasBox.height + 1,
    `画布右键菜单应保持在画布边界内：${JSON.stringify({ menuCanvasBox, contextMenuBox })}`,
  );
  await page.keyboard.press("Escape");
  await assert.doesNotReject(workflowContextMenu.waitFor({ state: "hidden" }));

  const startNode = page.locator(".workflow-node--system").filter({ hasText: "开始" });
  await startNode.click({ button: "right" });
  await workflowContextMenu.waitFor();
  assert.deepEqual(
    (await workflowContextMenu.getByRole("menuitem").allTextContents()).map((text) =>
      text.trim(),
    ),
    ["配置运行范围"],
    "开始节点右键应直接配置运行范围",
  );
  await workflowContextMenu.getByRole("menuitem", { name: "配置运行范围" }).click();
  await workflowConfigPanel.waitFor();
  await workflowConfigPanel
    .getByRole("button", { name: "关闭工作流配置", exact: true })
    .click();

  const firstToolNode = page.locator(".workflow-node--tool").first();
  await firstToolNode.evaluate((element) => {
    const canvas = element.closest(".flow-canvas")?.getBoundingClientRect();
    if (!canvas) throw new Error("未找到工作流画布");
    element.dispatchEvent(
      new MouseEvent("contextmenu", {
        bubbles: true,
        cancelable: true,
        view: window,
        button: 2,
        buttons: 2,
        clientX: canvas.left + canvas.width / 2,
        clientY: canvas.top + canvas.height / 2,
      }),
    );
  });
  await workflowContextMenu.waitFor();
  assert.ok(
    await workflowContextMenu.getByRole("menuitem", { name: "配置节点参数" }).isVisible(),
    "工具节点右键应提供参数配置",
  );
  assert.ok(
    await workflowContextMenu.getByRole("menuitem", { name: "删除节点" }).isVisible(),
    "可编辑节点右键应提供删除入口",
  );
  await workflowContextMenu.getByRole("menuitem", { name: "配置节点参数" }).click();
  const nodeInputEditor = page.locator(".node-input-editor");
  await nodeInputEditor.waitFor();
  await page.waitForTimeout(240);
  const [nodeEditorBox, libraryBox] = await Promise.all([
    nodeInputEditor.boundingBox(),
    page.locator(".library-scroll").boundingBox(),
  ]);
  assert.ok(nodeEditorBox && libraryBox, "工具节点参数编辑区应可见");
  assert.ok(
    nodeEditorBox.y < libraryBox.y + libraryBox.height &&
      nodeEditorBox.y + nodeEditorBox.height > libraryBox.y,
    `右键配置节点后应将参数编辑区滚入视口：${JSON.stringify({ nodeEditorBox, libraryBox })}`,
  );

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
  await workflowConfigButton.click();
  await workflowConfigPanel.locator(".project-select input").focus();
  await page.keyboard.press("Delete");
  assert.equal(
    await page.locator(".workflow-node").count(),
    afterDeleteCount,
    "输入框聚焦时按 Delete 不应误删节点",
  );
  await workflowConfigPanel
    .getByRole("button", { name: "关闭工作流配置", exact: true })
    .click();
  await page.setViewportSize({ width: 760, height: 900 });
  await page.waitForTimeout(180);
  const narrowHeaderMetrics = await headerDescription.evaluate((element) => ({
    clientHeight: element.clientHeight,
    scrollHeight: element.scrollHeight,
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
  }));
  assert.ok(
    narrowHeaderMetrics.scrollHeight <= narrowHeaderMetrics.clientHeight + 1 &&
      narrowHeaderMetrics.scrollWidth <= narrowHeaderMetrics.clientWidth + 1,
    `窄屏工作流说明应完整换行：${JSON.stringify(narrowHeaderMetrics)}`,
  );
  const narrowSummaryOverflow = await workflowSummary.locator("span").evaluateAll((items) =>
    items.map((item) => ({
      width: item.clientWidth,
      scrollWidth: item.scrollWidth,
      height: item.clientHeight,
      scrollHeight: item.scrollHeight,
    })),
  );
  assert.ok(
    narrowSummaryOverflow.every(
      (item) =>
        item.scrollWidth <= item.width + 1 && item.scrollHeight <= item.height + 1,
    ),
    `窄屏工作流摘要不应截断：${JSON.stringify(narrowSummaryOverflow)}`,
  );
  await workflowConfigButton.click();
  await workflowConfigPanel.waitFor();
  const [narrowCanvasBox, narrowPanelBox] = await Promise.all([
    page.locator(".flow-canvas").boundingBox(),
    workflowConfigPanel.boundingBox(),
  ]);
  assert.ok(narrowCanvasBox && narrowPanelBox, "窄屏工作流配置面板应可见");
  assert.ok(
    narrowCanvasBox.height >= 400 &&
    narrowPanelBox.x >= narrowCanvasBox.x - 1 &&
      narrowPanelBox.y >= narrowCanvasBox.y - 1 &&
      narrowPanelBox.x + narrowPanelBox.width <= narrowCanvasBox.x + narrowCanvasBox.width + 1 &&
      narrowPanelBox.y + narrowPanelBox.height <= narrowCanvasBox.y + narrowCanvasBox.height + 1,
    `窄屏工作流画布和配置面板尺寸应稳定：${JSON.stringify({ narrowCanvasBox, narrowPanelBox })}`,
  );
  await page.screenshot({
    path: path.join(outputDir, "workflow-config-narrow.png"),
    fullPage: true,
  });
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

async function verifyDashboardComposer(browser) {
  const viewports = [
    { width: 1000, height: 700 },
    { width: 1440, height: 900 },
    { width: 1920, height: 1080 },
  ];

  for (const viewport of viewports) {
    const size = `${viewport.width}x${viewport.height}`;
    const { context, page } = await createPage(browser, viewport);
    await gotoDesktopPage(page, "/", ".welcome-composer");

    const refreshGeometry = await page
      .locator(".chat-header-actions .header-icon-button")
      .evaluate((button) => {
        const icon = button.querySelector(".el-icon");
        const glyph = button.querySelector(".fluent-system-icon");
        if (!icon || !glyph) return null;
        const geometry = (element) => {
          const rect = element.getBoundingClientRect();
          return {
            width: rect.width,
            height: rect.height,
            centerX: rect.x + rect.width / 2,
            centerY: rect.y + rect.height / 2,
          };
        };
        const style = getComputedStyle(button);
        return {
          button: geometry(button),
          icon: geometry(icon),
          glyph: geometry(glyph),
          boxSizing: style.boxSizing,
          padding: [
            style.paddingTop,
            style.paddingRight,
            style.paddingBottom,
            style.paddingLeft,
          ],
        };
      });
    assert.ok(refreshGeometry, `${size} 无法读取刷新按钮图标几何信息`);
    assert.ok(
      Math.abs(refreshGeometry.button.width - 36) <= 0.5 &&
        Math.abs(refreshGeometry.button.height - 36) <= 0.5,
      `${size} 刷新按钮应为 36x36：${JSON.stringify(refreshGeometry.button)}`,
    );
    assert.equal(refreshGeometry.boxSizing, "border-box");
    assert.deepEqual(refreshGeometry.padding, ["0px", "0px", "0px", "0px"]);
    assert.ok(
      Math.abs(refreshGeometry.icon.width - 18) <= 0.5 &&
        Math.abs(refreshGeometry.icon.height - 18) <= 0.5,
      `${size} 刷新按钮图标容器应为 18x18：${JSON.stringify(refreshGeometry.icon)}`,
    );
    assert.ok(
      Math.abs(refreshGeometry.glyph.width - 16) <= 0.5 &&
        Math.abs(refreshGeometry.glyph.height - 16) <= 0.5,
      `${size} 刷新按钮 Fluent 图标应为 16x16：${JSON.stringify(refreshGeometry.glyph)}`,
    );
    for (const [name, box] of [
      ["图标容器", refreshGeometry.icon],
      ["Fluent 图标", refreshGeometry.glyph],
    ]) {
      assert.ok(
        Math.abs(box.centerX - refreshGeometry.button.centerX) <= 0.5 &&
          Math.abs(box.centerY - refreshGeometry.button.centerY) <= 0.5,
        `${size} 刷新按钮${name}未居中：${JSON.stringify({
          button: refreshGeometry.button,
          box,
        })}`,
      );
    }

    const welcomeGeometry = await page.evaluate(() => {
      const selectors = [
        ".composer-footer > .target-picker",
        ".composer-footer > .el-switch",
        ".composer-footer > .composer-shortcut",
        ".composer-footer > .send-button",
      ];
      const elements = selectors.map((selector) => document.querySelector(selector));
      if (elements.some((element) => !element)) return null;
      const boxes = elements.map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          x: rect.x,
          width: rect.width,
          height: rect.height,
          centerY: rect.y + rect.height / 2,
        };
      });
      return {
        boxes,
        shortcutWhiteSpace: getComputedStyle(elements[2]).whiteSpace,
      };
    });
    assert.ok(welcomeGeometry, `${size} 无法读取欢迎页输入区`);
    const welcomeCenters = welcomeGeometry.boxes.map((box) => box.centerY);
    assert.ok(
      Math.max(...welcomeCenters) - Math.min(...welcomeCenters) <= 1,
      `${size} 欢迎页输入区控件未保持同一行：${JSON.stringify(welcomeGeometry.boxes)}`,
    );
    assert.equal(
      welcomeGeometry.shortcutWhiteSpace,
      "nowrap",
      `${size} 快捷键提示不应换行`,
    );
    assert.ok(
      welcomeGeometry.boxes[3].x >
        welcomeGeometry.boxes[2].x + welcomeGeometry.boxes[2].width,
      `${size} 发送按钮应位于快捷键提示右侧`,
    );

    await page.locator(".welcome-composer textarea").fill("检查当前授权目标");
    await page.locator(".welcome-composer .send-button").click();
    await page.locator(".thread-composer").waitFor();
    const threadBoxes = await page
      .locator(
        ".thread-composer > .el-switch, .thread-composer > textarea, .thread-composer > button",
      )
      .evaluateAll((elements) =>
        elements.map((element) => {
          const rect = element.getBoundingClientRect();
          return {
            width: rect.width,
            bottom: rect.bottom,
          };
        }),
      );
    assert.equal(threadBoxes.length, 3, `${size} 对话输入区应包含三个主控件`);
    const threadBottoms = threadBoxes.map((box) => box.bottom);
    assert.ok(
      Math.max(...threadBottoms) - Math.min(...threadBottoms) <= 1,
      `${size} 对话输入区控件未对齐：${JSON.stringify(threadBoxes)}`,
    );
    assert.ok(threadBoxes[1].width >= 200, `${size} 对话输入框过窄`);
    await page.screenshot({
      path: path.join(outputDir, `dashboard-composer-${size}.png`),
    });
    await context.close();
  }
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
  await page.addInitScript(() => {
    window.toolboxDesktop = {
      launchCaptureBrowser: async () => ({ running: true }),
    };
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
  const toolbarActionGaps = await page.evaluate(() => {
    const selectors = [
      ".capture-browser-reopen",
      ".capture-filter-button",
      ".traffic-refresh",
      ".capture-toggle",
    ];
    const boxes = selectors.map((selector) =>
      document.querySelector(selector)?.getBoundingClientRect(),
    );
    if (boxes.some((box) => !box)) return null;
    return boxes.slice(1).map((box, index) =>
      Number((box.left - boxes[index].right).toFixed(2)),
    );
  });
  assert.ok(toolbarActionGaps, "流量工具栏的四个操作按钮应全部可见");
  assert.ok(
    toolbarActionGaps.every((gap) => Math.abs(gap - 8) <= 1),
    `流量工具栏按钮间距应统一为 8px：${JSON.stringify(toolbarActionGaps)}`,
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

async function verifyTargetAuthorizationTimeDisplay(browser) {
  const { context, page } = await createPage(browser, {
    width: 1440,
    height: 900,
  });
  await page.goto(`${baseUrl}/targets`, { waitUntil: "networkidle" });
  await page.locator(".targets-page").waitFor();
  const inheritedAuthorizationWindow = page
    .locator(".target-authorization-window")
    .nth(1);
  await inheritedAuthorizationWindow.waitFor();
  assert.match(
    await inheritedAuthorizationWindow.innerText(),
    /随项目\s+起\s*2026-07-01 00:00\s+止\s*2026-12-31 23:59/,
    "目标未设置独立时间时，列表应显示所属项目的实际授权有效期",
  );
  const deleteButton = page.locator(".target-action-delete").first();
  const deleteColor = await deleteButton.evaluate(
    (element) => getComputedStyle(element).color,
  );
  assert.equal(deleteColor, "rgb(180, 35, 24)", "删除链接应使用 Fluent danger 红");
  await page.locator(".target-action-edit").first().click();
  const editDialog = page.getByRole("dialog", { name: "编辑授权目标" });
  await editDialog.waitFor();
  const editDateValues = await editDialog
    .locator(".el-date-editor input")
    .evaluateAll((inputs) => inputs.map((input) => input.value));
  assert.deepEqual(
    editDateValues,
    ["2026-07-01 00:00", "2026-12-31 23:59"],
    `旧的无时区授权时间也应在编辑弹窗回填：${JSON.stringify(editDateValues)}`,
  );
  await editDialog
    .getByText("未单独设置的时间将沿用所属项目", { exact: false })
    .waitFor({ state: "hidden" });
  await page.screenshot({
    path: path.join(outputDir, "target-authorization-time-edit.png"),
  });
  await editDialog.getByRole("button", { name: "取消", exact: true }).click();

  await page.locator(".target-action-edit").nth(1).click();
  await editDialog.waitFor();
  const inheritedDateValues = await editDialog
    .locator(".el-date-editor input")
    .evaluateAll((inputs) =>
      inputs.map((input) => ({
        value: input.value,
        placeholder: input.placeholder,
      })),
    );
  assert.deepEqual(
    inheritedDateValues,
    [
      { value: "", placeholder: "项目：2026-07-01 00:00" },
      { value: "", placeholder: "项目：2026-12-31 23:59" },
    ],
    `继承项目时间应显示实际值，但不能写入目标级字段：${JSON.stringify(inheritedDateValues)}`,
  );
  assert.match(
    await editDialog.locator(".target-inherited-time").innerText(),
    /评估项目 1\s+开始 2026-07-01 00:00 · 结束 2026-12-31 23:59/,
    "编辑弹窗应明确显示所属项目的完整授权时间",
  );
  await page.screenshot({
    path: path.join(outputDir, "target-authorization-time-inherited.png"),
  });
  await editDialog.getByRole("button", { name: "取消", exact: true }).click();

  await page.getByRole("button", { name: "新增目标", exact: true }).click();
  const createDialog = page.getByRole("dialog", { name: "新增授权目标" });
  await createDialog.waitFor();
  const createDateValues = await createDialog
    .locator(".el-date-editor input")
    .evaluateAll((inputs) => inputs.map((input) => input.value));
  assert.deepEqual(
    createDateValues,
    ["2026-07-01 00:00", "2026-12-31 23:59"],
    `新增目标应默认带入所属项目授权时间：${JSON.stringify(createDateValues)}`,
  );
  await context.close();
}

async function verifyProjectReportLayout(browser) {
  const { context, page } = await createPage(browser, {
    width: 1440,
    height: 900,
  });
  await page.goto(`${baseUrl}/projects`, { waitUntil: "networkidle" });
  await page.getByText("进入项目", { exact: true }).first().click();
  await page.locator(".project-detail-page").waitFor();
  await page.getByRole("tab", { name: "项目报告", exact: true }).click();
  await page.locator(".report-severity-chip").first().waitFor();

  const severityInsets = await page
    .locator(".report-severity-chip")
    .evaluateAll((chips) =>
      chips.map((chip) => {
        const tag = chip.querySelector(".el-tag");
        if (!tag) return null;
        const chipBox = chip.getBoundingClientRect();
        const tagBox = tag.getBoundingClientRect();
        return {
          top: tagBox.top - chipBox.top,
          bottom: chipBox.bottom - tagBox.bottom,
          left: tagBox.left - chipBox.left,
        };
      }),
    );
  assert.ok(
    severityInsets.every((insets) => {
      if (!insets) return false;
      const values = Object.values(insets);
      return (
        Math.max(...values) - Math.min(...values) <= 1 &&
        values.every((value) => value >= 4.5 && value <= 5.5)
      );
    }),
    `风险等级胶囊的上、下、左内距应等距：${JSON.stringify(severityInsets)}`,
  );

  const reportSpacing = await page.evaluate(() => {
    const alert = document.querySelector(".report-safety-alert");
    const head = document.querySelector(".report-recent-head");
    const title = head?.querySelector(".project-subtitle");
    const selects = [...(head?.querySelectorAll(".el-select") || [])];
    if (!alert || !head || !title || selects.length !== 2) return null;
    const alertBox = alert.getBoundingClientRect();
    const headBox = head.getBoundingClientRect();
    const titleBox = title.getBoundingClientRect();
    const selectBoxes = selects.map((select) => select.getBoundingClientRect());
    return {
      verticalGap: headBox.top - alertBox.bottom,
      centerDeltas: selectBoxes.map(
        (box) =>
          box.top + box.height / 2 - (titleBox.top + titleBox.height / 2),
      ),
    };
  });
  assert.ok(reportSpacing, "项目报告安全提示和最近任务筛选器应可测量");
  assert.ok(
    reportSpacing.verticalGap >= 15 && reportSpacing.verticalGap <= 17,
    `安全提示与最近任务筛选区应保留 16px 间距：${JSON.stringify(reportSpacing)}`,
  );
  assert.ok(
    reportSpacing.centerDeltas.every((delta) => Math.abs(delta) <= 2),
    `最近任务标题与筛选器应垂直居中：${JSON.stringify(reportSpacing)}`,
  );
  await page.screenshot({
    path: path.join(outputDir, "project-report-spacing.png"),
    fullPage: true,
  });

  await page.getByRole("tab", { name: "审批与审计", exact: true }).click();
  await page.getByText("不适用（未生成任务）", { exact: true }).waitFor();
  await page.screenshot({
    path: path.join(outputDir, "project-audit-snapshot-placeholder.png"),
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
  const [pagerButtonBox, jumperBox] = await Promise.all([
    page.locator(".catalog-pagination .btn-prev").boundingBox(),
    page
      .locator(".catalog-pagination .el-pagination__editor .el-input__wrapper")
      .boundingBox(),
  ]);
  assert.ok(pagerButtonBox && jumperBox, "无法读取漏洞库分页控件尺寸");
  assert.ok(
    jumperBox.height <= pagerButtonBox.height + 1,
    `跳页输入框不应高于分页按钮：${jumperBox.height}px / ${pagerButtonBox.height}px`,
  );
  assert.ok(jumperBox.width <= 44, `跳页输入框仍然过宽：${jumperBox.width}px`);
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

async function verifyFingerprintCatalogUpdate(browser) {
  const { context, page } = await createPage(browser, {
    width: 1440,
    height: 900,
  });
  await page.goto(`${baseUrl}/projects`, { waitUntil: "networkidle" });
  await page.locator(".projects-page").waitFor();
  await page.getByText("进入项目", { exact: true }).first().click();
  await page.locator(".project-detail-page").waitFor();
  await page.getByRole("tab", { name: "探测服务", exact: true }).click();
  const panel = page.locator(".fingerprint-catalog-panel");
  await panel.waitFor();
  assert.match(await panel.innerText(), /visual-smoke/);
  assert.match(await panel.innerText(), /409 条/);
  const catalogToggle = panel.locator(".fingerprint-catalog-toggle");
  const catalogDetails = panel.locator("#project-fingerprint-catalog-body");
  assert.equal(
    await catalogToggle.getAttribute("aria-expanded"),
    "false",
    "指纹规则库默认应保持收起",
  );
  assert.equal(await catalogDetails.getAttribute("aria-hidden"), "true");
  assert.equal(
    await catalogDetails.evaluate((element) => element.inert),
    true,
    "收起的指纹规则详情应禁止交互",
  );
  const [collapsedPanelBox, collapsedHeadingBox] = await Promise.all([
    panel.boundingBox(),
    panel.locator(".fingerprint-catalog-heading").boundingBox(),
  ]);
  assert.ok(collapsedPanelBox && collapsedHeadingBox, "指纹规则库摘要应可见");
  assert.ok(
    collapsedPanelBox.height <= collapsedHeadingBox.height + 2,
    `收起后的指纹规则库不应保留详情占位：${JSON.stringify({
      collapsedPanelBox,
      collapsedHeadingBox,
    })}`,
  );
  const sourceTagAlignment = await panel
    .locator(".fingerprint-catalog-source-tag")
    .evaluate((tag) => {
      const content = tag.querySelector(".el-tag__content");
      if (!content) return null;
      const tagBox = tag.getBoundingClientRect();
      const contentBox = content.getBoundingClientRect();
      const style = getComputedStyle(tag);
      return {
        centerDelta:
          contentBox.top + contentBox.height / 2 -
          (tagBox.top + tagBox.height / 2),
        display: style.display,
        alignItems: style.alignItems,
        marginTop: style.marginTop,
      };
    });
  assert.ok(sourceTagAlignment, "指纹来源标签应可测量");
  assert.match(sourceTagAlignment.display, /flex/);
  assert.equal(sourceTagAlignment.alignItems, "center");
  assert.equal(sourceTagAlignment.marginTop, "0px");
  assert.ok(
    Math.abs(sourceTagAlignment.centerDelta) <= 1,
    `指纹来源标签文字应垂直居中：${JSON.stringify(sourceTagAlignment)}`,
  );
  assert.equal(
    await panel.getByRole("button", { name: "重新读取" }).isVisible(),
    false,
    "收起时不应显示指纹库维护操作",
  );
  await page.screenshot({
    path: path.join(outputDir, "project-fingerprint-catalog-collapsed.png"),
  });
  await catalogToggle.click();
  assert.equal(await catalogToggle.getAttribute("aria-expanded"), "true");
  assert.equal(await catalogDetails.getAttribute("aria-hidden"), "false");
  assert.equal(
    await catalogDetails.evaluate((element) => element.inert),
    false,
  );
  await panel.getByRole("button", { name: "重新读取" }).waitFor();
  await panel.getByRole("button", { name: "更新指纹库" }).waitFor();

  await panel.locator('input[type="file"]').setInputFiles({
    name: "broken-fingerprints.json",
    mimeType: "application/json",
    buffer: Buffer.from("{not-json", "utf8"),
  });
  await panel.getByText("更新失败", { exact: true }).waitFor();
  assert.match(await panel.innerText(), /文件不是有效的 JSON 指纹规则库/);

  const catalogJson = JSON.stringify({
    version: "visual-upload",
    rules: [
      {
        id: "visual-rule",
        name: "视觉回归规则",
        category: "FRAMEWORK",
        confidence: 90,
      },
    ],
  });
  await panel.locator('input[type="file"]').setInputFiles({
    name: "visual-fingerprints.json",
    mimeType: "application/json",
    buffer: Buffer.from(catalogJson, "utf8"),
  });
  const confirmation = page.locator("body > .el-overlay.is-message-box");
  await confirmation.waitFor();
  assert.match(await confirmation.innerText(), /visual-fingerprints\.json/);

  const updateRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return (
      request.method() === "PUT" &&
      url.pathname === "/api/fingerprints/catalog"
    );
  });
  await confirmation
    .getByRole("button", { name: "上传并更新", exact: true })
    .click();
  const request = await updateRequest;
  assert.match(request.headers()["content-type"] || "", /^application\/json/i);
  assert.equal(request.postDataBuffer()?.toString("utf8"), catalogJson);

  await panel.getByText("更新成功", { exact: true }).waitFor();
  assert.match(await panel.innerText(), /visual-fingerprints\.json/);
  assert.match(await panel.innerText(), /visual-upload/);
  assert.match(await panel.innerText(), /1 条规则/);
  assert.match(await panel.innerText(), /a{64}/);
  await confirmation.waitFor({ state: "hidden" });
  await page.screenshot({
    path: path.join(outputDir, "project-fingerprint-catalog-update.png"),
  });
  await context.close();

  const ordinary = await createPage(
    browser,
    { width: 1280, height: 800 },
    "reduce",
    "USER",
  );
  await ordinary.page.goto(`${baseUrl}/projects`, { waitUntil: "networkidle" });
  await ordinary.page.getByText("进入项目", { exact: true }).first().click();
  await ordinary.page.getByRole("tab", { name: "探测服务", exact: true }).click();
  const readOnlyPanel = ordinary.page.locator(".fingerprint-catalog-panel");
  await readOnlyPanel.waitFor();
  assert.match(await readOnlyPanel.innerText(), /visual-smoke/);
  assert.equal(
    await readOnlyPanel.getByRole("button", { name: "重新读取" }).count(),
    0,
    "普通用户不应看到指纹规则重载动作",
  );
  assert.equal(
    await readOnlyPanel.getByRole("button", { name: "更新指纹库" }).count(),
    0,
    "普通用户不应看到指纹库更新动作",
  );
  await ordinary.context.close();
}

async function verifyScheduledScannerConfiguration(browser) {
  const { context, page } = await createPage(browser, {
    width: 1440,
    height: 900,
  });
  await page.goto(`${baseUrl}/tasks`, { waitUntil: "networkidle" });
  await page.locator(".schedule-trigger").click();
  const dialog = page.locator(".el-dialog:visible").filter({
    hasText: "定时任务管理",
  });
  await dialog.waitFor();

  const ruleGaps = [];
  for (const modeLabel of ["每天", "每周", "每月", "按间隔"]) {
    await dialog.getByText(modeLabel, { exact: true }).click();
    const metrics = await dialog.evaluate((element) => {
      const row = element.querySelector(".schedule-rule-row");
      const preview = element.querySelector(".schedule-rule-preview");
      const items = row ? [...row.querySelectorAll(".el-form-item")] : [];
      if (!row || !preview || !items.length) return null;
      const controlBottom = Math.max(
        ...items.map((item) => item.getBoundingClientRect().bottom),
      );
      return {
        gap: preview.getBoundingClientRect().top - controlBottom,
        margins: items.map((item) => getComputedStyle(item).marginBottom),
      };
    });
    assert.ok(metrics, `${modeLabel}执行规则控件和说明文字应可见`);
    assert.ok(
      metrics.margins.every((margin) => margin === "8px"),
      `${modeLabel}执行规则的表单项底部间距应统一为 8px：${JSON.stringify(metrics)}`,
    );
    ruleGaps.push({ modeLabel, gap: metrics.gap });
  }
  const ruleGapValues = ruleGaps.map((item) => item.gap);
  assert.ok(
    Math.max(...ruleGapValues) - Math.min(...ruleGapValues) <= 1,
    `四种执行方式的控件与说明文字间距应一致：${JSON.stringify(ruleGaps)}`,
  );
  assert.ok(
    ruleGapValues.every((gap) => gap >= 11 && gap <= 13),
    `执行规则说明应与控件保持约 12px 间距：${JSON.stringify(ruleGaps)}`,
  );
  await dialog.getByText("每天", { exact: true }).click();
  await page.screenshot({
    path: path.join(outputDir, "tasks-schedule-rule-spacing.png"),
  });

  const formSelect = (label) =>
    dialog
      .locator(".el-form-item")
      .filter({ hasText: label })
      .locator(".el-select")
      .first();
  await formSelect("项目授权目标").click();
  const targetDropdown = page.locator(".el-select-dropdown:visible");
  await targetDropdown
    .getByText("授权目标 1 · target-1.authorized.test", { exact: true })
    .click();
  await targetDropdown.waitFor({ state: "hidden" });
  await formSelect("检测工具").click();
  await page
    .locator(".el-select-dropdown:visible")
    .getByText("Nuclei 漏洞扫描", { exact: true })
    .click();
  assert.equal(
    await dialog.getByText("默认安全模板", { exact: true }).count(),
    0,
    "Nuclei 无人值守任务不得回退到未逐项复核的默认模板目录",
  );
  await dialog.getByRole("button", { name: "创建", exact: true }).click();
  await page
    .locator(".el-message--warning")
    .filter({ hasText: "请为 NUCLEI 至少选择一个 PoC" })
    .waitFor();

  await formSelect("检测工具").click();
  await page
    .locator(".el-select-dropdown:visible")
    .getByText("Xray PoC 扫描", { exact: true })
    .click();

  assert.equal(
    await dialog.getByText("全部已同步", { exact: true }).count(),
    0,
    "无人值守扫描不应再提供动态全部 PoC",
  );
  await dialog.getByText("指定安全 PoC", { exact: true }).waitFor();
  const pocSelect = formSelect("指定 PoC");
  const pocRequestPromise = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return (
      url.pathname === "/api/vulnerabilities" &&
      url.searchParams.get("source") === "XRAY"
    );
  });
  await pocSelect.click();
  const pocRequest = await pocRequestPromise;
  assert.equal(
    new URL(pocRequest.url()).searchParams.get("scanSafety"),
    "SAFE",
    "定时扫描器 PoC 检索必须限制为 SAFE",
  );
  await page
    .locator(".el-select-dropdown:visible")
    .getByText("XRAY 安全 PoC 1", { exact: true })
    .click();
  assert.match(
    await dialog.locator(".schedule-parameter-help").allTextContents().then((items) =>
      items.join(" "),
    ),
    /SAFE/,
  );

  const scheduleRequest = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/api/scan-schedules",
  );
  await dialog.getByRole("button", { name: "创建", exact: true }).click();
  const confirmation = page.locator("body > .el-overlay.is-message-box");
  await confirmation.waitFor();
  assert.match(
    await confirmation.innerText(),
    /不会执行需审查或高影响 PoC.*SAFE 分级/s,
  );
  await confirmation
    .getByRole("button", { name: "创建定时任务", exact: true })
    .click();
  const request = await scheduleRequest;
  const payload = request.postDataJSON();
  assert.equal(payload.toolCode, "xray_scan");
  assert.deepEqual(payload.parameters, {
    pocCodes: ["XR-000000000000000000000001"],
  });
  assert.equal("allPocs" in payload.parameters, false);
  await page.screenshot({
    path: path.join(outputDir, "tasks-scheduled-safe-poc.png"),
  });
  await context.close();
}

async function main() {
  assert.ok(edgePath, "未找到 Edge 或 Chrome 可执行文件，请设置 EDGE_PATH 环境变量");
  fs.mkdirSync(outputDir, { recursive: true });
  const browser = await chromium.launch({
    executablePath: edgePath,
    headless: true,
  });
  try {
    if (process.env.VISUAL_DASHBOARD_ONLY === "1") {
      await verifyDashboardComposer(browser);
    } else if (process.env.VISUAL_WORKFLOW_ONLY === "1") {
      await verifyWorkflowStatusSummary(browser);
    } else if (process.env.VISUAL_TASKS_ONLY === "1") {
      await verifyScheduledScannerConfiguration(browser);
    } else if (process.env.VISUAL_FINGERPRINT_ONLY === "1") {
      await verifyFingerprintCatalogUpdate(browser);
    } else if (process.env.VISUAL_LAYOUT_FIXES_ONLY === "1") {
      await verifyTargetAuthorizationTimeDisplay(browser);
      await verifyProjectReportLayout(browser);
      await verifyTraffic(browser);
    } else {
      await verifyDashboardComposer(browser);
      await verifyNavigationMotion(browser);
      await verifyOfflineToolIndicator(browser);
      await verifySharedSelectionIndicators(browser);
      await verifyWorkflowStatusSummary(browser);
      await verifyScheduledScannerConfiguration(browser);
      await verifyDatePickerCorners(browser);
      await verifySettings(browser);
      await verifyCatalogSyncProgress(browser);
      await verifyTraffic(browser);
      await verifyTargetAuthorizationTimeDisplay(browser);
      await verifyProjectReportLayout(browser);
      await verifyPagination(browser);
      await verifyFunctionalPagination(browser);
      await verifyFingerprintCatalogUpdate(browser);
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
