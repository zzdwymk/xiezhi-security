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
        total: 41,
        builtin: 41,
        nuclei: 0,
        knownExploited: 0,
        safeToScan: 41,
        templatesAvailable: false,
        syncing: false,
      };
    } else if (endpoint === "/vulnerabilities/rules") {
      body = [];
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

async function createPage(browser, viewport) {
  const context = await browser.newContext({
    viewport,
    colorScheme: "light",
    reducedMotion: "reduce",
  });
  const page = await context.newPage();
  await installApiMock(page);
  await page.addInitScript(() => {
    localStorage.setItem("security_toolbox_setup_complete_v2", "true");
    localStorage.setItem("security_toolbox_token", "visual-smoke-token");
  });
  return { context, page };
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
  const [overlayBox, dialogBox, sidebarBox] = await Promise.all([
    overlay.boundingBox(),
    overlay.locator(".el-dialog").boundingBox(),
    page.locator("#desktop-v2-sidebar").boundingBox(),
  ]);
  assert.ok(overlayBox && dialogBox, `${label} 无法读取对话框边界`);
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
    `${label} 对话框本体超出工作区或窗口：${JSON.stringify(dialogBox)}`,
  );
}

async function openSettingsDialogAndCheck(page, native, label, screenshotName) {
  await page
    .locator(".settings-row")
    .filter({ hasText: "AI 模型服务" })
    .click();
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
      return {
        borderBottomWidth: style.borderBottomWidth,
        boxShadow: style.boxShadow,
      };
    });
  assert.equal(
    toolbarStyle.borderBottomWidth,
    "0px",
    "流量工作区标题栏不应叠加底部边框",
  );
  assert.match(
    toolbarStyle.boxShadow,
    /0px 1px 0px/,
    "流量工作区标题栏应只保留 1px 分隔线",
  );
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
    await verifySettings(browser);
    await verifyTraffic(browser);
    await verifyPagination(browser);
    await verifyFunctionalPagination(browser);
    await verifyResponsiveMatrix(browser);
  } finally {
    await browser.close();
  }
  console.log(`视觉冒烟测试通过，截图目录：${outputDir}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
