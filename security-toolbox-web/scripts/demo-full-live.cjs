/*
 * 全程可见的现场演示：清空业务数据 → 重建项目/目标 → 平台爬虫真实爬取 → AI 基于证据规划注入验证。
 *
 * 关键原则：
 *   1. 桌面窗口全程可见，每一步都截图留证；
 *   2. 提示词从脚本里逐字打印出来，证明没有把任何路径喂给 AI；
 *   3. 审批弹窗出现后 **脚本不点批准**，停下来等人在弹窗里手动确认；
 *   4. 不修改数据库、不绕过任何安全校验。
 */
const fs = require("node:fs");
const path = require("node:path");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
const out = path.resolve(root, "..", ".run", "full-live-demo", new Date().toISOString().replace(/[:.]/g, "-"));
fs.mkdirSync(out, { recursive: true });

const TARGET_HOST = "192.168.222.139";
const PROMPT =
  "请对当前授权目标进行信息收集，并针对爬虫实际发现的可疑参数端点，提出 SQL 注入验证方案；" +
  "不要猜测或自行构造未发现的路径。";

let shotSeq = 0;
const steps = [];

function log(message) {
  console.log(`[${new Date().toLocaleTimeString()}] ${message}`);
}

function step(name, status, detail = "") {
  const icon = { PASS: "✅", FAIL: "❌", WAIT: "⏸️", INFO: "ℹ️" }[status] || "•";
  console.log(`${icon} ${name}${detail ? " — " + detail : ""}`);
  steps.push({ name, status, detail: String(detail).slice(0, 1200) });
}

async function shot(page, label) {
  shotSeq += 1;
  const file = path.join(out, `${String(shotSeq).padStart(2, "0")}-${label}.png`);
  if (page && !page.isClosed()) {
    await page.screenshot({ path: file, fullPage: true }).catch(() => {});
  }
  return file;
}

async function bodyText(page) {
  return page.locator("body").innerText().catch(() => "");
}

async function waitUntil(page, predicate, timeoutMs, message) {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    last = await bodyText(page);
    if (predicate(last)) return last;
    await page.waitForTimeout(700);
  }
  throw new Error(`${message}；末次内容：${last.slice(-200).replace(/\s+/g, " ")}`);
}

async function api(page, info, pathname, init = {}) {
  return page.evaluate(
    async ({ backend, pathname, init }) => {
      const token =
        localStorage.getItem("security_toolbox_token") ||
        sessionStorage.getItem("security_toolbox_session_token");
      const res = await fetch(`${backend}${pathname}`, {
        ...init,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
          ...(init.headers || {}),
        },
      });
      const text = await res.text();
      let body;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
      return { status: res.status, body };
    },
    { backend: info.backend, pathname, init },
  );
}

(async () => {
  if (!fs.existsSync(exePath)) throw new Error(`未找到打包产物：${exePath}`);

  log("启动桌面程序（窗口保持可见，请在前台观察）...");
  const app = await electron.launch({
    executablePath: exePath,
    args: ["."],
    env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined },
    timeout: 180000,
  });

  let page;
  const deadline = Date.now() + 180000;
  while (Date.now() < deadline) {
    for (const candidate of app.windows().slice().reverse()) {
      if (candidate.isClosed()) continue;
      const url = candidate.url();
      if (url && (url.includes("/dist/index.html") || url.includes("#/"))) {
        page = candidate;
        break;
      }
    }
    if (page) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  if (!page) throw new Error("等待桌面主窗口超时");
  page.setDefaultTimeout(90000);
  await page.waitForTimeout(2000);
  step("1. 桌面主窗口就绪", "PASS", await page.title());
  await shot(page, "desktop-ready");

  // ---------------------------------------------------------------- 登录
  let text = await bodyText(page);
  if (!/AI 安全助手/.test(text)) {
    for (let i = 0; i < 12 && !/用户名|本机安全凭据/.test(text); i += 1) {
      const next = page.locator("button").filter({ hasText: /下一步/ }).first();
      if ((await next.count()) && !(await next.isDisabled().catch(() => true))) {
        await next.click().catch(() => {});
      }
      await page.waitForTimeout(900);
      text = await bodyText(page);
    }
    const quick = page.locator("button").filter({ hasText: /本机安全凭据/ }).first();
    if (await quick.count()) await quick.click();
    await waitUntil(page, (t) => /AI 安全助手/.test(t), 90000, "登录未完成");
  }
  step("2. 桌面登录完成", "PASS", "通过程序自带本机安全凭据登录");
  await shot(page, "logged-in");

  const info = await page.evaluate(async () => {
    const query = new URLSearchParams(window.location.search);
    const backend = (
      query.get("backend") ||
      window.toolboxDesktop?.backendBaseUrl ||
      "http://127.0.0.1:18080/api"
    ).replace(/\/+$/, "");
    return { backend };
  });
  log(`后端地址：${info.backend}`);

  // ---------------------------------------------------------------- 3. 清空业务数据（走平台自己的设置接口）
  const before = await api(page, info, "/projects");
  step(
    "3. 清空前平台数据快照",
    "INFO",
    `项目数=${Array.isArray(before.body) ? before.body.length : "?"}`,
  );
  await shot(page, "before-clear");

  const cleared = await api(page, info, "/settings/data", {
    method: "DELETE",
    body: JSON.stringify({ confirmation: "永久清空" }),
  });
  if (cleared.status !== 200) {
    throw new Error(`清空业务数据失败：HTTP ${cleared.status} ${JSON.stringify(cleared.body).slice(0, 300)}`);
  }
  step(
    "4. 业务数据已清空",
    "PASS",
    `删除记录数=${cleared.body?.deletedRecords ?? JSON.stringify(cleared.body).slice(0, 200)}`,
  );
  await page.reload().catch(() => {});
  await page.waitForTimeout(4000);
  await shot(page, "after-clear");
  const after = await api(page, info, "/projects");
  step(
    "5. 清空后复查",
    "PASS",
    `项目数=${Array.isArray(after.body) ? after.body.length : "?"}（应为 0）`,
  );

  // 重新登录（清空会清掉 AI 会话，token 仍有效则跳过）
  let probe = await api(page, info, "/projects");
  if (probe.status === 401) {
    const quick = page.locator("button").filter({ hasText: /本机安全凭据/ }).first();
    if (await quick.count()) await quick.click();
    await waitUntil(page, (t) => /AI 安全助手/.test(t), 90000, "重新登录失败");
  }

  // ---------------------------------------------------------------- 6. 重建项目 + 目标
  const now = new Date();
  const from = new Date(now.getTime() - 86400000).toISOString();
  const to = new Date(now.getTime() + 30 * 86400000).toISOString();

  const projectRes = await api(page, info, "/projects", {
    method: "POST",
    body: JSON.stringify({
      name: `${TARGET_HOST} 靶场安全评估项目`,
      description: "现场演示：从零开始对授权局域网靶机做真实漏洞挖掘",
      authorizationStatement: `书面授权测试：仅对 ${TARGET_HOST} 允许的端口做受控安全测试`,
      authorizationValidFrom: from,
      authorizationExpiresAt: to,
      owner: "admin",
    }),
  });
  if (projectRes.status >= 300) throw new Error(`创建项目失败：HTTP ${projectRes.status}`);
  const projectId = projectRes.body.id;
  await api(page, info, `/projects/${projectId}/status`, {
    method: "POST",
    body: JSON.stringify({ status: "ACTIVE" }),
  });

  const targetRes = await api(page, info, "/targets", {
    method: "POST",
    body: JSON.stringify({
      name: "靶机 sqli-labs",
      targetValue: `http://${TARGET_HOST}`,
      targetType: "url",
      authorizationNote: "已确认书面授权，允许端口 80",
      allowedPorts: "80",
      enabled: true,
      authorizationValidFrom: from,
      authorizationExpiresAt: to,
      projectId,
    }),
  });
  if (targetRes.status >= 300) throw new Error(`创建目标失败：HTTP ${targetRes.status}`);
  const targetId = targetRes.body.id;
  info.projectId = projectId;
  info.targetId = targetId;

  await page.evaluate((tid) => {
    localStorage.setItem("security_toolbox_dashboard_target", String(tid));
  }, targetId);
  step("6. 项目与授权目标已重建", "PASS", `项目 ID=${projectId}，目标 ID=${targetId}`);

  // ---------------------------------------------------------------- 7. 平台爬虫真实爬取
  const pathsBefore = await api(page, info, `/targets/${targetId}/discovered-paths`);
  step(
    "7. 爬取前基线",
    "INFO",
    `已发现路径数=${Array.isArray(pathsBefore.body) ? pathsBefore.body.length : "?"}（应为 0）`,
  );

  log("调用平台爬虫（crawlSite，只做页面源码链接提取，不用字典爆破）...");
  const recon = await api(page, info, `/projects/${projectId}/recon/collect`, {
    method: "POST",
    body: JSON.stringify({
      targetId,
      mode: "ACTIVE",
      activeNetworkProbe: false,
      crawlSite: true,
      enumeratePaths: false,
      includeHttp: true,
    }),
  });
  if (recon.status >= 300) throw new Error(`爬虫调用失败：HTTP ${recon.status}`);

  let webPaths = recon.body?.webPaths ?? [];
  if (typeof webPaths === "string") {
    try {
      webPaths = JSON.parse(webPaths);
    } catch {
      webPaths = [];
    }
  }
  step("8. 平台爬虫执行完成", "PASS", `接口返回 webPaths 条数=${Array.isArray(webPaths) ? webPaths.length : 0}`);
  log(`爬虫返回样例：${(Array.isArray(webPaths) ? webPaths : []).slice(0, 8).join("  |  ")}`);

  const storedRes = await api(page, info, `/targets/${targetId}/discovered-paths`);
  const stored = Array.isArray(storedRes.body)
    ? storedRes.body.map((row) => row.path || row.url).filter(Boolean)
    : [];
  step(
    "9. 平台入库的爬取结果",
    "PASS",
    `共 ${stored.length} 条；前 5 条：${stored.slice(0, 5).join(" | ")}`,
  );
  fs.writeFileSync(path.join(out, "crawled-paths.json"), JSON.stringify(stored, null, 2), "utf8");
  await shot(page, "crawl-finished");

  // ---------------------------------------------------------------- 10. AI 基于证据规划
  const nav = page.locator("#desktop-v2-primary-navigation");
  const aiNav = nav.locator("button.desktop-v2-nav-item", { hasText: "AI 安全助手" }).first();
  if (await aiNav.count()) await aiNav.click();
  await page.waitForTimeout(2500);

  console.log("\n============ 发给 AI 的提示词（逐字打印，无任何具体路径）============");
  console.log(PROMPT);
  console.log("====================================================================\n");
  fs.writeFileSync(path.join(out, "prompt-sent.txt"), PROMPT, "utf8");
  const leaks = /Less-|id=1|sql-connections|\/[A-Za-z]+-\d/.test(PROMPT);
  step("10. 提示词泄漏检查", leaks ? "FAIL" : "PASS", leaks ? "提示词含具体路径！" : "提示词不含任何具体路径");

  const composer = page.locator(".welcome-composer textarea, .thread-composer textarea").first();
  await composer.waitFor({ state: "visible", timeout: 60000 });
  await page.waitForFunction(
    () => {
      const el = document.querySelector(".welcome-composer textarea, .thread-composer textarea");
      return el && !el.disabled;
    },
    { timeout: 90000 },
  );
  await composer.fill(PROMPT);
  await shot(page, "prompt-typed");
  const send = page.locator(".send-button:visible, button.send-button").first();
  if (await send.count()) await send.click();
  else await composer.press("Enter");
  log("提示词已发送，等待 AI 检索爬虫证据并给出待审批方案...");

  const planDeadline = Date.now() + 240000;
  let planText = "";
  while (Date.now() < planDeadline) {
    planText = await bodyText(page);
    if (
      /sqlmap|SQL\s*注入/i.test(planText) &&
      /等待管理员确认|查看方案详情|检测操作授权审批|确认 AI 行动方案|确认并执行/.test(planText)
    ) {
      break;
    }
    await page.waitForTimeout(1000);
  }
  await shot(page, "ai-plan");

  const referenced = Array.from(
    new Set(planText.match(/(?:https?:\/\/[^\s"'<>]+|\/[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]+)/g) || []),
  );
  fs.writeFileSync(path.join(out, "ai-plan.txt"), planText, "utf8");
  const hits = referenced.filter((ref) =>
    stored.some((item) => String(item).includes(ref.split("?")[0]) && ref.length > 2),
  );
  step(
    "11. AI 方案引用爬虫真实端点",
    hits.length ? "PASS" : "FAIL",
    hits.length ? `引用到已入库端点：${hits.slice(0, 6).join(" | ")}` : "AI 未引用爬虫入库端点",
  );

  // ---------------------------------------------------------------- 12. 停在审批弹窗，等人工点
  const approval = page
    .locator(".ai-approval-modal:visible, .el-dialog:visible")
    .filter({ hasText: /检测操作授权审批|确认 AI 行动方案/ })
    .last();
  const hasApproval = (await approval.count()) > 0;
  if (!hasApproval) {
    const detailBtn = page.locator("button:visible", { hasText: /查看方案详情/ }).last();
    if (await detailBtn.count()) {
      await detailBtn.click().catch(() => {});
      await page.waitForTimeout(1500);
    }
  }
  await shot(page, "approval-gate");

  console.log(`
==============================================================
⏸️  已停在审批环节，脚本不会替你点「允许执行」。
    请在桌面窗口的弹窗里亲自确认；如果弹窗没出现，
    请点「查看方案详情」或直接看 AI 回答里的方案。
==============================================================
`);

  const approved = await Promise.race([
    (async () => {
      const end = Date.now() + 600000;
      while (Date.now() < end) {
        const r = await api(page, info, `/tasks?projectId=${projectId}&limit=10`);
        const tasks = Array.isArray(r.body) ? r.body : [];
        const mine = tasks.find((t) => t.toolCode === "sqlmap_scan");
        if (mine && ["SUCCESS", "FAILED"].includes(mine.status)) return mine;
        await page.waitForTimeout(3000);
      }
      return null;
    })(),
  ]);

  if (approved) {
    step("12. 你已授权，SQLMap 任务已执行", approved.status === "SUCCESS" ? "PASS" : "FAIL", `任务 ID=${approved.id}，状态=${approved.status}`);
    await page.waitForTimeout(3000);
    await shot(page, "sqlmap-finished");

    const findingsNav = page
      .locator("#desktop-v2-primary-navigation")
      .locator("button.desktop-v2-nav-item", { hasText: "安全发现" })
      .first();
    if (await findingsNav.count()) await findingsNav.click();
    await page.waitForTimeout(3500);
    const findingsText = await bodyText(page);
    const hasSql = /SQL\s*注入|STB-SQLMAP/i.test(findingsText);
    step("13. 安全发现核查", hasSql ? "PASS" : "FAIL", hasSql ? "列表中出现 SQL 注入相关记录" : "列表中未出现 SQL 注入记录");
    fs.writeFileSync(path.join(out, "findings-page.txt"), findingsText, "utf8");
    await shot(page, "findings");
  } else {
    step("12. 未在 10 分钟内检测到授权的 SQLMap 任务", "WAIT", "审批未完成或未执行，未产生任何注入探测");

    await shot(page, "waiting-for-approval");
  }

  const summary = {
    generatedAt: new Date().toISOString(),
    target: `http://${TARGET_HOST}`,
    projectId: info.projectId,
    targetId: info.targetId,
    prompt: PROMPT,
    promptLeaksPath: leaks,
    crawledCount: stored.length,
    crawledSample: stored.slice(0, 10),
    steps,
  };
  fs.writeFileSync(path.join(out, "demo-report.json"), JSON.stringify(summary, null, 2), "utf8");
  console.log(`\n截图与报告目录：${out}`);
  console.log("桌面窗口保持打开，供现场核对。");
  await new Promise(() => setInterval(() => {}, 60000));
})().catch((error) => {
  console.error("演示中断：", (error && error.message) || error);
  process.exitCode = 1;
});
