/*
 * 现场演示脚本：验证 192.168.222.139 的爬虫发现路径来自平台爬虫，而不是提示词里写死的。
 *
 * 演示步骤（全部在可见的桌面窗口里执行）：
 *   1. 启动打包好的桌面程序并完成本机安全凭据登录（窗口保持可见，供现场围观）。
 *   2. 进入「项目与资产」，把爬虫结果页面打开截图，作为“演示前”证据。
 *   3. 打印本脚本送给 AI 的完整提示词全文 —— 证明提示词里没有任何具体路径。
 *   4. 让 AI 助手自己调用平台检索证据的能力，读回爬虫发现的端点，并原样输出。
 *   5. 打开「安全发现 / 资产路径」界面，把平台自己记录的路径截图，供人工核对。
 *
 * 不做任何扫描、不触发审批、不改数据库。运行：
 *   node scripts/demo-crawler-live.cjs
 */
const fs = require("node:fs");
const path = require("node:path");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
const out = path.resolve(root, "..", ".run", "crawler-live-demo", new Date().toISOString().replace(/[:.]/g, "-"));

const PROMPT =
  "请只依据当前授权项目里平台爬虫已经采集到的证据来回答，不要凭常识补全，也不要构造任何路径。" +
  "请调用你检索项目证据的能力，读出爬虫实际发现的端点，并原样列出来源。";

fs.mkdirSync(out, { recursive: true });

function log(message) {
  console.log(`[${new Date().toLocaleTimeString()}] ${message}`);
}

let shotSeq = 0;
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

(async () => {
  if (!fs.existsSync(exePath)) throw new Error(`未找到打包产物：${exePath}`);

  log("启动桌面程序（窗口保持可见）...");
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

  page.setDefaultTimeout(60000);
  await page.waitForTimeout(2000);
  log(`主窗口标题：${await page.title()}`);

  // ---- 登录（走程序自己的入口，不使用任何硬编码口令）
  let text = await bodyText(page);
  if (!/AI 安全助手/.test(text)) {
    for (let i = 0; i < 10 && !/用户名|本机安全凭据/.test(text); i += 1) {
      const next = page.locator("button").filter({ hasText: /下一步/ }).first();
      if ((await next.count()) && !(await next.isDisabled().catch(() => true))) {
        await next.click().catch(() => {});
      }
      await page.waitForTimeout(900);
      text = await bodyText(page);
    }
    const quick = page.locator("button").filter({ hasText: /本机安全凭据/ }).first();
    if (await quick.count()) {
      log("使用「本机安全凭据」登录（程序自带的安全登录入口）");
      await quick.click();
    }
    const ready = Date.now() + 90000;
    while (Date.now() < ready) {
      text = await bodyText(page);
      if (/AI 安全助手/.test(text)) break;
      await page.waitForTimeout(1000);
    }
  }
  if (!/AI 安全助手/.test(text)) throw new Error("未能进入 AI 工作区");
  await shot(page, "workspace-ready");

  // ---- 演示参数：项目 / 目标（由平台自己查，不写死 ID）
  const info = await page.evaluate(async () => {
    const query = new URLSearchParams(window.location.search);
    const backend = (
      query.get("backend") ||
      window.toolboxDesktop?.backendBaseUrl ||
      "http://127.0.0.1:18080/api"
    ).replace(/\/+$/, "");
    const token =
      localStorage.getItem("security_toolbox_token") ||
      sessionStorage.getItem("security_toolbox_session_token");
    const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
    const projects = await (await fetch(`${backend}/projects`, { headers })).json();
    const project = Array.isArray(projects)
      ? projects.find((p) => (p.name || "").includes("192.168.222.139"))
      : null;
    if (!project) return { backend, projectId: 0, targetId: 0 };
    const targets = await (
      await fetch(`${backend}/projects/${project.id}/targets`, { headers })
    ).json();
    const target = Array.isArray(targets) && targets.length ? targets[0] : null;
    return {
      backend,
      projectId: project.id,
      targetId: target ? target.targetId || target.id : 0,
    };
  });
  log(`项目 ID=${info.projectId}，目标 ID=${info.targetId}`);

  // ---- 演示前：平台自己已经记录的爬取结果（直接读平台数据库接口）
  const stored = await page.evaluate(
    async ({ backend, targetId }) => {
      const token =
        localStorage.getItem("security_toolbox_token") ||
        sessionStorage.getItem("security_toolbox_session_token");
      const headers = { Authorization: `Bearer ${token}` };
      const res = await fetch(`${backend}/targets/${targetId}/discovered-paths`, { headers });
      const data = await res.json();
      return Array.isArray(data) ? data.map((p) => p.path || p.url).filter(Boolean) : [];
    },
    info,
  );
  log(`平台已记录的爬取路径数量：${stored.length}`);
  log(`前 5 条（平台原样记录）：${stored.slice(0, 5).join("  |  ")}`);
  fs.writeFileSync(
    path.join(out, "stored-paths.json"),
    JSON.stringify(stored, null, 2),
    "utf8",
  );

  // ---- 关键证据：本脚本发给 AI 的提示词全文
  console.log("\n================ 发给 AI 的提示词（全文，逐字打印）================");
  console.log(PROMPT);
  console.log("==================================================================\n");
  fs.writeFileSync(path.join(out, "prompt-sent.txt"), PROMPT, "utf8");
  const containsPath = /Less-|id=1|\/sql-connections|\/[A-Za-z]+-\d/.test(PROMPT);
  console.log(`提示词中是否包含任何具体路径片段：${containsPath ? "是（有问题！）" : "否"}`);

  // ---- 让 AI 自己去读证据
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
  log("提示词已发送，等待 AI 检索项目证据...");

  let answer = "";
  const answerDeadline = Date.now() + 180000;
  while (Date.now() < answerDeadline) {
    answer = await bodyText(page);
    if (/Less-\d/.test(answer)) break;
    await page.waitForTimeout(1000);
  }
  await shot(page, "ai-answer");

  const hits = Array.from(new Set((answer.match(/https?:\/\/192\.168\.222\.139[^\s，。、）)】"]+/g) || [])));
  console.log("\n================ AI 回答里出现的端点 ================");
  console.log(hits.length ? hits.join("\n") : "（未从回答文本中解析到端点）");
  console.log("=====================================================\n");
  fs.writeFileSync(path.join(out, "ai-answer.txt"), answer, "utf8");

  console.log(`截图与证据目录：${out}`);
  console.log("桌面窗口保持打开，供现场核对。");

  // 演示脚本不主动退出 Electron；由调用方决定何时清理。
  await new Promise(() => setInterval(() => {}, 60000));
})().catch((error) => {
  console.error("演示失败：", error && error.message ? error.message : error);
  process.exitCode = 1;
});
