/*
 * 现场演示（第二阶段）：目标由用户给定 192.168.222.139，其余一律不指定。
 *
 * 与上一版的区别：
 *   - 提示词不提及 SQL 注入、不提及任何工具，只要求 AI 依据证据判断下一步；
 *   - 不硬编码任何端点路径；
 *   - 授权项目/目标只在平台里核对存在性，若不存在则停下来请用户手动创建；
 *   - 审批环节脚本绝不代点，只截图并等待用户操作。
 *
 * 用法：node scripts/demo-evidence-driven.cjs
 */
const fs = require("node:fs");
const path = require("node:path");
const { _electron: electron } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const exePath = path.join(root, "desktop-release", "win-unpacked", "獬豸安全测试平台.exe");
const out = path.resolve(root, "..", ".run", "evidence-driven-demo", new Date().toISOString().replace(/[:.]/g, "-"));
fs.mkdirSync(out, { recursive: true });

const TARGET_HOST = "192.168.222.139"; // 用户唯一指定的信息

const PROMPT = `授权目标是 ${TARGET_HOST}。请先梳理该项目已有的证据，判断这个目标当前存在哪些值得进一步验证的安全风险，并给出下一步建议；只依据平台已采集到的证据，说明依据来自哪条记录，不要假设、不要补全、不要编造未发现的路径。`;

let shotSeq = 0;
const steps = [];
const log = (m) => console.log(`[${new Date().toLocaleTimeString()}] ${m}`);

function step(name, status, detail = "") {
  const icon = { PASS: "✅", FAIL: "❌", WAIT: "⏸️", INFO: "ℹ️" }[status] || "•";
  console.log(`${icon} ${name}${detail ? " — " + detail : ""}`);
  steps.push({ name, status, detail: String(detail).slice(0, 1200) });
}

async function shot(page, label) {
  shotSeq += 1;
  const file = path.join(out, `${String(shotSeq).padStart(2, "0")}-${label}.png`);
  if (page && !page.isClosed()) await page.screenshot({ path: file, fullPage: true }).catch(() => {});
  return file;
}

const bodyText = (page) => page.locator("body").innerText().catch(() => "");

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

async function api(page, backend, pathname, init = {}) {
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
    { backend, pathname, init },
  );
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
  page.setDefaultTimeout(90000);
  await page.waitForTimeout(2000);
  step("1. 桌面主窗口就绪", "PASS", await page.title());
  await shot(page, "desktop-ready");

  // ---- 登录（走程序自带入口）
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
  step("2. 登录完成", "PASS", "程序自带本机安全凭据登录");
  await shot(page, "logged-in");

  const backend = await page.evaluate(() => {
    const q = new URLSearchParams(window.location.search);
    return (q.get("backend") || window.toolboxDesktop?.backendBaseUrl || "http://127.0.0.1:18080/api").replace(/\/+$/, "");
  });

  // ---- 核对授权项目/目标是否由用户建立（脚本不创建）
  const projects = await api(page, backend, "/projects");
  const list = Array.isArray(projects.body) ? projects.body : [];
  const project = list.find((p) => (p.name || "").includes(TARGET_HOST));
  if (!project) {
    step("3. 未找到包含该目标的授权项目", "WAIT", "请在界面上手动新建项目与目标后告诉我");
    await shot(page, "no-project");
    console.log(`\n请在桌面窗口里手动完成：新建项目 → 添加授权目标 http://${TARGET_HOST} → 填写授权信息 → 保存。\n完成后告诉我，我再继续。\n`);
    await new Promise(() => setInterval(() => {}, 60000));
    return;
  }
  step("3. 授权项目已由用户建立", "PASS", `项目 ID=${project.id}，状态=${project.status}`);

  const targetsRes = await api(page, backend, `/projects/${project.id}/targets`);
  const targets = Array.isArray(targetsRes.body) ? targetsRes.body : [];
  const target = targets.find((t) => JSON.stringify(t).includes(TARGET_HOST)) || targets[0];
  if (!target) {
    step("3b. 项目下没有授权目标", "WAIT", "请手动添加目标后再继续");
    await shot(page, "no-target");
    await new Promise(() => setInterval(() => {}, 60000));
    return;
  }
  const targetId = target.targetId || target.id;
  step("3b. 授权目标已由用户建立", "PASS", `目标 ID=${targetId}`);

  // ---- 记录当前证据基线（不触发任何扫描）
  const pathsRes = await api(page, backend, `/targets/${targetId}/discovered-paths`);
  const paths = Array.isArray(pathsRes.body)
    ? pathsRes.body.map((r) => r.path || r.url).filter(Boolean)
    : [];
  step("4. 当前证据基线", "INFO", `平台已记录端点 ${paths.length} 条`);
  fs.writeFileSync(path.join(out, "paths-baseline.json"), JSON.stringify(paths, null, 2), "utf8");
  await shot(page, "baseline");

  // ---- 交给 AI，看它自己怎么判断
  const nav = page.locator("#desktop-v2-primary-navigation");
  const aiNav = nav.locator("button.desktop-v2-nav-item", { hasText: "AI 安全助手" }).first();
  if (await aiNav.count()) await aiNav.click();
  await page.waitForTimeout(2500);

  console.log("\n============ 发给 AI 的提示词（逐字，未指定漏洞类型/工具）============");
  console.log(PROMPT);
  console.log("======================================================================\n");
  fs.writeFileSync(path.join(out, "prompt-sent.txt"), PROMPT, "utf8");
  const leaked = /SQL|注入|sqlmap|nmap|nuclei|爆破|漏洞类型/i.test(PROMPT.split("说明依据")[0]);
  step("5. 提示词自检", leaked ? "FAIL" : "PASS", leaked ? "提示词含结论性词汇" : "未预设漏洞类型与工具");

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
  log("已发送，等待 AI 自行判断...");

  const answerDeadline = Date.now() + 300000;
  let answer = "";
  while (Date.now() < answerDeadline) {
    answer = await bodyText(page);
    if (/已完成|等待管理员确认|查看方案详情|检测操作授权审批/.test(answer)) break;
    await page.waitForTimeout(1000);
  }
  await shot(page, "ai-answer");
  fs.writeFileSync(path.join(out, "ai-answer.txt"), answer, "utf8");

  const tail = answer.split("安全助手").pop() || answer;
  console.log("\n============ AI 的回答（截取正文）============");
  console.log(tail.slice(0, 4000));
  console.log("=============================================\n");
  step("6. AI 已给出判断", "PASS", "见 ai-answer.txt");

  // ---- 若 AI 提出动作，停在审批处，绝不代点
  const approval = page
    .locator(".ai-approval-modal:visible, .el-dialog:visible")
    .filter({ hasText: /检测操作授权审批|确认 AI 行动方案/ })
    .last();
  if (!(await approval.count())) {
    const detailBtn = page.locator("button:visible", { hasText: /查看方案详情/ }).last();
    if (await detailBtn.count()) {
      await detailBtn.click().catch(() => {});
      await page.waitForTimeout(1500);
    }
  }
  await shot(page, "approval-or-answer");
  console.log(`
==============================================================
⏸️  脚本到此为止。若出现审批弹窗，由你自己判断是否点「允许执行」；
    本脚本不会点击任何批准/执行按钮，也不会调用任何扫描工具。
==============================================================
`);

  fs.writeFileSync(
    path.join(out, "demo-report.json"),
    JSON.stringify({ generatedAt: new Date().toISOString(), target: TARGET_HOST, projectId: project.id, targetId, prompt: PROMPT, steps }, null, 2),
    "utf8",
  );
  console.log(`证据目录：${out}`);
  await new Promise(() => setInterval(() => {}, 60000));
})().catch((error) => {
  console.error("演示中断：", (error && error.message) || error);
  process.exitCode = 1;
});
