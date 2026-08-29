/*
 * 獬豸授权安全测试平台 — 全链路 UI 端到端测试
 *
 * 运行方式：
 *   node tests/e2e/run-all.cjs                # 运行全部阶段
 *   node tests/e2e/run-all.cjs a b            # 只运行指定阶段
 *   HEADLESS=1 node tests/e2e/run-all.cjs     # 无头模式
 *
 * 约束：所有业务操作均由真实浏览器 UI 触发（点击/输入/选择），
 *       测试代码不直接调用后端 API 制造或篡改业务数据。
 */
const path = require("node:path");
const fs = require("node:fs");
const { chromium } = require(path.resolve(__dirname, "..", "..", "node_modules", "playwright-core"));
const { Harness, loadCredentials } = require("./lib/harness.cjs");

const BASE_URL = process.env.E2E_BASE_URL || "http://127.0.0.1:5173";
const TARGET_IP = process.env.E2E_TARGET || "192.168.136.131";
const TARGET_WEB_PORT = process.env.E2E_TARGET_WEB_PORT || "8000";

// 执行顺序按业务依赖排列：先建项目/目标，再发起检测并等待完成，
// 之后才检查项目详情、漏洞结果与报告；授权边界负向用例放在最后，
// 因为它会临时改变项目/目标状态。
const STAGES = [
  ["a", "a-setup-login.cjs"],
  ["b", "b-projects.cjs"],
  ["c", "c-targets.cjs"],
  ["e", "e-active-scan.cjs"],
  ["f", "f-tasks.cjs"],
  ["d", "d-project-detail.cjs"],
  ["g", "g-findings.cjs"],
  ["h", "h-reports.cjs"],
  ["i", "i-traffic.cjs"],
  ["k", "k-ai-assistant.cjs"],
  ["l", "l-offline-tools.cjs"],
  ["m", "m-settings-audit.cjs"],
  ["n", "n-negative-auth.cjs"],
];

function browserPath() {
  if (process.env.E2E_BROWSER && fs.existsSync(process.env.E2E_BROWSER)) return process.env.E2E_BROWSER;
  const standardPaths = process.platform === "win32" ? [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  ] : [];
  for (const sp of standardPaths) {
    if (fs.existsSync(sp)) return sp;
  }
  const names = process.platform === "win32"
    ? ["msedge.exe", "chrome.exe"]
    : ["microsoft-edge", "google-chrome", "chromium", "chromium-browser"];
  for (const directory of (process.env.PATH || "").split(path.delimiter)) {
    if (!directory) continue;
    for (const name of names) {
      const candidate = path.join(directory, name);
      if (fs.existsSync(candidate)) return candidate;
    }
  }
  throw new Error("未找到 Edge 或 Chrome 可执行文件");
}

(async () => {
  const only = process.argv.slice(2).map((s) => s.toLowerCase());
  const creds = loadCredentials();
  const H = new Harness(process.env.E2E_RUN_ID);

  const ctx = {
    baseUrl: BASE_URL,
    username: creds.username,
    password: creds.password,
    targetIp: TARGET_IP,
    targetWebPort: TARGET_WEB_PORT,
    stamp: Date.now().toString().slice(-6),
    // 阶段间传递的业务标识
    projectName: null,
    targetName: null,
    createdTaskIds: [],
  };

  console.log(`\n獬豸平台 全链路 UI 端到端测试`);
  console.log(`运行编号 : ${H.runId}`);
  console.log(`前端地址 : ${BASE_URL}`);
  console.log(`测试靶机 : ${TARGET_IP} (Web 端口 ${TARGET_WEB_PORT})`);
  console.log(`证据目录 : ${H.dir}\n`);

  const headless = process.env.HEADLESS === "1";
  const browser = await chromium.launch({
    executablePath: browserPath(),
    headless,
    args: ["--start-maximized", "--disable-features=Translate"],
  });
  const context = await browser.newContext({
    viewport: headless ? { width: 1680, height: 1000 } : null,
    locale: "zh-CN",
    ignoreHTTPSErrors: true,
  });

  /*
   * 记录应用实际收到的文件下载响应。
   *
   * 报告类接口返回 Content-Disposition: attachment，Chromium 的下载管理器会拦截该响应，
   * 使发起请求的 XHR 只拿到一个空的合成响应（状态 204、无 content-type）。
   * 这是浏览器/自动化环境的行为，并非应用缺陷——一旦据此断言"下载到 0 字节"，
   * 就会把环境现象误判成产品缺陷。
   *
   * 因此这里在页面内包裹 XHR，直接记录应用真实收到的状态码、内容类型与字节数，
   * 让断言基于"应用是否取到了有效文件"，而不依赖浏览器的下载行为。
   */
  await context.addInitScript(() => {
    window.__xhrDownloads = [];
    const OrigOpen = XMLHttpRequest.prototype.open;
    const OrigSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
      this.__url = String(url);
      this.__method = method;
      return OrigOpen.call(this, method, url, ...rest);
    };
    XMLHttpRequest.prototype.send = function (...args) {
      if (/\/reports\//.test(this.__url)) {
        this.addEventListener("loadend", () => {
          let size = -1;
          try {
            const r = this.response;
            if (r && typeof r.size === "number") size = r.size;
            else if (r && typeof r.byteLength === "number") size = r.byteLength;
            else if (typeof r === "string") size = r.length;
          } catch { /* 忽略读取失败 */ }
          window.__xhrDownloads.push({
            url: this.__url,
            status: this.status,
            size,
            contentType: this.getResponseHeader("content-type"),
            at: Date.now(),
          });
        });
      }
      return OrigSend.apply(this, args);
    };
  });

  const page = await context.newPage();
  page.setDefaultTimeout(20000);
  H.attach(page);

  let fatal = null;
  try {
    for (const [key, file] of STAGES) {
      if (only.length && !only.includes(key)) continue;
      const full = path.join(__dirname, "suite", file);
      if (!fs.existsSync(full)) {
        H.phase(`阶段 ${key.toUpperCase()} — 未实现`);
        H.skip(`${key.toUpperCase()}-00`, `阶段模块 ${file}`, "模块尚未创建");
        continue;
      }
      const mod = require(full);
      try {
        await mod.run(page, H, ctx);
      } catch (err) {
        H.record(`${key.toUpperCase()}-XX`, `阶段 ${key.toUpperCase()} 异常中断`, "FAIL", (err && err.message) || String(err));
        await H.shot(page, `${key}-阶段异常`);
      }
    }
  } catch (err) {
    fatal = err;
  } finally {
    H.save();
    if (!process.env.E2E_KEEP_OPEN) {
      await context.close().catch(() => {});
      await browser.close().catch(() => {});
    }
  }

  if (fatal) {
    console.error("致命错误:", fatal);
    process.exit(2);
  }
  process.exit(H.summary.fail > 0 ? 1 : 0);
})();
