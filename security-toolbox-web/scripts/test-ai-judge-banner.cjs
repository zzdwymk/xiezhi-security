// Isolated headless Edge + Vite fixture: verifies the semantic-judge banner inside
// AiApprovalDialog renders the "疑似 xxx 行为" warning and the circuit-breaker state.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright-core");

const root = path.resolve(__dirname, "..");
const out = path.resolve(
  root,
  "../.run/ai-judge-banner",
  new Date().toISOString().replace(/[:.]/g, "-"),
);
fs.mkdirSync(out, { recursive: true });

const judgeWarning = {
  degraded: false,
  steps: [
    {
      workflowNodeId: "sqlmap",
      toolCode: "sqlmap_scan",
      allow: false,
      behaviour: "SQL注入探测",
      risk: "HIGH",
      confidence: 0.93,
      summary: "该动作会向 /Less-1/?id=1 注入单引号以触发数据库报错回显",
    },
  ],
  worstRisk: "HIGH",
  requiresHumanReview: true,
  headline: "SQL注入探测",
};

const judgeCircuit = {
  degraded: true,
  steps: [],
  worstRisk: "CRITICAL",
  requiresHumanReview: true,
  headline: "判官熔断（无法判定）",
  degradedReason: "judge_timeout",
};

const judgeClear = {
  degraded: false,
  steps: [
    {
      workflowNodeId: "headers",
      toolCode: "http_headers",
      allow: true,
      behaviour: "常规安全探测",
      risk: "SAFE",
      confidence: 0.96,
      summary: "仅读取 HTTP 响应头",
    },
  ],
  worstRisk: "SAFE",
  requiresHumanReview: false,
  headline: "常规安全探测",
};

const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="app"></div><script type="module">
import {createApp,h,reactive} from 'vue';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';
import '/src/unified-theme.css';
import Dialog from '/src/components/AiApprovalDialog.vue';
const base={id:'answer',role:'assistant',content:'请审核',status:'completed',approvalId:42,approvalStatus:'REQUIRED',taskIds:[],steps:[{id:'s1',toolCode:'sqlmap_scan',parameters:{path:'/Less-1/?id=1',level:1},requiresApproval:true,risk:'CAUTION'}],createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};
const state=reactive({visible:true,message:{...base}});
window.fixture=state;
createApp({setup:()=>()=>h('main',[h(Dialog,{visible:state.visible,message:state.message,targetName:'sqli-labs 靶机',targetValue:'192.168.222.139',allowedPorts:'80','onUpdate:visible':()=>{},onDecide:()=>{}})])}).use(ElementPlus).mount('#app');
</script></body></html>`;

let browser;
let server;
const results = [];
const errors = [];

(async () => {
  const { createServer } = await import("vite");
  const vue = (await import("@vitejs/plugin-vue")).default;
  server = await createServer({
    configFile: false,
    root,
    cacheDir: path.join(out, "cache"),
    optimizeDeps: { entries: [], include: ["vue", "element-plus"], noDiscovery: true },
    plugins: [
      vue(),
      {
        name: "judge-fixture",
        configureServer(s) {
          s.middlewares.use(async (req, res, next) => {
            if (req.url !== "/__judge") return next();
            res.setHeader("Content-Type", "text/html; charset=utf-8");
            res.end(await s.transformIndexHtml(req.url, html));
          });
        },
      },
    ],
    server: { host: "127.0.0.1", port: 19876, strictPort: false, hmr: false, watch: { ignored: ["**/desktop-release/**", "**/dist/**"] } },
    logLevel: "error",
  });
  await server.listen();
  browser = await chromium.launch({
    executablePath: "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 720, height: 900 } });
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("http://127.0.0.1:" + server.httpServer.address().port + "/__judge");
  const dialog = page.getByRole("dialog", { name: "确认 AI 行动方案", exact: true });
  await dialog.waitFor();

  async function setJudge(judge, expectClass) {
    await page.evaluate((j) => {
      window.fixture.message.judge = j;
    }, judge);
    if (expectClass) {
      await page.locator(`.approval-judge-banner--${expectClass}`).waitFor();
    }
  }

  // 1. 无判官结论时，不显示横幅
  {
    const count = await page.locator(".approval-judge-banner").count();
    assert.equal(count, 0, "no judge => no banner");
    results.push({ name: "无判官结论时不显示横幅", status: "PASS" });
  }

  // 2. 判官告警：显示「疑似 SQL注入探测」黄色横幅
  await setJudge(judgeWarning, "warning");
  {
    const banner = page.locator(".approval-judge-banner--warning");
    assert.equal(await banner.count(), 1, "warning banner present");
    const text = await banner.innerText();
    assert.match(text, /疑似 SQL注入探测/);
    assert.match(text, /SQL注入探测/);
    assert.match(text, /置信度 93%/);
    assert.match(text, /最高风险 HIGH/);
    assert.match(text, /注入单引号/);
    await page.screenshot({ path: path.join(out, "judge-warning.png"), fullPage: true, animations: "disabled" });
    results.push({ name: "判官告警横幅渲染", status: "PASS" });
  }

  // 3. 判官熔断：红色横幅 + 熔断拦截标签 + Fail-Closed 说明
  await setJudge(judgeCircuit, "critical");
  {
    const banner = page.locator(".approval-judge-banner--critical");
    assert.equal(await banner.count(), 1, "critical banner present");
    const text = await banner.innerText();
    assert.match(text, /判官熔断/);
    assert.match(text, /熔断拦截/);
    assert.match(text, /Fail-Closed/);
    assert.match(text, /judge_timeout/);
    assert.match(text, /最高风险 CRITICAL/);
    await page.screenshot({ path: path.join(out, "judge-circuit.png"), fullPage: true, animations: "disabled" });
    results.push({ name: "判官熔断横幅渲染", status: "PASS" });
  }

  // 4. 判官放行：绿色横幅，无「熔断」「疑似」字样
  await setJudge(judgeClear, "clear");
  {
    const banner = page.locator(".approval-judge-banner--clear");
    assert.equal(await banner.count(), 1, "clear banner present");
    // The circuit-breaker tag was v-if'd out but Element Plus plays a leave transition;
    // wait for the node to actually disappear before asserting on innerText.
    await page.locator(".approval-judge-banner .el-tag--danger").waitFor({ state: "detached" });
    const text = await banner.innerText();
    assert.match(text, /判官未发现需要拦截的行为/);
    assert.match(text, /最高风险 SAFE/);
    assert.doesNotMatch(text, /熔断/);
    assert.doesNotMatch(text, /疑似/);
    await page.screenshot({ path: path.join(out, "judge-clear.png"), fullPage: true, animations: "disabled" });
    results.push({ name: "判官放行横幅渲染", status: "PASS" });
  }

  assert.deepEqual(errors, []);
  console.log("EVIDENCE " + out);
})().catch((e) => {
  results.push({ status: "FAIL", error: e.stack });
  console.error(e);
  process.exitCode = 1;
}).finally(async () => {
  fs.writeFileSync(path.join(out, "results.json"), JSON.stringify({ scope: "isolated real Vue + Element Plus; no real judge API", results, errors }, null, 2));
  if (browser) await browser.close();
  if (server) await server.close();
});
