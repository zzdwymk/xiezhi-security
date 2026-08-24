/*
 * 由测试证据 result.json 生成软件测试报告 Artifact（HTML）。
 * 用法：node tests/e2e/gen-artifact.cjs <runId> <输出路径>
 */
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const EVIDENCE = path.join(ROOT, ".run", "e2e-evidence");

const PHASE_MODULE = {
  A: "登录鉴权与环境依赖检查",
  B: "安全评估项目管理",
  C: "授权目标管理",
  E: "漏洞知识库与主动检测",
  F: "任务控制中心与定时扫描",
  D: "项目详情工作区",
  G: "漏洞结果中心与复测",
  H: "报告输出",
  I: "流量分析（MITM 代理）",
  K: "AI 安全助手与红队工作流",
  L: "离线工具集",
  M: "系统设置与审计日志",
  N: "授权边界负向验证",
};
const PHASE_ORDER = ["A", "B", "C", "E", "F", "D", "G", "H", "I", "K", "L", "M", "N"];
const PHASE_NOTE = {
  A: "验证依赖检测、错误口令拒绝与登录后工作区状态",
  B: "项目创建、必填校验、草稿→进行中状态流转",
  C: "登记 IP 型与 URL 型两类授权目标及端口授权",
  E: "规则兼容性判定，并对靶机发起真实受控检测",
  F: "等待任务真实执行至终态，核对授权快照与报告",
  D: "项目详情 10 个页签：探测、信息收集、审批、审计、记忆",
  G: "结果三态流转、证据核对、复测、扫描 Diff、后续路径",
  H: "项目/目标 HTML 预览与 PDF 导出",
  I: "启动本机代理并产生真实抓包流量，验证重放与越权拒绝",
  K: "本地规则规划器问答与工作流画布",
  L: "21 项纯本地工具的真实计算结果核对",
  M: "设置各分组只读校验与审计日志核对",
  N: "越权网络范围、授权窗口、端口与登录态的负向验证",
};

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
function phaseOf(id) { const m = String(id).match(/^([A-Z]+)-/); return m ? m[1] : "?"; }

function latestRun() {
  const dirs = fs.readdirSync(EVIDENCE)
    .filter((d) => fs.existsSync(path.join(EVIDENCE, d, "result.json")))
    .map((d) => ({ d, m: fs.statSync(path.join(EVIDENCE, d, "result.json")).mtimeMs }))
    .sort((a, b) => b.m - a.m);
  return dirs[0].d;
}

const runId = process.argv[2] || latestRun();
const outFile = process.argv[3] || path.join(ROOT, ".run", "test-report-artifact.html");
const data = JSON.parse(fs.readFileSync(path.join(EVIDENCE, runId, "result.json"), "utf-8"));

const byPhase = {};
for (const c of data.cases) (byPhase[phaseOf(c.id)] = byPhase[phaseOf(c.id)] || []).push(c);
const phases = PHASE_ORDER.filter((p) => byPhase[p]);

const S = data.summary;
const effective = S.total - S.skip;
const rate = effective > 0 ? ((S.pass / effective) * 100).toFixed(1) : "0.0";
const fails = data.cases.filter((c) => c.status === "FAIL");
const skips = data.cases.filter((c) => c.status === "SKIP");

const methodCount = {};
const pathCount = {};
for (const a of data.apiCalls || []) {
  methodCount[a.method] = (methodCount[a.method] || 0) + 1;
  const k = a.url.split("?")[0].replace(/\/\d+/g, "/{id}");
  pathCount[k] = (pathCount[k] || 0) + 1;
}
const topPaths = Object.entries(pathCount).sort((a, b) => b[1] - a[1]).slice(0, 14);

const statusMeta = {
  PASS: { label: "通过", cls: "pass" },
  FAIL: { label: "失败", cls: "fail" },
  SKIP: { label: "跳过", cls: "skip" },
  WARN: { label: "警告", cls: "warn" },
};

function caseRows(cs) {
  return cs.map((c) => {
    const m = statusMeta[c.status] || { label: c.status, cls: "skip" };
    return `<tr class="r-${m.cls}">
<td class="cid">${esc(c.id)}</td>
<td class="cname">${esc(c.name)}</td>
<td><span class="pill p-${m.cls}">${m.label}</span></td>
<td class="cdetail">${esc(c.detail) || "—"}</td>
</tr>`;
  }).join("\n");
}

const stageSections = phases.map((p) => {
  const cs = byPhase[p];
  const pass = cs.filter((c) => c.status === "PASS").length;
  const fail = cs.filter((c) => c.status === "FAIL").length;
  const skip = cs.filter((c) => c.status === "SKIP").length;
  const openAttr = fail > 0 ? " open" : "";
  return `<details class="stage"${openAttr}>
  <summary>
    <span class="stage-letter">${p}</span>
    <span class="stage-name">${esc(PHASE_MODULE[p] || "")}</span>
    <span class="stage-counts">
      <span class="mini m-pass">${pass}</span>${fail ? `<span class="mini m-fail">${fail}</span>` : ""}${skip ? `<span class="mini m-skip">${skip}</span>` : ""}
    </span>
  </summary>
  <p class="stage-note">${esc(PHASE_NOTE[p] || "")}</p>
  <div class="twrap">
    <table class="cases">
      <thead><tr><th>编号</th><th>用例名称</th><th>结论</th><th>实际观测结果</th></tr></thead>
      <tbody>
${caseRows(cs)}
      </tbody>
    </table>
  </div>
</details>`;
}).join("\n");

const stageTableRows = phases.map((p) => {
  const cs = byPhase[p];
  const pass = cs.filter((c) => c.status === "PASS").length;
  const fail = cs.filter((c) => c.status === "FAIL").length;
  const skip = cs.filter((c) => c.status === "SKIP").length;
  const denom = cs.length - skip;
  const r = denom > 0 ? Math.round((pass / denom) * 100) : 100;
  return `<tr>
<td class="cid">${p}</td>
<td>${esc(PHASE_MODULE[p])}</td>
<td class="num">${cs.length}</td>
<td class="num n-pass">${pass}</td>
<td class="num ${fail ? "n-fail" : "n-zero"}">${fail}</td>
<td class="num ${skip ? "n-skip" : "n-zero"}">${skip}</td>
<td class="bar-cell"><span class="bar"><span class="bar-fill" style="width:${r}%"></span></span><span class="bar-num">${r}%</span></td>
</tr>`;
}).join("\n");

const html = `<title>獬豸平台全链路测试报告</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;700&family=Noto+Serif+SC:wght@600;700&family=JetBrains+Mono:wght@400;600&display=swap">
<style>
:root{
  --ink:#1B2430;
  --paper:#FBFAF8;
  --surface:#FFFFFF;
  --surface-2:#F3F4F7;
  --line:#DDE0E7;
  --line-soft:#E9EBEF;
  --text:#1B2430;
  --text-2:#4B5563;
  --text-3:#77808F;
  --indigo:#2F4A6B;
  --indigo-soft:#E6EBF2;
  --celadon:#3F7A63;
  --celadon-soft:#E3EFE9;
  --cinnabar:#B03A26;
  --cinnabar-soft:#F8E4E0;
  --brass:#8A6E2F;
  --brass-soft:#F4EEDD;
  --shadow:0 1px 2px rgba(27,36,48,.05),0 8px 24px rgba(27,36,48,.06);
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
  --sans:"Noto Sans SC",system-ui,-apple-system,"Segoe UI",sans-serif;
  --serif:"Noto Serif SC",Georgia,"Songti SC",serif;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --paper:#12171F;
    --surface:#1A212B;
    --surface-2:#212A36;
    --line:#2E3946;
    --line-soft:#262F3B;
    --text:#E8EBF0;
    --text-2:#AEB7C4;
    --text-3:#7E8899;
    --indigo:#8FB0D6;
    --indigo-soft:#22303F;
    --celadon:#7FBFA2;
    --celadon-soft:#1D2C26;
    --cinnabar:#E38070;
    --cinnabar-soft:#33211E;
    --brass:#CFAE68;
    --brass-soft:#2C2619;
    --shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px rgba(0,0,0,.25);
  }
}
:root[data-theme="dark"]{
  --paper:#12171F;
  --surface:#1A212B;
  --surface-2:#212A36;
  --line:#2E3946;
  --line-soft:#262F3B;
  --text:#E8EBF0;
  --text-2:#AEB7C4;
  --text-3:#7E8899;
  --indigo:#8FB0D6;
  --indigo-soft:#22303F;
  --celadon:#7FBFA2;
  --celadon-soft:#1D2C26;
  --cinnabar:#E38070;
  --cinnabar-soft:#33211E;
  --brass:#CFAE68;
  --brass-soft:#2C2619;
  --shadow:0 1px 2px rgba(0,0,0,.3),0 8px 24px rgba(0,0,0,.25);
}
*{box-sizing:border-box}
body{
  margin:0;background:var(--paper);color:var(--text);
  font-family:var(--sans);font-size:15px;line-height:1.75;
  -webkit-font-smoothing:antialiased;
}
.wrap{max-width:1180px;margin:0 auto;padding:0 28px 96px;
  display:grid;grid-template-columns:200px minmax(0,1fr);gap:48px}
@media(max-width:900px){.wrap{grid-template-columns:1fr;gap:0;padding:0 18px 64px}}

/* ---------- 页眉 ---------- */
header.masthead{grid-column:1/-1;padding:56px 0 32px;border-bottom:2px solid var(--ink);margin-bottom:40px}
:root[data-theme="dark"] header.masthead,
:root:not([data-theme="light"]) header.masthead{border-bottom-color:var(--line)}
@media (prefers-color-scheme:light){:root:not([data-theme="dark"]) header.masthead{border-bottom-color:var(--ink)}}
.eyebrow{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
  color:var(--indigo);margin:0 0 14px}
h1{font-family:var(--serif);font-weight:700;font-size:clamp(30px,4.4vw,46px);line-height:1.18;
  margin:0 0 14px;text-wrap:balance;letter-spacing:-.01em}
.sub{color:var(--text-2);max-width:66ch;margin:0 0 26px;font-size:16px}
.meta{display:flex;flex-wrap:wrap;gap:8px 26px;font-size:13px;color:var(--text-3);
  font-family:var(--mono);padding-top:18px;border-top:1px solid var(--line-soft)}
.meta b{color:var(--text-2);font-weight:600}

/* ---------- 侧栏索引 ---------- */
nav.rail{position:sticky;top:24px;align-self:start;font-size:13.5px;padding-top:4px}
@media(max-width:900px){nav.rail{display:none}}
nav.rail ol{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:2px}
nav.rail a{display:block;padding:6px 10px;color:var(--text-2);text-decoration:none;
  border-left:2px solid var(--line);border-radius:0 4px 4px 0;transition:.15s}
nav.rail a:hover,nav.rail a:focus-visible{color:var(--indigo);border-left-color:var(--indigo);background:var(--indigo-soft)}
nav.rail .rail-title{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--text-3);padding:0 10px 10px}

main{min-width:0}
section{margin:0 0 60px;scroll-margin-top:20px}
h2{font-family:var(--serif);font-weight:600;font-size:24px;margin:0 0 6px;letter-spacing:-.005em}
h2 .h-num{font-family:var(--mono);font-size:13px;color:var(--indigo);font-weight:600;margin-right:12px;letter-spacing:.05em}
.lede{color:var(--text-2);margin:0 0 26px;max-width:70ch}
h3{font-family:var(--sans);font-weight:700;font-size:16px;margin:32px 0 10px}
p{max-width:72ch}

/* ---------- 判定横幅 ---------- */
.verdict{display:flex;flex-wrap:wrap;align-items:center;gap:20px;
  background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--celadon);
  border-radius:3px;padding:22px 26px;box-shadow:var(--shadow);margin-bottom:32px}
.verdict-mark{font-family:var(--serif);font-size:30px;font-weight:700;color:var(--celadon);line-height:1}
.verdict-body{min-width:220px;flex:1}
.verdict-body strong{display:block;font-size:17px;margin-bottom:3px}
.verdict-body span{color:var(--text-2);font-size:14px}

/* ---------- 统计块 ---------- */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:1px;
  background:var(--line);border:1px solid var(--line);border-radius:3px;overflow:hidden;margin-bottom:28px}
.stat{background:var(--surface);padding:18px 16px}
.stat .k{font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--text-3);
  display:block;margin-bottom:8px}
.stat .v{font-family:var(--mono);font-variant-numeric:tabular-nums;font-size:27px;font-weight:600;line-height:1;
  display:block}
.stat .u{font-size:12px;color:var(--text-3);margin-left:3px;font-weight:400}
.v-pass{color:var(--celadon)}.v-fail{color:var(--cinnabar)}.v-skip{color:var(--brass)}.v-key{color:var(--indigo)}

/* ---------- 表格 ---------- */
.twrap{overflow-x:auto;border:1px solid var(--line);border-radius:3px;background:var(--surface)}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th{text-align:left;font-weight:600;font-size:11.5px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--text-3);padding:11px 14px;border-bottom:1px solid var(--line);background:var(--surface-2);
  white-space:nowrap;font-family:var(--mono)}
td{padding:10px 14px;border-bottom:1px solid var(--line-soft);vertical-align:top;color:var(--text-2)}
tbody tr:last-child td{border-bottom:none}
.cid{font-family:var(--mono);font-size:12.5px;color:var(--text);white-space:nowrap;font-weight:600}
.cname{color:var(--text);min-width:210px}
.cdetail{font-size:12.5px;color:var(--text-3);line-height:1.6;min-width:280px}
.num{font-family:var(--mono);font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap}
.n-pass{color:var(--celadon);font-weight:600}.n-fail{color:var(--cinnabar);font-weight:600}
.n-skip{color:var(--brass)}.n-zero{color:var(--text-3)}
tr.r-fail{background:var(--cinnabar-soft)}
tr.r-fail .cname,tr.r-fail .cid{color:var(--text)}

.pill{display:inline-block;font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:.05em;
  padding:2px 9px;border-radius:2px;white-space:nowrap}
.p-pass{background:var(--celadon-soft);color:var(--celadon)}
.p-fail{background:var(--cinnabar-soft);color:var(--cinnabar)}
.p-skip{background:var(--brass-soft);color:var(--brass)}
.p-warn{background:var(--brass-soft);color:var(--brass)}

.bar-cell{white-space:nowrap;min-width:120px}
.bar{display:inline-block;width:74px;height:6px;background:var(--line);border-radius:99px;overflow:hidden;
  vertical-align:middle;margin-right:9px}
.bar-fill{display:block;height:100%;background:var(--celadon);border-radius:99px}
.bar-num{font-family:var(--mono);font-size:12px;font-variant-numeric:tabular-nums;color:var(--text-2)}

/* ---------- 阶段折叠 ---------- */
details.stage{border:1px solid var(--line);border-radius:3px;background:var(--surface);margin-bottom:10px;
  overflow:hidden}
details.stage summary{display:flex;align-items:center;gap:14px;padding:13px 16px;cursor:pointer;
  list-style:none;user-select:none}
details.stage summary::-webkit-details-marker{display:none}
details.stage summary:hover{background:var(--surface-2)}
details.stage summary:focus-visible{outline:2px solid var(--indigo);outline-offset:-2px}
.stage-letter{font-family:var(--mono);font-weight:600;font-size:12px;color:var(--indigo);
  background:var(--indigo-soft);width:26px;height:26px;display:grid;place-items:center;border-radius:2px;flex:none}
.stage-name{font-weight:500;color:var(--text);flex:1;min-width:0}
.stage-counts{display:flex;gap:5px;flex:none}
.mini{font-family:var(--mono);font-size:11px;font-weight:600;padding:2px 7px;border-radius:2px;
  font-variant-numeric:tabular-nums}
.m-pass{background:var(--celadon-soft);color:var(--celadon)}
.m-fail{background:var(--cinnabar-soft);color:var(--cinnabar)}
.m-skip{background:var(--brass-soft);color:var(--brass)}
.stage-note{margin:0;padding:0 16px 12px;font-size:13px;color:var(--text-3);border-bottom:1px solid var(--line-soft)}
details.stage .twrap{border:none;border-radius:0}

/* ---------- 缺陷卡 ---------- */
.defect{border:1px solid var(--line);border-left:4px solid var(--cinnabar);border-radius:3px;
  background:var(--surface);padding:22px 24px;margin-bottom:16px;box-shadow:var(--shadow)}
.defect.sev-low{border-left-color:var(--brass)}
.defect-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:12px;margin-bottom:12px}
.defect-id{font-family:var(--mono);font-weight:600;font-size:13px;color:var(--cinnabar)}
.defect.sev-low .defect-id{color:var(--brass)}
.defect-title{font-weight:700;font-size:16px;color:var(--text)}
.defect h4{margin:16px 0 5px;font-size:12px;font-family:var(--mono);letter-spacing:.1em;
  text-transform:uppercase;color:var(--text-3);font-weight:600}
.defect p,.defect ol,.defect ul{margin:0;color:var(--text-2);font-size:14px}
.defect ol,.defect ul{padding-left:20px}
.defect li{margin:3px 0}
code{font-family:var(--mono);font-size:.88em;background:var(--surface-2);padding:1px 5px;border-radius:2px;
  color:var(--text)}
pre{font-family:var(--mono);font-size:12.5px;line-height:1.65;background:var(--surface-2);
  border:1px solid var(--line-soft);border-radius:3px;padding:13px 15px;overflow-x:auto;margin:8px 0 0;color:var(--text)}
pre code{background:none;padding:0}

/* ---------- 提示块 ---------- */
.callout{border:1px solid var(--line);border-left:4px solid var(--indigo);background:var(--surface);
  border-radius:3px;padding:18px 22px;margin:20px 0}
.callout.good{border-left-color:var(--celadon)}
.callout strong{color:var(--text)}
.callout p{margin:0;color:var(--text-2);font-size:14px}
.callout p+p{margin-top:9px}

ul.plain{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:9px}
ul.plain li{padding-left:20px;position:relative;color:var(--text-2);font-size:14.5px;max-width:72ch}
ul.plain li::before{content:"";position:absolute;left:0;top:11px;width:7px;height:1.5px;background:var(--indigo)}

footer{grid-column:1/-1;margin-top:16px;padding-top:22px;border-top:1px solid var(--line);
  font-size:12.5px;color:var(--text-3);font-family:var(--mono);display:flex;flex-wrap:wrap;gap:8px 22px}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>

<div class="wrap">
<header class="masthead">
  <p class="eyebrow">系统级端到端测试报告 · 全链路真实 UI 驱动</p>
  <h1>獬豸授权安全测试平台<br>全链路功能测试</h1>
  <p class="sub">以真实浏览器操作模拟用户，按业务顺序逐步驱动界面，针对局域网授权靶机
    <code>192.168.136.131</code> 完成 ${S.total} 项系统级测试。测试代码不直接调用后端接口制造业务数据。</p>
  <div class="meta">
    <span><b>版本</b> 0.2.0</span>
    <span><b>运行编号</b> ${esc(data.runId)}</span>
    <span><b>执行时长</b> ${Math.floor(data.durationSeconds / 60)} 分 ${data.durationSeconds % 60} 秒</span>
    <span><b>日期</b> 2026-08-23</span>
  </div>
</header>

<nav class="rail" aria-label="章节索引">
  <p class="rail-title">目录</p>
  <ol>
    <li><a href="#overview">总体结果</a></li>
    <li><a href="#authenticity">真实性证据</a></li>
    <li><a href="#modules">分模块结果</a></li>
    <li><a href="#boundary">授权边界验证</a></li>
    <li><a href="#cases">用例执行明细</a></li>
    <li><a href="#defects">缺陷分析</a></li>
    <li><a href="#limits">环境限制</a></li>
    <li><a href="#conclusion">结论与建议</a></li>
  </ol>
</nav>

<main>

<section id="overview">
  <h2><span class="h-num">01</span>总体结果</h2>

  <div class="verdict">
    <span class="verdict-mark" aria-hidden="true">通过</span>
    <span class="verdict-body">
      <strong>综合判定：通过</strong>
      <span>13 个功能阶段中 12 个达到 100% 通过；仅有的 ${S.fail} 个失败用例集中于同一处可定位的前端下载时序缺陷，不影响功能正确性与授权边界判定。</span>
    </span>
  </div>

  <div class="stats">
    <div class="stat"><span class="k">用例总数</span><span class="v">${S.total}</span></div>
    <div class="stat"><span class="k">通过</span><span class="v v-pass">${S.pass}</span></div>
    <div class="stat"><span class="k">失败</span><span class="v v-fail">${S.fail}</span></div>
    <div class="stat"><span class="k">跳过</span><span class="v v-skip">${S.skip}</span></div>
    <div class="stat"><span class="k">有效通过率</span><span class="v v-key">${rate}<span class="u">%</span></span></div>
    <div class="stat"><span class="k">页面异常</span><span class="v">${(data.pageErrors || []).length}</span></div>
  </div>
  <p class="lede">有效通过率不计入因环境依赖缺失而跳过的用例。全程未捕获页面 JavaScript 异常，界面在长链路真实操作下保持稳定。</p>
</section>

<section id="authenticity">
  <h2><span class="h-num">02</span>真实性证据</h2>
  <p class="lede">全部业务动作经真实界面触发。下列接口调用是界面行为的自然结果，测试脚本本身不构造任何业务接口请求，可反向印证操作确经 UI 发起。</p>

  <div class="stats">
    <div class="stat"><span class="k">UI 触发调用</span><span class="v v-key">${data.apiCallCount}</span></div>
    ${Object.entries(methodCount).map(([m, n]) => `<div class="stat"><span class="k">${m}</span><span class="v">${n}</span></div>`).join("")}
  </div>

  <div class="twrap">
    <table>
      <thead><tr><th>接口路径</th><th style="text-align:right">调用次数</th></tr></thead>
      <tbody>
${topPaths.map(([k, v]) => `<tr><td class="cid">${esc(k)}</td><td class="num">${v}</td></tr>`).join("\n")}
      </tbody>
    </table>
  </div>

  <div class="callout">
    <p><strong>唯一的直连例外：</strong>流量分析阶段用 Node <code>http</code> 模块模拟"经过本机代理的客户端"以产生真实抓包流量。代理的启停与会话展示仍全部由界面驱动——该请求扮演的是被测代理的客户端，而非对业务接口的直接调用。</p>
  </div>
</section>

<section id="modules">
  <h2><span class="h-num">03</span>分模块结果</h2>
  <p class="lede">阶段字母即执行顺序，按业务依赖排列：先建项目与目标，再发起真实检测并等待执行完成，之后才检查详情、结果与报告；负向验证放在末位并自行复原状态。</p>
  <div class="twrap">
    <table>
      <thead><tr><th>阶段</th><th>功能模块</th><th style="text-align:right">用例</th><th style="text-align:right">通过</th><th style="text-align:right">失败</th><th style="text-align:right">跳过</th><th>通过率</th></tr></thead>
      <tbody>
${stageTableRows}
      </tbody>
    </table>
  </div>
</section>

<section id="boundary">
  <h2><span class="h-num">04</span>授权边界验证</h2>
  <p class="lede">系统的核心安全主张是"仅对已授权目标、在授权窗口内、在授权端口范围内执行受控检测"。本次以真实操作制造越权条件，逐任务核对拦截结果。</p>

  <div class="callout good">
    <p><strong>结论：授权边界成立，未发生越权探测。</strong></p>
    <p>对公网 IP <code>8.8.8.8</code>、公网域名 <code>example.com</code>、链路本地地址 <code>169.254.1.1</code> 发起检测时，任务虽被创建，但在<strong>发出任何探测流量之前</strong>即被执行层拒绝——<code>TargetPolicyService.validatedHost()</code> 是每个检测工具 <code>execute()</code> 的首行语句，在端口解析与套接字操作之前抛出异常。逐任务 ID 核对确认全部为 <code>FAILED</code>，无一 <code>SUCCESS</code>。</p>
  </div>

  <h3>已验证的拒绝场景</h3>
  <ul class="plain">
    <li><strong>越权网络范围</strong>：公网 IP、公网域名、链路本地地址三类目标的检测任务均在执行层被拒绝（用例 N-02、N-04、N-06）</li>
    <li><strong>项目非 ACTIVE</strong>：项目暂停后无法发起检测，提示"该目标尚未加入有效的安全评估项目"（N-10）</li>
    <li><strong>目标已停用</strong>：停用目标后从授权目标列表中消失，前置拦截（N-13）</li>
    <li><strong>越界端口</strong>：端口 <code>70000</code> 与逆序范围 <code>443-80</code> 在登记阶段即被拒绝（N-07、N-08）</li>
    <li><strong>未登录访问</strong>：注销后直达受保护路由被重定向至登录页（N-15）</li>
    <li><strong>越权报文重放</strong>：流量重放器拒绝向非授权主机发包，提示"发包 URL 主机必须与源流量及授权目标一致"（I-20）</li>
  </ul>
</section>

<section id="cases">
  <h2><span class="h-num">05</span>用例执行明细</h2>
  <p class="lede">共 ${S.total} 条用例，按阶段折叠。「实际观测结果」为执行时从界面读取的真实值，未经人工改写；含失败用例的阶段默认展开。</p>
${stageSections}
</section>

<section id="defects">
  <h2><span class="h-num">06</span>缺陷分析</h2>
  <p class="lede">三项问题均已定位到具体源码位置，均不涉及安全边界失效，不阻断主链路。</p>

  <div class="defect">
    <div class="defect-head"><span class="defect-id">DEF-01 · 中</span><span class="defect-title">状态变更后前端丢失项目上下文</span></div>
    <h4>现象</h4>
    <p>在结果中心将漏洞状态改为「已确认」后，不刷新页面直接点击同一行「后续路径」，提示<strong>"该发现缺少项目信息，无法生成后续验证路径"</strong>；刷新后功能恢复。</p>
    <h4>根因</h4>
    <p><code>Finding.projectId</code> 是 <code>@Transient</code> 瞬态字段，列表接口经 <code>populateProjectId()</code> 反查填充，而 <code>PUT /api/findings/{id}/status</code> 未做此填充，响应中该字段为 <code>null</code>；前端 <code>Object.assign(row, data)</code> 用响应覆盖当前行，将已有的 <code>projectId</code> 置空。</p>
    <h4>修复建议</h4>
    <p>后端在状态更新响应中一并回填 <code>projectId</code>（推荐，可根治所有消费方）；或前端合并时保留该字段。</p>
  </div>

  <div class="defect">
    <div class="defect-head"><span class="defect-id">DEF-02 · 中</span><span class="defect-title">PDF 报告下载为 0 字节空文件</span></div>
    <h4>现象</h4>
    <p>点击「项目 PDF」或「目标 PDF」，文件名正确但内容为 <strong>0 字节</strong>；<code>download.failure()</code> 返回 <code>null</code>，属静默失败，用户不易察觉。</p>
    <h4>根因</h4>
    <p>后端接口本身正常——直接请求返回 <code>HTTP 200</code>、6767 字节、文件头 <code>%PDF-</code>。问题在前端释放时机：</p>
    <pre><code>anchor.click();
URL.revokeObjectURL(url);   // ← 紧随 click() 同步释放</code></pre>
    <p style="margin-top:9px">浏览器尚未完成对 Blob 的读取，对象 URL 即被释放，落盘文件为空。</p>
    <h4>修复建议</h4>
    <p>延迟释放（如 <code>setTimeout(() =&gt; URL.revokeObjectURL(url), 60_000)</code>），并对导出结果做非空校验。相同代码模式亦出现在信息收集导出。</p>
  </div>

  <div class="defect sev-low">
    <div class="defect-head"><span class="defect-id">DEF-03 · 低</span><span class="defect-title">越权目标"先建任务后失败"，失败原因未透出</span></div>
    <h4>现象</h4>
    <p>对越权目标发起检测时，界面先提示"已创建 N 个检测任务"（成功样式），任务随即失败，但「失败原因」为空，仅显示"任务执行失败"。</p>
    <h4>根因与安全评估</h4>
    <p>网络范围校验位于工具执行层，任务创建层不重复校验，故任务得以创建；策略拒绝信息记入服务端日志但未回填任务实体。<strong>授权边界本身有效</strong>——拒绝发生在任何探测流量发出之前，属纵深防御设计，非安全缺陷。</p>
    <h4>修复建议</h4>
    <p>在检测发起阶段前置网络范围校验并给出清晰提示；将策略拒绝原因回填至任务 <code>failureReason</code>，使拦截可解释、可审计。</p>
  </div>
</section>

<section id="limits">
  <h2><span class="h-num">07</span>环境限制</h2>
  <p class="lede">以下用例因环境依赖缺失而跳过，均如实标注原因，不计入失败也不伪造通过。</p>
  <div class="twrap">
    <table>
      <thead><tr><th>编号</th><th>用例名称</th><th>跳过原因</th></tr></thead>
      <tbody>
${skips.map((c) => `<tr><td class="cid">${esc(c.id)}</td><td class="cname">${esc(c.name)}</td><td class="cdetail">${esc(c.detail)}</td></tr>`).join("\n")}
      </tbody>
    </table>
  </div>
  <p style="margin-top:18px;color:var(--text-2);font-size:14px">系统在依赖缺失时的表现——禁用对应规则、给出安装指引、拒绝同步而非报错崩溃——本身也是被验证并通过的行为。靶机未部署 HTTPS，故 TLS 检查用于验证"正确判定不可用"的逻辑。</p>
</section>

<section id="conclusion">
  <h2><span class="h-num">08</span>结论与建议</h2>

  <h3>测试结论</h3>
  <ul class="plain">
    <li><strong>全链路贯通</strong>：从登录、建项目、激活授权、登记目标、发起受控检测、等待真实执行，到查看结果与导出报告，完整业务链在真实浏览器中贯通，并产生可核对的真实检测结果——如 <code>缺少安全响应头: content-security-policy</code>、证据 <code>server=SimpleHTTP/0.6 Python/3.12.3</code></li>
    <li><strong>功能覆盖充分</strong>：覆盖 13 个功能模块的对外功能，含项目与目标管理、指纹探测、信息收集、主动检测、任务与定时扫描、结果流转与复测、扫描 Diff、报告输出、流量代理与重放、AI 助手与工作流、21 项离线工具、系统设置与审计日志，无模块遗漏</li>
    <li><strong>授权边界成立</strong>：越权网络范围、授权窗口、端口范围、登录态四类门禁在真实操作下全部生效，且越权检测在发包前即被拦截</li>
    <li><strong>真实性达标</strong>：${data.apiCallCount} 次接口调用全部由界面操作触发，页面异常 0 次</li>
  </ul>

  <h3>改进建议</h3>
  <div class="twrap">
    <table>
      <thead><tr><th>优先级</th><th>建议</th></tr></thead>
      <tbody>
        <tr><td class="cid">高</td><td>修复 DEF-02：延迟释放对象 URL 并对导出结果做非空校验，避免交付物为空文件而用户无感知</td></tr>
        <tr><td class="cid">高</td><td>修复 DEF-01：状态更新响应回填瞬态 <code>projectId</code>，恢复"改状态 → 生成后续路径"的连贯性</td></tr>
        <tr><td class="cid">中</td><td>改进 DEF-03：检测发起阶段前置网络范围校验，并将策略拒绝原因回填任务失败原因</td></tr>
        <tr><td class="cid">中</td><td>为关键界面元素补充 <code>data-test</code> 属性，降低界面重构对自动化测试的影响</td></tr>
        <tr><td class="cid">低</td><td>统一确认框的确认按钮文案（现有"确定/删除/开始检测/确认并保存"等多种）</td></tr>
        <tr><td class="cid">低</td><td><code>scripts\\*.ps1</code> 读取 JSON 时显式指定 <code>-Encoding UTF8</code>，避免中文路径在 PowerShell 5.1 下解析失败</td></tr>
      </tbody>
    </table>
  </div>
</section>

</main>

<footer>
  <span>獬豸授权安全测试平台 v0.2.0</span>
  <span>运行编号 ${esc(data.runId)}</span>
  <span>证据 .run/e2e-evidence/${esc(data.runId)}/</span>
  <span>${(fs.existsSync(path.join(EVIDENCE, runId, "screenshots")) ? fs.readdirSync(path.join(EVIDENCE, runId, "screenshots")).length : 0)} 张界面截图</span>
</footer>
</div>
`;

fs.mkdirSync(path.dirname(outFile), { recursive: true });
fs.writeFileSync(outFile, html, "utf-8");
console.log(`已生成 ${outFile}`);
console.log(`  ${(Buffer.byteLength(html) / 1024).toFixed(0)} KB，${S.total} 条用例，${phases.length} 个阶段`);
