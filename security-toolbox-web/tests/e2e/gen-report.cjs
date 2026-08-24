/*
 * 从测试证据（result.json）生成软件测试文档中的结果章节（Markdown）。
 *
 * 用法：node tests/e2e/gen-report.cjs [runId]
 * 省略 runId 时使用 .run/e2e-evidence 下最新的一次运行。
 */
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..", "..", "..");
const EVIDENCE = path.join(ROOT, ".run", "e2e-evidence");

const PHASE_ORDER = ["A", "B", "C", "E", "F", "D", "G", "H", "I", "K", "L", "M", "N"];

const PHASE_MODULE = {
  A: "登录鉴权与环境依赖检查",
  B: "安全评估项目管理",
  C: "授权目标管理",
  E: "漏洞知识库与主动检测",
  F: "任务控制中心与定时扫描",
  D: "项目详情工作区（探测/信息收集/审批/审计/记忆）",
  G: "漏洞结果中心与复测",
  H: "报告输出",
  I: "流量分析（MITM 代理）",
  K: "AI 安全助手与红队工作流",
  L: "离线工具集",
  M: "系统设置与审计日志",
  N: "授权边界负向验证",
};

function latestRun() {
  if (!fs.existsSync(EVIDENCE)) throw new Error(`证据目录不存在: ${EVIDENCE}`);
  const dirs = fs
    .readdirSync(EVIDENCE)
    .filter((d) => fs.existsSync(path.join(EVIDENCE, d, "result.json")))
    .map((d) => ({ d, m: fs.statSync(path.join(EVIDENCE, d, "result.json")).mtimeMs }))
    .sort((a, b) => b.m - a.m);
  if (!dirs.length) throw new Error("未找到任何包含 result.json 的运行记录");
  return dirs[0].d;
}

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/\|/g, "\\|")
    .replace(/\r?\n/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function phaseOf(id) {
  const m = String(id).match(/^([A-Z]+)-/);
  return m ? m[1] : "?";
}

function main() {
  const runId = process.argv[2] || latestRun();
  const dir = path.join(EVIDENCE, runId);
  const data = JSON.parse(fs.readFileSync(path.join(dir, "result.json"), "utf-8"));

  const byPhase = {};
  for (const c of data.cases) {
    const p = phaseOf(c.id);
    (byPhase[p] = byPhase[p] || []).push(c);
  }
  const phases = PHASE_ORDER.filter((p) => byPhase[p]).concat(
    Object.keys(byPhase).filter((p) => !PHASE_ORDER.includes(p)).sort(),
  );

  const out = [];

  // ---- 汇总统计 ----
  const s = data.summary;
  const rate = s.total ? ((s.pass / (s.total - s.skip || 1)) * 100).toFixed(1) : "0.0";
  out.push("### 8.1 总体执行结果\n");
  out.push("| 指标 | 数值 |");
  out.push("| --- | --- |");
  out.push(`| 运行编号 | \`${data.runId}\` |`);
  out.push(`| 开始时间 | ${data.startedAt} |`);
  out.push(`| 结束时间 | ${data.finishedAt} |`);
  out.push(`| 执行时长 | ${Math.floor(data.durationSeconds / 60)} 分 ${data.durationSeconds % 60} 秒 |`);
  out.push(`| 用例总数 | ${s.total} |`);
  out.push(`| 通过 | ${s.pass} |`);
  out.push(`| 失败 | ${s.fail} |`);
  out.push(`| 跳过 | ${s.skip} |`);
  out.push(`| 有效通过率 | ${rate}%（不计跳过用例） |`);
  out.push(`| UI 触发的接口调用 | ${data.apiCallCount} 次 |`);
  out.push(`| 页面 JS 异常 | ${(data.pageErrors || []).length} 次 |`);
  out.push("");

  // ---- 按阶段统计 ----
  out.push("### 8.2 分模块执行结果\n");
  out.push("| 阶段 | 功能模块 | 用例数 | 通过 | 失败 | 跳过 | 通过率 |");
  out.push("| --- | --- | --- | --- | --- | --- | --- |");
  for (const p of phases) {
    const cs = byPhase[p];
    const pass = cs.filter((c) => c.status === "PASS").length;
    const fail = cs.filter((c) => c.status === "FAIL").length;
    const skip = cs.filter((c) => c.status === "SKIP").length;
    const denom = cs.length - skip;
    const r = denom > 0 ? ((pass / denom) * 100).toFixed(0) + "%" : "—";
    out.push(`| ${p} | ${PHASE_MODULE[p] || "—"} | ${cs.length} | ${pass} | ${fail} | ${skip} | ${r} |`);
  }
  out.push(`| **合计** | | **${s.total}** | **${s.pass}** | **${s.fail}** | **${s.skip}** | **${rate}%** |`);
  out.push("");

  // ---- 明细用例表 ----
  out.push("### 8.3 测试用例执行明细\n");
  out.push("> 「实际结果」栏为自动化执行时从界面读取的真实观测值，未经人工改写。\n");
  for (const p of phases) {
    const cs = byPhase[p];
    out.push(`#### 阶段 ${p} — ${PHASE_MODULE[p] || ""}\n`);
    out.push("| 用例编号 | 用例名称 | 结论 | 实际结果 / 说明 |");
    out.push("| --- | --- | --- | --- |");
    for (const c of cs) {
      const verdict = { PASS: "通过", FAIL: "**失败**", SKIP: "跳过", WARN: "警告" }[c.status] || c.status;
      out.push(`| ${c.id} | ${esc(c.name)} | ${verdict} | ${esc(c.detail) || "—"} |`);
    }
    out.push("");
  }

  // ---- 失败清单 ----
  const fails = data.cases.filter((c) => c.status === "FAIL");
  out.push("### 8.4 失败用例清单\n");
  if (!fails.length) {
    out.push("本次执行无失败用例。\n");
  } else {
    out.push("| 用例编号 | 用例名称 | 失败信息 |");
    out.push("| --- | --- | --- |");
    for (const c of fails) out.push(`| ${c.id} | ${esc(c.name)} | ${esc(c.detail)} |`);
    out.push("");
  }

  // ---- 跳过清单 ----
  const skips = data.cases.filter((c) => c.status === "SKIP");
  out.push("### 8.5 跳过用例及原因\n");
  if (!skips.length) {
    out.push("本次执行无跳过用例。\n");
  } else {
    out.push("| 用例编号 | 用例名称 | 跳过原因 |");
    out.push("| --- | --- | --- |");
    for (const c of skips) out.push(`| ${c.id} | ${esc(c.name)} | ${esc(c.detail)} |`);
    out.push("");
  }

  // ---- 接口调用证据 ----
  const methodCount = {};
  const pathCount = {};
  for (const a of data.apiCalls || []) {
    methodCount[a.method] = (methodCount[a.method] || 0) + 1;
    const key = a.url.split("?")[0].replace(/\/\d+/g, "/{id}");
    pathCount[key] = (pathCount[key] || 0) + 1;
  }
  const topPaths = Object.entries(pathCount).sort((a, b) => b[1] - a[1]).slice(0, 25);
  out.push("### 8.6 界面驱动的接口调用统计（真实性证据）\n");
  out.push(
    "下表为测试过程中由**浏览器界面操作触发**的后端接口调用。测试脚本本身不构造任何业务接口请求，" +
      "该统计可作为「全链路经由真实 UI 操作」的客观证据。\n",
  );
  out.push(`请求方法分布：${Object.entries(methodCount).map(([k, v]) => `${k} ${v} 次`).join("，")}。\n`);
  out.push("| 接口路径 | 调用次数 |");
  out.push("| --- | --- |");
  for (const [k, v] of topPaths) out.push(`| \`${k}\` | ${v} |`);
  out.push("");

  // ---- 截图证据 ----
  const shotDir = path.join(dir, "screenshots");
  let shots = [];
  if (fs.existsSync(shotDir)) shots = fs.readdirSync(shotDir).filter((f) => f.endsWith(".png"));
  out.push("### 8.7 证据文件清单\n");
  out.push(`- 结构化结果：\`.run/e2e-evidence/${runId}/result.json\``);
  out.push(`- 界面截图：\`.run/e2e-evidence/${runId}/screenshots/\`，共 ${shots.length} 张`);
  out.push("");
  if (shots.length) {
    out.push("主要截图：\n");
    out.push("| 序号 | 文件名 |");
    out.push("| --- | --- |");
    for (const f of shots.slice(0, 40)) {
      out.push(`| ${f.slice(0, 3)} | \`${f}\` |`);
    }
    out.push("");
  }

  const text = out.join("\n");
  const target = path.join(ROOT, ".run", `test-report-section-${runId}.md`);
  fs.writeFileSync(target, text, "utf-8");
  console.log(text);
  console.error(`\n[已写入] ${target}`);
}

main();
