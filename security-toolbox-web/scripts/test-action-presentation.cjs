// Presentation contracts: execution caution is not vulnerability severity;
// known titles localize without rewriting stored or unknown scanner evidence.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
function load(file) {
  const output = { exports: {} };
  const code = ts.transpileModule(fs.readFileSync(file, 'utf8'), {
    compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const localRequire = name => name.startsWith('.') ? load(path.resolve(path.dirname(file), `${name}.ts`)) : require(name);
  vm.runInNewContext(code, { module: output, exports: output.exports, require: localRequire });
  return output.exports;
}
const { actionRiskLabel, actionStepLabel, findingTitleLabel, copilotReferenceTypeLabel, displayKnownTestName } = load(path.resolve(__dirname, '../src/utils/aiPresentation.ts'));
const { parse } = require('@vue/compiler-sfc');
const dashboardSource = parse(fs.readFileSync(path.resolve(__dirname, '../src/views/Dashboard.vue'), 'utf8')).descriptor.scriptSetup.content;
const dashboardAst = ts.createSourceFile('Dashboard.ts', dashboardSource, ts.ScriptTarget.Latest, true);
const displayFunction = dashboardAst.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'displayedStepTitle');
const displayCode = ts.transpileModule(displayFunction.getText(dashboardAst), { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText;
const displayedStepTitle = vm.runInNewContext(displayCode + '\ndisplayedStepTitle', { actionStepLabel });
assert.equal(actionRiskLabel('CAUTION'), '需谨慎');
assert.equal(actionRiskLabel('MEDIUM'), '中等风险');
assert.equal(actionRiskLabel('BLOCKED'), '已拦截');
assert.equal(actionStepLabel('nuclei_scan', 'nuclei'), 'Nuclei 通用漏洞扫描');
assert.equal(actionStepLabel('nuclei_scan', '仅检查首页'), '仅检查首页');
assert.equal(actionStepLabel('msf_scan', 'msf_scan'), 'Metasploit 模块执行');
assert.equal(displayedStepTitle({toolCode:'nuclei_scan',title:'nuclei'}), 'Nuclei 通用漏洞扫描');
assert.equal(displayedStepTitle({toolCode:'msf_scan',title:'msf'}), 'Metasploit 模块执行');
assert.equal(displayedStepTitle({toolCode:'nuclei_scan',title:'仅检查首页'}), '仅检查首页');
for (const type of ['target','task','finding','vulnerability','traffic','traffic-session','audit','audit-log','ai-settings-status'])
  assert.ok(/[\u4e00-\u9fff]/.test(copilotReferenceTypeLabel(type)));
assert.equal(copilotReferenceTypeLabel('target'), '授权目标');
assert.equal(copilotReferenceTypeLabel('unknown-type'), '功能引用');
assert.equal(displayKnownTestName('AI本机HTTP夹具-2026-10-01T12-38-32-728Z'), 'AI 本机 HTTP 测试目标 · 2026-10-01 20:38:32');
assert.equal(displayKnownTestName('AI本机闭环验收-2026-10-01T20-38-32-728Z'), 'AI 本机闭环验收 · 2026-10-02 04:38:32');
for (const value of ['用户目标-2026-10-01T12-38-32-728Z','AI本机HTTP夹具-2026-02-30T12-38-32-728Z','前缀 AI本机HTTP夹具-2026-10-01T12-38-32-728Z','AI本机HTTP夹具-2026-10-01T12:38:32.728Z'])
  assert.equal(displayKnownTestName(value),value);
const original = { title: 'Missing Anti-clickjacking Header', evidence: 'raw HTTP response', sourceTool: 'zap_scan' };
const before = JSON.stringify(original);
assert.equal(findingTitleLabel(original.title, original.sourceTool), '缺少防点击劫持响应头');
assert.equal(JSON.stringify(original), before);
assert.equal(findingTitleLabel(original.title, 'custom_scan'), original.title);
assert.equal(findingTitleLabel('Unrecognized alert title', 'zap_scan'), 'Unrecognized alert title');
assert.equal(findingTitleLabel('Content Security Policy (CSP) Header Not Set', 'zap_scan'), '未设置内容安全策略（CSP）响应头');
assert.equal(findingTitleLabel('X-Content-Type-Options Header Missing', 'zap_scan'), '缺少 X-Content-Type-Options 响应头');
assert.equal(findingTitleLabel('Server Leaks Version Information via "Server" HTTP Response Header Field', 'zap_scan'), 'Server 响应头泄露服务器版本信息');
console.log('PASS action-risk, Dashboard step-label, reference labels, strict legacy fixture names and original-evidence presentation assertions');
