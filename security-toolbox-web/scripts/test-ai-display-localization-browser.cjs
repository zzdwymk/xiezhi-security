// Isolated rendering of real MarkdownBody and workflow/provider template fragments.
// No business data, model calls, desktop sessions or remote requests are used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const { baseParse } = require('@vue/compiler-dom');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '../.run/ai-display-localization', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(output, { recursive: true });
const workflow = parse(fs.readFileSync(path.join(root, 'src/views/Workflow.vue'), 'utf8')).descriptor;
const findings = parse(fs.readFileSync(path.join(root, 'src/views/Findings.vue'), 'utf8')).descriptor;
const ast = ts.createSourceFile('workflow.ts', workflow.scriptSetup.content, ts.ScriptTarget.Latest, true);
function scriptDeclaration(name) {
  const statement = ast.statements.find(node =>
    ts.isFunctionDeclaration(node) ? node.name?.text === name :
    ts.isVariableStatement(node) && node.declarationList.declarations.some(decl => decl.name.getText(ast) === name));
  assert.ok(statement, 'Missing production declaration ' + name);
  return ts.transpileModule(statement.getText(ast), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
}
function templateFragment(descriptor, predicate) {
  function walk(node) {
    if (node.type === 1 && predicate(node)) return node.loc.source;
    for (const child of node.children || []) { const result = walk(child); if (result) return result; }
  }
  const fragment = walk(baseParse(descriptor.template.content));
  assert.ok(fragment, 'Missing production template fragment');
  return fragment;
}
const suggestionTitle = templateFragment(workflow, n => n.tag === 'strong' && n.loc.source.includes('localizeSuggestionText(item.title)'));
const suggestionDetail = templateFragment(workflow, n => n.tag === 'MarkdownBody' && n.loc.source.includes(':content="item.detail"'));
const providerTag = templateFragment(findings, n => n.tag === 'el-tag' && n.loc.source.includes('postScanPlan.provider'));
const fixtureId = path.join(root, '__ai-display-localization.vue').replace(/\\/g, '/');
const fixture = `<script setup>
import {computed,reactive,shallowRef} from 'vue';
import MarkdownBody from '/src/components/MarkdownBody.vue';
import {actionStepLabel,aiProviderLabel,localizeAiDisplayText,localizeAiInlineIdentifier} from '/src/utils/aiPresentation';
import {renderMarkdown} from '/src/utils/markdown';
const state=reactive({content:'',localize:true,nodeLabels:{},provider:'openai-compatible'});
const nodes=shallowRef([{id:'service-scan',data:{tool:'nmap_service_scan',label:'服务与版本识别'}},{id:'service-scan-extra',data:{tool:'http_headers',label:'补充响应头'}}]);
const item=reactive({title:'service-scan → service-scan-extra',detail:''});
const postScanPlan=computed(()=>({provider:state.provider}));
${scriptDeclaration('SUGGESTION_TERM_LABELS')}
${scriptDeclaration('suggestionNodeLabels')}
${scriptDeclaration('localizeSuggestionText')}
window.displayFixture={state,nodes,item,localizeAiDisplayText,localizeAiInlineIdentifier,aiProviderLabel,renderMarkdown};
</script><template><main>
<section id="body"><MarkdownBody :content="state.content" :localize="state.localize" :node-labels="state.nodeLabels" /></section>
<section id="suggestion">${suggestionTitle}${suggestionDetail}</section>
<section id="provider">${providerTag}</section>
</main></template>`;
const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><style>main{max-width:900px;margin:30px auto}section{margin:20px;padding:15px;border:1px solid #ddd}</style></head><body><div id="app"></div><script type="module">
import {createApp} from 'vue';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';
import '/src/unified-theme.css';import Fixture from '/__ai-display-localization.vue';createApp(Fixture).use(ElementPlus).mount('#app');
</script></body></html>`;
let browser, server;
const checks = [], errors = [], unexpectedRequests = [];
async function check(name, fn) { await fn(); checks.push({ name, status: 'PASS' }); console.log('PASS ' + name); }
(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.join(output, 'cache'), plugins: [{
    name: 'ai-display-fixture', resolveId(id) { if (id === '/__ai-display-localization.vue') return fixtureId; },
    load(id) { if (id === fixtureId) return fixture; }, configureServer(s) { s.middlewares.use(async (req, res, next) => {
      if (req.url !== '/__ai-display-localization') return next();
      res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(await s.transformIndexHtml(req.url, html));
    }); }
  }, vue()], optimizeDeps: { entries: [], include: ['vue', 'marked', 'dompurify', 'element-plus'], noDiscovery: true },
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/desktop-release/**', '**/dist/**'] } }, logLevel: 'error' });
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.AI_PROGRESS_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
  page.on('pageerror', e => errors.push(e.message));
  page.on('request', request => { if (!request.url().startsWith('http://127.0.0.1:') && !request.url().startsWith('data:')) unexpectedRequests.push(request.url()); });
  await page.goto('http://127.0.0.1:' + server.httpServer.address().port + '/__ai-display-localization', { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.locator('#body .markdown-body').waitFor({ state: 'attached' });
  await check('known terms and statuses localize without rewriting ordinary English, paths or unknown identifiers', async () => {
    const actual = await page.evaluate(() => {
      const f = window.displayFixture;
      return [f.localizeAiDisplayText('AI Runtime 协议校验；Harness 协议；Ledger 证据链；本 Turn 已结束。状态:SUCCESS，APPROVED，CONFIRMED，WAITING_TASKS；工具 fscan_scan。'),
        f.localizeAiDisplayText('Harness the power. Ledger accounting. Turn left. RuntimeException my_SUCCESS SUCCESS_BACKUP fscan_scan.exe /tmp/fscan_scan https://example.test/FAILED'),
        f.localizeAiInlineIdentifier('constructor'), f.aiProviderLabel('constructor')];
    });
    assert.equal(actual[0], '智能服务 协议校验；执行校验 协议；执行记录 证据链；本轮对话 已结束。状态:已完成，已通过，已确认，等待前置任务；工具 fscan 主机扫描。');
    assert.equal(actual[1], 'Harness the power. Ledger accounting. Turn left. RuntimeException my_SUCCESS SUCCESS_BACKUP fscan_scan.exe /tmp/fscan_scan https://example.test/FAILED');
    assert.equal(actual[2], 'constructor'); assert.equal(actual[3], '来源未说明');
  });
  const evidenceId = 'ev-435b6db24330fb59cd361bf6';
  const otherEvidenceId = 'ev-45d913ea223f9ff9190d4357';
  await check('only exact product evidence IDs are hidden in prose and single-token inline code', async () => {
    const result = await page.evaluate(({ evidenceId, otherEvidenceId }) => {
      const f = window.displayFixture;
      const preserved = [`prefix_${evidenceId}`, `${evidenceId}-copy`, `${evidenceId}.json`, evidenceId.slice(0, -1), evidenceId + 'a', evidenceId.toUpperCase(),
        `https://example.test/${evidenceId}?ref=${otherEvidenceId}`, `/tmp/${evidenceId}`, `C:\\evidence\\${evidenceId}`, '任务 #435、发现 #243、CVE-2025-12345'];
      return {
        prose: f.localizeAiDisplayText(`证据${evidenceId} 支持该结论（证据 ${otherEvidenceId}）。`),
        inline: f.localizeAiInlineIdentifier(evidenceId),
        command: f.localizeAiInlineIdentifier(`echo ${evidenceId}`),
        protected: preserved.map(value => [value, f.localizeAiDisplayText(value)]),
      };
    }, { evidenceId, otherEvidenceId });
    assert.equal(result.prose, '相关证据 支持该结论（相关证据）。');
    assert.equal(result.inline, '相关证据'); assert.equal(result.command, `echo ${evidenceId}`);
    for (const [original, actual] of result.protected) assert.equal(actual, original);
  });
  await check('evidence aliases apply to real Markdown while URLs, commands, business IDs and user input remain intact', async () => {
    const evidenceMarkdown = [`证据${evidenceId} 支持发现 #243 和任务 #435，关联 CVE-2025-12345（证据 ${otherEvidenceId}）。`,
      '`' + evidenceId + '`', '`echo ' + evidenceId + '`', '```text\n' + evidenceId + '\n```',
      `[证据${evidenceId}](https://example.test/${evidenceId} "证据 ${otherEvidenceId}")`, `https://example.test/${otherEvidenceId}`].join('\n\n');
    await page.evaluate(content => { window.displayFixture.state.content = content; window.displayFixture.state.localize = true; }, evidenceMarkdown);
    await page.waitForFunction(() => document.querySelector('#body p')?.textContent.includes('相关证据'));
    assert.equal(await page.locator('#body p').first().textContent(), '相关证据 支持发现 #243 和任务 #435，关联 CVE-2025-12345（相关证据）。');
    assert.deepEqual(await page.locator('#body p code').allTextContents(), ['相关证据', `echo ${evidenceId}`]);
    assert.equal((await page.locator('#body pre code').textContent()).trim(), evidenceId);
    assert.equal(await page.locator('#body a').first().getAttribute('href'), `https://example.test/${evidenceId}`);
    assert.equal(await page.locator('#body a').first().getAttribute('title'), '相关证据');
    assert.equal(await page.locator('#body a').last().textContent(), `https://example.test/${otherEvidenceId}`);
    await page.evaluate(() => { window.displayFixture.state.localize = false; });
    await page.waitForFunction(id => document.querySelector('#body p')?.textContent.includes('证据' + id), evidenceId);
    assert.equal(await page.locator('#body p code').first().textContent(), evidenceId);
    assert.equal(await page.evaluate(() => window.displayFixture.state.content), evidenceMarkdown);
    assert.equal(await page.evaluate(source => window.displayFixture.renderMarkdown(source).includes(source), evidenceId), true);
    await page.evaluate(() => { window.displayFixture.state.localize = true; });
  });
  const content = ['## nmap_service_scan', '状态 **SUCCESS**，`APPROVED`，`CONFIRMED`，`fscan_scan`。',
    '`fscan_scan --ports 18888`', '```json', '{"tool":"fscan_scan","status":"SUCCESS"}', '```',
    '[nmap_service_scan](https://example.test/nmap_service_scan?status=SUCCESS "SUCCESS nmap_service_scan")',
    'https://example.test/fscan_scan', '`https://example.test/SUCCESS`', '<kbd>SUCCESS</kbd> <samp>fscan_scan</samp>'].join('\n\n');
  await check('Markdown prose and pure internal inline identifiers localize while commands and code stay exact', async () => {
    await page.evaluate(content => { window.displayFixture.state.content = content; }, content);
    await page.locator('#body h2').waitFor();
    assert.equal(await page.locator('#body h2').innerText(), 'Nmap 服务识别');
    assert.equal(await page.locator('#body strong').innerText(), '已完成');
    assert.deepEqual(await page.locator('#body p code').allTextContents(), ['已通过', '已确认', 'fscan 主机扫描', 'fscan_scan --ports 18888', 'https://example.test/SUCCESS']);
    assert.equal((await page.locator('#body pre code').textContent()).trim(), '{"tool":"fscan_scan","status":"SUCCESS"}');
    assert.equal(await page.locator('#body kbd').textContent(), 'SUCCESS');
    assert.equal(await page.locator('#body samp').textContent(), 'fscan_scan');
    assert.equal(await page.evaluate(() => window.displayFixture.state.content), content);
  });
  await check('link labels localize but destinations and visible URL addresses remain exact', async () => {
    const links = page.locator('#body a');
    assert.deepEqual(await links.allTextContents(), ['Nmap 服务识别', 'https://example.test/fscan_scan']);
    assert.equal(await links.nth(0).getAttribute('href'), 'https://example.test/nmap_service_scan?status=SUCCESS');
    assert.equal(await links.nth(0).getAttribute('rel'), 'noopener noreferrer');
    assert.equal(await links.nth(0).getAttribute('title'), '已完成 Nmap 服务识别');
    assert.equal(await links.nth(1).getAttribute('href'), 'https://example.test/fscan_scan');
  });
  await check('user mode and raw render default preserve source codes even after localized renders', async () => {
    await page.evaluate(() => { window.displayFixture.state.localize = false; });
    await page.waitForFunction(() => document.querySelector('#body h2')?.textContent === 'nmap_service_scan');
    assert.equal(await page.locator('#body strong').innerText(), 'SUCCESS');
    assert.deepEqual(await page.locator('#body p code').allTextContents(), ['APPROVED', 'CONFIRMED', 'fscan_scan', 'fscan_scan --ports 18888', 'https://example.test/SUCCESS']);
    const modes = await page.evaluate(() => { const f = window.displayFixture; return [f.renderMarkdown('SUCCESS'), f.renderMarkdown('SUCCESS', { localizeToolCodes: true }), f.renderMarkdown('SUCCESS')]; });
    assert.match(modes[0], /SUCCESS/); assert.match(modes[1], /已完成/); assert.equal(modes[2], modes[0]);
    assert.equal(await page.evaluate(() => window.displayFixture.state.content), content);
  });
  await check('actual workflow suggestions resolve current node IDs by their visible names', async () => {
    await page.evaluate(() => { window.displayFixture.state.localize = true; window.displayFixture.item.detail = '先执行 `service-scan`，再执行 service-scan-extra。\n\n```text\nservice-scan --argument\n```\n\n[证据](https://example.test/service-scan)'; });
    await page.locator('#suggestion pre').waitFor();
    assert.equal(await page.locator('#suggestion > strong').innerText(), '服务与版本识别 → 补充响应头');
    assert.equal(await page.locator('#suggestion p code').innerText(), '服务与版本识别');
    assert.match(await page.locator('#suggestion .markdown-body').innerText(), /再执行 补充响应头/);
    assert.equal((await page.locator('#suggestion pre code').textContent()).trim(), 'service-scan --argument');
    assert.equal(await page.locator('#suggestion a').getAttribute('href'), 'https://example.test/service-scan');
    await page.screenshot({ path: path.join(output, 'display-localization.png'), fullPage: true });
  });
  await check('node rename invalidates display cache and inserted user names are text, not HTML or replacement syntax', async () => {
    await page.evaluate(() => { const f = window.displayFixture; f.nodes.value = [{ id: 'service-scan', data: { tool: 'nmap_service_scan', label: '<img src=x onerror=alert(1)> $&' } }, f.nodes.value[1]]; });
    await page.waitForFunction(() => document.querySelector('#suggestion > strong')?.textContent.includes('<img'));
    assert.equal(await page.locator('#suggestion p code').textContent(), '<img src=x onerror=alert(1)> $&');
    assert.equal(await page.locator('#suggestion img').count(), 0);
    assert.match(await page.locator('#suggestion > strong').textContent(), /\$&/);
  });
  await check('provider label distinguishes model analysis with rule planning from local fallback and unknown source', async () => {
    assert.equal(await page.locator('#provider').innerText(), '模型分析 · 规则规划');
    await page.evaluate(() => { window.displayFixture.state.provider = 'local-rule-fallback'; });
    await page.waitForFunction(() => document.querySelector('#provider').textContent.includes('未采用模型结果'));
    assert.equal(await page.locator('#provider').innerText(), '本地规则（未采用模型结果）');
    await page.evaluate(() => { window.displayFixture.state.provider = 'custom-internal-provider'; });
    await page.waitForFunction(() => document.querySelector('#provider').textContent.includes('来源未说明'));
    assert.equal(await page.locator('#provider').innerText(), '来源未说明');
  });
  assert.deepEqual(errors, []); assert.deepEqual(unexpectedRequests, []);
  await page.screenshot({ path: path.join(output, 'escaped-node-and-unknown-source.png'), fullPage: true });
  console.log('EVIDENCE ' + output);
})().catch(error => { checks.push({ status: 'FAIL', error: error.stack }); console.error(error); process.exitCode = 1; })
  .finally(async () => { fs.writeFileSync(path.join(output, 'results.json'), JSON.stringify({ checks, errors, unexpectedRequests }, null, 2)); await browser?.close(); await server?.close(); });
