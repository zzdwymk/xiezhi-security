// Render the production templates, including the exact post-scan dialog from Findings.
// This fixture has no API client and never creates or dispatches a real scan.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { parse } = require('@vue/compiler-sfc');
const { baseParse } = require('@vue/compiler-dom');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../.run/ai-markdown-surfaces', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(out, { recursive: true });
const descriptors = Object.fromEntries(['Findings', 'Tasks', 'Workflow', 'ProjectDetail'].map(name =>
  [name, parse(fs.readFileSync(path.join(root, 'src/views', name + '.vue'), 'utf8')).descriptor]));
function find(name, predicate) {
  function walk(node) {
    if (node.type === 1 && predicate(node)) return node;
    for (const child of node.children || []) { const result = walk(child); if (result) return result; }
  }
  const node = walk(baseParse(descriptors[name].template.content));
  assert.ok(node, 'Missing production fragment: ' + name);
  return node;
}
const hasClass = name => node => node.props.some(p => p.type === 6 && p.name === 'class' && p.value?.content.split(' ').includes(name));
const model = value => node => node.tag === 'el-dialog' && node.props.some(p => p.type === 7 && p.name === 'model' && p.exp?.content === value);
const descriptions = (name, value) => find(name, model(value)).children.find(n => n.type === 1 && n.tag === 'el-descriptions').loc.source;
const code = 'const evidence = "' + 'x'.repeat(170) + '";';
const markdown = ['## 验证路径', '**优先路径**', '', '- 检查已有证据', '- 核对授权目标', '',
  '| 检查项 | 结论 |', '| --- | --- |', '| 响应头 | 待确认 |', '', '```text', code, '```',
  '[证据链接](https://example.test/evidence)', '<script>window.surfaceXss=1</script><img src="https://example.test/tracker" onerror="window.surfaceXss=1">'
].join('\n');
const longAnalysis = markdown + '\n\n' + Array.from({ length: 16 }, (_, i) => '**核验步骤 ' + (i + 1) + '**\n\n只依据已保存的扫描证据进行解释。').join('\n\n');
const record = { id: 1, title: '扫描发现', sourceTool: 'http_headers', description: markdown, remediation: markdown, evidence: '**原始证据**\nHTTP/1.1 200 OK', status: 'OPEN', severity: 'LOW' };
const data = {
  analysis: longAnalysis, provider: 'openai-compatible', status: 'DRAFT', taskIds: [],
  paths: [{ id: 'path', title: '核对响应头', riskLevel: 'SAFE', confidence: 'HIGH', goal: markdown, prerequisites: ['**目标仍在授权范围**', '- 核对源扫描状态'], evidenceBasis: '**响应头证据**', limitations: ['**只读限制**'], stopConditions: ['**遇到异常停止**'] }],
  steps: [{ id: 'step', title: '检查响应头', phase: 'VERIFY', riskLevel: 'SAFE', automated: true, reason: markdown, prerequisites: ['**确认服务可用**'], expectedEvidence: '**证据字段**', impact: '**仅增加一次读取请求**', toolCode: 'http_headers' },
    { id: 'manual', title: '人工复核', phase: 'VERIFY', riskLevel: 'HIGH', automated: false, reason: '**等待人工复核**', expectedEvidence: '**复核记录**', blockedReason: '**此步骤不可自动执行**' }]
};
const jsValue = value => JSON.stringify(value).replace(/</g, '\\u003c');
const sfc = `<script setup lang="ts">
import {ref,reactive} from 'vue';
import MarkdownBody from '/src/components/MarkdownBody.vue';
import ProjectEvidenceResult from '/src/components/ProjectEvidenceResult.vue';
import FluentCodeBlock from '/src/components/FluentCodeBlock.vue';
import {InfoCircle,VideoPlay} from '/src/components/fluentIcons';
import {actionStepLabel,findingTitleLabel,aiProviderLabel,aiToolLabel,severityLabel} from '/src/utils/aiPresentation';
const postScanVisible=ref(true),postScanLoading=ref(false),postScanRefreshing=ref(false),postScanExecuting=ref(false),selectedPostScanSteps=ref(['step']);
const postScanPlan=reactive(${jsValue(data)});
const detail=reactive(${jsValue(record)}),findingDetail=detail,endFindingDetail=detail;
const detailResultSummary=ref(${jsValue(markdown)});
const nodeDetailRun=reactive({summary:detail.description,status:'SUCCESS',output:{raw:'**原始数据**'},log:'**原始日志**'});
const suggestionNodeLabels={};
const postScanStatusLabel=()=> '待执行',pathRiskType=()=> 'info',riskLevelLabel=v=>v,phaseLabel=v=>v,nodeStatusType=()=> 'success',statusLabel=v=>v,endFindingTagType=()=> 'info',findingSeverityType=()=> 'info',findingStatusLabel=v=>v;
${descriptors.Findings.scriptSetup.content.match(/function confidenceLabel\([^]*?\n\}/)[0]}
const executePostScanPath=()=>{window.fixtureDispatches=(window.fixtureDispatches||0)+1};
const refreshPostScanPath=()=>{};
window.markdownSurfaces={postScanPlan,detail,nodeDetailRun,detailResultSummary,postScanVisible};
</script><template>
${find('Findings', model('postScanVisible')).loc.source}
<main v-show="!postScanVisible" class="fixtures">
<section data-surface="findings">${descriptions('Findings', 'detailVisible')}</section>
<section data-surface="tasks">${find('Tasks', hasClass('task-result-summary')).loc.source}</section>
<section data-surface="workflow-node">${find('Workflow', hasClass('node-detail-body')).loc.source}</section>
<section data-surface="workflow-finding">${find('Workflow', hasClass('end-finding-detail')).loc.source}</section>
<section data-surface="project">${descriptions('ProjectDetail', 'findingDetailVisible')}</section>
</main></template>
${Object.values(descriptors).flatMap(d => d.styles.map(s => '<style scoped>' + s.content + '</style>')).join('\n')}`;
const fixtureId = path.join(root, '__ai-markdown-surfaces.vue').replace(/\\/g, '/');
const html = `<!doctype html><html lang="zh-CN" data-system-theme="light" data-window-material="none"><head><meta charset="utf-8"><style>
html,body{height:auto!important;overflow:auto!important}.fixtures{max-width:840px;margin:20px auto}.fixtures>section{margin:16px;padding:12px;border:1px solid var(--app-border)}
</style></head><body><div id="fixture"></div><script type="module">
import {createApp} from 'vue';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';
import '/src/desktop-v2.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';import '/src/motion.css';
import Fixture from '/__ai-markdown-surfaces.vue';createApp(Fixture).use(ElementPlus).mount('#fixture');
</script></body></html>`;
let server, browser;
const results = [], errors = [], unexpectedRequests = [];
async function check(name, fn) { await fn(); results.push({ name, status: 'PASS' }); console.log('PASS ' + name); }
(async () => {
  const { createServer } = await import('vite');
  const pluginVue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.join(out, 'cache'), plugins: [{
    name: 'production-markdown-fragments', resolveId(id) { if (id === '/__ai-markdown-surfaces.vue') return fixtureId; },
    load(id) { if (id === fixtureId) return sfc; }, configureServer(s) { s.middlewares.use(async (req, res, next) => {
      if (req.url !== '/__ai-markdown-surfaces') return next();
      res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(await s.transformIndexHtml(req.url, html));
    }); }
  }, pluginVue()], optimizeDeps:{entries:[],include:['vue','marked','dompurify','element-plus'],noDiscovery:true},
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/desktop-release/**', '**/dist/**'] } }, logLevel: 'error' });
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.AI_PROGRESS_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 }, reducedMotion: 'reduce' });
  page.on('pageerror', e => errors.push(e.message));
  page.on('request', req => { if (!req.url().startsWith('http://127.0.0.1:') && !req.url().startsWith('data:')) unexpectedRequests.push(req.url()); });
  await page.goto('http://127.0.0.1:' + server.httpServer.address().port + '/__ai-markdown-surfaces');
  await page.locator('.post-scan-summary h2').waitFor();
  await check('actual post-scan analysis, paths and step explanations render Markdown', async () => {
    const summary = page.locator('.post-scan-summary');
    assert.equal(await summary.locator('h2').innerText(), '验证路径');
    assert.equal(await summary.locator('li').count(), 2);
    assert.equal(await summary.locator('table td').count(), 2);
    assert.equal((await summary.locator('pre code').innerText()).trim(), code);
    assert.equal(await summary.locator('a').getAttribute('rel'), 'noopener noreferrer');
    assert.equal(await page.locator('.post-scan-paths .post-scan-prose h2').count(), 1);
    for (const expected of ['目标仍在授权范围', '响应头证据', '只读限制', '遇到异常停止', '确认服务可用', '证据字段', '仅增加一次读取请求', '此步骤不可自动执行']) {
      assert.equal(await page.locator('.post-scan-dialog .markdown-body strong').filter({ hasText: expected }).count(), 1, expected);
    }
    assert.equal(await page.locator('.post-scan-meta').evaluate(e => getComputedStyle(e).display), 'flex');
    assert.ok((await page.locator('.post-scan-paths').innerText()).includes('置信度 高'));
    assert.ok(!(await page.locator('.post-scan-paths').innerText()).includes('HIGH'));
    assert.equal(await summary.evaluate(e => getComputedStyle(e).display), 'block');
    assert.equal(await page.evaluate(() => window.fixtureDispatches || 0), 0);
  });
  await check('empty plans explicitly disclose that no executable steps or tasks exist', async () => {
    await page.evaluate(()=>window.markdownSurfaces.postScanPlan.steps=[]);
    await page.getByText('暂无可执行步骤',{exact:true}).waitFor();
    assert.ok((await page.locator('.post-scan-steps').innerText()).includes('尚未创建或执行任务'));
    assert.equal(await page.locator('.post-scan-steps input[type="checkbox"]').count(),0);
    assert.equal(await page.evaluate(()=>window.fixtureDispatches||0),0);
    await page.evaluate(steps=>window.markdownSurfaces.postScanPlan.steps=steps, data.steps);
  });
  for (const theme of ['light', 'dark']) {
    for (const width of [1280, 520]) {
      await check('post-scan ' + theme + ' theme at ' + width + 'px keeps footer visible and scrolls long content', async () => {
        await page.setViewportSize({ width, height: 800 });
        await page.evaluate(theme => { document.documentElement.dataset.systemTheme = theme; }, theme);
        const geometry = await page.locator('.el-dialog').evaluate(el => {
          const body = el.querySelector('.el-dialog__body'), footer = el.querySelector('.el-dialog__footer'), pre = el.querySelector('pre');
          const box = el.getBoundingClientRect(), f = footer.getBoundingClientRect();
          return { left: box.left, right: box.right, footerBottom: f.bottom, bodyOverflow: getComputedStyle(body).overflowY,
            scrolls: body.scrollHeight > body.clientHeight, bodyWidth: body.clientWidth, bodyScrollWidth: body.scrollWidth,
            codeOverflow: getComputedStyle(pre).overflowX, foreground: getComputedStyle(el.querySelector('.post-scan-summary')).color,
            background: getComputedStyle(el).backgroundColor };
        });
        assert.ok(geometry.left >= 0 && geometry.right <= width + 1, JSON.stringify(geometry));
        assert.ok(geometry.footerBottom <= 800, JSON.stringify(geometry));
        assert.equal(geometry.scrolls, true); assert.equal(geometry.bodyOverflow, 'auto');
        assert.equal(geometry.codeOverflow, 'auto');
        assert.ok(geometry.bodyScrollWidth <= geometry.bodyWidth + 1, JSON.stringify(geometry));
        assert.notEqual(geometry.foreground, geometry.background);
        results.push({ name: 'layout ' + theme + ' ' + width, geometry });
        await page.screenshot({ path: path.join(out, 'post-scan-' + theme + '-' + width + '.png'), animations: 'disabled' });
      });
    }
  }
  await check('bottom sections remain reachable and automated/manual step selection is preserved', async () => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.locator('.post-scan-steps').scrollIntoViewIfNeeded();
    const checkboxes = page.locator('.post-scan-steps input[type="checkbox"]');
    assert.equal(await checkboxes.nth(0).isChecked(), true);
    assert.equal(await checkboxes.nth(0).isDisabled(), false);
    assert.equal(await checkboxes.nth(1).isDisabled(), true);
    assert.equal(await page.evaluate(() => window.fixtureDispatches || 0), 0);
    await page.screenshot({ path: path.join(out, 'post-scan-bottom.png'), animations: 'disabled' });
  });
  await page.getByRole('button', { name: '关闭', exact: true }).click();
  await page.locator('.post-scan-dialog').waitFor({ state: 'detached' });
  await check('finding, task, workflow and project details render the same Markdown contract', async () => {
    for (const [surface, count] of [['findings', 2], ['tasks', 1], ['workflow-node', 1], ['workflow-finding', 2], ['project', 2]]) {
      const section = page.locator('[data-surface="' + surface + '"]');
      assert.equal(await section.locator('.markdown-body h2').count(), count, surface);
      assert.equal(await section.locator('.markdown-body table').count(), count, surface);
      assert.equal(await section.locator('.markdown-body pre code').count(), count, surface);
    }
    assert.equal(await page.locator('[data-surface="findings"] textarea').inputValue(), record.evidence);
    assert.equal(await page.locator('[data-surface="project"] textarea').inputValue(), record.evidence);
    assert.equal(await page.locator('[data-surface="workflow-node"]').getByRole('textbox', { name: '工作流节点输出', exact: true }).inputValue(), JSON.stringify({ raw: '**原始数据**' }, null, 2));
    assert.equal(await page.evaluate(() => window.markdownSurfaces.detail.description), markdown);
    assert.equal(await page.evaluate(() => window.markdownSurfaces.postScanPlan.analysis), longAnalysis);
    assert.equal(await page.locator('.markdown-body script,.markdown-body img,.markdown-body [onerror]').count(), 0);
    assert.equal(await page.evaluate(() => window.surfaceXss), undefined);
    assert.deepEqual(unexpectedRequests, []); assert.deepEqual(errors, []);
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.screenshot({ path: path.join(out, 'detail-surfaces-dark.png'), fullPage: true, animations: 'disabled' });
  });
  await check('retrieved project evidence shows readable source excerpts without protocol fields',async()=>{
    await page.evaluate(()=>{
      const run=window.markdownSurfaces.nodeDetailRun;
      run.toolCode='retrieve_project_context';
      run.output={query:'响应头',projectId:7,targetId:9,indexRevision:4,items:[{title:'响应头记录',source:'finding',snippet:'**已保存的证据**\n\n缺少响应头。',evidenceId:'ev-0123456789abcdef01234567',contentDigest:'internal-digest'}]};
      run.log='retrieve_project_context';
    });
    const section=page.locator('[data-surface="workflow-node"]');
    await section.locator('.project-evidence-result').waitFor();
    assert.equal(await section.locator('.evidence-item .markdown-body strong').innerText(),'已保存的证据');
    const text=await section.innerText();assert.match(text,/查询内容/);assert.match(text,/检测发现/);
    assert.doesNotMatch(text,/ev-0123|indexRevision|contentDigest|retrieve_project_context/);
    await page.evaluate(()=>window.markdownSurfaces.nodeDetailRun.output.items=[]);
    await section.getByText('没有找到匹配的已有资料，不能据此判断目标不存在风险。').waitFor();
    assert.equal(await section.locator('.evidence-item').count(),0);
    assert.deepEqual(errors,[]);
  });
  fs.writeFileSync(path.join(out, 'result.json'), JSON.stringify({ status: 'PASS', results, errors, unexpectedRequests }, null, 2));
  console.log(out);
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => { await browser?.close(); await server?.close(); });
