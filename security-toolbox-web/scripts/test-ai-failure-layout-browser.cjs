'use strict';
// Production message body, execution plan and toolbar; isolated synthetic state only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { parse } = require('@vue/compiler-sfc');
const { baseParse } = require('@vue/compiler-dom');
const ts = require('typescript');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../.run/ai-failure-layout', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(out, { recursive: true });
const dashboard = parse(fs.readFileSync(path.join(root, 'src/views/Dashboard.vue'), 'utf8')).descriptor;
function find(node, predicate) {
  if (node.type === 1 && predicate(node)) return node;
  for (const child of node.children || []) { const found = find(child, predicate); if (found) return found; }
}
const hasClass = value => node => node.props.some(prop => prop.type === 6 && prop.name === 'class' && prop.value?.content.split(' ').includes(value));
const ast = baseParse(dashboard.template.content);
const response = find(ast, hasClass('message-response'));
const actions = find(ast, hasClass('message-actions'));
const stamp = find(ast, node => node.tag === 'AiStatusStamp');
assert(response && actions && stamp, 'Actual production response, status stamp and toolbar must exist');
const scriptAst = ts.createSourceFile('Dashboard.ts', dashboard.scriptSetup.content, ts.ScriptTarget.Latest, true);
function productionFunction(name) {
  const fn = scriptAst.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
  assert(fn, 'Actual production function ' + name);
  return ts.transpileModule(fn.getText(scriptAst), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
}
const start = '2026-10-20T09:34:44Z', finish = '2026-10-20T09:34:53Z';
const failure = '本轮方案与上次已交付方案不同，未提交审批，未创建任务。请新建会话重新规划，再申请执行。变化：\n方案.steps[5]：原值（不存在） → 新值 ' + JSON.stringify({ toolCode: 'dir_scan', workflowNodeId: 'dir-scan', group: 1, dependsOnNodeIds: ['context'], risk: 'CAUTION', requiresApproval: true, parameters: { concurrency: 10, dictionary: 'dirb-common' } });
const message = { id: 'failed-turn', role: 'assistant', status: 'failed', modelStreamStatus: 'failed', provider: 'langchain-grounded', content: failure, taskIds: [], createdAt: start, updatedAt: finish, progressStartedAt: start, progressFinishedAt: finish,
  steps: ['http_headers', 'tls_config', 'nmap_service_scan', 'nuclei_scan', 'dir_scan'].map((toolCode, index) => ({ id: 'step-' + index, toolCode, title: toolCode, parameters: {}, status: 'pending', requiresApproval: true })),
  agentEvents: [{ type: 'progress', stage: 'ASSESSED', source: 'runtime-public-progress', eventTiming: 'LIVE', assessmentSource: 'MODEL', modelDecision: 'FINALIZE', evidenceDecision: 'FINALIZE', reasonCodes: ['DIRECT_SUPPORT'], summary: '已有证据足以生成当前方案。', createdAt: start }],
};
const fixtureId = path.join(root, '__ai-failure-layout.vue').replace(/\\/g, '/');
const fixture = `<script setup>
import { computed, reactive, nextTick } from 'vue';
import AiProgressPanel from '/src/components/AiProgressPanel.vue';
import AiStatusStamp from '/src/components/AiStatusStamp.vue';
import AiFailureNotice from '/src/components/AiFailureNotice.vue';
import AiDispatchNotice from '/src/components/AiDispatchNotice.vue';
import FluentCodeBlock from '/src/components/FluentCodeBlock.vue';
import FluentIcon from '/src/components/FluentIcon.vue';
import { CircleCheck, CopyDocument, EditPen, Connection } from '/src/components/fluentIcons';
import quoteIcon from '@fluentui/svg-icons/icons/text_quote_24_regular.svg?url';
import { aiAnswerSource } from '/src/utils/aiAnswer';
import { aiToolLabel } from '/src/utils/aiPresentation';
import { isAwaitingAiApproval, isAwaitingAiDispatch, isAiDispatchRejected } from '/src/utils/aiApproval';
import { isAiStatusOutsideCard } from '/src/utils/aiStatus';
const state = reactive({ message: ${JSON.stringify(message)}, tasks: [], clicks: [] });
const message = computed(() => state.message);
const relatedTasks = () => state.tasks;
const sending = false, approvingMessageId = null, copiedMessageId = '', retryingMessageIds = new Set();
const messageQuoteStyle = { maskImage: 'url("' + quoteIcon + '")' };
const router = { push: value => state.clicks.push(value) };
const quoteMessage = () => state.clicks.push('quote'), copyMessage = () => {}, editMessage = () => {};
const retryConversationMessage = () => state.clicks.push('retry'), openAiDiagnostics = () => state.clicks.push('diagnostics');
${productionFunction('hasDispatchNotice')}
${productionFunction('isStatusOutsideAnswerCard')}
const displayedContentForMessage = message => message.status === 'failed' ? '' : message.content, renderMarkdown = value => value;
const isTrafficReference = () => false, genericReferences = () => [], agentCitations = () => [];
const taskLogs = () => '', planTaskSummary = () => '已结束 0/1 个任务';
const taskState = message => ({label:message.status === 'failed' ? '处理失败' : '已完成',className:message.status === 'failed' ? 'failed' : 'success'});
const planStepState = () => ({state:'pending',label:'待执行',progress:0});
const displayedStepTitle = step => aiToolLabel(step.toolCode, step.title), displayedStepReason = () => '';
const reopenApproval = () => {}, handleAgentApprovalDecision = () => {}, adjustDispatchPlan = () => {};
window.failureLayout = state;
window.updateFailure = async patch => { Object.assign(state, patch); await nextTick(); await new Promise(requestAnimationFrame); };
</script><template><main class="desktop-v2-app-frame desktop-v2-native-frame"><section class="fixture-content"><article class="chat-message assistant"><div class="message-avatar"><FluentIcon name="shield-checkmark" /></div><div class="message-column"><div class="message-meta"><strong>安全助手</strong><span>2026-10-20 17:34:44</span><span class="message-answer-source">{{aiAnswerSource(message.provider,message.status === 'failed')}}</span></div>${response.loc.source}${stamp.loc.source}${actions.loc.source}</div></article></section></main></template>
${dashboard.styles.map(style => '<style' + (style.scoped ? ' scoped' : '') + '>' + style.content + '</style>').join('\n')}`;
const html = `<!doctype html><html lang="zh-CN" data-system-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body{margin:0;height:auto!important;overflow:auto!important}.desktop-v2-app-frame{display:block!important;min-height:100vh}.fixture-content{box-sizing:border-box;max-width:900px;margin:0 auto;padding:40px 16px}</style></head><body><div id="fixture"></div><script type="module">import {createApp} from 'vue';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';import '/src/desktop-v2.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';import Fixture from '/__ai-failure-layout.vue';createApp(Fixture).use(ElementPlus).mount('#fixture');</script></body></html>`;
let server, browser, page;
const errors = [], blocked = [], checks = [];
async function check(name, fn) { await fn(); checks.push({ name, status: 'PASS' }); console.log('PASS ' + name); }
async function surfaceMetrics() {
  return page.locator('.message-response').evaluate(card => {
    const rect = element => { const r = element.getBoundingClientRect(); return { x: r.x, y: r.y, width: r.width, height: r.height, right: r.right, bottom: r.bottom }; };
    const style = element => { const s = getComputedStyle(element); return { border: s.border, radius: s.borderRadius, padding: s.padding, background: s.backgroundColor, shadow: s.boxShadow }; };
    const toolbar = card.parentElement.querySelector('.message-actions'), status = card.parentElement.querySelector('.message-status'), plan = card.querySelector('.execution-plan-card'), box = rect(card), bar = rect(toolbar);
    const statusBox = status ? rect(status) : null;
    return { card: box, toolbar: bar, status: statusBox && { x: statusBox.x, width: statusBox.width, offsetY: statusBox.y - box.bottom }, surface: style(card), plan: style(plan), actions: { ...style(toolbar), margin: getComputedStyle(toolbar).margin, gap: getComputedStyle(toolbar).gap, offsetX: bar.x - box.x, offsetY: bar.y - (statusBox || box).bottom }, toolbarOpacity: getComputedStyle(toolbar).opacity, toolbarPointer: getComputedStyle(toolbar).pointerEvents, scroll: card.scrollWidth, client: card.clientWidth, documentWidth: document.documentElement.scrollWidth, viewport: innerWidth, buttons: [...toolbar.querySelectorAll('button')].map(rect) };
  });
}
async function setOutcome(failed) {
  await page.evaluate(async ({ failed, failure }) => { const state = window.failureLayout; state.message.status = failed ? 'failed' : 'completed'; state.message.modelStreamStatus = failed ? 'failed' : 'completed'; state.message.content = failed ? failure : '已核对当前授权范围，方案可继续审阅。'; await window.updateFailure({}); }, { failed, failure });
  await page.locator('.chat-message').hover();
  await page.waitForFunction(() => getComputedStyle(document.querySelector('.message-actions')).opacity === '1');
}
(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.join(out, 'vite-cache'), plugins: [{ name: 'failure-layout-fixture', resolveId(id) { if (id === '/__ai-failure-layout.vue') return fixtureId; }, load(id) { if (id === fixtureId) return fixture; }, configureServer(s) { s.middlewares.use(async (req, res, next) => { if (req.url !== '/__failure-layout') return next(); res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(await s.transformIndexHtml(req.url, html)); }); } }, vue()], optimizeDeps: { entries: [], include: ['vue', 'element-plus', 'marked', 'dompurify'], noDiscovery: true }, server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/desktop-release/**', '**/dist/**'] } }, logLevel: 'error' });
  await server.listen();
  const origin = 'http://127.0.0.1:' + server.httpServer.address().port;
  browser = await chromium.launch({ executablePath: process.env.AI_PROGRESS_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  page = await browser.newPage({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
  page.setDefaultTimeout(120000); page.setDefaultNavigationTimeout(120000);
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => { const url = route.request().url(); if (url.startsWith(origin + '/') && !new URL(url).pathname.startsWith('/api/')) return route.continue(); blocked.push(url); return route.abort(); });
  await page.goto(origin + '/__failure-layout');
  await page.locator('.message-response.is-failed').waitFor();
  for (const theme of ['light', 'dark']) for (const width of [1280, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await page.evaluate(theme => document.documentElement.dataset.systemTheme = theme, theme);
    await check(`${theme}/${width}: failure reuses the successful response surface and unboxed toolbar`, async () => {
      await setOutcome(true);
      const metrics = await surfaceMetrics();
      assert.ok(metrics.card.width <= 720 && metrics.card.width >= 200, JSON.stringify(metrics));
      assert.equal(await page.locator('.failed-response-card').evaluate(el => getComputedStyle(el).borderTopWidth), '0px');
      assert.equal(metrics.surface.radius, '8px'); assert.equal(metrics.surface.padding, '12px 16px'); assert.match(metrics.surface.border, /^1px solid /);
      assert.equal(metrics.actions.padding, '0px'); assert.match(metrics.actions.border, /^0px /); assert.equal(metrics.actions.offsetX, 0); assert.equal(metrics.actions.offsetY, 6);
      assert.equal(metrics.toolbarOpacity, '1'); assert.equal(metrics.toolbarPointer, 'auto');
      assert.ok(metrics.scroll <= metrics.client + 1 && metrics.documentWidth <= metrics.viewport + 1, JSON.stringify(metrics));
      assert.equal(metrics.buttons.length, 4);
      for (const button of metrics.buttons) { assert.ok(button.x >= metrics.toolbar.x && button.right <= metrics.toolbar.right + 1); assert.ok(Math.abs(button.y - metrics.buttons[0].y) <= 1); if (width <= 640) assert.ok(button.width >= 40 && button.height >= 40); }
      assert.equal(await page.locator('.message-answer-source').innerText(), '本轮未完成');
      assert.equal(await page.locator('.failure-details').getAttribute('open'), null);
      assert.equal(await page.locator('.message-status').count(), 0, 'Summary controls stay inside the response');
      assert.equal(await page.locator('.message-response .progress-header').count(), 1);
      await setOutcome(false);
      const success = await surfaceMetrics();
      assert.deepEqual(metrics.surface, success.surface); assert.deepEqual(metrics.plan, success.plan); assert.deepEqual(metrics.actions, success.actions);
      assert.equal(metrics.card.width, success.card.width); assert.equal(metrics.card.x, success.card.x);
      await page.screenshot({ path: path.join(out, `success-reference-${theme}-${width}.png`), fullPage: true });
      await setOutcome(true);
      await page.screenshot({ path: path.join(out, `failed-${theme}-${width}.png`), fullPage: true });
    });
    await check(`${theme}/${width}: terminal replies without model summaries share the same outside status and toolbar placement`, async () => {
      await page.evaluate(async () => { window.savedAssessmentEvents = window.failureLayout.message.agentEvents; window.failureLayout.message.agentEvents = []; await window.updateFailure({}); });
      await setOutcome(true);
      assert.equal(await page.locator('.message-response .progress-header').count(), 0);
      assert.equal(await page.locator('.message-status').count(), 1);
      assert.match(await page.locator('.message-status').innerText(), /未完成/);
      assert.equal(await page.locator('.failure-summary').isVisible(), true);
      assert.doesNotMatch(await page.locator('.failure-summary').innerText(), /方案\.steps|parameters|workflowNodeId/);
      const failed = await surfaceMetrics();
      assert.equal(failed.status.x, failed.card.x); assert.equal(failed.status.width, failed.card.width); assert.equal(failed.status.offsetY, 0);
      await page.screenshot({ path: path.join(out, `failed-outside-status-${theme}-${width}.png`), fullPage: true });
      await setOutcome(false);
      assert.equal(await page.locator('.message-response .progress-header').count(), 0);
      assert.equal(await page.locator('.message-status').count(), 1);
      assert.match(await page.locator('.message-status').innerText(), /已完成/);
      const success = await surfaceMetrics();
      assert.deepEqual(failed.surface, success.surface); assert.deepEqual(failed.status, success.status); assert.deepEqual(failed.actions, success.actions);
      await page.screenshot({ path: path.join(out, `success-outside-status-${theme}-${width}.png`), fullPage: true });
      await page.evaluate(async () => { window.failureLayout.message.agentEvents = window.savedAssessmentEvents; await window.updateFailure({}); });
      await setOutcome(true);
    });
    await check(`${theme}/${width}: keyboard details and expanded plan stay inside the card`, async () => {
      await page.locator('.failure-details summary').focus(); await page.keyboard.press('Enter');
      await page.waitForFunction(() => document.querySelector('.failure-details > p')?.innerText.length > 0);
      assert.match(await page.locator('.failure-details > p').innerText(), /方案\.steps\[5\]/);
      await page.locator('.execution-plan-disclosure').click();
      await page.locator('.execution-plan-list').waitFor({ state: 'visible' });
      assert.equal(await page.locator('.execution-plan-list li').count(), 5);
      const metrics = await page.locator('.message-response').evaluate(card => ({ scroll: card.scrollWidth, client: card.clientWidth, document: document.documentElement.scrollWidth, viewport: innerWidth }));
      assert.ok(metrics.scroll <= metrics.client + 1 && metrics.document <= metrics.viewport + 1, JSON.stringify(metrics));
      await page.screenshot({ path: path.join(out, `failed-expanded-${theme}-${width}.png`), fullPage: true });
      await page.locator('.execution-plan-disclosure').click(); await page.locator('.failure-details summary').click();
    });
  }
  await check('very long persisted error is scrollable, not a page-sized or horizontally overflowing payload', async () => {
    await page.evaluate(async text => { const state = window.failureLayout; state.message.content = text; await window.updateFailure({}); }, failure + '\n' + '参数变化：' + 'longUnbrokenParameter'.repeat(1000));
    await page.locator('.failure-details summary').click();
    await page.waitForFunction(() => document.querySelector('.failure-details > p')?.innerText.length > 0);
    const metrics = await page.locator('.failure-details > p').evaluate(el => ({ height: el.getBoundingClientRect().height, scrollHeight: el.scrollHeight, clientHeight: el.clientHeight, scrollWidth: el.scrollWidth, clientWidth: el.clientWidth, overflow: getComputedStyle(el).overflowY }));
    assert.ok(metrics.height <= 241 && metrics.scrollHeight > metrics.clientHeight, JSON.stringify(metrics)); assert.equal(metrics.overflow, 'auto'); assert.ok(metrics.scrollWidth <= metrics.clientWidth + 1, JSON.stringify(metrics));
    await page.screenshot({ path: path.join(out, 'failed-long-detail-mobile.png'), fullPage: true });
    await page.locator('.failure-details summary').click();
  });
  await check('linked tasks retain their independent execution state and recovery actions', async () => {
    await page.evaluate(async () => { const state = window.failureLayout; state.message.taskIds = [17]; state.message.content = '汇总回答未完成，已有任务请以任务中心为准。'; await window.updateFailure({ tasks: [{ id: 17, toolCode: 'http_headers', status: 'RUNNING', createdAt: '2026-10-20T09:34:44Z' }] }); });
    assert.match(await page.locator('.tool-state').evaluate(el => el.textContent), /执行中/);
    assert.match(await page.locator('.progress-heading').innerText(), /回答中断/);
    await page.getByRole('button', { name: '重新生成回复', exact: true }).click(); await page.getByRole('button', { name: '配置诊断', exact: true }).click();
    assert.deepEqual(await page.evaluate(() => window.failureLayout.clicks), ['retry', 'diagnostics']);
  });
  assert.deepEqual(errors, []); assert.deepEqual(blocked, []);
  console.log('EVIDENCE ' + out);
})().catch(async error => { console.error(error); checks.push({ status: 'FAIL', error: error.stack }); process.exitCode = 1; if (page) await page.screenshot({ path: path.join(out, 'failure.png'), fullPage: true }); }).finally(async () => { fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify({ scope: 'Actual production Dashboard response/plan/toolbar fragments and styles, actual Vue components; synthetic isolated state, no application API or scan', checks, errors, blocked }, null, 2)); await browser?.close(); await server?.close(); });
