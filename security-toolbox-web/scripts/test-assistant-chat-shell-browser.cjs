'use strict';
// Isolated production-template/component/scoped-CSS check. No real profile,
// archives, model, business API, visible browser, or running desktop is used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { parse } = require('@vue/compiler-sfc');
const { baseParse } = require('@vue/compiler-dom');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../reports/assistant-style-audit-20261007/browser', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(out, { recursive: true });
const descriptors = Object.fromEntries(['Dashboard', 'Traffic'].map(name => [name,
  parse(fs.readFileSync(path.join(root, 'src/views', name + '.vue'), 'utf8')).descriptor]));
function find(node, predicate) {
  if (node.type === 1 && predicate(node)) return node;
  for (const child of node.children || []) { const found = find(child, predicate); if (found) return found; }
}
const hasClass = value => node => node.props.some(p => p.type === 6 && p.name === 'class' && p.value?.content.split(' ').includes(value));
const response = find(baseParse(descriptors.Dashboard.template.content), hasClass('message-response'));
const panel = find(response, node => node.tag === 'AiProgressPanel');
const actions = find(response, hasClass('message-actions'));
const traffic = find(baseParse(descriptors.Traffic.template.content), hasClass('traffic-chat-message'));
assert(response && panel && actions && traffic, 'Production fragments must exist');
const openResponse = response.loc.source.slice(0, response.loc.source.indexOf('>') + 1);
const displayedMessageContent = descriptors.Dashboard.scriptSetup.content.match(/function displayedMessageContent\([^]*?\n\}/)[0];
const value = v => JSON.stringify(v).replace(/</g, '\\u003c');
const start = '2026-10-07T01:00:00.000Z', finish = '2026-10-07T01:00:10.000Z';
const base = { id: 'synthetic-success', role: 'assistant', status: 'completed', content: '新增历史核验', provider: 'openai-compatible', taskIds: [], steps: [], agentEvents: [], createdAt: start, updatedAt: finish, progressStartedAt: start, progressFinishedAt: finish, modelStreamStatus: 'completed' };
const longUrl = 'https://example.test/evidence/' + 'long-path'.repeat(24);
const code = 'const evidence = "' + 'x'.repeat(220) + '";';
const markdown = ['## 检查结论', '**仅依据已有证据。**', '', '- 认证状态待核实', '- 会话信息应按授权范围核验', '',
  '| ' + Array.from({ length: 14 }, (_, i) => '字段' + i).join(' | ') + ' |',
  '| ' + Array(14).fill('---').join(' | ') + ' |',
  '| ' + Array(14).fill('ABCDEFGHIJKLMN').join(' | ') + ' |', '', '```javascript', code, '```', '', '[' + longUrl + '](' + longUrl + ')', '',
  '<script>window.fixtureXss=1</script><img src="https://example.test/tracker" onerror="window.fixtureXss=1">'].join('\n');
const task = (status = 'SUCCESS') => ({ id: 41, toolCode: 'http_headers', status, createdAt: start, startedAt: start,
  ...(status === 'RUNNING' ? {} : { finishedAt: finish }), ...(status === 'FAILED' ? { errorMessage: '检测工具返回失败，请查看任务记录。' } : {}) });
const cases = [
  { name: 'completed', expectCompleted: true },
  ...['sending', 'planning', 'running', 'answering'].map(status => ({ name: status, message: { status, modelStreamStatus: 'running', progressFinishedAt: undefined, content: '' }, expectBody: false })),
  { name: 'executing', message: { status: 'running', modelStreamStatus: 'completed', taskIds: [41], content: '' }, tasks: [task('RUNNING')], expectBody: false },
  { name: 'failed', message: { status: 'failed', modelStreamStatus: 'failed', content: '服务器处理失败，请稍后重试' }, expectBody: false, failure: true },
  { name: 'failed-with-tasks', message: { status: 'failed', modelStreamStatus: 'failed', taskIds: [41], content: '汇总回答生成失败，已有任务保留。' }, tasks: [task()], expectBody: false, failure: true },
  { name: 'clarify', message: { executionDecision: 'CLARIFY', content: '请补充授权目标。' }, title: /等待补充信息/ },
  { name: 'approval-required', message: { approvalStatus: 'REQUIRED', content: '请确认执行计划。' }, title: /等待确认/ },
  { name: 'approval-pending', message: { approvalStatus: 'PENDING' }, title: /等待确认/ },
  { name: 'approval-rejected', message: { approvalStatus: 'REJECTED' }, title: /驳回/ },
  { name: 'dispatch-unknown', message: { approvalDispatchStatus: 'unknown', approvalDispatchError: '请核对原审批及任务记录。' }, title: /待核实/ },
  { name: 'dispatch-rejected', message: { approvalDispatchStatus: 'rejected' }, title: /已拒绝/ },
  { name: 'dispatch-pending', message: { approvalStatus: 'APPROVED', approvalDispatchStatus: 'dispatching' }, title: /等待派发/ },
  { name: 'stream-interrupted-retained', message: { modelStreamStatus: 'interrupted', content: '已经生成并保留的回答内容。' }, title: /连接已结束/ },
  { name: 'regeneration-failed-retained', message: { modelStreamStatus: 'failed', content: '重新生成失败后保留的原回答内容。' }, title: /未完成/ },
  { name: 'tool-success', message: { taskIds: [41] }, tasks: [task()], expectCompleted: true },
  { name: 'tool-failure', message: { taskIds: [41] }, tasks: [task('FAILED')], title: /失败|未成功|需关注/ },
  ...['CANCELLED','TIMEOUT','SKIPPED','BLOCKED','PENDING','REJECTED'].map(status => ({name:'tool-'+status.toLowerCase(),message:{taskIds:[41]},tasks:[task(status)]})),
  { name:'tool-unresolved', message:{taskIds:[9999]},tasks:[] },
  { name: 'history-no-duration', message: { progressStartedAt: undefined, progressFinishedAt: undefined, modelStreamStatus: undefined }, expectCompleted: true, noDuration: true },
  { name: 'rich-markdown', message: { content: markdown }, expectCompleted: true },
];
const fixture = `<script setup lang="ts">
import { computed, reactive, nextTick } from 'vue';
import AiProgressPanel from '/src/components/AiProgressPanel.vue';
import AiFailureNotice from '/src/components/AiFailureNotice.vue';
import MarkdownBody from '/src/components/MarkdownBody.vue';
import FluentIcon from '/src/components/FluentIcon.vue';
import { CopyDocument, CircleCheck, EditPen } from '/src/components/fluentIcons';
import quoteIcon from '@fluentui/svg-icons/icons/text_quote_24_regular.svg?url';
import { renderMarkdown } from '/src/utils/markdown';
import { aiProgressFailureText, localizeAiRuntimeFailure } from '/src/utils/aiPresentation';
import { aiAnswerSource } from '/src/utils/aiAnswer';
const state = reactive({ message: ${value(base)}, tasks: [], surface:'dashboard', native:false });
const message = computed(() => state.message);
const currentTrafficChat = computed(() => [{ ...state.message, role: 'ASSISTANT' }]);
const relatedTasks = () => state.tasks;
const router = { push: () => window.fixtureTaskClicks = (window.fixtureTaskClicks || 0) + 1 };
const sending = false, copiedMessageId = '', retryingMessageIds = new Set();
const messageQuoteStyle = {maskImage:'url("' + quoteIcon + '")'};
const quoteMessage = () => {}, copyMessage = () => {}, retryConversationMessage = () => {}, openAiDiagnostics = () => {}, editMessage = () => {};
${displayedMessageContent}
window.chatShellFixture = state;
window.setChatShellCase = async update => {
  Object.assign(state, update); await nextTick();
  // Production reduced-motion CSS still uses a 0.01ms transition. Force style
  // resolution, then await its real completion before measuring the settled UI.
  document.documentElement.getBoundingClientRect();
  await Promise.allSettled(document.getAnimations().filter(a => Number.isFinite(a.effect?.getComputedTiming().endTime)).map(a => a.finished));
  await new Promise(requestAnimationFrame);
};
</script><template>
<main class="desktop-v2-app-frame" :class="{'desktop-v2-native-frame':state.native}">
<div class="fixture-content">
<article v-if="state.surface === 'dashboard'" class="chat-message assistant">
<div class="message-avatar"><FluentIcon name="shield-checkmark" /></div>
<div class="message-column"><div class="message-meta"><strong>安全助手</strong><span>2026-10-07 09:00:00</span></div>
${openResponse}${panel.loc.source}${actions.loc.source}</div></div></article>
<div v-else class="traffic-analysis-messages">${traffic.loc.source}</div>
</div></main>
</template>
${Object.values(descriptors).flatMap(d => d.styles.map(s => '<style' + (s.scoped ? ' scoped' : '') + '>' + s.content + '</style>')).join('\n')}`;
const fixtureId = path.join(root, '__assistant-chat-shell-fixture.vue').replace(/\\/g, '/');
const html = `<!doctype html><html lang="zh-CN" data-system-theme="light" data-window-material="none"><head><meta charset="utf-8"><style>
html,body{margin:0;height:auto!important;overflow:auto!important}.desktop-v2-app-frame{display:block!important;min-height:100vh}.fixture-content{box-sizing:border-box;max-width:900px;margin:0 auto;padding:20px 16px}
</style></head><body><div id="fixture"></div><script type="module">
import {createApp} from 'vue';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';
import '/src/desktop-v2.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';import '/src/motion.css';
import Fixture from '/__assistant-chat-shell-fixture.vue';createApp(Fixture).use(ElementPlus).mount('#fixture');
</script></body></html>`;
let server, browser, activePage;
const results = [], errors = [], blockedRequests = [];
async function check(name, fn) { const detail = await fn(); results.push({ name, status: 'PASS', detail }); console.log('PASS ' + name); }
async function setCase(page, scenario, surface = 'dashboard') {
  await page.evaluate(update => window.setChatShellCase(update), { message: {...base, ...scenario.message, id: scenario.name}, tasks: scenario.tasks || [], surface });
}
async function shellMetrics(page, selector) {
  return page.locator(selector).evaluate(el => {
    const s = getComputedStyle(el), r = el.getBoundingClientRect();
    return { border:s.borderTopWidth, borderStyle:s.borderTopStyle, borderColor:s.borderTopColor, radius:s.borderTopLeftRadius, background:s.backgroundColor,
      className:el.className, padding:s.padding, transition:s.transition, animations:el.getAnimations().map(a=>({name:a.constructor.name,playState:a.playState})), color:s.color, left:r.left, right:r.right, width:r.width, scroll:el.scrollWidth, client:el.clientWidth, viewport:innerWidth, documentWidth:document.documentElement.scrollWidth };
  });
}
function assertShell(m, { failure = false, traffic = false } = {}) {
  assert.equal(m.border, '1px', JSON.stringify(m)); assert.equal(m.borderStyle, 'solid');
  assert.notEqual(m.borderColor, 'rgba(0, 0, 0, 0)'); assert.notEqual(m.background, 'rgba(0, 0, 0, 0)');
  assert.notEqual(m.background, m.color); assert.equal(m.radius, '8px');
  assert.equal(m.padding, traffic ? '12px' : failure ? '0px' : '12px 16px',JSON.stringify(m));
  assert(m.left >= 0 && m.right <= m.viewport + 1 && m.documentWidth <= m.viewport + 1 && m.scroll <= m.client + 1, JSON.stringify(m));
}
(async () => {
  const { createServer } = await import('vite'); const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({configFile:false, root, cacheDir:path.join(out,'vite-cache'), plugins:[{
    name:'actual-chat-shell-fixture', resolveId(id) { if(id === '/__assistant-chat-shell-fixture.vue') return fixtureId; },
    load(id) { if(id === fixtureId) return fixture; }, configureServer(s) { s.middlewares.use(async(req,res,next)=>{
      if(req.url !== '/__assistant-chat-shell') return next(); res.setHeader('Content-Type','text/html; charset=utf-8'); res.end(await s.transformIndexHtml(req.url,html));
    }); }
  },vue()], optimizeDeps:{entries:[],include:['vue','element-plus','marked','dompurify'],noDiscovery:true},
  server:{host:'127.0.0.1',port:0,hmr:false,watch:{ignored:['**/desktop-release/**','**/dist/**','**/reports/**']}},logLevel:'error'});
  await server.listen(); const origin = 'http://127.0.0.1:' + server.httpServer.address().port;
  browser = await chromium.launch({executablePath:process.env.AI_PROGRESS_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
  const page = await browser.newPage({viewport:{width:1000,height:800},reducedMotion:'reduce'});
  activePage=page;
  page.on('pageerror', e=>errors.push(e.message));
  await page.route('**/*', route => { const url = route.request().url(); if(url.startsWith(origin + '/') && !new URL(url).pathname.startsWith('/api/')) return route.continue(); blockedRequests.push(url); return route.abort(); });
  await page.goto(origin + '/__assistant-chat-shell'); await page.locator('.message-response').waitFor();
  for(const theme of ['light','dark']) for(const native of [false,true]) {
    await page.evaluate(({theme,native})=>{document.documentElement.dataset.systemTheme=theme;window.chatShellFixture.native=native;},{theme,native});
    for(const scenario of cases) await check(`${theme}/${native?'native':'web'}/${scenario.name}`, async()=>{
      await setCase(page,scenario); const m = await shellMetrics(page,'.message-response'); assertShell(m,scenario);
      assert.notEqual(await page.locator('.message-quote-icon').evaluate(el=>getComputedStyle(el).maskImage),'none');
      assert.equal(await page.locator('.ai-progress-panel.is-completed').count(),scenario.expectCompleted?1:0);
      if(scenario.title) assert.match(await page.locator('.progress-heading').innerText(),scenario.title);
      assert.equal(await page.locator('.message-bubble').count(),scenario.expectBody===false?0:1);
      if(scenario.expectBody!==false) {
        const body = await page.locator('.message-bubble').evaluate(el=>{const s=getComputedStyle(el);return {border:s.borderTopWidth,padding:s.padding,background:s.backgroundColor,shadow:s.boxShadow};});
        assert.deepEqual(body,{border:'0px',padding:'0px',background:'rgba(0, 0, 0, 0)',shadow:'none'});
        if(scenario.name.includes('retained')) assert.equal((await page.locator('.message-bubble').innerText()).trim(),scenario.message.content);
      }
      if(scenario.failure) {
        assert.equal(await page.locator('.ai-failure-notice').evaluate(el=>getComputedStyle(el).padding),'16px');
        assert.equal(await page.locator('.failure-details').getAttribute('open'),null);
        await page.locator('.failure-details summary').focus(); await page.keyboard.press('Enter');
        await page.locator('.failure-details > p').waitFor({state:'visible'});
        assert((await page.locator('.failure-details > p').innerText()).length>0);
        await page.locator('.failure-details summary').click();
      }
      if(scenario.noDuration) assert.equal(await page.locator('.progress-elapsed').count(),0);
      if(scenario.expectCompleted) {
        const b=await page.locator('.message-bubble').boundingBox(), h=await page.locator('.progress-header').boundingBox(), a=await page.locator('.message-actions').boundingBox();
        assert(h.y >= b.y+b.height+12 && h.y <= b.y+b.height+16); assert(a.y>=h.y+h.height); assert.equal(a.x,b.x);
        assert.equal(await page.locator('.progress-heading strong').evaluate(el=>getComputedStyle(el).fontSize),'13px');
      }
      if(theme==='light'&&!native&&['completed','failed','rich-markdown'].includes(scenario.name)) {
        await page.locator('.message-response').hover();
        await page.screenshot({path:path.join(out,scenario.name+'.png'),fullPage:true});
      }
      if(theme==='dark'&&native&&scenario.name==='rich-markdown') await page.screenshot({path:path.join(out,'rich-markdown-dark-native.png'),fullPage:true});
      return m;
    });
  }
  for(const theme of ['light','dark']) for(const surface of ['dashboard','traffic']) for(const width of [1000,320]) {
    await page.setViewportSize({width,height:800}); await page.evaluate(theme=>document.documentElement.dataset.systemTheme=theme,theme);
    await check(`rich/${surface}/${theme}/${width}px/native`,async()=>{
      await setCase(page,cases.find(s=>s.name==='rich-markdown'),surface);
      const selector = surface==='traffic'?'.traffic-chat-message':'.message-response';
      const m=await shellMetrics(page,selector); assertShell(m,{traffic:surface==='traffic'});
      const body=page.locator(selector+' .markdown-body'); assert.equal(await body.locator('h2').innerText(),'检查结论');
      assert.equal((await body.locator('pre code').innerText()).trim(),code); assert.equal(await body.locator('table').count(),1);
      for(const tag of ['pre','table']) assert.equal(await body.locator(tag).evaluate(el=>getComputedStyle(el).overflowX),'auto');
      const table=await body.locator('table').evaluate(el=>{
        const cell=el.querySelector('td'),range=document.createRange();range.selectNodeContents(cell);
        return {scroll:el.scrollWidth,client:el.clientWidth,wordRects:Array.from(range.getClientRects()).map(r=>({top:r.top,height:r.height})),wordBreak:getComputedStyle(el).wordBreak,overflowWrap:getComputedStyle(el).overflowWrap};
      });
      assert.equal(table.wordBreak,'normal');assert.equal(table.overflowWrap,'normal');
      assert.equal(new Set(table.wordRects.map(r=>r.top)).size,1,JSON.stringify(table));
      if(width===320) assert(table.scroll>table.client,JSON.stringify(table));
      assert.equal(await body.locator('script,img,[onerror]').count(),0); assert.equal(await page.evaluate(()=>window.fixtureXss),undefined);
      if(surface==='dashboard') await page.locator('.message-response').hover();
      await page.screenshot({path:path.join(out,`${surface}-${theme}-${width}.png`),fullPage:true});
      if(surface==='traffic') {
        await body.locator('a').scrollIntoViewIfNeeded();
        const bottom=await body.locator('a').evaluate(el=>{const r=el.getBoundingClientRect(),holder=el.closest('.traffic-analysis-messages').getBoundingClientRect();return {top:r.top,bottom:r.bottom,holderTop:holder.top,holderBottom:holder.bottom};});
        assert(bottom.top>=bottom.holderTop-1&&bottom.bottom<=bottom.holderBottom+1,JSON.stringify(bottom));
        await page.screenshot({path:path.join(out,`${surface}-${theme}-${width}-bottom.png`),fullPage:true});
      }
      return {...m,table};
    });
  }
  await page.setViewportSize({width:320,height:800});
  for(const scenario of cases.filter(s=>s.name!=='rich-markdown')) await check('320px/native/'+scenario.name,async()=>{
    await setCase(page,scenario); const m=await shellMetrics(page,'.message-response'); assertShell(m,scenario); return m;
  });
  assert.deepEqual(errors,[]); assert.deepEqual(blockedRequests,[]);
  fs.writeFileSync(path.join(out,'results.json'),JSON.stringify({status:'PASS',scope:'Production Dashboard message-response/AiProgressPanel/default-slot/toolbar fragments and all Dashboard/Traffic scoped CSS, actual AiFailureNotice and Traffic article/MarkdownBody; synthetic states; no application API or real desktop. Reference, plan and citation accessory fragments excluded.',checks:results,errors,blockedRequests},null,2));
  console.log('Evidence: '+out);
})().catch(async error=>{console.error(error);fs.writeFileSync(path.join(out,'failure.json'),JSON.stringify({error:error.stack,checks:results,errors,blockedRequests},null,2));if(activePage){await activePage.screenshot({path:path.join(out,'failure.png'),fullPage:true});fs.writeFileSync(path.join(out,'failure.html'),await activePage.content());}process.exitCode=1;}).finally(async()=>{await browser?.close();await server?.close();});
