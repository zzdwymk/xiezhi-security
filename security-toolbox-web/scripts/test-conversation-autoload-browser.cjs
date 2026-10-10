'use strict';
// Real App.vue auto-history template/handlers in a headless Vue fixture. No desktop/API access.
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const { parse } = require('@vue/compiler-sfc'), { baseParse } = require('@vue/compiler-dom'), ts = require('typescript');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..'), out = path.resolve(root, '../reports/desktop-qa-2026-10-04/regressions/conversation-auto-prefetch/component-' + Date.now());
fs.mkdirSync(out, { recursive: true });
const source = fs.readFileSync(path.join(root, 'src/App.vue'), 'utf8'), descriptor = parse(source).descriptor;
const ast = ts.createSourceFile('App.vue', descriptor.scriptSetup.content, ts.ScriptTarget.Latest, true);
const names = ['CONVERSATION_PAGE_SIZE', 'CONVERSATION_PREFETCH_MARGIN', 'visibleConversationLimit', 'loadingMoreConversations', 'visibleConversations', 'conversationCount', 'hasMoreConversations', 'activeNavigation', 'recentNavigation', 'conversationLoadSentinel', 'conversationPreloadFrame', 'conversationPreloadMounted', 'conversationIntersectionObserver', 'conversationResizeObserver'];
const declarations = names.map(name => { const stmt = ast.statements.find(s => ts.isVariableStatement(s) && s.declarationList.declarations.some(d => d.name.getText(ast) === name)); assert(stmt, name); const d = stmt.declarationList.declarations.find(d => d.name.getText(ast) === name); return (stmt.declarationList.flags & ts.NodeFlags.Const ? 'const ' : 'let ') + d.getText(ast) + ';'; });
const functions = ['queueConversationPreload', 'preloadConversations', 'observeConversationPreload', 'openConversation'].map(name => { const n = ast.statements.find(n => ts.isFunctionDeclaration(n) && n.name?.text === name); assert(n, name); return n.getText(ast); });
const lifecycle = ast.statements.filter(s => ts.isExpressionStatement(s) && /^(?:watch|onMounted|onBeforeUnmount)\(/.test(s.getText(ast)) && /queueConversationPreload|observeConversationPreload|conversationPreloadMounted/.test(s.getText(ast))).map(s => s.getText(ast));
assert.equal(lifecycle.length, 5);
function section(node) { if (node.type === 1 && node.tag === 'section' && node.props.some(p => p.type === 6 && p.name === 'class' && p.value?.content === 'desktop-v2-recents')) return node; for (const c of node.children || []) { const found = section(c); if (found) return found; } }
const history = section(baseParse(descriptor.template.content)); assert(history);
const fixture = `<script setup lang="ts">
import {computed,ref,reactive,nextTick,watch,onMounted,onBeforeUnmount} from 'vue';
import {ElIcon,ElTooltip} from 'element-plus';import {ArrowDown,ChatDotRound,Delete} from '/src/components/fluentIcons';
const total=Number(new URLSearchParams(location.search).get('count')||118);
const conversations=reactive({items:Array.from({length:total},(_,i)=>({id:'history-'+String(i+1).padStart(3,'0'),title:'原会话 '+(i+1),targetName:'192.168.136.132',messages:[{content:'原文'+i,taskIds:[]}]})),taskIds:t=>t.messages.flatMap(m=>m.taskIds)});
const route=reactive({path:'/',query:{conversation:''}});const router={push(t){route.path=t.path;route.query=t.query||{}}};
const collapsed=ref(false),navigationGroupCollapsed=()=>collapsed.value,toggleNavigationGroup=()=>{collapsed.value=!collapsed.value};
const displayConversationTitle=t=>t.title,displayKnownTestName=v=>v,clearRecentConversations=()=>{throw Error('No deletion in fixture')},removeConversation=clearRecentConversations;
${declarations.join('\n')}
${functions.join('\n')}
${lifecycle.join('\n')}
window.autoHistory={conversations,route};
</script><template><main class="desktop-v2-app-frame" style="width:min(280px,100vw)"><input id="focus-keeper" value="焦点保持"/><output id="active-navigation">{{activeNavigation}}</output>${history.loc.source}</main></template>`;
const fixtureId = path.join(out, 'actual-auto-fragment.vue').replace(/\\/g, '/'); fs.writeFileSync(fixtureId, fixture);
const html = '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"></head><body><div id="fixture"></div><script type="module">import{createApp}from"vue";import App from"/__auto.vue";import"/src/desktop-v2.css";import"/src/unified-theme.css";import"/src/fluent-design-2.css";import"/src/fluent-design-3.css";createApp(App).mount("#fixture");</script></body></html>';
let server, browser; const results = [], errors = [], blockedNetwork = [];
async function check(name, run) { results.push({ name, status: 'PASS', detail: await run() }); console.log('PASS ' + name); }
(async () => {
  const { createServer } = await import('vite'), vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.join(out, 'vite-cache'), optimizeDeps: { entries: [], include: ['vue', 'element-plus'], noDiscovery: true }, logLevel: 'error',
    plugins: [{ name: 'auto-history-fixture', resolveId(id) { if (id === '/__auto.vue') return fixtureId; }, load(id) { if (id === fixtureId) return fixture; }, configureServer(s) { s.middlewares.use(async (req, res, next) => { if (!req.url?.startsWith('/__auto?')) return next(); res.setHeader('Content-Type', 'text/html'); res.end(await s.transformIndexHtml(req.url, html)); }); } }, vue()],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/desktop-release/**', '**/dist/**'] } } });
  await server.listen(); const origin = 'http://127.0.0.1:' + server.httpServer.address().port;
  browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true, args: ['--disable-smooth-scrolling'] });
  const page = await browser.newPage({ viewport: { width: 800, height: 900 } });
  await page.route('**/*', r => { if (new URL(r.request().url()).origin === origin) return r.continue(); blockedNetwork.push(r.request().url()); return r.abort(); });
  page.on('pageerror', e => errors.push(e.stack));
  await page.addInitScript(() => {
    window.autoSamples = [];
    const sample = kind => { const root = document.querySelector('#desktop-v2-recents-list'); if (!root) return; const sentinel = root.querySelector('.desktop-v2-recents-sentinel'); const box = root.getBoundingClientRect(); window.autoSamples.push({ kind, at: performance.now(), count: root.querySelectorAll('.desktop-v2-recent-open').length, top: root.scrollTop, remaining: sentinel ? sentinel.getBoundingClientRect().top - box.bottom : null, scrollHeight: root.scrollHeight, clientHeight: root.clientHeight, focus: document.activeElement?.id || document.activeElement?.getAttribute('data-conversation-id') || document.activeElement?.tagName, loading: root.getAttribute('aria-busy') }); };
    document.addEventListener('scroll', e => { if (e.target?.id === 'desktop-v2-recents-list') sample('scroll'); }, true);
    new MutationObserver(() => sample('mutation')).observe(document, { childList: true, subtree: true, attributes: true, attributeFilter: ['aria-busy'] });
  });
  const list = () => page.locator('#desktop-v2-recents-list'), rows = () => list().locator('.desktop-v2-recent-open');
  const geometry = () => list().evaluate(root => { const s = root.querySelector('.desktop-v2-recents-sentinel'); return { count: root.querySelectorAll('.desktop-v2-recent-open').length, top: root.scrollTop, remaining: s ? s.getBoundingClientRect().top - root.getBoundingClientRect().bottom : null, clientHeight: root.clientHeight, scrollHeight: root.scrollHeight, loading: root.getAttribute('aria-busy') }; });
  async function settled() { await page.waitForFunction(() => { const root = document.querySelector('#desktop-v2-recents-list'), s = root?.querySelector('.desktop-v2-recents-sentinel'); return root && root.getAttribute('aria-busy') === 'false' && (!s || s.getBoundingClientRect().top - root.getBoundingClientRect().bottom > Number(root.dataset.prefetchMargin)); }); }
  await page.goto(origin + '/__auto?count=118'); await list().waitFor(); await settled();
  await check('First screen fills automatically by8 batches, stops with preload reserve, never mounts118', async () => {
    const g = await geometry(); assert(g.count > 8 && g.count < 118); assert.equal(g.count % 8, 0); assert(g.scrollHeight > g.clientHeight); assert(g.remaining > 280); assert.equal(g.top, 0);
    assert.equal(await page.getByRole('button', { name: '加载更多对话', exact: true }).count(), 0);
    const samples = await page.evaluate(() => window.autoSamples); const unique = [...new Set(samples.map(s => s.count))]; assert.equal(unique[0], 8); assert(unique.every((n, i) => !i || n - unique[i - 1] === 8)); return { geometry: g, counts: unique };
  });
  await check('Real wheel triggers before bottom, appending does not steal focus or move scrollTop', async () => {
    await page.locator('#focus-keeper').focus(); const before = await geometry(); await list().hover(); await page.mouse.wheel(0, Math.max(1, before.remaining - 150));
    await page.waitForFunction(n => document.querySelectorAll('.desktop-v2-recent-open').length > n, before.count); await settled();
    const after = await geometry(), samples = await page.evaluate(() => window.autoSamples), event = [...samples].reverse().find(s => s.kind === 'scroll' && s.count === before.count);
    assert(event && event.remaining > 0 && event.remaining <= 280); assert.equal(after.top, event.top); assert.equal(await page.evaluate(() => document.activeElement.id), 'focus-keeper'); return { before, event, after };
  });
  await check('Native PageDown and End work on the actual focusable internal scroll container', async () => {
    assert.equal(await list().getAttribute('tabindex'), '0'); await list().focus(); assert.equal(await list().evaluate(el => document.activeElement === el), true);
    await page.keyboard.press('PageDown'); await page.waitForTimeout(120); await settled(); const before = await geometry();
    await page.keyboard.press('End'); await page.waitForFunction(n => document.querySelectorAll('.desktop-v2-recent-open').length > n, before.count); await settled();
    assert.equal(await list().evaluate(el => document.activeElement === el), true); return { after: await geometry() };
  });
  await check('Fast down/up input coalesces without duplicate rows, focus changes or whole-history loading', async () => {
    const before = await geometry(); await list().hover(); await page.mouse.wheel(0, 1000); await page.mouse.wheel(0, -10000); await page.waitForTimeout(200); await settled();
    const after = await geometry(); assert(after.count >= before.count && after.count <= before.count + 8); assert(after.count < 118); assert.equal(after.top, 0); const ids = await rows().evaluateAll(nodes => nodes.map(n => n.dataset.conversationId)); assert.equal(new Set(ids).size, ids.length); return { before, after };
  });
  await check('Collapse/reopen and viewport resize preserve records and do not loop while hidden', async () => {
    await page.locator('.desktop-v2-recents-toggle').click(); const count = await rows().count(); await page.waitForTimeout(250); assert.equal(await rows().count(), count);
    await page.setViewportSize({ width: 250, height: 740 }); assert.equal(await rows().count(), count); await page.locator('.desktop-v2-recents-toggle').click(); await settled(); assert((await rows().count()) < 118);
    await page.setViewportSize({ width: 800, height: 900 }); await settled(); return geometry();
  });
  await check('Slow CPU scheduling still bounds each batch and never duplicates or steals focused container', async () => {
    const cdp = await page.context().newCDPSession(page); await cdp.send('Emulation.setCPUThrottlingRate', { rate: 6 });
    try { await list().focus(); const before = await geometry(); await page.keyboard.press('End'); await page.waitForFunction(n => document.querySelectorAll('.desktop-v2-recent-open').length > n, before.count); await settled(); const after = await geometry(); assert.equal(after.count - before.count, 8); assert.equal(await list().evaluate(el => document.activeElement === el), true); return { before, after, throttle: 6 }; }
    finally { await cdp.send('Emulation.setCPUThrottlingRate', { rate: 1 }); await cdp.detach(); }
  });
  await check('Repeated native End reaches118 exactly; final sentinel disappears and idle does not reload', async () => {
    await list().focus(); let guard = 0;
    while (await rows().count() < 118) { assert(++guard < 20); const before = await rows().count(); await page.keyboard.press('End'); await page.waitForFunction(n => document.querySelectorAll('.desktop-v2-recent-open').length > n, before); await settled(); }
    assert.equal(await list().locator('.desktop-v2-recents-sentinel').count(), 0); assert.match(await page.locator('.desktop-v2-recents-status').innerText(), /已显示全部 118 条对话/); await page.waitForTimeout(300); assert.equal(await rows().count(), 118);
    const ids = await rows().evaluateAll(nodes => nodes.map(n => n.dataset.conversationId)); assert.deepEqual(ids, Array.from({ length: 118 }, (_, i) => 'history-' + String(i + 1).padStart(3, '0'))); await page.locator('[data-conversation-id="history-118"]').click(); assert.equal(await page.locator('#active-navigation').textContent(), '');
    await page.screenshot({ path: path.join(out, 'auto-last-page.png'), fullPage: true }); return { count: ids.length, terminalWaitMs: 300 };
  });
  for (const n of [0, 1, 8, 9]) await check('Small inventory auto-fill and terminal guard ' + n, async () => { await page.goto(origin + '/__auto?count=' + n); await list().waitFor(); await settled(); assert.equal(await rows().count(), n); assert.equal(await list().locator('.desktop-v2-recents-sentinel').count(), 0); });
  assert.deepEqual(errors, []); assert.deepEqual(blockedNetwork, []);
  fs.writeFileSync(path.join(out, 'samples.json'), JSON.stringify(await page.evaluate(() => window.autoSamples), null, 2));
  fs.writeFileSync(path.join(out, 'result.json'), JSON.stringify({ status: 'PASS', count: results.length, results, errors, layer: 'Auxiliary real Vue component and native browser wheel/keys; no packaged desktop or physical trackpad claim' }, null, 2)); console.log(JSON.stringify({ status: 'PASS', count: results.length, out }));
})().catch(error => { fs.writeFileSync(path.join(out, 'failure.json'), JSON.stringify({ error: error.stack, results, errors }, null, 2)); console.error(error); process.exitCode = 1; }).finally(async () => { await browser?.close(); await server?.close(); });
