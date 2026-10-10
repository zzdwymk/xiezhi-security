'use strict';
// Actual App.vue history template and handlers, mounted in a fresh headless component fixture.
// No connection to the desktop profile, backend, AI provider or scan target.
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const { parse } = require('@vue/compiler-sfc');
const ts = require('typescript');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../reports/desktop-qa-2026-10-04/regressions/conversation-history-pagination/component-' + Date.now());
fs.mkdirSync(out, { recursive: true });
const app = fs.readFileSync(path.join(root, 'src/App.vue'), 'utf8'), sfc = parse(app);
assert.deepEqual(sfc.errors, []);
const ast = ts.createSourceFile('App.vue', sfc.descriptor.scriptSetup.content, ts.ScriptTarget.Latest, true);
const variableNames = ['CONVERSATION_PAGE_SIZE', 'visibleConversationLimit', 'visibleConversations', 'conversationCount', 'hasMoreConversations', 'activeNavigation', 'recentNavigation'];
const declarations = variableNames.map(name => {
  const declaration = ast.statements.flatMap(s => ts.isVariableStatement(s) ? [...s.declarationList.declarations] : []).find(d => d.name.getText(ast) === name);
  assert(declaration, name); return 'const ' + declaration.getText(ast) + ';';
});
const functions = ['loadMoreConversations', 'openConversation'].map(name => {
  const statement = ast.statements.find(s => ts.isFunctionDeclaration(s) && s.name?.text === name); assert(statement, name); return statement.getText(ast);
});
const { baseParse } = require('@vue/compiler-dom');
const templateAst = baseParse(sfc.descriptor.template.content);
function findSection(node) {
  if (node.type === 1 && node.tag === 'section' && node.props.some(p => p.type === 6 && p.name === 'class' && p.value?.content === 'desktop-v2-recents')) return node;
  for (const child of node.children || []) { const found = findSection(child); if (found) return found; }
}
const history = findSection(templateAst); assert(history);
const fixture = `<script setup lang="ts">
import {computed,ref,reactive,nextTick} from 'vue';
import {ElIcon,ElTooltip} from 'element-plus';
import {ArrowDown,ChatDotRound,Delete} from '/src/components/fluentIcons';
const count=Number(new URLSearchParams(location.search).get('count')||0);
const make=(id)=>({id,title:'会话 '+id,targetName:'192.168.136.132',messages:[{id:id+'-message',content:'保留正文 '+id,taskIds:[]}]});
const conversations=reactive({items:Array.from({length:count},(_,i)=>make('history-'+String(i+1).padStart(3,'0'))),taskIds:(thread)=>thread.messages.flatMap(m=>m.taskIds)});
const route=reactive({path:'/',query:{conversation:new URLSearchParams(location.hash.slice(1)).get('conversation')||''}});
const router={push(target){route.path=target.path;route.query=target.query||{};location.hash=new URLSearchParams(route.query).toString()}};
const collapsed=ref(false);const navigationGroupCollapsed=()=>collapsed.value;const toggleNavigationGroup=()=>{collapsed.value=!collapsed.value};
const displayConversationTitle=thread=>thread.title;const displayKnownTestName=value=>value;
const clearRecentConversations=()=>{throw Error('No destructive actions in component test')};const removeConversation=clearRecentConversations;
${declarations.join('\n')}
${functions.join('\n')}
window.historyFixture={conversations,route,prepend(){conversations.items.unshift(make('new-history'))},loadMoreConversations};
</script><template><main class="desktop-v2-app-frame" style="width:280px"><output id="active-navigation">{{activeNavigation}}</output>${history.loc.source}</main></template>`;
fs.writeFileSync(path.join(out, 'actual-app-fragment.vue'), fixture);
const fixtureId = path.join(out, 'actual-app-fragment.vue').replace(/\\/g, '/');
const html = '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"></head><body><div id="fixture"></div><script type="module">import{createApp}from"vue";import App from"/__history.vue";import"/src/desktop-v2.css";import"/src/unified-theme.css";import"/src/fluent-design-2.css";import"/src/fluent-design-3.css";createApp(App).mount("#fixture");</script></body></html>';
const results = [], errors = [], unexpectedRequests = [];
let browser, server;
async function check(name, action) { const result = await action(); results.push({ name, status: 'PASS', result }); console.log('PASS ' + name); }
(async () => {
  const { createServer } = await import('vite'); const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.join(out, 'vite-cache'), logLevel: 'error',
    optimizeDeps: { entries: [], include: ['vue', 'element-plus'], noDiscovery: true },
    plugins: [{ name: 'history-source-fixture', resolveId(id) { if (id === '/__history.vue') return fixtureId; }, load(id) { if (id === fixtureId) return fixture; },
      configureServer(instance) { instance.middlewares.use(async (req, res, next) => { if (!req.url?.startsWith('/__history?')) return next(); res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(await instance.transformIndexHtml(req.url, html)); }); } }, vue()],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/desktop-release/**', '**/dist/**'] } } });
  await server.listen(); const origin = 'http://127.0.0.1:' + server.httpServer.address().port;
  browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 800, height: 900 } });
  await page.route('**/*', route => { if (new URL(route.request().url()).origin === origin) return route.continue(); unexpectedRequests.push(route.request().url()); return route.abort(); });
  page.on('pageerror', error => errors.push(error.stack));
  const rows = () => page.locator('button.desktop-v2-recent-open');
  const more = () => page.getByRole('button', { name: '加载更多对话', exact: true });
  const ids = () => rows().evaluateAll(nodes => nodes.map(node => node.dataset.conversationId));
  async function go(count, hash = '') { await page.goto(origin + '/__history?count=' + count + hash); await page.locator('.desktop-v2-recents-toggle').waitFor(); await page.waitForFunction(() => Boolean(window.historyFixture)); }
  for (const total of [0, 1, 8, 9, 16]) await check('Initial actual DOM boundary ' + total, async () => {
    await go(total); assert.equal(await rows().count(), Math.min(total, 8)); assert.equal(await more().count(), total > 8 ? 1 : 0);
    assert.equal(await page.evaluate(() => window.historyFixture.conversations.items.length), total);
    if (total) assert.equal((await page.locator('.desktop-v2-recents-count').innerText()).trim(), String(total));
    else assert.match(await page.locator('.desktop-v2-recent-empty').innerText(), /暂无最近对话/);
  });
  await check('117 complete records mount only8 actual rows, then load9th with ID highlight', async () => {
    await go(117); const before = await page.evaluate(() => JSON.stringify(window.historyFixture.conversations.items));
    assert.equal(await rows().count(), 8); assert.equal(await page.locator('.desktop-v2-recent-item').count(), 8);
    await more().click(); await page.waitForFunction(() => document.querySelectorAll('.desktop-v2-recent-open').length === 16);
    assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('data-conversation-id')), 'history-009');
    await page.locator('[data-conversation-id="history-009"]').click();
    assert.equal(await page.locator('.desktop-v2-recent-item.active button.desktop-v2-recent-open').getAttribute('data-conversation-id'), 'history-009');
    assert.equal(await page.locator('[data-conversation-id="history-009"]').getAttribute('aria-current'), 'page');
    assert.equal(await page.locator('#active-navigation').textContent(), '');
    assert.equal(await page.evaluate(() => JSON.stringify(window.historyFixture.conversations.items)), before);
  });
  await check('Native Enter and Space append one batch each and focus first new row', async () => {
    for (const [key, count, first] of [['Enter', 24, 'history-017'], ['Space', 32, 'history-025']]) {
      await more().focus(); assert.equal(await more().evaluate(node => node.tabIndex), 0); await page.keyboard.press(key);
      await page.waitForFunction(expected => document.querySelectorAll('.desktop-v2-recent-open').length === expected, count);
      assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('data-conversation-id')), first);
    }
  });
  await check('Load every preserved record without duplicates, clipped rows or an extra empty last page', async () => {
    const seen = [];
    while (await more().count()) { const before = await rows().count(); await more().click(); await page.waitForFunction(expected => document.querySelectorAll('.desktop-v2-recent-open').length === expected, Math.min(before + 8, 117)); seen.push(await rows().count()); }
    const all = await ids(); assert.equal(all.length, 117); assert.equal(new Set(all).size, 117);
    assert.deepEqual(all, Array.from({ length: 117 }, (_, i) => 'history-' + String(i + 1).padStart(3, '0')));
    await page.locator('[data-conversation-id="history-117"]').click(); assert.equal(await page.locator('#active-navigation').textContent(), '');
    const geometry = await page.locator('#desktop-v2-recents-list').evaluate(el => ({ overflow: getComputedStyle(el).overflowY, height: el.clientHeight, scroll: el.scrollHeight, minRow: Math.min(...[...el.querySelectorAll('.desktop-v2-recent-item')].map(row => row.getBoundingClientRect().height)) }));
    assert.equal(geometry.overflow, 'auto'); assert(geometry.scroll > geometry.height); assert(geometry.minRow >= 40);
    assert.match(await page.locator('.desktop-v2-recents-status').innerText(), /已显示全部 117 条对话/);
    await page.evaluate(() => window.historyFixture.loadMoreConversations()); assert.equal(await rows().count(), 117);
    await page.screenshot({ path: path.join(out, 'history-last-page.png'), fullPage: true }); return { seen, geometry };
  });
  await check('Collapse and route switching preserve loaded rows; true refresh resets mount budget to8', async () => {
    await page.locator('.desktop-v2-recents-toggle').click(); assert.equal(await rows().count(), 117); assert.equal(await page.locator('#desktop-v2-recents-list').getAttribute('inert'), '');
    await page.locator('.desktop-v2-recents-toggle').click(); await page.locator('[data-conversation-id="history-009"]').click(); assert.equal(await rows().count(), 117);
    await page.reload(); await page.locator('.desktop-v2-recents-toggle').waitFor(); assert.equal(await rows().count(), 8);
    assert.equal(await page.locator('#active-navigation').textContent(), '', 'An existing deep route must not highlight the welcome navigation merely because its row is not mounted');
    assert.equal(await page.evaluate(() => window.historyFixture.conversations.items.length), 117);
  });
  await check('Adding a new record preserves every old record and the8-row budget', async () => {
    const old = await page.evaluate(() => JSON.stringify(window.historyFixture.conversations.items)); await page.evaluate(() => window.historyFixture.prepend());
    await page.waitForFunction(() => document.querySelector('.desktop-v2-recent-open')?.getAttribute('data-conversation-id') === 'new-history');
    assert.equal(await rows().count(), 8); assert.equal(await page.evaluate(() => window.historyFixture.conversations.items.length), 118);
    assert.equal(await page.evaluate(() => JSON.stringify(window.historyFixture.conversations.items.slice(1))), old);
  });
  assert.deepEqual(errors, []); assert.deepEqual(unexpectedRequests, []);
  fs.writeFileSync(path.join(out, 'result.json'), JSON.stringify({ status: 'PASS', layer: 'Real source Vue component; isolated headless fixture, not packaged desktop', count: results.length, results, errors, unexpectedRequests }, null, 2));
  console.log(JSON.stringify({ status: 'PASS', count: results.length, out }));
})().catch(error => { fs.writeFileSync(path.join(out, 'failure.json'), JSON.stringify({ error: error.stack, results, errors, unexpectedRequests }, null, 2)); console.error(error); process.exitCode = 1; })
  .finally(async () => { await browser?.close(); await server?.close(); });
