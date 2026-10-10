// Real Vue toolbar, isolated HTTP/IPC fixtures. No live proxy or desktop data is used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '../.run');
fs.mkdirSync(output, { recursive: true });
let browser, server;
const calls = [], errors = [];
const proxy = { running: false, capturing: false, listenHost: '127.0.0.1', listenPort: 19080 };
let failCapture = false, failStatus = false;
const session = { id: 1, method: 'GET', host: 'example.test', port: 80, path: '/', requestHeaders: 'Host: example.test', responseBody: 'response', statusCode: 200, marked: false, riskLevel: 'NONE' };
let holdNextSessionsRead = false, releaseSessionsRead;
const html = `<!doctype html><html><head><meta charset="utf-8"><style>html,body,#app{margin:0;height:100%}#app{padding:16px;box-sizing:border-box}</style></head><body><div id="app"></div><script type="module">
import {createApp} from 'vue';import {createPinia} from 'pinia';import {createRouter,createMemoryHistory} from 'vue-router';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';import '/src/desktop-v2.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';import Traffic from '/src/views/Traffic.vue';
const state=window.fixture={browserRunning:false,launchMode:'ok',closeMode:'ok',launches:0,closes:0,synced:[],holdNextRead:false,pendingRead:null,pendingLaunch:null};
let onClosed=()=>{};
window.toolboxDesktop={
launchCaptureBrowser:async()=>{state.launches++;if(state.launchMode==='reject')throw new Error('launch rejected');if(state.launchMode==='hold')await new Promise(resolve=>state.pendingLaunch=resolve);state.browserRunning=true;if(state.launchMode==='closed'){state.browserRunning=false;onClosed();}return {running:true}},
closeCaptureBrowser:async()=>{state.closes++;if(state.closeMode==='reject')throw new Error('close rejected');if(state.closeMode==='cancel')return {running:true};state.browserRunning=false;onClosed();return {running:false}},
getCaptureBrowserStatus:async()=>{const snapshot={running:state.browserRunning};if(state.holdNextRead){state.holdNextRead=false;return await new Promise(resolve=>state.pendingRead=()=>{state.pendingRead=null;resolve(snapshot)});}return snapshot;},
onCaptureBrowserClosed:callback=>{onClosed=callback;return()=>{onClosed=()=>{}}},
setCaptureBrowserProxyState:async state=>window.fixture.synced.push({...state})};
const app=createApp(Traffic);app.use(createPinia());app.use(createRouter({history:createMemoryHistory(),routes:[{path:'/',component:Traffic}]}));app.use(ElementPlus);app.mount('#app');window.unmountTraffic=()=>app.unmount();
</script></body></html>`;
async function check(name, fn) { await fn(); console.log('PASS ' + name); }
(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.join(output, 'traffic-toolbar-cache'), plugins: [vue(), { name: 'toolbar-fixture', configureServer(s) { s.middlewares.use(async (req, res, next) => { if (req.url !== '/__toolbar') return next(); res.setHeader('Content-Type', 'text/html'); res.end(await s.transformIndexHtml(req.url, html)); }); } }], server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/dist/**', '**/desktop-release/**'] } }, logLevel: 'error' });
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 1560, height: 980 } });
  page.on('pageerror', e => errors.push(e.message));
  await page.route('**/api/**', async route => {
    const req = route.request(); const api = new URL(req.url()).pathname.replace(/^\/api/, ''); const data = req.postDataJSON() || {};
    calls.push({ api, method: req.method(), data });
    let result = [];
    if (api === '/traffic/status') {
      if (failStatus) return route.fulfill({ status: 503, json: { message: '代理状态暂不可达' } });
      result = { ...proxy };
    } else if (api === '/traffic/sessions') {
      result = [{ ...session }];
      if (holdNextSessionsRead) {
        holdNextSessionsRead = false;
        await new Promise(resolve => { releaseSessionsRead = () => { releaseSessionsRead = undefined; resolve(); }; });
      }
    } else if (api === '/traffic/sessions/1/marked' && req.method() === 'PUT') { session.marked = data.marked; result = { ...session }; }
    else if (api === '/traffic/proxy/start') { proxy.running = true; result = { ...proxy }; }
    else if (api === '/traffic/proxy/capture') {
      if (failCapture) return route.fulfill({ status: 500, json: { message: '记录操作失败' } });
      proxy.capturing = data.enabled; result = { ...proxy };
    } else if (api === '/traffic/proxy/stop') { proxy.running = false; proxy.capturing = false; result = { ...proxy }; }
    try { await route.fulfill({ json: result }); } catch { /* A newer operation may abort this older refresh. */ }
  });
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__toolbar`);
  await page.locator('.traffic-row').waitFor();
  const button = name => page.getByRole('button', { name, exact: true });
  const waitIdle = async () => { await page.waitForFunction(() => !document.querySelector('.capture-browser-reopen.is-loading, .capture-toggle.is-loading, .proxy-toggle.is-loading')); };
  const statusStyle = () => page.locator('.proxy-state').evaluate(el => ({ color: getComputedStyle(el).color, dot: getComputedStyle(el.querySelector('i')).backgroundColor, shadow: getComputedStyle(el.querySelector('i')).boxShadow, capturing: el.classList.contains('capturing') }));
  await check('scan history belongs to the workspace toolbar and clear is directly visible and keyboard-accessible', async () => {
    assert.equal(await page.locator('.traffic-toolbar-actions').getByRole('button', { name: '扫描记录', exact: true }).count(), 1);
    assert.equal(await page.locator('.session-rail-header').getByText('扫描记录', { exact: true }).count(), 0);
    assert.equal(await page.getByText('扫描台账', { exact: true }).count(), 0);
    assert.equal(await button('流量会话更多操作').count(), 0);
    const clear = page.locator('.session-rail-header').getByRole('button', { name: '清空未标记', exact: true });
    assert.equal(await clear.isVisible(), true);
    assert.equal(await clear.isEnabled(), true);
    const deletions = calls.filter(c => c.method === 'DELETE').length;
    await clear.focus();
    await page.keyboard.press('Enter');
    await page.getByRole('dialog', { name: '清空未标记流量' }).waitFor();
    await button('取消').click();
    await page.getByRole('dialog', { name: '清空未标记流量' }).waitFor({ state: 'hidden' });
    assert.equal(calls.filter(c => c.method === 'DELETE').length, deletions);
    assert.equal(await page.locator('.traffic-row').count(), 1);
  });
  await check('session rows omit risk ratings while marking survives refresh including an older list response', async () => {
    const row = page.locator('.traffic-row');
    const verifyNoRiskLabel = async () => {
      assert.equal(await row.getByText(/^(未评级|未标记|高危|HIGH|NONE)$/).count(), 0);
      assert.equal(await row.locator('[title^="风险等级"]').count(), 0);
      assert.equal(await row.getByText('GET', { exact: true }).count(), 1);
      assert.equal(await row.getByText('200', { exact: true }).count(), 1);
    };
    assert.equal(session.riskLevel, 'NONE');
    await verifyNoRiskLabel();
    holdNextSessionsRead = true;
    await button('刷新流量').click();
    const readDeadline = Date.now() + 5000;
    while (!releaseSessionsRead && Date.now() < readDeadline) await page.waitForTimeout(10);
    assert.equal(typeof releaseSessionsRead, 'function');
    await row.click({ button: 'right' });
    await page.getByRole('menuitem', { name: '标记会话', exact: true }).click();
    await row.locator('.session-marked-flag').waitFor();
    assert.equal(session.marked, true);
    releaseSessionsRead();
    await page.waitForTimeout(150);
    assert.equal(await row.locator('.session-marked-flag').count(), 1);
    await verifyNoRiskLabel();
    await button('刷新流量').click();
    await page.waitForTimeout(150);
    assert.equal(await row.locator('.session-marked-flag').count(), 1);
    await row.click({ button: 'right' });
    await page.getByRole('menuitem', { name: '取消标记', exact: true }).click();
    await row.locator('.session-marked-flag').waitFor({ state: 'detached' });
    assert.equal(session.marked, false);
    await button('刷新流量').click();
    await page.waitForTimeout(150);
    assert.equal(await row.locator('.session-marked-flag').count(), 0);
    await verifyNoRiskLabel();
    session.riskLevel = 'HIGH';
    session.path = '/high-risk-fixture';
    await button('刷新流量').click();
    await row.getByText('/high-risk-fixture', { exact: true }).waitFor();
    await verifyNoRiskLabel();
  });
  await check('opening starts a stopped proxy and records; reopening a paused proxy preserves pause', async () => {
    await button('打开抓包浏览器').click(); await button('暂停记录').waitFor(); await waitIdle();
    assert.equal(proxy.running, true); assert.equal(proxy.capturing, true);
    const recordingStyle = await statusStyle();
    assert.equal(recordingStyle.capturing, true); assert.equal(recordingStyle.shadow, 'none');
    assert.equal(await page.evaluate(() => window.fixture.browserRunning), true);
    assert.equal(await button('打开抓包浏览器').isVisible(), true);
    assert.equal(await page.getByText('浏览器已打开', { exact: true }).isVisible(), true);
    await button('暂停记录').click(); await button('开始记录').waitFor(); await waitIdle();
    const pausedStyle = await statusStyle();
    assert.equal(pausedStyle.capturing, false); assert.equal(pausedStyle.shadow, 'none');
    assert.notEqual(pausedStyle.color, recordingStyle.color);
    assert.notEqual(pausedStyle.dot, recordingStyle.dot);
    const captures = calls.filter(c => c.api === '/traffic/proxy/capture').length;
    await button('打开抓包浏览器').click(); await waitIdle();
    assert.equal(proxy.capturing, false);
    assert.equal(calls.filter(c => c.api === '/traffic/proxy/capture').length, captures);
    assert.deepEqual(await page.evaluate(() => window.fixture.synced.at(-1)), { running: true, capturing: false });
  });
  await check('close browser preserves proxy; stop proxy preserves browser and its document', async () => {
    await button('关闭浏览器').click(); await button('关闭浏览器').waitFor({ state: 'detached' }); await waitIdle();
    assert.equal(proxy.running, true); assert.equal(proxy.capturing, false);
    await button('打开抓包浏览器').click(); await button('关闭浏览器').waitFor(); await waitIdle();
    const closes = await page.evaluate(() => window.fixture.closes);
    await button('关闭代理').click(); await button('关闭代理').waitFor({ state: 'detached' }); await waitIdle();
    assert.equal(await page.evaluate(() => window.fixture.browserRunning), true);
    assert.equal(await page.evaluate(() => window.fixture.closes), closes);
    assert.deepEqual(await page.evaluate(() => window.fixture.synced.at(-1)), { running: false, capturing: false });
    await button('开始记录').click(); await button('暂停记录').waitFor(); await waitIdle();
    assert.equal(proxy.running, true); assert.equal(proxy.capturing, true);
  });
  await check('rejected and cancelled closes keep the real opened state', async () => {
    for (const mode of ['reject', 'cancel']) {
      await page.evaluate(mode => window.fixture.closeMode = mode, mode);
      const before = await page.evaluate(() => window.fixture.closes);
      await button('关闭浏览器').click(); await page.waitForFunction(n => window.fixture.closes > n, before); await waitIdle();
      assert.equal(await page.evaluate(() => window.fixture.browserRunning), true);
      assert.equal(await button('关闭浏览器').isVisible(), true);
      assert.equal(proxy.capturing, true);
    }
    await page.evaluate(() => window.fixture.closeMode = 'ok');
    await button('关闭浏览器').click(); await button('关闭浏览器').waitFor({ state: 'detached' }); await waitIdle();
  });
  await check('launch failure reports the recording state and reconciles without inventing a browser', async () => {
    await page.evaluate(() => window.fixture.launchMode = 'reject');
    await button('打开抓包浏览器').click(); await waitIdle();
    assert.equal(proxy.running, true); assert.equal(proxy.capturing, true);
    assert.equal(await button('关闭浏览器').count(), 0);
    assert.ok((await page.locator('.el-message--error').allTextContents()).some(text => text.includes('代理仍在记录流量')));
    await button('暂停记录').click(); await button('开始记录').waitFor(); await waitIdle();
    await button('打开抓包浏览器').click(); await waitIdle();
    assert.equal(proxy.capturing, false);
    assert.ok((await page.locator('.el-message--error').allTextContents()).some(text => text.includes('记录已暂停')));
    await page.evaluate(() => window.fixture.launchMode = 'ok');
  });
  await check('stale refresh and overlapping silent/manual reads cannot overwrite an operation', async () => {
    await page.evaluate(() => window.fixture.holdNextRead = true);
    await button('刷新流量').click(); await page.waitForFunction(() => Boolean(window.fixture.pendingRead));
    const count = calls.filter(c => c.api === '/traffic/status').length;
    await page.waitForTimeout(2700);
    assert.equal(calls.filter(c => c.api === '/traffic/status').length, count);
    await button('开始记录').click(); await button('暂停记录').waitFor(); await waitIdle();
    await page.evaluate(() => window.fixture.pendingRead());
    await page.waitForTimeout(100);
    assert.equal(await button('暂停记录').isVisible(), true);
    assert.deepEqual(await page.evaluate(() => window.fixture.synced.at(-1)), { running: true, capturing: true });
  });
  await check('a native closed event wins over an older launch IPC reply', async () => {
    await page.evaluate(() => window.fixture.launchMode = 'closed');
    await button('打开抓包浏览器').click(); await waitIdle();
    assert.equal(await page.evaluate(() => window.fixture.browserRunning), false);
    assert.equal(await button('关闭浏览器').count(), 0);
    await page.evaluate(() => window.fixture.launchMode = 'ok');
    await button('打开抓包浏览器').click(); await button('关闭浏览器').waitFor(); await waitIdle();
  });
  await check('failed operations recheck state and signal unknown when the backend is unreachable', async () => {
    failCapture = true; failStatus = true;
    await button('暂停记录').click(); await waitIdle();
    await page.getByText('代理状态未知', { exact: true }).waitFor();
    assert.deepEqual(await page.evaluate(() => window.fixture.synced.at(-1)), { running: null, capturing: false });
    failCapture = false; failStatus = false;
    await button('刷新流量').click(); await page.getByText('正在记录', { exact: true }).waitFor();
  });
  await page.waitForTimeout(3300);
  await page.screenshot({ path: path.join(output, 'traffic-toolbar-normal.png'), fullPage: true });
  await check('light and dark themes preserve status semantics and direct clear button visibility', async () => {
    for (const theme of ['light', 'dark']) {
      await page.emulateMedia({ colorScheme: theme });
      await page.evaluate(theme => { document.documentElement.dataset.systemTheme = theme; document.documentElement.style.colorScheme = theme; }, theme);
      await page.mouse.move(600, 500);
      await page.waitForTimeout(3300);
      await page.screenshot({ path: path.join(output, `traffic-toolbar-${theme}.png`), fullPage: true });
      const recordingStyle = await statusStyle();
      assert.equal(recordingStyle.capturing, true);
      const foreground = await page.evaluate(() => { const probe = document.createElement('span'); probe.style.color = 'var(--app-success-foreground)'; document.body.append(probe); const color = getComputedStyle(probe).color; probe.remove(); return color; });
      assert.equal(recordingStyle.color, foreground);
      assert.equal(recordingStyle.dot, foreground);
      await button('暂停记录').click(); await button('开始记录').waitFor(); await waitIdle();
      const pausedStyle = await statusStyle();
      assert.equal(pausedStyle.capturing, false); assert.equal(pausedStyle.shadow, 'none');
      assert.notEqual(recordingStyle.dot, pausedStyle.dot);
      await page.waitForTimeout(3300);
      assert.equal(await button('清空未标记').isVisible(), true);
      await page.mouse.move(600, 500);
      await page.screenshot({ path: path.join(output, `traffic-toolbar-${theme}-paused.png`), fullPage: true });
      await button('开始记录').click(); await button('暂停记录').waitFor(); await waitIdle();
    }
  });
  await check('controls are mutually exclusive and unmounted operations discard later callbacks', async () => {
    await page.evaluate(() => window.fixture.launchMode = 'hold');
    await button('打开抓包浏览器').click(); await page.waitForFunction(() => Boolean(window.fixture.pendingLaunch));
    assert.equal(await button('关闭浏览器').isDisabled(), true);
    assert.equal(await button('暂停记录').isDisabled(), true);
    assert.equal(await button('关闭代理').isDisabled(), true);
    assert.equal(await button('刷新流量').isDisabled(), true);
    await page.evaluate(() => window.unmountTraffic());
    const syncCount = await page.evaluate(() => window.fixture.synced.length);
    const statusCount = calls.filter(c => c.api === '/traffic/status').length;
    await page.evaluate(() => window.fixture.pendingLaunch());
    await page.waitForTimeout(2700);
    assert.equal(await page.evaluate(() => window.fixture.synced.length), syncCount);
    assert.equal(calls.filter(c => c.api === '/traffic/status').length, statusCount);
  });
  assert.deepEqual(errors, []);
  console.log('PASS no Vue/browser runtime errors');
})().catch(e => { console.error(e); process.exitCode = 1; }).finally(async () => { await browser?.close(); await server?.close(); });
