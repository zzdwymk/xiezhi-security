// Real, independently controlled SSE streams verify that concurrent scans never share UI state.
const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
let server, browser;
const streams = [], errors = [];
const html = `<!doctype html><html><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module">
import {createApp} from 'vue';import {createPinia} from 'pinia';import {createRouter,createMemoryHistory} from 'vue-router';import ElementPlus,{ElMessage} from 'element-plus';import 'element-plus/dist/index.css';import '/src/desktop-v2.css';import '/src/unified-theme.css';import Traffic from '/src/views/Traffic.vue';
sessionStorage.setItem('security_toolbox_session_token','fixture');const app=createApp(Traffic);app.use(createPinia());const router=createRouter({history:createMemoryHistory(),routes:[{path:'/',component:Traffic},{path:'/traffic',component:Traffic}]});app.use(router);window.fixtureNavigate=to=>router.push(to);window.clearMessages=()=>ElMessage.closeAll();app.use(ElementPlus);app.mount('#app');
</script></body></html>`;
const hit = title => ({ title, severity: 'HIGH', description: title });
const send = (index, event) => streams[index].res.write(`data: ${JSON.stringify(event)}\n\n`);
async function start(page, menu) {
  await page.locator('.traffic-row').first().click({ button: 'right' });
  await page.getByRole('menuitem', { name: menu, exact: true }).click();
  await page.getByRole('dialog', { name: '选择本次主动操作的授权目标', exact: true }).getByRole('button', { name: '校验并执行', exact: true }).click();
}

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.resolve(root, '../.run/traffic-scan-isolation-cache'),
    optimizeDeps: { entries: [], include: ['vue', 'element-plus', 'pinia', 'vue-router'], noDiscovery: true },
    plugins: [vue(), { name: 'scan-isolation-fixture', configureServer(s) { s.middlewares.use(async (req, res, next) => {
      const match = req.url?.match(/^\/api\/traffic\/packets\/1\/(zap|xray|sqlmap)-scan\/stream$/);
      if (match) {
        req.resume();
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
        const id = streams.push({ res, engine: match[1].toUpperCase() }) - 1;
        send(id, { type: 'record', scanId: 701 + id });
        send(id, { type: 'start', targetUrl: 'http://fixture.invalid/?id=1' });
        return;
      }
      if (req.url?.split('?')[0] !== '/__scan_isolation') return next();
      res.setHeader('Content-Type', 'text/html; charset=utf-8');res.end(await s.transformIndexHtml(req.url, html));
    }); } }], server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/dist/**', '**/desktop-release/**'] } }, logLevel: 'error' });
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 1500, height: 980 } });
  page.setDefaultTimeout(12000);
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/api/**', route => {
    const api = new URL(route.request().url()).pathname.replace(/^\/api/, '');
    if (/\/traffic\/packets\/1\/(zap|xray|sqlmap)-scan\/stream$/.test(api)) return route.continue();
    if (api === '/traffic/scans/91') return route.fulfill({ json: {
      entry: { id: 91, packetId: 1, engine: 'SQLMAP', status: 'COMPLETED' },
      result: { packetId: 1, engine: 'SQLMAP', status: 'COMPLETED', hits: [hit('STORED_RESULT')], probes: [], message: 'STORED_SUMMARY' },
    } });
    let result = [];
    if (api === '/traffic/status') result = { running: false, capturing: false, listenHost: '127.0.0.1', listenPort: 19080 };
    if (api === '/traffic/sessions') result = [{ id: 1, targetId: 7, method: 'GET', host: 'fixture.invalid', port: 80, path: '/?id=1', url: 'http://fixture.invalid/?id=1', statusCode: 200, requestHeaders: { Host: 'fixture.invalid' } }];
    if (api === '/targets') result = [{ id: 7, enabled: true, name: 'Fixture target', targetValue: 'fixture.invalid' }];
    return route.fulfill({ json: result });
  });
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__scan_isolation?desktop=1`);
  await page.locator('.traffic-row').waitFor();
  await start(page, 'ZAP 定向探测');
  const zap = page.getByRole('dialog', { name: 'OWASP ZAP 定向主动探测', exact: true });
  await zap.getByText(/记录 #701/).waitFor();
  await zap.getByRole('button', { name: '关闭', exact: true }).click();
  await zap.waitFor({ state: 'hidden' });
  await start(page, 'Xray 靶向探测');
  const xray = page.getByRole('dialog', { name: 'Xray 靶向 PoC 探测', exact: true });
  await xray.getByText(/记录 #702/).waitFor();
  await page.evaluate(() => window.clearMessages());
  send(0, { type: 'hit', hit: hit('ZAP_STALE_HIT') });
  send(0, { type: 'probe', probe: { name: 'ZAP_STALE_PROBE', target: 'fixture.invalid', triggered: true } });
  send(0, { type: 'status', message: '旧扫描诊断 ZAP_STALE_LOG' });
  send(0, { type: 'error', message: 'ZAP_STALE_FAILURE' });
  send(1, { type: 'status', message: '当前 Xray 扫描正在执行' });
  await xray.getByText('当前 Xray 扫描正在执行', { exact: true }).first().waitFor();
  await page.waitForTimeout(250);
  assert.doesNotMatch(await xray.innerText(), /ZAP_STALE/);
  assert.equal(await xray.getByRole('button', { name: '重新测试', exact: true }).isDisabled(), true, 'A finally must not clear B loading');
  assert.equal(await page.locator('.el-message').filter({ hasText: 'ZAP_STALE_FAILURE' }).count(), 0);
  console.log('PASS closing A and starting B isolates queued hits, probes, logs, errors and loading');

  await page.evaluate(() => window.fixtureNavigate('/traffic?scanId=91'));
  const stored = page.getByRole('dialog', { name: 'sqlmap SQL 注入复核', exact: true });
  await stored.getByText('STORED_RESULT', { exact: true }).waitFor();
  send(1, { type: 'hit', hit: hit('XRAY_STALE_HIT') });
  send(1, { type: 'status', message: '旧扫描诊断 XRAY_STALE_LOG' });
  send(1, { type: 'complete', result: { packetId: 1, engine: 'XRAY', status: 'COMPLETED', hits: [hit('XRAY_STALE_HIT')], message: 'XRAY_STALE_COMPLETE' } });
  await page.waitForTimeout(350);
  assert.doesNotMatch(await stored.innerText(), /XRAY_STALE/);
  assert.match(await stored.innerText(), /STORED_SUMMARY/);
  assert.equal(await stored.getByRole('button', { name: '重新测试', exact: true }).isEnabled(), true);
  assert.equal(await page.locator('.el-message').filter({ hasText: 'XRAY_STALE_COMPLETE' }).count(), 0);
  console.log('PASS reopening persisted results isolates in-flight stream ticks, completion and diagnostics');

  await stored.getByRole('button', { name: '关闭', exact: true }).click();
  await stored.waitFor({ state: 'hidden' });
  await start(page, 'sqlmap 复核');
  await stored.getByText(/记录 #703/).waitFor();
  send(2, { type: 'hit', hit: hit('SQLMAP_CURRENT_HIT') });
  send(2, { type: 'complete', result: { packetId: 1, engine: 'SQLMAP', status: 'COMPLETED', hits: [hit('SQLMAP_CURRENT_HIT')], message: 'SQLMAP_CURRENT_COMPLETE' } });
  await stored.getByText('SQLMAP_CURRENT_COMPLETE', { exact: true }).waitFor();
  assert.equal(await stored.getByRole('button', { name: '重新测试', exact: true }).isEnabled(), true);
  assert.doesNotMatch(await stored.innerText(), /STORED_RESULT|ZAP_STALE|XRAY_STALE/);
  assert.deepEqual(errors, []);
  console.log('PASS the current scan still completes normally after concurrent and restored results');
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  for (const stream of streams) stream.res.end();
  await browser?.close(); await server?.close();
});
