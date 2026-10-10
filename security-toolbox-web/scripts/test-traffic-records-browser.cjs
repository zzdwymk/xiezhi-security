// Exercise the real Tasks/Findings pages against isolated persisted-scan fixtures.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '../.run/traffic-records');
fs.mkdirSync(output, { recursive: true });
let server, browser;
const errors = [];
const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module">
import {createApp} from 'vue';import {createPinia} from 'pinia';import {createRouter,createMemoryHistory,RouterView} from 'vue-router';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';import '/src/desktop-v2.css';import '/src/unified-theme.css';
import Tasks from '/src/views/Tasks.vue';import Findings from '/src/views/Findings.vue';import {endpoints} from '/src/api';import {useAuthStore} from '/src/stores/auth';
sessionStorage.setItem('security_toolbox_session_token','fixture');
for(const key of Object.keys(endpoints))endpoints[key]=async()=>({data:key==='findings'?{content:[],totalElements:0}:key==='taskControlStatus'?{runningTaskCount:0,pendingTaskCount:0,maxConcurrentTasks:3}:[]});
const router=createRouter({history:createMemoryHistory(),routes:[{path:'/tasks',component:Tasks},{path:'/findings',component:Findings}]});
const app=createApp(RouterView);app.use(createPinia());app.use(router);app.use(ElementPlus);const auth=useAuthStore();const params=new URL(location.href).searchParams;auth.user={username:'fixture',role:params.get('role')||'ADMIN'};
window.fixtureNavigate=to=>router.push(to);window.fixtureLocation=()=>router.currentRoute.value.fullPath;window.fixtureRole=role=>auth.user={username:'fixture',role};await router.push(params.get('start')||'/tasks');await router.isReady();app.mount('#app');window.fixtureReady=true;
</script></body></html>`;
const scan = (id, extra = {}) => ({ id, packetId: 9000 + id, targetId: 7, engine: 'ZAP', host: 'fixture.invalid', url: `http://fixture.invalid/?id=${id}`, status: 'COMPLETED', hitCount: 0, createdAt: '2026-10-04T01:00:00Z', ...extra });
const hit = { title: 'Stored SQL injection evidence', severity: 'HIGH', description: 'Saved fixture finding', parameter: 'id', evidence: 'Persisted request/response evidence', solution: 'Use parameterized queries' };

async function pageFor(start, role = 'ADMIN') {
  const page = await browser.newPage({ viewport: { width: 1460, height: 1000 } });
  page.setDefaultTimeout(12000);
  page.on('pageerror', e => errors.push(e.message));
  const calls = [];
  const state = { completed: false };
  await page.route('**/api/**', async route => {
    const req = route.request();
    const url = new URL(req.url());
    const api = url.pathname.replace(/^\/api/, '');
    calls.push({ api, method: req.method(), params: Object.fromEntries(url.searchParams) });
    assert.equal(req.method(), 'GET', 'viewing saved records must not start operations');
    if (api === '/traffic/scans') {
      const entries = [scan(401, { status: state.completed ? 'COMPLETED' : 'RUNNING', hitCount: state.completed ? 1 : 0 }),
        scan(402, { status: 'FAILED', message: 'ZAP REST 调用失败（core/action/accessUrl），HTTP 500，INTERNAL_ERROR' }),
        scan(403), scan(404, { engine: 'FUZZ', status: 'TIMEOUT', hitCount: 1 }),
        ...Array.from({ length: 8 }, (_, i) => scan(405 + i))];
      const sources = url.searchParams.get('findingsOnly') === 'true' ? entries.filter(e => e.hitCount > 0 && e.engine !== 'FUZZ') : entries;
      const filtered = url.searchParams.get('engine') ? sources.filter(e => e.engine === url.searchParams.get('engine')) : sources;
      const index = Number(url.searchParams.get('page')) * Number(url.searchParams.get('size'));
      return route.fulfill({ json: { content: filtered.slice(index, index + Number(url.searchParams.get('size'))), totalElements: filtered.length } });
    }
    if (api === '/traffic/scans/401') return route.fulfill({ json: {
      entry: scan(401, { status: state.completed ? 'COMPLETED' : 'RUNNING', hitCount: state.completed ? 1 : 0 }),
      result: state.completed ? { status: 'COMPLETED', hits: [hit], probes: [{ name: 'Saved probe', target: 'fixture.invalid', payload: 'fixture', triggered: true, statusCode: 200, responseSnippet: 'Saved response' }] } : null,
    } });
    if (api === '/traffic/scans/402') return route.fulfill({ json: {
      entry: scan(402, { status: 'FAILED', message: 'ZAP REST 调用失败（core/action/accessUrl），HTTP 500，INTERNAL_ERROR' }),
      result: { status: 'FAILED', hits: [hit], probes: [] },
    } });
    if (api === '/traffic/scans/403') return route.fulfill({ json: { entry: scan(403, { hitCount: 2 }), result: null } });
    if (api === '/traffic/scans/404') return route.fulfill({ json: {
      entry: scan(404, { engine: 'FUZZ', status: 'TIMEOUT', hitCount: 1 }),
      result: { status: 'TIMEOUT', results: { 9404: { status: 'TIMEOUT', completedRequests: 1, results: [{ payload: 'Saved fuzz payload', statusCode: 500, reason: 'Response changed', durationMs: 30 }] } } },
    } });
    if (api.startsWith('/traffic/')) throw new Error('Unexpected dependency on live traffic: ' + api);
    return route.fulfill({ status: 200, contentType: 'text/event-stream', body: '' });
  });
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__traffic_records?role=${role}&start=${encodeURIComponent(start)}`);
  await page.waitForFunction(() => window.fixtureReady);
  return { page, calls, state };
}

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.join(output, 'cache'),
    optimizeDeps: { entries: [], include: ['vue', 'element-plus', 'pinia', 'vue-router'], noDiscovery: true },
    plugins: [vue(), { name: 'traffic-records-fixture', configureServer(s) { s.middlewares.use(async (req, res, next) => {
      if (req.url?.split('?')[0] !== '/__traffic_records') return next();
      res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(await s.transformIndexHtml(req.url, html));
    }); } }], server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/dist/**', '**/desktop-release/**'] } }, logLevel: 'error' });
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });

  const { page, calls, state } = await pageFor('/tasks');
  await page.getByRole('tab', { name: '流量检测', exact: true }).waitFor();
  assert.equal(calls.some(c => c.api.startsWith('/traffic/')), false, 'project tab must not fetch traffic');
  await page.getByRole('tab', { name: '流量检测', exact: true }).click();
  const records = page.locator('.traffic-scan-records');
  await records.getByText('http://fixture.invalid/?id=401', { exact: true }).waitFor();
  await records.getByRole('button', { name: '执行详情', exact: true }).first().click();
  const dialog = page.getByRole('dialog', { name: '流量检测执行详情', exact: true });
  await dialog.getByText('检测进行中，结果会在完成后自动更新。', { exact: true }).waitFor();
  state.completed = true;
  await dialog.getByText('Saved probe', { exact: true }).waitFor();
  assert.equal(await dialog.getByText(hit.title, { exact: false }).count(), 0, 'task detail must not duplicate finding evidence');
  assert.equal(await dialog.getByText(hit.solution, { exact: false }).count(), 0, 'task detail must not duplicate remediation');
  assert.equal(await dialog.locator('.el-alert--warning').count(), 1, 'completed findings must not appear as a green all-clear');
  assert.ok(calls.filter(c => c.api === '/traffic/scans/401').length >= 2);
  await dialog.getByRole('button', { name: '关闭', exact: true }).click();
  await records.locator('.el-pager').getByText('2', { exact: true }).click();
  await records.getByText('http://fixture.invalid/?id=411', { exact: true }).waitFor();
  assert.ok(calls.some(c => c.api === '/traffic/scans' && c.params.page === '1'));
  await records.locator('.traffic-record-toolbar .el-select').click();
  await page.getByRole('option', { name: '模糊测试', exact: true }).click();
  await records.getByText('http://fixture.invalid/?id=404', { exact: true }).waitFor();
  assert.ok(calls.some(c => c.api === '/traffic/scans' && c.params.engine === 'FUZZ' && c.params.page === '0'));
  console.log('PASS tasks source tabs, paginated/filterable records and automatic running-result refresh');

  await page.evaluate(() => window.fixtureNavigate('/findings?source=traffic&scanId=402'));
  const findingDialog = page.getByRole('dialog', { name: '流量安全发现', exact: true });
  await findingDialog.getByText(hit.evidence, { exact: true }).waitFor();
  assert.equal(await findingDialog.getByText('Saved probe', { exact: true }).count(), 0);
  assert.ok(calls.some(c => c.api === '/traffic/scans' && c.params.findingsOnly === 'true'));
  assert.equal(await page.locator('.traffic-scan-records').getByText('http://fixture.invalid/?id=404', { exact: true }).count(), 0, 'FUZZ anomalies must not appear in finding sources');
  assert.equal(await page.getByRole('tab', { name: '流量发现', exact: true }).getAttribute('aria-selected'), 'true');
  await page.screenshot({ path: path.join(output, 'stored-failed-result.png'), fullPage: true });
  await page.evaluate(() => window.fixtureNavigate('/findings?source=traffic&scanId=403'));
  await findingDialog.getByText('这条历史记录仅保存了执行摘要，没有完整结果快照。', { exact: true }).waitFor();
  await page.evaluate(() => window.fixtureNavigate('/findings?source=traffic&scanId=404'));
  await findingDialog.getByText('模糊测试记录的是请求响应差异，不能直接确认为漏洞；请在来源记录查看执行证据。', { exact: true }).waitFor();
  assert.equal(await findingDialog.getByText('Saved fuzz payload', { exact: true }).count(), 0);
  await findingDialog.getByRole('button', { name: '来源记录', exact: true }).click();
  await dialog.getByText('Saved fuzz payload', { exact: true }).waitFor();
  assert.equal(await dialog.locator('.el-alert--warning').count(), 1);
  await page.evaluate(() => window.fixtureNavigate('/findings?source=traffic')); 
  assert.equal(calls.some(c => c.api.startsWith('/traffic/packets')), false);
  console.log('PASS result center restores failed, legacy and partial FUZZ records without captured packets or new scans');
  await page.evaluate(() => window.fixtureRole('USER'));
  await page.getByRole('tab', { name: '流量发现', exact: true }).waitFor({ state: 'hidden' });
  assert.equal(await page.locator('.traffic-scan-records').count(), 0);
  await page.close();

  for (const start of ['/tasks?source=traffic&scanId=401', '/findings?source=traffic&scanId=401']) {
    const guest = await pageFor(start, 'USER');
    assert.equal(await guest.page.locator('.traffic-scan-records').count(), 0);
    assert.equal(guest.calls.some(c => c.api.startsWith('/traffic/')), false);
    await guest.page.close();
  }
  assert.deepEqual(errors, []);
  console.log('PASS non-admin deep links do not render or request traffic records; no browser errors');
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  await browser?.close(); await server?.close();
});
