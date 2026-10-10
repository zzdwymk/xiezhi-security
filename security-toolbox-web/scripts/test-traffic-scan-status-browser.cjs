// Render the real Traffic view against isolated HTTP/SSE fixtures. No target is scanned.
const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
let server, browser;
const errors = [], scans = [], fuzzCalls = [];
const zapRequests = [];
let scenario;
let fuzzStatus;
let finishProgressStream;
const html = `<!doctype html><html><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module">
import {createApp} from 'vue';import {createPinia} from 'pinia';import {createRouter,createMemoryHistory} from 'vue-router';import ElementPlus,{ElMessage} from 'element-plus';import 'element-plus/dist/index.css';import '/src/desktop-v2.css';import '/src/unified-theme.css';import Traffic from '/src/views/Traffic.vue';
sessionStorage.setItem('security_toolbox_session_token','fixture-token');
const app=createApp(Traffic);app.use(createPinia());const fixtureRouter=createRouter({history:createMemoryHistory(),routes:[{path:'/',component:Traffic},{path:'/traffic',component:Traffic}]});app.use(fixtureRouter);window.notificationTestNavigate=path=>fixtureRouter.push(path);window.recordNavigations=[];fixtureRouter.beforeEach(to=>{if(['/tasks','/findings'].includes(to.path)){window.recordNavigations.push(to.fullPath);return false;}});app.use(ElementPlus);app.mount('#app');window.clearMessages=()=>ElMessage.closeAll();
</script></body></html>`;
const engineCases = [
  { key: 'zap', menu: 'ZAP 定向注入探测', title: 'OWASP ZAP 定向主动探测' },
  { key: 'xray', menu: 'Xray 靶向 PoC 探测', title: 'Xray 靶向 PoC 探测' },
  { key: 'sqlmap', menu: 'sqlmap 注入复核', title: 'sqlmap SQL 注入复核' },
];
const hit = { title: 'Fixture finding', severity: 'HIGH', description: 'Fixture only', parameter: 'id' };
const zapAccessError = 'ZAP REST 调用失败（core/action/accessUrl），HTTP 500，INTERNAL_ERROR';
const probe = { name: 'Fixture probe', target: 'http://fixture.test/?id=1', triggered: false };
const stream = events => events.map(event => `data: ${JSON.stringify(event)}\n\n`).join('');

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.resolve(root, '../.run/traffic-scan-status-cache'), plugins: [vue(), {
    name: 'scan-status-fixture', configureServer(s) { s.middlewares.use(async (req, res, next) => {
      if (req.url?.split('?')[0] === '/api/traffic/packets/1/zap-scan/stream' && scenario?.liveProgress) {
        res.setHeader('Content-Type', 'text/event-stream');
        res.write(stream([{ type: 'record', scanId: 77 }, { type: 'status', message: 'ZAP 主动扫描进度 26% · 已用 90 秒，本次最多等待 1800 秒。当前检查尚未结束，进度可能暂时不变。' }]));
        finishProgressStream = () => res.end(stream([{ type: 'complete', result: { status: 'COMPLETED', engine: 'ZAP', hits: [], probes: [] } }]));
        return;
      }
      if (req.url?.split('?')[0] !== '/__scan_status') return next();
      res.setHeader('Content-Type', 'text/html'); res.end(await s.transformIndexHtml(req.url, html));
    }); },
  }], server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/dist/**', '**/desktop-release/**'] } }, logLevel: 'error' });
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 1560, height: 980 } });
  page.on('pageerror', e => errors.push(e.message));
  await page.route('**/api/**', async route => {
    const request = route.request();
    const api = new URL(request.url()).pathname.replace(/^\/api/, '');
    if (api === '/traffic/fuzz-batches') {
      fuzzCalls.push(fuzzStatus);
      assert.deepEqual(request.postDataJSON().packetIds, [1]);
      return route.fulfill({ json: { batchId: 'fixture-batch', status: fuzzStatus, message: '测试未全部完成：fixture', results: { '1': { packetId: 1, method: 'GET', url: 'http://fixture.test/?id=1', engine: 'LOOP', status: fuzzStatus, results: [], completedRequests: 0, payloadCount: 1 } } } });
    }
    if (/\/traffic\/packets\/1\/(zap|xray|sqlmap)-scan\/stream$/.test(api)) {
      scans.push(api);
      if (api.includes('/zap-scan/')) zapRequests.push(request.postDataJSON());
      if (scenario.liveProgress) return route.continue();
      if (scenario.httpError) return route.fulfill({ status: 503, json: { message: '检测服务暂不可用' } });
      const events = scenario.events || [{ type: 'complete', result: { packetId: 1, engine: api.includes('/xray-') ? 'XRAY' : api.includes('/zap-') ? 'ZAP' : 'SQLMAP', status: scenario.status, hits: scenario.hits || [], probes: [], message: scenario.message || '' } }];
      return route.fulfill({ contentType: 'text/event-stream', body: stream([{ type: 'record', scanId: 77 }, ...events]) });
    }
    if (api === '/traffic/scans/51') return route.fulfill({ json: {
      entry: { id: 51, packetId: 99, engine: 'SQLMAP', status: 'TIMEOUT' },
      result: { packetId: 99, engine: 'SQLMAP', status: 'TIMEOUT', hits: [hit], probes: [], message: 'Stored notification timeout' },
    } });
    if (api === '/traffic/scans/52') return route.fulfill({ json: {
      entry: { id: 52, packetId: 99, engine: 'FUZZ', status: 'FAILED' },
      result: { batchId: 'stored', status: 'FAILED', message: 'Stored partial batch result', results: {
        '99': { packetId: 99, method: 'GET', engine: 'LOOP', status: 'COMPLETED', results: [], completedRequests: 3, payloadCount: 3 },
      } },
    } });
    if (api === '/traffic/packets/99') return route.fulfill({ json: { id: 99, sessionId: 88, targetId: 7, method: 'GET', host: 'stored.test', path: '/recorded', url: 'http://stored.test/recorded' } });
    let result = [];
    if (api === '/traffic/status') result = { running: false, capturing: false, listenHost: '127.0.0.1', listenPort: 19080 };
    if (api === '/traffic/sessions') result = [{ id: 1, targetId: 7, method: 'GET', host: 'fixture.test', port: 80, path: '/?id=1', url: 'http://fixture.test/?id=1', statusCode: 200, requestHeaders: { Host: 'fixture.test' } }];
    if (api === '/targets') result = [{ id: 7, enabled: true, name: 'Fixture target', targetValue: 'fixture.test' }];
    await route.fulfill({ json: result });
  });
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__scan_status?desktop=1`);
  await page.locator('.traffic-row').waitFor();
  const cases = [
    { name: 'login-context SSE error', events: [{ type: 'error', message: '请先登录后再继续操作' }], alert: 'error', text: '请先登录后再继续操作' },
    { name: 'HTTP service error', httpError: true, alert: 'error', text: '检测服务暂不可用' },
    { name: 'failed final result', status: 'FAILED', message: '工具执行失败', alert: 'error', text: '工具执行失败' },
    { name: 'readable ZAP access failure', status: 'FAILED', message: zapAccessError, alert: 'error', text: 'ZAP 访问目标网站时出错，检测未完成', detail: zapAccessError },
    { name: 'readable ZAP stream error', events: [{ type: 'error', message: zapAccessError }], alert: 'error', text: 'ZAP 访问目标网站时出错，检测未完成', detail: zapAccessError },
    { name: 'target connection failure', status: 'FAILED', message: '连接目标失败: java.net.ConnectException: Connection refused', alert: 'error', text: '无法连接目标网站，检测未完成', detail: '连接目标失败: java.net.ConnectException: Connection refused' },
    { name: 'missing traffic is not a missing tool', status: 'FAILED', message: '流量记录不存在', alert: 'error', text: '流量记录不存在' },
    { name: 'specific rule repair advice is preserved', status: 'FAILED', message: '所选漏洞检测规则未能加载，本次没有执行检测。请重新选择规则，或检查 Xray 规则库后重试。', alert: 'error', text: '所选漏洞检测规则未能加载', guidance: '请重新选择规则，或检查 Xray 规则库后重试。' },
    { name: 'timed-out result', status: 'TIMEOUT', message: '检测已超时', alert: 'warning', text: '检测已超时' },
    { name: 'scan timeout keeps budget and last progress visible', status: 'TIMEOUT', message: 'ZAP 检测达到等待上限（1800 秒），最后进度 26%，检测未完成。可降低检测强度或调整等待时长后重试。', alert: 'warning', text: '等待上限（1800 秒），最后进度 26%', guidance: '可降低检测强度或调整等待时长后重试。' },
    { name: 'engine timeout keeps specific recovery advice', status: 'TIMEOUT', message: '等待 ZAP 引擎响应超时，检测未完成。请检查引擎运行状态后重试。', alert: 'warning', text: '等待 ZAP 引擎响应超时', guidance: '请检查引擎运行状态后重试。' },
    { name: 'cancelled result', status: 'CANCELLED', alert: 'warning', text: '已取消' },
    { name: 'missing status', alert: 'warning', text: '状态待核实' },
    { name: 'missing status with misleading completion text', message: '检测完成，未发现漏洞', alert: 'warning', text: '状态待核实' },
    { name: 'running status in final response', status: 'RUNNING', message: '检测进行中', alert: 'warning', text: '状态待核实' },
    { name: 'empty stream', events: [], alert: 'error', text: '没有返回有效结果' },
    { name: 'malformed terminal result', events: [{ type: 'complete', result: null }], alert: 'error', text: '没有返回有效结果' },
    { name: 'confirmed empty completion', status: 'COMPLETED', alert: 'success' },
    { name: 'findings only in final result', status: 'COMPLETED', hits: [hit], alert: 'warning' },
    { name: 'partial findings before error', events: [{ type: 'hit', hit }, { type: 'error', message: '流式检测中断' }], alert: 'error', text: '检测连接中断', partial: true },
    { name: 'partial findings before failed final response', events: [{ type: 'hit', hit }, { type: 'complete', result: { status: 'FAILED', hits: [], message: '工具执行失败' } }], alert: 'error', text: '工具执行失败', partial: true },
    { name: 'command output is not a negative probe', events: [{ type: 'status', message: '执行命令: sqlmap --batch -u http://fixture.test/?id=1' }, { type: 'complete', result: { status: 'FAILED', hits: [], message: '工具执行失败' } }], alert: 'error', text: '工具执行失败', log: true },
    { name: 'probe without a response is not a negative finding', events: [{ type: 'complete', result: { status: 'FAILED', hits: [], probes: [probe], message: '工具执行失败' } }], alert: 'error', text: '工具执行失败', probe: true },
  ];
  for (const engine of engineCases) {
    for (const test of cases) {
      scenario = test;
      await page.evaluate(() => window.clearMessages());
      await page.getByRole('button', { name: '安全探测' }).click();
      await page.getByRole('menuitem', { name: engine.menu, exact: true }).click();
      const targetDialog = page.getByRole('dialog', { name: '选择本次主动操作的授权目标', exact: true });
      if (engine.key === 'zap') {
        assert.equal(await targetDialog.getByRole('radio', { name: '标准', exact: true }).isChecked(), true);
        assert.match(await targetDialog.locator('.zap-strength-description').innerText(), /默认选项/);
      } else {
        assert.equal(await targetDialog.getByRole('radio', { name: '标准', exact: true }).count(), 0);
      }
      await targetDialog.getByRole('button', { name: '校验并执行', exact: true }).click();
      const dialog = page.getByRole('dialog', { name: engine.title, exact: true });
      await dialog.locator(`.el-alert--${test.alert}`).waitFor();
      if (test.text) assert.ok((await dialog.locator('.el-alert').innerText()).includes(test.text));
      if (test.guidance) assert.equal(await dialog.locator('.targeted-scan-guidance').first().innerText(), test.guidance);
      if (test.detail) {
        assert.doesNotMatch(await dialog.locator('.el-alert').innerText(), /REST|INTERNAL_ERROR|HTTP 500|ConnectException/);
        const details = dialog.locator('details').filter({ has: page.locator('summary', { hasText: '查看技术详情' }) });
        assert.equal(await details.getAttribute('open'), null);
        assert.equal(await details.locator('pre').isVisible(), false);
        assert.match(await dialog.locator('.targeted-scan-guidance').first().innerText(), /确认目标设备已开机/);
        await details.locator('summary').click();
        assert.equal(await details.locator('pre').innerText(), test.detail);
        if (engine.key === 'zap' && test.name === 'readable ZAP access failure') {
          await details.locator('summary').click();
          await page.screenshot({ path: path.resolve(root, '../.run/traffic-scan-readable-error.png') });
        }
      }
      if (test.log) {
        assert.equal(await dialog.getByText('sqlmap 命令', { exact: true }).count(), 0);
        assert.equal(await dialog.getByText('未命中', { exact: true }).count(), 0);
        const log = dialog.locator('details').filter({ has: page.locator('summary', { hasText: '查看执行日志' }) });
        await log.locator('summary').click();
        assert.match(await log.locator('pre').innerText(), /sqlmap --batch/);
      }
      if (test.probe) {
        const row = dialog.locator('.targeted-probes').getByRole('row').filter({ hasText: 'Fixture probe' });
        assert.match(await row.innerText(), /响应未确认/);
        assert.doesNotMatch(await row.innerText(), /未命中|GET/);
      }
      const hasHits = Boolean(test.hits?.length || test.partial);
      assert.equal(await dialog.getByText('Fixture finding', { exact: true }).count(), hasHits ? 1 : 0);
      if (test.status === 'COMPLETED' && !hasHits) {
        assert.match(await dialog.locator('.targeted-empty').innerText(), /本次检查已完成，未返回命中结果/);
      } else if (!hasHits) {
        assert.match(await dialog.locator('.targeted-empty').innerText(), /本次检测未完成，不能据此判断/);
      }
      if (test.status !== 'COMPLETED') {
        assert.equal(await dialog.locator('.el-alert--success').count(), 0);
        assert.equal(await dialog.getByText(/未返回命中结果|未发现明确的注入点/).count(), 0);
        assert.equal(await page.locator('.el-message--success').count(), 0);
      }
      assert.equal(scans.at(-1), `/traffic/packets/1/${engine.key}-scan/stream`);
      if (!test.httpError) {
        await dialog.getByRole('button', { name: '检测任务', exact: true }).click();
        await dialog.getByRole('button', { name: '安全发现', exact: true }).click();
        assert.deepEqual(await page.evaluate(() => window.recordNavigations.slice(-2)), ['/tasks?source=traffic&scanId=77', '/findings?source=traffic&scanId=77']);
      }
      await dialog.getByRole('button', { name: '关闭', exact: true }).click();
      await dialog.waitFor({ state: 'hidden' });
      console.log(`PASS ${engine.key}: ${test.name}`);
    }
  }
  assert.ok(zapRequests.every(request => request.strength === 'MEDIUM' && request.policy === 'Default Policy'));
  assert.equal(scans.length, engineCases.length * cases.length);
  for (const choice of [
    { label: '低强度', value: 'LOW', guidance: /请求较少.*可能漏掉/ },
    { label: '深入', value: 'HIGH', guidance: /耗时更长.*负载/ },
    { label: '标准', value: 'MEDIUM', guidance: /默认选项/ },
  ]) {
    scenario = { status: 'COMPLETED' };
    await page.evaluate(() => window.clearMessages());
    await page.getByRole('button', { name: '安全探测' }).click();
    await page.getByRole('menuitem', { name: 'ZAP 定向注入探测', exact: true }).click();
    const targetDialog = page.getByRole('dialog', { name: '选择本次主动操作的授权目标', exact: true });
    await targetDialog.getByText(choice.label, { exact: true }).click();
    assert.equal(await targetDialog.getByRole('radio', { name: choice.label, exact: true }).isChecked(), true);
    assert.match(await targetDialog.locator('.zap-strength-description').innerText(), choice.guidance);
    assert.match(await targetDialog.innerText(), /三档均使用默认检测策略/);
    if (choice.value === 'LOW') await page.screenshot({ path: path.resolve(root, '../.run/traffic-zap-strength-options.png'), animations: 'disabled' });
    await targetDialog.getByRole('button', { name: '校验并执行', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'OWASP ZAP 定向主动探测', exact: true });
    await dialog.locator('.el-alert--success').waitFor();
    assert.equal(zapRequests.at(-1).strength, choice.value);
    assert.equal(zapRequests.at(-1).policy, 'Default Policy');
    await dialog.getByRole('button', { name: '关闭', exact: true }).click();
    await dialog.waitFor({ state: 'hidden' });
    console.log(`PASS explicit ZAP strength: ${choice.label} -> ${choice.value}`);
  }
  scenario = { liveProgress: true };
  await page.evaluate(() => window.clearMessages());
  await page.getByRole('button', { name: '安全探测' }).click();
  await page.getByRole('menuitem', { name: 'ZAP 定向注入探测', exact: true }).click();
  await page.getByRole('dialog', { name: '选择本次主动操作的授权目标', exact: true }).getByRole('button', { name: '校验并执行', exact: true }).click();
  const progressDialog = page.getByRole('dialog', { name: 'OWASP ZAP 定向主动探测', exact: true });
  await progressDialog.locator('.el-alert--info').filter({ hasText: '进度 26%' }).waitFor();
  assert.match(await progressDialog.locator('.el-alert--info').innerText(), /已用 90 秒.*最多等待 1800 秒/);
  assert.match(await progressDialog.locator('.el-alert--info').innerText(), /当前检查尚未结束/);
  await page.getByRole('dialog', { name: '选择本次主动操作的授权目标', exact: true }).waitFor({ state: 'hidden' });
  await page.screenshot({ path: path.resolve(root, '../.run/traffic-zap-live-progress.png'), animations: 'disabled' });
  finishProgressStream();
  await progressDialog.locator('.el-alert--success').waitFor();
  await progressDialog.getByRole('button', { name: '关闭', exact: true }).click();
  await progressDialog.waitFor({ state: 'hidden' });
  console.log('PASS live ZAP progress keeps elapsed time and budget visible before terminal result');
  const scansBeforeNotifications = scans.length;
  await page.getByRole('button', { name: '模糊器', exact: true }).click();
  await page.locator('.fuzz-url-wrap input').fill('http://fixture.test/?id=§id§');
  for (const status of [undefined, 'FAILED', 'TIMEOUT', 'CANCELLED', 'COMPLETED']) {
    fuzzStatus = status;
    await page.evaluate(() => window.clearMessages());
    await page.getByRole('button', { name: '运行模糊测试', exact: true }).click();
    await page.getByRole('dialog', { name: '选择本次主动操作的授权目标', exact: true }).getByRole('button', { name: '校验并执行', exact: true }).click();
    const success = status === 'COMPLETED';
    await page.locator(success ? '.el-message--success' : '.el-message--warning').filter({ hasText: success ? '测试已返回' : '测试未全部完成' }).waitFor();
    if (!success) assert.equal(await page.locator('.el-message--success').count(), 0);
    assert.equal(await page.getByText('全部同基线', { exact: true }).count(), 0);
    await page.getByText(success ? '未返回可对比结果' : '检测未完成，尚无完整对比结论', { exact: true }).waitFor();
    console.log(`PASS fuzz summary: ${status || 'missing status'}`);
  }
  assert.equal(fuzzCalls.length, 5);
  await page.evaluate(() => window.notificationTestNavigate('/traffic?packetId=99&scanId=51'));
  const restored = page.getByRole('dialog', { name: 'sqlmap SQL 注入复核', exact: true });
  await restored.waitFor();
  await restored.getByText('Fixture finding', { exact: true }).waitFor();
  assert.match(await restored.innerText(), /超时|未完成/);
  await restored.getByRole('button', { name: '关闭', exact: true }).click();
  await page.evaluate(() => window.notificationTestNavigate('/traffic?packetId=99&scanId=52'));
  await page.getByText('Stored partial batch result', { exact: true }).waitFor();
  await page.getByText('未返回可对比结果', { exact: true }).waitFor();
  await page.waitForTimeout(2800);
  assert.equal(await page.locator('.traffic-row').filter({ hasText: 'stored.test' }).count(), 1);
  assert.equal(scans.length, scansBeforeNotifications, 'opening results must not rerun a scan');
  assert.equal(fuzzCalls.length, 5, 'opening batch results must not resend fuzz requests');
  console.log('PASS notification deep links restore stored scan and partial batch results across polling');

  assert.deepEqual(errors, []);
  console.log(`PASS all ${scans.length + fuzzCalls.length} isolated scan-result cases; no Vue/browser errors or live scans`);
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => { await browser?.close(); await server?.close(); });
