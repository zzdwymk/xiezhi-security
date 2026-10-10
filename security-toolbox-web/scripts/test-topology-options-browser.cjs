// Render the actual topology and Element Plus in an isolated headless browser.
// Fixed props only; every API request and non-fixture HTTP request is blocked.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../.run/topology-options', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(out, { recursive: true });
const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
html,body{margin:0!important;height:100%!important}#app{padding:24px!important;height:100vh!important;box-sizing:border-box}.asset-topology-container{height:calc(100vh - 48px)!important}
</style></head><body><div id="app"></div><script type="module">
import {createApp} from 'vue';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';
import '/src/desktop-v2.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';import '/src/motion.css';
import AssetTopology from '/src/components/AssetTopology.vue';
createApp(AssetTopology,{projectId:1,hubLabel:'隔离拓扑项目',assets:[
{id:1,projectId:1,targetId:1,url:'https://fixture.example.test/',server:'Fixture'},
{id:2,projectId:1,targetId:1,url:'https://fixture.example.test/path',server:'Fixture'},
{id:3,projectId:1,targetId:2,url:'http://second.example.test/',server:'Fixture'}
]}).use(ElementPlus).mount('#app');
</script></body></html>`;
let server, browser, page;
const results = [], errors = [], unexpected = [];
async function check(name, fn) {
  const detail = await fn();
  results.push({ name, status: 'PASS', detail });
  console.log('PASS ' + name);
}
async function waitOpen(open) {
  await page.locator('.view-options').waitFor({ state: open ? 'visible' : 'hidden', timeout: 3000 });
}
async function outsideClick() {
  await page.locator('.topology-canvas-wrap').click({ position: { x: 20, y: 20 } });
  await waitOpen(false);
}
async function optionsScreenshot(name) {
  await page.screenshot({ path: path.join(out, name + '.png'), fullPage: true });
}
async function setCheckbox(name, checked) {
  const control = page.getByRole('checkbox', { name, exact: true });
  if (await control.isChecked() !== checked) {
    // Element Plus hides its native input; the visible label is the user target.
    await page.locator('.view-options .el-checkbox').filter({ hasText: name }).click();
  }
  assert.equal(await control.isChecked(), checked);
}
(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.join(out, 'cache'),
    plugins: [vue(), { name: 'topology-options-fixture', configureServer(s) {
      s.middlewares.use(async (req, res, next) => {
        if (req.url !== '/__topology-options') return next();
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(await s.transformIndexHtml(req.url, html));
      });
    } }], server: { host: '127.0.0.1', port: 0, hmr: false,
      watch: { ignored: ['**/desktop-release/**', '**/dist/**'] } }, logLevel: 'error' });
  await server.listen();
  const origin = 'http://127.0.0.1:' + server.httpServer.address().port;
  browser = await chromium.launch({ executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  page.setDefaultTimeout(5000);
  page.on('pageerror', e => errors.push(e.message));
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.origin !== origin || url.pathname.startsWith('/api/')) {
      unexpected.push(url.href);
      return route.abort();
    }
    return route.continue();
  });
  await page.goto(origin + '/__topology-options', { timeout: 30000 });
  await page.locator('.node-card-group').first().waitFor();
  const button = page.getByRole('button', { name: '视图选项', exact: true });
  await check('click opens view options and another click closes it', async () => {
    await button.click();
    await waitOpen(true);
    await optionsScreenshot('options-open');
    await button.click();
    await waitOpen(false);
  });
  await check('click outside closes view options', async () => {
    await button.click();
    await waitOpen(true);
    await outsideClick();
  });
  await check('minimap and connection animation controls update the real canvas', async () => {
    await button.click();
    await waitOpen(true);
    const minimap = page.getByRole('checkbox', { name: '显示缩略图', exact: true });
    const animation = page.getByRole('checkbox', { name: '连接动画', exact: true });
    assert.equal(await minimap.isChecked(), false);
    assert.equal(await animation.isChecked(), false);
    await setCheckbox('显示缩略图', true);
    await page.locator('.topology-minimap').waitFor({ state: 'visible' });
    await setCheckbox('连接动画', true);
    await page.locator('.edge-flow-line').first().waitFor({ state: 'visible' });
    await waitOpen(true);
    await optionsScreenshot('options-enabled');
    await setCheckbox('显示缩略图', false);
    await page.locator('.topology-minimap').waitFor({ state: 'hidden' });
    await setCheckbox('连接动画', false);
    assert.equal(await page.locator('.edge-flow-line').count(), 0);
    const prefs = await page.evaluate(() => JSON.parse(localStorage.getItem('topology.globalPrefs.v1')));
    assert.equal(prefs.showMinimap, false);
    assert.equal(prefs.enableFlowAnim, false);
    await outsideClick();
  });
  await check('keyboard Enter and Space can open and close view options', async () => {
    for (const key of ['Enter', 'Space']) {
      await button.focus();
      await button.press(key);
      await waitOpen(true);
      await button.press(key);
      await waitOpen(false);
    }
  });
  await check('native fullscreen keeps options visible and interactive', async () => {
    await page.getByRole('button', { name: '全屏模式', exact: true }).click();
    await page.waitForFunction(() => document.fullscreenElement?.classList.contains('asset-topology-container'));
    await button.click();
    await waitOpen(true);
    assert.equal(await page.locator('.view-options').evaluate(el => document.fullscreenElement.contains(el)), true);
    await setCheckbox('显示缩略图', true);
    await page.locator('.topology-minimap').waitFor({ state: 'visible' });
    await optionsScreenshot('options-fullscreen');
    await outsideClick();
    await page.getByRole('button', { name: '退出全屏', exact: true }).click();
    await page.waitForFunction(() => !document.fullscreenElement);
    await button.click();
    await waitOpen(true);
    await outsideClick();
  });
  assert.deepEqual(errors, []);
  assert.deepEqual(unexpected, []);
  console.log('EVIDENCE ' + out);
})().catch(async error => {
  results.push({ status: 'FAIL', error: error.stack });
  if (page) await optionsScreenshot('failure').catch(() => {});
  console.error(error);
  process.exitCode = 1;
}).finally(async () => {
  fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify({ scope: 'actual AssetTopology.vue + Element Plus, isolated headless Edge, fixed props, blocked APIs', results, errors, unexpected }, null, 2));
  await browser?.close();
  await server?.close();
});
