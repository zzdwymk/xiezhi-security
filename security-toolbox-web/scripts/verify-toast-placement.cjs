/*
 * Verification (one-off): ElMessage toast placement.
 *
 * Reproduces the desktop app frame — 38px native caption, 260px sidebar, the
 * real `.workspace-list-page > .section-head` header with a centered toolbar
 * search field and a primary button — then renders a real `ElMessage.success`
 * and asserts where it lands relative to the workspace and the page chrome.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../.run/toast-placement', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(out, { recursive: true });

const html = `<!doctype html><html lang="zh-CN" data-system-theme="light"><head><meta charset="utf-8">
<style>
  html,body{height:100%;margin:0}
  .desktop-v2-app-frame{display:flex;flex-direction:column;height:100vh}
  .desktop-v2-native-titlebar{display:flex;align-items:center;gap:8px;height:38px;padding:0 12px;border-bottom:1px solid #ddd;background:#fff;-webkit-app-region:drag}
  .desktop-v2-native-titlebar::after{content:"";flex:1}
  .desktop-v2-shell{display:flex;flex:1;min-height:0}
  .desktop-v2-sidebar{width:260px;flex:0 0 260px;border-right:1px solid #e5e5e5;background:#fafafa}
  .desktop-v2-content{flex:1;min-width:0;overflow:auto}
  .workspace-list-page{padding:20px 24px 24px;margin:0!important;border:0!important;background:transparent!important;box-shadow:none!important;width:100%;box-sizing:border-box}
  .section-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin:0 0 20px!important}
  .section-head h3{margin:0!important;font-size:16px}
  .section-head p{margin:0!important;font-size:13px}
  .target-head-actions{display:flex;align-items:center;gap:12px}
  .list-search-input{width:300px}
</style></head>
<body>
<div class="desktop-v2-app-frame desktop-v2-native-frame">
  <header class="desktop-v2-native-titlebar" aria-label="窗口标题栏"><span>獬豸授权安全测试平台</span></header>
  <div class="desktop-v2-shell" style="--sidebar-width:260px">
    <aside id="desktop-v2-sidebar" class="desktop-v2-sidebar"></aside>
    <main id="app" class="desktop-v2-content"></main>
  </div>
</div>
<script type="module">
import {createApp, h} from 'vue';
import ElementPlus, {ElMessage, ElConfigProvider} from 'element-plus';
import zhCn from 'element-plus/es/locale/lang/zh-cn';
import 'element-plus/dist/index.css';
import '/src/desktop-v2.css';
import '/src/unified-theme.css';
import '/src/fluent-design-2.css';
import '/src/fluent-design-3.css';

const Page = {
  setup() {
    return () => h('section', {class: 'panel targets-page workspace-list-page'}, [
      h('div', {class: 'section-head'}, [
        h('div', {}, [h('h3', {}, '目标'), h('p', {}, '仅保存已获授权的地址和允许检测的端口。')]),
        h('div', {class: 'target-head-actions'}, [
          h(ElInput ? 'input' : 'input', {class: 'list-search-input qa-search', placeholder: '搜索名称 / 地址 / 类型 / 授权记录'}),
          h('button', {class: 'el-button el-button--primary qa-primary', type: 'button'}, '新增目标'),
        ]),
      ]),
      h('div', {class: 'el-table qa-table', style: {height: '420px', border: '1px solid #ddd'}}),
    ]);
  },
};

const app = createApp({render: () => h(ElConfigProvider, {locale: zhCn}, {default: () => h(Page)})});
app.use(ElementPlus);
app.mount('#app');
window.__toast = () => ElMessage.success('目标已更新');
</script></body></html>`;

let server;
let browser;
(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({
    configFile: false,
    root,
    cacheDir: path.join(out, 'cache'),
    plugins: [vue(), {
      name: 'toast-fixture',
      configureServer(s) {
        s.middlewares.use(async (req, res, next) => {
          if (req.url !== '/__toast') return next();
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.end(await s.transformIndexHtml(req.url, html));
        });
      },
    }],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/dist/**', '**/desktop-release/**', '**/.run/**'] } },
    logLevel: 'error',
  });
  await server.listen();
  browser = await chromium.launch({
    executablePath: process.env.TOAST_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1610, height: 1000 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('http://127.0.0.1:' + server.httpServer.address().port + '/__toast');
  await page.waitForSelector('.qa-primary');
  await page.evaluate(() => window.__toast());
  const toast = page.locator('.el-message').last();
  await toast.waitFor({ state: 'visible' });

  const geometry = await page.evaluate(() => {
    const rect = (node) => {
      const r = node.getBoundingClientRect();
      return { x: r.x, y: r.y, right: r.right, bottom: r.bottom, width: r.width, height: r.height };
    };
    const message = document.querySelector('.el-message');
    const content = document.querySelector('.desktop-v2-content');
    const title = document.querySelector('.section-head h3');
    const primary = document.querySelector('.qa-primary');
    return {
      viewport: { width: innerWidth, height: innerHeight },
      message: rect(message),
      content: rect(content),
      title: rect(title),
      primary: rect(primary),
      messageClass: message.className,
      messageStyle: { top: getComputedStyle(message).top, right: getComputedStyle(message).right, left: getComputedStyle(message).left, transform: getComputedStyle(message).transform },
      gap: getComputedStyle(document.documentElement).getPropertyValue('--desktop-workspace-gap').trim(),
      titlebar: rect(document.querySelector('.desktop-v2-native-titlebar')),
    };
  });

  fs.writeFileSync(path.join(out, 'geometry.json'), JSON.stringify(geometry, null, 2));
  await page.screenshot({ path: path.join(out, 'toast-placement.png'), animations: 'disabled' });

  const { message, content, title, primary, titlebar } = geometry;
  assert.deepEqual(errors, [], 'no page errors');
  assert.ok(message.right <= content.right - 19, `toast right (${message.right}) must sit 20px inside the workspace right edge (${content.right})`);
  assert.ok(message.right > content.right - 40, `toast right (${message.right}) must stay near the workspace right edge (${content.right})`);
  assert.ok(message.y >= titlebar.bottom + 15, `toast top (${message.y}) must clear the caption + 20px (${titlebar.bottom + 20})`);
  assert.ok(message.x > title.x + title.width, `toast must not overlap the page title (title right ${title.x + title.width})`);
  assert.ok(message.y >= primary.y + primary.height || message.x > primary.x + primary.width || message.y + message.height <= primary.y,
    'toast must not cover the page primary action');
  console.log(JSON.stringify(geometry, null, 2));
  console.log('PASS toast placement; screenshot at ' + path.join(out, 'toast-placement.png'));
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
}).finally(async () => {
  await browser?.close();
  await server?.close();
});
