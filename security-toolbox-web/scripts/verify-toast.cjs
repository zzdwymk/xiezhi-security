const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../.run/toast-verify', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(out, { recursive: true });

const html = `<!doctype html><html lang="zh-CN" data-system-theme="light"><head><meta charset="utf-8">
<link rel="stylesheet" href="/node_modules/element-plus/dist/index.css">
<link rel="stylesheet" href="/src/desktop-v2.css">
<link rel="stylesheet" href="/src/unified-theme.css">
<style>
  html,body{height:100%;margin:0}
  .desktop-v2-app-frame{display:flex;flex-direction:column;height:100vh}
  .desktop-v2-native-titlebar{display:flex;align-items:center;gap:8px;height:38px;padding:0 12px;border-bottom:1px solid #ddd;background:#fff;-webkit-app-region:drag}
  .desktop-v2-shell{display:flex;flex:1;min-height:0}
  .desktop-v2-sidebar{width:260px;flex:0 0 260px;border-right:1px solid #e5e5e5;background:#fafafa}
  .desktop-v2-content{flex:1;min-width:0;overflow:auto}
  .workspace-list-page{padding:20px 24px 24px;margin:0!important;border:0!important;background:transparent!important;box-shadow:none!important;width:100%;box-sizing:border-box}
  .section-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin:0 0 20px!important}
  .section-head h3{margin:0!important;font-size:16px}
  .target-head-actions{display:flex;align-items:center;gap:12px}
  .list-search-input{width:300px}
</style></head>
<body>
<div class="desktop-v2-app-frame desktop-v2-native-frame">
  <header class="desktop-v2-native-titlebar"><span>獬豸授权安全测试平台</span></header>
  <div class="desktop-v2-shell" style="--sidebar-width:260px">
    <aside class="desktop-v2-sidebar"></aside>
    <main class="desktop-v2-content">
      <section class="workspace-list-page">
        <div class="section-head">
          <div><h3>目标</h3><p>仅保存已获授权的地址和允许检测的端口。</p></div>
          <div class="target-head-actions">
            <input class="list-search-input" placeholder="搜索名称 / 地址 / 类型 / 授权记录">
            <button class="el-button el-button--primary" type="button">新增目标</button>
          </div>
        </div>
        <div style="height:420px;border:1px solid #ddd"></div>
      </section>
    </main>
  </div>
</div>
<script src="/node_modules/vue/dist/vue.global.js"></script>
<script src="/node_modules/element-plus/dist/index.full.js"></script>
<script>
  const { ElMessage } = ElementPlus;
  document.querySelector('.el-button--primary').addEventListener('click', () => ElMessage.success('目标已更新'));
</script></body></html>`;

const http = require('node:http');
const url = require('node:url');

const mime = {
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.html': 'text/html',
};

const server = http.createServer((req, res) => {
  const p = url.parse(req.url).pathname;
  if (p === '/__toast') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(html);
    return;
  }
  const file = path.join(root, decodeURIComponent(p));
  if (!file.startsWith(root)) { res.writeHead(403); res.end(); return; }
  try {
    const data = fs.readFileSync(file);
    const ext = path.extname(file);
    res.setHeader('Content-Type', mime[ext] || 'application/octet-stream');
    res.end(data);
  } catch (e) { res.writeHead(404); res.end(); }
});

let browser;
(async () => {
  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  const port = server.address().port;
  browser = await chromium.launch({
    executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1610, height: 1000 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(`http://127.0.0.1:${port}/__toast`);
  await page.click('.el-button--primary');
  await page.waitForSelector('.el-message', { state: 'visible' });
  await page.waitForTimeout(400); // let Element Plus entrance animation finish

  const geo = await page.evaluate(() => {
    const rect = (n) => { const r = n.getBoundingClientRect(); return { x:r.x, y:r.y, right:r.right, bottom:r.bottom, w:r.width, h:r.height }; };
    const msg = document.querySelector('.el-message');
    const content = document.querySelector('.desktop-v2-content');
    const h3 = document.querySelector('.section-head h3');
    const cs = getComputedStyle(msg);
    return { message: rect(msg), content: rect(content), title: rect(h3), msgStyle: { top: msg.style.top, left: msg.style.left, right: msg.style.right }, computed: { top: cs.top, left: cs.left, right: cs.right, transform: cs.transform }, bodyHasFrame: document.body.querySelector('.desktop-v2-native-frame') !== null };
  });
  fs.writeFileSync(path.join(out, 'geo.json'), JSON.stringify(geo, null, 2));
  await page.screenshot({ path: path.join(out, 'toast.png'), animations: 'disabled' });

  assert.deepEqual(errors, [], 'no page errors');
  // 新位置：水平居中，top = 标题栏(38) + 48 = 86px，避开 section-head（约 y=58~79）
  assert.ok(geo.message.y >= 38 + 45, `toast top ${geo.message.y} should be below caption+48 (~86)`);
  assert.ok(geo.message.y <= 38 + 52, `toast top ${geo.message.y} should be around caption+48`);
  const center = (geo.message.x + geo.message.right) / 2;
  const contentCenter = (geo.content.x + geo.content.right) / 2;
  assert.ok(Math.abs(center - contentCenter) < 80, `toast center ${center} should align with content center ${contentCenter}`);
  // 不要盖住标题（至少留 2px 空隙）
  assert.ok(geo.message.y >= geo.title.bottom + 2, `toast top ${geo.message.y} should clear title bottom ${geo.title.bottom}`);
  console.log(JSON.stringify(geo, null, 2));
  console.log('PASS screenshot:', path.join(out, 'toast.png'));
})().catch((err) => { console.error(err); process.exitCode = 1; }).finally(async () => {
  await browser?.close();
  server.close();
});
