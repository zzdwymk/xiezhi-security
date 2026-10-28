// 只渲染「安全发现」页签列表（真实 el-table DOM + 真实 App 外壳结构 + 真实样式表），
// 验证空态下表格是否撑满页面卡片。整壳 App.vue 会启动 SSE/轮询，headless 下不稳定。
// 用法：node scripts/verify-findings-fill-mock.cjs
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '..', '.run', 'findings-fill-mock');
fs.mkdirSync(output, { recursive: true });

const html = `<!doctype html>
<html lang="zh-CN" data-system-theme="light" data-caption-mode="solid">
<head><meta charset="utf-8"><base href="/__fill/"><title>findings fill</title>
<style>html,body{margin:0;height:100%;overflow:hidden;background:#fafaf9}</style></head>
<body>
<div id="app" style="height:100vh">
  <div class="desktop-v2-shell desktop-v2-app-frame" style="display:flex;height:100%;min-height:0">
    <main class="desktop-v2-content">
      <section class="panel findings-page workspace-list-page findings-tabbed-page">
        <div class="section-head">
          <div><h3>安全发现</h3><p>统一管理全量授权目标的漏洞发现、安全基线风险与技术证据。</p></div>
          <div class="finding-head-actions section-head-actions">
            <button class="el-button">刷新</button><button class="el-button">扫描差异</button><button class="el-button">清空</button>
          </div>
        </div>
        <div class="findings-source-tabs"><div style="height:40px"></div><div style="height:1px;background:var(--app-border)"></div></div>
        <div class="findings-source-pane findings-list-plane">
          <div class="findings-filter-toolbar">
            <div class="finding-filter-cell"><div style="height:32px;border:1px solid var(--app-border);border-radius:4px"></div></div>
            <div class="finding-filter-cell"><div style="height:32px;border:1px solid var(--app-border);border-radius:4px"></div></div>
            <div class="finding-filter-cell"><div style="height:32px;border:1px solid var(--app-border);border-radius:4px"></div></div>
            <div class="finding-filter-cell"><div style="height:32px;border:1px solid var(--app-border);border-radius:4px"></div></div>
            <div class="finding-filter-row"><div style="height:32px;flex:1;border:1px solid var(--app-border);border-radius:4px"></div></div>
          </div>
          <div id="table-host"></div>
        </div>
      </section>
    </main>
  </div>
</div>
<script type="module">
  import 'element-plus/es/components/table/style/css';
  import 'element-plus/es/components/table-column/style/css';
  import { createApp, h } from 'vue';
  import { ElTable, ElTableColumn } from 'element-plus';
  const App = {
    render() {
      return h(ElTable, { data: [], class: 'traffic-records-table' }, {
        empty: () => h('div', { class: 'empty-state', style: 'display:flex;flex-direction:column;align-items:center;gap:8px' }, [
          h('strong', '暂无风险记录'),
          h('p', { style: 'margin:0' }, '任务产生的检查结果会显示在这里。'),
        ]),
        default: () => [
          h(ElTableColumn, { prop: 'title', label: '名称', minWidth: 150 }),
          h(ElTableColumn, { label: '等级', width: 75 }),
          h(ElTableColumn, { label: '工具', minWidth: 110 }),
          h(ElTableColumn, { prop: 'targetId', label: '目标', width: 65 }),
          h(ElTableColumn, { label: '发现时间', minWidth: 140 }),
          h(ElTableColumn, { label: '状态', width: 115 }),
          h(ElTableColumn, { label: '操作', minWidth: 288 }),
        ],
      });
    },
  };
  createApp(App).mount('#table-host');
</script>
</body></html>`;

const PROBE = `(() => {
  const box = (el) => { if (!el) return null; const r = el.getBoundingClientRect(); return { y: Math.round(r.y), bottom: Math.round(r.bottom), h: Math.round(r.height) }; };
  const cs = (el) => (el ? getComputedStyle(el) : null);
  const page = document.querySelector('.findings-page');
  const table = document.querySelector('.findings-list-plane .el-table');
  const content = document.querySelector('.desktop-v2-content');
  return {
    content: box(content),
    page: { ...box(page), minHeight: cs(page).minHeight, padding: cs(page).padding },
    table: { ...box(table), flex: cs(table).flex, minHeight: cs(table).minHeight, radius: cs(table).borderRadius, border: cs(table).borderTopWidth },
    emptyBlock: box(document.querySelector('.findings-list-plane .el-table__empty-block')),
    gapBelowTable: Math.round(page.getBoundingClientRect().bottom - table.getBoundingClientRect().bottom),
  };
})()`;

(async () => {
  const { createServer } = await import('vite');
  const Components = (await import('unplugin-vue-components/vite')).default;
  const { ElementPlusResolver } = await import('unplugin-vue-components/resolvers');
  const server = await createServer({
    configFile: false,
    root,
    cacheDir: path.join(output, 'cache'),
    optimizeDeps: { include: ['vue', 'element-plus'], noDiscovery: true },
    plugins: [
      Components({ dts: false, resolvers: [ElementPlusResolver({ importStyle: 'css' })] }),
      {
        name: 'fill-fixture',
        configureServer(s) {
          s.middlewares.use(async (req, res, next) => {
            if (!req.url.startsWith('/__fill')) return next();
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.end(await s.transformIndexHtml(req.url, html));
          });
        },
      },
    ],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: null },
    logLevel: 'error',
  });
  await server.listen();
  const browser = await chromium.launch({
    executablePath:
      process.env.TRAFFIC_TEST_BROWSER ||
      'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  page.setDefaultTimeout(30000);
  const port = server.httpServer.address().port;
  let failed = false;
  for (const height of [1000, 1294]) {
    await page.setViewportSize({ width: 1440, height });
    await page.goto(`http://127.0.0.1:${port}/__fill/page.html`, { waitUntil: 'load' });
    await page.waitForSelector('.findings-list-plane .el-table__empty-block', { timeout: 30000 });
    await page.waitForTimeout(400);
    const m = await page.evaluate(PROBE);
    console.log(`\n===== 1440x${height} 空态 =====`);
    console.log(JSON.stringify(m, null, 1));
    if (!(m.gapBelowTable >= 0 && m.gapBelowTable <= 30)) {
      failed = true;
      console.log(`!! 未撑满：表格底边距卡片底边 ${m.gapBelowTable}px`);
    }
    await page.screenshot({ path: path.join(output, `fill-${height}.png`) });
  }
  console.log(`\n结果：${failed ? 'FAIL' : 'PASS'}`);
  await browser.close();
  await server.close();
  if (failed) process.exitCode = 1;
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
