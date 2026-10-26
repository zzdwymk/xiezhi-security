// Measures the 流量发现 tab (TrafficScanRecords embedded in Findings.vue) and the
// 项目发现 tab side by side, so their spacing / table height / empty state can be
// compared at the same viewport. Set PARITY_EMPTY=1 for the no-records case.
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '..', '.run', 'findings-task-parity');
fs.mkdirSync(output, { recursive: true });
const EMPTY_MODE = process.env.PARITY_EMPTY === '1';

const html = `<!doctype html><html><head><meta charset="utf-8"><base href="/__parity/"></head><body><div id="app"></div><script type="module">
import '/src/main';
</script></body></html>`;

const finding = (id) => ({
  id, taskId: 1228, targetId: 289, projectId: 1,
  title: `CVE-2026-${String(id).padStart(4, '0')} 授权测试风险`,
  severity: id % 2 ? 'HIGH' : 'MEDIUM', status: 'OPEN', sourceTool: 'nuclei',
  description: 'Fixture risk description', evidence: 'Fixture finding evidence',
  remediation: 'Fixture repair advice', createdAt: '2026-10-25T07:15:28Z',
});
const trafficRecord = (id) => ({
  id, engine: id % 2 ? 'XRAY' : 'ZAP', status: 'SUCCESS',
  url: `http://127.0.0.1:8080/authorized/target/${id}`, host: '127.0.0.1',
  hitCount: id % 2 ? 3 : 0, createdAt: '2026-10-25T07:15:28Z',
});

const PROBE = `(() => {
  const pane = document.querySelector('.findings-source-pane');
  const table = pane && pane.querySelector('.el-table');
  const emptyBlock = table && table.querySelector('.el-table__empty-block');
  const emptyWrap = table && table.querySelector('.traffic-empty-container');
  const ths = table ? [...table.querySelectorAll('th.el-table__cell')] : [];
  const rows = table ? table.querySelectorAll('tbody tr.el-table__row').length : 0;
  const rect = (el) => { if (!el) return null; const r = el.getBoundingClientRect(); return { top: Math.round(r.top), bottom: Math.round(r.bottom), h: Math.round(r.height), w: Math.round(r.width) }; };
  const paneTop = pane ? pane.getBoundingClientRect().top : null;
  return {
    tabsBottom: (() => { const t = document.querySelector('.findings-source-hiba, .findings-source-tabs'); return t ? Math.round(t.getBoundingClientRect().bottom) : null; })(),
    paneTop: paneTop ? Math.round(paneTop) : null,
    paneGap: pane ? getComputedStyle(pane).gap : null,
    firstChild: pane && pane.firstElementChild ? pane.firstElementChild.className : null,
    table: rect(table),
    tableTopGapFromPane: table && paneTop ? Math.round(table.getBoundingClientRect().top - paneTop) : null,
    tableFlex: table ? getComputedStyle(table).flex : null,
    tableMinHeight: table ? getComputedStyle(table).minHeight : null,
    tableBorder: table ? getComputedStyle(table).borderTopWidth : null,
    tableRadius: table ? getComputedStyle(table).borderRadius : null,
    headerRow: ths.length ? { count: ths.length, h: Math.round(ths[0].getBoundingClientRect().height), labels: ths.map(t => t.textContent.trim()) } : null,
    cellPad: (() => { const c = table && table.querySelector('th.el-table__cell .cell'); return c ? getComputedStyle(c).padding : null; })(),
    dataRowCount: rows,
    rowH: rows ? Math.round(table.querySelector('tbody tr.el-table__row').getBoundingClientRect().height) : null,
    emptyBlock: rect(emptyBlock),
    emptyWrap: rect(emptyWrap),
    emptyState: (() => { const es = table && table.querySelector('.empty-state'); return es ? rect(es) : null; })(),
    wrapperClass: (() => { const w = document.querySelector('.traffic-scan-records'); return w ? w.className : null; })(),
  };
})()`;

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  const Components = (await import('unplugin-vue-components/vite')).default;
  const { ElementPlusResolver } = await import('unplugin-vue-components/resolvers');
  const server = await createServer({
    configFile: false, root,
    cacheDir: path.join(output, 'cache'),
    optimizeDeps: { include: ['vue', 'element-plus', 'pinia', 'vue-router'], noDiscovery: true },
    plugins: [
      vue(),
      Components({ dts: false, resolvers: [ElementPlusResolver({ importStyle: 'css' })] }),
      { name: 'dayjs-esm', enforce: 'pre', resolveId(source) {
          if (source === 'dayjs') return path.join(root, 'node_modules', 'dayjs', 'esm', 'index.js');
          if (source.startsWith('dayjs/plugin/')) { const n = source.replace('dayjs/plugin/', '').replace(/\.js$/, ''); return path.join(root, 'node_modules', 'dayjs', 'esm', 'plugin', n, 'index.js'); }
          return null;
      } },
      { name: 'parity-fixture', configureServer(s) { s.middlewares.use(async (req, res, next) => {
          if (!req.url.startsWith('/__parity')) return next();
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.end(await s.transformIndexHtml(req.url, html));
      }); } },
    ],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: null },
    logLevel: 'error',
  });
  await server.listen();
  const browser = await chromium.launch({ executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 2070, height: 1293 } });
  page.setDefaultTimeout(30000);
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const api = url.pathname.replace(/^\/api/, '');
    if (api === '/findings') {
      const data = EMPTY_MODE ? [] : Array.from({ length: 6 }, (_, i) => finding(1000 + i));
      return route.fulfill({ json: { content: data, totalElements: data.length } });
    }
    if (api.startsWith('/traffic/scans')) {
      const data = EMPTY_MODE ? [] : Array.from({ length: 6 }, (_, i) => trafficRecord(900 + i));
      return route.fulfill({ json: { content: data, totalElements: data.length, totalPages: 1, number: 0, size: 10 } });
    }
    if (api === '/auth/me') return route.fulfill({ json: { id: 1, username: 'admin', role: 'ADMIN' } });
    if (api.startsWith('/auth/')) return route.fulfill({ json: { token: 't', tokenType: 'Bearer', expiresIn: 3600, user: { id: 1, username: 'admin', role: 'ADMIN' } } });
    if (api === '/tasks/control/status') return route.fulfill({ json: { maxConcurrentTasks: 3, availableConcurrentSlots: 3, maxConcurrentTasksPerTarget: 3, queueCapacity: 50, pendingTasks: 0, runningTasks: 0 } });
    return route.fulfill({ json: [] });
  });
  await page.addInitScript(() => {
    localStorage.setItem('security_toolbox_setup_complete_v2', 'true');
    localStorage.setItem('security_toolbox_token', 'parity-token');
    sessionStorage.setItem('security_toolbox_session_token', 'parity-token');
  });
  const port = server.httpServer.address().port;

  for (const [label, switchToTraffic] of [['project', false], ['traffic', true]]) {
    // recordSource is derived from route.query.source; under the hash-less dev
    // server the query must land on the route itself, so navigate then assert.
    const url = switchToTraffic ? `http://127.0.0.1:${port}/findings?source=traffic` : `http://127.0.0.1:${port}/findings`;
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('.findings-page', { timeout: 30000 });
    await page.waitForTimeout(2200);
    if (switchToTraffic) {
      const isTraffic = await page.locator('.traffic-scan-records').count();
      if (!isTraffic) {
        console.warn(`[warn] traffic tab did not activate via URL; got ${await page.evaluate(() => location.href)}`);
      }
    }
    await page.evaluate(() => document.documentElement.setAttribute('data-system-theme', 'light'));
    for (const width of [2070, 1440, 1280]) {
      await page.setViewportSize({ width, height: 1293 });
      await page.waitForTimeout(700);
      const m = await page.evaluate(PROBE);
      console.log(`\n===== ${label} / ${EMPTY_MODE ? 'EMPTY' : 'WITH DATA'} @ ${width}px =====`);
      console.log(JSON.stringify(m, null, 1));
      await page.screenshot({ path: path.join(output, `tab-${label}-${EMPTY_MODE ? 'empty' : 'data'}-${width}.png`), clip: { x: 0, y: 0, width, height: 620 } });
    }
  }
  await browser.close();
  await server.close();
})().catch((e) => { console.error(e); process.exitCode = 1; });
