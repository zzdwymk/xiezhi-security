// Measures the exact gap between the filter toolbar and the table, plus the table's
// empty-block height, at the same window size as the desktop screenshot.
// Also dumps every rule that could add/remove that gap.
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '..', '.run', 'findings-task-parity');
fs.mkdirSync(output, { recursive: true });

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

const PROBE = `(() => {
  const bar = document.querySelector('.findings-filter-toolbar');
  const pane = document.querySelector('.findings-source-pane');
  const table = pane && pane.querySelector('.el-table');
  const emptyBlock = table && table.querySelector('.el-table__empty-block');
  const ths = table ? [...table.querySelectorAll('th.el-table__cell')] : [];
  const rows = table ? table.querySelectorAll('tbody tr.el-table__row').length : 0;
  const rect = (el) => { if (!el) return null; const r = el.getBoundingClientRect(); return { top: Math.round(r.top), bottom: Math.round(r.bottom), left: Math.round(r.left), right: Math.round(r.right), h: Math.round(r.height), w: Math.round(r.width) }; };
  const tag = bar && bar.querySelector('.finding-task-filter-tag');
  const clear = bar && bar.querySelector('.finding-filter-clear');
  const sort = bar && bar.querySelector('.finding-filter-cell--sort');
  const search = bar && bar.querySelector('.finding-filter-cell--search');
  return {
    toolbar: rect(bar),
    table: rect(table),
    gapToolbarToTable: bar && table ? Math.round(table.getBoundingClientRect().top - bar.getBoundingClientRect().bottom) : null,
    paneGap: pane ? getComputedStyle(pane).gap : null,
    barRows: bar ? new Set([...bar.children].map(c => Math.round(c.getBoundingClientRect().top))).size : null,
    barH: bar ? Math.round(bar.getBoundingClientRect().height) : null,
    barKids: bar ? [...bar.children].map(c => ({ cls: String(c.className).split(' ')[0], top: Math.round(c.getBoundingClientRect().top), h: Math.round(c.getBoundingClientRect().height), left: Math.round(c.getBoundingClientRect().left), w: Math.round(c.getBoundingClientRect().width) })) : [],
    rowKids: (() => { const r = bar && bar.querySelector('.finding-filter-row'); return r ? [...r.children].map(c => ({ cls: String(c.className).split(' ').slice(-1)[0], top: Math.round(c.getBoundingClientRect().top), h: Math.round(c.getBoundingClientRect().height), left: Math.round(c.getBoundingClientRect().left), w: Math.round(c.getBoundingClientRect().width) })) : []; })(),
    rowH: (() => { const r = bar && bar.querySelector('.finding-filter-row'); return r ? Math.round(r.getBoundingClientRect().height) : null; })(),
    barCols: bar ? getComputedStyle(bar).gridTemplateColumns : null,
    tag: rect(tag),
    clear: rect(clear),
    sort: rect(sort),
    search: rect(search),
    tagOverlapsClear: tag && clear ? !(tag.getBoundingClientRect().right <= clear.getBoundingClientRect().left || clear.getBoundingClientRect().right <= tag.getBoundingClientRect().left) : null,
    tableFlex: table ? getComputedStyle(table).flex : null,
    tableMinHeight: table ? getComputedStyle(table).minHeight : null,
    headerRow: ths.length ? { count: ths.length, h: Math.round(ths[0].getBoundingClientRect().height), labels: ths.map(t => t.textContent.trim()) } : null,
    dataRowCount: rows,
    emptyBlock: emptyBlock ? { h: Math.round(emptyBlock.getBoundingClientRect().height), pad: getComputedStyle(emptyBlock).padding } : null,
    emptyState: (() => { const es = table && table.querySelector('.empty-state'); return es ? { h: Math.round(es.getBoundingClientRect().height), w: Math.round(es.getBoundingClientRect().width) } : null; })(),
  };
})()`;

const EMPTY_MODE = process.env.PARITY_EMPTY === '1';

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
  const withTaskFilter = process.env.PARITY_TASK_FILTER === '1';
  await page.goto(`http://127.0.0.1:${port}/findings${withTaskFilter ? '?taskId=1257' : ''}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);
  await page.evaluate(() => document.documentElement.setAttribute('data-system-theme', 'light'));
  await page.waitForTimeout(600);
  for (const width of [2070, 1440, 1280]) {
    await page.setViewportSize({ width, height: 1293 });
    await page.waitForTimeout(700);
    const m = await page.evaluate(PROBE);
    console.log(`\n===== mode: ${EMPTY_MODE ? 'EMPTY (no records)' : 'WITH DATA'} @ ${width}px =====`);
    console.log(JSON.stringify(m, null, 1));
    await page.screenshot({ path: path.join(output, `findings-gap-${EMPTY_MODE ? 'empty' : 'data'}-${width}.png`), clip: { x: 0, y: 0, width, height: 620 } });
  }
  await browser.close();
  await server.close();
})().catch((e) => { console.error(e); process.exitCode = 1; });
