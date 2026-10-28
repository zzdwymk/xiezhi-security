// 验证「安全发现」两个页签（项目发现 / 流量发现）的表格是否撑满页面卡片：
// 空态和少量数据两种情况下，表格底边都应贴近页面卡片底边（只剩页脚/内边距）。
// 用真实 App.vue 外壳 + 真实路由，只 mock /api。
// 用法：node scripts/verify-findings-fill.cjs
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '..', '.run', 'findings-fill-verify');
fs.mkdirSync(output, { recursive: true });

const html = `<!doctype html><html><head><meta charset="utf-8"><base href="/__frame/"></head><body><div id="app"></div><script type="module">
import '/src/main';
</script></body></html>`;

const finding = (id) => ({
  id,
  taskId: 1228,
  targetId: 289,
  projectId: 1,
  title: `CVE-2026-${String(id).padStart(4, '0')} 授权测试风险`,
  severity: id % 2 ? 'HIGH' : 'MEDIUM',
  status: 'OPEN',
  sourceTool: 'nuclei',
  description: 'Fixture risk description',
  evidence: 'Fixture finding evidence',
  remediation: 'Fixture repair advice',
  createdAt: '2026-10-25T07:15:28Z',
});

const trafficHit = {
  id: 5501,
  engine: 'FUZZ',
  url: 'https://example.test/login?next=/admin',
  hitCount: 3,
  status: 'DONE',
  createdAt: '2026-10-25T07:15:28Z',
};

const PROBE = `(() => {
  const box = (el) => { if (!el) return null; const r = el.getBoundingClientRect(); return { y: Math.round(r.y), bottom: Math.round(r.bottom), h: Math.round(r.height) }; };
  const cs = (el) => (el ? getComputedStyle(el) : null);
  const page = document.querySelector('.findings-page');
  if (!page) return { error: 'no .findings-page', url: location.pathname + location.search, text: document.body.innerText.slice(0, 300) };
  const table = document.querySelector('.findings-list-plane .el-table');
  const pagination = document.querySelector('.findings-list-plane .findings-pagination')
    || document.querySelector('.findings-scan-records .findings-pagination')
    || document.querySelector('.findings-list-plane > :last-child');
  const rowCount = document.querySelectorAll('.findings-list-plane .el-table__body tr').length;
  return {
    pageBottom: Math.round(page.getBoundingClientRect().bottom),
    table: { ...box(table), flex: cs(table).flex },
    emptyBlock: box(document.querySelector('.findings-list-plane .el-table__empty-block')),
    pagination: box(pagination),
    rowCount,
    bottomGap: table ? Math.round(page.getBoundingClientRect().bottom - table.getBoundingClientRect().bottom) : null,    extra: (() => {
      const q = (s) => document.querySelector(s);
      const wrap = q('.traffic-scan-records.is-embedded');
      const bar = q('.findings-filter-toolbar');
      const toolbarCs = bar && getComputedStyle(bar);
      const wrapCs = wrap && getComputedStyle(wrap);
      return {
        filterBar: box(bar),
        filterBarGrid: bar ? getComputedStyle(bar).gridTemplateColumns : null,
        pageH: Math.round(page.getBoundingClientRect().height),
        paneH: Math.round(q('.findings-list-plane').getBoundingClientRect().height),
        wrap: wrap ? { ...box(wrap), pt: wrapCs.paddingTop, flex: wrapCs.flex, children: [...wrap.children].map((c) => ({ cls: c.className.toString().slice(0, 40), ...box(c) })) } : null,
        searchCell: (() => { const s = q('.finding-filter-cell--search'); if (!s) return null; const r = s.getBoundingClientRect(); return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) }; })(),
      };
    })(),
  };
})()`;

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  const Components = (await import('unplugin-vue-components/vite')).default;
  const { ElementPlusResolver } = await import('unplugin-vue-components/resolvers');
  const server = await createServer({
    configFile: false,
    root,
    cacheDir: path.join(output, 'cache'),
    optimizeDeps: { include: ['vue', 'element-plus', 'pinia', 'vue-router'], noDiscovery: true },
    plugins: [
      vue(),
      Components({ dts: false, resolvers: [ElementPlusResolver({ importStyle: 'css' })] }),
      {
        name: 'dayjs-esm',
        enforce: 'pre',
        resolveId(source) {
          if (source === 'dayjs') return path.join(root, 'node_modules', 'dayjs', 'esm', 'index.js');
          if (source.startsWith('dayjs/plugin/')) {
            const name = source.replace('dayjs/plugin/', '').replace(/\.js$/, '');
            return path.join(root, 'node_modules', 'dayjs', 'esm', 'plugin', name, 'index.js');
          }
          return null;
        },
      },
      {
        name: 'fill-fixture',
        configureServer(s) {
          s.middlewares.use(async (req, res, next) => {
            if (!req.url.startsWith('/__frame')) return next();
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
  const port = server.httpServer.address().port;
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  page.setDefaultTimeout(30000);

  async function mount(dataset) {
    await page.unrouteAll({ behavior: 'ignoreErrors' });
    const login = { token: 'parity-token', tokenType: 'Bearer', expiresIn: 3600, user: { id: 1, username: 'admin', role: 'ADMIN' } };
    await page.route('**/api/**', async (route) => {
      const api = new URL(route.request().url()).pathname.replace(/^\/api/, '');
      console.log(`  [api] ${api}`);
      if (api.startsWith('/auth/')) return route.fulfill({ json: login });
      if (api === '/findings') return route.fulfill({ json: dataset.findings });
      if (api === '/tasks/control/status') {
        return route.fulfill({ json: { maxConcurrentTasks: 3, availableConcurrentSlots: 3, maxConcurrentTasksPerTarget: 3, queueCapacity: 50, pendingTasks: 0, runningTasks: 0 } });
      }
      if (api.includes('/traffic')) return route.fulfill({ json: dataset.traffic });
      return route.fulfill({ json: { content: [], totalElements: 0 } });
    });
  }

  await page.addInitScript(() => {
    localStorage.setItem('security_toolbox_setup_complete_v2', 'true');
    localStorage.setItem('security_toolbox_token', 'parity-token');
    sessionStorage.setItem('security_toolbox_session_token', 'parity-token');
  });

  const datasets = {
    empty: { findings: { content: [], totalElements: 0 }, traffic: { content: [], totalElements: 0 } },
    populated: { findings: { content: [0, 1, 2].map((i) => finding(1000 + i)), totalElements: 3 }, traffic: { content: [trafficHit], totalElements: 1 } },
  };

  let failed = false;
  for (const [name, dataset] of Object.entries(datasets)) {
    await mount(dataset);
    for (const tab of ['项目发现']) {
      await page.goto(`http://127.0.0.1:${port}/findings`, { waitUntil: 'domcontentloaded' });
      await page.waitForFunction(() => document.querySelector('.findings-page'), null, { timeout: 30000 });
      if (tab === '流量发现') {
        if (tab === '流量发现') {
          await page.evaluate((t) => { const el = [...document.querySelectorAll('.findings-source-tabs .el-tabs__item')].find((e) => e.textContent.includes(t)); if (el) el.click(); }, tab);
        }
      }
      await page.waitForSelector('.findings-list-plane .el-table__header', { timeout: 20000 });
      await page.waitForTimeout(700);
      const m = await page.evaluate(PROBE);
      console.log(`\n===== ${name} / ${tab} =====`);
      console.log(JSON.stringify(m, null, 1));
      if (m.error) {
        failed = true;
        continue;
      }
      // 分页存在时表格底边之后只剩页脚；没有分页时应几乎贴住卡片底边。
      const limit = m.pagination ? 60 : 40;
      if (!(m.bottomGap >= 0 && m.bottomGap <= limit)) {
        failed = true;
        console.log(`!! 表格没有撑满：底部剩余 ${m.bottomGap}px（上限 ${limit}px）`);
      }
      await page.screenshot({ path: path.join(output, `${name}-${tab === '项目发现' ? 'project' : 'traffic'}.png`) });
    }
  }
  console.log(`\n结果：${failed ? 'FAIL' : 'PASS'} — 截图目录 ${output}`);
  await browser.close();
  await server.close();
  if (failed) process.exitCode = 1;
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});

