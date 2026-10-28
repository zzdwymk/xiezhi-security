// 验证「安全发现」两个页签（项目发现 / 流量发现）的表格是否都有完整外框。
// 用真实 App.vue 外壳 + 真实路由渲染，只 mock /api。
// 用法：node scripts/verify-findings-table-frame.cjs
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '..', '.run', 'findings-table-frame');
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

// 采集表格外框的盒模型：四边 border-width / color、圆角、背景、相对页面卡片的位置。
const PROBE = `(() => {
  const page = document.querySelector('.findings-page');
  const table = document.querySelector('.findings-list-plane .el-table');
  if (!table) return { error: 'no table' };
  const cs = getComputedStyle(table);
  const r = table.getBoundingClientRect();
  const pr = page.getBoundingClientRect();
  const px = (v) => Math.round(parseFloat(v) * 10) / 10;
  return {
    table: { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) },
    page: { x: Math.round(pr.x), y: Math.round(pr.y), w: Math.round(pr.width), h: Math.round(pr.height) },
    border: {
      top: px(cs.borderTopWidth), right: px(cs.borderRightWidth),
      bottom: px(cs.borderBottomWidth), left: px(cs.borderLeftWidth),
      color: cs.borderTopColor,
    },
    radius: cs.borderRadius,
    background: cs.backgroundColor,
    toolbar: (() => {
      const bar = document.querySelector('.findings-filter-toolbar');
      if (!bar) return null;
      const b = bar.getBoundingClientRect();
      const bcs = getComputedStyle(bar);
      return { x: Math.round(b.x), w: Math.round(b.width), border: bcs.borderTopWidth, color: bcs.borderTopColor };
    })(),
    rowHeight: (() => {
      const td = document.querySelector('.findings-list-plane .el-table__body td.el-table__cell');
      return td ? Math.round(td.getBoundingClientRect().height) : null;
    })(),
    headerHeight: (() => {
      const th = document.querySelector('.findings-list-plane .el-table__header th.el-table__cell');
      return th ? Math.round(th.getBoundingClientRect().height) : null;
    })(),
    tabBar: (() => {
      const bar = document.querySelector('.findings-source-tabs');
      const active = document.querySelector('.findings-source-tabs .el-tabs__item.is-active');
      return { barBottom: bar ? Math.round(bar.getBoundingClientRect().bottom) : null, active: active ? active.textContent.trim() : null };
    })(),
    emptyBlock: (() => {
      const e = document.querySelector('.findings-list-plane .el-table__empty-block');
      return e ? Math.round(e.getBoundingClientRect().height) : null;
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
        name: 'frame-fixture',
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
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  page.setDefaultTimeout(30000);
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const api = url.pathname.replace(/^\/api/, '');
    if (api === '/findings') {
      const data = Array.from({ length: 6 }, (_, i) => finding(1000 + i));
      return route.fulfill({ json: { content: data, totalElements: data.length } });
    }
    if (api === '/tasks/control/status') {
      return route.fulfill({
        json: {
          maxConcurrentTasks: 3,
          availableConcurrentSlots: 3,
          maxConcurrentTasksPerTarget: 3,
          queueCapacity: 50,
          pendingTasks: 0,
          runningTasks: 0,
        },
      });
    }
    if (api.startsWith('/auth/')) {
      return route.fulfill({
        json: { token: 't', tokenType: 'Bearer', expiresIn: 3600, user: { id: 1, username: 'admin', role: 'ADMIN' } },
      });
    }
    if (api.includes('/traffic')) {
      return route.fulfill({ json: { content: [], totalElements: 0 } });
      return route.fulfill({ json: { content: [trafficHit], totalElements: 1 } });
    }
    return route.fulfill({ json: [] });
  });
  await page.addInitScript(() => {
    localStorage.setItem('security_toolbox_setup_complete_v2', 'true');
    localStorage.setItem('security_toolbox_token', 'parity-token');
    sessionStorage.setItem('security_toolbox_session_token', 'parity-token');
  });

  const port = server.httpServer.address().port;
  await page.goto(`http://127.0.0.1:${port}/findings`, { waitUntil: 'networkidle' });
  await page.evaluate(() => document.documentElement.setAttribute('data-system-theme', 'light'));
  await page.waitForTimeout(1200);

  let failed = false;
  for (const tab of ['流量发现', '项目发现']) {
    const tabBtn = page.locator('.findings-source-tabs .el-tabs__item', { hasText: tab }).first();
    await page.waitForTimeout(600);
    if (await tabBtn.count()) {
      await tabBtn.click();
      await page.waitForTimeout(900);
    }
    const m = await page.evaluate(PROBE);
    console.log(`\n===== ${tab} =====`);
    console.log(JSON.stringify(m, null, 1));
    if (m.error) {
      failed = true;
    } else {
      const b = m.border;
      if (!(b.top && b.right && b.bottom && b.left)) {
        failed = true;
        console.log('!! 表格外框不完整');
      }
      if (m.toolbar && m.toolbar.x !== m.table.x) {
        failed = true;
        console.log('!! 表格与筛选栏左右未对齐');
      }
    }
    await page.screenshot({
      path: path.join(output, `findings-frame-${tab === '项目发现' ? 'project' : 'traffic'}.png`),
      fullPage: false,
    });
  }
  console.log(`\n结果：${failed ? 'FAIL' : 'PASS'} — 截图目录 ${output}`);
  await browser.close();
  await server.close();
  if (failed) process.exitCode = 1;
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});


