// 验证「安全发现」筛选栏收尾项：「清除筛选」与「来源任务 #1257」是否同行。
// 通过 /findings?taskId=1257 进入来源任务筛选态（两者都会出现），测量几何。
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '..', '.run', 'findings-trailing-row');
fs.mkdirSync(output, { recursive: true });

const html = `<!doctype html><html><head><meta charset="utf-8"><base href="/__parity/"></head><body><div id="app"></div><script type="module">
import '/src/main';
</script></body></html>`;

const finding = (id) => ({
  id,
  taskId: 1257,
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

const PROBE = `(() => {
  const bar = document.querySelector('.findings-filter-toolbar');
  if (!bar) return { error: 'no toolbar' };
  const clear = bar.querySelector('.finding-filter-clear');
  const tag = bar.querySelector('.finding-task-filter-tag');
  const wrap = bar.querySelector('.finding-filter-trailing');
  const rect = (el) => { if (!el) return null; const r = el.getBoundingClientRect(); return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) }; };
  const c = rect(clear), t = rect(tag), w = rect(wrap);
  let sameRow = null;
  if (c && t) {
    const overlap = Math.min(c.y + c.h, t.y + t.h) - Math.max(c.y, t.y);
    sameRow = overlap > Math.min(c.h, t.h) * 0.5;
  }
  return { clear: c, tag: t, wrap: w, sameRow };
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
        name: 'parity-fixture',
        configureServer(s) {
          s.middlewares.use(async (req, res, next) => {
            if (!req.url.startsWith('/__parity')) return next();
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
    executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  page.setDefaultTimeout(30000);
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const api = url.pathname.replace(/^\/api/, '');
    if (api === '/findings') {
      const data = Array.from({ length: 4 }, (_, i) => finding(1000 + i));
      return route.fulfill({ json: { content: data, totalElements: data.length } });
    }
    if (api === '/tasks/control/status') {
      return route.fulfill({ json: { maxConcurrentTasks: 3, availableConcurrentSlots: 3, maxConcurrentTasksPerTarget: 3, queueCapacity: 50, pendingTasks: 0, runningTasks: 0 } });
    }
    if (api.startsWith('/auth/')) {
      return route.fulfill({ json: { token: 't', tokenType: 'Bearer', expiresIn: 3600, user: { id: 1, username: 'admin', role: 'ADMIN' } } });
    }
    return route.fulfill({ json: [] });
  });
  await page.addInitScript(() => {
    localStorage.setItem('security_toolbox_setup_complete_v2', 'true');
    localStorage.setItem('security_toolbox_token', 'parity-token');
    sessionStorage.setItem('security_toolbox_session_token', 'parity-token');
  });

  const port = server.httpServer.address().port;
  let ok = true;
  for (const width of [1440, 1280, 1024]) {
    await page.goto(`http://127.0.0.1:${port}/findings?taskId=1257`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(1400);
    await page.evaluate(() => document.documentElement.setAttribute('data-system-theme', 'light'));
    await page.setViewportSize({ width, height: 1000 });
    await page.waitForTimeout(700);
    const m = await page.evaluate(PROBE);
    console.log(`\n===== viewport ${width} =====`);
    console.log(JSON.stringify(m, null, 1));
    if (m.clear && m.tag && m.sameRow !== true) { ok = false; console.log('!! 不同行'); }
    await page.screenshot({ path: path.join(output, `trailing-${width}.png`), clip: { x: 0, y: 0, width, height: 420 } });
  }
  await browser.close();
  await server.close();
  console.log(ok ? '\nRESULT: PASS — 清除筛选与来源任务标签同行' : '\nRESULT: FAIL');
  process.exitCode = ok ? 0 : 1;
})().catch((e) => { console.error(e); process.exitCode = 1; });
