// Measures the 安全发现 filter toolbar side by side with the 检测任务 filter bar
// using the same isolated Vite fixture, so both bars render with the same theme,
// Element Plus build and viewport. Prints geometry per viewport plus a screenshot.
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '../.run/filter-bar-parity');
fs.mkdirSync(output, { recursive: true });
let server, browser;

const html = `<!doctype html><html><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module">
import {createApp} from 'vue';import {createPinia} from 'pinia';import {createRouter,createMemoryHistory,RouterView} from 'vue-router';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';import 'element-plus/es/components/message/style/css';import 'element-plus/es/components/message-box/style/css';
import '/src/desktop-v2.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';import '/src/code-block.css';import '/src/motion.css';
import Findings from '/src/views/Findings.vue';import Tasks from '/src/views/Tasks.vue';import {endpoints} from '/src/api';import {useAuthStore} from '/src/stores/auth';
sessionStorage.setItem('security_toolbox_session_token','fixture');
const realFindings=endpoints.findings;
for(const key of Object.keys(endpoints))endpoints[key]=async()=>({data:[]});
Object.assign(endpoints,{findings:realFindings});
const router=createRouter({history:createMemoryHistory(),routes:[{path:'/tasks',component:Tasks},{path:'/findings',component:Findings}]});
const app=createApp(RouterView);app.use(createPinia());app.use(router);app.use(ElementPlus);useAuthStore().user={username:'fixture',role:'ADMIN'};
const initialRoute=window.__route||'/findings';await router.push(initialRoute);await router.isReady();app.mount('#app');window.fixtureReady=true;
</script></body></html>`;

const finding = id => ({id, taskId:160, targetId:7, projectId:1, title:`Fixture vulnerability ${id}`, severity:'HIGH', status:'OPEN', sourceTool:'nuclei', description:'Fixture risk description', evidence:'Fixture finding evidence', remediation:'Fixture repair advice', createdAt:'2026-10-04T01:00:00Z'});
const task = id => ({id, projectId:1, targetId:7, toolCode:'nuclei_scan', status:'SUCCESS', progress:100, createdAt:'2026-10-04T01:00:00Z'});

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({
    configFile: false,
    root,
    cacheDir: path.join(output, 'cache'),
    optimizeDeps: { entries: [], include: ['vue', 'element-plus', 'pinia', 'vue-router'], noDiscovery: true },
    plugins: [vue(), { name: 'filter-bar-parity-fixture', configureServer(s) { s.middlewares.use(async (req, res, next) => { if (req.url !== '/__parity') return next(); res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(await s.transformIndexHtml(req.url, html)); }); } }],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: null },
    logLevel: 'error',
  });
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
  page.setDefaultTimeout(20000);
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    const api = url.pathname.replace(/^\/api/, '');
    if (api === '/findings') {
      const data = [finding(701), finding(702)];
      return route.fulfill({ json: { content: data, totalElements: data.length } });
    }
    if (api === '/tasks') {
      return route.fulfill({ json: [task(801), task(802)] });
    }
    return route.fulfill({ json: [] });
  });

  const PROBE = `(() => {
    const pick = (root, sel) => { const el = root.querySelector(sel); if (!el) return null; const r = el.getBoundingClientRect(); return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) }; };
    const findingsBar = document.querySelector('.findings-filter-toolbar');
    const tasksBar = document.querySelector('.task-filter-bar');
    return {
      findings: findingsBar ? {
        bar: pick(document, '.findings-filter-toolbar'),
        pad: getComputedStyle(findingsBar).padding,
        gap: getComputedStyle(findingsBar).columnGap,
        cols: getComputedStyle(findingsBar).gridTemplateColumns,
        border: getComputedStyle(findingsBar).borderRadius,
        bg: getComputedStyle(findingsBar).backgroundColor,
        row: pick(findingsBar, '.finding-filter-row'),
        rowChildren: [...findingsBar.querySelectorAll('.finding-filter-row > *')].map(el => { const r = el.getBoundingClientRect(); return { cls: el.className, h: Math.round(r.height), w: Math.round(r.width) }; }),
        selects: [...findingsBar.querySelectorAll(':scope > .finding-filter-cell')].map(el => Math.round(el.getBoundingClientRect().height)),
        search: pick(findingsBar, '.finding-filter-cell--search'),
      } : null,
      tasks: tasksBar ? {
        bar: pick(document, '.task-filter-bar'),
        pad: getComputedStyle(tasksBar).padding,
        gap: getComputedStyle(tasksBar).columnGap,
        cols: getComputedStyle(tasksBar).gridTemplateColumns,
        border: getComputedStyle(tasksBar).borderRadius,
        bg: getComputedStyle(tasksBar).backgroundColor,
        row: pick(tasksBar, '.task-filter-row'),
        rowChildren: [...tasksBar.querySelectorAll('.task-filter-row > *')].map(el => { const r = el.getBoundingClientRect(); return { cls: el.className, h: Math.round(r.height), w: Math.round(r.width) }; }),
        selects: [...tasksBar.querySelectorAll(':scope > .task-filter-cell')].map(el => Math.round(el.getBoundingClientRect().height)),
        search: pick(tasksBar, '.task-filter-cell--search'),
      } : null,
    };
  })()`;

  for (const route of ['findings', 'tasks']) {
    await page.addInitScript(r => { window.__route = r; }, route);
    await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__parity`, { waitUntil: 'networkidle' });
    await page.waitForFunction(() => window.fixtureReady);
    if (route === 'findings') {
      await page.locator('.findings-filter-toolbar').waitFor();
    } else {
      await page.locator('.task-filter-bar').waitFor();
    }
    await page.waitForTimeout(500);
    for (const width of [1920, 1440, 1280, 1100]) {
      await page.setViewportSize({ width, height: 1000 });
      await page.waitForTimeout(400);
      const m = await page.evaluate(PROBE);
      const side = route === 'findings' ? m.findings : m.tasks;
      console.log(`\n=== ${route} @ ${width} ===`);
      console.log(`  bar   ${JSON.stringify(side.bar)} pad=${side.pad} colGap=${side.gap} radius=${side.border} bg=${side.bg}`);
      console.log(`  cols  ${side.cols}`);
      console.log(`  row   ${JSON.stringify(side.row)}`);
      console.log(`  rowKids ${side.rowChildren.map(k => `${k.cls.split(' ').pop()}:${k.w}x${k.h}`).join(' ')}`);
      console.log(`  selects ${JSON.stringify(side.selects)} search ${JSON.stringify(side.search)}`);
      await page.screenshot({ path: path.join(output, `${route}-${width}.png`), clip: { x: 0, y: 0, width, height: 300 } });
    }
  }
  if (errors.length) { console.error('page errors:', errors); process.exitCode = 1; }
  console.log(`\nScreenshots in ${output}`);
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => { await browser?.close(); await server?.close(); });
