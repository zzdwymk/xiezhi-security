// Measures the Findings filter toolbar geometry with real Vue + Element Plus and
// isolated API fixtures. Prints one row per viewport so the one-line layout can be
// verified without the backend.
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '../.run/findings-toolbar');
fs.mkdirSync(output, { recursive: true });
let server, browser;

const html = `<!doctype html><html><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module">
import {createApp} from 'vue';import {createPinia} from 'pinia';import {createRouter,createMemoryHistory,RouterView} from 'vue-router';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';import 'element-plus/es/components/message/style/css';import 'element-plus/es/components/message-box/style/css';
import '/src/desktop-v2.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';import '/src/code-block.css';import '/src/motion.css';
import Findings from '/src/views/Findings.vue';import {endpoints} from '/src/api';import {useAuthStore} from '/src/stores/auth';
sessionStorage.setItem('security_toolbox_session_token','fixture');
const realFindings=endpoints.findings;
for(const key of Object.keys(endpoints))endpoints[key]=async()=>({data:[]});
Object.assign(endpoints,{findings:realFindings});
const router=createRouter({history:createMemoryHistory(),routes:[{path:'/tasks',component:{template:'<p>Tasks</p>'}},{path:'/findings',component:Findings}]});
const app=createApp(RouterView);app.use(createPinia());app.use(router);app.use(ElementPlus);useAuthStore().user={username:'fixture',role:'USER'};
window.fixtureNavigate=to=>router.push(to);await router.push('/findings?taskId=160');await router.isReady();app.mount('#app');window.fixtureReady=true;
</script></body></html>`;

const finding = id => ({id, taskId:160, targetId:7, projectId:1, title:`Fixture vulnerability ${id}`, severity:'HIGH', status:'OPEN', sourceTool:'nuclei', description:'Fixture risk description', evidence:'Fixture finding evidence', remediation:'Fixture repair advice', createdAt:'2026-10-04T01:00:00Z'});

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({
    configFile: false,
    root,
    cacheDir: path.join(output, 'cache'),
    optimizeDeps: { entries: [], include: ['vue', 'element-plus', 'pinia', 'vue-router'], noDiscovery: true },
    plugins: [vue(), { name: 'findings-toolbar-fixture', configureServer(s) { s.middlewares.use(async (req, res, next) => { if (req.url !== '/__toolbar') return next(); res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(await s.transformIndexHtml(req.url, html)); }); } }],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: null },
    logLevel: 'error',
  });
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 1800, height: 1000 }, deviceScaleFactor: 1 });
  page.setDefaultTimeout(15000);
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    const api = url.pathname.replace(/^\/api/, '');
    if (api === '/findings') {
      const data = [finding(701), finding(702)];
      return route.fulfill({ json: { content: data, totalElements: data.length } });
    }
    return route.fulfill({ json: [] });
  });
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__toolbar`);
  await page.waitForFunction(() => window.fixtureReady);
  await page.locator('.findings-filter-toolbar').waitFor();
  await page.waitForTimeout(800);

  const widths = [1920, 1600, 1440, 1280, 1100, 960];
  for (const width of widths) {
    await page.setViewportSize({ width, height: 1000 });
    await page.waitForTimeout(500);
    const m = await page.evaluate(() => {
      const bar = document.querySelector('.findings-filter-toolbar');
      const tag = document.querySelector('.finding-task-filter-tag');
      const kids = [...bar.children].map(el => {
        const r = el.getBoundingClientRect();
        return { name: el.className || el.tagName, x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) };
      });
      const rows = new Set(kids.map(k => k.y));
      const tagStyle = tag ? getComputedStyle(tag) : null;
      return {
        barWidth: Math.round(bar.getBoundingClientRect().width),
        rowCount: rows.size,
        kids,
        tagText: tag ? tag.textContent.trim() : null,
        tagVarColor: tagStyle ? tagStyle.getPropertyValue('--el-tag-text-color') : null,
        tagVarBorder: tagStyle ? tagStyle.getPropertyValue('--el-tag-border-color') : null,
        tagColor: tagStyle ? tagStyle.color : null,
        tagBorder: tagStyle ? tagStyle.borderTopColor : null,
        tagBg: tagStyle ? tagStyle.backgroundColor : null,
        tagOpacity: tagStyle ? tagStyle.opacity : null,
        tagOutline: tagStyle ? `${tagStyle.outlineStyle} ${tagStyle.outlineColor}` : null,
        accent: getComputedStyle(document.documentElement).getPropertyValue('--app-accent'),
        scheme: getComputedStyle(document.documentElement).getPropertyValue('color-scheme'),
      };
    });
    console.log(`\n=== viewport ${width} === bar=${m.barWidth}px rows=${m.rowCount}`);
    for (const k of m.kids) console.log(`  ${String(k.name).split(' ')[0].padEnd(30)} x=${String(k.x).padStart(5)} y=${String(k.y).padStart(4)} w=${String(k.w).padStart(4)} h=${k.h}`);
    console.log(`  tag text=${JSON.stringify(m.tagText)} varColor=${m.tagVarColor.trim()} varBorder=${m.tagVarBorder.trim()}`);
    console.log(`  tag color=${m.tagColor} border=${m.tagBorder} bg=${m.tagBg} outline=${m.tagOutline} opacity=${m.tagOpacity}`);
    console.log(`  accent=${m.accent.trim()} color-scheme=${m.scheme.trim()}`);
    await page.screenshot({ path: path.join(output, `findings-toolbar-${width}.png`), clip: { x: 0, y: 0, width, height: 260 } });
  }
  if (errors.length) { console.error('page errors:', errors); process.exitCode = 1; }
  console.log(`\nScreenshots in ${output}`);
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => { await browser?.close(); await server?.close(); });
