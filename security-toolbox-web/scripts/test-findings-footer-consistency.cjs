// 验证「安全发现」页两个页签（项目发现 / 流量发现）分页页脚的一致性：
// 计算样式（margin/padding）与几何位置（表格→分页间距、右侧留白）都实测对比。
const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
let server, browser;

const html = `<!doctype html><html><head><meta charset="utf-8">
<style>html,body{margin:0;height:100%}#app,.frame,.content{height:100%}</style>
</head><body><div id="app"></div>
<script type="module">
import {createApp, h} from 'vue';import {createPinia} from 'pinia';import {createRouter,createMemoryHistory,RouterView} from 'vue-router';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';import Findings from '/src/views/Findings.vue';import Tasks from '/src/views/Tasks.vue';import {useAuthStore} from '/src/stores/auth';
sessionStorage.setItem('security_toolbox_session_token','fixture-token');
// 与真实 App.vue 一致的 frame 层级：页面 section 是 .desktop-v2-content 的直接子元素，
// 否则 .desktop-v2-app-frame .desktop-v2-content > :is(...) 规则（flex / --page-gap）不生效。
const Root = { render: () => h('div', { class: 'desktop-v2-app-frame' }, [h('div', { class: 'desktop-v2-content' }, [h(RouterView)])]) };
const app=createApp(Root);app.use(createPinia());
const router=createRouter({history:createMemoryHistory(),routes:[{path:'/',component:Findings},{path:'/findings',component:Findings},{path:'/tasks',component:Tasks}]});
app.use(router);app.use(ElementPlus);
const auth=useAuthStore();
app.mount('#app');
await auth.fetchMe();
window.__navigate=(path)=>router.push(path);
window.__ready=true;
</script></body></html>`;

const finding = (i) => ({
  id: i, title: `示例发现 ${i}`, sourceTool: 'ZAP', targetId: 1, severity: 'HIGH',
  status: 'OPEN', category: 'vulnerability', createdAt: '2026-01-01T00:00:00Z',
  description: 'fixture', evidence: 'fixture', remediation: 'fixture',
});
const scan = (i) => ({
  id: 100 + i, engine: 'ZAP', packetId: i, targetId: 1, host: 'fixture.test',
  url: 'http://fixture.test/?id=' + i, hitCount: i, status: 'COMPLETED',
  message: 'fixture', createdAt: '2026-01-01T00:00:00Z',
});
const task = (i) => ({
  id: i, toolCode: 'ZAP', targetId: 1, status: 'COMPLETED', progress: 100,
  createdAt: '2026-01-01T00:00:00Z',
});

async function measure(page) {
  return page.evaluate(() => {
    // Findings 页：pane 内找表格与分页；Tasks 页：section 直接子元素
    const pane = document.querySelector('.findings-source-pane') || document.querySelector('.tasks-page');
    const table = pane ? pane.querySelector('.el-table') : null;
    const pagHost = pane ? (pane.querySelector('.traffic-records-pagination') || pane.querySelector(':scope > .tasks-pagination') || pane.querySelector('.findings-pagination')) : null;
    const row = pagHost ? pagHost.querySelector('.el-pagination') : null;
    if (!table || !pagHost || !row) return { missing: true };
    const cs = getComputedStyle(pagHost);
    const t = table.getBoundingClientRect();
    const r = row.getBoundingClientRect();
    return {
      missing: false,
      marginTop: cs.marginTop,
      paddingTop: cs.paddingTop, paddingRight: cs.paddingRight, paddingBottom: cs.paddingBottom, paddingLeft: cs.paddingLeft,
      gapTableToRow: +(r.top - t.bottom).toFixed(1),
      // 右侧留白统一以「表格卡片右边缘」为参照：分页行右缘距表格右缘的距离。
      // 不用 pane/section 外框——不同页面的容器内边距不同，基准不可比。
      rowRightToTableRight: +(t.right - r.right).toFixed(1),
    };
  });
}

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({
    configFile: false, root, cacheDir: path.resolve(root, '../.run/findings-footer-cache'), plugins: [vue(), {
      name: 'findings-footer-fixture', configureServer(s) { s.middlewares.use(async (req, res, next) => {
        if (req.url?.split('?')[0] !== '/__findings_footer') return next();
        res.setHeader('Content-Type', 'text/html'); res.end(await s.transformIndexHtml(req.url, html));
      }); },
    }],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/dist/**', '**/desktop-release/**'] } },
    optimizeDeps: { entries: [] },
    logLevel: 'error',
  });
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 1560, height: 980 } });
  const errors = [];
  page.on('pageerror', e => { errors.push(e.message); console.log('[pageerror]', e.message); });
  page.on('console', m => { if (m.type() === 'error') console.log('[console.error]', m.text().slice(0, 300)); });
  await page.route('**/api/**', async route => {
    const api = new URL(route.request().url()).pathname.replace(/^\/api/, '');
    if (api === '/auth/me') return route.fulfill({ json: { username: 'tester', role: 'ADMIN' } });
    if (api === '/targets') return route.fulfill({ json: [{ id: 1, enabled: true, name: 'Fixture target', targetValue: 'fixture.test' }] });
    if (api === '/findings') return route.fulfill({ json: { content: Array.from({ length: 6 }, (_, i) => finding(i + 1)), totalElements: 6 } });
    if (api === '/traffic/scans') return route.fulfill({ json: { content: [scan(1), scan(2)], totalElements: 2 } });
    if (api === '/tasks') return route.fulfill({ json: Array.from({ length: 6 }, (_, i) => task(i + 1)) });
    if (api === '/tasks/control/status') return route.fulfill({ json: { pendingTasks: 0, queueCapacity: 4, availableConcurrentSlots: 4, maxConcurrentTasksPerTarget: 2 } });
    if (api === '/scan-schedules') return route.fulfill({ json: [] });
    if (api === '/projects') return route.fulfill({ json: [] });
    return route.fulfill({ json: [] });
  });
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__findings_footer`, { timeout: 120000, waitUntil: 'domcontentloaded' });
  try {
    // auth.fetchMe() 异步完成前 canReadTraffic 为 false、页签栏不渲染，
    // 因此等首个分页出现即视为就绪。
    await page.locator('.findings-source-tabs, .findings-pagination .el-pagination').first().waitFor({ timeout: 90000 });
  } catch {
    const body = await page.evaluate(() => document.body.innerHTML.slice(0, 1500)).catch(() => 'evaluate failed');
    console.log('BODY SNAPSHOT:', body);
    throw new Error(`tabs not rendered; pageerrors=${JSON.stringify(errors)}`);
  }
  await page.locator('.findings-source-tabs').waitFor({ timeout: 30000 });

  // —— 页签一：项目发现（基准）——
  await page.waitForTimeout(400);
  const project = await measure(page);
  console.log('项目发现  :', JSON.stringify(project));

  // —— 切到页签二：流量发现 ——
  await page.getByText('流量发现', { exact: true }).click();
  await page.locator('.traffic-records-pagination .el-pagination').waitFor({ timeout: 15000 });
  await page.waitForTimeout(400);
  const traffic = await measure(page);
  console.log('流量发现  :', JSON.stringify(traffic));

  // ========== 任务控制中心（/tasks）：项目任务 / 流量检测 ==========
  await page.evaluate(() => window.__navigate('/tasks'));
  await page.locator('.task-source-tabs').waitFor({ timeout: 30000 }).catch(async () => {
    const body = await page.evaluate(() => document.body.innerHTML.slice(0, 1200)).catch(() => 'evaluate failed');
    throw new Error(`tasks page not rendered; body=${body}; pageerrors=${JSON.stringify(errors)}`);
  });
  await page.waitForTimeout(600);
  const projectTasks = await measure(page);
  console.log('项目任务  :', JSON.stringify(projectTasks));

  await page.getByText('流量检测', { exact: true }).click();
  await page.locator('.traffic-records-pagination .el-pagination').waitFor({ timeout: 15000 });
  await page.waitForTimeout(400);
  const trafficTasks = await measure(page);
  console.log('流量检测  :', JSON.stringify(trafficTasks));

  assert.equal(project.missing, false, '项目发现分页未渲染');
  assert.equal(traffic.missing, false, '流量发现分页未渲染');
  assert.equal(projectTasks.missing, false, `项目任务分页未渲染: ${JSON.stringify(projectTasks)}`);
  assert.equal(trafficTasks.missing, false, `流量检测分页未渲染: ${JSON.stringify(trafficTasks)}`);

  console.log('\n—— 一致性检查（基准：项目发现）——');
  // margin-top 不要求相等：项目发现靠 pane 的 14px gap，流量发现靠 margin-top 14px
  // 补偿（组件根没有 gap），两者达到相同的视觉间距，因此只对比视觉指标。
  // 四个页签全部对照「项目发现」基准。
  const targets = [['流量发现', traffic], ['项目任务', projectTasks], ['流量检测', trafficTasks]];
  const checks = [['padding-top', 'paddingTop', 0.5], ['padding-right', 'paddingRight', 0.5], ['padding-bottom', 'paddingBottom', 0.5], ['padding-left', 'paddingLeft', 0.5], ['表格→分页间距', 'gapTableToRow', 3], ['右侧留白', 'rowRightToTableRight', 3]];
  let failed = 0;
  for (const [label, m] of targets) {
    for (const [name, key, tol] of checks) {
      const a = parseFloat(project[key]); const b = parseFloat(m[key]);
      const ok = Math.abs(a - b) <= tol;
      if (!ok) failed++;
      console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}.${name}: 基准=${project[key]} 实测=${m[key]} (容差±${tol})`);
    }
  }
  if (errors.length) { console.log('\n页面错误:', errors); }
  await browser.close(); await server.close();
  if (failed) { console.log(`\n${failed} 项不一致`); process.exit(1); }
  console.log('\n安全发现（项目发现/流量发现）与任务控制中心（项目任务/流量检测）四个页签的分页页脚一致 ✓');
})().catch(async e => { console.error(e); try { await browser?.close(); await server?.close(); } catch {} process.exit(1); });
