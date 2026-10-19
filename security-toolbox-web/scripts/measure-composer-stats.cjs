// Measures the chat composer footer geometry (composer-hint + composer-stats-bar)
// against the bottom edge of .chat-page with real Vue + Element Plus and a seeded
// localStorage conversation, so the vertical gaps can be balanced to pixel parity
// without the backend. Prints one row per viewport height.
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '../.run/composer-stats');
fs.mkdirSync(output, { recursive: true });
let server, browser;

const threadId = 'fixture-thread';
const now = '2026-10-18T00:00:00Z';
// A completed assistant message carrying modelUsage so the stats bar renders.
const assistantMessage = {
  id: 'fixture-msg-2',
  role: 'assistant',
  content: '这是一条用于测量底栏间距的回复。',
  status: 'completed',
  provider: 'openai-compatible',
  taskIds: [],
  steps: [],
  agentEvents: [],
  modelUsage: {
    available: true,
    source: 'MIXED',
    model: 'fixture-model',
    modelCalls: 3,
    inputTokens: 5000,
    outputTokens: 1200,
    totalTokens: 6200,
    cachedInputTokens: 4000,
    cacheHitRatePermille: 645,
    contextWindowTokens: 128000,
    contextWindowUsedTokens: 23456,
    contextWindowUsagePermille: 183,
    peakInputTokens: 6000,
    cacheReportedCalls: 3,
    cacheWriteTokens: 300,
    reasoningTokens: 0,
    estimatedInputTokens: 5000,
    lastInputTokens: 5000,
    contextWindowSource: 'MODEL',
    estimator: 'fixture',
  },
  createdAt: now,
  updatedAt: now,
};
const conversation = {
  id: threadId,
  title: '测量对话',
  targetId: 1,
  targetName: '示例目标',
  messages: [
    {
      id: 'fixture-msg-1',
      role: 'user',
      content: '测量底栏间距',
      status: 'completed',
      taskIds: [],
      steps: [],
      createdAt: now,
      updatedAt: now,
    },
    assistantMessage,
  ],
  createdAt: now,
  updatedAt: now,
};

const html = `<!doctype html><html lang="zh-CN" data-system-theme="light"><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module">
import {createApp,h} from 'vue';import {createPinia} from 'pinia';import {createRouter,createMemoryHistory,RouterView} from 'vue-router';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';import 'element-plus/es/components/message/style/css';import 'element-plus/es/components/message-box/style/css';
import '/src/desktop-v2.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';import '/src/code-block.css';import '/src/motion.css';
import Dashboard from '/src/views/Dashboard.vue';
import {useAuthStore} from '/src/stores/auth';
localStorage.setItem('security_toolbox_session_token','fixture');
localStorage.setItem('security_toolbox_ai_conversations_v2', JSON.stringify([${JSON.stringify(conversation)}]));
localStorage.setItem('security_toolbox_setup_complete_v2','true');
localStorage.setItem('security_toolbox_dashboard_target','1');
const router=createRouter({history:createMemoryHistory(),routes:[{path:'/',component:Dashboard},{path:'/targets',component:{template:'<p>targets</p>'}}]});
const app=createApp({render:()=>h(RouterView)}).use(createPinia()).use(router).use(ElementPlus);
useAuthStore().checked=true;useAuthStore().user={username:'fixture',role:'USER'};
window.fixtureNavigate=to=>router.push(to);
await router.push('/?conversation=${threadId}');await router.isReady();app.mount('#app');window.fixtureReady=true;
</script></body></html>`;

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({
    configFile: false,
    root,
    cacheDir: path.join(output, 'cache'),
    optimizeDeps: { entries: [], include: ['vue', 'element-plus', 'pinia', 'vue-router'], noDiscovery: true },
    plugins: [vue(), { name: 'composer-stats-fixture', configureServer(s) { s.middlewares.use(async (req, res, next) => { if (req.url !== '/__composer-stats') return next(); res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(await s.transformIndexHtml(req.url, html)); }); } }],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: null },
    logLevel: 'error',
  });
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 }, deviceScaleFactor: 1 });
  page.setDefaultTimeout(30000);
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', msg => { if (msg.type() === 'error' || msg.type() === 'warning') errors.push('console.' + msg.type() + ': ' + msg.text()); });
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    const p = url.pathname.replace(/^\/api/, '');
    if (p === '/targets') return route.fulfill({ json: [{ id: 1, name: '示例目标', targetValue: 'https://example.test', targetType: 'WEB', authorizationNote: '授权', allowedPorts: '80,443', enabled: true }] });
    if (p === '/dashboard/summary') return route.fulfill({ json: { targets: 1, running: 0, findings: 0 } });
    if (p === '/system/health') return route.fulfill({ json: { status: 'UP' } });
    if (p === '/projects') return route.fulfill({ json: [] });
    return route.fulfill({ json: [] });
  });
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__composer-stats`);
  await page.waitForFunction(() => window.fixtureReady);
  await page.waitForTimeout(2500);
  const diag = await page.evaluate(() => ({
    hasWelcome: !!document.querySelector('.chat-welcome'),
    hasThread: !!document.querySelector('.chat-conversation-body'),
    hasHint: !!document.querySelector('.composer-hint'),
    hasStats: !!document.querySelector('.composer-stats-bar'),
    hasTarget: !!document.querySelector('.thread-target'),
    hasComposer: !!document.querySelector('.thread-composer'),
    bodyText: (document.body.innerText || '').slice(0, 300),
    storage: localStorage.getItem('security_toolbox_ai_conversations_v2'),
  }));
  console.log('DIAG: ' + JSON.stringify(diag));
  console.log('ERRORS SO FAR: ' + JSON.stringify(errors));
  await page.locator('.composer-stats-bar').waitFor({ state: 'attached' });
  await page.locator('.composer-hint').waitFor({ state: 'attached' });
  await page.waitForTimeout(1000);

  const measure = async () => page.evaluate(() => {
    const box = el => { const b = el.getBoundingClientRect(); return { top: b.top, bottom: b.bottom, height: b.height, y: b.y }; };
    const page = document.querySelector('.chat-page');
    const wrap = document.querySelector('.chat-composer-wrap');
    const composer = document.querySelector('.thread-composer');
    const hint = document.querySelector('.composer-hint');
    const stats = document.querySelector('.composer-stats-bar');
    const pill = stats ? stats.querySelector('.stats-pill') : null;
    const hintRect = hint ? hint.getBoundingClientRect() : null;
    const statsRect = stats ? stats.getBoundingClientRect() : null;
    const composerRect = composer ? composer.getBoundingClientRect() : null;
    const pageRect = page ? page.getBoundingClientRect() : null;
    return {
      page: box(page), wrap: box(wrap), composer: box(composer), hint: box(hint), stats: box(stats),
      gapHintToStats: statsRect && hintRect ? Math.round((statsRect.top - hintRect.bottom) * 10) / 10 : null,
      gapComposerToHint: hintRect && composerRect ? Math.round((hintRect.top - composerRect.bottom) * 10) / 10 : null,
      gapStatsToPageBottom: pageRect && statsRect ? Math.round((pageRect.bottom - statsRect.bottom) * 10) / 10 : null,
      hintMarginTop: hint ? getComputedStyle(hint).marginTop : null,
      statsPaddingTop: stats ? getComputedStyle(stats).paddingTop : null,
      statsPaddingBottom: stats ? getComputedStyle(stats).paddingBottom : null,
      wrapPaddingBottom: wrap ? getComputedStyle(wrap).paddingBottom : null,
      hintFontSize: hint ? getComputedStyle(hint).fontSize : null,
      hintLineHeight: hint ? getComputedStyle(hint).lineHeight : null,
      pillFontSize: pill ? getComputedStyle(pill).fontSize : null,
      pillLineHeight: pill ? getComputedStyle(pill).lineHeight : null,
      pillHeight: pill ? pill.getBoundingClientRect().height : null,
    };
  });

  const heights = [900, 800, 720, 640, 560];
  for (const height of heights) {
    await page.setViewportSize({ width: 1200, height });
    await page.waitForTimeout(400);
    const m = await measure();
    console.log('VIEWPORT ' + height + 'px: ' + JSON.stringify(m));
  }

  await page.screenshot({ path: path.join(output, 'composer-stats.png') });

  if (errors.length) {
    console.log('PAGE ERRORS: ' + JSON.stringify(errors));
  }
  await browser.close();
  await server.close();
})().catch(err => { console.error(err); process.exit(1); });
