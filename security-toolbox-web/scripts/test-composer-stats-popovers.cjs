// Regression test: the composer stats bar must never show two stats cards at once.
//
// Background: the three stats pills each render an <el-popover trigger="click">.
// Click detection lives only in Element Plus's document click-outside handler,
// which uses the trigger's bounding rect. When a popover is anchored to the
// composer footer it can cover the neighbouring pills, so the second click lands
// on the open popover instead of the pill; neither -trigger nor -popper counts
// that as "outside", so two cards stay stacked on screen (the screenshot this
// test comes from: 会话统计 + Token 用量 open together).
//
// No dev server is needed: the component is mounted alone with a stubbed API
// client, which keeps the assertions focused on the mutual exclusion contract.
//
// Run: node scripts/test-composer-stats-popovers.cjs
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');

const webRoot = path.resolve(__dirname, '..');
const output = path.resolve(webRoot, '..', '.run', 'composer-stats-popovers');
fs.mkdirSync(output, { recursive: true });

const BROWSERS = [
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
];
const executablePath = process.env.TRAFFIC_TEST_BROWSER || BROWSERS.find((item) => fs.existsSync(item));

const now = '2026-10-18T00:00:00Z';
const modelUsage = {
  available: true,
  source: 'MIXED',
  model: 'fixture-model',
  modelCalls: 3,
  inputTokens: 19158,
  outputTokens: 968,
  totalTokens: 20126,
  cachedInputTokens: 2944,
  cacheHitRatePermille: 133,
  contextWindowTokens: 128000,
  contextWindowUsedTokens: 23000,
  contextWindowUsagePermille: 180,
  peakInputTokens: 21398,
  providerReportedCalls: 3,
  estimatedCalls: 0,
  cacheReportedCalls: 3,
  cacheWriteTokens: 0,
  reasoningTokens: 0,
  estimatedInputTokens: 19158,
  lastInputTokens: 21102,
  contextWindowSource: 'MODEL',
  estimator: 'fixture',
};
const conversation = {
  id: 'fixture-thread',
  title: '统计卡片测试对话',
  targetId: 1,
  targetName: '示例目标',
  messages: [
    { id: 'fixture-msg-1', role: 'user', content: '统计卡片只能同时展开一个', status: 'completed', taskIds: [], steps: [], createdAt: now, updatedAt: now },
    {
      id: 'fixture-msg-2', role: 'assistant', content: '用于回归统计卡片互斥展开。', status: 'completed',
      provider: 'openai-compatible', taskIds: [], steps: [], agentEvents: [], modelUsage,
      progressStartedAt: now, progressFinishedAt: '2026-10-18T00:00:20Z', createdAt: now, updatedAt: now,
    },
  ],
  createdAt: now,
  updatedAt: now,
};

// Everything the component pulls from the network is stubbed, so the page can be
// mounted from Vite's module graph without the Spring backend or the AI runtime.
const apiStub = `
const noop = async () => undefined;
const targets = [{ id: 1, name: '示例目标', targetValue: 'https://example.test', targetType: 'WEB', authorizationNote: '授权', allowedPorts: '80,443', enabled: true }];
const endpoints = {
  targets: async () => targets,
  dashboardSummary: async () => ({ targets: 1, running: 0, findings: 0 }),
  systemHealth: async () => ({ status: 'UP' }),
  projects: async () => [],
  tasks: async () => [],
  findings: async () => [],
  saveConversation: async () => ({ data: {} }),
};
export { endpoints };
// Mirror the real safeGet contract: always resolves to an object with a data
// field (and an offline flag) so mount-time loaders do not throw while the
// popover behaviour is being exercised.
export const safeGet = async () => ({ data: [], offline: false });
export const connectTaskEventFeed = () => () => undefined;
export const dispatchAiStreaming = noop;
export const normalizeAgentEvent = (event) => event;
export const api = { get: noop, post: noop, put: noop, delete: noop, request: noop };
export const get = async () => ({ data: { status: 'UP', targets: [{ id: 1, name: '\u793a\u4f8b\u76ee\u6807' }] } });
export const post = get;
export const put = get;
export const del = get;
export const request = noop;
export const http = api;
export default endpoints;
`;

const fixtureSource = () => `
import { createApp, h } from 'vue';
import { createPinia } from 'pinia';
import { useConversationStore } from '/src/stores/conversations';
import { createRouter, createMemoryHistory, RouterView } from 'vue-router';
import ElementPlus from 'element-plus';
import 'element-plus/dist/index.css';
import '/src/desktop-v2.css';
import '/src/unified-theme.css';
import '/src/fluent-design-2.css';
import '/src/fluent-design-3.css';
import Dashboard from '/src/views/Dashboard.vue';
import { useAuthStore } from '/src/stores/auth';
localStorage.setItem('security_toolbox_session_token', 'fixture');
localStorage.setItem('security_toolbox_ai_conversations_v2', JSON.stringify(FIXTURE_CONVERSATION()));
localStorage.setItem('security_toolbox_setup_complete_v2', 'true');
localStorage.setItem('security_toolbox_dashboard_target', '1');
const pinia = createPinia();
const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/', component: Dashboard }, { path: '/:pathMatch(.*)*', component: Dashboard }] });
const app = createApp({ render: () => h(RouterView) }).use(pinia).use(router).use(ElementPlus);
useAuthStore().checked = true;
useAuthStore().user = { username: 'fixture', role: 'USER' };
await router.push('/?conversation=fixture-thread');
await router.isReady();
// Element Plus mounts the popover content only after the client resolves the
// conversation, so the store is seeded before mount and re-checked after.
useConversationStore(pinia).items = [FIXTURE_CONVERSATION()];
app.mount('#app');
useConversationStore(pinia).items = [FIXTURE_CONVERSATION()];
await new Promise((resolve) => setTimeout(resolve, 0));
window.fixtureReady = true;
`;

async function startServer() {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  const root = webRoot;
  const virtual = new Map([
    ['\0fixture:api', apiStub],
    ['\0fixture:entry', fixtureSource()],
  ]);
  const server = await createServer({
    configFile: false,
    root,
    cacheDir: path.join(output, 'cache'),
    logLevel: 'error',
    appType: 'custom',
    optimizeDeps: { entries: [], include: ['vue', 'element-plus', 'pinia', 'vue-router'], noDiscovery: true },
    plugins: [
      vue(),
      {
        name: 'stats-popover-fixture',
        enforce: 'pre',
        resolveId(id) {
          if (id === 'fixture:entry') return '\0fixture:entry';
          if (id === '../api' || id === './api' || id === '/src/api' || id === '/src/api/index.ts') return '\0fixture:api';
          return null;
        },
        load(id) {
          const code = virtual.get(id);
          return code === undefined || code === null ? null : code.replaceAll('FIXTURE_CONVERSATION()', JSON.stringify(conversation));
        },
        configureServer(s) {
          s.middlewares.use(async (req, res, next) => {
            const url = (req.url || '').split('?')[0];
            if (url !== '/' && url !== '/index.html') return next();
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.end(`<!doctype html><html lang="zh-CN" data-system-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head><body><div id="app"></div><script type="module" src="/@id/fixture:entry"></script></body></html>`);
          });
        },
      },
    ],
    server: { port: 0, strictPort: false, host: '127.0.0.1', hmr: false, watch: null },
  });
  await server.listen();
  return server;
}

async function openPage(browser, port, viewport) {
  const page = await browser.newPage({ viewport, deviceScaleFactor: 1 });
  page.setDefaultTimeout(20000);
  const errors = [];
  page.on('pageerror', (error) => errors.push('pageerror: ' + error.message));
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push('console.error: ' + msg.text());
  });
  await page.route('**/api/**', (route) => route.fulfill({ json: [] }));
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'commit' });
  await page.waitForFunction(() => window.fixtureReady, null, { timeout: 60000 }).catch((e) => { throw new Error('fixture not ready. errors=' + JSON.stringify(errors.slice(0, 4))); });
  await page.waitForFunction(() => {
    const bar = document.querySelector('.composer-stats-bar');
    return bar && bar.querySelectorAll('.stats-pill').length > 0;
  }, null, { timeout: 20000 }).catch((e) => { throw new Error('stats bar missing. errors=' + JSON.stringify(errors.slice(0, 4))); });
  return { page, errors };
}

// Titles of the stats cards that are really visible on screen.
const visibleCards = () => [...document.body.querySelectorAll('.stats-pill-popover')]
  .filter((el) => {
    const style = getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return style.display !== 'none'
      && style.visibility !== 'hidden'
      && style.opacity !== '0'
      && el.getAttribute('aria-hidden') !== 'true'
      && rect.width > 0
      && rect.height > 0;
  })
  .map((el) => el.querySelector('strong')?.textContent?.trim() || el.textContent.trim().slice(0, 8));

const failures = [];
function check(name, ok, detail) {
  console.log(`${ok ? '[PASS]' : '[FAIL]'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures.push(name);
}

(async () => {
  const server = await startServer();
  const browser = await chromium.launch({ executablePath, headless: true });
  const port = server.config.server.port;

  for (const viewport of [{ width: 1440, height: 900 }, { width: 1024, height: 700 }]) {
    const tag = `${viewport.width}x${viewport.height}`;
    const { page, errors } = await openPage(browser, port, viewport);
    const pills = page.locator('.composer-stats-bar .stats-pill');
    const count = await pills.count();
    check(`${tag} 统计栏渲染三个胶囊`, count === 3, `实际 ${count}`);
    if (count === 0) {
      console.log('DOM: ' + (await page.evaluate(() => document.body.innerText)).slice(0, 400));
      console.log('ERRORS: ' + JSON.stringify(errors.slice(0, 4)));
      await page.close();
      continue;
    }
    check(`${tag} 初始无展开卡片`, (await page.evaluate(visibleCards)).length === 0);

    // Sequential clicks used to leave two cards open, because the first popover
    // covered the next pill and swallowed the second click.
    for (let index = 0; index < count; index += 1) {
      await pills.nth(index).click();
      await page.waitForTimeout(420);
      const open = await page.evaluate(visibleCards);
      check(`${tag} 点击第 ${index + 1} 个胶囊后只展开一张卡片`, open.length === 1, `展开 ${JSON.stringify(open)}`);
      if (index === 0) {
        await page.screenshot({ path: path.join(output, `${tag}-single-card.png`) });
      }
    }

    // Toggling any pill that is not the one covered by the open card closes it.
    // (The first pill sits under the 260px card opened from the last pill, so the
    // hit test there lands on the card itself — that is the original bug's shape.)
    await pills.nth(1).click();
    await page.waitForTimeout(420);
    const openedByToggle = await page.evaluate(visibleCards);
    check(`${tag} 点击第二个胶囊展开其卡片`, openedByToggle.length === 1, `展开 ${JSON.stringify(openedByToggle)}`);
    await pills.nth(1).click();
    await page.waitForTimeout(420);
    const reopened = await page.evaluate(visibleCards);
    check(`${tag} 再次点击同一胶囊收起卡片`, reopened.length === 0, `展开 ${JSON.stringify(reopened)}`);

    // Blank space closes the card.
    await pills.nth(1).click();
    await page.waitForTimeout(420);
    await page.mouse.click(viewport.width / 2, Math.max(20, viewport.height / 2 - 140));
    await page.waitForTimeout(420);
    const afterOutside = await page.evaluate(visibleCards);
    check(`${tag} 点击空白处收起卡片`, afterOutside.length === 0, `展开 ${JSON.stringify(afterOutside)}`);

    // Escape closes the card.
    await pills.nth(2).click();
    await page.waitForTimeout(420);
    await page.keyboard.press('Escape');
    await page.waitForTimeout(420);
    const afterEsc = await page.evaluate(visibleCards);
    check(`${tag} Esc 收起卡片`, afterEsc.length === 0, `展开 ${JSON.stringify(afterEsc)}`);

    // Every pill exposes its open/closed state via aria-pressed; exactly the open
    // one reports true, so assistive tech matches what is on screen.
    await pills.nth(2).click();
    await page.waitForTimeout(420);
    const expanded = await page.evaluate(() => [...document.querySelectorAll('.composer-stats-bar .stats-pill')]
      .map((el) => el.getAttribute('aria-pressed')));
    check(`${tag} 打开第三张卡片时仅该胶囊 aria-pressed=true`,
      JSON.stringify(expanded) === JSON.stringify(['false', 'false', 'true']), JSON.stringify(expanded));
    await page.keyboard.press('Escape');
    await page.waitForTimeout(320);

    check(`${tag} 无控制台错误`, errors.length === 0, JSON.stringify(errors.slice(0, 3)));
    await page.close();
  }

  await browser.close();
  await server.close();

  if (failures.length) {
    console.log(`\n${failures.length} 项检查失败：${failures.join('；')}`);
    process.exit(1);
  }
  console.log('\n全部检查通过：统计卡片互斥展开。');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});












