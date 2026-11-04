// Regression test: the answer list must not force itself back to the bottom while
// the user is reading further up.
//
// Background: every streamed token (and every typewriter step, task event and
// status change) ran `scrollTop = scrollHeight` unconditionally. The list therefore
// snapped to the bottom on each update, making it impossible to scroll up while an
// answer was being written.
//
// This mounts the real Dashboard.vue alone (stubbed API, same fixture trick as
// test-composer-stats-popovers.cjs) and asserts:
//   1. while new content arrives, a user who scrolled up keeps their position,
//   2. once they return to the bottom, following resumes on the next update,
//   3. content that grows while they are already at the bottom keeps following.
//
// Run: node scripts/test-chat-scroll-follow.cjs
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');

const webRoot = path.resolve(__dirname, '..');
const output = path.resolve(webRoot, '..', '.run', 'chat-scroll-follow');
fs.mkdirSync(output, { recursive: true });

const BROWSERS = [
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
];
const executablePath = process.env.TOOLBOX_TEST_BROWSER || BROWSERS.find((item) => fs.existsSync(item));

const now = '2026-11-04T07:18:06Z';
// A long conversation so the list is genuinely scrollable in a normal viewport.
const paragraph = (index) =>
  `第 ${index} 段：这里是一段较长的回答内容，用来把对话列表撑出滚动条，` +
  `以便验证用户在回看历史时不会被强制拉回底部。`;
const longAnswer = Array.from({ length: 40 }, (_, index) => paragraph(index + 1)).join('\n\n');

const conversation = {
  id: 'fixture-thread',
  title: '滚动跟随回归',
  targetId: 1,
  targetName: '示例目标',
  messages: [
    { id: 'u-1', role: 'user', content: '这个项目怎么打', status: 'completed', taskIds: [], steps: [], createdAt: now, updatedAt: now },
    {
      id: 'a-1',
      role: 'assistant',
      content: longAnswer,
      status: 'completed',
      provider: 'openai-compatible',
      taskIds: [],
      steps: [],
      agentEvents: [],
      createdAt: now,
      updatedAt: now,
    },
  ],
  createdAt: now,
  updatedAt: now,
};

const apiStub = `
const noop = async () => undefined;
const targets = [{ id: 1, name: '示例目标', targetValue: '192.168.222.149', targetType: 'IP', authorizationNote: '授权', allowedPorts: '80,443', enabled: true }];
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
export const safeGet = async () => ({ data: [], offline: false });
export const connectTaskEventFeed = () => () => undefined;
export const dispatchAiStreaming = noop;
export const normalizeAgentEvent = (event) => event;
export const api = { get: noop, post: noop, put: noop, delete: noop, request: noop };
export const get = async () => ({ data: { status: 'UP', targets: [{ id: 1, name: '示例目标' }] } });
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
useConversationStore(pinia).items = [FIXTURE_CONVERSATION()];
app.mount('#app');
useConversationStore(pinia).items = [FIXTURE_CONVERSATION()];
await new Promise((resolve) => setTimeout(resolve, 0));
// Simulates a streamed chunk: growing an existing answer re-runs the same
// content-length watcher that used to snap the list to the bottom.
window.__appendAnswer = (extra) => {
  const store = useConversationStore(pinia);
  const thread = store.items.find((item) => item.id === 'fixture-thread');
  const assistant = thread.messages.find((item) => item.id === 'a-1');
  store.updateMessage(thread.id, assistant.id, { content: assistant.content + extra });
};
window.fixtureReady = true;
`;

async function startServer() {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  const virtual = new Map([
    ['\0fixture:api', apiStub],
    ['\0fixture:entry', fixtureSource()],
  ]);
  const server = await createServer({
    configFile: false,
    root: webRoot,
    cacheDir: path.join(output, 'cache'),
    logLevel: 'error',
    appType: 'custom',
    optimizeDeps: { entries: [], include: ['vue', 'element-plus', 'pinia', 'vue-router'], noDiscovery: true },
    plugins: [
      vue(),
      {
        name: 'chat-scroll-fixture',
        enforce: 'pre',
        resolveId(id) {
          if (id === 'fixture:entry') return '\0fixture:entry';
          if (id === '../api' || id === './api' || id === '/src/api' || id === '/src/api/index.ts') return '\0fixture:api';
          return null;
        },
        load(id) {
          const code = virtual.get(id);
          return code === undefined || code === null ? null
            : code.replaceAll('FIXTURE_CONVERSATION()', JSON.stringify(conversation));
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

const failures = [];
function check(name, ok, detail) {
  console.log(`${ok ? '[PASS]' : '[FAIL]'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures.push(name);
}

(async () => {
  const server = await startServer();
  const browser = await chromium.launch({ executablePath, headless: true });
  const port = server.config.server.port;
  const errors = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 700 }, deviceScaleFactor: 1 });
    page.setDefaultTimeout(20000);
    page.on('pageerror', (error) => errors.push('pageerror: ' + error.message));
    page.on('console', (msg) => { if (msg.type() === 'error') errors.push('console.error: ' + msg.text()); });
    await page.route('**/api/**', (route) => route.fulfill({ json: [] }));
    await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'commit' });
    await page.waitForFunction(() => window.fixtureReady, null, { timeout: 60000 });
    await page.locator('.chat-messages').waitFor({ state: 'visible' });
    await page.waitForTimeout(400);

    const geometry = () =>
      page.evaluate(() => {
        const box = document.querySelector('.chat-messages');
        return {
          scrollTop: Math.round(box.scrollTop),
          scrollHeight: box.scrollHeight,
          clientHeight: box.clientHeight,
          distanceFromBottom: Math.round(box.scrollHeight - box.scrollTop - box.clientHeight),
          scrollable: box.scrollHeight > box.clientHeight + 40,
        };
      });

    const initial = await geometry();
    check('对话列表足够长，形成可滚动区域', initial.scrollable, JSON.stringify(initial));

    // Untouched conversation: it should sit at the newest message.
    check('打开对话时定位在最新内容', initial.distanceFromBottom <= 2, JSON.stringify(initial));

    // 1. The user scrolls up. `scroll-behavior: smooth` makes even a programmatic
    //    assignment animate, so wait for the animation to settle before measuring —
    //    otherwise the measurement itself would race the list's own scrolling.
    await page.evaluate(() => {
      const box = document.querySelector('.chat-messages');
      box.style.scrollBehavior = 'auto';
      box.scrollTop = Math.round((box.scrollHeight - box.clientHeight) * 0.25);
      const ta = document.querySelector('.thread-composer textarea, .welcome-composer textarea');
      if (ta) ta.blur();
      box.style.scrollBehavior = '';

    });
    await page.waitForTimeout(600);
    const beforeStream = await geometry();
    check('向上滚动后离开底部', beforeStream.distanceFromBottom > 200, JSON.stringify(beforeStream));

    for (let index = 0; index < 5; index += 1) {

      await page.evaluate((marker) => window.__appendAnswer('\n\n' + marker), `流式新增内容 ${index + 1}`);
      await page.waitForTimeout(150);

    }
    const afterStream = await geometry();

    check(
      '回答流式增长时，用户回看的位置不被拉回底部',
      Math.abs(afterStream.scrollTop - beforeStream.scrollTop) <= 2,
      JSON.stringify({ before: beforeStream.scrollTop, after: afterStream.scrollTop, distanceFromBottom: afterStream.distanceFromBottom }),
    );
    check('新内容确实被追加（列表变高）', afterStream.scrollHeight > beforeStream.scrollHeight, JSON.stringify({ before: beforeStream.scrollHeight, after: afterStream.scrollHeight }));
    await page.screenshot({ path: path.join(output, 'scrolled-up-while-streaming.png') });

    // 3. The "jump to newest" button: only shown away from the bottom, and it
    //    returns the list to the newest content.
    const jumpButton = page.getByRole('button', { name: '回到最新内容' });
    check('离开底部时出现「回到最新内容」按钮', await jumpButton.isVisible());

    const buttonBox = await jumpButton.boundingBox();
    const viewport = page.viewportSize();

    check(
      '按钮位于可视区域内（未被输入框或滚动容器裁掉）',
      Boolean(buttonBox) && buttonBox.y > 0 && buttonBox.y + buttonBox.height < viewport.height,
      JSON.stringify(buttonBox),
    );
    // It must not cover the text column: it should sit in the gutter beside it.
    check(
      '按钮没有压住正文内容',
      await page.evaluate(() => {
        const button = document.querySelector('.jump-to-bottom');
        if (!button) return false;
        const b = button.getBoundingClientRect();
        const inner = document.querySelector('.messages-inner');
        if (!inner) return false;
        const t = inner.getBoundingClientRect();
        return b.right <= t.left + 1 || b.left >= t.right - 1;
      }),
    );

    await jumpButton.click();
    await page.waitForTimeout(700);
    const afterJump = await geometry();
    check('点击后直达最新内容', afterJump.distanceFromBottom <= 2, JSON.stringify(afterJump));
    check('回到最新后按钮自动隐藏', !(await jumpButton.isVisible()));
    await page.screenshot({ path: path.join(output, 'after-jump-to-bottom.png') });

    // 4. Following resumes after the jump.
    await page.evaluate(() => window.__appendAnswer('\n\n点击回到最新之后的内容'));
    await page.waitForTimeout(300);
    const followingAfterJump = await geometry();
    check('点击回到最新后恢复自动跟随', followingAfterJump.distanceFromBottom <= 2, JSON.stringify(followingAfterJump));

    // 5. Returning to the bottom resumes following.
    await page.evaluate(() => {
      const box = document.querySelector('.chat-messages');
      box.style.scrollBehavior = 'auto';
      box.scrollTop = Math.round((box.scrollHeight - box.clientHeight) * 0.2);
      box.style.scrollBehavior = '';
    });
    await page.waitForTimeout(400);
    await page.evaluate(() => {
      const box = document.querySelector('.chat-messages');
      box.style.scrollBehavior = 'auto';
      box.scrollTop = box.scrollHeight;
      box.style.scrollBehavior = '';
    });
    // Let the scroll event reach the handler that re-arms following.
    await page.waitForTimeout(250);
    const atBottom = await geometry();
    await page.evaluate(() => window.__appendAnswer('\n\n回到最底部之后的新内容'));
    await page.waitForTimeout(250);
    const resumed = await geometry();
    check(
      '回到底部后恢复自动跟随',
      resumed.distanceFromBottom <= 2,
      JSON.stringify({ atBottom: atBottom.distanceFromBottom, resumed: resumed.distanceFromBottom }),
    );

    check('无控制台错误', errors.length === 0, JSON.stringify(errors.slice(0, 3)));
  } finally {
    await browser.close();
    await server.close();
  }

  if (failures.length) {
    console.log(`\n${failures.length} 项检查失败：${failures.join('；')}`);
    process.exit(1);
  }
  console.log('\n全部检查通过：回答生成期间可以自由向上翻看，回到底部后恢复自动跟随。');
})().catch((error) => { console.error(error); process.exit(1); });
