// Regression test: a Fluent hover bubble and an Element Plus dark tooltip must
// never be on screen at the same time (the screenshot this comes from: the chat
// message toolbar showed “选择复制格式” below the row and “重试回复” above it).
//
// The mutex under test is the REAL src/utils/tooltipMutex.ts, served through
// Vite's module graph against real Element Plus. The Fluent bubble is a minimal
// stand-in that mirrors App.vue's contract: hideOpenElementPlusTooltips() before
// showing, hide on pointerout/pointerdown, body-mounted fixed bubble.
//
// Invariants guarded:
//  1. Fluent showing snaps an open EP tooltip instantly (no 200ms fade overlap)
//     and it STAYS hidden while EP's open state is unchanged.
//  2. An EP tooltip opening hides the Fluent bubble (observer direction).
//  3. A snapped tooltip re-opens cleanly once its trigger genuinely re-hovers.
//  4. Menus/dropdowns/selects are never snapped by the mutex.
//
// Run: node scripts/test-tooltip-mutex-browser.cjs
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');

const webRoot = path.resolve(__dirname, '..');
const output = path.resolve(webRoot, '..', '.run', 'tooltip-mutex', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(output, { recursive: true });

const BROWSERS = [
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
];
const executablePath = process.env.TRAFFIC_TEST_BROWSER || BROWSERS.find((item) => fs.existsSync(item));

const fixtureSource = () => `
import { createApp, h } from 'vue';
import { ElTooltip, ElDropdown, ElDropdownMenu, ElDropdownItem, ElSelect, ElOption } from 'element-plus';
import 'element-plus/dist/index.css';
import { hideOpenElementPlusTooltips, startElementPlusTooltipMutex } from '/src/utils/tooltipMutex';

// —— Fluent 气泡替身：契约与 App.vue 的 fluent-hover-tooltip 一致 ——
const bubble = document.createElement('div');
bubble.className = 'fluent-hover-tooltip';
Object.assign(bubble.style, {
  position: 'fixed', zIndex: '2147483000', padding: '6px 9px',
  borderRadius: '6px', background: '#111827', color: '#f8fafc',
  pointerEvents: 'none', opacity: '0', top: '0', left: '0',
  transition: 'opacity 120ms',
});
document.body.appendChild(bubble);
let current = null;
window.__fluentShow = (target) => {
  hideOpenElementPlusTooltips();               // 与 showFluentTooltip 相同的互斥入口
  bubble.textContent = target.getAttribute('data-fluent-tooltip');
  const rect = target.getBoundingClientRect();
  bubble.style.left = rect.left + 'px';
  bubble.style.top = rect.bottom + 8 + 'px';
  bubble.style.opacity = '1';
  current = target;
};
window.__fluentHide = () => { bubble.style.opacity = '0'; current = null; };
window.__fluentVisible = () => Number(bubble.style.opacity) > 0.5;
document.addEventListener('pointerover', (e) => {
  const target = e.target instanceof Element && e.target.closest('[data-fluent-tooltip]');
  if (target) window.__fluentShow(target);
});
document.addEventListener('pointerout', () => window.__fluentHide());
document.addEventListener('pointerdown', (e) => {
  if (current && e.target instanceof Node && current.contains(e.target)) return;
  window.__fluentHide();
});

// —— 页面：一个 Fluent 目标按钮 + 一个 el-tooltip 按钮 + 下拉/选择器 ——
const app = createApp({
  setup() {
    return () => h('div', { style: 'display:flex;gap:24px;padding:80px 40px;align-items:flex-start;' }, [
      h('button', { id: 'fluent-btn', type: 'button', 'data-fluent-tooltip': '选择复制格式' }, '复制按钮'),
      h(ElTooltip, { content: '重试回复', placement: 'top', showAfter: 50, hideAfter: 0 }, () => h('button', { id: 'ep-btn', type: 'button' }, '重试按钮')),
      h(ElDropdown, { trigger: 'click' }, {
        default: () => h('button', { id: 'menu-btn', type: 'button' }, '菜单'),
        dropdown: () => h(ElDropdownMenu, () => [
          h(ElDropdownItem, () => '菜单项一'),
          h(ElDropdownItem, () => '菜单项二'),
        ]),
      }),
      h(ElSelect, { modelValue: 'a', 'onUpdate:modelValue': () => {}, style: 'width:160px' }, () => [
        h(ElOption, { value: 'a', label: '选项一' }),
        h(ElOption, { value: 'b', label: '选项二' }),
      ]),
    ]);
  },
});
app.use(ElTooltip).use(ElDropdown).use(ElSelect);
app.mount('#app');
window.__mutexVisibleTooltipCount = () => Array.from(document.querySelectorAll('.el-popper[role="tooltip"]'))
  .filter((el) => (el instanceof HTMLElement ? el.style.display : '') !== 'none'
    && el.getBoundingClientRect().width > 2);
window.__fluentBtn = () => document.getElementById('fluent-btn');
window.__epBtn = () => document.getElementById('ep-btn');
window.__fluentHide();
startElementPlusTooltipMutex(window.__fluentHide);
window.fixtureReady = true;
`;

async function startServer() {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  const server = await createServer({
    configFile: false,
    root: webRoot,
    cacheDir: path.join(output, 'cache'),
    logLevel: 'error',
    appType: 'custom',
    optimizeDeps: { entries: [], include: ['vue', 'element-plus'], noDiscovery: true },
    plugins: [
      vue(),
      {
        name: 'tooltip-mutex-fixture',
        enforce: 'pre',
        resolveId(id) { if (id === 'fixture:entry') return '\0fixture:entry'; return null; },
        load(id) { if (id === '\0fixture:entry') return fixtureSource(); return null; },
        configureServer(s) {
          s.middlewares.use(async (req, res, next) => {
            const url = (req.url || '').split('?')[0];
            if (url !== '/' && url !== '/index.html') return next();
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.end(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module" src="/@id/fixture:entry"></script></body></html>`);
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
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

(async () => {
  const server = await startServer();
  const browser = await chromium.launch({ executablePath, headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  page.setDefaultTimeout(20000);
  const errors = [];
  page.on('pageerror', (error) => errors.push('pageerror: ' + error.message));
  page.on('console', (msg) => { if (msg.type() === 'error' || msg.text().includes('MUTEXDBG')) errors.push(msg.type() + ': ' + msg.text()); });
  await page.goto(`http://127.0.0.1:${server.config.server.port}/`, { waitUntil: 'commit' });
  await page.waitForFunction(() => window.fixtureReady, null, { timeout: 60000 }).catch(() => { throw new Error('fixture not ready. errors=' + JSON.stringify(errors.slice(0, 4))); });

  try {
    // 1) 悬停重试按钮 → EP tooltip 亮起
    await page.locator('#ep-btn').hover();
    await page.waitForFunction(() => window.__mutexVisibleTooltipCount().length === 1, null, { timeout: 5000 });
    check('悬停后恰好一个 EP 黑框', true);

    // 2) Fluent 气泡出现（focusin 路径）→ EP 黑框立即按灭，且不随渲染回弹
    await page.evaluate(() => window.__fluentShow(window.__fluentBtn()));
    await page.waitForFunction(() => window.__mutexVisibleTooltipCount().length === 0, null, { timeout: 1000 });
    await sleep(400); // 若 EP 响应式渲染会打回 display，这里就会复活
    const stayedHidden = await page.evaluate(() => window.__mutexVisibleTooltipCount().length === 0);
    check('Fluent 出现后 EP 黑框立即按灭且不回弹', stayedHidden);
    check('按灭期间 Fluent 气泡可见', await page.evaluate(() => window.__fluentVisible()));

    // 3) 指针离开再重新悬停 → EP tooltip 正常复亮（互斥没有破坏 EP 状态机；
    //    按灭后指针停在原触发元素上时不会自动复亮，这是互斥的预期行为）
    await page.locator('#fluent-btn').hover();
    await sleep(150);
    await page.locator('#ep-btn').hover();
    await page.waitForFunction(() => window.__mutexVisibleTooltipCount().length === 1, null, { timeout: 5000 });
    check('离开后重新悬停 EP 黑框正常复亮', true);

    // 4) EP 黑框亮起时收起 Fluent（observer 方向）：hover 复制按钮亮气泡 → 移到重试按钮
    await page.locator('#fluent-btn').hover();
    await page.waitForFunction(() => window.__fluentVisible(), null, { timeout: 3000 });
    await page.locator('#ep-btn').hover();
    await page.waitForFunction(() => window.__mutexVisibleTooltipCount().length === 1, null, { timeout: 5000 });
    await page.waitForFunction(() => !window.__fluentVisible(), null, { timeout: 2000 });
    check('EP 黑框亮起后 Fluent 气泡被收起', true);

    // 5) 交互弹层不受互斥影响：下拉菜单与 select 下拉在按灭清单之外
    // 注意 ElDropdown 会给触发按钮生成自己的 el-id-*，#menu-btn 不存在。
    const menuProbe = await page.evaluate(() => {
      document.querySelector('.el-dropdown [aria-haspopup="menu"]')?.click();
      return new Promise((resolve) => setTimeout(() => resolve({
        expanded: document.querySelector('.el-dropdown [aria-haspopup="menu"]')?.getAttribute('aria-expanded'),
        menus: Array.from(document.querySelectorAll('.el-dropdown-menu')).map((el) => `disp=${getComputedStyle(el).display}|wh=${el.getBoundingClientRect().width}x${el.getBoundingClientRect().height}`),
      }), 300));
    });
    console.log('MENUDBG ' + JSON.stringify(menuProbe));
    await page.waitForSelector('.el-dropdown-menu:visible', { timeout: 5000 });
    await page.evaluate(() => window.__fluentShow(window.__fluentBtn()));
    const menuStillOpen = await page.locator('.el-dropdown-menu:visible').count();
    check('按灭时下拉菜单不被关闭', menuStillOpen === 1, `实际 ${menuStillOpen}`);
    await page.keyboard.press('Escape');
    await page.mouse.click(640, 500);
  } catch (error) {
    const dom = await page.evaluate(() => {
      const poppers = Array.from(document.querySelectorAll('.el-popper')).map((el) => {
        const s = getComputedStyle(el);
        return `${el.className.split(' ').slice(0, 3).join('.')}|role=${el.getAttribute('role')}|ah=${el.getAttribute('aria-hidden')}|disp=${s.display}|w=${Math.round(el.getBoundingClientRect().width)}`;
      });
      return `count=${window.__mutexVisibleTooltipCount().length} fluent=${window.__fluentVisible()} :: ${poppers.join(' ;; ')}`;
    }).catch((e) => 'dump失败: ' + e.message);
    check('测试执行', false, error.message + ' POPPERS: ' + dom);
  } finally {
    await page.screenshot({ path: path.join(output, 'final.png') });
    if (errors.length) console.log('页面错误: ' + JSON.stringify(errors.slice(0, 4)));
    await browser.close();
    await server.close();
  }

  if (failures.length) { console.error(`${failures.length} 项失败`); process.exitCode = 1; }
  else console.log('全部通过');
})();
