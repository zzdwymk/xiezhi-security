// Loads the REAL production bundle (dist/index.html + dist/assets/*.js) and drives
// the three composer stats pills to prove only one popover card can be open at a
// time. This exercises the exact JavaScript that ships in the desktop app, unlike
// the unit-style harness which mounts Dashboard.vue from source.
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright-core');

const webRoot = path.resolve(__dirname, '..');
const distDir = path.join(webRoot, 'dist');
const outDir = path.resolve(webRoot, '..', '.run', 'composer-stats-popovers');
fs.mkdirSync(outDir, { recursive: true });

const BROWSERS = [
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
];
const executablePath = process.env.TRAFFIC_TEST_BROWSER || BROWSERS.find((item) => fs.existsSync(item));

const now = '2026-10-18T00:00:00Z';
const modelUsage = {
  available: true, source: 'MIXED', model: 'fixture-model', modelCalls: 3,
  inputTokens: 75759, outputTokens: 2149, totalTokens: 77908, cachedInputTokens: 6784,
  cacheHitRatePermille: 80, contextWindowTokens: 200000, contextWindowUsedTokens: 46000,
  contextWindowUsagePermille: 230, peakInputTokens: 80000, providerReportedCalls: 3,
  estimatedCalls: 0, cacheReportedCalls: 3, cacheWriteTokens: 0, reasoningTokens: 0,
  estimatedInputTokens: 75759, lastInputTokens: 78543, contextWindowSource: 'MODEL', estimator: 'fixture',
};
const conversation = {
  id: 'fixture-thread', title: '统计卡片测试对话', targetId: 1, targetName: '示例目标',
  messages: [
    { id: 'm1', role: 'user', content: '统计卡片只能同时展开一个', status: 'completed', taskIds: [], steps: [], createdAt: now, updatedAt: now },
    { id: 'm2', role: 'assistant', content: '用于回归统计卡片互斥展开。', status: 'completed', provider: 'openai-compatible', taskIds: [], steps: [], agentEvents: [], modelUsage, progressStartedAt: now, progressFinishedAt: '2026-10-18T00:00:22Z', createdAt: now, updatedAt: now },
  ],
  createdAt: now, updatedAt: now,
};

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.png': 'image/png', '.ico': 'image/x-icon',
};

function startStaticServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const url = decodeURIComponent((req.url || '/').split('?')[0]);
      let file = path.join(distDir, url === '/' ? '/index.html' : url);
      if (!file.startsWith(distDir) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
        file = path.join(distDir, 'index.html');
      }
      res.setHeader('Content-Type', MIME[path.extname(file)] || 'application/octet-stream');
      res.end(fs.readFileSync(file));
    });
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

const visibleCards = () => [...document.body.querySelectorAll('.stats-pill-popover')]
  .filter((el) => {
    const s = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    return s.display !== 'none' && s.visibility !== 'hidden' && s.opacity !== '0'
      && el.getAttribute('aria-hidden') !== 'true' && r.width > 0 && r.height > 0;
  })
  .map((el) => el.querySelector('strong')?.textContent?.trim() || '(card)');

const failures = [];
function check(name, ok, detail) {
  console.log(`${ok ? '[PASS]' : '[FAIL]'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures.push(name);
}

(async () => {
  if (!fs.existsSync(path.join(distDir, 'index.html'))) {
    console.error('dist/index.html missing — run npm run build first');
    process.exit(2);
  }
  const server = await startStaticServer();
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  const browser = await chromium.launch({ executablePath, headless: true });

  for (const viewport of [{ width: 1440, height: 900 }, { width: 1024, height: 700 }]) {
    const tag = `${viewport.width}x${viewport.height}`;
    const page = await browser.newPage({ viewport, deviceScaleFactor: 1 });
    page.setDefaultTimeout(25000);
    const errors = [];
    page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));

    // Seed session + conversation BEFORE the app boots, and stub every API call.
    await page.addInitScript((conv) => {
      localStorage.setItem('security_toolbox_token', 'fixture');
      localStorage.setItem('security_toolbox_ai_conversations_v2', JSON.stringify([conv]));
      localStorage.setItem('security_toolbox_setup_complete_v2', 'true');
      localStorage.setItem('security_toolbox_dashboard_target', '1');
    }, conversation);

    await page.route('**/api/**', (route) => {
      const p = new URL(route.request().url()).pathname;
      if (p.endsWith('/auth/me')) return route.fulfill({ json: { username: 'fixture', role: 'ADMIN' } });
      if (p.endsWith('/targets')) {
        return route.fulfill({ json: [{ id: 1, name: '示例目标', targetValue: 'https://example.test', targetType: 'WEB', authorizationNote: '授权', allowedPorts: '80,443', enabled: true }] });
      }
      if (p.includes('dashboard')) return route.fulfill({ json: {} });
      if (p.endsWith('/tasks')) return route.fulfill({ json: [] });
      if (p.endsWith('/projects')) return route.fulfill({ json: [] });
      return route.fulfill({ json: {} });
    });

    // Load the real bundle in web mode (no ?desktop=1) so the seeded setup flag
    // and auth token are honoured instead of being cleared by the desktop gate.
    await page.goto(`${base}/?conversation=${conversation.id}`, { waitUntil: 'commit' });
    await page.locator('.composer-stats-bar').waitFor({ state: 'attached', timeout: 25000 })
      .catch(async () => {
        await page.evaluate((id) => { location.href = `/?conversation=${id}`; }, conversation.id);
        await page.locator('.composer-stats-bar').waitFor({ state: 'attached', timeout: 25000 });
      });
    await page.waitForTimeout(1500);

    const pills = page.locator('.composer-stats-bar .stats-pill');
    const count = await pills.count();
    check(`${tag} 三个胶囊渲染`, count === 3, `实际 ${count}`);
    if (!count) { await page.close(); continue; }
    check(`${tag} 初始无展开卡片`, (await page.evaluate(visibleCards)).length === 0);

    for (let i = 0; i < count; i += 1) {
      await pills.nth(i).click();
      await page.waitForTimeout(400);
      const open = await page.evaluate(visibleCards);
      check(`${tag} 点击第 ${i + 1} 个胶囊仅一张卡片`, open.length === 1, `展开 ${JSON.stringify(open)}`);
    }
    await page.screenshot({ path: path.join(outDir, `dist-${tag}.png`) });

    // Rapid succession: click all three as fast as possible, then settle.
    for (let i = 0; i < count; i += 1) { await pills.nth(i).click(); }
    await page.waitForTimeout(600);
    const afterRapid = await page.evaluate(visibleCards);
    check(`${tag} 连点三个胶囊后仍只有一张卡片`, afterRapid.length <= 1, `展开 ${JSON.stringify(afterRapid)}`);

    // Simulate the stats recompute the real app triggers (polling/events) and
    // ensure a re-render does not resurrect a second card.
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await page.waitForTimeout(800);
    check(`${tag} 重渲染后仍只有一张卡片`, (await page.evaluate(visibleCards)).length <= 1);

    check(`${tag} 无页面异常`, errors.length === 0, JSON.stringify(errors.slice(0, 3)));
    await page.close();
  }

  await browser.close();
  server.close();
  if (failures.length) {
    console.log(`\n${failures.length} 项失败：${failures.join('；')}`);
    process.exit(1);
  }
  console.log('\n生产构建（dist）检查通过：统计卡片互斥展开。');
})().catch((e) => { console.error(e); process.exit(1); });

