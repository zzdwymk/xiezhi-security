// Regression test: the turn-rail preview tooltip must leave nothing behind.
//
// Symptom this guards against: hovering a rail mark then moving the pointer away
// used to leave a small empty dark rounded box next to the rail. The card content
// was gated on `hoveredTurn` (cleared immediately) while the popper shell kept
// Element Plus's default fade transition, which keeps the node painted for ~180ms.
// The fix uses an instant transition, so the shell leaves the layout in one frame.
//
// Run: node scripts/test-turn-rail-tooltip-leftover.cjs
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright-core');

const webRoot = path.resolve(__dirname, '..');
const distDir = path.join(webRoot, 'dist');
const outDir = path.resolve(webRoot, '..', '.run', 'turn-rail-tooltip');
fs.mkdirSync(outDir, { recursive: true });

const BROWSERS = [
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
];
const executablePath = process.env.TRAFFIC_TEST_BROWSER || BROWSERS.find((item) => fs.existsSync(item));

const now = '2026-10-18T00:00:00Z';
const usage = {
  available: true, source: 'MIXED', model: 'fixture-model', modelCalls: 1,
  inputTokens: 1000, outputTokens: 100, totalTokens: 1100, cachedInputTokens: 200,
  cacheHitRatePermille: 190, contextWindowTokens: 200000, contextWindowUsedTokens: 36000,
  contextWindowUsagePermille: 180, peakInputTokens: 1100, providerReportedCalls: 1,
  estimatedCalls: 0, cacheReportedCalls: 1, cacheWriteTokens: 0, reasoningTokens: 0,
  estimatedInputTokens: 1000, lastInputTokens: 1100, contextWindowSource: 'MODEL', estimator: 'fixture',
};
const messages = [];
for (let i = 1; i <= 4; i += 1) {
  messages.push({ id: `u${i}`, role: 'user', content: `第 ${i} 轮提问内容`, status: 'completed', taskIds: [], steps: [], createdAt: now, updatedAt: now });
  messages.push({ id: `a${i}`, role: 'assistant', content: `第 ${i} 轮的回答。`, status: 'completed', provider: 'openai-compatible', taskIds: [], steps: [], agentEvents: [], modelUsage: usage, createdAt: now, updatedAt: now });
}
const conversation = { id: 'fixture-thread', title: '轮次横条测试', targetId: 1, targetName: '示例目标', messages, createdAt: now, updatedAt: now };

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

// Any painted tooltip node still occupying space counts as leftover.
const paintedTooltips = () => [...document.body.querySelectorAll('.turn-rail-tooltip')]
  .filter((el) => {
    const cs = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    return cs.display !== 'none' && cs.visibility !== 'hidden' && cs.opacity !== '0'
      && el.getAttribute('aria-hidden') !== 'true' && r.width > 1 && r.height > 1;
  })
  .map((el) => el.textContent.trim().slice(0, 16));

const failures = [];
function check(name, ok, detail) {
  console.log(`${ok ? '[PASS]' : '[FAIL]'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures.push(name);
}

(async () => {
  const server = await startStaticServer();
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ executablePath, headless: true });

  for (const viewport of [{ width: 1440, height: 900 }, { width: 1024, height: 700 }]) {
    const tag = `${viewport.width}x${viewport.height}`;
    const page = await browser.newPage({ viewport, deviceScaleFactor: 1 });
    page.setDefaultTimeout(25000);
    const errors = [];
    page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));

    await page.addInitScript((conv) => {
      localStorage.setItem('security_toolbox_token', 'fixture');
      localStorage.setItem('security_toolbox_ai_conversations_v2', JSON.stringify([conv]));
      localStorage.setItem('security_toolbox_setup_complete_v2', 'true');
      localStorage.setItem('security_toolbox_dashboard_target', '1');
    }, conversation);
    await page.route('**/api/**', (route) => {
      const p = new URL(route.request().url()).pathname;
      if (p.endsWith('/auth/me')) return route.fulfill({ json: { username: 'fixture', role: 'ADMIN' } });
      if (p.endsWith('/targets')) return route.fulfill({ json: [{ id: 1, name: '示例目标', targetValue: 'https://e.test', targetType: 'WEB', authorizationNote: 'x', allowedPorts: '80', enabled: true }] });
      if (p.endsWith('/tasks') || p.endsWith('/projects')) return route.fulfill({ json: [] });
      return route.fulfill({ json: {} });
    });

    await page.goto(`${base}/?conversation=${conversation.id}`, { waitUntil: 'commit' });
    await page.locator('.turn-rail').waitFor({ state: 'attached' });
    await page.waitForTimeout(1200);

    const marks = page.locator('.turn-rail-mark');
    const markCount = await marks.count();
    check(`${tag} 轮次横条已渲染`, markCount > 1, `实际 ${markCount}`);
    if (markCount < 2) { await page.close(); continue; }
    check(`${tag} 初始无悬停卡片`, (await page.evaluate(paintedTooltips)).length === 0);

    const box = await marks.nth(1).boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForTimeout(400);
    const hovered = await page.evaluate(paintedTooltips);
    check(`${tag} 悬停后显示预览卡片`, hovered.length === 1, `实际 ${JSON.stringify(hovered)}`);
    check(`${tag} 预览卡片内容完整`, (hovered[0] || '').includes('第 2 轮提问'), JSON.stringify(hovered));

    // Move away and sample from the next frame onward. The very first sample can
    // still observe the pre-flush state of the same task (the component has not
    // re-rendered yet), which is not a leftover; anything painted one frame later
    // is the bug this test guards (an empty shell lingering for ~180ms).
    await page.mouse.move(Math.round(viewport.width * 0.42), Math.round(viewport.height * 0.4));
    await page.waitForTimeout(20);
    let worst = [];
    for (let sample = 0; sample < 10; sample += 1) {
      const open = await page.evaluate(paintedTooltips);
      if (open.length > 0) worst = open;
      await page.waitForTimeout(25);
    }
    check(`${tag} 移走后不残留空框`, worst.length === 0, `残留 ${JSON.stringify(worst)}`);

    // Re-hovering still works after the pointer left.
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForTimeout(400);
    const again = await page.evaluate(paintedTooltips);
    check(`${tag} 再次悬停可正常显示`, again.length === 1, `实际 ${JSON.stringify(again)}`);
    await page.screenshot({ path: path.join(outDir, `rail-${tag}.png`) });

    check(`${tag} 无页面异常`, errors.length === 0, JSON.stringify(errors.slice(0, 3)));
    await page.close();
  }

  await browser.close();
  server.close();
  if (failures.length) {
    console.log(`\n${failures.length} 项失败：${failures.join('；')}`);
    process.exit(1);
  }
  console.log('\n生产构建（dist）检查通过：轮次预览卡片移走后不残留。');
})().catch((e) => { console.error(e); process.exit(1); });
