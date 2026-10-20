/**
 * 右侧「对话轮次快速导航」tooltip 单例回归测试。
 *
 * 守护的不变量：鼠标在相邻横条之间划过时，任何一帧都**最多只有一张**预览卡片。
 *
 * 背景：改造前每个横条各挂一个 <el-tooltip>，Element Plus 为每个实例各跑一套
 * show-after / hide-after 计时器和渐隐过渡。横条间距只有约 17px，鼠标划过去时
 * 前一张卡片还在渐隐、后一张已经弹出，两张卡片就叠在一起。
 *
 * fixture 在 scripts/fixtures/turn-rail-tooltip.html，其中的样式由本脚本把
 * Dashboard.vue 的 .turn-rail 段落原样注入（PROBE_STYLES 占位），
 * 所以测试对象就是生产样式。
 *
 * 用法：node scripts/test-turn-rail-tooltip-browser.cjs
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../.run/turn-rail-tooltip', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(out, { recursive: true });

// 从 Dashboard.vue 原样抽取 turn-rail 相关样式。
const dashboard = fs.readFileSync(path.join(root, 'src/views/Dashboard.vue'), 'utf8');
const styleStart = dashboard.indexOf('.turn-rail {');
const styleEnd = dashboard.indexOf('/* DSH 同款底部性能与用量统计栏 */');
if (styleStart < 0 || styleEnd < 0) throw new Error('未能在 Dashboard.vue 中定位 turn-rail 样式');
const turnRailStyles = dashboard.slice(styleStart, styleEnd);

const fixtureSource = fs.readFileSync(path.join(__dirname, 'fixtures/turn-rail-tooltip.html'), 'utf8');
if (!fixtureSource.includes('/* PROBE_STYLES */')) throw new Error('fixture 缺少 PROBE_STYLES 占位');
const html = fixtureSource.replace('/* PROBE_STYLES */', turnRailStyles);

let server, browser, page;
const results = [];
const errors = [];

/** 只统计「真的画在屏幕上」的预览卡片。 */
const SAMPLER = `
window.__samples = [];
window.__visibleCards = () => Array.from(document.querySelectorAll('.el-popper.turn-rail-tooltip'))
  .filter((el) => {
    if (el.getAttribute('aria-hidden') === 'true') return false;
    const style = getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden') return false;
    if (Number(style.opacity) < 0.05) return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 2 && rect.height > 2;
  })
  .map((el) => {
    const rect = el.getBoundingClientRect();
    return {
      label: (el.querySelector('.turn-tooltip-header strong')?.textContent || '').trim(),
      top: Math.round(rect.top),
      height: Math.round(rect.height),
    };
  });
window.__startSampling = () => {
  window.__samples = [];
  window.__sampling = true;
  const tick = () => {
    if (!window.__sampling) return;
    window.__samples.push({ t: performance.now(), cards: window.__visibleCards() });
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
};
window.__stopSampling = () => { window.__sampling = false; return window.__samples; };
`;

async function check(name, fn) {
  const detail = await fn();
  results.push({ name, status: 'PASS', detail });
  console.log('PASS ' + name + (detail ? ' — ' + JSON.stringify(detail) : ''));
}

async function markGeometry() {
  return page.locator('.turn-rail-mark').evaluateAll((els) =>
    els.map((el) => {
      const r = el.getBoundingClientRect();
      return { x: r.x + r.width / 2, y: r.y + r.height / 2, top: r.top, bottom: r.bottom };
    }),
  );
}

/** 用真实鼠标从第 from 条横条逐帧滑到第 to 条横条，收集逐帧卡片数量。 */
async function sweep(fromIndex, toIndex) {
  const marks = await markGeometry();
  const from = marks[fromIndex];
  const to = marks[toIndex];
  if (!from || !to) throw new Error('横条索引越界');

  await page.mouse.move(from.x, from.y);
  await page.waitForTimeout(180);
  await page.evaluate(() => window.__startSampling());
  const steps = 6;
  for (let i = 1; i <= steps; i += 1) {
    await page.mouse.move(to.x, from.y + ((to.y - from.y) * i) / steps);
    await page.waitForTimeout(16);
  }
  await page.waitForTimeout(320);
  const samples = await page.evaluate(() => window.__stopSampling());
  const maxCards = samples.reduce((m, s) => Math.max(m, s.cards.length), 0);
  const multi = samples.filter((s) => s.cards.length > 1);
  return {
    frames: samples.length,
    maxSimultaneousCards: maxCards,
    overlapFrames: multi.length,
    overlapLabels: Array.from(new Set(multi.map((s) => s.cards.map((c) => c.label).join(' + ')))),
    pitch: Math.round(to.y - from.y),
    gap: Math.round(to.top - from.bottom),
  };
}

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({
    configFile: false,
    root,
    cacheDir: path.join(out, 'cache'),
    // 关掉依赖预扫描：仓库 tools/ 目录（metasploit 等）有数十万文件，
    // dep-scan 会遍历整棵树并卡死，与本测试无关。
    optimizeDeps: { entries: [], include: ['vue', 'element-plus'], noDiscovery: true },
    resolve: {
      // fixture 用字符串 template，需要带运行时编译器的 Vue 构建。
      alias: { vue: 'vue/dist/vue.esm-bundler.js' },
    },
    plugins: [
      vue(),
      {
        name: 'turn-rail-tooltip-fixture',
        configureServer(s) {
          s.middlewares.use(async (req, res, next) => {
            if (!req.url.startsWith('/__turn-rail-tooltip')) return next();
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.end(await s.transformIndexHtml(req.url, html));
          });
        },
      },
    ],
    server: {
      host: '127.0.0.1',
      port: 0,
      hmr: false,
      fs: { strict: false },
      watch: {
        ignored: ['**/desktop-release/**', '**/dist/**', '**/tools/**', '**/target/**', '**/.run/**'],
      },
    },
    logLevel: 'error',
  });
  await server.listen();
  const origin = 'http://127.0.0.1:' + server.httpServer.address().port;

  browser = await chromium.launch({
    executablePath: process.env.AI_PROGRESS_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  page = await browser.newPage({ viewport: { width: 900, height: 700 }, colorScheme: 'light' });
  page.setDefaultTimeout(15000);
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => {
    if (m.type() !== 'warning' && m.type() !== 'error') return;
    const text = m.text().slice(0, 300);
    // 无关噪声：fixture 没有 favicon，浏览器会报一次 404。
    if (/favicon/i.test(text) || /status of 404 \(Not Found\)/.test(text)) return;
    errors.push(`[${m.type()}] ${text}`);
  });

  await page.goto(origin + '/__turn-rail-tooltip', { timeout: 60000 });
  await page.waitForFunction(() => window.__railReady === true, null, { timeout: 60000 });
  // mount() 后 DOM 更新在微任务里完成，等一帧再断言。
  await page.waitForTimeout(600);
  const rendered = await page.evaluate(() => document.querySelectorAll('.turn-rail-mark').length);
  if (rendered === 0) {
    const appHtml = await page.evaluate(() => (document.getElementById('app')?.innerHTML || '').slice(0, 600));
    throw new Error('导航条未渲染，app 内容：' + appHtml + ' 页面错误：' + errors.join(' | '));
  }
  await page.evaluate(SAMPLER);

  await check('导航条只渲染一个 tooltip 实例', async () => {
    const marks = await page.locator('.turn-rail-mark').count();
    assert.equal(marks, 5, '应当渲染 5 条横条，实际 ' + marks);
    // 单例判据：导航条里只有一处 tooltip 内容模板（悬停时才 teleport 出卡片），
    // 未悬停时不应存在任何 turn-rail-tooltip 卡片。
    const cardsBeforeHover = await page.evaluate(
      () => document.querySelectorAll('.el-popper.turn-rail-tooltip').length,
    );
    assert.equal(cardsBeforeHover, 0, '未悬停时不应存在卡片，实际 ' + cardsBeforeHover);
    return { marks, cardsBeforeHover };
  });

  await check('悬停单条横条只出现一张卡片', async () => {
    await page.locator('.turn-rail-mark').nth(1).hover();
    await page.waitForTimeout(220);
    const cards = await page.evaluate(() => window.__visibleCards());
    assert.equal(cards.length, 1, '应当只有一张卡片，实际 ' + JSON.stringify(cards));
    assert.match(cards[0].label, /第 2 轮提问/);
    return { label: cards[0].label };
  });

  await check('相邻横条快速划过不出现两张卡片', async () => {
    const forward = await sweep(1, 2);
    assert.equal(forward.overlapFrames, 0, '正向划过出现重叠帧：' + JSON.stringify(forward));
    const backward = await sweep(2, 1);
    assert.equal(backward.overlapFrames, 0, '反向划过出现重叠帧：' + JSON.stringify(backward));
    const skip = await sweep(0, 4);
    assert.equal(skip.overlapFrames, 0, '跃过多条出现重叠帧：' + JSON.stringify(skip));
    return {
      forwardMax: forward.maxSimultaneousCards,
      backwardMax: backward.maxSimultaneousCards,
      skipMax: skip.maxSimultaneousCards,
      pitch: forward.pitch,
      gap: forward.gap,
    };
  });

  await check('快速来回甩动鼠标仍只保留一张卡片', async () => {
    const marks = await markGeometry();
    await page.evaluate(() => window.__startSampling());
    for (let round = 0; round < 6; round += 1) {
      for (const index of [0, 1, 2, 3, 4, 3, 2, 1]) {
        await page.mouse.move(marks[index].x, marks[index].y);
        await page.waitForTimeout(12);
      }
    }
    await page.waitForTimeout(300);
    const samples = await page.evaluate(() => window.__stopSampling());
    const maxCards = samples.reduce((m, s) => Math.max(m, s.cards.length), 0);
    assert.ok(maxCards <= 1, '甩动过程中同时出现 ' + maxCards + ' 张卡片');
    return { frames: samples.length, maxSimultaneousCards: maxCards };
  });

  await check('移出导航条后卡片立即消失', async () => {
    await page.mouse.move(200, 200);
    await page.waitForTimeout(250);
    const cards = await page.evaluate(() => window.__visibleCards());
    assert.equal(cards.length, 0, '移出后仍有卡片：' + JSON.stringify(cards));
    return { remaining: cards.length };
  });

  await check('键盘聚焦横条同样只出现一张卡片', async () => {
    await page.locator('.turn-rail-mark').first().focus();
    await page.waitForTimeout(220);
    const cards = await page.evaluate(() => window.__visibleCards());
    assert.equal(cards.length, 1, '聚焦时应当正好一张卡片，实际 ' + JSON.stringify(cards));
    await page.locator('.turn-rail-mark').nth(2).focus();
    await page.waitForTimeout(220);
    const next = await page.evaluate(() => window.__visibleCards());
    assert.equal(next.length, 1, '切换焦点后应当仍只有一张卡片：' + JSON.stringify(next));
    assert.match(next[0].label, /第 3 轮提问/);
    return { label: next[0].label };
  });

  await page.screenshot({ path: path.join(out, 'turn-rail.png') });

  assert.deepEqual(errors, [], '页面报错：' + errors.join(' | '));
  fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify({ status: 'PASS', results }, null, 2));
  console.log('\n' + results.length + ' turn-rail tooltip checks passed.');
})().catch((error) => {
  fs.writeFileSync(
    path.join(out, 'results.json'),
    JSON.stringify({ status: 'FAIL', results, errors, message: String((error && error.message) || error) }, null, 2),
  );
  console.error('FAIL ' + ((error && error.stack) || error));
  process.exitCode = 1;
}).finally(async () => {
  try { await browser?.close(); } catch { /* ignore */ }
  try { await server?.close(); } catch { /* ignore */ }
});
