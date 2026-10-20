/*
 * Verification (one-off): the Vue app resolves the same window geometry tokens
 * it used to declare inline in src/unified-theme.css, now that they are
 * @imported from electron/desktop-chrome.css.
 *
 * Serves src/ through Vite (so the @import chain is exercised exactly as in a
 * real build) and probes the computed custom properties plus a rendered
 * workspace card on the production-like desktop frame.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createServer } = require('vite');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');

const html = `<!doctype html><html lang="zh-CN" data-system-theme="light" data-caption-mode="solid"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>html,body{height:100%;margin:0}</style>
<link rel="stylesheet" href="/src/unified-theme.css">
</head><body>
<div class="desktop-v2-app-frame desktop-v2-native-frame" id="frame">
  <header class="desktop-v2-native-titlebar"></header>
  <div class="desktop-v2-shell" style="--desktop-sidebar-width:260px">
    <aside class="desktop-v2-sidebar" style="width:260px"></aside>
    <section class="desktop-v2-workspace" id="workspace"><div class="desktop-v2-topbar"></div></section>
  </div>
</div>
</body></html>`;

(async () => {
  const server = await createServer({
    root,
    configFile: false,
    plugins: [
      {
        name: 'probe-html',
        configureServer(s) {
          s.middlewares.use((req, res, next) => {
            if (req.headers.accept?.includes('text/html') !== true) return next();
            res.setHeader('Content-Type', 'text/html');
            res.end(html);
          });
        },
      },
    ],
    server: { host: '127.0.0.1', port: 0, hmr: false },
    logLevel: 'error',
  });
  await server.listen();
  const url = `http://127.0.0.1:${server.httpServer.address().port}/`;
  const browser = await chromium.launch({
    executablePath:
      process.env.SETUP_TEST_BROWSER ||
      'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  try {
    const page = await browser.newPage({ viewport: { width: 1380, height: 860 } });
    await page.goto(url);
    await page.waitForLoadState('load');

    const result = await page.evaluate(() => {
      const cs = getComputedStyle(document.documentElement);
      const workspace = document.getElementById('workspace');
      const rect = workspace.getBoundingClientRect();
      const frame = document.getElementById('frame').getBoundingClientRect();
      return {
        gap: cs.getPropertyValue('--desktop-workspace-gap').trim(),
        radius: cs.getPropertyValue('--fluent-workspace-radius').trim(),
        titlebar: cs.getPropertyValue('--desktop-titlebar-height').trim(),
        sidebarDefault: cs.getPropertyValue('--desktop-default-sidebar-width').trim(),
        fluentXlarge: cs.getPropertyValue('--fluent-radius-xlarge').trim(),
        cardRadius: cs.getPropertyValue('--fluent-radius-card').trim(),
        measured: {
          right: Math.round(frame.right - rect.right),
          bottom: Math.round(frame.bottom - rect.bottom),
          radius: getComputedStyle(workspace).borderRadius,
        },
      };
    });

    assert.equal(result.gap, '5px', 'workspace gap token must still resolve in the app');
    assert.equal(result.radius, '8px', 'workspace radius token must still resolve in the app');
    assert.equal(result.titlebar, '38px', 'caption height token must still resolve');
    assert.equal(result.sidebarDefault, '260px', 'default sidebar width token must resolve');
    assert.equal(result.fluentXlarge, '8px', 'Fluent radius scale must be untouched');
    assert.equal(result.cardRadius, '8px', 'card radius alias must still track xlarge');
    assert.equal(result.measured.right, 5, 'workspace right inset must be 5px');
    assert.equal(result.measured.bottom, 5, 'workspace bottom inset must be 5px');
    assert.equal(result.measured.radius, '8px', 'workspace radius must be 8px');

    console.log('PASS app resolves shared window geometry');
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await browser.close();
    await server.close();
  }
})().catch((error) => {
  console.error('FAIL', error);
  process.exitCode = 1;
});
