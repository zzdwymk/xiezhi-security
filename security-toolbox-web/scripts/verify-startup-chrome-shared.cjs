/*
 * Verification (one-off): the splash page and the Vue app must render the
 * workspace card at the same distance from the window frame.
 *
 * Both surfaces now read their frame geometry from a single stylesheet,
 * electron/desktop-chrome.css:
 *   - src/unified-theme.css @imports it (bundled into dist/);
 *   - electron/startup.html links it directly (<link rel="stylesheet">).
 *
 * This loads the real splash over file:// so the production CSP
 * (style-src 'self' 'unsafe-inline') applies, and asserts the linked sheet
 * actually loads and that the measured gap matches the token.
 */
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const startupEntry = path.join(root, 'electron', 'startup.html');

(async () => {
  const browser = await chromium.launch({
    executablePath:
      process.env.SETUP_TEST_BROWSER ||
      'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
    args: ['--allow-file-access-from-files'],
  });
  try {
    const page = await browser.newPage({ viewport: { width: 900, height: 620 } });
    const cspViolations = [];
    page.on('console', (msg) => {
      const text = msg.text();
      // 'frame-ancestors' is only honoured in a real response header; the meta
      // tag delivery note is pre-existing noise, not a blocked resource.
      if (/frame-ancestors' is ignored/i.test(text)) return;
      if (/Content Security Policy|Refused to/i.test(text)) cspViolations.push(text);
    });
    page.on('pageerror', (err) => cspViolations.push(String(err)));

    await page.goto(pathToFileURL(startupEntry).href);
    await page.waitForLoadState('load');

    const result = await page.evaluate(() => {
      const cs = getComputedStyle(document.documentElement);
      const workspace = document.querySelector('.workspace');
      const rect = workspace.getBoundingClientRect();
      return {
        gap: cs.getPropertyValue('--desktop-workspace-gap').trim(),
        radius: cs.getPropertyValue('--fluent-workspace-radius').trim(),
        sheets: [...document.styleSheets].map((sheet) => ({
          href: sheet.href ? sheet.href.split(/[\\/]/).pop() : '(inline)',
          rules: (() => {
            try {
              return sheet.cssRules.length;
            } catch {
              return -1;
            }
          })(),
        })),
        measured: {
          right: Math.round(window.innerWidth - rect.right),
          bottom: Math.round(window.innerHeight - rect.bottom),
          radius: getComputedStyle(workspace).borderRadius,
        },
      };
    });

    const expected = Number.parseFloat(result.gap);
    assert.ok(expected > 0, 'workspace gap token must resolve');
    assert.equal(result.radius, '8px', 'workspace radius must come from the shared sheet');
    assert.equal(result.measured.right, expected, 'splash right inset must equal the shared gap');
    assert.equal(result.measured.bottom, expected, 'splash bottom inset must equal the shared gap');
    assert.deepEqual(cspViolations, [], 'no CSP violations on the splash');
    const sharedSheet = result.sheets.find((sheet) => sheet.href === 'desktop-chrome.css');
    assert.ok(sharedSheet, 'desktop-chrome.css must be linked');
    assert.ok(sharedSheet.rules > 0, 'desktop-chrome.css rules must load before CSP blocks them');

    console.log('PASS splash shares window geometry');
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error('FAIL', error);
  process.exitCode = 1;
});
