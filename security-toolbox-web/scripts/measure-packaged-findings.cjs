// Measures the real packaged desktop build (desktop-release/win-unpacked) instead
// of the Vite fixture, by pointing Playwright at the unpacked index.html on the
// file system. Reports the toolbar->table gap, page-root gap, and whether the
// findings filter row honours the latest flex rules.
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const unpacked = path.join(root, 'desktop-release', 'win-unpacked');
// The renderer lives inside app.asar; unpack dist/ next to it once so we can load
// the exact bytes Electron loads, over file:// just like the desktop shell does.
const extracted = path.join(root, '.run', 'packaged-renderer');
const indexHtml = path.join(extracted, 'dist', 'index.html');

if (!fs.existsSync(indexHtml)) {
  fs.mkdirSync(extracted, { recursive: true });
  const asarPath = path.join(unpacked, 'resources', 'app.asar');
  if (!fs.existsSync(asarPath)) {
    console.error('app.asar not found:', asarPath);
    process.exit(2);
  }
  const buf = fs.readFileSync(asarPath);
  const headerSize = buf.readUInt32LE(12);
  const header = JSON.parse(buf.subarray(16, 16 + headerSize).toString('utf8'));
  const walk = (node, prefix) => {
    const out = [];
    for (const [name, value] of Object.entries(node.files || {})) {
      const next = `${prefix}/${name}`;
      if (value.files) out.push(...walk(value, next));
      else out.push({ path: next, offset: Number(value.offset), size: value.size });
    }
    return out;
  };
  for (const file of walk(header, '')) {
    if (!file.path.startsWith('/dist/')) continue;
    const target = path.join(extracted, file.path.replace(/^\//, ''));
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, buf.subarray(16 + headerSize + file.offset, 16 + headerSize + file.offset + file.size));
  }
  console.log('extracted packaged renderer ->', extracted);
}

const finding = (id) => ({
  id, taskId: 1228, targetId: 289, projectId: 1,
  title: `CVE-2026-${String(id).padStart(4, '0')} 授权测试风险`,
  severity: id % 2 ? 'HIGH' : 'MEDIUM', status: 'OPEN', sourceTool: 'nuclei',
  description: 'Fixture risk description', evidence: 'Fixture finding evidence',
  remediation: 'Fixture repair advice', createdAt: '2026-10-25T07:15:28Z',
});

const PROBE = `(() => {
  const page = document.querySelector('.findings-page, .workspace-list-page');
  const bar = document.querySelector('.findings-filter-toolbar');
  const pane = document.querySelector('.findings-source-pane');
  const table = pane && pane.querySelector('.el-table');
  const rect = (el) => { if (!el) return null; const r = el.getBoundingClientRect(); return { top: Math.round(r.top), bottom: Math.round(r.bottom), h: Math.round(r.height) }; };
  return {
    pageClass: page ? page.className : null,
    pageGap: page ? getComputedStyle(page).gap : null,
    pageRowGap: page ? getComputedStyle(page).rowGap : null,
    pageDisplay: page ? getComputedStyle(page).display : null,
    pageChildren: page ? [...page.children].map(c => c.tagName + '.' + String(c.className).split(' ')[0]) : [],
    toolbar: rect(bar),
    toolbarMargin: bar ? getComputedStyle(bar).margin : null,
    table: rect(table),
    gapToolbarToTable: bar && table ? Math.round(table.getBoundingClientRect().top - bar.getBoundingClientRect().bottom) : null,
    tableMarginTop: table ? getComputedStyle(table).marginTop : null,
    pane: rect(pane),
    paneDisplay: pane ? getComputedStyle(pane).display : null,
    paneChildren: pane ? [...pane.children].map(c => c.tagName + '.' + String(c.className).split(' ')[0]) : [],
    sortFlex: (() => { const s = bar && bar.querySelector('.finding-filter-cell--sort'); return s ? getComputedStyle(s).flex : null; })(),
    searchFlex: (() => { const s = bar && bar.querySelector('.finding-filter-cell--search'); return s ? getComputedStyle(s).flex : null; })(),
    searchW: (() => { const s = bar && bar.querySelector('.finding-filter-cell--search'); return s ? Math.round(s.getBoundingClientRect().width) : null; })(),
    sortW: (() => { const s = bar && bar.querySelector('.finding-filter-cell--sort'); return s ? Math.round(s.getBoundingClientRect().width) : null; })(),
  };
})()`;

(async () => {
  const browser = await chromium.launch({
    executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 2070, height: 1293 } });
  page.setDefaultTimeout(30000);
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const api = url.pathname.replace(/^\/api/, '');
    if (api === '/findings') {
      const data = Array.from({ length: 6 }, (_, i) => finding(1000 + i));
      return route.fulfill({ json: { content: data, totalElements: data.length } });
    }
    if (api.startsWith('/auth/')) return route.fulfill({ json: { token: 't', tokenType: 'Bearer', expiresIn: 3600, user: { id: 1, username: 'admin', role: 'ADMIN' } } });
    if (api === '/tasks/control/status') return route.fulfill({ json: { maxConcurrentTasks: 3, availableConcurrentSlots: 3, maxConcurrentTasksPerTarget: 3, queueCapacity: 50, pendingTasks: 0, runningTasks: 0 } });
    return route.fulfill({ json: [] });
  });
  await page.addInitScript(() => {
    localStorage.setItem('security_toolbox_setup_complete_v2', 'true');
    localStorage.setItem('security_toolbox_token', 'parity-token');
  });
  // file:// URL: exactly how Electron loads the unpacked desktop build.
  await page.goto('file:///' + indexHtml.replace(/\\/g, '/') + '#/findings', { waitUntil: 'load' });
  await page.waitForTimeout(3000);
  await page.evaluate(() => document.documentElement.setAttribute('data-system-theme', 'light'));
  await page.waitForTimeout(800);
  const m = await page.evaluate(PROBE);
  console.log(JSON.stringify(m, null, 1));
  await page.screenshot({ path: path.join(root, '..', '.run', 'findings-task-parity', 'findings-packaged-2070.png'), clip: { x: 0, y: 0, width: 2070, height: 620 } });
  await browser.close();
})().catch((e) => { console.error('FAILED:', e && e.message); process.exitCode = 1; });
