// Renders 安全发现 and 检测任务 with the real App.vue shell, real router and the
// real Element Plus build, against isolated API fixtures, so the source-tab strip
// and the filter toolbar of both pages can be measured side by side with exactly
// the same theme, container width and control stack. Prints geometry for every
// viewport plus clipped screenshots for a visual before/after comparison.
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '../.run/findings-task-parity');
fs.mkdirSync(output, { recursive: true });
let server, browser;
const errors = [];

const html = `<!doctype html><html><head><meta charset="utf-8"><base href="/__parity/"></head><body><div id="app"></div><script type="module">
import '/src/main';
setTimeout(() => {
  const store = window.__pinia?.state?.value?.auth;
  window.__authDebug = { token: store?.token ?? null, user: store?.user ?? null, checked: store?.checked ?? null, hash: location.hash, setup: localStorage.getItem('security_toolbox_setup_complete_v2') };
}, 1500);
</script></body></html>`;

const finding = id => ({
  id,
  taskId: 1228,
  targetId: 289,
  projectId: 1,
  title: `CVE-2026-${String(id).padStart(4, '0')} 授权测试风险`,
  severity: id % 2 ? 'HIGH' : 'MEDIUM',
  status: 'OPEN',
  sourceTool: 'nuclei',
  description: 'Fixture risk description',
  evidence: 'Fixture finding evidence',
  remediation: 'Fixture repair advice',
  createdAt: '2026-10-25T07:15:28Z',
});
const task = (id, status) => ({
  id,
  projectId: 1,
  targetId: 289,
  toolCode: 'nmap_service_scan',
  status,
  progress: status === 'SUCCESS' ? 100 : 0,
  createdAt: '2026-10-25T07:15:28Z',
});

const PROBE = `(() => {
  const pick = (sel, scope = document) => {
    const el = scope.querySelector(sel);
    if (!el) return null;
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return {
      x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height),
      font: s.fontSize + '/' + s.fontWeight, pad: s.padding, color: s.color, bg: s.backgroundColor,
    };
  };
  const tabs = document.querySelector('.findings-source-tabs, .task-source-tabs');
  const tabStrip = tabs || null;
  const items = tabStrip ? [...tabStrip.querySelectorAll('.el-tabs__item')] : [];
  const activeBar = tabStrip ? tabStrip.querySelector('.el-tabs__active-bar') : null;
  const navWrap = tabStrip ? tabStrip.querySelector('.el-tabs__nav-wrap') : null;
  const bar = document.querySelector('.findings-filter-toolbar, .task-filter-bar');
  const head = document.querySelector('.desktop-v2-content > .panel > .section-head');
  const headActions = head ? head.querySelector('.section-head-actions') : null;
  const row = bar ? bar.querySelector('.finding-filter-row, .task-filter-row') : null;
  const rect = el => { if (!el) return null; const r = el.getBoundingClientRect(); return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) }; };
  return {
    head: rect(head),
    headButtons: headActions ? [...headActions.querySelectorAll('.el-button')].map(b => rect(b)) : [],
    tabs: rect(tabStrip),
    tabItems: items.map(el => ({
      ...rect(el),
      active: el.classList.contains('is-active'),
      color: getComputedStyle(el).color,
      weight: getComputedStyle(el).fontWeight,
      fontSize: getComputedStyle(el).fontSize,
      padding: getComputedStyle(el).padding,
    })),
    tabHeaderMargin: tabStrip ? getComputedStyle(tabStrip.querySelector('.el-tabs__header')).margin : null,
    tabNavAfter: navWrap ? getComputedStyle(navWrap, '::after').display : null,
    activeBar: activeBar ? { ...rect(activeBar), bg: getComputedStyle(activeBar).backgroundColor, radius: getComputedStyle(activeBar).borderRadius } : null,
    bar: bar ? { ...rect(bar), pad: getComputedStyle(bar).padding, gap: getComputedStyle(bar).columnGap, cols: getComputedStyle(bar).gridTemplateColumns, radius: getComputedStyle(bar).borderRadius, bg: getComputedStyle(bar).backgroundColor, border: getComputedStyle(bar).borderTopColor } : null,
    rowKids: row ? [...row.children].map(el => ({ cls: el.className, ...rect(el) })) : [],
    cells: bar ? [...bar.children].map(el => ({ cls: String(el.className).split(' ')[0], ...rect(el) })) : [],
    controlHeight: (() => {
      const c = bar ? bar.querySelector('.el-select, .el-input, .el-date-editor') : null;
      return c ? Math.round(c.getBoundingClientRect().height) : null;
    })(),
    firstAfter: (() => {
      if (!bar) return null;
      const next = bar.nextElementSibling;
      return next ? { tag: next.tagName, cls: next.className, ...rect(next) } : null;
    })(),
    table: (() => {
      const pane = document.querySelector('.findings-source-pane');
      const table = pane
        ? pane.querySelector('.traffic-records-table, .findings-filter-toolbar + .el-table, .el-table')
        : document.querySelector('.tasks-page .el-table');
      if (!table) return null;
      const s = getComputedStyle(table);
      const th = table.querySelector('th.el-table__cell');
      const td = table.querySelector('td.el-table__cell');
      const thS = th ? getComputedStyle(th) : null;
      const tdS = td ? getComputedStyle(td) : null;
      return {
        cls: table.className,
        ...rect(table),
        border: s.borderTopWidth + ' ' + s.borderTopColor,
        radius: s.borderRadius,
        bg: s.backgroundColor,
        thHeight: th ? Math.round(th.getBoundingClientRect().height) : null,
        thFont: thS ? thS.fontSize + '/' + thS.fontWeight : null,
        thBg: thS ? thS.backgroundColor : null,
        thPad: thS ? thS.padding : null,
        tdPad: tdS ? tdS.padding : null,
        tdFont: tdS ? tdS.fontSize : null,
        tableTop: table.getBoundingClientRect().top,
        paneTop: (document.querySelector('.findings-source-pane, .task-filter-bar') || document.body).getBoundingClientRect().top,
        /* 空态 / 状态区：表格是否还在、空态占多宽多高、是否有自带外框 */
        emptyWrap: (() => {
          const el = document.querySelector('.findings-source-pane .el-table__empty-block, .task-filter-bar + .empty-state, .task-list-empty, .tasks-page > .empty-state');
          if (!el) return null;
          const es = getComputedStyle(el);
          return {
            cls: String(el.className).slice(0, 60),
            ...rect(el),
            tableBorder: 'n/a',
          };
        })(),
        emptyState: (() => {
          const el = document.querySelector('.findings-source-pane .empty-state, .tasks-page > .empty-state');
          if (!el) return null;
          return { ...rect(el), cls: String(el.className) };
        })(),
        toolbar: (() => {
          const el = document.querySelector('.findings-filter-toolbar, .task-filter-bar');
          if (!el) return null;
          const kids = [...el.children].map(k => ({ cls: String(k.className).split(' ')[0], ...rect(k) }));
          const clr = el.querySelector('.finding-filter-clear, .task-filter-clear');
          return {
            ...rect(el),
            cols: getComputedStyle(el).gridTemplateColumns,
            rowGap: getComputedStyle(el).rowGap,
            rows: new Set(kids.map(k => k.y)).size,
            kids,
            clear: clr ? { text: clr.textContent.trim(), alignSelf: getComputedStyle(clr).alignSelf, justifySelf: getComputedStyle(clr).justifySelf, ...rect(clr) } : null,
            tag: (() => {
              const t = el.querySelector('.finding-task-filter-tag');
              return t ? { ...rect(t), span: getComputedStyle(t).gridColumn } : null;
            })(),
          };
        })(),
        cellPads: [...table.querySelectorAll('th.el-table__cell .cell, td.el-table__cell .cell')]
          .slice(0, 4)
          .map(el => getComputedStyle(el).padding),
        firstThTextX: (() => {
          const th = table.querySelector('th.el-table__cell .cell');
          if (!th) return null;
          const tableLeft = table.getBoundingClientRect().left;
          // 数字列/操作列居中，文字偏移不等于留白；因此同时给出列盒偏移与对齐方式，
          // 判断留白是否一致要看 cellPads。
          const thBox = th.parentElement;
          const textRect = document.createRange();
          textRect.selectNodeContents(th);
          return {
            thBoxX: Math.round(thBox.getBoundingClientRect().left - tableLeft),
            align: getComputedStyle(thBox).textAlign,
            textX: textRect.getBoundingClientRect().width
              ? Math.round(textRect.getBoundingClientRect().left - tableLeft)
              : null,
          };
        })(),
      };
    })(),
  };
})()`;

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  const Components = (await import('unplugin-vue-components/vite')).default;
  const { ElementPlusResolver } = await import('unplugin-vue-components/resolvers');
  server = await createServer({
    configFile: false,
    root,
    cacheDir: path.join(output, 'cache'),
    optimizeDeps: { include: ['vue', 'element-plus', 'pinia', 'vue-router'], noDiscovery: true },
    plugins: [
      vue(),
      // 与 vite.config.ts 相同的 Element Plus 按需引入解析器：否则 App.vue /
      // Tasks.vue 里的 el-* 组件全部解析失败，页面渲染不出来。
      Components({ dts: false, resolvers: [ElementPlusResolver({ importStyle: 'css' })] }),
      {
        // dayjs 在这里只有 CJS 包，浏览器直接加载会报 “does not provide an
        // export named 'default'”；改用它随包提供的 ESM 版本。
        name: 'dayjs-esm',
        enforce: 'pre',
        resolveId(source) {
          if (source === 'dayjs') return path.join(root, 'node_modules', 'dayjs', 'esm', 'index.js');
          if (source.startsWith('dayjs/plugin/')) {
            const name = source.replace('dayjs/plugin/', '').replace(/\.js$/, '');
            return path.join(root, 'node_modules', 'dayjs', 'esm', 'plugin', name, 'index.js');
          }
          return null;
        },
      },
      {
        name: 'findings-task-parity-fixture',
        configureServer(s) {
          s.middlewares.use(async (req, res, next) => {
            if (!req.url.startsWith('/__parity')) return next();
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.end(await s.transformIndexHtml(req.url, html));
          });
        },
      },
    ],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: null },
    logLevel: 'error',
  });
  await server.listen();
  browser = await chromium.launch({
    executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
  page.setDefaultTimeout(30000);
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => errors.push(`${m.type()}: ${m.text()}`));
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    const api = url.pathname.replace(/^\/api/, '');
    if (api === '/findings') {
      const data = process.env.PARITY_EMPTY === '1'
        ? []
        : Array.from({ length: 6 }, (_, i) => finding(1000 + i));
      return route.fulfill({ json: { content: data, totalElements: data.length } });
    }
    if (api === '/tasks') {
      return route.fulfill({ json: [task(1228, 'FAILED'), task(1227, 'FAILED'), task(1225, 'SUCCESS')] });
    }
    if (api === '/tasks/control/status') {
      return route.fulfill({ json: { maxConcurrentTasks: 3, availableConcurrentSlots: 3, maxConcurrentTasksPerTarget: 3, queueCapacity: 50, pendingTasks: 0, runningTasks: 0 } });
    }
    if (api === '/auth/me') {
      return route.fulfill({ json: { id: 1, username: 'admin', role: 'ADMIN', displayName: 'admin' } });
    }
    if (api.startsWith('/auth/')) {
      return route.fulfill({ json: { token: 'parity-token', tokenType: 'Bearer', expiresIn: 3600, user: { id: 1, username: 'admin', role: 'ADMIN' } } });
    }
    if (api.startsWith('/traffic/scans')) {
      const records = process.env.PARITY_EMPTY === '1'
        ? []
        : Array.from({ length: 4 }, (_, i) => ({
            id: 900 + i,
            engine: i % 2 ? 'XRAY' : 'ZAP',
            status: 'SUCCESS',
            url: `http://127.0.0.1:8080/authorized/target/${900 + i}`,
            host: '127.0.0.1',
            hitCount: i % 2 ? 3 : 0,
            createdAt: '2026-10-25T07:15:28Z',
          }));
      return route.fulfill({ json: { content: records, totalElements: records.length, totalPages: 1, number: 0, size: 10 } });
    }
    return route.fulfill({ json: [] });
  });
  await page.addInitScript(() => {
    localStorage.setItem('security_toolbox_setup_complete_v2', 'true');
    localStorage.setItem('security_toolbox_token', 'parity-token');
    sessionStorage.setItem('security_toolbox_session_token', 'parity-token');
  });

  const port = server.httpServer.address().port;
  const results = {};
  for (const route of ['findings', 'tasks', 'findings-traffic']) {
    for (const theme of ['light']) {
    await page.emulateMedia({ colorScheme: theme });
    await page.addInitScript(() => { localStorage.setItem('security_toolbox_theme', 'light'); });
    await page.addInitScript(r => { window.__parityRoute = r; }, route);
    await page.goto(`http://127.0.0.1:${port}/${route === 'findings-traffic' ? 'findings?source=traffic' : route}`, { waitUntil: 'networkidle' });
    // 与桌面端一致：3 分钟后先以“带来源任务筛选”进入项目发现（任务行「发现」跳转的形态）。
    if (process.env.PARITY_TASK_FILTER === '1' && route === 'findings') {
      await page.goto(`http://127.0.0.1:${port}/findings?taskId=1228`, { waitUntil: 'networkidle' });
    }
    await page.waitForTimeout(1200);
    await page.evaluate(() => {
      document.documentElement.setAttribute('data-system-theme', 'light');
    });
    await page.waitForTimeout(500);
    if (process.env.PARITY_DEBUG === '1') {
      console.log('DEBUG url', page.url());
      console.log('DEBUG body', (await page.evaluate(() => document.body.innerText)).slice(0, 800));
      console.log('DEBUG app', (await page.evaluate(() => document.querySelector('#app')?.innerHTML || '')).slice(0, 1200));
      console.log('DEBUG content', await page.evaluate(() => {
        const main = document.querySelector('.desktop-v2-content');
        if (!main) return 'no main';
        return [...main.children].map(el => el.tagName + '.' + el.className).join(' | ') + ' :: ' + main.innerHTML.slice(0, 200)
          + ' :: sidebar=' + Boolean(document.querySelector('.desktop-v2-sidebar'))
          + ' hash=' + location.hash
          + ' auth=' + JSON.stringify(window.__authDebug || null)
          + ' ls=' + JSON.stringify(Object.keys(localStorage));
      }));
      console.log('DEBUG errors', JSON.stringify(errors.slice(-12)));
    }
    await page.waitForSelector(route === 'tasks' ? '.tasks-page' : '.findings-page', { timeout: 30000 });
    const viewports = [1440, 1280, 1100];
    const perWidth = {};
    for (const width of viewports) {
      await page.setViewportSize({ width, height: 1000 });
      await page.waitForTimeout(600);
      perWidth[width] = await page.evaluate(PROBE);
      await page.screenshot({ path: path.join(output, `${route}-${width}.png`), clip: { x: 0, y: 0, width, height: 420 } });
    }
    results[route] = perWidth;
    }
  }

  for (const width of [1440, 1280, 1100]) {
    console.log(`\n================ viewport ${width} ================`);
    for (const route of ['findings', 'tasks', 'findings-traffic']) {
      const m = results[route][width];
      console.log(`\n[${route}]`);
      console.log(`  head           ${JSON.stringify(m.head)}  buttons=${JSON.stringify(m.headButtons)}`);
      console.log(`  tabs           ${JSON.stringify(m.tabs)} headerMargin=${m.tabHeaderMargin} navAfter=${m.tabNavAfter}`);
      for (const item of m.tabItems) console.log(`    item ${JSON.stringify(item)}`);
      console.log(`  activeBar      ${JSON.stringify(m.activeBar)}`);
      console.log(`  bar            ${JSON.stringify(m.bar)}`);
      console.log(`  barCount       ${m.cells.length} controlHeight=${m.controlHeight}`);
      for (const c of m.cells) console.log(`    cell ${c.cls.padEnd(30)} x=${String(c.x).padStart(5)} y=${String(c.y).padStart(4)} w=${String(c.w).padStart(4)} h=${c.h}`);
      console.log(`  rowKids        ${m.rowKids.map(k => `${String(k.cls).split(' ').pop()}:${k.w}x${k.h}@${k.x}`).join(' ')}`);
      console.log(`  nextAfter      ${JSON.stringify(m.firstAfter)}`);
      console.log(`  table          ${JSON.stringify(m.table)}`);
      console.log(`  toolbar        ${JSON.stringify(m.toolbar)}`);
    }
  }
  if (errors.length) {
    console.error('\npage errors:', errors);
    process.exitCode = 1;
  }  console.log(`\nScreenshots in ${output}`);
})()
  .catch(async error => {
    console.error('FAILED:', error && error.message);
    if (errors.length) console.error('page errors:', errors);
    await browser?.close();
    await server?.close();
    process.exitCode = 1;
  })
  .finally(async () => {
    await browser?.close();
    await server?.close();
  });

