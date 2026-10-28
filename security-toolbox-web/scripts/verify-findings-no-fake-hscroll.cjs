// 回归验证：「安全发现」列表页（项目发现 / 流量发现两个页签）不应出现
// 由 1~2px 边框误差引起的假横向滚动条，同时真实列溢出的横向滚动能力必须保留。
// 用法：node scripts/verify-findings-no-fake-hscroll.cjs
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '..', '.run', 'findings-hscroll');
fs.mkdirSync(output, { recursive: true });

const FINDING_COLS = [
  { prop: 'title', label: '名称', minWidth: 150 },
  { label: '等级', width: 75 },
  { prop: 'sourceTool', label: '工具', minWidth: 110 },
  { prop: 'targetId', label: '目标', width: 65 },
  { label: '发现时间', minWidth: 140 },
  { label: '状态', width: 115 },
  { label: '操作', minWidth: 288 },
];

const TRAFFIC_COLS = [
  { prop: 'id', label: '来源记录', width: 95 },
  { label: '引擎', width: 115 },
  { prop: 'url', label: '目标 URL', minWidth: 260 },
  { prop: 'hitCount', label: '告警数', width: 95 },
  { label: '操作', width: 190 },
];

const html = `<!doctype html>
<html lang="zh-CN" data-system-theme="light" data-caption-mode="solid">
<head><meta charset="utf-8"><base href="/__hs/"><title>hscroll</title>
<style>html,body{margin:0;height:100%;overflow:hidden;background:#fafaf9}</style></head>
<body>
<div id="app" style="height:100vh;display:flex">
  <div class="desktop-v2-shell desktop-v2-app-frame" style="display:flex;flex:1;min-width:0;height:100%;min-height:0">
    <main class="desktop-v2-content" style="flex:1;min-width:0;display:flex;flex-direction:column">
      <section class="panel findings-page workspace-list-page findings-tabbed-page">
        <div class="section-head">
          <div><h3>安全发现</h3><p>统一管理全量授权目标的漏洞发现、安全基线风险与技术证据。</p></div>
          <div class="finding-head-actions section-head-actions">
            <button class="el-button">刷新</button><button class="el-button">扫描差异</button><button class="el-button">清空</button>
          </div>
        </div>
        <div class="findings-source-tabs"><div style="height:40px"></div><div style="height:1px;background:var(--app-border)"></div></div>
        <div class="findings-source-pane findings-list-plane">
          <div class="findings-filter-toolbar">
            <div class="finding-filter-cell"><div style="height:32px;border:1px solid var(--app-border);border-radius:4px"></div></div>
            <div class="finding-filter-cell"><div style="height:32px;border:1px solid var(--app-border);border-radius:4px"></div></div>
            <div class="finding-filter-cell"><div style="height:32px;border:1px solid var(--app-border);border-radius:4px"></div></div>
            <div class="finding-filter-cell"><div style="height:32px;border:1px solid var(--app-border);border-radius:4px"></div></div>
            <div class="finding-filter-row"><div style="height:32px;flex:1;border:1px solid var(--app-border);border-radius:4px"></div></div>
          </div>
          <div class="findings-pagination" style="height:24px"></div>
        </div>
      </section>
    </main>
  </div>
</div>
<script type="module">
  import 'element-plus/es/components/table/style/css';
  import 'element-plus/es/components/table-column/style/css';
  import '/src/desktop-v2.css';
  import '/src/unified-theme.css';
  import '/src/fluent-design-2.css';
  import '/src/fluent-design-3.css';
  import { createApp, h } from 'vue';
  import { ElTable, ElTableColumn } from 'element-plus';

  const FINDING_COLS = ${JSON.stringify(FINDING_COLS)};
  const TRAFFIC_COLS = ${JSON.stringify(TRAFFIC_COLS)};

  let app = null;
  window.__render = (scenario) => {
    if (app) { app.unmount(); app = null; }
    const cols = scenario === 'traffic' ? TRAFFIC_COLS : FINDING_COLS;
    const hasRows = scenario === 'project';
    const data = hasRows
      ? [
          { id: 1, title: 'SQL 注入漏洞', sourceTool: 'nuclei', targetId: 7, status: 'OPEN' },
          { id: 2, title: '开放目录', sourceTool: 'nmap', targetId: 7, status: 'OPEN' },
          { id: 3, title: 'TLS 弱套件', sourceTool: 'httpx', targetId: 8, status: 'OPEN' },
        ]
      : [];
    const host = document.querySelector('.findings-list-plane');
    const pagination = host.querySelector('.findings-pagination');
    app = createApp({
      render() {
        return h(ElTable, { data, class: 'traffic-records-table', rowKey: 'id' }, {
          empty: () =>
            h('div', { class: 'empty-state' }, [
              h('strong', '暂无风险记录'),
              h('p', { style: 'margin:0' }, '任务产生的检查结果会显示在这里。'),
            ]),
          default: () => cols.map((c) => h(ElTableColumn, { key: c.label, ...c })),
        });
      },
    });
    // 真实页面上 .el-table 是 .findings-list-plane 的直接子元素，
    // 宿主选择器 "> .el-table" 依赖这一点；挂载后把节点提升到 list-plane 里。
    const tmp = document.createElement('div');
    app.mount(tmp);
    const tableEl = tmp.firstElementChild;
    host.insertBefore(tableEl, pagination);
  };
  window.__render(new URLSearchParams(location.search).get('scenario') || 'empty');
</script>
</body></html>`;

const PROBE = `(() => {
  const table = document.querySelector('.findings-list-plane .el-table');
  const wrap = table && table.querySelector('.el-scrollbar__wrap');
  const bar = table && table.querySelector('.el-scrollbar__bar.is-horizontal');
  const thumb = bar && bar.querySelector('.el-scrollbar__thumb');
  const cs = table && getComputedStyle(table);
  // 外框改为「表头 th / 数据 td 的 border 拼成」，不再依赖伪元素或 .el-table 的 border。
  const th = table && table.querySelector('th.el-table__cell');
  const thcs = th && getComputedStyle(th);
  const thFirst = table && table.querySelector('th.el-table__cell');
  const thLast = table && table.querySelector('th.el-table__cell:last-child');
  const lastTd = table && table.querySelector('.el-table__body tr:last-child td.el-table__cell:last-child');
  const inner = table && table.querySelector('.el-table__inner-wrapper');
  const ics = inner && getComputedStyle(inner);
  return {
    tableOffsetWidth: table && table.offsetWidth,
    tableClientWidth: table && table.clientWidth,
    wrapClientWidth: wrap && wrap.clientWidth,
    wrapScrollWidth: wrap && wrap.scrollWidth,
    fakeOverflowPx: wrap ? wrap.scrollWidth - wrap.clientWidth : null,
    epThinksHScrollable: !!(thumb && thumb.style.width),
    thumbWidth: (thumb && thumb.style.width) || '',
    tableBorder: cs ? cs.borderTopWidth + ' ' + cs.borderTopStyle : null,
    tableRadius: cs ? cs.borderTopLeftRadius : null,
    thTopBorder: thcs ? thcs.borderTopWidth + ' ' + thcs.borderTopStyle : null,
    thLeftBorder: thFirst ? getComputedStyle(thFirst).borderLeftWidth + ' ' + getComputedStyle(thFirst).borderLeftStyle : null,
    thRightBorder: thLast ? getComputedStyle(thLast).borderRightWidth + ' ' + getComputedStyle(thLast).borderRightStyle : null,
    lastTdBottomBorder: lastTd ? getComputedStyle(lastTd).borderBottomWidth + ' ' + getComputedStyle(lastTd).borderBottomStyle : null,
    innerRadius: ics ? ics.borderTopLeftRadius : null,
  };
})()`;

(async () => {
  const { createServer } = await import('vite');
  const Components = (await import('unplugin-vue-components/vite')).default;
  const { ElementPlusResolver } = await import('unplugin-vue-components/resolvers');
  const server = await createServer({
    configFile: false,
    root,
    cacheDir: path.join(output, 'cache'),
    optimizeDeps: { include: ['vue', 'element-plus'], noDiscovery: true },
    plugins: [
      Components({ dts: false, resolvers: [ElementPlusResolver({ importStyle: 'css' })] }),
      {
        name: 'hscroll-fixture',
        configureServer(s) {
          s.middlewares.use(async (req, res, next) => {
            if (!req.url.startsWith('/__hs')) return next();
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store');
            res.end(await s.transformIndexHtml(req.url, html));
          });
        },
      },
    ],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: null },
    logLevel: 'error',
  });
  await server.listen();
  const browser = await chromium.launch({
    executablePath: process.env.TRAFFIC_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });
  const port = server.httpServer.address().port;
  const page = await browser.newPage({ viewport: { width: 1920, height: 1294 } });
  page.setDefaultTimeout(30000);

  let failed = false;
  const fail = (msg) => { failed = true; console.log('  !! ' + msg); };

  const scenario = async (name, query, width) => {
    await page.setViewportSize({ width, height: 1294 });
    await page.goto('http://127.0.0.1:' + port + '/__hs/page.html' + query, { waitUntil: 'load' });
    await page.waitForSelector('.findings-list-plane .el-table', { timeout: 30000 });
    await page.waitForTimeout(450);
    const box = await page.evaluate(() => {
      const r = document.querySelector('.findings-list-plane .el-table').getBoundingClientRect();
      return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
    });
    // 鼠标划过表格：el-scrollbar 的 thumb 只有在 mousemove 后才有显示条件
    await page.mouse.move(box.x, box.y);
    await page.waitForTimeout(250);
    const m = await page.evaluate(PROBE);
    const barState = await page.evaluate(() => {
      const bar = document.querySelector('.findings-list-plane .el-table .el-scrollbar__bar.is-horizontal');
      if (!bar) return null;
      const cs = getComputedStyle(bar);
      const r = bar.getBoundingClientRect();
      return { display: cs.display, w: Math.round(r.width), h: Math.round(r.height) };
    });
    console.log('\n===== ' + name + ' @ ' + width + 'px =====');
    console.log(JSON.stringify({ ...m, barAfterHover: barState }, null, 1));
    await page.screenshot({ path: path.join(output, name + '-' + width + '.png'), clip: { x: 0, y: 300, width, height: 620 } });
    return m;
  };

  // 方案（用户已拍板）：外框用真 border 画在 .el-table 上，得到完美圆角；
  // border 会让 offsetWidth 多 2px（EP 据此认为可横向滚动），但那条「假横条」
  // 的视觉 chrome 已被 CSS 隐藏（bar display:none），且 wrap 用 overflow-x:auto
  // 保留真实列溢出的滚动能力。所以断言改为：
  //   - border 已生效（真外框，圆角 10px）
  //   - 横向 bar 在 hover 后仍不显示（用户看不到假条）
  //   - 窄视口真实溢出时 wrapScrollWidth > wrapClientWidth（滚动能力保留）
  // 1) 项目发现 · 空态
  for (const width of [1920, 1600, 1440]) {
    const m = await scenario('project-empty', '?scenario=empty', width);
    if (!/solid/.test(m.tableBorder || '')) fail('表格外框 border 未生效（空态 ' + width + 'px）: ' + m.tableBorder);
    if (m.tableRadius !== '10px') fail('表格圆角不是 10px: ' + m.tableRadius);
    if (m.barAfterHover && m.barAfterHover.display !== 'none') fail('假横向滚动条在 hover 后仍显示: ' + JSON.stringify(m.barAfterHover));
  }

  // 2) 项目发现 · 有数据
  {
    const m = await scenario('project-data', '?scenario=project', 1920);
    if (!/solid/.test(m.tableBorder || '')) fail('表格外框 border 未生效（有数据）: ' + m.tableBorder);
    if (m.barAfterHover && m.barAfterHover.display !== 'none') fail('假横向滚动条在 hover 后仍显示（有数据）');
  }

  // 3) 流量发现页签
  {
    const m = await scenario('traffic', '?scenario=traffic', 1920);
    if (m.barAfterHover && m.barAfterHover.display !== 'none') fail('假横向滚动条在 hover 后仍显示（流量发现）');
  }

  // 4) 真溢出：7 列在 640px 下必然超宽，wrap 必须真的横向可滚
  {
    const m = await scenario('project-narrow', '?scenario=project', 640);
    if (!(m.wrapScrollWidth > m.wrapClientWidth)) fail('窄视口下没有真实横向溢出，用例失效');
  }

  // 5) 外框圆角 + 内层裁切圆角
  {
    const m = await scenario('frame-visual', '?scenario=empty', 1920);
    if (m.tableRadius !== '10px') fail('表格圆角不是 10px: ' + m.tableRadius);
    if (m.innerRadius !== '10px') fail('inner-wrapper 圆角不是 10px: ' + m.innerRadius);
  }

  console.log('\n结果：' + (failed ? 'FAIL' : 'PASS'));
  await browser.close();
  await server.close();
  if (failed) process.exitCode = 1;
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});




