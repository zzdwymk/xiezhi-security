/**
 * Read-only acceptance against an existing, manually authenticated packaged EXE.
 * Usage: node tests/e2e/verify-all-features-live.cjs [--only=navigation,projects,tasks,...]
 * Attach only to loopback CDP 19229. Never launches/restarts/logs in, reads browser
 * storage, sends API requests, creates tasks, saves settings or deletes records.
 * All product actions are UI clicks/input; all 22 offline tools use known vectors
 * in the existing 78-case suite. Missing data is BLOCKED, never a silent PASS.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const { navigate, openSettings, sleep, selectOn } = require('./lib/ui.cjs');
const ROOT = path.resolve(__dirname, '../../..');
const OUT = path.join(ROOT, '.run/all-features-ui-test', new Date().toISOString().replace(/[:.]/g, '-'));
const onlyArg = process.argv.find(a => a.startsWith('--only='));
const only = onlyArg ? new Set(onlyArg.slice(7).split(',').filter(Boolean)) : null;
const projectArg = process.argv.find(a => a.startsWith('--project='));
const preferredProject = projectArg ? projectArg.slice(10) : '四目标实战全景测试项目-049988';
const results = [];
let page;
fs.mkdirSync(OUT, { recursive: true });
function must(ok, message) { if (!ok) throw new Error(message); }
function blocked(message) { const e = new Error(message); e.resultStatus = 'BLOCKED'; throw e; }
function save() {
  const record = { createdAt: new Date().toISOString(), method: 'Packaged EXE; UI clicks/input only; manually authenticated; read-only business checks', results };
  fs.writeFileSync(path.join(OUT, 'results.json'), JSON.stringify(record, null, 2));
  fs.writeFileSync(path.join(OUT, 'results.md'), '# 全功能 UI 验收\n\n缺少数据记为 BLOCKED；导航通过不等于业务执行通过。\n\n| 用例 | 结果 | 秒 | 说明 |\n| --- | --- | ---: | --- |\n' + results.map(r => `| ${r.id} | ${r.status} | ${r.seconds} | ${(r.error || r.note || '').replace(/[\r\n|]/g, ' ').slice(0, 450)} |`).join('\n'));
}
async function shot(id) {
  if (!page) return;
  // Raw traffic/log bodies and password fields are excluded from screenshots.
  await page.screenshot({ path: path.join(OUT, id.replace(/[^\w\u4e00-\u9fff-]/g, '_') + '.png'), fullPage: true,
    mask: [page.locator('input[type="password"], .traffic-detail-pane, .packet-content, pre, code')], timeout: 15000 });
}
async function closeDialogs() {
  // Only close controls are used: never infer an affirmative confirmation label.
  for (let i = 0; i < 4; i++) {
    const modal = page.locator('.el-dialog:visible, .el-message-box:visible').last();
    const close = modal.locator('.el-dialog__headerbtn, .el-message-box__headerbtn').first();
    if (!await close.isVisible().catch(() => false)) break;
    await close.click();
    await modal.waitFor({state:'hidden'});
  }
  await page.keyboard.press('Escape');
}
async function runCase(id, title, action) {
  const started = Date.now();
  console.log('START ' + id + ' ' + title);
  let row;
  try {
    const value = await action();
    row = { id, title, status: 'PASS', ...(typeof value === 'string' ? { note: value } : value) };
  } catch (error) {
    row = { id, title, status: error.resultStatus || 'FAIL', error: String(error.message).slice(0, 1200) };
  }
  row.seconds = +((Date.now() - started) / 1000).toFixed(1);
  await shot(id).catch(e => { row.screenshotError = String(e.message).slice(0, 160); });
  results.push(row); save();
  console.log(JSON.stringify({ id, status: row.status, seconds: row.seconds, error: row.error, note: row.note?.slice(0, 450) }));
  await closeDialogs().catch(() => {});
  return row;
}
async function waitRows(selector = '.el-table__row:visible') {
  for (let i = 0; i < 25; i++) {
    if (await page.locator(selector).count()) return page.locator(selector);
    if (i > 5 && await page.getByText(/无法连接后端|列表暂时不可用/).isVisible().catch(() => false)) throw new Error('后端列表不可用');
    await sleep(200);
  }
  blocked('当前没有可用于这项业务断言的已有记录；未创建测试数据');
}
async function filteredEmpty(input, selector = '.el-table__row:visible') {
  const original = await input.inputValue();
  try {
    await input.fill('__XIEZHI_ACCEPTANCE_NO_MATCH_0929__');
    for (let i = 0; i < 40; i++) {
      if (!(await page.locator(selector).count())) return;
      await sleep(200);
    }
    throw new Error('输入不存在的关键字后仍显示结果');
  } finally { await input.fill(original); await sleep(400); }
}
async function enterProject() {
  await navigate(page, '评估项目');
  const search = page.getByPlaceholder('搜索项目名称 / 负责人 / 说明');
  if (await search.isVisible()) await search.fill('');
  const rows = await waitRows();
  const preferred = rows.filter({ hasText: preferredProject });
  const row = await preferred.count() ? preferred.first() : rows.first();
  await row.getByRole('button', { name: '进入项目', exact: true }).click();
  await page.getByRole('tab', { name: '概览', exact: true }).waitFor();
}
async function projectTab(name) {
  if (!/\/projects\/\d+/.test(page.url())) await enterProject();
  const tab = page.getByRole('tab', { name, exact: true });
  await tab.click();
  const panelId = await tab.getAttribute('aria-controls');
  must(panelId, name + '页签没有关联面板');
  const panel = page.locator('[id="' + panelId + '"]');
  await panel.waitFor({ state: 'visible' });
  await sleep(400);
  return panel;
}
const cases = {
  async navigation() {
    const routes = [['AI 安全助手', /#\/(?:\?|$)/], ['红队工作流', /\/workflow/], ['评估项目', /\/projects/],
      ['授权目标', /\/targets/], ['资产拓扑', /\/assets\/topology/], ['主动检测', /\/vulnerabilities/],
      ['检测任务', /\/tasks/], ['结果中心', /\/findings/], ['流量分析', /\/traffic/], ['审计日志', /\/audits/], ['离线工具集', /\/offline-tools/]];
    for (const [name, expected] of routes) {
      await runCase('nav-' + name, name + '可达性', async () => {
        await navigate(page, name);
        must(expected.test(page.url()), name + '导航URL不匹配');
        return '通过侧栏按钮进入；此项只证明导航与页面装载';
      });
    }
    await openSettings(page);
    must(page.url().includes('/settings'), '系统设置导航失败');
    return '11个侧栏入口逐项记录，系统设置通过用户菜单进入';
  },
  async projects() {
    await navigate(page, '评估项目');
    await waitRows();
    await filteredEmpty(page.getByPlaceholder('搜索项目名称 / 负责人 / 说明'));
    await enterProject();
    const names = ['概览', '授权目标', '探测服务', '信息收集', '检测任务', '漏洞与复测', '安全行动', '审批与审计', 'AI 记忆', '项目报告'];
    for (const name of names) {
      await runCase('project-tab-' + name, '项目详情：' + name, async () => {
        const panel = await projectTab(name);
        must((await panel.innerText()).trim().length > 0, name + '内容为空');
        return '页签与只读内容可见；未发起探测、审批、删除或保存';
      });
    }
    return '项目搜索无匹配筛选与恢复通过；10个详情页签分别记录';
  },
  async targets() {
    await navigate(page, '授权目标');
    const rows = await waitRows();
    const count = await rows.count();
    await filteredEmpty(page.getByPlaceholder('搜索名称 / 地址 / 类型 / 授权记录'));
    must(await page.locator('.el-table__row:visible').count() > 0, '恢复筛选后目标消失');
    return `读取${count}个当前页授权目标；搜索、无匹配状态、恢复通过`;
  },
  async tasks() {
    await navigate(page, '检测任务');
    const rows = await waitRows();
    const taskId = (await rows.first().locator('td').first().innerText()).trim();
    must(/^\d+$/.test(taskId), '任务ID不是有效数字');
    const input = page.getByPlaceholder('搜任务 ID / 工具');
    await input.fill(taskId); await sleep(600);
    const match = page.locator('.el-table__row:visible').filter({ hasText: taskId }).first();
    await match.getByRole('button', { name: '详情', exact: true }).click();
    const d = page.locator('.el-dialog:visible').last(); await d.waitFor();
    must((await d.innerText()).includes(taskId), '详情未对应所选任务');
    await closeDialogs(); await input.fill('');
    return `任务${taskId}筛选和详情通过；未点击取消、重试或新建任务`;
  },
  async findings() {
    await navigate(page, '结果中心');
    await waitRows();
    await filteredEmpty(page.getByPlaceholder('搜索名称、等级、工具、规则...'));
    const row = (await waitRows()).first();
    await row.getByRole('button', { name: '详情', exact: true }).click();
    const d = page.locator('.el-dialog:visible').last(); await d.waitFor();
    must((await d.innerText()).length > 35, '漏洞详情无实质内容');
    await closeDialogs();
    await page.getByRole('button', { name: '扫描 Diff', exact: true }).click();
    const diffDialog = page.getByRole('dialog', { name: '扫描 Diff', exact: true });
    await diffDialog.getByText('选择基线任务', { exact: true }).waitFor();
    await diffDialog.getByText('选择当前任务', { exact: true }).waitFor();
    must(await diffDialog.getByRole('combobox').count() === 2, '扫描Diff没有两个任务选择框');
    return '结果搜索、详情和扫描Diff表单通过；未执行复测、状态修改或后续路径';
  },
  async catalog() {
    await navigate(page, '主动检测');
    const items = await waitRows('.catalog-list > button:visible');
    await items.first().click();
    const detail = page.locator('.vuln-detail-pane');
    for (const label of ['风险说明', '检测方式', '修复建议', '模板元数据']) {
      must((await detail.innerText()).includes(label), '知识库缺少' + label);
    }
    await filteredEmpty(page.getByPlaceholder('搜索 CVE、模板 ID、名称、标签'), '.catalog-list > button:visible');
    must(await page.locator('.scan-launcher-pane').isVisible(), '受控检测配置区不可见');
    return '既有知识条目详情与搜索通过，主动检测配置可见；未同步库或扫描';
  },
  async report() {
    await enterProject();
    const panel = await projectTab('项目报告');
    await panel.getByRole('button', { name: '刷新摘要', exact: true }).click();
    await panel.locator('.report-overview').waitFor({ timeout: 30000 });
    const metrics = await panel.locator('.report-overview__metrics .report-card').count();
    must(metrics > 0, '报告没有汇总指标');
    await panel.getByRole('button', { name: '项目 HTML', exact: true }).click();
    const frame = page.locator('.el-dialog:visible iframe'); await frame.waitFor({ timeout: 30000 });
    must(await frame.getAttribute('sandbox') === '', 'HTML报告预览沙箱不为空');
    const content = await frame.contentFrame().locator('body').innerText();
    must(content.length > 100, 'HTML预览无报告正文');
    await closeDialogs();
    const select = panel.locator('.target-report-toolbar .el-select');
    await select.click();
    const options = page.locator('.el-select-dropdown:visible li.el-select-dropdown__item');
    if (await options.count() < 2) { await page.keyboard.press('Escape'); blocked('项目HTML预览通过，但缺少单目标数据验证报告筛选'); }
    const firstTarget = await options.nth(1).innerText();
    await options.nth(1).click(); await sleep(500);
    must(!(await panel.getByRole('button', { name: '目标 HTML', exact: true }).isDisabled()), '选择目标后目标报告仍禁用');
    await selectOn(page, select, '全部目标', { exact: true });
    return `项目HTML有正文且sandbox严格隔离；${metrics}项汇总指标；单目标范围选择及恢复通过（${firstTarget.trim()}）`;
  },
  async topology() {
    await navigate(page, '资产拓扑');
    await page.getByRole('button', { name: '刷新拓扑', exact: true }).click();
    const graph = page.locator('.topology-wrapper'); await graph.waitFor();
    const nodes = graph.locator('.node-card-group:visible');
    for (let i = 0; i < 40 && !await nodes.count(); i++) await sleep(250);
    if (!await nodes.count()) blocked('拓扑页面已显示，但没有既有节点可验证');
    const count = await nodes.count();
    return `刷新后呈现${count}个拓扑节点；未移动、增删或修改资产`;
  },
  async workflow() {
    await navigate(page, '红队工作流');
    await page.locator('.flow-canvas, .vue-flow').first().waitFor();
    const nodes = await page.locator('.workflow-node:visible').count();
    if (!nodes) blocked('工作流画布存在，但没有节点可检查');
    await page.getByRole('button', { name: '工作流配置', exact: true }).click();
    const config = page.locator('#workflow-config-panel'); await config.waitFor();
    const text = await config.innerText();
    for (const label of ['评估项目', '授权目标', '工作流模板']) must(text.includes(label), '配置缺少' + label);
    await config.getByRole('button', { name: '关闭工作流配置', exact: true }).click();
    must(await page.locator('.phase-library').isVisible(), '阶段库不可见');
    must(await page.locator('.capability-library').isVisible(), '能力库不可见');
    return `${nodes}个工作流节点，项目/目标/模板配置与阶段/能力库可见；未保存或执行`;
  },
  async traffic() {
    await navigate(page, '流量分析');
    await page.getByRole('button', { name: '刷新流量', exact: true }).click();
    const rows = await waitRows('.traffic-row:visible');
    const before = await rows.count();
    await filteredEmpty(page.getByPlaceholder('筛选 URL、Host 或方法'), '.traffic-row:visible');
    await (await waitRows('.traffic-row:visible')).first().click();
    must(await page.getByRole('button', { name: '转交 AI 智能体', exact: true }).isVisible(), '流量明细未显示转交入口');
    return `${before}条当前页真实流量，列表过滤、恢复和选择明细通过；未启动代理、重放或拦截`;
  },
  async audits() {
    await navigate(page, '审计日志');
    const rows = await waitRows();
    const count = await rows.count();
    must(await page.locator('.audits-pagination').isVisible(), '审计分页不可见');
    const ai = page.getByRole('button', { name: 'AI 核查', exact: true });
    return `${count}条当前页审计记录、分页可见；${await ai.count()}条记录提供AI核查入口`;
  },
  async notifications() {
    await openSettings(page);
    await page.locator('button.settings-row').filter({ hasText: '漏洞等级提醒' }).click();
    const dialog = page.getByRole('dialog', { name: '漏洞等级提醒', exact: true });
    await dialog.waitFor();
    const text = await dialog.innerText();
    for (const label of ['任务完成提醒', '工作流']) must(text.includes(label), '设置缺少通知配置' + label);
    const switches = dialog.getByRole('switch');
    must(await switches.count() === 2, '通知设置应提供两个独立开关');
    must(await dialog.getByRole('checkbox').count() === 4, '通知设置应提供四个严重程度选项');
    return '任务完成与工作流通知配置已显示；本项仅检查现有配置，不通过创建任务触发系统通知';
  },
  async offline() {
    // Reuse the full known-vector suite with a strict result adapter.
    const H = {
      phase(name) { console.log(name); },
      run(id, title, action) { return runCase(id, title, action); },
      async shot(_page, name) { await shot(name).catch(() => {}); },
    };
    const start = results.length;
    const previousFixtureDir = process.env.E2E_FIXTURE_DIR;
    process.env.E2E_FIXTURE_DIR = path.join(OUT, 'offline-fixtures');
    try { await require('./suite/l-offline-tools.cjs').run(page, H, {}); }
    finally {
      if (previousFixtureDir === undefined) delete process.env.E2E_FIXTURE_DIR;
      else process.env.E2E_FIXTURE_DIR = previousFixtureDir;
    }
    const rows = results.slice(start);
    must(rows.length === 78, '离线用例数量发生变化，应重新核对覆盖清单');
    must(rows.every(r => r.status === 'PASS'), '离线工具存在失败或阻塞；详见每个L用例');
    return '22个离线工具，78个UI用例全部通过；已知向量在Node侧独立计算';
  },
};
(async () => {
  console.log('RESULTS ' + OUT);
  if (only) for (const id of only) must(Object.hasOwn(cases, id), '未知用例组：' + id);
  const browser = await chromium.connectOverCDP('http://127.0.0.1:19229', { timeout: 15000 });
  page = browser.contexts().flatMap(c => c.pages()).find(p => /app\.asar/.test(p.url()) && !/startup\.html|capture-browser\.html/.test(p.url()));
  must(page, '未找到已运行的打包EXE主页面');
  page.setDefaultTimeout(12000);
  if (!await page.locator('#desktop-v2-primary-navigation').isVisible()) console.log('WAITING_MANUAL_LOGIN');
  await page.locator('#desktop-v2-primary-navigation').waitFor({ state: 'visible', timeout: 600000 });
  console.log('AUTHENTICATED by user');
  for (const [id, action] of Object.entries(cases)) {
    if (!only || only.has(id)) await runCase(id, id, action);
  }
  console.log('COMPLETE ' + OUT);
  // Do not close the browser/app; leave the user's authenticated session intact.
  process.exit(results.some(r => r.status === 'FAIL') ? 1 : results.some(r => r.status === 'BLOCKED') ? 2 : 0);
})().catch(error => { console.error(String(error.message)); save(); process.exit(3); });
