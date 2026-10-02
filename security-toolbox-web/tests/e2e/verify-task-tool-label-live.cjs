/** Read-only DOM verification against the manually logged-in packaged EXE.
 * No business API calls, storage/cookies, task actions, or browser.close().
 * node tests/e2e/verify-task-tool-label-live.cjs
 * Optional: --task=854 --project=131 --project-name=... --tool=Metasploit --code=msf_scan
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const arg = (name, fallback) => process.argv.find(value => value.startsWith(`--${name}=`))?.slice(name.length + 3) || fallback;
const taskId = arg('task', '854');
const projectId = arg('project', '131');
const projectName = arg('project-name', '四目标实战全景测试项目-049988');
const toolName = arg('tool', 'Metasploit');
const toolCode = arg('code', 'msf_scan');
assert.match(taskId, /^\d+$/);
assert.match(projectId, /^\d+$/);
const out = path.resolve(__dirname, '../../../.run/task-tool-label', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(out, { recursive: true });
const report = { projectId, projectName, taskId, toolName, toolCode, method: 'DOM-only; existing task; no task writes', checks: [] };
let page;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const save = () => fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify(report, null, 2));
async function navigate(groupId, label) {
  // Do not dismiss an existing approval or unknown user dialog.
  assert.equal(await page.locator('.el-dialog:visible, .el-message-box:visible').count(), 0, '存在用户弹窗，请手动处理后重跑');
  const nav = page.locator('#desktop-v2-primary-navigation');
  await nav.waitFor({ state: 'visible', timeout: 15000 });
  const group = nav.locator(`#nav-group-${groupId}`);
  if (await group.getAttribute('aria-expanded') !== 'true') await group.click();
  await nav.getByRole('button', { name: label, exact: true }).click();
}
function rowForTask() {
  return page.locator('.el-table__body tr.el-table__row:visible').filter({
    has: page.locator('td:first-child .cell').filter({ hasText: new RegExp(`^\\s*${taskId}\\s*$`) }),
  });
}
async function findTaskAcrossPages() {
  for (let i = 0; i < 100; i++) {
    for (let retry = 0; retry < 10; retry++) {
      const row = rowForTask();
      if (await row.count()) return row.first();
      await sleep(150);
    }
    const next = page.locator('.el-pagination:visible .btn-next');
    if (!await next.count() || await next.isDisabled()) break;
    const before = await page.locator('.el-table__body').first().innerText();
    await next.click();
    for (let retry = 0; retry < 20; retry++) {
      if (await page.locator('.el-table__body').first().innerText() !== before) break;
      await sleep(100);
    }
  }
  throw new Error(`当前项目筛选下找不到任务 ${taskId}`);
}
function detailValue(dialog, label) {
  return dialog.locator('.el-descriptions__label').filter({ hasText: new RegExp(`^\\s*${label}\\s*$`) }).locator('xpath=following-sibling::td[1]');
}
(async () => {
  const browser = await chromium.connectOverCDP('http://127.0.0.1:19229', { timeout: 15000 });
  page = browser.contexts().flatMap(context => context.pages()).find(candidate => /[?&]desktop=1/.test(candidate.url()));
  assert.ok(page, '未找到已运行的桌面主窗口');
  await page.bringToFront();
  // Establish project identity using its visible row and detail URL.
  await navigate('projects-assets', '评估项目');
  await page.getByPlaceholder('搜索项目名称 / 负责人 / 说明').fill(projectName);
  const projectRow = page.locator('.el-table__row:visible').filter({ hasText: projectName });
  await projectRow.getByRole('button', { name: '进入项目', exact: true }).click();
  await page.waitForURL(url => new RegExp(`/projects/${projectId}(?:[?&#]|$)`).test(url.href));
  report.checks.push({ name: '项目名称与ID匹配', status: 'PASS', url: page.url() });

  await navigate('detection-analysis', '检测任务');
  const clear = page.getByRole('button', { name: '清除筛选', exact: true });
  if (await clear.isVisible()) await clear.click();
  const select = page.locator('.el-select').filter({ has: page.getByRole('combobox', { name: '按项目筛选', exact: true }) });
  await select.click();
  await page.locator('.el-select-dropdown:visible').getByRole('option', { name: projectName, exact: true }).click();
  assert.ok((await select.innerText()).includes(projectName), '项目筛选未显示指定项目');
  const search = page.getByPlaceholder('搜任务 ID / 工具');
  for (const [kind, keyword] of [['id', taskId], ['name', toolName], ['code', toolCode]]) {
    await search.fill(keyword);
    const row = await findTaskAcrossPages();
    const displayedTool = (await row.locator('td').nth(1).innerText()).trim();
    assert.ok(displayedTool.includes(toolName), `工具列不是友好名称：${displayedTool}`);
    assert.ok(!displayedTool.includes(toolCode), `工具列仍显示内部代码：${displayedTool}`);
    await page.screenshot({ path: path.join(out, `list-${kind}.png`), fullPage: true });
    report.checks.push({ name: `${kind}搜索命中任务`, status: 'PASS', keyword, displayedTool, projectName });
  }
  await search.fill(taskId);
  const row = await findTaskAcrossPages();
  await row.getByRole('button', { name: '详情', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: '任务详情', exact: true });
  await dialog.waitFor({ state: 'visible' });
  assert.equal((await detailValue(dialog, '任务 ID').innerText()).trim(), taskId);
  const tool = (await detailValue(dialog, '工具').innerText()).trim();
  assert.ok(tool.includes(toolName) && !tool.includes(toolCode), `详情工具名称错误：${tool}`);
  await page.screenshot({ path: path.join(out, 'detail.png'), fullPage: true });
  report.checks.push({ name: '任务详情友好名称', status: 'PASS', tool });
  await dialog.locator('.el-dialog__headerbtn').click();
  report.status = 'PASS';
  save();
  console.log(JSON.stringify({ status: report.status, output: out, checks: report.checks }));
  // Disconnect by exiting only this test process. Never close the user's EXE.
  process.exit(0);
})().catch(async error => {
  report.status = 'FAIL';
  report.error = String(error.stack || error);
  if (page) await page.screenshot({ path: path.join(out, 'failure.png'), fullPage: true }).catch(() => {});
  save();
  console.error(JSON.stringify({ status: report.status, error: error.message, output: out }));
  process.exit(1);
});
