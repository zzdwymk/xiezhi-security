/** Real packaged-app post-scan closure, restricted to existing project 133 / target 298.
 * PREPARED ONLY: run after the rebuilt EXE is ready, CDP 19229 is enabled and login is complete.
 * Uses visible DOM controls and passive response bodies only. Never reads credentials,
 * browser storage or cookies, calls business APIs, deletes records or closes the EXE.
 * The script owns 127.0.0.1:18888; a port conflict stops the run without killing anything.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const h = require('./verify-ai-local-fixture.cjs');
const { navigate, selectOn } = require('./lib/ui.cjs');
const SCOPE = Object.freeze({
  projectId: 133, targetId: 298,
  projectName: 'AI本机闭环验收-2026-10-01T12-38-32-728Z',
  targetName: 'AI本机HTTP夹具-2026-10-01T12-38-32-728Z',
  targetUrl: 'http://127.0.0.1:18888', allowedPorts: '18888',
});
let page, out, source, planned, chosen, dispatched;
const pathWrites = [];
function pending(suffix, method = 'GET', timeout = 30000) {
  return page.waitForResponse(r => new URL(r.url()).pathname.endsWith(suffix) && r.request().method() === method, { timeout });
}
function save(name, value) { fs.writeFileSync(path.join(out, name + '.json'), JSON.stringify(value, null, 2)); }
function scoped(value) {
  assert.equal(Number(value.projectId), SCOPE.projectId, 'Unexpected project');
  assert.equal(Number(value.targetId), SCOPE.targetId, 'Unexpected target');
}
function observe(response) {
  const pathname = new URL(response.url()).pathname;
  if (/\/post-scan-paths\/(?:plans|\d+\/confirm)$/.test(pathname) && response.request().method() === 'POST')
    pathWrites.push({ pathname, status: response.status(), body: response.request().postDataJSON() });
}
async function taskSnapshot() {
  await navigate(page, '检测任务');
  const clear = page.getByRole('button', { name: '清除筛选', exact: true });
  if (await clear.isVisible()) await clear.click();
  const filter = page.locator('.el-select').filter({ has: page.getByRole('combobox', { name: '按项目筛选', exact: true }) });
  await selectOn(page, filter, SCOPE.projectName, { exact: true });
  const response = pending('/tasks');
  await page.getByRole('button', { name: '刷新', exact: true }).click();
  const data = await (await response).json();
  const rows = Array.isArray(data) ? data : data.content;
  assert.ok(Array.isArray(rows));
  return rows.filter(task => Number(task.projectId) === SCOPE.projectId && Number(task.targetId) === SCOPE.targetId);
}
async function sourceFinding() {
  await navigate(page, '安全发现');
  const select = page.locator('.findings-filter-toolbar .el-select').nth(1);
  await select.click();
  const option = page.locator('.el-select-dropdown:visible').last().locator('.el-select-dropdown__item').filter({ hasText: '(#298)' });
  await option.waitFor({ state: 'visible' });
  assert.equal(await option.count(), 1, 'Expected the unique target 298 option');
  const filtered = page.waitForResponse(r => new URL(r.url()).pathname.endsWith('/findings') && new URL(r.url()).searchParams.get('targetId') === '298');
  await option.click();
  const response = await filtered; assert.ok(response.ok());
  const data = await response.json();
  const index = data.content.findIndex(f => Number(f.projectId) === SCOPE.projectId && Number(f.targetId) === SCOPE.targetId
    && f.sourceTool === 'http_headers' && !['FIXED', 'FALSE_POSITIVE'].includes(f.status));
  assert.ok(index >= 0, 'No active HTTP-header finding on the existing local fixture; no new source scan will be started');
  source = data.content[index]; scoped(source);
  const row = page.locator('.findings-page .el-table__body-wrapper .el-table__row').nth(index);
  assert.equal((await row.locator('td').nth(3).innerText()).trim(), '298');
  assert.match(await row.locator('td').nth(2).innerText(), /HTTP.*响应头/);
  const before = h.fixture.requests;
  const created = pending('/post-scan-paths/plans', 'POST', 220000);
  await row.getByRole('button', { name: '后续路径', exact: true }).click();
  const reply = await created; assert.ok(reply.ok(), await reply.text());
  const request = reply.request().postDataJSON(); scoped(request); assert.deepEqual(request.findingIds, [source.id]);
  planned = await reply.json(); scoped(planned);
  assert.ok(Number(planned.id) > 0); assert.equal(planned.status, 'DRAFT'); assert.deepEqual(planned.taskIds, []);
  assert.deepEqual(planned.findingIds, [source.id]); assert.equal(h.fixture.requests, before, 'Planning contacted the target');
  assert.equal(planned.provider, 'openai-compatible', 'Real model analysis was not returned');
  save('source-and-draft', { source, planned });
  return { pathId: planned.id, findingId: source.id, provider: planned.provider, note: '从已有响应头发现创建并保存真实模型路径；尚未执行。' };
}
async function verifyPresentationAndReadback() {
  const dialog = page.getByRole('dialog', { name: 'AI 扫描后渗透验证路径', exact: true });
  await dialog.locator('.post-scan-summary').waitFor();
  const summary = dialog.locator('.post-scan-summary');
  assert.ok((await summary.innerText()).trim().length > 30);
  assert.ok(await summary.locator('p,h1,h2,h3,ul,ol,table,pre').count() > 0, 'Analysis is not rendered markup');
  if (/\*\*[^\n]+\*\*/.test(planned.analysis)) assert.ok(await summary.locator('strong').count() > 0, 'Model emphasis remained literal');
  assert.equal(await summary.locator('script,iframe,img,[onerror]').count(), 0);
  assert.ok(await dialog.locator('.post-scan-paths .post-scan-field > strong').filter({ hasText: /^前置条件$/ }).count() > 0);
  assert.ok(await dialog.locator('.post-scan-steps .post-scan-field > strong').filter({ hasText: /^执行前置条件$/ }).count() > 0);
  assert.ok(await dialog.locator('.post-scan-steps .post-scan-field > strong').filter({ hasText: /^预期影响$/ }).count() > 0);
  const choices = planned.steps.filter(step => step.automated && step.riskLevel === 'SAFE' && (
    step.toolCode === 'http_headers' && Object.keys(step.parameters || {}).length === 0 ||
    step.toolCode === 'http_security_check' && step.parameters?.check === 'cookies' && Object.keys(step.parameters).length === 1));
  chosen = choices.find(step => step.toolCode === 'http_security_check') || choices[0];
  assert.ok(chosen, 'No permitted read-only HTTP step; will not choose any other tool or parameters');
  const boxes = dialog.locator('.post-scan-steps input[type="checkbox"]');
  assert.equal(await boxes.count(), planned.steps.length);
  for (let i = 0; i < planned.steps.length; i++) {
    const step = planned.steps[i], checkbox = boxes.nth(i);
    if (!step.automated || step.riskLevel !== 'SAFE') { assert.ok(await checkbox.isDisabled()); continue; }
    if (await checkbox.isChecked() !== (step.id === chosen.id)) await checkbox.setChecked(step.id === chosen.id);
  }
  const saved = pending('/post-scan-paths/' + planned.id);
  await dialog.getByRole('button', { name: '刷新状态', exact: true }).click();
  const response = await saved; assert.ok(response.ok());
  const readback = await response.json(); scoped(readback);
  assert.equal(readback.id, planned.id); assert.equal(readback.analysis, planned.analysis);
  assert.deepEqual(readback.paths, planned.paths); assert.deepEqual(readback.steps, planned.steps);
  assert.equal(readback.status, 'DRAFT'); assert.deepEqual(readback.taskIds, []);
  assert.equal(await boxes.nth(planned.steps.findIndex(s => s.id === chosen.id)).isChecked(), true);
  await dialog.locator('.post-scan-steps').scrollIntoViewIfNeeded();
  save('saved-draft', readback);
  return { pathId: planned.id, selectedStep: chosen, note: '真实 Markdown、前置条件及影响显示，且只读重读与服务端保存计划完全一致。' };
}
async function confirmAndReadback() {
  const before = h.fixture.requests;
  const dialog = page.getByRole('dialog', { name: 'AI 扫描后渗透验证路径', exact: true });
  await dialog.getByRole('button', { name: '自动执行安全步骤', exact: true }).click();
  const box = page.locator('.el-message-box:visible');
  await box.waitFor();
  const confirmation = await box.innerText();
  assert.match(confirmation, /授权目标 #298/); assert.match(confirmation, /执行 1 个低风险/);
  assert.equal(h.fixture.requests, before, 'Target was contacted before explicit confirmation');
  const accepted = pending('/post-scan-paths/' + planned.id + '/confirm', 'POST', 60000);
  await box.getByRole('button', { name: '确认执行', exact: true }).click();
  const response = await accepted; assert.ok(response.ok(), await response.text());
  assert.deepEqual(response.request().postDataJSON(), { acknowledged: true, selectedStepIds: [chosen.id] });
  dispatched = await response.json(); scoped(dispatched);
  assert.equal(dispatched.id, planned.id); assert.equal(dispatched.status, 'DISPATCHED');
  assert.equal(dispatched.taskIds.length, 1); assert.ok(dispatched.taskIds.every(id => Number(id) > 0));
  await dialog.getByText('后续验证任务已创建', { exact: true }).waitFor();
  assert.equal(await dialog.getByRole('button', { name: '自动执行安全步骤', exact: true }).count(), 0);
  const saved = pending('/post-scan-paths/' + planned.id);
  await dialog.getByRole('button', { name: '刷新状态', exact: true }).click();
  const readback = await (await saved).json(); scoped(readback);
  assert.equal(readback.status, 'DISPATCHED'); assert.deepEqual(readback.taskIds, dispatched.taskIds);
  assert.equal(readback.analysis, planned.analysis);
  save('saved-dispatch', { confirmation, dispatched, readback });
  await dialog.getByRole('button', { name: '关闭', exact: true }).click();
  return { pathId: planned.id, taskIds: dispatched.taskIds, note: '仅明确确认的一项只读 HTTP 步骤下发，已保存状态和任务编号重读一致。' };
}
async function verifyTask(beforeIds) {
  const taskId = dispatched.taskIds[0];
  await h.waitTask(taskId, chosen.toolCode);
  const row = page.locator('.el-table__row').filter({ has: page.locator('td:first-child .cell').filter({ hasText: new RegExp('^\\s*' + taskId + '\\s*$') }) });
  const detailResponse = pending('/tasks/' + taskId);
  await row.getByRole('button', { name: '详情', exact: true }).click();
  const task = await (await detailResponse).json(); scoped(task);
  assert.equal(task.status, 'SUCCESS'); assert.equal(task.toolCode, chosen.toolCode);
  assert.equal(task.allowedPortsSnapshot, '18888');
  assert.ok(task.authorizationSnapshotHash && task.snapshotCapturedAt && task.authorizationStatementSnapshot, 'Missing authorization evidence');
  assert.ok(task.resultJson, 'Missing authoritative task result');
  assert.ok(h.fixture.requests > 0, 'Successful HTTP task never contacted the owned fixture');
  assert.ok(Object.keys(h.fixture.methods).every(method => ['GET', 'HEAD', 'OPTIONS'].includes(method)), 'Unexpected mutating HTTP method');
  const detail = page.getByRole('dialog', { name: '任务详情', exact: true });
  assert.match(await detail.innerText(), /18888/);
  await detail.getByRole('button', { name: '关闭', exact: true }).click();
  const finalTasks = await taskSnapshot();
  assert.deepEqual(finalTasks.filter(t => !beforeIds.has(t.id)).map(t => t.id).sort(), dispatched.taskIds.slice().sort(), 'Unexpected task batch');
  assert.equal(pathWrites.filter(write => write.pathname.endsWith('/plans')).length, 1);
  assert.equal(pathWrites.filter(write => write.pathname.endsWith('/confirm')).length, 1);
  save('task-and-authority', { task, fixture: h.fixture, pathWrites });
  return { taskId, taskStatus: task.status, authorizationSnapshotHash: task.authorizationSnapshotHash,
    fixture: { ...h.fixture }, note: '服务端任务成功终态、真实只读 HTTP 访问、授权快照及唯一任务数相互一致。' };
}
async function main() {
  assert.equal(process.argv.length, 2, 'This acceptance has a fixed scope and accepts no overrides');
  try {
    await h.step('postscan-fixture-start', h.startFixture);
    await h.step('postscan-exe-attach', h.attach);
    ({ page, out } = h.state()); page.on('response', observe);
    await h.step('postscan-scope-restore', () => h.restoreScope(SCOPE));
    const before = await taskSnapshot();
    assert.ok(before.every(task => !['PENDING', 'RUNNING'].includes(task.status)), 'Existing local target task is still running');
    const beforeIds = new Set(before.map(task => task.id));
    await h.step('postscan-draft', sourceFinding);
    await h.step('postscan-render-and-persistence', verifyPresentationAndReadback);
    await h.step('postscan-confirm-and-persistence', confirmAndReadback);
    await h.step('postscan-task-and-authorization', () => verifyTask(beforeIds));
  } finally {
    await h.closeFixture(); h.save();
    if (page) page.off('response', observe);
  }
  console.log('COMPLETE ' + h.state().out);
  process.exit(h.results.some(result => result.status !== 'PASS') ? 1 : 0);
}
if (require.main === module) main().catch(error => { console.error(String(error)); h.save(); process.exit(1); });
