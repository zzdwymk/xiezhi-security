/** Real packaged-app acceptance on an owned loopback fixture.
 * Only visible UI mutations and passive business response inspection. Never reads
 * credentials, storage or cookies. Only the project created by this run is edited.
 * Keeps all records. Fscan is limited to SAFE, one loopback port; no PoCs/bruteforce.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const h = require('./verify-ai-local-fixture.cjs');
const { navigate, selectOn, formItem, sleep } = require('./lib/ui.cjs');
let page, projectId, targetId, projectName, targetName, out, savedSpec;
const receivedTasks = new Map();
const approvalRequests = [];
function observe(response) {
  const pathname = new URL(response.url()).pathname;
  if (/\/tasks(?:\/\d+)?$/.test(pathname)) response.json().then(data => {
    const rows = Array.isArray(data) ? data : data.content || (data.id ? [data] : []);
    for (const task of rows) if (Number(task.projectId) === projectId) receivedTasks.set(Number(task.id), task);
  }).catch(() => {});
}
function responseFor(suffix, method = 'POST', timeout = 30000) {
  return page.waitForResponse(r => new URL(r.url()).pathname.endsWith(suffix) && r.request().method() === method, { timeout });
}
function node(id) { return page.locator(`.vue-flow__node[data-id=${JSON.stringify(id)}]`); }
async function revealNode(id) {
  await sleep(250);
  for (let attempt = 0; attempt < 8; attempt++) {
    const area = await page.locator('.flow-canvas').boundingBox(); const box = await node(id).boundingBox();
    assert.ok(area && box);
    const x = box.x + box.width / 2, y = box.y + box.height / 2;
    if (x > area.x + 35 && x < area.x + area.width - 35 && y > area.y + 35 && y < area.y + area.height - 35) return;
    const dx = Math.max(-area.width / 3, Math.min(area.width / 3, area.x + area.width / 2 - x));
    const dy = Math.max(-area.height / 3, Math.min(area.height / 3, area.y + area.height / 2 - y));
    const sx = area.x + area.width / 2, sy = area.y + area.height / 2;
    await page.mouse.move(sx, sy); await page.mouse.down({ button: 'middle' });
    await page.mouse.move(sx + dx, sy + dy, { steps: 15 }); await page.mouse.up({ button: 'middle' }); await sleep(200);
  }
  throw new Error('Cannot bring node into visible canvas: ' + id);
}
async function connect(source, target) {
  await page.getByRole('button', { name: '适应画布', exact: true }).click(); await sleep(250);
  const a = await node(source).locator('.node-handle--source').boundingBox();
  const b = await node(target).locator('.node-handle--target').boundingBox();
  assert.ok(a && b, `Missing connection handles ${source} -> ${target}`);
  await page.mouse.move(a.x + a.width / 2, a.y + a.height / 2); await page.mouse.down();
  await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 15 }); await page.mouse.up(); await sleep(150);
  assert.ok(await page.locator('.vue-flow__edge').evaluateAll((edges, pair) => edges.some(e => e.getAttribute('data-id')?.includes(pair[0]) && e.getAttribute('data-id')?.includes(pair[1])), [source, target]), `Connection not drawn: ${source} -> ${target}`);
}
async function moveNodeToWorld(id, x, y) {
  for (let i = 0; i < 40; i++) {
    await revealNode(id);
    const geometry = await node(id).evaluate(el => {
      const m = el.style.transform.match(/translate\(([-\d.]+)px,\s*([-\d.]+)px\)/);
      const b = el.getBoundingClientRect();
      return { x: Number(m?.[1]), y: Number(m?.[2]), zoom: b.width / el.offsetWidth, cx: b.x + b.width / 2, cy: b.y + b.height / 2 };
    });
    assert.ok(Number.isFinite(geometry.x) && geometry.zoom > 0);
    if (Math.abs(geometry.x - x) < 8 && Math.abs(geometry.y - y) < 8) return;
    const area = await page.locator('.flow-canvas').boundingBox();
    const dx = Math.max(-area.width / 4, Math.min(area.width / 4, (x - geometry.x) * geometry.zoom));
    const dy = Math.max(-area.height / 4, Math.min(area.height / 4, (y - geometry.y) * geometry.zoom));
    const title = await node(id).locator('.node-main > strong').boundingBox();
    const sx = title ? title.x + title.width / 2 : geometry.cx, sy = title ? title.y + title.height / 2 : geometry.cy;
    await page.mouse.move(sx, sy); await page.mouse.down();
    await page.mouse.move(sx + dx, sy + dy, { steps: 15 }); await page.mouse.up(); await sleep(100);
  }
  throw new Error('Could not arrange node through drag: ' + id);
}
async function openWorkflowScope() {
  await navigate(page, '红队工作流');
  await page.locator('.editor-head-actions').getByRole('button', { name: '工作流配置', exact: true }).click();
  const config = page.locator('#workflow-config-panel');
  await selectOn(page, config.locator('.project-select'), projectName, { exact: true });
  await selectOn(page, config.locator('.target-select'), targetName);
  await page.getByRole('button', { name: '关闭工作流配置', exact: true }).click();
  const loaded = responseFor('/ai/workflow', 'GET');
  await page.locator('.editor-head-actions').getByRole('button', { name: '重新加载', exact: true }).click();
  const response = await loaded;
  assert.ok(response.ok());
  assert.equal(Number(new URL(response.url()).searchParams.get('projectId')), projectId);
  const original = await response.json();
  // A new project returns the unsaved default without snapshot identity metadata.
  if (original.scopeId != null) assert.equal(Number(original.scopeId), projectId);
  fs.writeFileSync(path.join(out, 'workflow-original.json'), JSON.stringify(original, null, 2));
  return original;
}
function verifyWorkflowScope(spec) {
  assert.equal(Number(spec.scopeId), projectId);
  assert.deepEqual(spec.steps.map(s => s.tool).sort(), ['retrieve_project_context', 'http_headers', 'tcp_ports', 'fscan_scan'].sort());
  for (const tool of ['tcp_ports', 'fscan_scan']) {
    const params = spec.steps.find(s => s.tool === tool).parameters;
    assert.equal(params.ports, '18888');
    assert.deepEqual(Object.keys(params).sort(), (tool === 'fscan_scan' ? ['ports', 'vulnMode'] : ['ports']).sort());
    if (tool === 'fscan_scan') assert.equal(params.vulnMode, 'SAFE');
  }
  assert.deepEqual(spec.steps.find(s => s.tool === 'http_headers').parameters, {});
}
async function setupWorkflow() {
  let original = await openWorkflowScope();
  if (!original.graph) {
    const saved = responseFor('/ai/workflow', 'PUT');
    await page.getByRole('button', { name: '保存工作流', exact: true }).click();
    const response = await saved; assert.ok(response.ok()); original = await response.json();
  }
  const contextId = original.graph.nodes.find(n => n.tool === 'retrieve_project_context')?.id;
  const headersId = original.graph.nodes.find(n => n.tool === 'http_headers')?.id;
  const phaseId = original.graph.nodes.find(n => n.type === 'phase')?.id;
  assert.ok(contextId && headersId && phaseId, 'Initial template must include a phase, context and headers');
  const kept = ['__start__', '__end__', phaseId, contextId, headersId];
  for (const item of original.graph.nodes.filter(n => !kept.includes(n.id))) {
    await page.getByRole('button', { name: '适应画布', exact: true }).click();
    await revealNode(item.id);
    await node(item.id).hover();
    await node(item.id).getByRole('button', { name: '删除节点', exact: true }).click();
  }
  for (const [source, target] of [['__start__', phaseId], [phaseId, contextId], [contextId, headersId], [headersId, '__end__']]) {
    if (!original.graph.edges.some(edge => edge.source === source && edge.target === target)) await connect(source, target);
  }
  for (const [tool, category] of [['tcp_ports', '资产发现'], ['fscan_scan', '漏洞发现']]) {
    await page.locator('.workflow-library-tabs').getByText('阶段与能力库', { exact: true }).click();
    const toggle = page.locator('button[aria-controls="workflow-capability-library-body"]');
    if (await toggle.getAttribute('aria-expanded') === 'false') await toggle.click();
    // Categories are display-only filters. Pick the observed option containing this tool.
    const filter = page.locator('.capability-library-head .el-select');
    await filter.click();
    const options = page.locator('.el-select-dropdown:visible').last().locator('li.el-select-dropdown__item');
    await options.first().waitFor({ state: 'visible' });
    const names = (await options.allTextContents()).map(s => s.trim());
    const wanted = names.find(n => n === category) || names.find(n => /全部/.test(n));
    assert.ok(wanted, 'Expected capability category: ' + names.join(','));
    await options.filter({ hasText: wanted }).first().click();
    const old = new Set(await page.locator('.vue-flow__node').evaluateAll(ns => ns.map(n => n.getAttribute('data-id'))));
    const card = page.locator(`.library-item[data-tool="${tool}"]`);
    await card.getByRole('button', { name: '加入选定阶段', exact: true }).click();
    const fresh = (await page.locator('.vue-flow__node').evaluateAll(ns => ns.map(n => n.getAttribute('data-id')))).filter(id => !old.has(id));
    assert.equal(fresh.length, 1); const id = fresh[0];
    await page.locator('.workflow-library-tabs').getByText('节点配置', { exact: true }).click();
    const editor = page.locator('[aria-label="已选节点参数"]');
    const ports = formItem(editor, page, '扫描端口').locator('.el-select');
    for (let i = 0; i < 10 && await ports.locator('.el-tag__close:visible').count(); i++) await ports.locator('.el-tag__close:visible').first().click();
    await ports.locator('input').first().fill('18888'); await page.keyboard.press('Enter'); await page.keyboard.press('Escape');
    if (tool === 'fscan_scan') await editor.getByText('安全（默认）', { exact: true }).click();
    await connect(contextId, id); await connect(id, '__end__');
  }
  assert.equal(await page.locator('.graph-validation:visible').count(), 0,
    await page.locator('.graph-validation:visible').count() ? await page.locator('.graph-validation:visible').innerText() : '');
  const pending = responseFor('/ai/workflow', 'PUT');
  await page.getByRole('button', { name: '保存工作流', exact: true }).click();
  const response = await pending; assert.ok(response.ok(), 'Workflow save failed');
  savedSpec = await response.json();
  verifyWorkflowScope(savedSpec);
  fs.writeFileSync(path.join(out, 'workflow-saved.json'), JSON.stringify(savedSpec, null, 2));
  assert.deepEqual(savedSpec.steps.map(s => s.tool).sort(), ['retrieve_project_context', 'http_headers', 'tcp_ports', 'fscan_scan'].sort());
  const fscan = savedSpec.steps.find(s => s.tool === 'fscan_scan');
  assert.equal(fscan.parameters.ports, '18888'); assert.equal(fscan.parameters.vulnMode, 'SAFE');
  assert.equal(fscan.requiresApproval, true); assert.equal(fscan.risk, 'CAUTION');
  assert.ok(!/\bCAUTION\b/.test(await page.locator('.vue-flow').innerText()));
  return { revision: savedSpec.revision, steps: savedSpec.steps, note: '仅本次独立项目；固定三项单端口检测及上下文节点。' };
}
async function projectTasks() {
  await navigate(page, '检测任务');
  const clear = page.getByRole('button', { name: '清除筛选', exact: true }); if (await clear.isVisible()) await clear.click();
  const filter = page.locator('.el-select').filter({ has: page.getByRole('combobox', { name: '按项目筛选', exact: true }) });
  await selectOn(page, filter, projectName, { exact: true });
  const pending = responseFor('/tasks', 'GET');
  await page.getByRole('button', { name: '刷新', exact: true }).click();
  const response = await pending; const data = await response.json();
  const rows = Array.isArray(data) ? data : data.content;
  assert.ok(Array.isArray(rows));
  // The endpoint returns all authorized tasks; the visible project filter is local.
  return rows.filter(t => Number(t.projectId) === projectId);
}
async function requestApproval() {
  await h.openTargetAi();
  const result = await h.send('请用 fscan 对当前本机目标的 18888 端口执行一次安全模式检测，使用该节点已保存的配置。仅检测这一项。', true);
  assert.equal(result.planSteps.length, 1);
  const item = result.planSteps[0]; assert.equal(item.toolCode, 'fscan_scan');
  assert.equal(item.parameters.ports, '18888'); assert.equal(item.parameters.vulnMode, 'SAFE');
  assert.ok(item.requiresApproval && item.risk === 'CAUTION');
  assert.ok(Number(result.approvalId) > 0, JSON.stringify(result)); assert.equal(result.taskIds.length, 0);
  assert.ok(['REQUIRED', 'PENDING'].includes(result.approvalStatus));
  const dialog = page.getByRole('dialog', { name: '确认本次检测', exact: true }); await dialog.waitFor();
  assert.equal(await dialog.locator('[data-approval-id]').getAttribute('data-approval-id'), String(result.approvalId));
  const text = await dialog.innerText(); assert.match(text, /127\.0\.0\.1:18888/); assert.match(text, /需人工确认/); assert.doesNotMatch(text, /\bCAUTION\b/);
  approvalRequests.push(result.approvalId); return result;
}
async function reject() {
  const before = (await projectTasks()).map(t => t.id).sort();
  const connectionsBefore = h.fixture.connections;
  const plan = await requestApproval();
  const pending = responseFor(`/projects/${projectId}/approvals/${plan.approvalId}/decision`);
  await page.getByRole('dialog', { name: '确认本次检测', exact: true }).getByRole('button', { name: '拒绝', exact: true }).click();
  const response = await pending; assert.ok(response.ok());
  await page.getByRole('dialog', { name: '确认本次检测', exact: true }).waitFor({ state: 'hidden' });
  assert.match(await page.locator('article.chat-message.assistant').last().innerText(), /驳回/);
  assert.deepEqual((await projectTasks()).map(t => t.id).sort(), before);
  assert.equal(h.fixture.connections, connectionsBefore, 'Approval rejection contacted fixture');
  return { ...plan, existingTaskIds: before, note: '驳回后未新增项目任务，本机夹具无新增连接。' };
}
async function approve() {
  const beforeCount = (await projectTasks()).length;
  const plan = await requestApproval();
  const pending = responseFor(`/projects/${projectId}/approvals/${plan.approvalId}/execute`, 'POST', 240000);
  await page.getByRole('dialog', { name: '确认本次检测', exact: true }).getByRole('button', { name: '批准本次执行', exact: true }).click();
  const response = await pending; assert.ok(response.ok(), 'Resume failed: ' + await response.text());
  const dispatch = await response.json();
  assert.equal(dispatch.taskIds.length, 1); assert.equal(dispatch.plan.steps[0].toolCode, 'fscan_scan');
  assert.deepEqual(dispatch.plan.steps[0].parameters, plan.planSteps[0].parameters);
  await page.getByRole('dialog', { name: '确认本次检测', exact: true }).waitFor({ state: 'hidden' });
  const task = await h.waitTask(dispatch.taskIds[0], 'fscan_scan');
  assert.ok(h.fixture.connections > 0); assert.equal((await projectTasks()).length, beforeCount + 1);
  return { approvalId: plan.approvalId, dispatch, task, note: '实际模型申请→管理员批准→原计划一项任务→本机真实执行成功。' };
}
async function runWorkflow() {
  const beforeIds = new Set((await projectTasks()).map(t => t.id));
  verifyWorkflowScope(await openWorkflowScope());
  const pending = responseFor('/workflow-runs', 'POST', 180000);
  void pending.catch(() => {});
  await page.getByRole('button', { name: '执行工作流', exact: true }).click();
  let confirmations = [];
  // Confirm only this run's known bounded operations, never skip unexpected errors.
  for (let i = 0; i < 8; i++) {
    const box = page.locator('.el-message-box:visible');
    await box.waitFor({ timeout: 120000 }); const text = await box.innerText(); confirmations.push(text);
    assert.ok(/执行红队工作流|解析的 Web 检测目标|确认需审批步骤/.test(text), 'Unexpected confirmation: ' + text);
    assert.doesNotMatch(text, /\bCAUTION\b/);
    const buttons = box.getByRole('button');
    const names = await buttons.allTextContents();
    const label = ['确认并继续', '确认执行', '确定'].find(s => names.some(n => n.trim() === s)); assert.ok(label, names.join(','));
    await box.getByRole('button', { name: label, exact: true }).click();
    await sleep(350);
    if (/确认需审批步骤/.test(text)) break;
  }
  const response = await pending; assert.ok(response.ok(), 'Workflow start failed: ' + await response.text());
  const started = await response.json(); const id = started.run.id;
  let final = started;
  for (let i = 0; i < 120 && !['COMPLETED', 'FAILED', 'PARTIAL_FAILED', 'STOPPED'].includes(final.run.status); i++) {
    const r = await responseFor(`/workflow-runs/${id}`, 'GET'); final = await r.json();
  }
  fs.writeFileSync(path.join(out, 'workflow-final.json'), JSON.stringify(final, null, 2));
  assert.equal(final.run.status, 'COMPLETED', JSON.stringify(final));
  const allTasks = await projectTasks();
  const tasks = allTasks.filter(t => !beforeIds.has(t.id)); assert.equal(tasks.length, 3);
  assert.ok(tasks.every(t => Number(t.workflowRunId) === Number(id)));
  assert.ok(tasks.every(t => t.status === 'SUCCESS'));
  assert.ok(tasks.every(t => t.authorizationSnapshotHash && t.snapshotCapturedAt), 'Every task must retain its authorization snapshot');
  return { runId: id, final, taskIds: tasks.map(t => t.id), confirmations, note: '工作流真实启动、依赖调度、三项任务终态与授权快照验收。' };
}
(async () => {
  const resumeArg = process.argv.find(arg => arg.startsWith('--resume='));
  const fromArg = process.argv.find(arg => arg.startsWith('--from='));
  const from = fromArg ? fromArg.slice('--from='.length) : 'workflow-configure';
  const stages = ['workflow-configure', 'reject', 'approve', 'workflow', 'tcp'];
  assert.ok(stages.includes(from), 'Unknown --from stage: ' + from);
  assert.ok(!fromArg || resumeArg, '--from requires --resume=<results.json>');
  const resume = resumeArg ? JSON.parse(fs.readFileSync(path.resolve(resumeArg.slice('--resume='.length)), 'utf8')) : null;
  await h.step('fixture-start', h.startFixture); await h.step('exe-attach', h.attach);
  ({ page, out } = h.state()); page.on('response', observe);
  if (resume) await h.step('scope-restore', () => h.restoreScope(resume));
  else {
    await h.step('project-create', h.createProject); await h.step('project-activate', h.activateProject); await h.step('target-create', h.createTarget);
  }
  ({ projectId, targetId, projectName, targetName } = h.state());
  const start = stages.indexOf(from);
  if (start <= 0) await h.step('workflow-configure', setupWorkflow);
  if (start <= 1) await h.step('high-risk-reject-zero-tasks', reject);
  if (start <= 2) await h.step('high-risk-approve-original-plan', approve);
  if (start <= 3) await h.step('workflow-real-run', runWorkflow);
  await h.runTool('tcp_ports');
})().catch(error => { console.error(error.stack); process.exitCode = 1; }).finally(async () => {
  await h.closeFixture(); h.save();
  console.log(JSON.stringify({ status: h.results.every(r => r.status === 'PASS') && !process.exitCode ? 'PASS' : 'FAIL', out: h.state().out, approvalRequests }));
  process.exit(process.exitCode || (h.results.some(r => r.status !== 'PASS') ? 1 : 0));
});
