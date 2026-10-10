/*
 * 阶段 F：任务控制中心
 *
 * 业务顺序：进入任务中心 → 校验配额概览 → 确认前序阶段创建的任务执行完成
 *          → 查看任务详情（授权快照、工具版本、实时日志）
 *          → 下载任务报告 → 定时任务管理
 *
 * 本阶段验证真实执行结果：业务靶机仅 lib/audit-target.cjs 声明的唯一授权地址。
 *
 * 注意：任务列表的「目标」列显示的是目标 ID（非 IP），状态列为英文枚举
 *       （PENDING/RUNNING/SUCCESS/FAILED/TIMEOUT/CANCELLED/REJECTED/SKIPPED），
 *       因此按「创建时间在本次运行窗口内」识别本次任务，并在详情中核对目标快照。
 */
const {
  sleep, navigate, pageTitle, dialog, dialogButton, selectOption,
  lastMessage, clearMessages, rowCount, confirmBoxIfPresent,
} = require("../lib/ui.cjs");

const { captureReport } = require("../lib/report-response.cjs");
const { TARGET_IP } = require("../lib/audit-target.cjs");
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { createRecorderCompat } = require('../../../../scripts/qa/desktop-recorder-compat.cjs');
const scheduleHash = value => crypto.createHash('sha256').update(value).digest('hex');
const scheduleBlocked = message => Object.assign(new Error(message), { qaClassification: 'BLOCKED', code: 'QA_BLOCKED' });

function validateScheduleFixtureProof(ctx, proof) {
  assert.equal(ctx.targetIp, TARGET_IP);
  if (ctx.fullRetestFixtureReady !== true || !ctx.fullRetestFixture || !ctx.fullScheduleFixtureProof)
    throw scheduleBlocked('F schedules require the completed fresh B/C fixture and immutable POST receipt proof');
  const fixture = ctx.fullRetestFixture;
  assert.equal(proof.kind, 'FRESH_FIXTURE_POST_RECEIPTS');
  assert.equal(path.resolve(proof.runDirectory), path.resolve(fixture.createdByRun));
  assert.equal(proof.stamp, ctx.fullRetestStamp);
  assert(String(fixture.projectName).endsWith('-' + proof.stamp));
  assert(Array.isArray(proof.beforeProjectIds) && Array.isArray(proof.beforeTargetIds));
  const project = proof.projectCreate, target = proof.targetCreate, membership = proof.membership;
  assert.equal(project.status, 201); assert.equal(project.request.method, 'POST');
  assert.equal(new URL(project.request.url, 'http://localhost').pathname, '/api/projects');
  assert.equal(project.body.id, fixture.projectId); assert.equal(project.body.name, fixture.projectName);
  assert.equal(project.request.body.name, fixture.projectName);
  assert(!proof.beforeProjectIds.map(Number).includes(Number(project.body.id)));
  assert.equal(target.status, 201); assert.equal(target.request.method, 'POST');
  assert.equal(new URL(target.request.url, 'http://localhost').pathname, '/api/targets');
  assert.equal(target.body.id, fixture.ipTargetId); assert.equal(target.request.body.projectId, fixture.projectId);
  assert.equal(String(target.body.targetType).toUpperCase(), 'IP');
  assert.equal(target.body.targetValue, TARGET_IP); assert.equal(target.request.body.targetValue, TARGET_IP);
  assert(!proof.beforeTargetIds.map(Number).includes(Number(target.body.id)));
  assert.equal(membership.status, 200); assert.equal(membership.request.method, 'GET');
  assert.equal(new URL(membership.request.url, 'http://localhost').pathname, `/api/projects/${fixture.projectId}/targets`);
  assert(membership.body.some(row => Number(row.projectId) === Number(fixture.projectId) && Number(row.targetId) === Number(fixture.ipTargetId)));
  assert.equal(ctx.projectId, fixture.projectId); assert.equal(ctx.ipTargetId, fixture.ipTargetId);
  assert(proof.evidenceFiles?.length >= 3, 'Freeze original response/baseline/membership source files');
  for (const ref of proof.evidenceFiles) assert.equal(scheduleHash(fs.readFileSync(ref.path)), ref.sha256, 'Fixture source hash ' + ref.path);
  assert(proof.serverTimeZone && proof.serverTimeZoneEvidence?.path, 'Verified Java systemDefault timezone proof required before daily creation');
  assert.equal(scheduleHash(fs.readFileSync(proof.serverTimeZoneEvidence.path)), proof.serverTimeZoneEvidence.sha256);
  return { projectId: fixture.projectId, targetId: fixture.ipTargetId, projectName: project.body.name, targetName: target.body.name,
    targetLabel: target.body.name && target.body.name !== target.body.targetValue ? `${target.body.name} · ${target.body.targetValue}` : target.body.targetValue,
    serverTimeZone: proof.serverTimeZone };
}

function allowScheduleMutation(method, pathname, body, state) {
  if (method !== 'POST') return false;
  if (pathname === '/api/scan-schedules') return state.createArmed === true && !state.createAttempted && state.fixture
    && body?.projectId === state.fixture.projectId && body?.targetId === state.fixture.targetId
    && body.toolCode === 'tcp_ports' && body.enabled === true && body.cronExpression === state.expectedCron
    && /^0 ([0-5]?\d) ([01]?\d|2[0-3]) \* \* \*$/.test(state.expectedCron || '')
    && Object.keys(body).every(key => ['projectId','targetId','toolCode','enabled','cronExpression','intervalSeconds','parameters'].includes(key))
    && body.intervalSeconds == null && body.parameters && typeof body.parameters === 'object' && !Array.isArray(body.parameters) && Object.keys(body.parameters).length === 0;
  return Number.isSafeInteger(state.ownedId) && state.ownedId > 0 && state.ownedReceiptVerified === true
    && pathname === `/api/scan-schedules/${state.ownedId}/disable` && state.disableArmed === true;
}

function ownedScheduleFromReceipt(response, state) {
  assert.equal(response.status, 201, 'Only actual successful creation201 proves owned schedule');
  const row = response.body;
  assert(Number.isSafeInteger(row?.id) && row.id > 0, 'Creation receipt numeric schedule ID');
  assert(!state.beforeSchedules.some(x => Number(x.id) === row.id), 'Creation ID must be absent from old list');
  assert.equal(Number(row.projectId), Number(state.fixture.projectId));
  assert.equal(Number(row.targetId), Number(state.fixture.targetId)); assert.equal(row.toolCode, 'tcp_ports');
  return row.id;
}

function retainScheduleCreationReceipt(state, response, persist) {
  state.createPending = false; state.creationReceipt = response;
  persist('creation-response-before-assertions', response);
  try {
    state.ownedId = ownedScheduleFromReceipt(response, state); state.ownedReceiptVerified = true;
    state.creationOutcome = 'OWNED_201'; state.needsDisable = true;
    if (response.body.lastTaskId != null || response.body.lastRunAt != null) { state.unexpectedTaskId = response.body.lastTaskId; state.taskReviewRequired = true; }
  } catch (error) {
    state.creationOutcome = 'UNVERIFIED'; state.receiptError = error.stack; state.needsDisable = true;
  }
  persist('creation-ownership-retained-before-case-validation', { ownedId: state.ownedId, outcome: state.creationOutcome });
}

function nextDailyTime(nowMs) {
  const d = new Date(nowMs + 12 * 60 * 60 * 1000);
  const hour = d.getHours(), minute = d.getMinutes();
  return { hour, minute, text: String(hour).padStart(2, '0') + ':' + String(minute).padStart(2, '0'), cron: `0 ${minute} ${hour} * * *` };
}

async function exactScheduleRow(page, dlg, id, trace = async () => {}) {
  if (!Number.isSafeInteger(id) || id <= 0) throw scheduleBlocked('No verified new schedule ID; never select first row');
  // Reopening a dialog can retain its old page. Return through actual previous
  // buttons before searching; changing page state directly is not permitted.
  for (let n = 0; n < 100; n++) {
    const prev = dlg.locator('.tasks-pagination button.btn-prev');
    if (await prev.count() !== 1 || await prev.isDisabled()) break;
    const before = await dlg.locator('.schedule-table .el-table__row').evaluateAll(nodes => nodes.map(row => row.querySelector('td:first-child .cell')?.textContent?.trim()).join(','));
    await prev.click(); await trace('previous-page', { soughtId: id, before });
    const end = Date.now() + 10000; let changed = false;
    while (Date.now() < end) { const after = await dlg.locator('.schedule-table .el-table__row').evaluateAll(nodes => nodes.map(row => row.querySelector('td:first-child .cell')?.textContent?.trim()).join(',')); if (after !== before) { changed = true; break; } await sleep(80); }
    if (!changed) throw scheduleBlocked('Previous schedule page did not change; do not infer row ownership');
    if (n === 99) throw scheduleBlocked('Could not reach first schedule page through bounded previous-page clicks');
  }
  for (let step = 0; step < 100; step++) {
    const table = dlg.locator('.schedule-table');
    if (await table.count() !== 1) throw scheduleBlocked('Schedule table unavailable or ambiguous');
    const rows = table.locator('.el-table__row');
    const visible = await rows.evaluateAll(nodes => nodes.map(n => ({ id: n.querySelector('td:first-child .cell')?.textContent?.trim(), text: n.textContent })));
    await trace('schedule-page', { soughtId: id, visible });
    const matches = visible.map((row, index) => ({ row, index })).filter(x => x.row.id === String(id));
    if (matches.length > 1) throw scheduleBlocked('Duplicate exact schedule ID in visible table');
    if (matches.length === 1) {
      const row = rows.nth(matches[0].index);
      assert.equal((await row.locator('td').nth(0).innerText()).trim(), String(id));
      return row;
    }
    const next = dlg.locator('.tasks-pagination button.btn-next');
    if (await next.count() !== 1 || await next.isDisabled()) throw scheduleBlocked('Verified new schedule ID is not reachable through actual UI pagination: ' + id);
    const previousIds = visible.map(r => r.id).join(','); await next.click();
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) { const currentIds = await rows.evaluateAll(nodes => nodes.map(n => n.querySelector('td:first-child .cell')?.textContent?.trim()).join(',')); if (currentIds !== previousIds) break; await sleep(80); }
    if (await rows.evaluateAll(nodes => nodes.map(n => n.querySelector('td:first-child .cell')?.textContent?.trim()).join(',')) === previousIds) throw scheduleBlocked('Exact schedule pagination did not advance');
  }
  throw scheduleBlocked('Schedule pagination bound reached; no first-row fallback');
}

async function runSchedules(page, H, ctx) {
  const dir = path.join(H.dir, 'fresh-schedules-' + Date.now()); fs.mkdirSync(dir, { recursive: true });
  let current = 'F-18', serial = 0, journal = 0, initialized = false, finishing = false, cleaned = false;
  const state = { fixture: null, beforeSchedules: null, createArmed: false, createAttempted: false, createPending: false,
    disableArmed: false, disablePending: false, ownedId: null, ownedReceiptVerified: false, needsDisable: false,
    creationOutcome: 'NOT_ATTEMPTED', oldRowsNeverMutated: true, responses: [], violations: [] };
  const pending = new Set(), inflight = new Set(), requestMap = new WeakMap(), asyncErrors = [];
  const logs = ctx.recorder ? createRecorderCompat({ recorder: ctx.recorder, directory: dir, source: 'fresh-schedules', getCase: () => current }) : null;
  const record = async (name, value) => { if (logs) await logs.write(name, value); else fs.writeFileSync(path.join(dir, name + '.json'), JSON.stringify(value, null, 2)); };
  function persist(event, detail = {}) {
    ctx.fullScheduleId = state.ownedId; ctx.fullScheduleNeedsDisable = state.needsDisable;
    ctx.fullSchedulePending = state.createPending || state.disablePending || inflight.size > 0;
    ctx.fullScheduleTaskReviewPending = Boolean(state.taskReviewRequired);
    ctx.fullScheduleUnsafeToRestart = ctx.fullSchedulePending || state.needsDisable || ctx.fullScheduleTaskReviewPending;
    const file = path.join(dir, 'lifecycle-' + String(++journal).padStart(5, '0') + '.json');
    // Synchronous append-only receipt before later assertions/awaits can fail.
    fs.writeFileSync(file, JSON.stringify({ at: new Date().toISOString(), event, detail, state: { ...state, responses: undefined },
      flags: { pending: ctx.fullSchedulePending, needsDisable: ctx.fullScheduleNeedsDisable, unsafeToRestart: ctx.fullScheduleUnsafeToRestart } }, null, 2), { flag: 'wx' });
    ctx.fullScheduleStateFile = file; return file;
  }
  const track = promise => { const p = Promise.resolve(promise); pending.add(p); p.catch(e => asyncErrors.push(e)).finally(() => pending.delete(p)); return p; };
  const drain = async () => { while (pending.size) await Promise.allSettled([...pending]); await logs?.flush(); if (asyncErrors.length) throw asyncErrors[0]; };
  const wait = async (fn, why, ms = 25000) => { const end = Date.now() + ms; while (Date.now() < end) { const result = await fn(); if (result) return result; await sleep(80); } throw scheduleBlocked(why); };
  const origin = new URL(new URL(page.url()).searchParams.get('backend')).origin;
  if (!['localhost', '127.0.0.1'].includes(new URL(origin).hostname)) throw scheduleBlocked('Schedule batch requires actual loopback backend');
  const onRequest = req => { const u = new URL(req.url()); if (u.origin !== origin || u.pathname !== '/api/scan-schedules' && !/^\/api\/scan-schedules\/\d+\/(disable|enable)$/.test(u.pathname)) return;
    let body; try { body = req.postDataJSON(); } catch { body = req.postData(); }
    const row = { serial: ++serial, caseId: current, url: req.url(), method: req.method(), body };
    requestMap.set(req, row); track(record('request-' + row.serial, row)); };
  const onResponse = res => { const request = requestMap.get(res.request());
    if (!request || new URL(res.url()).origin !== origin || /text\/event-stream/i.test(res.headers()['content-type'] || '')) return;
    if (logs && !logs.shouldCollect(res)) return;
    track((async () => { const row = { request, status: res.status() };
      try { row.body = logs ? await logs.responseJson(res) : await res.json(); } catch (e) { row.readError = { message: e.message, stack: e.stack }; }
      const pathname = new URL(request.url).pathname;
      if (request.method === 'POST' && pathname === '/api/scan-schedules') {
        retainScheduleCreationReceipt(state, row, persist);
      }
      if (request.method === 'POST' && pathname === `/api/scan-schedules/${state.ownedId}/disable`) { state.disablePending = false; state.disableReceipt = row; }
      state.responses.push(row); inflight.delete(res.request()); persist('response-settled', row);
      await record('response-' + request.serial, logs ? logs.tagResponse(row, res) : row);
      if (finishing && !inflight.size) queueMicrotask(() => { void cleanup().catch(e => { asyncErrors.push(e); persist('late-cleanup-error', { error: e.stack }); }); });
    })()); };
  const onFailed = req => { const r = requestMap.get(req); if (!r) return;
    inflight.delete(req); if (r.method === 'POST') { state.createPending = false; state.disablePending = false; state.needsDisable = true; state.creationOutcome = state.ownedId ? state.creationOutcome : 'TRANSPORT_UNKNOWN'; }
    persist('request-failed-outcome-not-assumed', { request: r, error: req.failure() });
    if (finishing && !inflight.size) queueMicrotask(() => { void cleanup().catch(e => { asyncErrors.push(e); persist('late-cleanup-error', { error: e.stack }); }); }); };
  const guard = async route => { const req = route.request(), u = new URL(req.url()); if (u.origin === origin && ['GET','HEAD','OPTIONS'].includes(req.method())) return route.fallback();
    let body; try { body = req.postDataJSON(); } catch {}
    if (u.origin === origin && allowScheduleMutation(req.method(), u.pathname, body, state)) {
      inflight.add(req);
      if (u.pathname === '/api/scan-schedules') { state.createArmed = false; state.createAttempted = true; state.createPending = true; state.needsDisable = true; state.creationOutcome = 'REQUEST_ADMITTED_OUTCOME_UNKNOWN'; }
      else { state.disableArmed = false; state.disablePending = true; }
      persist('mutation-admitted-before-network', { url: req.url(), method: req.method(), body }); return route.fallback();
    }
    state.violations.push({ caseId: current, url: req.url(), method: req.method(), body }); persist('blocked-unowned-schedule-mutation'); return route.abort('blockedbyclient'); };
  async function cleanup() { if (cleaned) return; if (inflight.size) return;
    await drain(); await page.unroute('**/api/scan-schedules**', guard); page.off('request', onRequest); page.off('response', onResponse); page.off('requestfailed', onFailed);
    ctx.recorder?.clearCaseResolver?.(); cleaned = true; persist('observers-removed-state-retained'); }
  async function ensureDialog() {
    if (!initialized) throw scheduleBlocked('Fresh schedule prerequisites failed');
    if (await page.locator('.el-message-box:visible').count()) throw scheduleBlocked('Unexpected confirmation dialog; do not click generic last button');
    const existing = page.locator('.el-dialog:visible').filter({ has: page.getByText('定时任务管理', { exact: true }) });
    if (await existing.count() === 1) return existing;
    const trigger = page.locator('button.schedule-trigger'); assert.equal(await trigger.count(), 1); await trigger.click();
    const dlg = await dialog(page, '定时任务管理'); await dlg.waitFor({ state: 'visible' }); return dlg;
  }
  async function refreshedSchedules() {
    const visible = page.locator('.el-dialog:visible').filter({ has: page.getByText('定时任务管理', { exact: true }) });
    if (await visible.count()) { const cancel = visible.getByRole('button', { name: '取消', exact: true }); assert.equal(await cancel.count(), 1); await cancel.click(); }
    const start = serial, refresh = page.locator('.tasks-page > .section-head .section-head-actions').getByRole('button', { name: '刷新', exact: true });
    assert.equal(await refresh.count(), 1); await refresh.click();
    const row = await wait(() => state.responses.find(r => r.request.serial > start && r.request.method === 'GET' && new URL(r.request.url).pathname === '/api/scan-schedules'), 'Normal task refresh did not return finite schedule list');
    assert.equal(row.status, 200); assert(Array.isArray(row.body)); return row.body;
  }
  async function test(id, name, fn) { current = id; return H.run(id, name, async () => { try { return await fn(); }
    finally { persist('case-finished-' + id); await record(id + '-state', { state, visibleText: await page.locator('body').innerText(), contextStateFile: ctx.fullScheduleStateFile }); await drain(); } }, { page, shotOnPass: true }); }
  try {
    await test('F-18', '打开定时管理并核验本轮新项目/132新目标证据', async () => {
      if (!logs) throw scheduleBlocked('Shared parent recorder required for fresh schedule batch');
      if (!ctx.fullScheduleFixtureProof) throw scheduleBlocked('Immutable actual fresh-fixture POST/membership proof required');
      const proof = JSON.parse(fs.readFileSync(ctx.fullScheduleFixtureProof || '', 'utf8').replace(/^\uFEFF/, ''));
      state.fixture = validateScheduleFixtureProof(ctx, proof); await record('fresh-fixture-proof', proof);
      const zones = await page.evaluate(() => ({ zone: Intl.DateTimeFormat().resolvedOptions().timeZone, now: Date.now() }));
      assert.equal(zones.zone, state.fixture.serverTimeZone, 'Browser and verified Java timezone must agree');
      assert.equal(Intl.DateTimeFormat().resolvedOptions().timeZone, zones.zone, 'Controller timezone must agree'); assert(Math.abs(zones.now - Date.now()) < 3000);
      page.on('request', onRequest); page.on('response', onResponse); page.on('requestfailed', onFailed); await page.route('**/api/scan-schedules**', guard); initialized = true;
      await navigate(page, '检测任务'); state.beforeSchedules = await refreshedSchedules(); persist('old-schedules-frozen');
      const dlg = await ensureDialog(); return { originalSchedules: state.beforeSchedules, fixture: state.fixture, visible: await dlg.isVisible(), networkTarget: TARGET_IP };
    });
    await test('F-19', '定时任务表单四类控件可达且新夹具状态齐备', async () => {
      const dlg = await ensureDialog(), text = await dlg.innerText(); for (const label of ['安全评估项目','项目授权目标','检测工具','执行方式']) assert(text.includes(label)); return { text };
    });
    await test('F-20', '只为本轮132新目标创建约12小时后每天计划并保留201新ID', async () => {
      const dlg = await ensureDialog(); if (state.createAttempted) throw scheduleBlocked('Creation already attempted; never duplicate after unknown outcome');
      for (const [label, value] of [['安全评估项目', state.fixture.projectName], ['项目授权目标', state.fixture.targetLabel], ['检测工具', 'TCP 端口探测']]) {
        const field = dlg.locator('.el-form-item').filter({ has: page.locator('.el-form-item__label').filter({ hasText: new RegExp('^\\s*\\*?\\s*' + label + '\\s*[:：]?\\s*$') }) });
        assert.equal(await field.count(), 1);
        await wait(() => field.locator('.el-select').evaluate(el => !el.classList.contains('is-disabled') && !el.querySelector('.is-loading') && !el.querySelector('[aria-disabled="true"]')), 'Schedule selector not ready: ' + label);
        await selectOption(dlg, page, label, value, { exact: true });
      }
      const daily = dlg.locator('.schedule-mode-picker .el-radio-button').filter({ hasText: /^每天$/ }); assert.equal(await daily.count(), 1); await daily.click();
      const time = nextDailyTime(Date.now()); state.expectedCron = time.cron; state.selectedTime = time;
      const input = dlg.getByPlaceholder('选择执行时间', { exact: true }); assert.equal(await input.count(), 1); await input.click();
      const panel = page.locator('.el-time-panel:visible'); await panel.waitFor({ state: 'visible' }); assert.equal(await panel.count(), 1);
      const columns = panel.locator('.el-time-spinner__wrapper'); assert.equal(await columns.count(), 2);
      for (const [index, value] of [[0,time.hour],[1,time.minute]]) { const item = columns.nth(index).locator('.el-time-spinner__item').filter({ hasText: new RegExp('^\\s*' + String(value).padStart(2,'0') + '\\s*$') }); assert.equal(await item.count(), 1); await item.click(); }
      const confirm = panel.getByRole('button', { name: '确定', exact: true }); assert.equal(await confirm.count(), 1); await confirm.click(); assert.equal(await input.inputValue(), time.text);
      state.createArmed = true; persist('create-ui-armed', { time });
      const create = dlg.getByRole('button', { name: '创建', exact: true }); assert.equal(await create.count(), 1); await create.click();
      await wait(() => state.creationReceipt || state.creationOutcome === 'TRANSPORT_UNKNOWN', 'Creation response missing; possible active schedule retained for parent');
      if (!state.ownedReceiptVerified) throw scheduleBlocked('New schedule ownership not proven by201; inspect retained receipt, no guessed ID');
      const saved = state.creationReceipt.body; assert.equal(saved.enabled, true); assert.equal(saved.cronExpression, time.cron); assert(saved.intervalSeconds == null);
      assert.equal(saved.parametersJson, '{}'); assert(Date.parse(saved.nextRunAt) - Date.now() >= 6 * 60 * 60 * 1000, 'Next run must be safely future; still proceed to exact owned disable after failure');
      assert(saved.lastTaskId == null && saved.lastRunAt == null, 'No schedule dispatch expected');
      return { scheduleId: state.ownedId, fullCreationReceipt: state.creationReceipt, needsDisable: true, intendedTargetPackets: 0 };
    });
    await test('F-21', '准确201新ID出现在列表并完整回读', async () => {
      if (!state.ownedReceiptVerified) throw scheduleBlocked('No proven new schedule ID');
      const list = await refreshedSchedules(); for (const old of state.beforeSchedules) assert.deepEqual(list.find(r => r.id === old.id), old, 'Old schedule changed');
      const saved = list.find(r => r.id === state.ownedId); assert(saved); assert.equal(saved.projectId, state.fixture.projectId); assert.equal(saved.targetId, state.fixture.targetId); assert.equal(saved.cronExpression, state.expectedCron);
      const dlg = await ensureDialog(), row = await exactScheduleRow(page, dlg, state.ownedId, (label,data) => record('F-21-' + label + '-' + Date.now(),data));
      const text = await row.innerText(); assert(text.includes(state.fixture.projectName) && text.includes(TARGET_IP) && text.includes('TCP 端口探测')); return { saved, visibleText: text };
    });
    await test('F-22', '仅停用准确201新ID并从正常UI回读已停用', async () => {
      if (!state.ownedReceiptVerified) throw scheduleBlocked('No verified201 new ID; unsafe to select any schedule row');
      const dlg = await ensureDialog(), row = await exactScheduleRow(page, dlg, state.ownedId, (label,data) => record('F-22-' + label + '-' + Date.now(),data));
      const disable = row.getByRole('button', { name: '停用', exact: true });
      if (await disable.count() === 1) { state.disableArmed = true; persist('exact-owned-disable-armed'); await disable.click();
        await wait(() => state.disableReceipt, 'Disable receipt missing; new schedule remains needsDisable');
        assert.equal(state.disableReceipt.status,200); assert.equal(state.disableReceipt.body.id,state.ownedId); assert.equal(state.disableReceipt.body.enabled,false); }
      else if (!((await row.innerText()).includes('已停用'))) throw scheduleBlocked('Exact owned row has no disable action or disabled state');
      const list = await refreshedSchedules(), saved = list.find(r => r.id === state.ownedId);
      assert(saved && saved.enabled === false && saved.nextRunAt == null, 'Normal UI GET must confirm disabled and no next run');
      assert.equal(saved.projectId,state.fixture.projectId); assert.equal(saved.targetId,state.fixture.targetId);
      if(saved.lastTaskId!=null||saved.lastRunAt!=null){state.unexpectedTaskId=saved.lastTaskId;state.taskReviewRequired=true;}
      state.needsDisable = false; state.disabledVerified = saved; persist('exact-owned-disabled-and-read-back');
      assert(saved.lastTaskId == null && saved.lastRunAt == null, 'Unexpected dispatched task requires separate parent review; verified schedule stays disabled');
      for (const old of state.beforeSchedules) assert.deepEqual(list.find(r => r.id === old.id),old,'Old schedule must remain identical');
      return { saved, noOldScheduleMutation:true, retainedNewScheduleId:state.ownedId };
    });
    await H.run('F-23','旧定时任务删除合同保持阻断',async()=>{throw scheduleBlocked('Main runner deletion guard retained; no schedule is deleted by this batch');},{page});
    await test('F-24','确认新计划已停用后关闭管理对话框并保留数据',async()=>{
      if(state.needsDisable||ctx.fullSchedulePending||ctx.fullScheduleTaskReviewPending)throw scheduleBlocked('New schedule may still be active/pending or already dispatched; leave visible for parent, do not close or silently finish');
      const dlg=await ensureDialog(),cancel=dlg.getByRole('button',{name:'取消',exact:true});assert.equal(await cancel.count(),1);await cancel.click();return {retainedId:state.ownedId,disabled:state.ownedId?true:null,creationAttempted:state.createAttempted};
    });
  } finally {
    finishing = true; persist('batch-return-parent-obligation'); await record('result',{state,contextStateFile:ctx.fullScheduleStateFile,needsParentAction:ctx.fullScheduleUnsafeToRestart,deleteNotExecuted:true});
    if(initialized&&!inflight.size)await cleanup(); else if(inflight.size)persist('observers-retained-for-late-response'); else ctx.recorder?.clearCaseResolver?.();
  }
  return {dir,scheduleId:state.ownedId,pending:ctx.fullSchedulePending,needsDisable:state.needsDisable,stateFile:ctx.fullScheduleStateFile};
}

// Current product labels from src/utils/aiPresentation.ts; retain stable tool codes in context.
const TOOL_CODES = { "TCP 端口探测": "tcp_ports", "HTTP 安全响应头检查": "http_headers", "HTTP 常见安全检查": "http_security_check" };

const TERMINAL = ["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED", "REJECTED", "SKIPPED"];
const STATUS_MAP = {
  "成功": "SUCCESS", "失败": "FAILED", "超时": "TIMEOUT", "已取消": "CANCELLED",
  "已拒绝": "REJECTED", "已跳过": "SKIPPED", "待执行": "PENDING", "排队中": "PENDING",
  "等待前置": "BLOCKED", "执行中": "RUNNING", "准备中": "RUNNING", "停止中": "RUNNING",
  "已停止": "CANCELLED", "部分失败": "FAILED",
  "SUCCESS": "SUCCESS", "FAILED": "FAILED", "TIMEOUT": "TIMEOUT", "CANCELLED": "CANCELLED",
  "REJECTED": "REJECTED", "SKIPPED": "SKIPPED", "PENDING": "PENDING", "RUNNING": "RUNNING", "BLOCKED": "BLOCKED"
};

/** 解析任务表格行：ID、工具、状态、进度、创建时间 */
async function readTasks(page) {
  const rows = page.locator(".el-table__row");
  const n = await rows.count();
  const out = [];
  for (let i = 0; i < n; i++) {
    const row = rows.nth(i);
    const raw = ((await row.textContent()) || "").replace(/\s+/g, " ").trim();
    const cells = row.locator("td");
    const cellCount = await cells.count();
    let taskId = null;
    let tool = null;
    let targetId = null;
    let status = null;
    let progress = null;
    let time = null;

    if (cellCount >= 6) {
      taskId = ((await cells.nth(0).textContent()) || "").trim() || null;
      tool = ((await cells.nth(1).textContent()) || "").trim() || null;
      targetId = ((await cells.nth(2).textContent()) || "").trim() || null;
      const statusRaw = ((await cells.nth(3).textContent()) || "").trim();
      status = STATUS_MAP[statusRaw] || null;
      const progressRaw = ((await cells.nth(4).textContent()) || "").trim();
      const pm = progressRaw.match(/(\d+)\s*%/);
      progress = pm ? Number(pm[1]) : null;
      const timeRaw = ((await cells.nth(5).textContent()) || "").trim();
      const tm = timeRaw.match(/(20\d\d-\d\d-\d\d \d\d:\d\d:\d\d)/);
      time = tm ? tm[1] : null;
    } else {
      tool = (raw.match(/(tcp_ports|http_headers|http_security_check|tls_config|nmap_service_scan|nuclei_scan|afrog_scan|xray_scan)/) || [])[1] || null;
      for (const [k, v] of Object.entries(STATUS_MAP)) {
        if (raw.includes(k)) { status = v; break; }
      }
      const timeMatch = (raw.match(/(20\d\d-\d\d-\d\d \d\d:\d\d:\d\d)/) || [])[1] || null;
      time = timeMatch;
      const progressMatch = (raw.match(/(\d+)\s*%/) || [])[1] || null;
      progress = progressMatch ? Number(progressMatch) : null;
      taskId = (raw.match(/^(\d+)/) || [])[1] || null;
    }

    const toolLabel = tool;
    tool = TOOL_CODES[tool] || tool;
    out.push({ i, raw, tool, toolLabel, status, time, taskId, targetId, progress });
  }
  return out;
}

/** 本次运行窗口内创建的任务 */
function ownTasks(tasks, sinceMs) {
  return tasks.filter((t) => {
    if (!t.time) return false;
    const ts = new Date(t.time.replace(" ", "T")).getTime();
    return ts >= sinceMs;
  });
}

async function clickRefresh(page) {
  const btn = page.locator("button", { hasText: "刷新" }).first();
  if (await btn.isVisible().catch(() => false)) { await btn.click(); await sleep(1200); }
}

async function run(page, H, ctx) {
  H.phase("阶段 F — 任务控制中心");

  // 本次任务的时间下界：留 20 分钟余量
  const since = Date.now() - 20 * 60 * 1000;

  await H.run("F-01", "通过侧边栏进入「检测任务」页面", async () => {
    await navigate(page, "检测任务");
    const t = await pageTitle(page);
    if (!page.url().includes("/tasks")) throw new Error(`URL 异常: ${page.url()}`);
    return `标题="${t}"`;
  }, { page });

  await sleep(2500);
  await H.shot(page, "F-任务中心");

  await H.run("F-02", "任务中心展示并发配额概览", async () => {
    const sum = page.locator(".task-control-summary").first();
    if (!(await sum.count())) throw new Error("未渲染任务资源配额区");
    const t = ((await sum.textContent()) || "").replace(/\s+/g, " ").trim();
    for (const k of ["当前运行", "等待队列"]) {
      if (!t.includes(k)) throw new Error(`配额概览缺少「${k}」: ${t.slice(0, 150)}`);
    }
    return `配额概览: ${t.slice(0, 130)}`;
  }, { page });

  await H.run("F-03", "任务列表加载并包含本次创建的检测任务", async () => {
    await page.locator(".el-table").first().waitFor({ state: "visible", timeout: 15000 });
    const n = await rowCount(page);
    if (n === 0) throw new Error("任务列表为空");
    const mine = ownTasks(await readTasks(page), since);
    if (mine.length === 0) throw new Error(`未找到本次运行窗口内创建的任务（列表共 ${n} 行）`);
    ctx.taskRowsTotal = n;
    return `列表共 ${n} 行，本次创建 ${mine.length} 个（工具: ${[...new Set(mine.map((t) => t.tool))].join("、")}）`;
  }, { page });

  // ---------- 等待任务执行完成 ----------
  await H.run("F-04", "本次创建的检测任务全部执行至终态", async () => {
    const expected = (ctx.ipScanTaskCount || 0) + (ctx.webScanTaskCount || 0);
    let last = "";
    for (let round = 0; round < 60; round++) {
      const mine = ownTasks(await readTasks(page), since);
      const done = mine.filter((t) => TERMINAL.includes(t.status));
      last = `本次任务 ${mine.length} 个，终态 ${done.length} 个`;
      if (mine.length >= expected && done.length === mine.length) {
        ctx.ownTasks = done;
        ctx.taskPairs = done
          .filter((t) => t.taskId && t.targetId && t.status === "SUCCESS")
          .map((t) => ({ taskId: t.taskId, targetId: t.targetId, tool: t.tool }));
        const byStatus = {};
        for (const d of done) byStatus[d.status] = (byStatus[d.status] || 0) + 1;
        return `${last}（期望 ${expected} 个）状态分布: ${JSON.stringify(byStatus)}`;
      }
      await sleep(3000);
      await clickRefresh(page);
    }
    throw new Error(`180 秒内任务未全部到达终态：${last}`);
  }, { page });

  await H.shot(page, "F-任务已完成");

  await H.run("F-05", "端口探测任务（tcp_ports）执行成功", async () => {
    const mine = ownTasks(await readTasks(page), since);
    const tcp = mine.filter((t) => t.tool === "tcp_ports");
    if (tcp.length === 0) throw new Error("未找到 tcp_ports 任务");
    const ok = tcp.filter((t) => t.status === "SUCCESS");
    if (ok.length === 0) throw new Error(`tcp_ports 任务未成功: ${tcp.map((t) => t.status).join(",")}`);
    return `${ok.length}/${tcp.length} 个端口探测任务 SUCCESS`;
  }, { page });

  await H.run("F-06", "HTTP 安全检查任务执行成功", async () => {
    const mine = ownTasks(await readTasks(page), since);
    const http = mine.filter((t) => t.tool === "http_headers" || t.tool === "http_security_check");
    if (http.length === 0) throw new Error("未找到 HTTP 检查任务");
    const ok = http.filter((t) => t.status === "SUCCESS");
    if (ok.length !== http.length) {
      throw new Error(`部分 HTTP 任务未成功: ${http.map((t) => `${t.tool}=${t.status}`).join(", ")}`);
    }
    return `${ok.length}/${http.length} 个 HTTP 检查任务 SUCCESS`;
  }, { page });

  await H.run("F-07", "成功任务进度显示为 100%", async () => {
    const mine = ownTasks(await readTasks(page), since).filter((t) => t.status === "SUCCESS");
    if (mine.length === 0) throw new Error("无成功任务");
    const notFull = mine.filter((t) => t.progress !== 100);
    if (notFull.length) throw new Error(`${notFull.length} 个成功任务进度不是 100%`);
    return `${mine.length} 个成功任务进度均为 100%`;
  }, { page });

  // ---------- 任务详情 ----------
  let ownRowIndex = 0;
  await H.run("F-08", "点击「详情」打开任务详情对话框", async () => {
    const mine = ownTasks(await readTasks(page), since).filter((t) => t.status === "SUCCESS");
    if (mine.length === 0) throw new Error("无成功任务可查看");
    ownRowIndex = mine[0].i;
    await page.locator(".el-table__row").nth(ownRowIndex)
      .locator("button", { hasText: "详情" }).first().click();
    const dlg = await dialog(page, "任务详情");
    if (!(await dlg.isVisible())) throw new Error("详情对话框未显示");
    return `已打开第 ${ownRowIndex + 1} 行任务详情`;
  }, { page });

  await H.shot(page, "F-任务详情");

  await H.run("F-09", "任务详情的授权快照中包含本次靶机地址", async () => {
    const dlg = await dialog(page, "任务详情");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const missing = ["授权目标快照", "允许端口快照", "授权声明"].filter((k) => !text.includes(k));
    if (missing.length) throw new Error(`详情缺少字段: ${missing.join("、")}`);
    if (!text.includes(ctx.targetIp)) {
      throw new Error(`快照未包含靶机地址 ${ctx.targetIp}`);
    }
    return `快照含靶机 ${ctx.targetIp}，授权字段完整`;
  }, { page });

  await H.run("F-10", "任务详情展示工具版本与规则版本指纹", async () => {
    const dlg = await dialog(page, "任务详情");
    const text = ((await dlg.textContent()) || "").replace(/\s+/g, " ");
    const has = ["工具版本", "规则版本"].filter((k) => text.includes(k));
    if (has.length === 0) throw new Error("详情未展示工具版本或规则版本");
    return `已展示: ${has.join("、")}`;
  }, { page });

  await H.run("F-11", "任务详情展示执行结果与实时执行日志", async () => {
    const dlg = await dialog(page, "任务详情");
    const refresh = dlg.getByRole('button', { name: /^(刷新详情|重试加载)$/ });
    if (await refresh.isEnabled()) await refresh.click();
    const collapse = dlg.locator('.el-collapse-item').filter({ hasText: '原始输出（高级排查）' });
    await collapse.waitFor({ state: 'visible', timeout: 20000 });
    const header = collapse.locator('.el-collapse-item__header');
    if (await header.getAttribute('aria-expanded') !== 'true') await header.click();
    const raw = collapse.locator('textarea').first();
    await raw.waitFor({ state: 'visible' });
    const logs = dlg.locator('textarea[aria-label="实时执行日志"], [aria-label="实时执行日志"] textarea').first();
    await logs.waitFor({ state: 'visible' });
    const resultText = (await raw.inputValue()).trim();
    const logText = (await logs.inputValue()).trim();
    ctx.taskResultOutput = resultText;
    ctx.taskLogSample = logText;
    if (!resultText || !logText) throw new Error('真实执行结果或日志为空: ' + JSON.stringify({ resultText, logText, visibleText: await dlg.innerText() }));
    return { input: '刷新详情→展开原始输出（高级排查）', expected: '执行结果和实时日志均非空', actual: { resultText, logText } };
  }, { page });

  await H.run("F-12", "任务详情中的执行结果包含针对靶机的真实探测输出", async () => {
    const dlg = await dialog(page, "任务详情");
    const collapse = dlg.locator('.el-collapse-item').filter({ hasText: '原始输出（高级排查）' });
    await collapse.waitFor({ state: 'visible', timeout: 20000 });
    const header = collapse.locator('.el-collapse-item__header');
    if (await header.getAttribute('aria-expanded') !== 'true') await header.click();
    const sample = (await collapse.locator('textarea').first().inputValue()).trim();
    ctx.taskResultOutput = sample;
    if (!sample || sample === '{}' || sample === 'null') throw new Error("真实原始执行输出为空，不能以任务SUCCESS替代输出校验");
    if (!(sample.includes(ctx.targetIp) || /port|端口|header|Header|http|HTTP/.test(sample))) {
      throw new Error(`执行输出与探测内容无关: ${sample.slice(0, 200)}`);
    }
    return { expected: '原始结果与本轮探测内容相关', actual: { length: sample.length, output: sample } };
  }, { page });

  await H.run("F-13", "关闭任务详情对话框", async () => {
    const dlg = await dialog(page, "任务详情");
    await dialogButton(dlg, "关闭");
    await sleep(1200);
    if (await dlg.isVisible().catch(() => false)) throw new Error("对话框未关闭");
    return "已关闭";
  }, { page });

  // ---------- 报告 ----------
  await H.run("F-14", "成功任务可获取 HTML 检测报告", async () => {
    await clearMessages(page);
    const row = page.locator(".el-table__row").nth(ownRowIndex);
    const btn = row.locator("button", { hasText: "报告" }).first();
    if (!(await btn.count())) throw new Error("未找到报告按钮");
    if (await btn.isDisabled()) throw new Error("成功任务的报告按钮不可用");
    const taskId = ((await row.locator("td").first().textContent()) || "").trim();
    if (!/^\d+$/.test(taskId)) throw new Error(`无法确认报告任务ID: ${taskId}`);
    const rec = await captureReport(page, H, btn, `/api/reports/tasks/${taskId}/download`, "f-task", 40000);
    if (!/text\/html/i.test(rec.contentType)) throw new Error(`报告内容类型异常: ${rec.contentType}`);
    if (rec.status !== 200) throw new Error(`报告接口返回 ${rec.status}`);
    if (rec.size < 200) throw new Error(`报告体积异常，仅 ${rec.size} 字节`);
    ctx.taskReportRecord = rec;
    return `HTTP ${rec.status}，${rec.contentType}，${rec.size} 字节`;
  }, { page });

  await H.run("F-15", "非成功状态任务的报告按钮被禁用", async () => {
    const tasks = await readTasks(page);
    const bad = tasks.filter((t) => t.status && t.status !== "SUCCESS");
    if (bad.length === 0) return "当前列表无非成功任务，跳过断言";
    for (const t of bad) {
      const btn = page.locator(".el-table__row").nth(t.i).locator("button", { hasText: "报告" }).first();
      if (!(await btn.count())) continue;
      if (!(await btn.isDisabled())) {
        throw new Error(`${t.status} 状态任务的报告按钮仍可用: ${t.raw.slice(0, 120)}`);
      }
      return `${t.status} 状态任务的报告按钮已正确禁用`;
    }
    return "未渲染报告按钮，跳过";
  }, { page });

  await H.run("F-16", "已完成任务不再提供取消操作", async () => {
    const row = page.locator(".el-table__row").nth(ownRowIndex);
    const cancel = row.locator("button", { hasText: "取消" });
    if ((await cancel.count()) === 0) return "成功任务未渲染取消按钮";
    if (!(await cancel.first().isDisabled())) throw new Error("成功任务的取消按钮仍可点击");
    return "成功任务的取消按钮已禁用";
  }, { page });

  await H.run("F-17", "任务行提供「执行诊断」AI联动入口", async () => {
    const row = page.locator(".el-table__row").nth(ownRowIndex);
    const ai = row.getByRole("button", { name: "执行诊断", exact: true });
    if (!(await ai.isVisible())) throw new Error("未渲染执行诊断入口");
    if (!(await ai.isEnabled())) throw new Error("执行诊断入口不可用");
    return { detail: "执行诊断入口可见且可用；真实AI调用由DAI-ENTRY-TASK单独验证", verificationDepth: "entry-availability-only" };
  }, { page });

  // Exact new201 schedule IDs only; old deletion remains BLOCKED.
  await runSchedules(page, H, ctx);

  return true;
}

module.exports = { run, runSchedules, validateScheduleFixtureProof, allowScheduleMutation, ownedScheduleFromReceipt, retainScheduleCreationReceipt, nextDailyTime, exactScheduleRow };
