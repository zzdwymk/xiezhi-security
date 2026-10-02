const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const cache = new Map();
function load(file) {
  file = path.resolve(file);
  if (cache.has(file)) return cache.get(file).exports;
  const module = { exports: {} }; cache.set(file, module);
  const code = ts.transpileModule(fs.readFileSync(file, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText;
  const requireLocal = name => name.startsWith('.') ? load(path.resolve(path.dirname(file), name + '.ts')) : require(name);
  vm.runInThisContext(`(function(require,module,exports){${code}\n})`, { filename: file })(requireLocal, module, module.exports);
  return module.exports;
}
const { buildAiProgress, aiProgressEventTitle } = load(path.join(__dirname, '../src/utils/aiProgress.ts'));
const { publicAiProgressText, isPublicAiProgressEvent, aiProgressFailureText } = load(path.join(__dirname, '../src/utils/aiPresentation.ts'));
const origin = Date.parse('2026-09-29T10:00:00Z');
const at = seconds => new Date(origin + seconds * 1000).toISOString();
const message = patch => ({ id: 'message', role: 'assistant', content: '', status: 'running', taskIds: [], steps: [], createdAt: at(0), updatedAt: at(0), ...patch });
let passed = 0;
function test(name, run) { run(); passed++; console.log('PASS ' + name); }

test('request is visible before the first stream event without invented progress', () => {
  const p = buildAiProgress(message(), [], origin + 21000);
  assert.equal(p.entries.length, 0); assert.equal(p.active, true);
  assert.equal(p.elapsed, 21000); assert.equal(p.quietFor, 21000);
  assert.equal(p.currentTitle, '等待处理反馈'); assert.equal(p.evidenceCount, undefined);
});
test('distinct stages and evidence summaries survive the same public node status', () => {
  const p = buildAiProgress(message({ agentEvents: [
    { type: 'plan', stage: 'model', publicNodeStatus: 'ROUTING', summary: '正在请求模型', createdAt: at(1) },
    { type: 'evidence', stage: 'retrieve', publicNodeStatus: 'ROUTING', summary: '找到目标历史检测依据', evidenceCount: 3, createdAt: at(4) },
    { type: 'decision', stage: 'review', summary: '依据不足，先检查HTTP响应头', createdAt: at(7) },
  ] }), [], origin + 9000);
  assert.equal(p.entries.length, 3); assert.equal(p.evidenceCount, 3);
  assert.match(p.entries[1].detail, /历史检测依据/); assert.match(p.decision, /依据不足/);
});
test('private reasoning and raw payloads cannot reach progress rendering', () => {
  for (const type of ['thinking', 'reasoning', 'chain_of_thought', 'analysis_delta', 'cot'])
    assert.equal(isPublicAiProgressEvent({ type }), false);
  const p = buildAiProgress(message({ agentEvents: [
    { type: 'thinking', summary: 'PRIVATE_TEXT', publicNodeStatus: 'ROUTING' },
    { type: 'progress', summary: '<think>PRIVATE_TEXT</think>' },
    { type: 'tool_result', output: 'PRIVATE_OUTPUT', input: { password: 'PRIVATE_PASSWORD' }, summary: '检查已返回' },
  ] }), [], origin + 9000);
  assert.ok(!p.entries.some(e => /PRIVATE/.test(e.title + e.detail)));
  assert.equal(publicAiProgressText('{"runId":"internal"}'), '');
  assert.equal(publicAiProgressText('runId=internal\n正在检索'), '正在检索');
});
test('agent done never marks a running detection task complete', () => {
  const task = { id: 17, toolCode: 'nmap_service_scan', status: 'RUNNING', createdAt: at(1), startedAt: at(2), progressMessage: '扫描1个授权端口' };
  const p = buildAiProgress(message({ status: 'completed', taskIds: [17], agentEvents: [{ type: 'done', createdAt: at(3) }] }), [task], origin + 10000);
  assert.equal(p.active, true); assert.equal(p.completeTasks, 0);
  assert.match(p.currentTitle, /任务正在推进/); assert.match(p.currentDetail, /1个授权端口/);
});
test('confirmed and unnecessary approval events do not read as waiting', () => {
  for (const approvalStatus of ['APPROVED', 'CONFIRMED', 'NOT_REQUIRED'])
    assert.equal(aiProgressEventTitle({ type: 'approval', approvalStatus, publicNodeStatus: 'WAITING_APPROVAL' }), '执行条件已确认');
});
test('skipped phases do not claim successful execution', () => {
  const p = buildAiProgress(message({ agentEvents: [{ type: 'stage', stage: 'validate', status: 'SKIPPED', summary: '本轮无需验证', createdAt: at(2) }] }), [], origin + 3000);
  assert.equal(p.entries[0].tone, 'neutral'); assert.match(p.entries[0].detail, /无需验证/);
});
test('retries show real attempts and reset the request elapsed time', () => {
  const p = buildAiProgress(message({ progressStartedAt: at(100), updatedAt: at(105), agentEvents: [{ type: 'retry', summary: '连接超时，正在重试', attempt: 2, maxAttempts: 3, createdAt: at(105) }] }), [], origin + 110000);
  assert.equal(p.elapsed, 10000); assert.match(p.entries[0].detail, /第 2 次尝试，最多 3 次/);
});
test('completed elapsed time remains fixed and retains zero retrieved evidence', () => {
  const m = message({ status: 'completed', updatedAt: at(8), agentEvents: [{ type: 'evidence', evidenceCount: 0, createdAt: at(2) }, { type: 'done', createdAt: at(8) }] });
  assert.equal(buildAiProgress(m, [], origin + 9000).elapsed, 8000);
  assert.equal(buildAiProgress(m, [], origin + 900000).elapsed, 8000);
  assert.equal(buildAiProgress(m, [], origin + 900000).evidenceCount, 0);
});
test('failure after task creation does not falsely claim no detection was executed', () => {
  const text = aiProgressFailureText('MODEL_TIMEOUT', true);
  assert.ok(!/没有执行检测|未执行任何检测/.test(text)); assert.match(text, /任务中心/);
});
test('quiet hint starts at fifteen seconds rather than fifteen milliseconds', () => {
  assert.equal(buildAiProgress(message(), [], origin + 14999).showQuietHint, false);
  assert.equal(buildAiProgress(message(), [], origin + 15000).showQuietHint, true);
});
test('skipped tasks finish while dependency-blocked tasks remain pending', () => {
  const skipped = { id: 1, toolCode: 'http_headers', status: 'SKIPPED', createdAt: at(1), finishedAt: at(2) };
  const p = buildAiProgress(message({ status: 'completed', taskIds: [1], updatedAt: at(3) }), [skipped], origin + 5000);
  assert.equal(p.active, false); assert.equal(p.completeTasks, 1); assert.equal(p.tone, 'warning');
  const blocked = buildAiProgress(message({ taskIds: [1] }), [{ ...skipped, status: 'BLOCKED', finishedAt: undefined }], origin + 5000);
  assert.equal(blocked.active, true); assert.match(blocked.currentDetail, /等待前置任务/);
});
test('failed answer keeps an already running task clock live', () => {
  const p = buildAiProgress(message({ status: 'failed', content: 'MODEL_TIMEOUT', taskIds: [7], updatedAt: at(5) }), [{ id: 7, toolCode: 'nmap_service_scan', status: 'RUNNING', createdAt: at(1), startedAt: at(2) }], origin + 10000);
  assert.equal(p.active, true); assert.equal(p.elapsed, 10000); assert.equal(p.failed, true);
  assert.match(p.currentTitle, /回答中断/); assert.equal(p.showQuietHint, false);
  assert.match(p.currentDetail, /任务中心/);
});
test('public runtime stages show evidence assessment rather than generic routing', () => {
  assert.equal(aiProgressEventTitle({ type: 'plan', stage: 'ASSESSING' }), '检查证据是否充分');
  assert.equal(aiProgressEventTitle({ type: 'plan', stage: 'GENERATING' }), '生成方案与回答');
  const p = buildAiProgress(message({ agentEvents: [{ type: 'plan', stage: 'GENERATING', summary: '正在请求模型生成回答', createdAt: at(2) }] }), [], origin + 3000);
  assert.equal(p.decision, '');
});
test('separate tool invocations with identical summaries are retained', () => {
  const p = buildAiProgress(message({ agentEvents: [1, 2].map(id => ({ type: 'tool_call', toolCode: 'http_headers', toolCallId: String(id), summary: '已提交检查', createdAt: at(id) })) }), [], origin + 3000);
  assert.equal(p.entries.length, 2);
});
test('plain Q&A aggregates graph bookkeeping without losing the public detail log', () => {
  const events = [
    { type: 'session', summary: '会话已绑定授权目标' },
    ...['正在读取上下文', '上下文已载入', '正在理解当前请求'].map(summary => ({ type: 'step', stage: 'engage', summary })),
    { type: 'plan', stage: 'ROUTING', summary: '正在理解当前请求' },
    { type: 'plan', stage: 'GENERATING', summary: '正在整理回答' },
    ...['recon', 'map', 'validate', 'impact'].map(stage => ({ type: 'step', stage, status: 'SKIPPED', summary: '本阶段没有匹配的受控动作' })),
    { type: 'step', stage: 'retest', summary: '当前没有失败动作需要重试', attempt: 0 },
    { type: 'step', stage: 'report', summary: '报告阶段已复核证据并准备交付' },
    { type: 'plan', actionCount: 0, summary: '本轮为一般问答' },
    { type: 'done', summary: '回答内容不应在关键阶段重复' },
  ].map((event, id) => ({ ...event, id: String(id), createdAt: at(id) }));
  const p = buildAiProgress(message({ status: 'completed', agentEvents: events }), [], origin + 20000);
  assert.equal(p.entries.length, events.length);
  assert.ok(p.summaryEntries.length <= 4);
  assert.ok(!p.summaryEntries.some(entry => /没有匹配|没有失败动作|准备交付|一般问答|回答内容/.test(entry.detail)));
  assert.ok(!p.entries.some(entry => /第 0 次|0 项计划动作/.test(entry.detail)));
  assert.ok(p.summaryEntries.every(entry => entry.tone !== 'active'));
  assert.equal(p.decision, '');
});
test('aggregation preserves failed, retry and approval milestones even with no actions', () => {
  const p = buildAiProgress(message({ agentEvents: [
    { type: 'retry', stage: 'contract_retry', attempt: 1, actionCount: 0, summary: '正在纠正输出格式' },
    { type: 'approval', approvalStatus: 'REQUIRED', actionCount: 0, summary: '等待确认' },
    { type: 'error', stage: 'validate', status: 'FAILED', actionCount: 0, summary: '证据核验失败' },
  ] }), [], origin + 9000);
  assert.deepEqual(p.summaryEntries.map(entry => entry.tone), ['warning', 'warning', 'failed']);
});
test('returning to a previous evidence stage highlights the latest actual feedback', () => {
  const p = buildAiProgress(message({ agentEvents: [
    { type: 'plan', stage: 'RETRIEVING', createdAt: at(1) },
    { type: 'plan', stage: 'GENERATING', createdAt: at(2) },
    { type: 'plan', stage: 'ASSESSING', createdAt: at(3) },
  ] }), [], origin + 4000);
  assert.equal(p.summaryEntries.at(-1).title, '检查证据是否充分');
  assert.equal(p.summaryEntries.at(-1).tone, 'active');
  assert.equal(p.summaryEntries.at(-1).at, origin + 3000);
  assert.equal(p.summaryEntries[0].tone, 'neutral');
});
test('unloaded dispatched tasks never display completed or successful execution', () => {
  const p = buildAiProgress(message({ status: 'completed', taskIds: [88], agentEvents: [{ type: 'done' }] }), [], origin + 5000);
  assert.equal(p.unresolvedTasks, 1); assert.equal(p.completeTasks, 0);
  assert.equal(p.tone, 'neutral'); assert.match(p.currentTitle, /同步检测任务状态/);
});
test('pending and rejected approval retain their distinct non-success states', () => {
  const waiting = buildAiProgress(message({ status: 'completed', approvalStatus: 'REQUIRED' }), [], origin + 5000);
  assert.equal(waiting.waitingApproval, true); assert.equal(waiting.tone, 'warning');
  assert.match(waiting.currentTitle, /等待确认/);
  const rejected = buildAiProgress(message({ status: 'completed', approvalStatus: 'REJECTED' }), [], origin + 5000);
  assert.equal(rejected.waitingApproval, false); assert.equal(rejected.tone, 'warning');
  assert.match(rejected.currentTitle, /已驳回/);
});
const { aiExecutionRequest, normalizeAiExecutionDecision, assertAiLegacyFallbackAllowed } = load(path.join(__dirname, '../src/utils/aiIntent.ts'));
test('AUTO preserves the exact current utterance and never asserts execution permission', () => {
  const request = aiExecutionRequest({ executionIntent: 'AUTO', executionRequested: true, content: '先给方案，不执行' });
  assert.deepEqual(request, { executionIntent: 'AUTO', userPrompt: '先给方案，不执行' });
  assert.equal(Object.hasOwn(request, 'execute'), false);
  assert.throws(() => aiExecutionRequest({ executionIntent: 'AUTO' }), /本轮请求/);
  assert.throws(() => aiExecutionRequest({ executionIntent: 'AUTO', content: 'a'.repeat(4001) }), /本轮请求/);
});
test('old request retries and explicit approval resumes keep their original permission', () => {
  assert.deepEqual(aiExecutionRequest({ executionRequested: false }), { execute: false });
  assert.deepEqual(aiExecutionRequest({ executionRequested: true }), { execute: true });
  assert.deepEqual(aiExecutionRequest({}), { execute: false });
});
test('AUTO cannot fall back to the legacy direct dispatcher', () => {
  assert.throws(() => assertAiLegacyFallbackAllowed({ executionIntent: 'AUTO' }), /不支持.*执行意图/);
  assert.doesNotThrow(() => assertAiLegacyFallbackAllowed({}));
  assert.equal(normalizeAiExecutionDecision('EXECUTE'), 'EXECUTE');
  assert.equal(normalizeAiExecutionDecision('PLAN_ONLY'), 'PLAN_ONLY');
  assert.equal(normalizeAiExecutionDecision('CLARIFY'), 'CLARIFY');
  assert.equal(normalizeAiExecutionDecision('anything_else'), undefined);
});
test('protocol failure localization is idempotent and retains the specific format diagnosis', () => {
  const { localizeAiRuntimeFailure } = load(path.join(__dirname, '../src/utils/aiPresentation.ts'));
  const first = localizeAiRuntimeFailure('AI Runtime Harness 协议校验失败，已安全停止');
  const second = localizeAiRuntimeFailure(first);
  assert.equal(second, first); assert.match(second, /内容格式/); assert.ok(!/访问权限/.test(second));
});
test('verified replay cannot end the current model request or claim tool success', () => {
  const p = buildAiProgress(message({ agentEvents: [
    { type: 'tool_result', status: 'COMPLETED', recorded: true, createdAt: at(1) },
    { type: 'done', status: 'RECORDED', eventTiming: 'VERIFIED_RECORD', createdAt: at(2) },
  ] }), [], origin + 3000);
  assert.equal(p.modelActive, true); assert.equal(p.active, true);
  assert.equal(p.entries[0].tone, 'neutral'); assert.equal(p.entries[1].tone, 'neutral');
  assert.equal(p.completeTasks, 0);
  const proposal = buildAiProgress(message({ agentEvents: [{ type: 'tool_result', status: 'COMPLETED' }] }), [], origin);
  assert.equal(proposal.entries[0].tone, 'neutral');
});
test('latest evidence count replaces earlier retrieval counts including zero', () => {
  const p = buildAiProgress(message({ citations: [{ title: 'old' }], agentEvents: [
    { type: 'evidence', evidenceCount: 8, createdAt: at(1) },
    { type: 'evidence', evidenceCount: 0, createdAt: at(2) },
  ] }), [], origin + 3000);
  assert.equal(p.evidenceCount, 0);
});
test('terminal elapsed time uses actual task completion after model completion', () => {
  const p = buildAiProgress(message({ status: 'completed', modelStreamStatus: 'completed', progressFinishedAt: at(3), taskIds: [1],
    agentEvents: [{ type: 'done', createdAt: at(2) }] }),
    [{ id: 1, toolCode: 'http_headers', status: 'SUCCESS', createdAt: at(1), finishedAt: at(12) }], origin + 90000);
  assert.equal(p.active, false); assert.equal(p.elapsed, 12000);
});
test('missing completion timestamp hides elapsed instead of inventing a duration', () => {
  const p = buildAiProgress(message({ status: 'completed', modelStreamStatus: 'completed', updatedAt: at(9),
    agentEvents: [{ type: 'evidence', createdAt: at(2) }, { type: 'done', recorded: true, createdAt: at(8) }] }), [], origin + 90000);
  assert.equal(p.elapsed, undefined);
  assert.equal(buildAiProgress(message({ status: 'completed', updatedAt: at(9) }), [], origin + 90000).elapsed, undefined);
});
test('model lifecycle is authoritative and ordinary answers do not invent scan summary work', () => {
  const p = buildAiProgress(message({ status: 'answering', modelStreamStatus: 'running', agentEvents: [{ type: 'done', createdAt: at(2) }] }), [], origin + 3000);
  assert.equal(p.modelActive, true); assert.equal(p.currentTitle, '等待模型回答');
  assert.equal(p.currentDetail, '模型请求尚未完成。');
  const failed = buildAiProgress(message({ modelStreamStatus: 'failed', progressFinishedAt: at(4) }), [], origin + 5000);
  assert.equal(failed.modelActive, false); assert.equal(failed.failed, true); assert.equal(failed.elapsed, 4000);
  assert.equal(buildAiProgress(message({ status: 'failed', modelStreamStatus: 'running' }), [], origin + 5000).modelActive, false);
});
test('restoring saved active streams stops the clock without inventing completion or failure', () => {
  const { normalizeConversations } = load(path.join(__dirname, '../src/stores/conversations.ts'));
  for (const patch of [{ modelStreamStatus: 'running' }, {}]) {
    const restored = normalizeConversations([{ messages: [message(patch)] }])[0].messages[0];
    assert.equal(restored.modelStreamStatus, 'interrupted');
    const p = buildAiProgress(restored, [], origin + 86400000);
    assert.equal(p.active, false); assert.equal(p.failed, false); assert.equal(p.elapsed, undefined);
    assert.match(p.currentTitle, /结果待确认/);
    assert.equal(p.tone, 'neutral');
  }
});
test('historical stage observations do not remain live after later feedback or completion', () => {
  const events = [{ type: 'plan', stage: 'RETRIEVING', createdAt: at(1) }, { type: 'plan', stage: 'GENERATING', createdAt: at(2) }];
  assert.deepEqual(buildAiProgress(message({ agentEvents: events }), [], origin + 3000).entries.map(e => e.tone), ['neutral', 'active']);
  assert.ok(buildAiProgress(message({ status: 'completed', agentEvents: events }), [], origin + 3000).entries.every(e => e.tone === 'neutral'));
});
test('terminal tasks without finish times never borrow another live task clock', () => {
  const { aiTaskElapsed } = load(path.join(__dirname, '../src/utils/aiProgress.ts'));
  const task = { id: 1, toolCode: 'http_headers', status: 'SUCCESS', createdAt: at(1), startedAt: at(2) };
  assert.equal(aiTaskElapsed(task, origin + 90000), undefined);
  assert.equal(aiTaskElapsed({ ...task, status: 'RUNNING' }, origin + 90000), 88000);
  assert.equal(aiTaskElapsed({ ...task, finishedAt: at(1) }, origin + 90000), undefined);
  const p = buildAiProgress(message({ status: 'completed', modelStreamStatus: 'completed', progressFinishedAt: at(3), taskIds: [1] }), [task], origin + 90000);
  assert.equal(p.elapsed, undefined);
});
console.log(`${passed} AI progress behavior checks passed.`);
