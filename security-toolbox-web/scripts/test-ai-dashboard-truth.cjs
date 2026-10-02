// Execute the actual Dashboard functions extracted through the TypeScript AST.
// Network and store boundaries are controlled; no application or business API is used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const filename = path.resolve(__dirname, '../src/views/Dashboard.vue');
const script = parse(fs.readFileSync(filename, 'utf8')).descriptor.scriptSetup.content;
const source = ts.createSourceFile(filename, script, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const printer = ts.createPrinter();
function functionSource(name, throughFirstTry = false) {
  let fn = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
  assert.ok(fn, 'Missing production function ' + name);
  if (throughFirstTry) {
    // Isolate the entire request lifecycle, leaving subsequent plan rendering out of this test.
    const index = fn.body.statements.findIndex(ts.isTryStatement);
    assert.ok(index >= 0, 'Request lifecycle must handle completion and rejection');
    fn = ts.factory.updateFunctionDeclaration(fn, fn.modifiers, fn.asteriskToken, fn.name,
      fn.typeParameters, fn.parameters, fn.type, ts.factory.updateBlock(fn.body, fn.body.statements.slice(0, index + 1)));
  }
  return printer.printNode(ts.EmitHint.Unspecified, fn, source);
}
function compile(code, bindings, expression) {
  const js = ts.transpileModule(code, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  return vm.runInNewContext(js + '\n' + expression, bindings);
}
const progressModule = { exports: {} };
compile(fs.readFileSync(path.resolve(__dirname, '../src/utils/taskProgress.ts'), 'utf8'),
  { exports: progressModule.exports, module: progressModule }, 'undefined');
const approvalModule = { exports: {} };
compile(fs.readFileSync(path.resolve(__dirname, '../src/utils/aiApproval.ts'), 'utf8'),
  { exports: approvalModule.exports, module: approvalModule }, 'undefined');
const tasks = { value: [] };
const view = compile(functionSource('planStepState') + functionSource('planTaskSummary') + functionSource('taskState'),
  { tasks, ...progressModule.exports, ...approvalModule.exports }, '({ planStepState, planTaskSummary, taskState })');
let passed = 0;
async function test(name, run) { await run(); passed++; console.log('PASS ' + name); }
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function lifecycleBindings(network) {
  const updates = [], appended = [];
  return { updates, appended, bindings: {
    conversations: { updateMessage: (_thread, _message, patch) => updates.push(patch), appendMessage: (_thread, item) => appended.push(item) },
    buildContextPrompt: () => '读取状态', messageReferences: () => [], projectIdForTarget: () => 131,
    latestWorkflowIdentity: async () => ({ workflowRevision: 2 }), dispatchAiStreaming: () => network.promise,
    aiExecutionRequest: () => ({ executionIntent: 'AUTO' }), agentContextReferences: value => value,
    recordThinkingProgress: () => {}, answeringMessages: new Set(), endpoints: { answerAi: () => network.promise },
    readableAiConversationError: (_error, fallback) => fallback, scrollToBottom: () => {},
  } };
}
(async () => {
  await test('proposal statuses and synthetic percentages never establish task execution', () => {
    for (const status of ['SUCCESS', 'COMPLETED', 'done', 'RUNNING', 'FAILED']) {
      const state = view.planStepState({ steps: [{ status, progress: 100 }], taskIds: [] }, 0);
      assert.equal(state.state, 'pending'); assert.equal(state.label, '待执行'); assert.equal(state.progress, 0);
    }
    assert.equal(view.planStepState({ steps: [{ status: 'COMPLETED', taskId: 999 }], taskIds: [999] }, 0).label, '等待任务状态');
  });
  await test('real running task ignores stage weights and displays only native tool counts', () => {
    const message = { steps: [{ status: 'COMPLETED', progress: 100, taskId: 1 }], taskIds: [1] };
    tasks.value = [{ id: 1, status: 'RUNNING', progress: 57, progressDeterminate: true }];
    let state = view.planStepState(message, 0);
    assert.equal(state.state, 'running'); assert.equal(state.indeterminate, true); assert.equal(state.progress, 0);
    tasks.value[0].progressCompleted = 4; tasks.value[0].progressTotal = 10;
    state = view.planStepState(message, 0);
    assert.equal(state.progress, 40); assert.equal(state.label, '执行中 40%');
  });
  await test('approval outcomes remain truthful before any task is confirmed', () => {
    for (const [approvalStatus, stepLabel, planLabel] of [
      ['REQUIRED', '等待审批', '等待审批'],
      ['PENDING', '等待审批', '等待审批'],
      ['APPROVED', '等待派发确认', '已批准，等待派发确认'],
      ['REJECTED', '未获批准', '方案已驳回'],
    ]) {
      const message = { approvalId: 77, approvalStatus, steps: [{ toolCode: 'nuclei_scan', status: 'pending' }], taskIds: [] };
      assert.equal(view.planStepState(message, 0).label, stepLabel);
      assert.equal(view.taskState(message).label, planLabel);
      assert.equal(view.taskState(message).progress, 0);
      assert.notEqual(view.taskState(message).className, 'success');
    }
    const message = { approvalId: 77, approvalStatus: 'APPROVED', steps: [{ taskId: 1 }], taskIds: [1] };
    assert.equal(view.planStepState(message, 0).label, '执行中 40%');
  });
  await test('plan summary counts ended tasks and retains missing task denominator', () => {
    tasks.value = [{ id: 1, status: 'SUCCESS' }, { id: 2, status: 'FAILED' }, { id: 3, status: 'RUNNING' }];
    assert.equal(view.planTaskSummary({ taskIds: [1, 2, 3, 4] }), '已结束 2/4 个任务');
  });
  for (const reject of [false, true]) await test('dispatch stream lifecycle records actual ' + (reject ? 'rejection' : 'completion'), async () => {
    const network = deferred(), harness = lifecycleBindings(network);
    const dispatch = compile(functionSource('dispatchConversationMessage', true), harness.bindings, 'dispatchConversationMessage');
    const pending = dispatch({ id: 'thread', targetId: 293 }, { id: 'user' }, { id: 'assistant' });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(harness.updates.length, 1); assert.equal(harness.updates[0].modelStreamStatus, 'running');
    assert.ok(Number.isFinite(Date.parse(harness.updates[0].progressStartedAt)));
    assert.equal(harness.updates[0].progressFinishedAt, undefined);
    if (reject) { network.reject(new Error('transport failure')); await assert.rejects(pending, /transport failure/); }
    else { network.resolve({}); await pending; }
    assert.equal(harness.updates.at(-1).modelStreamStatus, reject ? 'failed' : 'completed');
    assert.ok(Number.isFinite(Date.parse(harness.updates.at(-1).progressFinishedAt)));
  });
  for (const reject of [false, true]) await test('final-answer lifecycle remains pending until actual ' + (reject ? 'failure' : 'response'), async () => {
    const network = deferred(), harness = lifecycleBindings(network);
    const request = compile(functionSource('requestFinalAnswer'), harness.bindings, 'requestFinalAnswer');
    const pending = request({ id: 'thread', targetId: 293, title: '状态', messages: [] }, { id: 'assistant', taskIds: [1] });
    assert.equal(harness.updates.at(-1).modelStreamStatus, 'running'); assert.equal(harness.appended.length, 0);
    if (reject) network.reject(new Error('summary failed')); else network.resolve({ data: { answer: '真实结果' } });
    await pending;
    assert.equal(harness.updates.at(-1).modelStreamStatus, reject ? 'failed' : 'completed');
    assert.ok(Number.isFinite(Date.parse(harness.updates.at(-1).progressFinishedAt)));
    assert.equal(harness.appended.length, 1); assert.equal(harness.bindings.answeringMessages.size, 0);
  });
  console.log(`${passed} Dashboard truth behavior checks passed.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
