const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const source = parse(fs.readFileSync(path.join(__dirname, '../src/views/Dashboard.vue'), 'utf8')).descriptor.scriptSetup.content;
const ast = ts.createSourceFile('Dashboard.ts', source, ts.ScriptTarget.Latest, true);
const handler = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'handleAgentApprovalDecision');
assert.ok(handler);
const code = ts.transpileModule(handler.getText(ast), { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText;
const apiAst = ts.createSourceFile('api.ts', fs.readFileSync(path.join(__dirname, '../src/api.ts'), 'utf8'), ts.ScriptTarget.Latest, true);
let resumeEndpoint;
function findResume(node) {
  if (ts.isPropertyAssignment(node) && node.name.getText(apiAst) === 'resumeProjectAiApproval') resumeEndpoint = node.initializer;
  ts.forEachChild(node, findResume);
}
findResume(apiAst);
assert.ok(resumeEndpoint);
const endpointCalls = [];
const endpointContext = vm.createContext({ api: { post: (...args) => endpointCalls.push(args) } });
vm.runInContext(ts.transpileModule(`const resume = ${resumeEndpoint.getText(apiAst)}; resume(3, 77);`, {
  compilerOptions: { target: ts.ScriptTarget.ES2020 },
}).outputText, endpointContext);
assert.equal(endpointCalls[0][0], '/projects/3/approvals/77/execute');
assert.equal(endpointCalls[0][1], undefined);
assert.equal(endpointCalls[0][2].timeout, 210000, 'Approval dispatch must allow current tool snapshot capture beyond the generic 10s timeout');
const approvalModule = { exports: {} };
vm.runInNewContext(ts.transpileModule(fs.readFileSync(path.join(__dirname, '../src/utils/aiApproval.ts'), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.CommonJS } }).outputText,
  { module: approvalModule, exports: approvalModule.exports });
function fixture(options = {}) {
  if (typeof options === 'boolean') options = { failResume: options };
  const message = { id: 'message', role: 'assistant', status: 'completed', modelStreamStatus: 'completed', approvalId: 77, approvalStatus: 'REQUIRED', content: 'saved plan', taskIds: [], steps: [{ toolCode: 'nmap_service_scan', parameters: { ports: '80', mode: 'service' } }] };
  const calls = [], errors = [];
  let shouldFail = options.failResume || Boolean(options.resumeError);
  const context = vm.createContext({
    approvingMessageId: { value: null }, sending: { value: false }, selectedThread: { value: { id: 'thread', targetId: 9 } },
    projectIdForTarget: () => 3,
    ...approvalModule.exports,
    endpoints: {
      decideProjectApproval: async (...args) => { calls.push(['decide', ...args]); if (options.decisionError) throw options.decisionError; },
      resumeProjectAiApproval: async (...args) => {
        calls.push(['resume', ...args]);
        if (shouldFail) { shouldFail = false; throw options.resumeError || new Error('temporary transport failure'); }
        return { data: { targetId: 9, taskIds: [42], plan: { steps: [{ toolCode: 'http_headers', title: 'Headers', parameters: {} }] } } };
      },
    },
    conversations: { updateMessage: (thread, id, patch) => Object.assign(message, patch), appendMessage: () => { throw new Error('Approval must not trigger model replanning'); } },
    ElMessage: { error: value => errors.push(value), warning: value => errors.push(value), info() {}, success() {} },
    readableConversationError: error => error.message,
    loadTasks: async () => { calls.push(['loadTasks']); if (options.loadError) throw options.loadError; },
  });
  vm.runInContext(code, context);
  return { message, calls, errors, run: decision => context.handleAgentApprovalDecision(message, decision) };
}
(async () => {
  const approved = fixture(); await approved.run('APPROVED');
  assert.deepEqual(approved.calls.map(call => call[0]), ['decide', 'resume', 'loadTasks']);
  assert.deepEqual(approved.calls[1], ['resume', 3, 77]);
  assert.equal(approved.message.approvalStatus, 'APPROVED'); assert.deepEqual(Array.from(approved.message.taskIds), [42]);
  assert.equal(approved.message.steps[0].taskId, 42);
  const rejected = fixture(); await rejected.run('REJECTED');
  assert.deepEqual(rejected.calls.map(call => call[0]), ['decide']);
  assert.equal(rejected.message.approvalStatus, 'REJECTED'); assert.equal(rejected.message.taskIds.length, 0);
  const retry = fixture(true); await retry.run('APPROVED');
  assert.equal(retry.message.approvalStatus, 'APPROVED'); assert.equal(retry.message.taskIds.length, 0);
  assert.equal(retry.errors.length, 1);
  assert.equal(retry.message.approvalDispatchStatus, 'unknown'); assert.equal(retry.message.content, 'saved plan');
  assert.equal(retry.message.status, 'completed'); assert(!retry.message.planningStatus.includes('未派发任务'));
  await retry.run('APPROVED');
  assert.deepEqual(retry.calls.filter(call => call[0] === 'resume'), [['resume', 3, 77], ['resume', 3, 77]]);
  assert.deepEqual(Array.from(retry.message.taskIds), [42]);
  assert.equal(retry.message.approvalDispatchStatus, 'dispatched'); assert.equal(retry.message.approvalDispatchError, undefined);
  for (const reason of ['授权目标已停用', '目标授权已过期', '目标地址或授权范围已变化，原审批不能继续执行，请重新申请']) {
    const test = fixture({ resumeError: Object.assign(new Error(reason), { response: { status: 400, data: { message: reason } } }) }); const steps = JSON.stringify(test.message.steps);
    await test.run('APPROVED');
    assert.equal(test.message.approvalStatus, 'APPROVED'); assert.equal(test.message.approvalDispatchStatus, 'rejected'); assert.equal(test.message.approvalDispatchError, reason);
    assert.equal(test.message.status, 'completed'); assert.equal(test.message.modelStreamStatus, 'completed'); assert.equal(test.message.content, 'saved plan'); assert.equal(JSON.stringify(test.message.steps), steps); assert.equal(test.message.taskIds.length, 0);
    assert.equal(test.message.planningStatus, '执行已拒绝，未派发任务'); assert(Number.isFinite(Date.parse(test.message.approvalDispatchUpdatedAt)));
    assert.deepEqual(test.calls.map(c => c[0]), ['decide','resume']);
    const persisted = JSON.parse(JSON.stringify(test.message)); assert.equal(persisted.approvalDispatchError, reason);
    await test.run('APPROVED'); assert.deepEqual(test.calls.filter(c => c[0] === 'resume'), [['resume',3,77],['resume',3,77]]); assert.equal(test.message.approvalDispatchStatus, 'dispatched'); assert.equal(test.message.approvalDispatchError, undefined);
  }
  const decisionFailure = fixture({ decisionError: new Error('cannot approve') }); await decisionFailure.run('APPROVED');
  assert.equal(decisionFailure.message.approvalStatus, 'REQUIRED'); assert.equal(decisionFailure.message.approvalDispatchStatus, undefined); assert.deepEqual(decisionFailure.calls.map(c => c[0]), ['decide']);
  const syncFailure = fixture({ loadError: Object.assign(new Error('list unavailable'), { response: { status: 400 } }) }); await syncFailure.run('APPROVED');
  assert.equal(syncFailure.message.approvalDispatchStatus, 'dispatched'); assert.equal(syncFailure.message.approvalDispatchError, undefined); assert.deepEqual(Array.from(syncFailure.message.taskIds), [42]);
  for (const error of [Object.assign(new Error('timeout'), { code: 'ECONNABORTED' }), Object.assign(new Error('server failed'), { response: { status: 500 } }), Object.assign(new Error('timeout response'), { response: { status: 408 } }), Object.assign(new Error('other400'), { response: { status: 400, data: { message: 'unknown execution error' } } }), Object.assign(new Error('授权目标已停用'), { response: { status: 400 } })]) {
    const uncertain = fixture({ resumeError: error }); await uncertain.run('APPROVED'); assert.equal(uncertain.message.approvalDispatchStatus, 'unknown'); assert(!uncertain.message.planningStatus.includes('未派发任务')); assert.equal(uncertain.message.content, 'saved plan');
  }
  console.log('PASS real Dashboard approval handler: approval/rejection,3 authorization refusals,5 uncertain outcomes,decision failure,post-dispatch synchronization failure,and same-ticket recovery without model replanning');
})().catch(error => { console.error(error); process.exitCode = 1; });
