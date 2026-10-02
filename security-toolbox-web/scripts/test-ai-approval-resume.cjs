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
function fixture(failResume = false) {
  const message = { id: 'message', approvalId: 77, approvalStatus: 'REQUIRED', content: 'saved plan', taskIds: [], steps: [] };
  const calls = [], errors = [];
  let shouldFail = failResume;
  const context = vm.createContext({
    approvingMessageId: { value: null }, sending: { value: false }, selectedThread: { value: { id: 'thread', targetId: 9 } },
    projectIdForTarget: () => 3,
    endpoints: {
      decideProjectApproval: async (...args) => { calls.push(['decide', ...args]); },
      resumeProjectAiApproval: async (...args) => {
        calls.push(['resume', ...args]);
        if (shouldFail) { shouldFail = false; throw new Error('temporary transport failure'); }
        return { data: { targetId: 9, taskIds: [42], plan: { steps: [{ toolCode: 'http_headers', title: 'Headers', parameters: {} }] } } };
      },
    },
    conversations: { updateMessage: (thread, id, patch) => Object.assign(message, patch), appendMessage: () => { throw new Error('Approval must not trigger model replanning'); } },
    ElMessage: { error: value => errors.push(value), warning: value => errors.push(value), info() {}, success() {} },
    readableConversationError: error => error.message,
    loadTasks: async () => { calls.push(['loadTasks']); },
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
  await retry.run('APPROVED');
  assert.deepEqual(retry.calls.filter(call => call[0] === 'resume'), [['resume', 3, 77], ['resume', 3, 77]]);
  assert.deepEqual(Array.from(retry.message.taskIds), [42]);
  console.log('PASS real Dashboard approval handler: persisted resume, rejection, transport failure and same-ticket retry');
})().catch(error => { console.error(error); process.exitCode = 1; });
