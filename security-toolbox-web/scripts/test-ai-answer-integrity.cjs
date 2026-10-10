'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const root = path.resolve(__dirname, '..');
const transpile = source => ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
const answerModule = { exports: {} };
vm.runInNewContext(`(function(module,exports){${transpile(fs.readFileSync(path.join(root, 'src/utils/aiAnswer.ts'), 'utf8'))}})`)(answerModule, answerModule.exports);
const helpers = answerModule.exports;
function productionFunction(view, name, context) {
  const source = parse(fs.readFileSync(path.join(root, 'src/views', view), 'utf8')).descriptor.scriptSetup.content;
  const ast = ts.createSourceFile(view, source, ts.ScriptTarget.Latest, true);
  const node = ast.statements.find(item => ts.isFunctionDeclaration(item) && item.name?.text === name);
  assert.ok(node, name);
  return vm.runInNewContext(`${transpile(node.getText(ast))}\n${name}`, { ...helpers, ...context });
}
function dispatchFixture(data) {
  const user = { id: 'u', content: '修改后的问题', copilotMode: 'analyze' };
  const assistant = { id: 'a', content: '正在核对目标', status: 'running', taskIds: [], steps: [] };
  const thread = { id: 'thread', targetId: 9, messages: [user, assistant] };
  const memories = [], requests = [];
  const context = {
    projectIdForTarget: () => 7, buildContextPrompt: () => user.content,
    messageReferences: () => [], latestWorkflowIdentity: async () => ({}),
    conversations: { items: [thread], updateMessage(_thread, _id, patch) { Object.assign(assistant, patch); } },
    dispatchAiStreaming: async request => { requests.push(request); return data; },
    aiExecutionRequest: () => ({}), agentContextReferences: value => value,
    recordThinkingProgress() {}, publicCitation: value => value,
    shouldPromptApproval: () => false, selectedThread: { value: thread },
    saveConversationMemory: async (...args) => memories.push(args), loadTasks: async () => {},
  };
  return { user, assistant, thread, memories, requests, run: productionFunction('Dashboard.vue', 'dispatchConversationMessage', context) };
}
const response = overrides => ({ plan: { summary: '', provider: 'openai-compatible', steps: [] }, taskIds: [], taskCount: 0, ...overrides });
let passed = 0;
async function test(name, run) { await run(); passed++; console.log('PASS ' + name); }
(async () => {
  await test('blank final response cannot promote progress to answer or memory', async () => {
    const f = dispatchFixture(response({ answer: '   ' }));
    await assert.rejects(f.run(f.thread, f.user, f.assistant), /未获得模型回答/);
    assert.notEqual(f.assistant.status, 'completed');
    assert.equal(f.memories.length, 0); assert.equal(f.requests.length, 1);
  });
  await test('real final model answer is displayed and remembered', async () => {
    const f = dispatchFixture(response({ answer: ' 1111 ' }));
    await f.run(f.thread, f.user, f.assistant);
    assert.equal(f.assistant.content, '1111'); assert.equal(f.assistant.status, 'completed');
    assert.equal(f.memories[0][2], '1111');
  });
  await test('final model plan summary remains a valid model reply', async () => {
    const f = dispatchFixture(response({ plan: { summary: '请先确认授权端口。', provider: 'openai-compatible', steps: [] } }));
    await f.run(f.thread, f.user, f.assistant);
    assert.equal(f.assistant.content, '请先确认授权端口。'); assert.equal(f.memories.length, 1);
  });
  await test('task receipt does not require or impersonate a model answer', async () => {
    const f = dispatchFixture(response({ taskIds: [71], taskCount: 1 }));
    await f.run(f.thread, f.user, f.assistant);
    assert.equal(f.assistant.status, 'running'); assert.equal(f.assistant.provider, 'operation-receipt');
    assert.match(f.assistant.content, /1 个任务/); assert.equal(f.memories.length, 0);
  });
  await test('approval receipt preserves approval with no invented answer', async () => {
    const f = dispatchFixture(response({ approvalId: 7, approvalStatus: 'REQUIRED' }));
    await f.run(f.thread, f.user, f.assistant);
    assert.equal(f.assistant.approvalId, 7); assert.equal(f.assistant.provider, 'operation-receipt');
    assert.equal(f.memories.length, 0);
  });
  await test('legacy local answers are labeled and excluded from model memory', async () => {
    const f = dispatchFixture(response({ answer: '本地结构参考', plan: { provider: 'local-rule-fallback', summary: '', steps: [] } }));
    await f.run(f.thread, f.user, f.assistant);
    assert.equal(f.memories.length, 0);
    assert.equal(helpers.aiAnswerSource(f.assistant.provider), '本地规则 · 未获得模型回答');
    assert.equal(helpers.aiAnswerSource('openai-compatible'), '模型回答');
    assert.equal(helpers.aiAnswerSource(undefined), '回答来源未说明');
  });
  await test('empty task summary becomes retryable failure, not completed answer', async () => {
    const appended = [], updates = [];
    const fn = productionFunction('Dashboard.vue', 'requestFinalAnswer', {
      answeringMessages: new Set(), conversations: { updateMessage: (...args) => updates.push(args), appendMessage: (_id, item) => appended.push(item) },
      endpoints: { answerAi: async () => ({ data: { answer: '\n', summary: '' } }) },
      projectIdForTarget: () => 7, buildContextPrompt: () => '问题',
      readableAiConversationError: error => error.message, scrollToBottom: async () => {},
    });
    await fn({ id: 't', targetId: 9, title: '问题', messages: [] }, { id: 'a', taskIds: [71], replyToId: 'u' });
    assert.equal(appended.length, 1); assert.equal(appended[0].status, 'failed');
    assert.match(appended[0].content, /未获得模型回答/);
    assert.equal(updates.at(-1)[2].modelStreamStatus, 'failed');
  });
  await test('traffic chat records empty response as failure and omits old failures from history', async () => {
    const appended = [], requests = [];
    const fn = productionFunction('Traffic.vue', 'sendTrafficChat', {
      selected: { value: { id: 19 } }, trafficChatPrompt: { value: '认证是否有风险' }, pendingTrafficChats: { value: {} },
      trafficChats: { value: { '19': [{ role: 'ASSISTANT', content: '旧失败', status: 'failed' }, { role: 'ASSISTANT', content: '本地参考', provider: 'local-summary' }] } },
      appendTrafficChat: (...args) => appended.push(args), readableError: error => error.message,
      api: { post: async (...args) => { requests.push(args); return { data: { answer: '  ', provider: 'openai-compatible' } }; } },
    });
    await fn();
    assert.equal(requests[0][0], '/traffic/packets/19/chat'); assert.equal(requests[0][1].history.length, 0);
    assert.equal(appended.at(-1)[3].status, 'failed'); assert.match(appended.at(-1)[2], /未获得模型回答/);
  });
  console.log(`${passed} AI answer integrity checks passed.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
