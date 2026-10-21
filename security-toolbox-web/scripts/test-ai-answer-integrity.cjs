'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const { createClient } = require('./test-ai-intent-request.cjs');
const root = path.resolve(__dirname, '..');
const transpile = source => ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
const answerModule = { exports: {} };
vm.runInNewContext(`(function(module,exports){${transpile(fs.readFileSync(path.join(root, 'src/utils/aiAnswer.ts'), 'utf8'))}})`)(answerModule, answerModule.exports);
const helpers = answerModule.exports;
const approvalModule = { exports: {} };
vm.runInNewContext(`(function(module,exports){${transpile(fs.readFileSync(path.join(root, 'src/utils/aiApproval.ts'), 'utf8'))}})`)(approvalModule, approvalModule.exports);
function productionFunction(view, name, context) {
  const source = parse(fs.readFileSync(path.join(root, 'src/views', view), 'utf8')).descriptor.scriptSetup.content;
  const ast = ts.createSourceFile(view, source, ts.ScriptTarget.Latest, true);
  const node = ast.statements.find(item => ts.isFunctionDeclaration(item) && item.name?.text === name);
  assert.ok(node, name);
  return vm.runInNewContext(`${transpile(node.getText(ast))}\n${name}`, { ...helpers, ...context });
}
function dispatchFixture(data, events = []) {
  const user = { id: 'u', content: '修改后的问题', copilotMode: 'analyze' };
  const assistant = { id: 'a', content: '正在核对目标', status: 'running', taskIds: [], steps: [] };
  const thread = { id: 'thread', targetId: 9, messages: [user, assistant] };
  const memories = [], requests = [], approvalDialogMessageId = { value: null };
  const context = {
    projectIdForTarget: () => 7, buildContextPrompt: () => user.content,
    messageReferences: () => [], latestWorkflowIdentity: async () => ({}),
    conversations: { items: [thread], updateMessage(_thread, _id, patch) { Object.assign(assistant, patch); } },
    dispatchAiStreaming: async (request, onEvent) => { requests.push(request); events.forEach(onEvent); return data; },
    aiExecutionRequest: () => ({}), agentContextReferences: value => value,
    recordThinkingProgress() {}, publicCitation: value => value,
    normalizeAgentEvent: createClient({}).normalizeAgentEvent,
    shouldPromptApproval: approvalModule.exports.createAiApprovalPromptGate(),
    approvalDialogMessageId, selectedThread: { value: thread },
    saveConversationMemory: async (...args) => memories.push(args), loadTasks: async () => {},
  };
  return { user, assistant, thread, memories, requests, approvalDialogMessageId, run: productionFunction('Dashboard.vue', 'dispatchConversationMessage', context) };
}
function failedSendFixture(patch = {}) {
  const assistant = {}, thread = { id: 'thread', targetId: 9, messages: [] };
  const conversations = {
    items: [thread],
    appendTurn(_id, user, answer) {
      Object.assign(assistant, { ...answer, id: 'a', replyToId: 'u' });
      const userMessage = { ...user, id: 'u' };
      thread.messages.push(userMessage, assistant);
      return { userMessage, assistantMessage: assistant };
    },
    updateMessage(_thread, _id, update) { Object.assign(assistant, update); },
  };
  const context = {
    prompt: { value: '加上目录扫描' }, sending: { value: false },
    selectedTarget: { value: { id: 9, name: '授权目标' } }, enabledTargets: { value: [{ id: 9 }] },
    selectedThread: { value: thread }, selectedTargetId: { value: 9 },
    editingMessage: { value: undefined }, activeDraft: { value: undefined }, quotedMessage: { value: undefined },
    activeSendingThreadIds: { value: new Set() }, cloneMessageDraft: value => value,
    auditScopeForMessage: async () => undefined, projectIdForTarget: () => 7,
    conversations, ConversationStorageError: class extends Error {},
    clearQuotedMessage() {}, scrollToBottom: async () => {}, ElMessage: { warning() {}, error() {} },
    router: { replace: async () => {} }, readableConversationError: error => error.message,
    dispatchConversationMessage: async () => { Object.assign(assistant, patch); throw new Error('本轮请求失败'); },
  };
  return { assistant, run: productionFunction('Dashboard.vue', 'sendPrompt', context) };
}
const response = overrides => ({ plan: { summary: '', provider: 'openai-compatible', steps: [] }, taskIds: [], taskCount: 0, ...overrides });
let passed = 0;
async function test(name, run) { await run(); passed++; console.log('PASS ' + name); }
(async () => {
  await test('blank final response cannot promote progress to answer or memory', async () => {
    const f = dispatchFixture(response({ answer: '   ' }));
    await assert.rejects(f.run(f.thread, f.user, f.assistant), /未获得模型回答/);
    assert.notEqual(f.assistant.status, 'completed');
    assert.equal(f.assistant.modelStreamStatus, 'failed');
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
  await test('live done answer survives an empty compatibility dispatch result', async () => {
    const f = dispatchFixture(response({}), [{ type: 'done', status: 'COMPLETED', data: { response: { message: '本轮已核对授权范围。' } } }]);
    await f.run(f.thread, f.user, f.assistant);
    assert.equal(f.assistant.content, '本轮已核对授权范围。'); assert.equal(f.assistant.status, 'completed');
    assert.equal(f.memories[0][2], '本轮已核对授权范围。');
  });
  await test('progress, replayed receipts and empty done messages cannot impersonate an answer', async () => {
    for (const event of [
      { type: 'planner_progress', answer: '仍在生成方案' },
      { type: 'done', status: 'COMPLETED', recorded: true, answer: '上轮回答' },
      { type: 'done', status: 'COMPLETED', eventTiming: 'VERIFIED_RECORD', answer: '历史回执' },
      { type: 'done', status: 'RECORDED', answer: '历史回执' },
      { type: 'done', status: 'FAILED', answer: '失败说明' },
      { type: 'done', status: 'COMPLETED', message: '本轮模型处理结束' },
    ]) {
      const f = dispatchFixture(response({}), [event]);
      await assert.rejects(f.run(f.thread, f.user, f.assistant), /未获得模型回答/);
      assert.equal(f.memories.length, 0);
    }
  });
  await test('send failures keep initial and intermediate placeholders failed and retryable', async () => {
    for (const patch of [
      {},
      { content: '目标上下文已载入', status: 'planning', modelStreamStatus: 'running' },
      { content: '阶段处理结束', status: 'planning', modelStreamStatus: 'completed' },
      { content: '生成失败', status: 'failed', modelStreamStatus: 'failed' },
    ]) {
      const f = failedSendFixture(patch);
      await f.run();
      assert.equal(f.assistant.status, 'failed'); assert.equal(f.assistant.modelStreamStatus, 'failed');
      assert.equal(f.assistant.content, '本轮请求失败');
    }
  });
  await test('a post-completion synchronization error preserves an already validated answer or task receipt', async () => {
    for (const patch of [
      { content: '已生成本轮方案，请审核。', status: 'completed', modelStreamStatus: 'completed' },
      { content: '原审批已派发一个任务。', status: 'running', modelStreamStatus: 'completed', taskIds: [71] },
    ]) {
      const f = failedSendFixture(patch);
      await f.run();
      assert.equal(f.assistant.status, 'completed'); assert.equal(f.assistant.modelStreamStatus, 'completed');
      assert.equal(f.assistant.content, patch.content);
    }
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
  await test('a revised directory scan plan opens its own approval without changing the earlier plan or creating tasks', async () => {
    const priorSteps = [{ toolCode: 'http_headers', title: 'HTTP 响应头检查', parameters: {}, risk: 'SAFE', requiresApproval: false }];
    const revisedSteps = [...priorSteps, { toolCode: 'dir_scan', title: 'Web 目录与路径探测', parameters: { concurrency: 10 }, risk: 'CAUTION', requiresApproval: true }];
    const f = dispatchFixture(response({ answer: '已加入目录扫描，请确认本轮方案。', approvalId: 42, approvalStatus: 'REQUIRED', plan: { provider: 'langgraph-runtime', summary: '本轮修订方案', steps: revisedSteps } }));
    const prior = { id: 'prior', role: 'assistant', approvalId: 41, approvalStatus: 'REQUIRED', taskIds: [], steps: priorSteps };
    const original = JSON.stringify(prior);
    f.thread.messages.unshift(prior);
    f.user.content = '加上目录扫描';
    await f.run(f.thread, f.user, f.assistant);
    assert.equal(f.approvalDialogMessageId.value, 'a');
    assert.equal(f.assistant.approvalId, 42); assert.equal(f.assistant.approvalStatus, 'REQUIRED');
    assert.equal(f.assistant.taskIds.length, 0); assert.equal(f.assistant.steps.length, 2);
    assert.equal(f.assistant.steps[1].toolCode, 'dir_scan');
    assert.equal(f.assistant.steps[1].parameters.concurrency, 10);
    assert.equal(JSON.stringify(prior), original); assert.equal(f.requests.length, 1);
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
