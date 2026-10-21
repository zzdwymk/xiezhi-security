'use strict';
// Isolated in-memory Storage and the real Pinia store/SFC handlers. No live profile/API access.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const ts = require('typescript'), { parse } = require('@vue/compiler-sfc');
const { ref, createSSRApp } = require('vue'), { renderToString } = require('vue/server-renderer');
const { createPinia, setActivePinia } = require('pinia');
const root = path.resolve(__dirname, '..'), KEY = 'security_toolbox_ai_conversations_v2';
const descriptor = parse(fs.readFileSync(path.join(root, 'src/views/Dashboard.vue'), 'utf8')).descriptor;
const ast = ts.createSourceFile('Dashboard.ts', descriptor.scriptSetup.content, ts.ScriptTarget.Latest, true);
const transpile = source => ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
function handler(name) {
  const node = ast.statements.find(n => ts.isFunctionDeclaration(n) && n.name?.text === name);
  assert(node, 'Missing actual Dashboard handler ' + name); return transpile(node.getText(ast));
}
function seed(count = 30) {
  return Array.from({ length: count }, (_, i) => ({ id: 'old-' + i, title: '原对话' + i, projectId: 140, targetId: 307,
    targetName: '192.168.136.132', createdAt: '2026-10-05T00:00:00Z', updatedAt: '2026-10-05T00:00:00Z',
    messages: [{ id: 'u-' + i, role: 'user', content: '原用户内容' + i, status: 'completed', taskIds: [], steps: [], createdAt: '2026-10-05T00:00:00Z', updatedAt: '2026-10-05T00:00:00Z' },
      { id: 'a-' + i, role: 'assistant', content: '原助手完整回答' + i, status: 'completed', modelStreamStatus: 'completed', replyToId: 'u-' + i, taskIds: [], steps: [], createdAt: '2026-10-05T00:00:00Z', updatedAt: '2026-10-05T00:00:00Z' }] }));
}
function fixture(initial = seed()) {
  const original = JSON.stringify(initial), data = new Map([[KEY, original]]), writes = [];
  let fail = false;
  const localStorage = { getItem: key => data.get(key) ?? null, setItem(key, value) {
    writes.push({ key, value }); if (fail) throw Object.assign(new Error('QuotaExceededError: isolated storage full'), { name: 'QuotaExceededError' });
    data.set(key, String(value));
  } };
  const context = vm.createContext({ Date, Math, Set, Map, Error, JSON, localStorage });
  const cache = new Map();
  function load(file) {
    file = path.resolve(file); if (cache.has(file)) return cache.get(file).exports;
    const module = { exports: {} }; cache.set(file, module);
    const requireLocal = name => name.startsWith('.') ? load(path.resolve(path.dirname(file), name + '.ts')) : require(name);
    vm.runInContext('(function(require,module,exports){' + transpile(fs.readFileSync(file, 'utf8')) + '\n})', context, { filename: file })(requireLocal, module, module.exports);
    return module.exports;
  }
  const { useConversationStore, ConversationStorageError } = load(path.join(root, 'src/stores/conversations.ts'));
  setActivePinia(createPinia()); const store = useConversationStore();
  return { store, original, writes, context, ConversationStorageError, raw: () => data.get(KEY), fail: value => { fail = value; } };
}
const user = content => ({ role: 'user', content, status: 'completed', taskIds: [], steps: [], executionIntent: 'AUTO' });
const assistant = content => ({ role: 'assistant', content, status: 'running', taskIds: [], steps: [], executionIntent: 'AUTO' });
const plain = value => JSON.parse(JSON.stringify(value));

test('creating31st and five later conversations preserves every original record and the recent limit is only presentation', () => {
  const f = fixture(), before = plain(f.store.items);
  for (let i = 0; i < 6; i++) f.store.createThread(307, '192.168.136.132', '新增对话' + i, 140);
  assert.equal(f.store.items.length, 36); assert.equal(f.store.recent.length, 8);
  const saved = JSON.parse(f.raw()); assert.equal(saved.length, 36);
  for (const item of before) assert.deepEqual(saved.find(row => row.id === item.id), item);
  assert.equal(f.store.persistenceError, undefined);
});

test('create/append/turn/fork/remove/clear quota failure preserves old memory, IDs, object identity and exact stored bytes', () => {
  const operations = [
    f => f.store.createThread(307, 'target', 'new', 140),
    f => f.store.appendMessage('old-0', user('new user')),
    f => f.store.appendTurn('old-0', user('new turn'), assistant('placeholder')),
    f => f.store.forkBeforeMessage('old-0', 'u-0', 'edited'),
    f => f.store.remove('old-0'), f => f.store.clear(),
  ];
  for (const operation of operations) {
    const f = fixture(), before = JSON.stringify(f.store.items), thread = f.store.items[0], message = thread.messages[0]; f.fail(true);
    assert.throws(() => operation(f), error => error instanceof f.ConversationStorageError);
    assert.equal(JSON.stringify(f.store.items), before); assert.equal(f.raw(), f.original);
    assert.equal(f.store.items[0], thread); assert.equal(thread.messages[0], message);
    assert.equal(f.writes.length, 1, 'No repeated shrink-and-retry writes');
    assert.match(f.store.persistenceError.message, /已有持久记录未删除/);
    assert.equal(f.store.hasUnsavedChanges, false);
  }
});

test('soft character limit never evicts older records or attempts a destructive smaller write', () => {
  const initial = seed(); initial[0].messages[0].content = '长'.repeat(3_500_000);
  const f = fixture(initial), before = JSON.stringify(f.store.items);
  assert.throws(() => f.store.createThread(307, 'target', 'new', 140), f.ConversationStorageError);
  assert.equal(f.raw(), f.original); assert.equal(JSON.stringify(f.store.items), before); assert.equal(f.writes.length, 0);
  assert.match(f.store.persistenceError.message, /保存大小限制/); assert.equal(f.store.items.length, 30);
});

test('stream updates and completed answer remain in memory without throwing; explicit retry saves full history', () => {
  const f = fixture(), thread = f.store.items[0], message = thread.messages[1]; f.fail(true);
  assert.doesNotThrow(() => f.store.updateMessage(thread.id, message.id, { content: '在途进度', status: 'planning', modelStreamStatus: 'running' }));
  assert.doesNotThrow(() => f.store.updateMessage(thread.id, message.id, { content: '完整成功终态🙂\n保留所有输出', status: 'completed', modelStreamStatus: 'completed' }));
  assert.equal(f.store.items[0], thread); assert.equal(thread.messages[1], message);
  assert.equal(message.status, 'completed'); assert.equal(message.modelStreamStatus, 'completed');
  assert.equal(f.raw(), f.original); assert.equal(f.store.hasUnsavedChanges, true);
  assert.match(f.store.persistenceError.message, /关闭前重试保存/);
  assert.equal(f.store.retryPersist(), false); assert.equal(f.raw(), f.original);
  f.fail(false); assert.equal(f.store.retryPersist(), true);
  assert.equal(f.store.hasUnsavedChanges, false); assert.equal(f.store.persistenceError, undefined);
  const saved = JSON.parse(f.raw()); assert.equal(saved.length, 30);
  assert.equal(saved[0].messages[1].content, '完整成功终态🙂\n保留所有输出');
  assert.equal(saved[0].messages[1].id, 'a-0');
});

test('asynchronous final-answer append explicitly retains content in memory on quota failure', () => {
  const f = fixture(); f.fail(true);
  const response = { ...assistant('独立最终汇总全文'), status: 'completed', modelStreamStatus: 'completed', replyToId: 'u-0' };
  const created = f.store.appendMessage('old-0', response, { keepInMemoryOnFailure: true });
  assert.equal(created.content, response.content); assert.equal(f.store.items[0].messages.at(-1).id, created.id);
  assert.equal(f.raw(), f.original); assert.equal(f.store.hasUnsavedChanges, true);
  f.fail(false); assert(f.store.retryPersist()); assert.equal(JSON.parse(f.raw())[0].messages.at(-1).content, response.content);
});

function installSend(f, selected = true) {
  const thread = selected ? f.store.items[0] : undefined, notices = [], dispatches = [];
  const context = f.context;
  Object.assign(context, { ConversationStorageError: f.ConversationStorageError, conversations: f.store,
    prompt: ref('  待发送原草稿🙂  '), sending: ref(false), selectedThread: ref(thread), selectedTarget: ref({ id: 307, name: '192.168.136.132' }),
    enabledTargets: ref([{ id: 307 }]), selectedTargetId: ref(307), editingMessage: ref(), activeDraft: ref(), quotedMessage: ref(),
    cloneMessageDraft: value => value === undefined ? undefined : plain(value), auditScopeForMessage: async () => undefined,
    projectIdForTarget: () => 140, clearQuotedMessage: () => {}, scrollToBottom: async () => {},
    router: { replace: async () => {} }, ElMessage: { error: message => notices.push(message), warning: message => notices.push(message) },
    readableConversationError: error => 'unexpected generic error: ' + error.message,
    dispatchConversationMessage: async (captured, u, a) => {
      assert.equal(captured.messages.find(m => m.id === u.id).content, u.content, 'Captured thread must see appended user');
      dispatches.push({ threadId: captured.id, user: plain(u), assistant: plain(a) });
    } });
  vm.runInContext(handler('sendPrompt'), context); return { context, notices, dispatches };
}

test('actual sendPrompt quota failure keeps draft and original messages; retry commits one user/assistant pair', async () => {
  const f = fixture(), before = JSON.stringify(f.store.items), { context, notices, dispatches } = installSend(f); f.fail(true);
  await context.sendPrompt();
  assert.equal(context.prompt.value, '  待发送原草稿🙂  '); assert.equal(context.sending.value, false);
  assert.equal(dispatches.length, 0); assert.equal(JSON.stringify(f.store.items), before); assert.equal(f.raw(), f.original);
  assert.equal(f.writes.length, 1, 'A turn is one atomic storage attempt'); assert.match(notices[0], /本次改动未提交/);
  f.fail(false); await context.sendPrompt();
  assert.equal(dispatches.length, 1); assert.equal(context.prompt.value, '');
  const added = f.store.items[0].messages.filter(m => m.content === '待发送原草稿🙂'); assert.equal(added.length, 1);
  const receipt = dispatches[0]; assert.equal(receipt.assistant.replyToId, receipt.user.id);
  assert.equal(f.store.items[0].messages.length, 4);
});

test('actual new-conversation send fails before navigation and retains draft when creating cannot be saved', async () => {
  const f = fixture(), before = JSON.stringify(f.store.items), { context, dispatches } = installSend(f, false); f.fail(true);
  await context.sendPrompt(); assert.equal(context.prompt.value, '  待发送原草稿🙂  ');
  assert.equal(dispatches.length, 0); assert.equal(JSON.stringify(f.store.items), before); assert.equal(f.raw(), f.original);
});

test('actual successful Dashboard dispatch is not changed to an error when terminal persistence fails', async () => {
  const f = fixture(), thread = f.store.items[0], u = thread.messages[0], a = thread.messages[1], trace = [];
  Object.assign(f.context, { conversations: f.store, selectedThread: ref(thread), approvalDialogMessageId: ref(),
    projectIdForTarget: () => 140, buildContextPrompt: () => u.content, messageReferences: () => [], agentContextReferences: () => [],
    latestWorkflowIdentity: async () => ({}), aiExecutionRequest: () => ({ executionIntent: 'AUTO', userPrompt: u.content }),
    recordThinkingProgress: (threadId, messageId) => f.store.updateMessage(threadId, messageId, { content: '完整成功回答', status: 'completed' }),
    normalizeAgentEvent: value => value,
    dispatchAiStreaming: async (_payload, onEvent) => { trace.push('done'); onEvent({ type: 'done' }); return {
      answer: '完整成功回答', plan: { provider: 'langgraph-runtime', steps: [] }, taskIds: [], citations: [] }; },
    requireAiAnswer: text => text, publicCitation: value => value, shouldPromptApproval: () => false, isLocalAiAnswer: () => false,
    saveConversationMemory: async () => { trace.push('memory'); }, loadTasks: async () => { trace.push('tasks'); },
  });
  vm.runInContext(handler('dispatchConversationMessage'), f.context); f.fail(true);
  await f.context.dispatchConversationMessage(thread, u, a, 140);
  assert.deepEqual(trace, ['done', 'memory', 'tasks']); assert.equal(a.status, 'completed');
  assert.equal(a.modelStreamStatus, 'completed'); assert.equal(a.content, '完整成功回答');
  assert.equal(f.raw(), f.original); assert.equal(f.store.hasUnsavedChanges, true);
});

test('actual task final-answer success/error remains visible in memory under quota, without duplicate summary attempts', async () => {
  for (const failure of [false, true]) {
    const f = fixture(), thread = f.store.items[0], originalAssistant = thread.messages[1], answeringMessages = new Set();
    let calls = 0, scrolls = 0;
    originalAssistant.taskIds = [901];
    Object.assign(f.context, { conversations: f.store, answeringMessages,
      projectIdForTarget: () => 140, buildContextPrompt: () => thread.messages[0].content,
      requireAiAnswer: answer => { assert(answer); return answer; },
      endpoints: { answerAi: async payload => {
        calls++; assert.equal(payload.targetId, 307); assert.deepEqual(plain(payload.taskIds), [901]);
        if (failure) throw new Error('upstream final-answer error (fixture)');
        return { data: { answer: '任务总结完整正文🙂', taskIds: [901], provider: 'fixture-only' } };
      } },
      readableAiConversationError: error => error.message,
      scrollToBottom: () => { scrolls++; },
    });
    vm.runInContext(handler('requestFinalAnswer'), f.context); f.fail(true);
    await f.context.requestFinalAnswer(thread, originalAssistant);
    assert.equal(calls, 1); assert.equal(scrolls, 1); assert.equal(answeringMessages.size, 0);
    assert.equal(thread.messages.length, 3); assert.equal(thread.messages[1], originalAssistant);
    const final = thread.messages.at(-1);
    assert.equal(originalAssistant.status, 'completed');
    assert.equal(originalAssistant.modelStreamStatus, failure ? 'failed' : 'completed');
    assert.equal(final.status, failure ? 'failed' : 'completed');
    assert.equal(final.replyToId, 'u-0');
    assert.equal(final.content, failure ? '任务已经结束，但生成检测结论时出现问题：upstream final-answer error (fixture)' : '任务总结完整正文🙂');
    assert.equal(f.raw(), f.original); assert.equal(f.store.hasUnsavedChanges, true);
    f.fail(false); assert(f.store.retryPersist());
    assert.equal(JSON.parse(f.raw())[0].messages.at(-1).content, final.content);
    assert.equal(calls, 1, 'Retry saving must not ask the model again');
  }
});

test('actual storage warning template renders a persistent alert and retry option, then clears after successful save', async () => {
  const fragment = descriptor.template.content.match(/<div v-if="conversations\.persistenceError"[\s\S]*?<\/div>/)?.[0]; assert(fragment);
  const f = fixture(); f.fail(true); f.store.updateMessage('old-0', 'a-0', { content: '终态全文', status: 'completed' });
  const render = () => renderToString(createSSRApp({ template: fragment, setup: () => ({ conversations: f.store }) }));
  const html = await render(); assert(html.includes('role="alert"')); assert(html.includes('已有持久记录未删除')); assert(html.includes('重试保存'));
  f.fail(false); assert(f.store.retryPersist()); const recovered = await render(); assert(!recovered.includes('role="alert"'));
});
