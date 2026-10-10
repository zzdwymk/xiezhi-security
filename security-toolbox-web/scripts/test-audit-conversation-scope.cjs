// Exercise the real Dashboard actions and Pinia store with isolated API/storage fixtures.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const { ref, reactive, computed } = require('vue');
const { createPinia, setActivePinia } = require('pinia');

const root = path.resolve(__dirname, '..');
const dashboard = parse(fs.readFileSync(path.join(root, 'src/views/Dashboard.vue'), 'utf8')).descriptor;
const ast = ts.createSourceFile('Dashboard.ts', dashboard.scriptSetup.content, ts.ScriptTarget.Latest, true);
function dashboardFunction(name) {
  const node = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name);
  assert.ok(node, `Dashboard function ${name} exists`);
  return node.getText(ast);
}
function transpile(source) {
  return ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
}
const actionNames = ['projectIdForTarget', 'auditScopeForMessage', 'cloneMessageDraft',
  'clearQuotedMessage', 'messageReferences', 'sendPrompt', 'retryConversationMessage',
  'loadProjectScopes', 'load'];
const actionSource = transpile(actionNames.map(dashboardFunction).join('\n'));
const json = value => JSON.parse(JSON.stringify(value));
const audit = (projectId = 4, extra = {}) => ({ type: 'audit', id: 9166, data: { projectId }, ...extra });
const defaultTargets = [
  { id: 9, name: '记忆中的其他项目目标', enabled: true },
  { id: 5, name: '审计项目目标', enabled: true },
  { id: 8, name: '历史项目目标', enabled: true },
  { id: 6, name: '已停用目标', enabled: false },
];
const defaultProjects = [{ id: 7, status: 'ACTIVE' }, { id: 4, status: 'ACTIVE' }, { id: 8, status: 'ARCHIVED' }];

function fixture(options = {}) {
  const storage = new Map();
  const localStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, String(value)) };
  const context = vm.createContext({ console, Date, Math, Set, Map, Number, Error, JSON, localStorage });
  const cache = new Map();
  function loadModule(filename) {
    filename = path.resolve(filename);
    if (cache.has(filename)) return cache.get(filename).exports;
    const module = { exports: {} };
    cache.set(filename, module);
    const requireSource = id => id.startsWith('.')
      ? loadModule(path.resolve(path.dirname(filename), id + '.ts')) : require(id);
    const execute = vm.runInContext('(function(require,module,exports){\n' + transpile(fs.readFileSync(filename, 'utf8')) + '\n})', context, { filename });
    execute(requireSource, module, module.exports);
    return module.exports;
  }
  const { useConversationStore, ConversationStorageError } = loadModule(path.join(root, 'src/stores/conversations.ts'));
  const { resolveAuditConversationScope } = loadModule(path.join(root, 'src/utils/auditConversationScope.ts'));
  const { requireAiAnswer } = loadModule(path.join(root, 'src/utils/aiAnswer.ts'));
  setActivePinia(createPinia());
  const conversations = useConversationStore();
  const route = reactive({ query: options.query || {} });
  const notices = [], requests = [], apiCalls = [], answerRequests = [];
  const targets = ref(json(options.targets || defaultTargets));
  const enabledTargets = computed(() => targets.value.filter(target => target.enabled));
  const selectedTargetId = ref(options.selectedTargetId ?? 9);
  const selectedTarget = computed(() => enabledTargets.value.find(target => target.id === selectedTargetId.value));
  const selectedThread = computed(() => conversations.items.find(thread => thread.id === route.query.conversation));
  const endpoints = {
    targets: async () => ({ data: json(options.targets || defaultTargets) }),
    projects: async () => { apiCalls.push(['projects']); return { data: json(options.projects || defaultProjects) }; },
    projectTargets: async projectId => {
      apiCalls.push(['projectTargets', projectId]);
      if (options.beforeMembership) await options.beforeMembership(projectId);
      return { data: ((options.memberships || { 7: [9], 4: [5, 6], 8: [8] })[projectId] || []).map(targetId => ({ targetId })) };
    },
    answerAi: async request => { answerRequests.push(json(request)); return { data: { answer: '已根据原有任务重新生成回答' } }; },
  };
  Object.assign(context, {
    resolveAuditConversationScope, requireAiAnswer, ConversationStorageError, conversations, route, endpoints, targets, enabledTargets,
    selectedTargetId, selectedTarget, selectedThread, notices, requests, answerRequests, apiCalls,
    prompt: ref('请结合这条审计日志核查操作是否符合预期。'),
    activeDraft: ref(options.refs ? { refs: json(options.refs), mode: 'ask' } : undefined),
    editingMessage: ref(), quotedMessage: ref(), sending: ref(false), retryingMessageIds: ref(new Set()),
    projectByTarget: ref({ 9: 7, 5: 4 }), loading: ref(false),
    router: { replace: async value => { route.query = value.query || {}; } },
    ElMessage: Object.fromEntries(['warning', 'error', 'success'].map(level => [level, text => notices.push({ level, text })])),
    readableConversationError: error => error.message || String(error),
    scrollToBottom: async () => {}, focusComposer: () => {}, loadTasks: async () => {},
    safeGet: async (request, fallback) => { try { return await request(); } catch { return { data: fallback }; } },
    copilot: { consume: () => options.draft ? json(options.draft) : undefined },
    buildContextPrompt: (thread, userId) => thread.messages.find(message => message.id === userId).content,
  });
  context.dispatchConversationMessage = async (thread, user, assistant, projectId = context.projectIdForTarget(thread.targetId, thread)) => {
    requests.push(json({ sessionId: thread.id, turnId: user.id, targetId: thread.targetId, projectId, user, assistant }));
    if (options.beforeDispatch) await options.beforeDispatch();
    conversations.updateMessage(thread.id, assistant.id, { content: '核查完成', status: 'completed' });
  };
  vm.runInContext(actionSource, context, { filename: 'Dashboard-extracted-actions.js' });
  context.localStorage.setItem('security_toolbox_dashboard_target', '9');
  context.failedThread = ({ projectId = 7, targetId = 9, refs = [audit()], taskIds = [] } = {}) => {
    const thread = conversations.createThread(targetId, '原始授权目标', '原始审计核查', projectId);
    const user = conversations.appendMessage(thread.id, { role: 'user', content: context.prompt.value, status: 'completed',
      taskIds: [], steps: [], references: json(refs), copilotMode: 'ask', executionIntent: 'AUTO' });
    const failed = conversations.appendMessage(thread.id, { role: 'assistant', content: '目标不属于该评估项目',
      status: 'failed', taskIds, steps: [], replyToId: user.id });
    route.query = { conversation: thread.id };
    return { thread, user, failed };
  };
  return context;
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test('load replaces a remembered target outside the audit project and send dispatches the resolved scope', async () => {
  const refs = [audit()];
  const f = fixture({ draft: { id: 'audit-draft', prompt: '核查审计', refs, mode: 'ask' }, query: { projectId: '7' } });
  await f.load();
  assert.equal(f.selectedTargetId.value, 5);
  assert.equal(f.loading.value, false);
  assert.deepEqual(json(f.activeDraft.value.refs), refs);
  await f.sendPrompt();
  assert.equal(f.requests.length, 1);
  assert.deepEqual({ project: f.requests[0].projectId, target: f.requests[0].targetId }, { project: 4, target: 5 });
  assert.deepEqual(f.requests[0].user.references, refs);
  assert.equal(f.selectedThread.value.projectId, 4);
  assert.equal(f.activeDraft.value, undefined);
});

test('an explicit archived audit project remains available for read-only review', async () => {
  const f = fixture({ refs: [audit(8)] });
  await f.sendPrompt();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].projectId, 8);
  assert.equal(f.requests[0].targetId, 8);
});

test('target audit ignores unrelated preferred project and discovers its actual membership', async () => {
  const f = fixture({ refs: [{ type: 'audit-log', id: 9167, targetId: 5 }] });
  await f.sendPrompt();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].projectId, 4);
  assert.equal(f.requests[0].targetId, 5);
});

test('target audit can discover an archived project when active projects have no membership', async () => {
  const f = fixture({ refs: [{ type: 'audit', id: 9168, targetId: 8 }] });
  await f.sendPrompt();
  assert.equal(f.requests[0].projectId, 8);
  assert.equal(f.requests[0].targetId, 8);
});

test('project without enabled members shows an actionable error without creating or dispatching a thread', async () => {
  const refs = [audit()];
  const f = fixture({ refs, memberships: { 4: [6], 7: [9] } });
  const prompt = f.prompt.value;
  await f.sendPrompt();
  assert.equal(f.requests.length, 0);
  assert.equal(f.conversations.items.length, 0);
  assert.match(f.notices.at(-1).text, /所属项目没有可用的关联目标/);
  assert.equal(f.prompt.value, prompt);
  assert.deepEqual(json(f.activeDraft.value.refs), refs);
  assert.equal(f.sending.value, false);
});

test('load clears invalid selection and surfaces the audit-specific membership error', async () => {
  const f = fixture({ draft: { prompt: '核查审计', refs: [audit()], mode: 'ask' }, memberships: { 4: [6], 7: [9] } });
  await f.load();
  assert.equal(f.selectedTargetId.value, undefined);
  assert.match(f.notices.at(-1).text, /所属项目没有可用的关联目标/);
  await f.sendPrompt();
  assert.equal(f.requests.length, 0);
});

test('target-specific audit cannot substitute another target in the referenced project', async () => {
  const f = fixture({ refs: [audit(4, { targetId: 9 })] });
  await f.sendPrompt();
  assert.equal(f.requests.length, 0);
  assert.match(f.notices.at(-1).text, /所属项目没有可用的关联目标/);
});

test('disabled and unassociated audit targets report actionable errors without dispatch', async () => {
  for (const [targetId, pattern] of [[6, /已删除或停用/], [5, /尚未关联评估项目/]]) {
    const f = fixture({ refs: [{ type: 'audit', id: 9168, targetId }], memberships: {} });
    await f.sendPrompt();
    assert.equal(f.requests.length, 0);
    assert.match(f.notices.at(-1).text, pattern);
  }
});

test('retry of an old mismatched audit thread uses a new session and preserves original messages and references', async () => {
  const f = fixture();
  const { thread, user, failed } = f.failedThread();
  const original = JSON.stringify(thread);
  await f.retryConversationMessage(failed);
  assert.equal(f.requests.length, 1);
  const request = f.requests[0];
  assert.notEqual(request.sessionId, thread.id);
  assert.notEqual(request.turnId, user.id);
  assert.deepEqual({ project: request.projectId, target: request.targetId }, { project: 4, target: 5 });
  assert.equal(JSON.stringify(f.conversations.items.find(item => item.id === thread.id)), original);
  assert.deepEqual(request.user.references, json(user.references));
  assert.equal(request.user.content, user.content);
  assert.equal(request.user.executionIntent, user.executionIntent);
  assert.equal(request.user.copilotMode, user.copilotMode);
  assert.equal(f.selectedThread.value.id, request.sessionId);
  f.selectedThread.value.messages[0].references[0].data.projectId = 999;
  assert.equal(user.references[0].data.projectId, 4);
  assert.equal(f.sending.value, false);
  assert.equal(f.retryingMessageIds.value.size, 0);
});

test('retry within the correct audit scope keeps the original session and turn', async () => {
  const f = fixture();
  const { thread, user, failed } = f.failedThread({ projectId: 4, targetId: 5 });
  await f.retryConversationMessage(failed);
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].sessionId, thread.id);
  assert.equal(f.requests[0].turnId, user.id);
  assert.equal(f.conversations.items.length, 1);
  assert.equal(f.conversations.items[0].messages.at(-1).status, 'completed');
});

test('audit retry remaps project even when the thread already has the correct target', async () => {
  const f = fixture();
  const { thread, failed } = f.failedThread({ projectId: 7, targetId: 5 });
  await f.retryConversationMessage(failed);
  assert.notEqual(f.requests[0].sessionId, thread.id);
  assert.equal(f.requests[0].projectId, 4);
  assert.equal(f.requests[0].targetId, 5);
});

test('legacy single-reference audit messages also recover into the proper scope', async () => {
  const f = fixture();
  const { thread, user, failed } = f.failedThread();
  f.conversations.updateMessage(thread.id, user.id, { references: undefined, reference: audit() });
  await f.retryConversationMessage(failed);
  assert.equal(f.requests[0].projectId, 4);
  assert.equal(f.requests[0].targetId, 5);
  assert.deepEqual(f.requests[0].user.references, [audit()]);
});

test('sending an audit draft from an unrelated thread creates a scoped session and keeps its source', async () => {
  const f = fixture({ refs: [audit()] });
  const { thread } = f.failedThread();
  const original = JSON.stringify(thread);
  await f.sendPrompt();
  assert.equal(f.requests.length, 1);
  assert.notEqual(f.requests[0].sessionId, thread.id);
  assert.equal(f.requests[0].projectId, 4);
  assert.equal(f.requests[0].targetId, 5);
  assert.equal(JSON.stringify(f.conversations.items.find(item => item.id === thread.id)), original);
});

test('sending an audit draft in an already matching thread keeps that session', async () => {
  const f = fixture({ refs: [audit()], selectedTargetId: 5 });
  const { thread } = f.failedThread({ projectId: 4, targetId: 5 });
  await f.sendPrompt();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].sessionId, thread.id);
  assert.equal(f.conversations.items.length, 1);
});

test('audit retry preserves the original failed thread even when it is oldest in a full local history', async () => {
  const f = fixture();
  const { thread, failed } = f.failedThread();
  const original = JSON.stringify(thread);
  for (let index = 0; index < 29; index++) f.conversations.createThread(9, '其他目标', '其他会话 ' + index, 7);
  await f.retryConversationMessage(failed);
  assert.equal(f.requests.length, 1);
  assert.equal(JSON.stringify(f.conversations.items.find(item => item.id === thread.id)), original);
  const stored = JSON.parse(f.localStorage.getItem('security_toolbox_ai_conversations_v2'));
  assert.equal(JSON.stringify(stored.find(item => item.id === thread.id)), original);
});

test('retry rechecks changed membership and keeps failed state if no valid target remains', async () => {
  const f = fixture({ memberships: { 4: [6], 7: [9] } });
  const { thread, failed } = f.failedThread();
  await f.retryConversationMessage(failed);
  assert.equal(f.requests.length, 0);
  assert.equal(f.conversations.items.length, 1);
  const result = f.conversations.items.find(item => item.id === thread.id).messages.at(-1);
  assert.equal(result.status, 'failed');
  assert.match(result.content, /所属项目没有可用的关联目标/);
  assert.equal(f.sending.value, false);
  assert.equal(f.retryingMessageIds.value.size, 0);
});

test('retries with real tasks regenerate the answer without moving sessions or dispatching tasks', async () => {
  const f = fixture();
  const { thread, failed } = f.failedThread({ taskIds: [303] });
  await f.retryConversationMessage(failed);
  assert.equal(f.requests.length, 0);
  assert.equal(f.answerRequests.length, 1);
  assert.deepEqual(f.answerRequests[0].taskIds, [303]);
  assert.equal(f.conversations.items.length, 1);
  assert.equal(f.selectedThread.value.id, thread.id);
  assert.deepEqual(json(f.selectedThread.value.messages.at(-1).taskIds), [303]);
});

test('async audit validation preserves send and retry duplicate-submit guards', async () => {
  for (const action of ['send', 'retry']) {
    let release;
    const held = new Promise(resolve => { release = resolve; });
    const f = fixture({ refs: [audit()], beforeMembership: () => held });
    const failed = action === 'retry' ? f.failedThread().failed : undefined;
    const first = action === 'send' ? f.sendPrompt() : f.retryConversationMessage(failed);
    assert.equal(f.sending.value, true);
    const second = action === 'send' ? f.sendPrompt() : f.retryConversationMessage(failed);
    await second;
    release();
    await first;
    assert.equal(f.requests.length, 1, action);
    assert.equal(f.sending.value, false, action);
    assert.equal(f.retryingMessageIds.value.size, 0, action);
  }
});

test('membership API failure preserves the unsent draft and releases the send lock', async () => {
  const f = fixture({ refs: [audit()], beforeMembership: async () => { throw new Error('项目成员读取失败'); } });
  const original = f.prompt.value;
  await f.sendPrompt();
  assert.equal(f.requests.length, 0);
  assert.equal(f.conversations.items.length, 0);
  assert.equal(f.prompt.value, original);
  assert.deepEqual(json(f.activeDraft.value.refs), [audit()]);
  assert.match(f.notices.at(-1).text, /项目成员读取失败/);
  assert.equal(f.sending.value, false);
});

test('ordinary non-audit send retains the selected target and existing scope behavior', async () => {
  const f = fixture({ refs: [{ type: 'finding', id: 77, targetId: 9 }] });
  await f.sendPrompt();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].projectId, 7);
  assert.equal(f.requests[0].targetId, 9);
  assert.equal(f.apiCalls.length, 0);
});

(async () => {
  let failures = 0;
  for (const { name, fn } of tests) {
    try { await fn(); console.log('PASS ' + name); }
    catch (error) { failures++; console.error('FAIL ' + name); console.error(error); }
  }
  console.log(`${tests.length - failures}/${tests.length} audit conversation regression checks passed`);
  if (failures) process.exitCode = 1;
})().catch(error => { console.error(error); process.exitCode = 1; });
