const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const { createPinia, setActivePinia } = require('pinia');
const { createClient } = require('./test-ai-intent-request.cjs');
const root = path.resolve(__dirname, '..');
const cache = new Map();
function load(file) {
  file = path.resolve(file);
  if (cache.has(file)) return cache.get(file).exports;
  const module = { exports: {} }; cache.set(file, module);
  const code = ts.transpileModule(fs.readFileSync(file, 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } }).outputText;
  const localRequire = name => name.startsWith('.') ? load(path.resolve(path.dirname(file), name + '.ts')) : require(name);
  vm.runInThisContext(`(function(require,module,exports){${code}\n})`, { filename: file })(localRequire, module, module.exports);
  return module.exports;
}
const { useConversationStore } = load(path.join(root, 'src/stores/conversations.ts'));
const { buildAiProgress } = load(path.join(root, 'src/utils/aiProgress.ts'));
const at = seconds => new Date(Date.parse('2026-10-01T00:00:00Z') + seconds * 1000).toISOString();
const message = patch => ({ id: 'message', role: 'assistant', content: 'existing answer', status: 'running', modelStreamStatus: 'running', taskIds: [], steps: [], createdAt: at(0), updatedAt: at(0), ...patch });
let passed = 0;
function test(name, run) { run(); passed++; console.log('PASS ' + name); }
const previousStorage = global.localStorage;
try {
  test('real Pinia store reload restores live streams as unknown but preserves completed records and server tasks', () => {
    const stored = [{ id: 'thread', messages: [message({}), message({ id: 'finished', status: 'completed', modelStreamStatus: 'completed', progressFinishedAt: at(9) }), message({ id: 'task', taskIds: [7] })] }];
    global.localStorage = { getItem: key => key.endsWith('_v2') ? JSON.stringify(stored) : null, setItem() {} };
    setActivePinia(createPinia());
    const store = useConversationStore();
    assert.equal(store.items[0].messages[0].modelStreamStatus, 'interrupted');
    assert.equal(buildAiProgress(store.items[0].messages[0], [], Date.parse(at(86400))).elapsed, undefined);
    const finished = buildAiProgress(store.items[0].messages[1], [], Date.parse(at(86400)));
    assert.equal(finished.interrupted, false); assert.equal(finished.elapsed, 9000);
    const task = buildAiProgress(store.items[0].messages[2], [{ id: 7, toolCode: 'http_headers', status: 'RUNNING', createdAt: at(1), startedAt: at(2) }], Date.parse(at(10)));
    assert.equal(task.modelActive, false); assert.equal(task.active, true); assert.equal(task.completeTasks, 0);
  });
} finally { global.localStorage = previousStorage; }
// Execute the production SFC handler and helpers, not a duplicate of its status logic.
const filename = path.join(root, 'src/views/Dashboard.vue');
const source = parse(fs.readFileSync(filename, 'utf8')).descriptor.scriptSetup.content;
const ast = ts.createSourceFile(filename + '.ts', source, ts.ScriptTarget.Latest, true);
const names = new Set(['applyAgentEvent', 'eventStepIndex', 'normalizedStep', 'publicCitation', 'displayAgentValue']);
const functions = ast.statements.filter(node => ts.isFunctionDeclaration(node) && names.has(node.name?.text)).map(node => node.getText(ast)).join('\n');
const code = ts.transpileModule(functions, { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText;
const presentation = load(path.join(root, 'src/utils/aiPresentation.ts'));
const steps = load(path.join(root, 'src/utils/aiStepState.ts'));
function fixture() {
  const current = message({});
  const conversations = { items: [{ id: 'thread', messages: [current] }], updateMessage(threadId, messageId, patch) { Object.assign(current, patch); } };
  const context = vm.createContext({ ...presentation, ...steps, conversations, normalizeAgentEvent: createClient({}).normalizeAgentEvent, scrollToBottom: async () => {}, Date });
  vm.runInContext(code, context, { filename });
  return { current, apply: event => context.applyAgentEvent('thread', 'message', event) };
}
for (const flag of [{ recorded: true }, { eventTiming: 'VERIFIED_RECORD' }]) {
  for (const type of ['done', 'error']) {
    test(`Dashboard retains active lifecycle for ${type} with ${Object.keys(flag)[0]}`, () => {
      const { current, apply } = fixture();
      apply({ type, status: type === 'error' ? 'FAILED' : 'COMPLETED', message: 'historical event', ...flag });
      assert.equal(current.status, 'running'); assert.equal(current.modelStreamStatus, 'running');
      assert.equal(current.progressFinishedAt, undefined);
      assert.equal(current.agentEvents.length, 1);
      assert.equal(current.agentEvents[0][Object.keys(flag)[0]], Object.values(flag)[0]);
    });
  }
}
test('Dashboard still accepts real live done and error lifecycle events', () => {
  for (const [type, status] of [['done', 'completed'], ['error', 'failed']]) {
    const { current, apply } = fixture();
    apply({ type, message: 'live event' });
    assert.equal(current.status, status);
    assert.equal(current.agentEvents.length, 1);
  }
});
console.log(`${passed} AI progress lifecycle integration checks passed.`);
