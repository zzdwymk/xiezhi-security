const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');

const root = path.join(__dirname, '..');
const script = parse(fs.readFileSync(path.join(root, 'src/views/Tasks.vue'), 'utf8')).descriptor.scriptSetup.content;
const ast = ts.createSourceFile('Tasks.ts', script, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const retryNode = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'retryTask');
assert.ok(retryNode, 'real Tasks.vue retry function exists');
const compile = source => ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.CommonJS },
}).outputText;
const retryCode = compile(retryNode.getText(ast));

function harness(storage = new Map(), transport) {
  const calls = [], messages = [], errors = [];
  let next = 0;
  const context = vm.createContext({
    retrying: { value: undefined }, pendingRetryKeys: new Map(),
    sessionStorage: {
      getItem: key => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: key => storage.delete(key),
    },
    crypto: { randomUUID: () => `request-${++next}` },
    endpoints: { retryTask: async (id, key) => {
      calls.push({ id, key });
      return transport ? transport(calls.length) : { data: { id: 81, status: 'PENDING', progressMessage: '等待队列' } };
    } },
    ElMessage: { success: message => messages.push(message), error: message => { messages.push(message); errors.push(message); } },
    load: async () => {}, toErrorMessage: (error, fallback) => error?.message || fallback,
  });
  vm.runInContext(`${retryCode}\nthis.runRetry = retryTask;`, context);
  return { context, calls, messages, errors, storage, retry: id => context.runRetry({ id }) };
}

async function main() {
  let passed = 0;
  async function test(name, run) { await run(); passed++; console.log('PASS ' + name); }
  await test('lost response reuses the same key and success starts a new explicit operation', async () => {
    const h = harness(new Map(), number => {
      if (number === 1) throw new Error('connection lost');
      return { data: { id: 81, status: 'PENDING' } };
    });
    await h.retry(7); await h.retry(7); await h.retry(7);
    assert.equal(h.calls[0].key, h.calls[1].key);
    assert.notEqual(h.calls[1].key, h.calls[2].key);
    assert.equal(h.storage.size, 0);
  });
  await test('page reconstruction resumes the unacknowledged operation from session storage', async () => {
    const shared = new Map();
    const first = harness(shared, () => { throw new Error('timeout'); });
    await first.retry(7);
    const restored = harness(shared);
    await restored.retry(7);
    assert.equal(first.calls[0].key, restored.calls[0].key);
    assert.equal(shared.size, 0);
  });
  await test('a double click cannot dispatch while the first request is pending', async () => {
    let resolve;
    const h = harness(new Map(), () => new Promise(ok => { resolve = ok; }));
    const first = h.retry(7); await h.retry(7);
    assert.equal(h.calls.length, 1);
    resolve({ data: { id: 81, status: 'PENDING' } });
    await first;
  });
  await test('blocked storage and unavailable randomUUID keep an in-memory retry key', async () => {
    const h = harness(new Map(), number => {
      if (number === 1) throw new Error('timeout');
      return { data: { id: 81, status: 'REJECTED', progressMessage: '本地任务队列已满' } };
    });
    h.context.crypto = {};
    h.context.sessionStorage = { getItem() { throw Error('blocked'); }, setItem() { throw Error('blocked'); }, removeItem() { throw Error('blocked'); } };
    await h.retry(7); await h.retry(7);
    assert.equal(h.calls[0].key, h.calls[1].key);
    assert.match(h.calls[0].key, /^[A-Za-z0-9_-]{1,128}$/);
    assert.equal(h.messages.at(-1), '重试任务 #81：本地任务队列已满');
    assert.equal(h.errors.at(-1), '重试任务 #81：本地任务队列已满');
  });
  await test('the real API adapter sends Idempotency-Key only when supplied', async () => {
    const source = fs.readFileSync(path.join(root, 'src/api.ts'), 'utf8');
    const apiAst = ts.createSourceFile('api.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    let initializer;
    const visit = node => {
      if (ts.isPropertyAssignment(node) && node.name.getText(apiAst) === 'retryTask') initializer = node.initializer.getText(apiAst);
      ts.forEachChild(node, visit);
    };
    visit(apiAst); assert.ok(initializer);
    const requests = [];
    const context = vm.createContext({ api: { post: (...args) => requests.push(args) } });
    vm.runInContext(compile(`const send = ${initializer}; this.send = send;`), context);
    context.send(7, 'key'); context.send(7);
    assert.equal(requests[0][0], '/tasks/7/retry');
    assert.equal(requests[0][2].headers['Idempotency-Key'], 'key');
    assert.equal(requests[1][2], undefined);
  });
  console.log(`${passed} task retry idempotency checks passed`);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
