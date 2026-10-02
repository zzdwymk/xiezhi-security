const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const source = path.join(__dirname, '../src/utils/taskDetail.ts');
const moduleOutput = { exports: {} };
const code = ts.transpileModule(fs.readFileSync(source, 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText;
vm.runInThisContext(`(function(module,exports){${code}\n})`, { filename: source })(moduleOutput, moduleOutput.exports);
const { createTaskDetailLoader, mergeTaskDetailSnapshot, isTerminalTaskStatus, taskDetailEmptyResultText } = moduleOutput.exports;
const tick = () => Promise.resolve();
function deferred() {
  let resolve, reject;
  const promise = new Promise((ok, bad) => { resolve = ok; reject = bad; });
  return { promise, resolve, reject };
}
function harness(extra = {}) {
  const calls = [], pending = [], applied = [], errors = [], loading = [];
  const loader = createTaskDetailLoader({
    fetch: id => { calls.push(id); const result = deferred(); pending.push(result); return result.promise; },
    apply: value => applied.push(value), loading: value => loading.push(value),
    error: error => { if (error) errors.push(error); }, ...extra,
  });
  return { loader, calls, pending, applied, errors, loading };
}
let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log('PASS ' + name); }

(async () => {
  await test('opening details waits for the authoritative result and exposes loading', async () => {
    const h = harness(); const request = h.loader.load(7);
    assert.deepEqual(h.loading, [true]); assert.equal(h.applied.length, 0);
    await tick(); h.pending[0].resolve({ id: 7, status: 'SUCCESS', resultJson: '{"findings":[]}' });
    await request; assert.equal(h.applied[0].resultJson, '{"findings":[]}'); assert.deepEqual(h.loading, [true, false]);
  });
  await test('switching detail selection ignores a late response and its loading cleanup', async () => {
    const h = harness(); const old = h.loader.load(1); await tick();
    const current = h.loader.load(2); await tick();
    h.pending[0].resolve({ id: 1, status: 'SUCCESS', resultJson: 'old' }); await old;
    assert.equal(h.applied.length, 0); assert.equal(h.loading.at(-1), true);
    h.pending[1].resolve({ id: 2, status: 'SUCCESS', resultJson: 'new' }); await current;
    assert.equal(h.applied[0].id, 2);
  });
  await test('duplicate refresh calls share one pending request', async () => {
    const h = harness(); const first = h.loader.load(1); const second = h.loader.load(1);
    assert.equal(first, second); await tick(); assert.deepEqual(h.calls, [1]);
    h.pending[0].resolve({ id: 1, status: 'RUNNING' }); await first;
  });
  await test('a terminal event supersedes an already running detail read', async () => {
    const h = harness(); const before = h.loader.load(1); await tick();
    const terminal = h.loader.load(1, true); await tick();
    h.pending[1].resolve({ id: 1, status: 'SUCCESS', resultJson: 'finished' }); await terminal;
    h.pending[0].resolve({ id: 1, status: 'RUNNING' }); await before;
    assert.equal(h.applied.length, 1); assert.equal(h.applied[0].resultJson, 'finished');
  });
  await test('closing details invalidates pending responses and errors', async () => {
    const h = harness(); const request = h.loader.load(1); await tick(); h.loader.invalidate();
    h.pending[0].reject(new Error('late network failure')); await request;
    assert.equal(h.applied.length, 0); assert.equal(h.errors.length, 0); assert.equal(h.loading.at(-1), false);
  });
  await test('a current request failure exposes an error without replacing cached details', async () => {
    const h = harness(); const request = h.loader.load(1); await tick();
    h.pending[0].reject(new Error('network unavailable')); await request;
    assert.equal(h.applied.length, 0); assert.match(h.errors[0].message, /network/); assert.equal(h.loading.at(-1), false);
  });
  await test('terminal state received before commit causes at most one delayed second read', async () => {
    const values = [{ id: 1, status: 'RUNNING' }, { id: 1, status: 'CANCELLED' }];
    const calls = []; let waits = 0;
    const h = harness({ fetch: async id => { calls.push(id); return values.shift(); },
      shouldRetry: task => !isTerminalTaskStatus(task.status), wait: async () => { waits++; } });
    await h.loader.load(1);
    assert.deepEqual(calls, [1, 1]); assert.equal(waits, 1); assert.equal(h.applied[0].status, 'CANCELLED');
    let boundedCalls = 0;
    const bounded = harness({ fetch: async () => { boundedCalls++; return { id: 1, status: 'RUNNING' }; }, shouldRetry: () => true, wait: async () => {} });
    await bounded.loader.load(1); assert.equal(boundedCalls, 2);
  });
  await test('normal terminal results do not trigger a second request', async () => {
    let calls = 0;
    const h = harness({ fetch: async () => { calls++; return { id: 1, status: 'SUCCESS', resultJson: '{}' }; }, shouldRetry: task => !isTerminalTaskStatus(task.status) });
    await h.loader.load(1); assert.equal(calls, 1);
  });
  await test('old polling snapshots cannot downgrade SSE terminal state or erase fresh results', () => {
    const current = { id: 1, status: 'SUCCESS', resultJson: '{"summary":"done"}', progressUpdatedAt: '2026-09-29T12:00:05Z' };
    const merged = mergeTaskDetailSnapshot(current, { id: 1, status: 'RUNNING', resultJson: undefined, progressUpdatedAt: '2026-09-29T12:00:01Z' });
    assert.equal(merged.status, 'SUCCESS'); assert.equal(merged.resultJson, current.resultJson);
    assert.equal(mergeTaskDetailSnapshot(current, { id: 1, status: 'SUCCESS' }).resultJson, current.resultJson);
    assert.equal(mergeTaskDetailSnapshot(current, { id: 2, status: 'RUNNING' }).resultJson, undefined);
  });
  await test('empty result wording distinguishes completion from no findings', () => {
    assert.match(taskDetailEmptyResultText({ id: 1, status: 'SUCCESS' }), /暂未读取到结果/);
    assert.match(taskDetailEmptyResultText({ id: 1, status: 'FAILED' }), /失败原因/);
    assert.match(taskDetailEmptyResultText({ id: 1, status: 'SKIPPED' }), /已跳过/);
    assert.equal(isTerminalTaskStatus('SKIPPED'), true); assert.equal(isTerminalTaskStatus('BLOCKED'), false);
  });
  console.log(`${passed} task detail behavior checks passed.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
