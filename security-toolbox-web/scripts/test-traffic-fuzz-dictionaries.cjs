'use strict';
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm'), assert = require('node:assert/strict');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const root = path.resolve(__dirname, '..');
const transpile = text => ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
const helperModule = { exports: {} };
vm.runInNewContext(`(function(module,exports){${transpile(fs.readFileSync(path.join(root, 'src/utils/trafficFuzzDraft.ts'), 'utf8'))}})`, { URL })(helperModule, helperModule.exports);
const { normalizeFuzzDictionary, validateFuzzDictionaries } = helperModule.exports;
const sfc = parse(fs.readFileSync(path.join(root, 'src/views/Traffic.vue'), 'utf8'));
assert.equal(sfc.errors.length, 0);
const ast = ts.createSourceFile('Traffic.vue', sfc.descriptor.scriptSetup.content, ts.ScriptTarget.Latest, true);
const productionFunction = (name, context) => {
  const node = ast.statements.find(item => ts.isFunctionDeclaration(item) && item.name?.text === name);
  assert(node, name);
  return vm.runInNewContext(`${transpile(node.getText(ast))}\n${name}`, { ...helperModule.exports, ...context });
};
const productionEstimate = context => {
  const node = ast.statements.flatMap(item => ts.isVariableStatement(item) ? [...item.declarationList.declarations] : []).find(item => item.name.getText(ast) === 'estimatedFuzzRequests');
  assert(node?.initializer);
  return vm.runInNewContext(`${transpile(`const result = ${node.initializer.getText(ast)}`)}\nresult`, { ...helperModule.exports, computed: callback => callback(), ...context });
};
const clone = value => JSON.parse(JSON.stringify(value));
const modes = ['PITCHFORK', 'SHORTEST', 'PITCHFORK_LONGEST', 'LONGEST', 'CLUSTER_BOMB', 'CLUSTERBOMB', 'CARTESIAN'];
const message = names => `多字典模式的每个占位符都需要至少一行非空载荷：${names.map(name => `§${name}§`).join('、')}`;
const checks = [];
async function check(name, action) { await action(); checks.push({ name, status: 'PASS' }); }
function fixture(mode, groups, shared = 'A') {
  const ref = value => ({ value });
  const calls = [], approvals = [], warnings = [], busyWrites = [];
  let busy = false;
  const context = {
    actionSessions: () => [{ id: 327 }], fuzzForm: ref({ method: 'GET', url: 'http://192.168.136.132/§x§?y=§y§', headers: 'Host: 192.168.136.132', body: '' }),
    fuzzRawPacket: ref(''), fuzzAddressEdited: ref('url'), fuzzVariables: ref(['x', 'y']), fuzzPayloadGroups: ref(groups),
    isSinglePayloadMode: ref(['SNIPER', 'BATTERING_RAM'].includes(mode)), fuzzSharedPayload: ref(shared), fuzzCombination: ref(mode), fuzzEngine: ref('loop'),
    fuzzRunning: { get value() { return busy; }, set value(value) { busy = value; busyWrites.push(value); } },
    fuzzError: ref('previous recorded failure'), fuzzBatchResults: ref({ previous: { status: 'FAILED' } }), fuzzResult: ref({ status: 'FAILED' }), fuzzFocusPacketId: ref(327), selectedId: ref(327), trafficAlive: true,
    ensureFuzzGroups() { throw new Error('Submission must not initialize missing dictionaries'); }, getFuzzPayload() { throw new Error('Submission must not fall back to the shared dictionary'); }, splitFuzzPacket() {},
    chooseOperationTarget: async (...args) => { approvals.push(args); return 308; },
    api: { post: async (url, input) => { calls.push({ url, input: clone(input) }); return { data: { batchId: 'unit-only', status: 'COMPLETED', results: {} } }; } },
    ElMessage: { warning: value => warnings.push(value), success() {}, error(value) { throw new Error(value); } }, readableError: String, fuzzRequestCount: () => 0,
  };
  return { context, calls, approvals, warnings, busyWrites, run: productionFunction('runFuzz', context), estimate: () => productionEstimate(context) };
}
(async () => {
  await check('normalization trims blank lines and preserves duplicate, Unicode and literal HTML-like payloads', () => {
    const text = ' \t\r\n A \n A \n<qa-probe>中🙂</qa-probe>\n\u00a0\u3000\ufeff';
    assert.deepEqual(clone(normalizeFuzzDictionary(text)), ['A', 'A', '<qa-probe>中🙂</qa-probe>']);
    assert.deepEqual(clone(normalizeFuzzDictionary(undefined)), []);
  });
  await check('missing-key, empty-array and whitespace-array contracts name only missing variables', () => {
    for (const groups of [{ y: ['1'] }, { x: [], y: ['1'] }, { x: [' ', '\t', '\u00a0\u3000\ufeff'], y: ['1'] }]) {
      const before = JSON.stringify(groups); assert.equal(validateFuzzDictionaries(['x', 'y'], groups), message(['x'])); assert.equal(JSON.stringify(groups), before);
    }
    assert.equal(validateFuzzDictionaries(['x', 'y'], {}), message(['x', 'y']));
    assert.equal(validateFuzzDictionaries(['x', 'y'], { x: ['A', 'A'], y: ['1'] }), undefined);
    assert.equal(validateFuzzDictionaries(['constructor'], {}), message(['constructor']));
  });
  for (const mode of modes) {
    await check(`${mode}: missing, empty and whitespace groups stop before target choice, busy state or API`, async () => {
      for (const [groups, missing] of [[{ y: '1' }, ['x']], [{ x: '', y: '1' }, ['x']], [{ x: ' A ', y: '' }, ['y']], [{ x: ' \t\n\u00a0\u3000\ufeff', y: '1' }, ['x']], [{ x: '', y: '' }, ['x', 'y']]]) {
        const f = fixture(mode, groups), before = JSON.stringify(groups), previous = f.context.fuzzResult.value, batches = f.context.fuzzBatchResults.value;
        assert.equal(f.estimate(), 0); await f.run();
        assert.deepEqual(f.warnings, [message(missing)]); assert.equal(f.approvals.length, 0); assert.equal(f.calls.length, 0); assert.deepEqual(f.busyWrites, []);
        assert.equal(JSON.stringify(groups), before); assert.equal(f.context.fuzzResult.value, previous); assert.equal(f.context.fuzzBatchResults.value, batches); assert.equal(f.context.fuzzError.value, 'previous recorded failure');
      }
    });
    await check(`${mode}: valid groups retain order and duplicates while sending trimmed values`, async () => {
      const groups = { x: ' A \n\n A \n B ', y: ' 1 ' }, before = JSON.stringify(groups), f = fixture(mode, groups);
      assert.equal(f.estimate(), ['PITCHFORK', 'SHORTEST'].includes(mode) ? 1 : 3);
      await f.run(); assert.equal(f.approvals.length, 1); assert.equal(f.calls.length, 1); assert.deepEqual(f.warnings, []);
      assert.deepEqual(f.calls[0].input.request.multiPayloads, { x: ['A', 'A', 'B'], y: ['1'] }); assert.equal(f.calls[0].input.request.payloads, null); assert.equal(f.calls[0].input.request.combination, mode);
      assert.equal(JSON.stringify(groups), before);
    });
  }
  for (const mode of ['SNIPER', 'BATTERING_RAM']) {
    await check(`${mode}: single-dictionary behavior still uses shared payloads without requiring individual groups`, async () => {
      const f = fixture(mode, { x: '', y: '' }, ' A \n A \n B '); await f.run();
      assert.equal(f.calls.length, 1); assert.deepEqual(f.warnings, []); assert.deepEqual(f.calls[0].input.request.payloads, ['A', 'A', 'B']);
      assert.deepEqual(f.calls[0].input.request.multiPayloads, { x: ['A', 'A', 'B'], y: ['A', 'A', 'B'] });
      const empty = fixture(mode, {}, ' \t\n '); await empty.run(); assert.deepEqual(empty.warnings, ['至少需要一行模糊测试载荷']); assert.equal(empty.calls.length, 0); assert.equal(empty.approvals.length, 0);
    });
  }
  await check('multi-group row count uses the same normalized lines as submission', () => {
    assert.match(sfc.descriptor.template.content, /class="fuzz-set-count">\s*\{\{ normalizeFuzzDictionary\(getFuzzPayload\(name\)\)\.length \}\} 行/);
  });
  console.log(JSON.stringify({ status: 'PASS', count: checks.length, layer: 'isolated production-function contract tests; no desktop or network execution', checks }, null, 2));
})().catch(error => { console.error(error); process.exitCode = 1; });
