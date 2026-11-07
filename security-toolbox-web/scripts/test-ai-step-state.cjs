const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');

const cache = new Map();
function load(file) {
  file = path.resolve(file);
  if (cache.has(file)) return cache.get(file).exports;
  const module = { exports: {} };
  cache.set(file, module);
  const code = ts.transpileModule(fs.readFileSync(file, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText;
  const requireLocal = name =>
    name.startsWith('.') ? load(path.resolve(path.dirname(file), name + '.ts')) : require(name);
  vm.runInThisContext(`(function(require,module,exports){${code}\n})`, { filename: file })(
    requireLocal,
    module,
    module.exports,
  );
  return module.exports;
}

const { mergePlanSteps, planStepKey, findMatchingAiStep, mergeAiStep } = load(
  path.join(__dirname, '../src/utils/aiStepState.ts'),
);

let passed = 0;
function test(name, run) {
  run();
  passed++;
  console.log('PASS ' + name);
}

const step = patch => ({
  toolCode: 'tcp_ports',
  title: '授权端口探测',
  parameters: { ports: '1-65535' },
  status: 'pending',
  progress: 0,
  ...patch,
});

test('re-delivering the same plan does not duplicate its steps', () => {
  const first = [step({ actionId: 'a'.repeat(32) })];
  const again = mergePlanSteps(first, [step({ actionId: 'a'.repeat(32) })]);
  assert.equal(again.length, 1);
});

test('a retry turn that re-plans every step keeps one row per step', () => {
  const plan = [
    step({ actionId: 'a'.repeat(32), status: 'failed' }),
    step({ actionId: 'b'.repeat(32), toolCode: 'nmap_service_scan', title: 'Nmap 服务识别' }),
    step({ actionId: 'c'.repeat(32), toolCode: 'sqlmap_scan', title: 'sqlmap SQL 注入检测' }),
  ];
  const retried = mergePlanSteps(plan, plan.map(item => ({ ...item, status: 'pending' })));
  assert.equal(retried.length, 3);
});

test('a terminal step keeps its status when the same attempt is re-delivered', () => {
  const done = [step({ actionId: 'a'.repeat(32), status: 'failed', attempt: 1 })];
  const again = mergePlanSteps(done, [step({ actionId: 'a'.repeat(32), status: 'pending', attempt: 1 })]);
  assert.equal(again[0].status, 'failed');
});

test('a higher attempt supersedes the previous terminal status', () => {
  const done = [step({ actionId: 'a'.repeat(32), status: 'failed', attempt: 1 })];
  const retried = mergePlanSteps(done, [step({ actionId: 'a'.repeat(32), status: 'pending', attempt: 2 })]);
  assert.equal(retried[0].status, 'pending');
  assert.equal(retried[0].attempt, 2);
});

test('steps without actionId still merge by tool and parameters', () => {
  const first = [step({})];
  const again = mergePlanSteps(first, [step({})]);
  assert.equal(again.length, 1);
  assert.equal(planStepKey(first[0]), planStepKey(step({})));
});

test('a genuinely different step is still appended', () => {
  const first = [step({})];
  const again = mergePlanSteps(first, [step({ parameters: { ports: '80,443' } })]);
  assert.equal(again.length, 2);
});

test('findMatchingAiStep prefers the stable actionId', () => {
  const steps = [step({ actionId: 'a'.repeat(32), taskId: 7 })];
  const match = findMatchingAiStep(steps, { actionId: 'a'.repeat(32), taskId: 99 });
  assert.equal(match, steps[0]);
});

test('existing terminal status survives a lower-attempt event', () => {
  const current = step({ status: 'success', attempt: 2 });
  const merged = mergeAiStep(current, step({ status: 'running', attempt: 0 }));
  assert.equal(merged.status, 'success');
});

test('an approval payload without actionId or parameters merges into existing step', () => {
  const first = [step({ actionId: 'a'.repeat(32), toolCode: 'sqlmap_scan', title: 'sqlmap SQL 注入检测', parameters: { path: '/less-1/?id=1' } })];
  // Approval payload from runtime approval_required event
  const approvalStep = step({ toolCode: 'sqlmap_scan', parameters: {} });
  const again = mergePlanSteps(first, [approvalStep]);
  assert.equal(again.length, 1);
  assert.equal(again[0].actionId, 'a'.repeat(32));
  assert.deepEqual(again[0].parameters, { path: '/less-1/?id=1' });
});

console.log(`\n${passed} ai step state checks passed`);
