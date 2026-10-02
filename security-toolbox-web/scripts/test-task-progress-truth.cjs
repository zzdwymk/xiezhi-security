const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const ts = require('typescript');
const source = fs.readFileSync(path.join(__dirname, '../src/utils/taskProgress.ts'), 'utf8');
const exported = {};
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText, { exports: exported });
const native = { status: 'RUNNING', progress: 57, progressDeterminate: true, progressCompleted: 40, progressTotal: 100 };
assert.equal(exported.taskProgressPercentage(native), 40);
assert.equal(exported.taskProgressText(native), '工具进度 40% · 40/100');
assert.equal(exported.taskProgressIndeterminate(native), false);
for (const values of [{}, { progressCompleted: null, progressTotal: 100 }, { progressCompleted: 101, progressTotal: 100 }, { progressCompleted: 1, progressTotal: 0 }]) {
  const unknown = { status: 'RUNNING', progress: 88, progressDeterminate: true, ...values };
  assert.equal(exported.taskProgressPercentage(unknown), 0);
  assert.equal(exported.taskProgressIndeterminate(unknown), true);
  assert.equal(exported.taskProgressText(unknown), '执行中');
}
assert.equal(exported.taskProgressText({ ...native, status: 'TIMEOUT' }), '已超时');
assert.equal(exported.taskProgressPercentage({ ...native, status: 'SUCCESS' }), 100);
console.log('PASS: native counters, unknown counters, invalid totals, and terminal states');
