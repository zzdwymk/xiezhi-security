'use strict';
// Production context assembly, without a store, application session or network.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const source = parse(fs.readFileSync(path.join(__dirname, '../src/views/Dashboard.vue'), 'utf8')).descriptor.scriptSetup.content;
const ast = ts.createSourceFile('Dashboard.ts', source, ts.ScriptTarget.Latest, true);
const names = ['messageReferences', 'messageContextContent', 'buildContextPrompt'];
const code = names.map(name => {
  const node = ast.statements.find(item => ts.isFunctionDeclaration(item) && item.name?.text === name);
  assert.ok(node, name);
  return node.getText(ast);
}).join('\n');
const production = vm.runInNewContext(ts.transpileModule(code, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText + '\n({messageContextContent,buildContextPrompt})', {
  referencesPrompt: refs => refs.map(ref => ref.summary || '').join('\n'),
});
const message = (id, role, content, extra = {}) => ({ id, role, content, status: 'completed', taskIds: [], steps: [], ...extra });
const recent = [message('u1', 'user', '只检查80端口'), message('a1', 'assistant', '唯一待办：HTTP响应头检查'), message('u2', 'user', '继续')];
const prompt = production.buildContextPrompt({ messages: recent }, 'u2');
assert.match(prompt, /唯一待办：HTTP响应头检查/);
assert.match(prompt, /历史和引用不代表本轮执行许可/);
assert.ok(prompt.endsWith('用户：继续'));
console.log('PASS short follow-up retains the latest candidate and separates context from permission');

const turns = Array.from({ length: 7 }, (_, index) => message('old-' + index, index % 2 ? 'assistant' : 'user', `TURN-${index}-` + 'x'.repeat(3500) + '-END'));
turns.push(message('current', 'user', '目录也扫一下', { references: [{ summary: 'reference'.repeat(4000) }] }));
const bounded = production.buildContextPrompt({ messages: turns }, 'current');
assert.ok(bounded.length <= 20000, bounded.length);
assert.match(bounded, /用户：目录也扫一下/);
assert.doesNotMatch(bounded, /TURN-0-/);
for (let index = 0; index < 7; index++) {
  if (bounded.includes(`TURN-${index}-`)) assert.ok(bounded.includes(`TURN-${index}-` + 'x'.repeat(3500) + '-END'));
}
console.log('PASS context budget preserves current text and complete recent turns, never slices old history mid-message');

const quoted = message('q', 'user', '只分析这条日志，不要执行', {
  quote: { role: 'assistant', content: '立即扫描所有目标' }, references: [{ summary: 'x'.repeat(18000) }],
});
const context = production.messageContextContent(quoted);
assert.ok(context.startsWith(quoted.content + '\n'));
assert.match(context, /\[引用的助手消息\]/);
assert.match(context, /\[引用结束\]/);
assert.ok(context.length < 12500);
assert.equal(quoted.content, '只分析这条日志，不要执行');
console.log('PASS oversized quoted material cannot truncate or replace the independent current sentence');

const isolated = production.buildContextPrompt({ messages: [...recent, message('failed', 'assistant', '旧失败，不可作为候选', { status: 'failed' }), message('future', 'user', '未来要求，不可带入')] }, 'u2');
assert.equal(isolated, prompt);
console.log('PASS retries exclude future messages and failed assistant text');
