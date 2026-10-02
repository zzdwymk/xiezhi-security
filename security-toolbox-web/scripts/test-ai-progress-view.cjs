const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { parse, compileScript } = require('@vue/compiler-sfc');
const { createSSRApp } = require('vue');
const { renderToString } = require('@vue/server-renderer');
const root = path.resolve(__dirname, '..');
const cache = new Map();
function load(file) {
  file = path.resolve(file);
  if (cache.has(file)) return cache.get(file).exports;
  const module = { exports: {} }; cache.set(file, module);
  const source = fs.readFileSync(file, 'utf8');
  const compiled = file.endsWith('.vue')
    ? compileScript(parse(source, { filename: file }).descriptor, { id: 'progress-view-test', inlineTemplate: true, templateOptions: { ssr: true } }).content
    : source;
  const code = ts.transpileModule(compiled, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } }).outputText;
  const localRequire = name => {
    if (name.endsWith('.svg?url')) return { default: `data:image/svg+xml;base64,${fs.readFileSync(require.resolve(name.slice(0, -4))).toString('base64')}`, __esModule: true };
    return name.startsWith('.') ? load(path.resolve(path.dirname(file), /\.(ts|vue)$/.test(name) ? name : name + '.ts')) : require(name);
  };
  vm.runInNewContext(`(function(require,module,exports){${code}\n})`, { setInterval: () => 0, clearInterval() {}, Date, console }, { filename: file })(localRequire, module, module.exports);
  return module.exports;
}
const Panel = load(path.join(root, 'src/components/AiProgressPanel.vue')).default;
const now = Date.now();
const message = patch => ({ id: 'progress-test', role: 'assistant', content: '', status: 'running', taskIds: [], steps: [], createdAt: new Date(now - 5000).toISOString(), updatedAt: new Date(now - 2000).toISOString(), ...patch });
async function render(patch, tasks = []) { return renderToString(createSSRApp(Panel, { message: message(patch), tasks })); }
let passed = 0;
async function test(name, run) { await run(); passed++; console.log('PASS ' + name); }
module.exports = { render };
if (require.main === module) (async () => {
  await test('running state has a labelled indeterminate spinner without a guessed percentage', async () => {
    const html = await render({});
    assert.match(html, /role="progressbar" aria-labelledby="progress-test-progress-title"/);
    assert.match(html, /id="progress-test-progress-title"/);
    assert.ok(!html.includes('aria-valuenow'));
    const liveRegion = html.match(/<div[^>]*role="status"[^>]*>([\s\S]*?)<\/div>/)?.[1];
    assert.ok(liveRegion); assert.ok(!/已用|用时/.test(liveRegion));
  });
  await test('public detail stays collapsed while keyboard disclosure controls its real region', async () => {
    const html = await render({ status: 'completed', agentEvents: [{ type: 'route', summary: '已理解请求' }] });
    assert.match(html, /<button[^>]*type="button"[^>]*aria-expanded="false"[^>]*aria-controls="progress-test-progress-timeline"/);
    assert.match(html, /<div[^>]*id="progress-test-progress-timeline"[^>]*style="display:none;"/);
    assert.match(html, /aria-label="关键阶段"/);
    assert.ok(!html.includes('role="progressbar"'));
  });
  await test('approval waits show a textual warning without a running spinner', async () => {
    const html = await render({ status: 'completed', approvalStatus: 'REQUIRED' });
    assert.match(html, /等待确认执行计划/);
    assert.ok(!html.includes('role="progressbar"'));
  });
  await test('approved plan without dispatch confirmation stays actionable instead of claiming completion', async () => {
    const patch = { status: 'completed', modelStreamStatus: 'completed', approvalId: 77, approvalStatus: 'APPROVED', steps: [{ toolCode: 'nuclei_scan', title: 'nuclei' }] };
    const html = await render(patch);
    const outside = html.split(/<div[^>]*id="progress-test-progress-timeline"/)[0];
    assert.match(outside, /审批已通过，等待派发确认/);
    assert.match(outside, /恢复原计划执行/);
    assert.match(outside, /progress-attention/);
    assert.ok(!outside.includes('本轮处理完成'));
    assert.ok(!outside.includes('role="progressbar"'));
    const dispatched = await render({ ...patch, taskIds: [1] }, [{ id: 1, toolCode: 'nuclei_scan', status: 'RUNNING', createdAt: new Date(now - 4000).toISOString() }]);
    assert.match(dispatched, /1 个任务正在推进/);
    assert.ok(!dispatched.includes('恢复原计划执行'));
  });
  await test('stream completion preserves the independent running task display', async () => {
    const html = await render({ status: 'completed', taskIds: [1] }, [{ id: 1, toolCode: 'nmap_service_scan', status: 'RUNNING', createdAt: new Date(now - 4000).toISOString() }]);
    assert.match(html, /1 个任务正在推进/); assert.match(html, /执行中/);
    assert.match(html, /任务已结束 0\/1/); assert.ok(!html.includes('本轮处理完成'));
  });
  await test('failed milestone exposes its status to assistive technology', async () => {
    const html = await render({ status: 'failed', agentEvents: [{ type: 'tool_result', status: 'FAILED', summary: '工具已返回' }] });
    assert.match(html, /role="img" aria-label="失败"/);
  });
  await test('completed question keeps only its status line outside the collapsed process', async () => {
    const html = await render({ status:'completed', executionDecision:'PLAN_ONLY', agentEvents:[{type:'evidence',evidenceCount:3,summary:'测试依据'}] });
    const outside = html.split(/<div[^>]*id="progress-test-progress-timeline"/)[0];
    assert.match(outside,/本轮处理完成/); assert.ok(!/测试依据|条证据|已识别/.test(outside));
    assert.ok(!/progress-activity|progress-attention|progress-tool-stream/.test(outside));
  });
  await test('successful real task calls remain available after completion', async () => {
    const html = await render({status:'completed',taskIds:[1]},[{id:1,toolCode:'http_headers',status:'SUCCESS',createdAt:new Date(now-4000).toISOString()}]);
    const outside=html.split(/<div[^>]*id="progress-test-progress-timeline"/)[0];
    assert.match(outside,/<details(?=[^>]*\bprogress-tool-call\b)(?=[^>]*\bsuccess\b)/); assert.match(outside,/HTTP 安全响应头检查/); assert.match(outside,/成功/);
    const internal=await render({status:'completed',agentEvents:[{type:'step',stage:'mapping',status:'SUCCESS'}]});
    assert.ok(!internal.includes('progress-tool-stream'));
  });
  await test('failed tasks and approval next steps remain outside the collapsed process', async () => {
    const html=await render({status:'completed',taskIds:[1]},[{id:1,toolCode:'http_headers',status:'FAILED',errorMessage:'连接被拒绝',createdAt:new Date(now-4000).toISOString()}]);
    const outside=html.split(/<div[^>]*id="progress-test-progress-timeline"/)[0];
    assert.match(outside,/progress-attention/); assert.match(outside,/连接被拒绝/); assert.match(outside,/任务中心/);
    const approval=await render({status:'completed',approvalStatus:'REQUIRED'});
    assert.match(approval.split(/<div[^>]*id="progress-test-progress-timeline"/)[0],/确认后才会继续受控操作/);
  });
  await test('clarification never overrides a genuine model failure or approval gate', async () => {
    const failed=await render({status:'failed',executionDecision:'CLARIFY',content:'MODEL_TIMEOUT'});
    assert.match(failed,/本轮处理未完成/); assert.ok(!failed.includes('等待补充信息')); assert.match(failed,/progress-attention/);
    const approval=await render({status:'completed',executionDecision:'CLARIFY',approvalStatus:'REQUIRED'});
    assert.match(approval,/等待确认执行计划/); assert.ok(!approval.includes('等待补充信息'));
    const clarify=await render({status:'completed',executionDecision:'CLARIFY'});
    assert.match(clarify,/等待补充信息/); assert.match(clarify,/请补充回答中列出的信息/);
  });
  await test('empty stage history describes terminal rounds without implying more feedback is pending', async () => {
    for (const status of ['completed', 'failed']) {
      const html=await render({status,agentEvents:[]});
      assert.match(html,/<p class="progress-empty"[^>]*>本轮未保存阶段记录。<\/p>/);
      assert.ok(!html.includes('等待首条阶段反馈'));
    }
    const running=await render({status:'running',agentEvents:[]});
    assert.match(running,/<p class="progress-empty"[^>]*>等待首条阶段反馈。<\/p>/);
    const pendingTask=await render({status:'completed',taskIds:[1],agentEvents:[]},[{id:1,toolCode:'http_headers',status:'RUNNING',createdAt:new Date(now-4000).toISOString()}]);
    assert.match(pendingTask,/<p class="progress-empty"[^>]*>等待首条阶段反馈。<\/p>/);
  });
  await test('verified replay is labelled as received history instead of stage duration', async () => {
    const html = await render({ status: 'completed', agentEvents: [{ type: 'plan', stage: 'GENERATING', eventTiming: 'VERIFIED_RECORD', createdAt: new Date(now - 2000).toISOString() }] });
    assert.match(html, /补发记录/); assert.match(html, /收到于/);
    assert.match(html, /流程记录数量不等于模型调用或实际检测次数/);
    assert.ok(!html.includes('完整公开阶段记录'));
  });
  await test('restored disconnected requests never spin or claim completion', async () => {
    const html = await render({ modelStreamStatus: 'interrupted', executionDecision: 'CLARIFY' });
    assert.match(html, /连接已结束，结果待确认/);
    assert.ok(!html.includes('role="progressbar"'));
    assert.ok(!html.includes('progress-elapsed'));
    assert.ok(!html.includes('等待补充信息'));
  });
  console.log(`${passed} AI progress view checks passed.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
