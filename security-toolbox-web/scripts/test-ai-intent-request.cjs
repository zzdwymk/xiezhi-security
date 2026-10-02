const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const root = path.resolve(__dirname, '..');
function createClient({ fetch, post }) {
  const cache = new Map();
  function load(file) {
    if (cache.has(file)) return cache.get(file).exports;
    const module = { exports: {} }; cache.set(file, module);
    const code = ts.transpileModule(fs.readFileSync(file, 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } }).outputText;
    const localRequire = name => {
      if (name === './apiClient') return { api: { post }, apiUrl: value => value };
      if (name === './authToken') return { readAuthToken: () => '' };
      if (name === './utils/taskbarProgress') return { taskbarProgress: new Proxy({}, { get: () => () => undefined }) };
      return name.startsWith('.') ? load(path.resolve(path.dirname(file), name + '.ts')) : require(name);
    };
    vm.runInNewContext(`(function(require,module,exports){${code}\n})`, { fetch, AbortController, TextDecoder, setTimeout, clearTimeout, console }, { filename: file })(localRequire, module, module.exports);
    return module.exports;
  }
  return load(path.join(root, 'src/api.ts'));
}
const payload = { projectId: 7, targetId: 9, prompt: '历史：请立即扫描。当前用户：先给方案，不执行。', userPrompt: '先给方案，不执行', executionIntent: 'AUTO' };
let passed = 0;
async function test(name, run) { await run(); passed++; console.log('PASS ' + name); }
module.exports = { createClient };
if (require.main === module) (async () => {
  await test('stream request preserves AUTO and current utterance separately from history', async () => {
    const calls = [];
    const client = createClient({ fetch: async (url, request) => {
      calls.push({ url, body: JSON.parse(request.body) });
      return new Response(JSON.stringify({ targetId: 9, message: '方案', taskIds: [] }), { headers: { 'content-type': 'application/json' } });
    }, post: async () => { throw new Error('Unexpected fallback'); } });
    await client.dispatchAiStreaming(payload, () => {});
    assert.equal(calls[0].url, '/ai/agent/stream');
    assert.deepEqual(calls[0].body, payload);
    assert.equal(Object.hasOwn(calls[0].body, 'execute'), false);
  });
  await test('non-streaming agent fallback retains the complete AUTO request', async () => {
    const calls = [];
    const client = createClient({ fetch: async () => new Response('', { status: 404 }), post: async (url, body) => {
      calls.push({ url, body }); return { data: { targetId: 9, message: '方案', taskIds: [] } };
    } });
    await client.dispatchAiStreaming(payload, () => {});
    assert.equal(calls.length, 1); assert.equal(calls[0].url, '/ai/agent'); assert.equal(calls[0].body, payload);
  });
  await test('unavailable agent cannot downgrade AUTO into direct task dispatch', async () => {
    const calls = [];
    const client = createClient({ fetch: async () => new Response('', { status: 404 }), post: async url => {
      calls.push(url); throw { response: { status: 404 } };
    } });
    await assert.rejects(client.dispatchAiStreaming(payload, () => {}), /不支持.*执行意图/);
    assert.deepEqual(calls, ['/ai/agent']);
  });
  await test('unassociated AUTO target fails closed before contacting a legacy endpoint', async () => {
    let calls = 0;
    const client = createClient({ fetch: async () => { calls++; throw new Error('Unexpected fetch'); }, post: async () => { calls++; throw new Error('Unexpected dispatch'); } });
    await assert.rejects(client.dispatchAiStreaming({ ...payload, projectId: undefined }, () => {}), /关联评估项目/);
    assert.equal(calls, 0);
  });
  await test('trusted route decisions are normalized to the declared display enum', async () => {
    const client = createClient({});
    for (const executionDecision of ['EXECUTE', 'PLAN_ONLY', 'CLARIFY'])
      assert.equal(client.normalizeAgentEvent({ type: 'route', executionDecision }).executionDecision, executionDecision);
    assert.equal(client.normalizeAgentEvent({ type: 'route', executionDecision: 'ignored' }).executionDecision, undefined);
  });
  await test('real done data.response retains the approval ticket and exact plan parameters', async () => {
    const response={targetId:9,approvalId:40,approvalStatus:'REQUIRED',message:'等待审批',taskIds:[],plan:{provider:'langgraph-runtime',model:'test',summary:'单项扫描',requiresConfirmation:true,steps:[{toolCode:'zap_scan',title:'ZAP',parameters:{spider:false,strength:'LOW'},risk:'CAUTION',requiresApproval:true}]}};
    const events=[];
    const client=createClient({fetch:async()=>new Response(`event: done\ndata: ${JSON.stringify({type:'done',status:'COMPLETED',data:{response}})}\n\n`,{headers:{'content-type':'text/event-stream'}})});
    const result=await client.dispatchAiStreaming(payload,e=>events.push(e));
    assert.equal(result.approvalId,40);assert.equal(result.approvalStatus,'REQUIRED');
    assert.deepEqual(JSON.parse(JSON.stringify(result.plan.steps[0].parameters)),{spider:false,strength:'LOW'});
    const done=events.find(e=>e.type==='done');assert.equal(done.approvalId,40);assert.equal(done.approvalStatus,'REQUIRED');
    assert.equal(client.normalizeAgentEvent(done).approvalId,40);
  });
  await test('non-streaming fallback retains pending approvals without fabricating tasks', async () => {
    const client=createClient({fetch:async()=>new Response('',{status:404}),post:async()=>({data:{targetId:9,message:'等待审批',approvalId:41,approvalStatus:'PENDING',taskIds:[],plan:{provider:'test',model:'test',summary:'审批',steps:[{toolCode:'nuclei_scan',parameters:{},requiresApproval:true}]}}})});
    const result=await client.dispatchAiStreaming(payload,()=>{});
    assert.equal(result.approvalId,41);assert.equal(result.approvalStatus,'PENDING');assert.equal(result.taskIds.length,0);
  });
  console.log(`${passed} AI intent request checks passed.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
