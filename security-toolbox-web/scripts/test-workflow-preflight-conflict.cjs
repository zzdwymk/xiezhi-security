'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),ts=require('typescript');
const root=path.resolve(__dirname,'..'),compile=source=>ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.CommonJS}}).outputText;
const helperModule={exports:{}};
vm.runInNewContext(compile(fs.readFileSync(path.join(root,'src/utils/errorMessage.ts'),'utf8')),{module:helperModule,exports:helperModule.exports});
const source=fs.readFileSync(path.join(root,'src/views/Workflow.vue'),'utf8');
const start=source.indexOf('async function executeWorkflow()'),end=source.indexOf('\nasync function stopExecution()',start);
assert(start>=0&&end>start);
const message='请求跳过的节点不在当前预检的不可用列表中，已拒绝创建工作流；请重新预检并确认后重试';
const failure={response:{status:409,data:{code:'WORKFLOW_PREFLIGHT_CHANGED',message,retryable:true,requiresPreflight:true}}};
const ref=value=>({value}),saved={workflowId:'workflow-1',revision:3,specDigest:'sha256:'+'a'.repeat(64),steps:[{nodeId:'headers',tool:'http_headers'},{nodeId:'tls',tool:'tls_config'},{nodeId:'scan',tool:'fscan_scan',requiresApproval:true}]};
let preflightCalls=0,startCalls=0,confirmCalls=0,cancelAt=Infinity;
const starts=[],errors=[],state={
  selectedProjectId:ref(140),selectedTargetId:ref(307),graphValidation:ref([]),
  serializeGraph:()=>saved,validateExecutionInputs:()=>'',runPollGeneration:0,
  suggestionNodeLabels:ref({headers:'响应头'}),loadFromSpec:()=>{},
  notifyWorkflowSkipped:async()=>{},actionStepLabel:tool=>tool,actionRiskLabel:risk=>risk,
  toErrorMessage:helperModule.exports.toErrorMessage,
  ElMessage:{warning:message=>errors.push(message),error:message=>errors.push(message)},
  ElMessageBox:{confirm:async()=>++confirmCalls===cancelAt?false:'confirm'},
  applyWorkflowRunDetail:()=>{},upsertWorkflowRun:()=>{},pollWorkflowRun:async()=>{},
  endpoints:{
    saveWorkflowSpec:async()=>({data:saved}),
    preflightWorkflowRun:async()=>{preflightCalls++;return {data:{issues:(preflightCalls===1?['headers','tls']:['tls']).map(nodeId=>({nodeId,label:nodeId,reason:'暂不可用'})),resolvedTargets:preflightCalls===1?{}:{headers:['http://192.168.136.132/']}}};},
    startWorkflowRun:async request=>{startCalls++;starts.push(JSON.parse(JSON.stringify(request)));if(startCalls===1)throw failure;return {data:{run:{id:99}}};},
  },
};
for(const name of ['executing','activeRunId','executeProgress','executeIndeterminate','executeStatus','executeLogs','executeTaskIds','nodeRuns','saving','viewingRunSnapshot','selectedRunId'])state[name]=ref();
vm.createContext(state);vm.runInContext(compile(source.slice(start,end)),state);
(async()=>{
  await state.executeWorkflow();
  assert.equal(preflightCalls,1);assert.equal(startCalls,1,'Conflict must not trigger an automatic retry');
  assert.deepEqual(starts[0].skippedNodeIds,['headers','tls']);
  assert.equal(errors.at(-1),message,'409 must expose the actionable server message');
  assert(state.executeLogs.value.some(line=>line.includes(message)));
  assert.equal(state.executing.value,false,'Execution button must be usable after failed creation');
  assert.equal(state.activeRunId.value,undefined);
  cancelAt=confirmCalls+2; // A second manual click refreshes preflight, then the user cancels target review.
  await state.executeWorkflow();
  assert.equal(preflightCalls,2);assert.equal(startCalls,1,'Cancel must not reuse the old approvals or skip set');
  cancelAt=Infinity;
  await state.executeWorkflow();
  assert.equal(preflightCalls,3);assert.equal(startCalls,2);
  assert.deepEqual(starts[1].skippedNodeIds,['tls']);
  assert.deepEqual(starts[1].approvedNodeIds,['scan']);
  assert.equal(state.activeRunId.value,99);
  const projectSource=fs.readFileSync(path.join(root,'src/views/ProjectDetail.vue'),'utf8');
  assert.match(projectSource,/function errorMessage\(error: unknown, fallback: string\)\s*\{\s*return toErrorMessage\(error, fallback\);/);
  assert.equal(helperModule.exports.toErrorMessage(failure,'联动工作流失败'),message);
  console.log('PASS: actual workflow function preserves the 409 reason, requires manual preflight/reconfirmation, honors cancellation, and submits only the newly reviewed skip set');
})().catch(error=>{console.error(error);process.exitCode=1;});
