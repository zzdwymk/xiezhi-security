const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');

const source = path.join(__dirname, '../src/utils/auditFormat.ts');
const moduleOutput = { exports: {} };
const code = ts.transpileModule(fs.readFileSync(source, 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText;
vm.runInThisContext(`(function(module,exports){${code}\n})`, { filename: source })(moduleOutput, moduleOutput.exports);

const { formatAuditDetail, formatAuditResult, formatAuditAction, formatAuditResource } = moduleOutput.exports;

console.log('Testing formatAuditDetail comprehensive suite...');

// 1. User screenshot JSON (AI_AGENT_TURN with CLARIFY)
const sampleClarifyJson = JSON.stringify({
  schemaVersion: 3,
  sessionId: "99fc2ae4-0aa1-490a-8ced-b7489b30076c",
  turnId: "2a2d8028-1079-48d9-86b7-c964019385b9",
  projectId: 385,
  targetId: 577,
  executed: false,
  taskIds: [],
  fallback: false,
  fallbackReason: "无",
  retrievalRoundCount: 0,
  evidenceIds: [],
  indexRevision: "",
  plannerSource: "langchain-grounded",
  executionIntent: "AUTO",
  executionDecision: "CLARIFY",
  terminationReason: "",
  runtimerRunId: "1b746fbe-c036-40d6-bc67-50490337a3bb",
  workflowDigest: "sha256:7f8bf0d612f327d67806d440298df71b18b7369c3c94c1127ca8c53105ad466e",
  outerNodeId: "ledger-agent",
  nodeRunId: "node-0e5c512d1d535f5292ae4e5b91a57b0e94b6af56b243707b8c4b022716a43606",
  ledgerSequence: 10,
  ledgerEntryDigest: "sha256:7ac7caa5423ee87045aa3d48982ac5a04d77d3095cd46b45acf1ef8c393b2268"
});

const formatted1 = formatAuditDetail(sampleClarifyJson);
console.log('Case 1 (Clarify):', formatted1);
assert.equal(formatted1, 'AI 决策：需向用户澄清（项目 #385，目标 #577，未派发新任务，账本序列 #10）');

// 2. AI_AGENT_TURN with EXECUTE and tasks
const sampleExecuteJson = JSON.stringify({
  schemaVersion: 3,
  sessionId: "session-123",
  turnId: "turn-456",
  projectId: 385,
  targetId: 577,
  executed: true,
  taskIds: [101, 102],
  executionDecision: "EXECUTE",
  ledgerSequence: 11
});
const formatted2 = formatAuditDetail(sampleExecuteJson);
console.log('Case 2 (Execute):', formatted2);
assert.equal(formatted2, 'AI 决策：执行安全方案（项目 #385，目标 #577，派发任务 2 项（#101、#102），账本序列 #11）');

// 3. AI_AGENT_TURN with error
const sampleErrorJson = JSON.stringify({
  schemaVersion: 3,
  projectId: 385,
  error: "模型响应超时"
});
const formatted3 = formatAuditDetail(sampleErrorJson);
console.log('Case 3 (Error):', formatted3);
assert.equal(formatted3, 'AI 交互异常：模型响应超时（项目 #385）');

// 4. AI_CONVERSATION_DELETE
const sampleDeleteSession = JSON.stringify({
  sessionId: "99fc2ae4-0aa1-490a-8ced-b7489b30076c",
  cleared: true,
  projectId: 385,
  targetId: 577
});
const formatted4 = formatAuditDetail(sampleDeleteSession);
console.log('Case 4 (Delete Conversation):', formatted4);
assert.equal(formatted4, '已清理 AI 对话记忆（项目 #385，目标 #577，会话 #99fc2ae4）');

// 5. BusinessDataReset
const sampleResetJson = JSON.stringify({
  deletedProjects: 2,
  deletedRecords: 50,
  runtimeDocumentsDeleted: 10,
  deletedByCategory: { 任务: 30, 漏洞: 20 },
  preservedData: ['管理员账户']
});
const formatted5 = formatAuditDetail(sampleResetJson);
console.log('Case 5 (Reset Data):', formatted5);
assert.ok(formatted5.includes('已清空全部业务数据'));
assert.ok(formatted5.includes('评估项目 2 个'));

// 6. Existing text format backward compatibility
const textSample1 = 'status=SUCCESS, hits=3';
const formatted6 = formatAuditDetail(textSample1);
console.log('Case 6 (Text hits):', formatted6);
assert.equal(formatted6, '成功，检出 3 个漏洞');

const textSample2 = 'approvalId=754';
const formatted7 = formatAuditDetail(textSample2);
console.log('Case 7 (Text approval):', formatted7);
assert.equal(formatted7, '审批单#754');

// 7. Generic JSON object
const genericJson = JSON.stringify({
  projectId: 12,
  status: "SUCCESS",
  count: 5
});
const formatted8 = formatAuditDetail(genericJson);
console.log('Case 8 (Generic JSON):', formatted8);
assert.equal(formatted8, '项目：12；状态：成功；数量：5');

// 8. Result meta
assert.equal(formatAuditResult('DENIED'), '已拦截');
assert.equal(formatAuditResult('SUCCESS'), '成功');

// 9. Newly added actions & resources
assert.equal(formatAuditAction('BATCH_CREATE_TASK'), '批量创建任务');
assert.equal(formatAuditAction('REQUEUE_WORKFLOW_TASK'), '重新排队工作流任务');
assert.equal(formatAuditAction('AGENT_CAPABILITY_APPROVAL_REQUESTED'), '申请受控能力审批');
assert.equal(formatAuditAction('AGENT_CAPABILITY_DENIED'), '受控能力拦截');
assert.equal(formatAuditResource('AGENT_CAPABILITY'), '受控安全能力');

// 10. Scan diff & batch task text formatting
assert.equal(formatAuditDetail('tool=nmap_service_scan; targets=3'), '工具：Nmap 服务识别; 目标数：3');
assert.equal(formatAuditDetail('baselineTaskId=1; added=2; resolved=1'), '基线任务#1; 新增 2 项漏洞; 已修复 1 项漏洞');
assert.equal(formatAuditDetail('retestTaskId=5; reoccurred=false; passes=2'), '复测任务#5; 漏洞复现：否; 通过次数：2');
assert.equal(formatAuditDetail('mode=AUTO; model unavailable'), '模式：自动; 模型服务不可用');
assert.equal(formatAuditDetail('BLACKLIST:SUFFIX:.jpg'), '黑名单:后缀匹配:.jpg');

console.log('ALL COMPREHENSIVE TESTS PASSED!');
