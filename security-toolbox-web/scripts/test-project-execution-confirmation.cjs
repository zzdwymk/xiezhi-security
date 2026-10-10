const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');

// Exercise the actual project handlers with a persisted-plan API double.
const source = fs.readFileSync(path.resolve(__dirname, '../src/views/ProjectDetail.vue'), 'utf8');
const handlers = source.slice(source.indexOf('async function reviewApproval('), source.indexOf('async function downloadProjectSummaryPdf('));
const js = ts.transpileModule(handlers, { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText;
function fixture() {
  const calls = [];
  const saved = { targetId: 9, status: 'PENDING', plan: { summary: 'saved', steps: [] }, dispatch: null };
  const row = { id: 42, action: 'AI_PLAN_EXECUTION', status: 'PENDING' };
  const context = {
    id: 3, approvalDecision: {}, planReview: {}, planReviewApproval: {}, planReviewVisible: { value: false },
    canManageSecurityActions: { value: true }, errorMessage: (_, fallback) => fallback,
    ElMessage: { success: text => calls.push(['success', text]), error: text => calls.push(['error', text]) },
    refreshProjectData: async () => calls.push(['refresh']),
    endpoints: {
      projectAiApprovalPlan: async (...args) => { calls.push(['detail', ...args]); return { data: { ...saved } }; },
      decideProjectApproval: async (projectId, approvalId, payload) => {
        calls.push(['decision', projectId, approvalId, payload.status]);
        saved.status = payload.status;
        return { data: { ...row, status: payload.status } };
      },
      resumeProjectAiApproval: async (...args) => { calls.push(['execute', ...args]); return { data: { taskIds: [71] } }; },
    },
  };
  vm.createContext(context); vm.runInContext(js, context);
  return { context, calls, row, saved };
}
(async () => {
  {
    const { context: c, calls, row } = fixture();
    await c.confirmPlanExecution('APPROVED');
    assert.deepEqual(calls, [], 'cannot execute before viewing a saved plan');
    await c.reviewApproval(row);
    assert.equal(c.planReviewVisible.value, true);
    await c.confirmPlanExecution('APPROVED');
    assert.deepEqual(calls.slice(0, 3), [['detail', 3, 42], ['decision', 3, 42, 'APPROVED'], ['execute', 3, 42]]);
    assert.equal(c.planReviewVisible.value, false);
  }
  {
    const { context: c, calls, row } = fixture();
    await c.reviewApproval(row); await c.confirmPlanExecution('REJECTED');
    assert.equal(row.status, 'REJECTED');
    assert.equal(calls.some(call => call[0] === 'execute'), false);
  }
  {
    const { context: c, calls, row } = fixture();
    await c.reviewApproval(row);
    const resume = c.endpoints.resumeProjectAiApproval;
    c.endpoints.resumeProjectAiApproval = async () => { throw new Error('connection lost'); };
    await c.confirmPlanExecution('APPROVED');
    assert.equal(c.planReviewVisible.value, true);
    assert.equal(row.status, 'APPROVED');
    assert.equal(c.approvalDecision.value, undefined);
    c.endpoints.resumeProjectAiApproval = resume;
    await c.confirmPlanExecution('APPROVED');
    assert.equal(calls.filter(call => call[0] === 'decision').length, 1, 'retry must reuse confirmation');
    assert.deepEqual(calls.find(call => call[0] === 'execute'), ['execute', 3, 42]);
  }
  {
    const { context: c, calls, row } = fixture();
    c.canManageSecurityActions.value = false;
    await c.reviewApproval(row); await c.confirmPlanExecution('APPROVED');
    assert.equal(calls.length, 1, 'non-admin can review but cannot confirm');
  }
  assert.equal(source.includes('申请高风险行动'), false);
  assert.equal(source.includes('openApprovalDialog'), false);
  assert.equal(source.includes('label="安全行动" name="security-actions"'), false);
  console.log('PASS project execution confirmation: saved plan, rejection, same-ID execution, retry, admin boundary, merged navigation');
})().catch(error => { console.error(error); process.exitCode = 1; });
