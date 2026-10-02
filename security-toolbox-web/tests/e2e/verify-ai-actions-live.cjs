/**
 * Ask the actual packaged product assistant to operate application modules.
 * Attach to the manually authenticated EXE on localhost CDP 19229.
 *
 * node tests/e2e/verify-ai-actions-live.cjs
 * node tests/e2e/verify-ai-actions-live.cjs --only=task_837,report,project_create
 * node tests/e2e/verify-ai-actions-live.cjs --only=fscan_scan
 * node tests/e2e/verify-ai-actions-live.cjs --only=nuclei_scan --reject-reviewed
 * node tests/e2e/verify-ai-actions-live.cjs --only=nuclei_scan --approve-reviewed
 * node tests/e2e/verify-ai-actions-live.cjs --list
 *
 * Scanner cases are NEVER in the default selection. All prompts use execution
 * mode, but only real task IDs / UI state can establish an executed operation.
 * Unsupported modules are still directly requested, not merely discussed.
 * UI navigation after an answer is operator verification, never AI execution.
 * No direct business API calls, storage/credential access, whole-library sync,
 * authorization edits, notifications, deletion, historical-task cancellation,
 * browser launch/restart/login or browser.close(). Created records are retained.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { chromium } = require('playwright-core');
const { navigate, selectOn, sleep } = require('./lib/ui.cjs');

const STAMP = new Date().toISOString().replace(/[:.]/g, '-');
const OUT = path.resolve(__dirname, '../../../.run/ai-actions-ui-test', STAMP);
const PROJECT_ID = 131;
const TARGET_ID = 293;
const HOST = '192.168.136.132';
const TEST_PROJECT = `AI模块操作验收-${STAMP}`;
const TEST_WORKFLOW = `AI操作验证-${STAMP}`;
const results = [];
let page, projectName, target;
const scope = `当前评估项目ID ${PROJECT_ID}、已登记授权目标ID ${TARGET_ID}（${HOST}）。`;
const limits = '遵守现有授权和工具白名单；不得更改凭据、权限、授权记录或有效期，不得发送通知、删除数据或取消历史任务。缺少权限、执行工具、已登记参数或依赖时如实说明未执行，不得虚构成功、任务ID或操作结果。';
const scanLimits = '本轮仅执行所指定的一项工具、参数与目标范围，使用本地已有依赖和已核实的低影响配置。需要审批时创建本轮审批单并等待核对。配置、授权或依赖不足时明确列出具体缺项，保持未执行；任务完成后报告真实任务编号和结果。';

const cases = {
  task_837: { title: '查询任务837', taskId: 837 },
  task_838: { title: '查询任务838', taskId: 838 },
  task_839: { title: '查询任务839', taskId: 839 },
  risks: { title: '查询现有风险', kind: 'query', prompt: '查询本项目现有风险和漏洞，按风险等级整理数量、真实记录ID、证据和修复优先级。不要创建新扫描或把建议当成已确认漏洞。', verify: 'findings' },
  report: { title: '生成并导出项目报告', prompt: '请生成当前项目的项目总结报告，并导出PDF文件供下载。报告应汇总实际目标、任务、风险、复测和审计记录。', verify: 'report' },
  topology: { title: '查看资产拓扑', prompt: '请打开并查看当前项目的资产拓扑，指出现有目标、服务及关联关系。', route: /\/assets\/topology/, verify: 'topology' },
  project_create: { title: '创建独立测试项目', prompt: `请在评估项目中创建独立草稿项目“${TEST_PROJECT}”，负责人填“AI操作验收”，说明填“聊天助手模块操作测试”。不要添加或扩大扫描授权，不要激活项目，不要删除或修改原项目；若创建必需的授权字段尚缺失，请如实说明缺失信息，不得编造授权。`, verify: 'project' },
  targets: { title: '核对已有授权目标', kind: 'query', prompt: '请查询并核对当前项目已经登记的全部授权目标，列出真实目标ID、地址、端口范围和授权有效状态；重点核对目标293。不要新增、编辑、删除或更改任何授权。', verify: 'targets' },
  workflow_save: { title: '保存工作流', prompt: `请把当前项目已有工作流保存为可复核的新版本，备注“${TEST_WORKFLOW}”。保留已有节点、参数、连线和授权范围，不执行检测。`, verify: 'workflow' },
  dns: { title: '执行DNS信息收集', prompt: '请在当前项目的信息收集功能中对目标293执行一次DNS信息收集并保存结果。若当前已登记目标类型不适用，请说明，不得改用其他地址或扩展目标。', verify: 'recon' },
  fingerprint: { title: '执行网站指纹探测', prompt: '请使用项目详情中的探测服务功能，对目标293执行一次已有低影响网站指纹识别，保存真实识别证据。不要改用端口扫描或漏洞检测来代替此功能。', verify: 'fingerprint' },
  traffic: { title: '查询分析已有流量', kind: 'query', prompt: '查询当前项目中绑定目标293的已有流量记录，选取一条实际记录并分析请求、响应和可见安全问题，给出记录ID及证据。不要启动代理、重放流量或发出新请求；没有绑定记录就如实说明。', verify: 'traffic' },
  base64: { title: '使用离线Base64工具', prompt: '请使用程序的离线工具集，把公开测试字符串“Xiezhi-AI-0929”进行UTF-8 Base64编码，并显示工具输出。', vector: Buffer.from('Xiezhi-AI-0929').toString('base64'), verify: 'offline' },
  sha256: { title: '使用离线SHA256工具', prompt: '请使用程序的离线工具集，计算不带换行的公开字符串“abc”的SHA-256，显示工具输出。', vector: crypto.createHash('sha256').update('abc').digest('hex'), verify: 'offline' },
  json: { title: '使用离线JSON工具', prompt: '请使用程序的离线工具集，格式化并验证这个公开JSON：{"project":131,"target":293,"ok":true,"tags":["ai","test"]}。显示工具输出，保留全部键和值。', verify: 'offline' },
  audit: { title: '查询与分析审计', kind: 'query', prompt: '请查询并审查本项目最近的AI派发、任务执行和授权相关审计记录，列出真实事件或审计ID、操作、结果及异常；不要修改、清空或导出原始敏感日志。', verify: 'audit' },
  settings: { title: '运行只读设置诊断', prompt: '请检查当前系统设置与AI服务、检索后端、工具依赖的运行状态，执行已有只读诊断并显示诊断结果。不得显示或修改密钥、凭据、权限，不得保存设置、安装依赖或重启服务。', route: /\/settings/ },
  notifications: { title: '查看通知', prompt: '请打开通知中心并查看现有通知，概括未读通知的类型和数量。不要发送任何通知、测试通知、删除通知或更改通知配置。', route: /\/notifications/ },
  tls_config: { title: 'TLS配置检查', scanner: true, prompt: '执行一次 tls_config，参数只能为{}。仅使用目标293自身已经登记的HTTPS地址；如果不是HTTPS，明确报告不适用，不得把HTTP改成HTTPS或换目标。' },
  nuclei_scan: { title: '中文要求Nuclei默认安全模板扫描', scanner: true, prompt: '现在用Nuclei扫描这台主机，只使用程序默认的安全模板和默认设置。只做这一次检查。需要审批就先提交这项扫描的审批单。' },
  afrog_scan: { title: 'Afrog已登记安全PoC', scanner: true, prompt: '现在用Afrog检查这台主机，只运行工作流中已选定的1Panel首页识别检查。只使用这一个现有模板读取首页；需要审批就先提交这项检查的审批单。' },
  xray_scan: { title: '中文要求Xray单项只读检查', scanner: true, prompt: '现在用Xray检查这台主机，只运行工作流中已选定的Docker Registry公开接口检查。只用这一个现有模板进行只读检查，保持当前目标范围；需要审批就先提交这项检查的审批单。' },
  zap_scan: { title: '中文要求ZAP低强度检查', scanner: true, prompt: '现在用ZAP检查这台主机的网站，扫描强度设为低，关闭爬虫，只检查当前地址。需要审批就先提交这项检查的审批单。' },
  fscan_scan: { title: '中文要求fscan安全模式检查80端口', scanner: true, prompt: '现在用fscan检查这台主机，只检查80端口，采用安全模式。需要审批就先提交这项检查的审批单。' },
  msf_scan: { title: '中文要求Metasploit读取HTTP响应头', scanner: true, prompt: '现在用Metasploit读取这台主机网站的HTTP响应头，只用本地现有的HTTP响应头读取模块，向网站根路径发送一次HEAD请求。仅这一项只读检查，目标和端口使用现有授权配置；需要审批就先提交这项检查的审批单。' },
};
const onlyArg = process.argv.find(arg => arg.startsWith('--only='));
const selected = [...new Set(onlyArg ? onlyArg.slice(7).split(',').filter(Boolean)
  : Object.keys(cases).filter(id => !cases[id].scanner))];
const taskWaitArg = process.argv.find(arg => arg.startsWith('--task-wait-ms='));
const taskWaitMs = taskWaitArg ? Number(taskWaitArg.slice(15)) : 120000;

function must(ok, message, detail) { if (!ok) { const e = new Error(message); e.detail = detail; throw e; } }
function publicEvidence(value, trail = '', out = []) {
  if (!value || typeof value !== 'object') return out;
  const allowed = /^(provider|plannerSource|fallback|fallbackReason|executed|executionIntent|executionDecision|taskIds|evidenceIds|evidenceRefs|retrievalMethod|retrievalBackend|retrievalRoundCount|terminationReason|indexRevision|runtimeRunId|ledgerSequence|ledgerEntryDigest|workflowId|workflowRevision|workflowDigest|method|source|type|status|errorCode|code|mode|targetId|projectId|sessionId|turnId|intent|toolId|toolCode|toolName|progressStage|stage|evidenceCount|evidenceDecision)$/;
  for (const [key, item] of Object.entries(value)) {
    const field = trail ? `${trail}.${key}` : key;
    if (allowed.test(key) && (item == null || typeof item !== 'object'
      || ['taskIds', 'evidenceIds', 'evidenceRefs'].includes(key))) out.push({ field, value: item });
    if (item && typeof item === 'object' && field.split('.').length < 16) publicEvidence(item, field, out);
  }
  return out;
}
function parseWire(body) {
  try { return [JSON.parse(body)]; } catch {}
  return body.split(/\r?\n/).flatMap(line => { try { return [JSON.parse(line.replace(/^data:\s*/, ''))]; } catch { return []; } });
}
function save() {
  fs.writeFileSync(path.join(OUT, 'results.json'), JSON.stringify({ updatedAt: new Date().toISOString(),
    method: 'Actual packaged EXE assistant, execution-mode DOM input; passive response inspection; separate read-only UI verification',
    scope: { projectId: PROJECT_ID, projectName, targetId: TARGET_ID, target, host: HOST },
    selected, taskWaitMs, testProjectName: TEST_PROJECT, testWorkflowRemark: TEST_WORKFLOW,
    legend: { PASS: 'Required operation supported by real task/result or matching read-only UI facts',
      UNSUPPORTED: 'Assistant explicitly reports unavailable operation; it was not executed',
      NOT_EXECUTED: 'No sufficient execution evidence, pending task or missing prerequisites; not a pass',
      NOT_VERIFIED: 'Task observed but actual creation time or parameters could not be verified; not a pass',
      FAIL: 'Transport, scope, output/contract or actual task failure' }, results }, null, 2));
  fs.writeFileSync(path.join(OUT, 'results.md'), '# AI实际模块操作验收\n\n所有用例请求执行模式；操作说明、模型自称成功和验收员事后导航均不等于AI执行。完整回答、来源和界面核对见JSON。\n\n'
    + '| 用例 | 结果 | 秒 | 依据 / 限制 |\n| --- | --- | ---: | --- |\n'
    + results.map(r => `| ${r.id} | ${r.status} | ${r.seconds} | ${(r.error || r.note || '').replace(/[\r\n|]/g, ' ').slice(0, 450)} |`).join('\n'));
}
async function shot(id) {
  await page.screenshot({ path: path.join(OUT, `${id}.png`), fullPage: true,
    mask: [page.locator('input[type="password"], .traffic-detail-pane, .packet-content')], timeout: 15000 });
}
function composer() { return page.locator('.welcome-composer textarea:visible, .thread-composer textarea:visible').first(); }
async function closeDialogs() {
  for (let i = 0; i < 4; i++) {
    const modal = page.locator('.el-dialog:visible, .el-message-box:visible').last();
    if (!await modal.isVisible().catch(() => false)) break;
    const close = modal.locator('.el-dialog__headerbtn, .el-message-box__headerbtn').first();
    if (!await close.isVisible().catch(() => false)) break;
    await close.click();
    await modal.waitFor({ state: 'hidden', timeout: 12000 });
  }
}
async function attachAndScope() {
  const browser = await chromium.connectOverCDP('http://127.0.0.1:19229', { timeout: 10000 });
  for (let attempt = 0; attempt < 120; attempt++) {
    page = browser.contexts().flatMap(context => context.pages()).find(p => p.url().includes('app.asar')
      && !/startup\.html|capture-browser\.html/.test(p.url()));
    if (page) break;
    await sleep(1000);
  }
  must(page, '未找到已打包EXE主页面');
  page.setDefaultTimeout(12000);
  if (!await page.locator('#desktop-v2-primary-navigation').isVisible()) console.log('WAITING_MANUAL_LOGIN');
  await page.locator('#desktop-v2-primary-navigation').waitFor({ state: 'visible', timeout: 600000 });
  const projectResponse = page.waitForResponse(r => /\/projects(?:\?|$)/.test(r.url()) && r.request().method() === 'GET', { timeout: 20000 });
  await navigate(page, '评估项目');
  const projectList = await (await projectResponse).json();
  const project = Array.isArray(projectList) && projectList.find(item => Number(item.id) === PROJECT_ID);
  must(project, '实际项目列表中没有项目131');
  projectName = project.name;
  const targetResponse = page.waitForResponse(r => /\/targets(?:\?|$)/.test(r.url())
    && !/\/projects\//.test(r.url()) && r.request().method() === 'GET', { timeout: 20000 });
  await navigate(page, '授权目标');
  const targetList = await (await targetResponse).json();
  const found = Array.isArray(targetList) && targetList.find(item => Number(item.id) === TARGET_ID);
  must(found, '实际目标列表中没有目标293');
  const actualHost = /^https?:\/\//i.test(found.targetValue) ? new URL(found.targetValue).hostname : found.targetValue;
  must(actualHost === HOST && found.enabled !== false, '目标293地址或启用状态不符合固定范围');
  target = { id: found.id, name: found.name, targetValue: found.targetValue,
    targetType: found.targetType, allowedPorts: found.allowedPorts, enabled: found.enabled };
  console.log('SCOPE ' + JSON.stringify({ projectId: PROJECT_ID, projectName, target }));
}
async function newScopedChat() {
  await closeDialogs();
  await navigate(page, 'AI 安全助手');
  await page.getByRole('button', { name: '新对话', exact: true }).click();
  await composer().waitFor({ state: 'visible' });
  await selectOn(page, page.locator('.target-picker .el-select'), target.name, { exact: false });
  // The option contains both name and address, so verify its selected label.
  must((await page.locator('.target-picker').innerText()).includes(target.name), '新对话未选中已核实的293目标');
}
async function send(id, prompt) {
  await composer().waitFor({ state: 'visible' });
  const sw = page.getByRole('switch', { name: 'AI 执行模式' });
  const legacyMode=await sw.count()>0;
  if (legacyMode && await sw.getAttribute('aria-checked') !== 'true')
    await page.locator('.el-switch').filter({ has: sw }).locator('.el-switch__core').click();
  if(legacyMode)must(await sw.getAttribute('aria-checked') === 'true', '未进入AI执行模式');
  await composer().fill(prompt);
  const passiveOperations = [], downloads = [], pendingReads = [];
  const onResponse = response => {
    const url = response.url().split('?')[0];
    // Record only public endpoint/method/status; never headers, credentials,
    // traffic bodies, full request bodies or arbitrary settings responses.
    if (/\/(?:projects|targets|tasks|reports|workflows?|recon|probes|fingerprints|audits|traffic|notifications)(?:\/|$)/.test(url)) {
      const pathname = new URL(url).pathname;
      const record = { path: pathname, method: response.request().method(), status: response.status() };
      passiveOperations.push(record);
      if (/\/reports\//.test(pathname) && response.ok()) pendingReads.push(response.body()
        .then(body => { record.responseBytes = body.length; record.magic = body.subarray(0, 5).toString('ascii'); })
        .catch(() => { record.bodyUnavailable = true; }));
    }
  };
  const onDownload = download => {
    const record = { suggestedFilename: download.suggestedFilename(), saved: false };
    downloads.push(record);
    const output = path.join(OUT, `${id}-download-${downloads.length}-${path.basename(download.suggestedFilename()).replace(/[^\w.\u4e00-\u9fff-]/g, '_')}`);
    pendingReads.push(download.saveAs(output).then(() => { record.saved = true; record.path = output; record.bytes = fs.statSync(output).size; })
      .catch(error => { record.error = String(error.message); }));
  };
  page.on('response', onResponse); page.on('download', onDownload);
  const started = Date.now();
  const pending = page.waitForResponse(r => /\/ai\/(agent|dispatches)\/stream(?:\?|$)/.test(r.url())
    && r.request().method() === 'POST', { timeout: 25000 });
  let response, request, wire = [], wireError;
  try {
    await page.locator('.send-button:visible').click();
    response = await pending;
    const rawRequest = response.request().postDataJSON();
    request = { execute: rawRequest.execute, executionIntent:rawRequest.executionIntent, userPrompt:rawRequest.userPrompt, mode: rawRequest.mode, projectId: rawRequest.projectId,
      targetId: rawRequest.targetId, sessionId: rawRequest.sessionId, turnId: rawRequest.turnId,
      refs: (rawRequest.refs || []).map(ref => ({ type: ref.type, id: ref.id })) };
    let deadline;
    try { wire = parseWire(await Promise.race([response.body().then(body=>body.toString('utf8')), new Promise((_, reject) => {
      deadline = setTimeout(() => reject(new Error('AI流180秒内未完成')), 180000);
    })])); } finally { clearTimeout(deadline); }
    for (let i = 0; i < 240 && !await composer().isEnabled().catch(() => true); i++) await sleep(500);
    await sleep(700);
  } catch (error) { wireError = String(error.message); }
  finally {
    page.off('response', onResponse); page.off('download', onDownload);
    await Promise.allSettled(pendingReads);
  }
  const terminal = wire.findLast(event => event.type === 'done')?.data;
  const currentMessage=page.locator('article.chat-message.assistant').last();
  const answerBody=currentMessage.locator('.message-bubble.markdown-body'),attention=currentMessage.locator('.progress-attention');
  const bodyText=await answerBody.count()?await answerBody.innerText():'';
  const answer=bodyText||(await attention.count()?await attention.innerText():'')||await currentMessage.locator('.ai-progress-panel').innerText().catch(()=> '');
  const taskIds = [...new Set((terminal?.response?.taskIds || terminal?.taskIds || []).map(Number).filter(Number.isSafeInteger))];
  const detail = { prompt, answer, answerPresentation:bodyText?'ANSWER':'PROGRESS_OR_ERROR',request, httpStatus: response?.status(), sentAt: new Date(started).toISOString(), streamMs: Date.now() - started,
    answerSource: terminal?.plannerSource || terminal?.response?.plan?.provider || '',
    executedClaim: terminal?.executed ?? terminal?.response?.executed, taskIds,
    approvalId: terminal?.response?.approvalId ?? terminal?.approvalId,
    approvalStatus: terminal?.response?.approvalStatus ?? terminal?.approvalStatus,
    planSteps: terminal?.response?.plan?.steps || [], evidence: wire.flatMap(event => publicEvidence(event)),
    publicMessages: wire.map(event => ({ type: event.type, message: event.message,
      summary: event.data?.summary, progressStage: event.data?.progressStage })).filter(event => event.message || event.summary),
    errors: wire.filter(event => event.type === 'error').map(event => ({ message: event.message, evidence: publicEvidence(event.data) })),
    passiveOperations, downloads, assistantUi: { url: page.url(), title: await page.locator('.desktop-v2-title > strong').first().innerText().catch(() => '') },
    uiReady: await composer().isEnabled().catch(() => false), wireError };
  fs.writeFileSync(path.join(OUT, `${id}-reply.txt`), answer);
  fs.writeFileSync(path.join(OUT, `${id}-public-evidence.json`), JSON.stringify(detail, null, 2));
  await shot(`${id}-assistant`);
  must(!wireError, wireError || '发送失败', detail);
  must((legacyMode ? request?.execute === true : request?.executionIntent === 'AUTO' && request.userPrompt === prompt) && Number(request.projectId) === PROJECT_ID && Number(request.targetId) === TARGET_ID,
    '请求执行模式或项目/目标范围不正确；停止后续用例', { ...detail, fatal: true });
  must(!wireError && detail.uiReady, wireError || 'AI仍在运行；停止后续用例，不取消后台任务', { ...detail, fatal: true });
  must(response.ok() && terminal && detail.errors.length === 0 && answer.trim().length > 8,
    'AI未返回完整成功响应', detail);
  must(!!bodyText||taskIds.length>0||(['REQUIRED','PENDING'].includes(detail.approvalStatus)&&detail.approvalId&&detail.planSteps.length),
    '不能将进度记录当成完整回答',detail);
  return detail;
}
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  return value;
}
async function decideReviewed(id, proposal, decision) {
  const approvalId = Number(proposal.approvalId);
  const article = page.locator('article.chat-message.assistant').last();
  const countBefore = await page.locator('article.chat-message').count();
  const approvalDialog = page.getByRole('dialog', { name: '确认本次检测', exact: true });
  await approvalDialog.waitFor({ state: 'visible' });
  must(await approvalDialog.locator(`[data-approval-id="${approvalId}"]`).count() === 1,
    '审批弹窗单号与原计划不一致，停止');
  must((await approvalDialog.innerText()).includes(HOST), '审批弹窗目标不匹配，停止');
  await shot(`${id}-reviewed-plan`);
  const operations = [];
  const observed = request => {
    if (request.method() === 'POST') operations.push(new URL(request.url()).pathname);
  };
  page.on('request', observed);
  const base = `/projects/${PROJECT_ID}/approvals/${approvalId}`;
  const decisionResponse = page.waitForResponse(response => response.url().split('?')[0].endsWith(base + '/decision')
    && response.request().method() === 'POST', { timeout: 25000 });
  const executeResponse = decision === 'APPROVED' ? page.waitForResponse(response => response.url().split('?')[0].endsWith(base + '/execute')
    && response.request().method() === 'POST', { timeout: 60000 }) : null;
  decisionResponse.catch(() => {});
  // Attach a rejection handler immediately so a decision failure is reported cleanly.
  executeResponse?.catch(() => {});
  let dispatch;
  try {
    await approvalDialog.getByRole('button', { name: decision === 'APPROVED' ? '批准本次执行' : '拒绝', exact: true }).click();
    const response = await decisionResponse;
    const saved = await response.json();
    must(response.ok() && Number(saved.id) === approvalId && saved.status === decision, '实际审批裁决失败', { httpStatus: response.status(), approvalId: saved.id, status: saved.status });
    if (executeResponse) {
      const execution = await executeResponse;
      dispatch = await execution.json();
      must(execution.ok() && Number(dispatch.targetId) === TARGET_ID && Array.isArray(dispatch.taskIds) && dispatch.taskIds.length > 0,
        '原审批计划未恢复执行', { status: execution.status(), dispatch });
      const contract = steps => steps.map(step => stable({ toolCode: step.toolCode, workflowNodeId: step.workflowNodeId,
        group: step.group, dependsOnNodeIds: step.dependsOnNodeIds || [], risk: step.risk, requiresApproval: step.requiresApproval,
        parameters: step.parameters || {} })).sort((a,b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
      must(JSON.stringify(contract(dispatch.plan?.steps || [])) === JSON.stringify(contract(proposal.planSteps)),
        '执行回执与已批准原计划不一致', { proposed: proposal.planSteps, returned: dispatch.plan?.steps, fatal: true });
    }
    await approvalDialog.waitFor({ state: 'hidden' });
    await sleep(1200);
    must(await page.locator('article.chat-message').count() === countBefore, '审批产生了新聊天轮次，疑似重新规划', { fatal: true });
    must(!operations.some(url => /\/ai\/(agent|dispatches)\/stream$/.test(url)), '审批后不应重新请求模型规划', { operations, fatal: true });
    if (decision === 'REJECTED') {
      must(!operations.some(url => url.endsWith('/execute')), '驳回后仍触发了执行接口', { operations, fatal: true });
      must(await article.locator('.progress-tool-call').count() === 0, '驳回消息出现检测任务', { fatal: true });
      must((await article.innerText()).includes('已驳回'), '界面没有显示实际驳回状态');
    }
    let replay = { status: 'NOT_REQUESTED' };
    if (decision === 'APPROVED' && process.argv.includes('--verify-replay')) {
      const replayButton = article.getByRole('button', { name: /同步审批任务|恢复原计划执行/ }).first();
      must(await replayButton.isVisible().catch(() => false), '当前界面没有可见的同审批同步/恢复入口；不能伪造状态或直接调用API来冒充UI重复恢复验收');
      const repeated = page.waitForResponse(response => response.url().split('?')[0].endsWith(base + '/execute')
        && response.request().method() === 'POST', { timeout: 60000 });
      repeated.catch(() => {});
      await replayButton.click();
      const response = await repeated;
      const receipt = await response.json();
      must(response.ok() && JSON.stringify(receipt.taskIds) === JSON.stringify(dispatch.taskIds)
        && JSON.stringify(stable(receipt.plan)) === JSON.stringify(stable(dispatch.plan)),
        '同审批恢复未返回相同任务与原计划', { before: dispatch, after: receipt, fatal: true });
      await sleep(600);
      must(await page.locator('article.chat-message').count() === countBefore
        && !operations.some(url => /\/ai\/(agent|dispatches)\/stream$/.test(url)), '重复恢复触发了模型重规划', { operations, fatal: true });
      replay = { status: 'PASS', taskIds: receipt.taskIds, samePlan: true };
    }
    const answer = await article.locator('.message-bubble').innerText();
    const detail = { ...proposal, answer, approvalStatus: decision, taskIds: dispatch?.taskIds || [],
      planSteps: dispatch?.plan?.steps || proposal.planSteps, rejectedApprovalVerified: decision === 'REJECTED',
      approvalResume: { approvalId, decision, operations, originalMessagePreserved: true, exactPlanVerified: !!dispatch, replay },
      reviewedProposal: { approvalId, request: proposal.request, planSteps: proposal.planSteps } };
    fs.writeFileSync(path.join(OUT, `${id}-approval-evidence.json`), JSON.stringify(detail, null, 2));
    await shot(`${id}-approval-result`);
    return detail;
  } finally { page.off('request', observed); }
}

async function enterProjectTab(name) {
  await navigate(page, '评估项目');
  await page.getByPlaceholder('搜索项目名称 / 负责人 / 说明').fill(projectName);
  await page.locator('.el-table__row').filter({ hasText: projectName }).first().getByRole('button', { name: '进入项目', exact: true }).click();
  await page.waitForURL(new RegExp(`/projects/${PROJECT_ID}(?:[/?#]|$)`));
  must(new RegExp(`/projects/${PROJECT_ID}(?:[/?#]|$)`).test(page.url()), '项目详情未进入131');
  await page.getByRole('tab', { name, exact: true }).click();
  await sleep(500);
  return page.locator('.el-tab-pane:visible').last();
}
async function readTask(taskId, waitMs = 0) {
  let actualRecord;
  const pendingReads = [];
  const onTaskResponse = response => {
    const url = new URL(response.url());
    if (!url.pathname.endsWith('/tasks') || response.request().method() !== 'GET' || !response.ok()) return;
    // Observe only UI-issued list reads. Never retain the whole response, snapshots,
    // execution logs, credentials, or another task's data.
    pendingReads.push(response.json().then(raw => {
      const list = Array.isArray(raw) ? raw : Array.isArray(raw?.content) ? raw.content : [];
      const task = list.find(item => Number(item.id) === taskId);
      if (!task) { actualRecord = undefined; return; }
      let parameters = task.parameters;
      if (parameters === undefined && typeof task.requestJson === 'string') {
        try { parameters = JSON.parse(task.requestJson); } catch { parameters = undefined; }
      }
      // These are the public scanner settings under review. Reject unrecognized
      // fields without copying their values into evidence files.
      const safeKeys = ['pocCodes', 'allPocs', 'spider', 'strength', 'ports', 'vulnMode', 'module', 'modules', 'options'];
      const parametersAvailable = !!parameters && typeof parameters === 'object' && !Array.isArray(parameters)
        && Object.keys(parameters).every(key => safeKeys.includes(key))
        && Object.entries(parameters).every(([key, value]) => key === 'options'
          ? value && typeof value === 'object' && !Array.isArray(value)
            && Object.entries(value).every(([option, setting]) => ['HTTP_METHOD', 'TARGETURI'].includes(option) && typeof setting === 'string')
          : Array.isArray(value) ? value.every(item => typeof item === 'string') : ['string', 'boolean', 'number'].includes(typeof value));
      actualRecord = { id: task.id, targetId: task.targetId, toolCode: task.toolCode,
        createdAt: task.createdAt, status: task.status, parametersAvailable,
        ...(parametersAvailable ? { parameters } : {}) };
    }).catch(() => {}));
  };
  page.on('response', onTaskResponse);
  let cells = [], text = '';
  try {
  await navigate(page, '检测任务');
  const clear = page.getByRole('button', { name: '清除筛选', exact: true });
  if (await clear.isVisible()) await clear.click();
  await selectOn(page, page.locator('.el-select').filter({ has: page.getByRole('combobox', { name: '按项目筛选' }) }), projectName);
  await page.getByPlaceholder('搜任务 ID / 工具').fill(String(taskId));
  const end = Date.now() + waitMs;
  do {
    await sleep(500);
    cells = []; text = '';
    const rows = page.locator('.el-table__row:visible');
    for (let i = 0; i < await rows.count(); i++) {
      const candidate = await rows.nth(i).locator('td').allInnerTexts();
      if (candidate[0]?.trim() === String(taskId)) { cells = candidate.map(value => value.trim()); text = await rows.nth(i).innerText(); break; }
    }
    if (cells[3] && /成功|失败|超时|拒绝|取消|跳过|停止|不可用/.test(cells[3])) break;
  } while (Date.now() < end);
  } finally {
    page.off('response', onTaskResponse);
    await Promise.allSettled(pendingReads);
  }
  return { verifiedBy: 'Operator read-only task-table navigation after AI answer', taskId, found: cells.length > 0,
    targetId: Number(cells[2]), toolCode: cells[1], status: cells[3], text,
    actualRecord, actualRecordSource: actualRecord ? 'Passive UI task-list GET response' : undefined };
}
async function verifyModule(id, spec) {
  if (!spec.verify) return undefined;
  let locator;
  if (spec.verify === 'project') {
    await navigate(page, '评估项目');
    await page.getByPlaceholder('搜索项目名称 / 负责人 / 说明').fill(TEST_PROJECT);
    await sleep(500);
    locator = page.locator('.el-table__row:visible').filter({ hasText: TEST_PROJECT });
  } else if (spec.verify === 'targets') {
    locator = await enterProjectTab('授权目标');
  } else if (['report', 'recon', 'fingerprint'].includes(spec.verify)) {
    locator = await enterProjectTab({ report: '项目报告', recon: '信息收集', fingerprint: '探测服务' }[spec.verify]);
  } else {
    const nav = { findings: '结果中心', topology: '资产拓扑', workflow: '红队工作流', traffic: '流量分析', offline: '离线工具集', audit: '审计日志' }[spec.verify];
    await navigate(page, nav);
    locator = spec.verify === 'workflow' ? page.locator('[aria-label="当前工作流配置"]')
      : spec.verify === 'traffic' ? page.locator('.traffic-row:visible')
        : spec.verify === 'offline' ? page.locator('.desktop-v2-title > strong')
          : spec.verify === 'topology' ? page.locator('.vue-flow__node:visible')
            : page.locator('.el-table__row:visible');
  }
  const observed = { verifiedBy: 'Operator read-only navigation, not assistant execution', url: page.url(),
    count: await locator.count(), text: (await locator.allInnerTexts()).join('\n').slice(0, 24000) };
  await shot(`${id}-verification`);
  return observed;
}
function unsupported(answer) {
  return /(?:不支持|尚未接入|未接入|没有.{0,12}(?:工具|接口|权限)|无法.{0,16}(?:直接|打开|执行|操作|创建|导出|保存|调用)|不能.{0,12}(?:直接|代替|操作|执行|创建|导出|保存)|需要.{0,6}(?:你|您|手动)).{0,30}/.test(answer);
}
function scannerContract(id, steps) {
  if (steps.length !== 1 || steps[0].toolCode !== id) return '没有唯一指定扫描工具的计划';
  const parameters = steps[0].parameters || {};
  const keys = Object.keys(parameters);
  if (['tls_config', 'nuclei_scan'].includes(id) && keys.length) return '空参数工具含额外参数';
  if (['afrog_scan', 'xray_scan'].includes(id)
    && (keys.some(key => key !== 'pocCodes') || parameters.pocCodes?.length !== 1 || !/^[A-Z]{2}-[A-F0-9]{24}$/.test(parameters.pocCodes[0]))) return 'PoC不是单个真实格式编号或启用了全库';
  if (id === 'afrog_scan' && parameters.pocCodes?.[0] !== 'AP-73D89DECF79507F352F87EC9') return 'Afrog模板不匹配已登记的首页识别';
  if (id === 'xray_scan' && parameters.pocCodes?.[0] !== 'XP-577D08DBE1BF06E5442CA3DF') return 'Xray模板不匹配已审阅检查';
  if (id === 'msf_scan' && ((parameters.module || (parameters.modules?.length === 1 ? parameters.modules[0] : '')) !== 'auxiliary/scanner/http/http_header'
    || Object.keys(parameters.options || {}).some(key => !['HTTP_METHOD', 'TARGETURI'].includes(key))
    || parameters.options?.HTTP_METHOD !== 'HEAD' || parameters.options?.TARGETURI !== '/')) return 'MSF参数不匹配已审阅只读检查';
  if (id === 'zap_scan' && (keys.some(key => !['spider', 'strength'].includes(key))
    || parameters.spider !== false || parameters.strength !== 'LOW')) return 'ZAP未保持spider=false、LOW';
  if (id === 'fscan_scan' && (keys.some(key => !['ports', 'vulnMode'].includes(key))
    || parameters.ports !== '80' || parameters.vulnMode !== 'SAFE')) return 'fscan不是80端口SAFE模式';
  if (id === 'msf_scan') {
    const modules = parameters.module ? [parameters.module] : parameters.modules;
    if (keys.some(key => !['module', 'modules', 'options'].includes(key)) || (parameters.module && parameters.modules)
      || !Array.isArray(modules) || modules.length !== 1 || !/^auxiliary\/scanner\/[a-z0-9_/]+$/.test(modules[0])) return 'MSF不是单个auxiliary/scanner模块';
    const forbidden = /^(RHOSTS?|RPORT|LHOST|LPORT|PAYLOAD|CMD|COMMAND|SHELL|CHOST|CPORT)$/;
    if (Object.entries(parameters.options || {}).some(([key, value]) => forbidden.test(key)
      || !/^[A-Z][A-Z0-9_]{0,63}$/.test(key) || typeof value !== 'string' || /[\x00-\x1f\x7f;]/.test(value))) return 'MSF含不允许的参数';
  }
  return '';
}
async function runCase(id) {
  const spec = cases[id], started = Date.now();
  let result;
  console.log('START ' + id);
  try {
    await newScopedChat();
    const prompt = (spec.scanner ? `当前选中的主机是${HOST}。` : scope) + (spec.taskId ? `查询并分析已有任务${spec.taskId}的当前真实状态、工具、目标、结果和失败原因（如有），给出引用的任务ID。不要重试、取消或创建其他任务。` : spec.prompt)
      + (spec.scanner ? scanLimits : limits);
    let reply = await send(id, prompt);
    if ((process.argv.includes('--approve-reviewed') || process.argv.includes('--reject-reviewed')) && spec.scanner && reply.approvalStatus === 'REQUIRED') {
      // Explicit test opt-in; only exact low-impact contracts reviewed for this host.
      const reviewedParameters=reply.planSteps[0]?.parameters || {};
      const reviewable = ['nuclei_scan', 'fscan_scan', 'zap_scan'].includes(id)
        || (id==='afrog_scan'&&reviewedParameters.pocCodes?.length===1&&reviewedParameters.pocCodes[0]==='AP-73D89DECF79507F352F87EC9')
        || (id==='xray_scan'&&reviewedParameters.pocCodes?.length===1&&reviewedParameters.pocCodes[0]==='XP-577D08DBE1BF06E5442CA3DF')
        || (id==='msf_scan'&&(reviewedParameters.module||(reviewedParameters.modules?.length===1?reviewedParameters.modules[0]:''))==='auxiliary/scanner/http/http_header'
          &&Object.keys(reviewedParameters.options||{}).every(key=>['HTTP_METHOD','TARGETURI'].includes(key))
          &&reviewedParameters.options?.HTTP_METHOD==='HEAD'&&reviewedParameters.options?.TARGETURI==='/');
      must(reviewable && Number.isSafeInteger(Number(reply.approvalId)) && Number(reply.approvalId) > 0
        && reply.taskIds.length === 0 && !scannerContract(id, reply.planSteps),
        '待审计划未匹配本次已审阅的单工具合同，未批准', reply);
      reply = await decideReviewed(id, reply, process.argv.includes('--reject-reviewed') ? 'REJECTED' : 'APPROVED');
    }
    result = { id, title: spec.title, ...reply, status: 'NOT_EXECUTED', note: '尚无足够证据证明请求操作已执行。' };
    const grounded = reply.answerSource === 'langchain-grounded';
    result.modelSourceVerified = grounded;
    if (reply.rejectedApprovalVerified) {
      result.status = 'PASS'; result.note = '实际驳回成功；原消息无任务、无execute请求、无新模型轮次。服务端零任务事务另有H2回归覆盖。';
    } else if (reply.taskIds.length) {
      result.tasks = [];
      for (const taskId of reply.taskIds) result.tasks.push(await readTask(taskId, spec.scanner ? taskWaitMs : 0));
      const wrongTask = result.tasks.find(task => !task.found || task.targetId !== TARGET_ID || (spec.scanner && task.toolCode !== id));
      const contractError = spec.scanner ? scannerContract(id, reply.planSteps) : '此模块操作不应以创建扫描任务代替';
      const actualChecks = spec.scanner ? result.tasks.map(task => {
        const actual = task.actualRecord;
        if (!actual || !Number.isFinite(Date.parse(actual.createdAt || '')) || !actual.parametersAvailable
          || !Number.isFinite(Date.parse(reply.sentAt || '')))
          return { taskId: task.taskId, status: 'NOT_VERIFIED', reason: '未取得实际任务创建时间或可核对的扫描参数' };
        const actualContract = scannerContract(id, [{ toolCode: actual.toolCode, parameters: actual.parameters }]);
        const error = Number(actual.id) !== task.taskId || Number(actual.targetId) !== TARGET_ID ? '实际任务身份或目标不一致'
          : Date.parse(actual.createdAt) < Date.parse(reply.sentAt) - 5000 ? '任务早于本轮发送，不能作为本轮新建任务'
            : actualContract;
        return { taskId: task.taskId, status: error ? 'FAIL' : 'VERIFIED', reason: error || '实际任务创建时间及参数符合本轮扫描合同' };
      }) : [];
      result.actualTaskChecks = actualChecks;
      const actualFailure = actualChecks.find(check => check.status === 'FAIL');
      const actualMissing = actualChecks.some(check => check.status === 'NOT_VERIFIED');
      if (wrongTask || contractError) { result.status = 'FAIL'; result.note = contractError || '任务表中未验证同范围指定工具任务'; result.fatal = true; }
      else if (actualFailure) { result.status = 'FAIL'; result.note = actualFailure.reason; result.fatal = true; }
      else if (result.tasks.some(task => /失败|超时|拒绝|取消|跳过|停止|不可用/.test(task.status))) { result.status = 'FAIL'; result.note = '真实任务已派发，但执行失败；详细状态见tasks。'; }
      else if (actualMissing) { result.status = 'NOT_VERIFIED'; result.note = '已观察到任务，但实际创建时间或扫描参数未核实，不能确认本轮扫描成功。'; }
      else if (grounded && result.tasks.every(task => /成功/.test(task.status))) { result.status = 'PASS'; result.note = '真实模型派发指定任务，已在项目131任务表核对目标293、工具及成功状态。'; }
      else if (grounded) { result.status = 'RUNNING'; result.note = '真实任务已派发并核对，仍在执行；尚无终态，不计为执行成功。'; }
      else { result.note = '真实任务ID已返回，但模型来源未通过，不能记为完整验收成功。'; }
      result.executionVerified = !wrongTask && !contractError && !actualFailure && !actualMissing;
      if (!spec.scanner) result.fatal = true;
    } else if (spec.taskId) {
      result.uiVerification = await readTask(spec.taskId);
      const task = result.uiVerification;
      const stateAliases = { 成功: /成功|SUCCEEDED|SUCCESS|COMPLETED/i, 失败: /失败|FAILED/i,
        执行中: /执行中|运行中|RUNNING/i, 待执行: /待执行|等待|PENDING/i, 排队中: /排队|QUEUED/i,
        等待前置: /等待前置|BLOCKED/i, 超时: /超时|TIMEOUT|TIMED_OUT/i, 已取消: /取消|CANCELED|CANCELLED/i,
        已拒绝: /拒绝|REJECTED/i, 已跳过: /跳过|SKIPPED/i, 已停止: /停止|STOPPED/i };
      const statusMatch = Object.entries(stateAliases).find(([state]) => task.status?.includes(state))?.[1]?.test(reply.answer);
      if (grounded && task.found && task.targetId === TARGET_ID && reply.answer.includes(String(spec.taskId))
        && reply.answer.includes(task.toolCode) && statusMatch) {
        result.status = 'PASS'; result.note = 'AI回答的任务ID、工具、状态与同项目真实任务表一致；这是查询分析，不是新任务执行。';
      } else { result.note = '查询结果未同时通过真实任务表ID、目标、工具、状态和模型来源核对，保留完整回答人工复核。'; }
    } else {
      result.uiVerification = await verifyModule(id, spec);
      if (unsupported(reply.answer)) {
        result.status = 'UNSUPPORTED'; result.note = '助手明确提示该操作未接入或需要人工完成；本次未完成该模块操作。';
      }
      if (spec.vector) result.answerCheck = { expected: spec.vector, matches: reply.answer.includes(spec.vector),
        note: '计算结果正确也不证明调用过离线工具。' };
      if (id === 'json') result.answerCheck = { expected: { project: 131, target: 293, ok: true, tags: ['ai', 'test'] },
        note: '保留原文供人工核对；模型格式化文本不证明调用过离线工具。' };
      if (id === 'project_create' && result.uiVerification?.count > 0 && result.uiVerification.text.includes(TEST_PROJECT)) {
        result.status = grounded ? 'PASS' : 'NOT_EXECUTED'; result.note = '真实项目表中出现本次唯一名称；核对草稿状态并保留记录。';
        if (!/草稿|DRAFT/.test(result.uiVerification.text)) { result.status = 'FAIL'; result.note = '项目已创建但未显示草稿状态。'; }
      }
      if (id === 'report' && (reply.downloads.some(download => download.saved && download.bytes > 100 && /\.pdf$/i.test(download.suggestedFilename))
        || reply.passiveOperations.some(operation => /\/reports\//.test(operation.path) && operation.status === 200 && operation.magic === '%PDF-' && operation.responseBytes > 100))) {
        result.status = grounded ? 'PASS' : 'NOT_EXECUTED'; result.note = 'AI请求期间观察到真实PDF下载/内容；验收员未点击导出按钮。';
      }
      if (spec.route && spec.route.test(reply.assistantUi.url)) {
        result.openedRequestedPage = true;
        result.status = id === 'topology' && grounded ? 'PASS' : 'NOT_EXECUTED';
        result.note = id === 'topology' ? '助手响应结束时已进入资产拓扑真实页面；界面截图保留。'
          : '助手响应结束时已打开请求页面，但未取得诊断结果或通知数量的执行证据，仅页面打开不能记为整个操作成功。';
      }
      if (spec.kind === 'query' && result.status === 'NOT_EXECUTED') result.note = '已尝试真实资料查询；来源与完整回答已保留，尚未自动核实全部事实，不能把文字回答记为操作完成。';
      if (spec.scanner && !reply.taskIds.length) result.note += ' 没有真实taskIds，未记为扫描执行；缺少配置/依赖/协议适配的说明见完整回复。';
      if (spec.scanner && ['REQUIRED','PENDING'].includes(reply.approvalStatus)) {
        result.note = `已有审批单${reply.approvalId}，等待核对本轮计划及参数后批准，尚未执行。`;
        result.scannerContractError = scannerContract(id, reply.planSteps);
      }
    }
    result.claimReviewRequired = !['PASS'].includes(result.status) && /已(?:成功)?(?:创建|保存|导出|执行|打开|完成)|执行成功|保存成功|导出成功/.test(reply.answer);
  } catch (error) {
    result = { ...result, id, title: spec.title, ...error.detail, status: 'FAIL', error: String(error.message), note: '用例未通过，保留已经取得的真实回复与证据。' };
  }
  result.seconds = +((Date.now() - started) / 1000).toFixed(1);
  await shot(`${id}-final`).catch(error => { result.screenshotError = String(error.message); });
  results.push(result); save();
  console.log(JSON.stringify({ id, status: result.status, seconds: result.seconds, taskIds: result.taskIds,
    note: result.note, error: result.error, claimReviewRequired: result.claimReviewRequired }));
  if (result.fatal) throw new Error('安全停止后续用例：' + (result.error || result.note));
}
(async () => {
  must(selected.length && selected.every(id => Object.hasOwn(cases, id)), '未知或空--only用例；使用--list查看');
  must(Number.isFinite(taskWaitMs) && taskWaitMs >= 0 && taskWaitMs <= 600000, '--task-wait-ms必须为0到600000');
  must(process.argv.slice(2).every(arg => arg === '--list' || arg === '--approve-reviewed' || arg === '--reject-reviewed' || arg === '--verify-replay' || arg.startsWith('--only=') || arg.startsWith('--task-wait-ms=')), '含未知参数');
  must(!process.argv.includes('--verify-replay') || process.argv.includes('--approve-reviewed'), '--verify-replay必须与--approve-reviewed一起使用');
  must(!(process.argv.includes('--approve-reviewed') && process.argv.includes('--reject-reviewed')), '不能同时批准和驳回');
  if (process.argv.includes('--list')) {
    console.log(Object.entries(cases).map(([id, spec]) => `${id}\t${spec.scanner ? 'OPT-IN SCANNER' : 'DEFAULT'}\t${spec.title}`).join('\n'));
    return;
  }
  fs.mkdirSync(OUT, { recursive: true });
  console.log('RESULTS ' + OUT);
  await attachAndScope(); save();
  for (const id of selected) await runCase(id);
  console.log('COMPLETE ' + OUT);
  // 0=all passed; 1=actual failure; 3=unsupported/not executed remains. The EXE stays open.
  process.exit(results.some(result => result.status === 'FAIL') ? 1 : results.some(result => result.status !== 'PASS') ? 3 : 0);
})().catch(error => {
  console.error(String(error.message));
  if (fs.existsSync(OUT)) save();
  process.exit(2);
});
