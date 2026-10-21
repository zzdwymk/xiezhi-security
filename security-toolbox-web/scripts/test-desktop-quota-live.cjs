// Real packaged desktop acceptance against the user's existing test project.
// Business writes use the actual UI. API calls below are read-only verification.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { _electron: electron, chromium } = require('playwright-core');

const web = path.resolve(__dirname, '..');
const workspace = path.dirname(web);
const out = path.join(workspace, '.run', 'desktop-quota-acceptance', new Date().toISOString().replace(/[:.]/g, '-'));
const exe = path.join(web, 'desktop-release', 'win-unpacked', '獬豸安全测试平台.exe');
const targetValue = process.env.QUOTA_TEST_TARGET || '192.168.222.141';
const expectedProfile = path.join(process.env.APPDATA, 'security-toolbox-desktop');
fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(workspace, '.run', 'desktop-quota-acceptance-current.txt'), out);
const results = [], pageErrors = [], executionResponses = [];
const resumeExisting = process.env.QUOTA_RESUME_EXISTING === 'true';
let app, page, browser, sequence = 0;
const started = Date.now();
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const terminal = new Set(['SUCCESS', 'FAILED', 'TIMEOUT', 'REJECTED', 'CANCELLED', 'SKIPPED']);

function checkpoint(phase) {
  fs.writeFileSync(path.join(out, 'phase.json'), JSON.stringify({ phase, at: new Date().toISOString() }));
  console.log('PHASE ' + phase);
}
async function shot(label) {
  await page.screenshot({ path: path.join(out, `${String(++sequence).padStart(2, '0')}-${label}.png`) });
}
async function check(name, run) {
  checkpoint(name);
  try {
    const detail = await run();
    results.push({ name, status: 'PASS', detail });
    console.log('PASS ' + name + ': ' + JSON.stringify(detail));
    await shot(name.replace(/[^a-z0-9-]/gi, '-'));
    return detail;
  } catch (error) {
    results.push({ name, status: 'FAIL', detail: error.message });
    await shot('failure').catch(() => {});
    throw error;
  }
}
async function until(read, accept, timeout = 120000) {
  const deadline = Date.now() + timeout;
  let value;
  while (Date.now() < deadline) {
    value = await read();
    if (accept(value)) return value;
    await delay(750);
  }
  throw new Error('Timed out waiting for condition: ' + JSON.stringify(value).slice(0, 1800));
}
async function apiGet(endpoint) {
  return page.evaluate(async endpoint => {
    const base = window.toolboxDesktop.backendBaseUrl.replace(/\/+$/, '');
    const token = localStorage.getItem('security_toolbox_token') || sessionStorage.getItem('security_toolbox_session_token');
    const response = await fetch(base + endpoint, { headers: { Authorization: 'Bearer ' + token } });
    if (!response.ok) throw new Error('Verification GET ' + endpoint + ' returned HTTP ' + response.status);
    return response.json();
  }, endpoint);
}
async function threads() {
  return page.evaluate(() => JSON.parse(localStorage.getItem('security_toolbox_ai_conversations_v2') || '[]'));
}
async function navigate(route) {
  const next = new URL(page.url());
  next.hash = '#' + route;
  await page.goto(next.href);
  await delay(1000);
}
async function dismissApproval() {
  const close = page.locator('.ai-approval-modal:visible button').filter({ hasText: '关闭，继续等待' });
  if (await close.count()) await close.click();
}
async function newConversation(prompt, target, requireApproval = true) {
  await dismissApproval();
  await navigate('/');
  const picker = page.locator('.composer-footer .target-picker, .composer-footer .el-select').first();
  await picker.waitFor({ state: 'visible', timeout: 30000 });
  await picker.click();
  const option = page.locator('.el-select-dropdown:visible .el-select-dropdown__item').filter({ hasText: targetValue }).first();
  await option.waitFor({ state: 'visible' });
  await option.click();
  const input = page.locator('.welcome-composer textarea, .thread-composer textarea').first();
  await input.fill(prompt);
  const previous = new Set((await threads()).map(thread => thread.id));
  await page.locator('.welcome-composer .send-button, .thread-composer .send-button').first().click();
  const read = () => threads().then(items => items.find(thread => !previous.has(thread.id) && thread.targetId === target.id));
  const completed = await until(read, thread => thread?.messages.some(message => message.role === 'assistant'
    && ['completed', 'failed'].includes(message.status)), 300000);
  const message = completed.messages.filter(message => message.role === 'assistant').at(-1);
  fs.writeFileSync(path.join(out, 'turn-' + completed.id + '.json'), JSON.stringify({ prompt, thread: completed }, null, 2));
  assert.notEqual(message.status, 'failed', message.content);
  assert.ok(message.steps.length > 0, 'No actionable plan: ' + message.content.slice(0, 1600));
  assert.ok(message.steps.length <= 4, 'Planner exceeded the target quota: ' + message.steps.length);
  if (requireApproval) {
    assert.ok(message.approvalId, 'Missing server-persisted approval');
    assert.equal(message.approvalStatus, 'REQUIRED', 'Explicit execution must reach administrator approval');
  }
  assert.equal(message.taskIds.length, 0, 'No task may be created before confirmation');
  return { thread: completed, message };
}

(async () => {
  assert.ok(fs.existsSync(exe), 'Packaged desktop executable is missing');
  const env = { ...process.env };
  delete env.ELECTRON_RUN_AS_NODE;
  // Use the shipped default limits, never a test-only larger quota.
  for (const key of ['AI_AGENT_MAX_ACTIVE_TASKS_PER_PROJECT', 'AI_AGENT_MAX_ACTIVE_TASKS_PER_TARGET',
    'MAX_CONCURRENT_TASKS', 'MAX_CONCURRENT_TASKS_PER_TARGET', 'AI_RUNTIME_EXECUTABLE']) delete env[key];
  checkpoint(resumeExisting ? 'attach-existing-packaged-desktop' : 'launch-existing-packaged-desktop');
  let processInfo;
  if (resumeExisting) {
    const port = fs.readFileSync(path.join(expectedProfile, 'DevToolsActivePort'), 'utf8').split(/\r?\n/)[0];
    browser = await chromium.connectOverCDP('http://127.0.0.1:' + port);
    page = browser.contexts().flatMap(context => context.pages()).find(candidate => candidate.url().includes('/app.asar/dist/index.html'));
    assert.ok(page, 'Existing packaged workspace not found');
    processInfo = { packaged: true, userData: expectedProfile, attached: true };
  } else {
    app = await electron.launch({ executablePath: exe, args: [], env, timeout: 180000 });
    processInfo = await app.evaluate(({ app }) => ({ packaged: app.isPackaged,
      userData: app.getPath('userData'), resources: process.resourcesPath, pid: process.pid }));
  }
  assert.equal(processInfo.packaged, true);
  assert.equal(path.resolve(processInfo.userData).toLowerCase(), path.resolve(expectedProfile).toLowerCase());
  fs.writeFileSync(path.join(out, 'build.json'), JSON.stringify({ ...processInfo, exe,
    components: ['resources/app.asar', 'resources/server/security-toolbox-server.jar',
      'resources/ai-runtime/security-toolbox-ai-runtime.exe'].map(relative => {
      const file = path.join(path.dirname(exe), relative);
      return { file, sha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),
        modified: fs.statSync(file).mtime.toISOString() };
    }) }, null, 2));
  page ||= await until(async () => app.windows().find(window => /\/dist\/index\.html|#\//.test(window.url())), Boolean, 180000);
  page.setDefaultTimeout(30000);
  page.on('pageerror', error => pageErrors.push(error.message));
  page.on('response', async response => {
    if (/\/approvals\/\d+\/execute$/.test(response.url())) {
      try { executionResponses.push({ url: response.url(), status: response.status(), data: await response.json() }); } catch {}
    }
  });
  await check('desktop-startup-and-login', async () => {
    await until(async () => {
      const text = await page.locator('body').innerText();
      if (page.url().includes('/setup')) {
        const next = page.locator('button').filter({ hasText: /下一步/ }).first();
        if (await next.count() && !await next.isDisabled()) await next.click();
        return false;
      }
      if (page.url().includes('/login')) {
        const quick = page.locator('button').filter({ hasText: '本机安全凭据' }).first();
        if (await quick.count()) await quick.click();
        await delay(1500);
        return false;
      }
      return text.includes('AI 安全助手') && Boolean(await page.locator('#desktop-v2-primary-navigation').count());
    }, Boolean, 240000);
    return { packaged: true, existingProfile: true, title: await page.title() };
  });

  const targets = await apiGet('/targets');
  const target = targets.find(item => item.targetValue === targetValue && item.enabled);
  assert.ok(target, 'Existing authorized target not found: ' + targetValue);
  const baseline = await apiGet('/tasks');
  fs.writeFileSync(path.join(out, 'baseline-task-ids.json'), JSON.stringify(baseline.map(task => ({ id: task.id, targetId: task.targetId, status: task.status })), null, 2));
  const active = baseline.filter(task => task.targetId === target.id && !terminal.has(task.status));
  assert.equal(active.length, 0, 'Target already has active tasks; do not interfere with them');
  const savedThreads = await threads();
  const old = savedThreads.flatMap(thread => thread.targetId === target.id
    ? thread.messages.map(message => ({ thread, message })) : [])
    .find(({ message }) => message.role === 'assistant' && message.approvalId
      && message.steps.length > 4 && !message.taskIds.length && message.approvalStatus === 'APPROVED');
  assert.ok(old, 'The original six-step approved, undispatched plan was not found');
  fs.writeFileSync(path.join(out, 'original-plan-before.json'), JSON.stringify(old, null, 2));

  await check('old-six-step-plan-refused-with-accurate-quota', async () => {
    await navigate('/?conversation=' + encodeURIComponent(old.thread.id));
    if (resumeExisting && old.message.approvalDispatchStatus === 'rejected') {
      assert.match(old.message.approvalDispatchError, /目标 AI 计划超出任务配额（本次 6 项，上限 4 项）/);
      return { approvalId: old.message.approvalId, steps: 6, reason: old.message.approvalDispatchError,
        resumedPreviouslyVerifiedRefusal: true, addedTasks: 0 };
    }
    const article = page.locator('.chat-message.assistant').filter({ has: page.locator('.execution-plan-list li') }).last();
    const retry = article.getByRole('button', { name: /重试原计划|恢复原计划执行|重新校验原方案/ }).first();
    await retry.waitFor({ state: 'visible' });
    await retry.click();
    const response = await until(async () => executionResponses.find(item => item.url.includes('/' + old.message.approvalId + '/execute')),
      Boolean, 120000);
    assert.equal(response.status, 400);
    assert.match(response.data.message, /目标 AI 计划超出任务配额（本次 6 项，上限 4 项）/);
    assert.equal((await apiGet('/tasks')).length, baseline.length);
    const restored = (await threads()).find(thread => thread.id === old.thread.id).messages.find(message => message.id === old.message.id);
    assert.deepEqual(restored.steps, old.message.steps);
    assert.equal(restored.approvalDispatchStatus, 'rejected');
    assert.equal(restored.taskIds.length, 0);
    return { approvalId: old.message.approvalId, steps: 6, status: 400,
      reason: response.data.message, addedTasks: 0, savedPlanPreserved: true };
  });

  let broad;
  await check('real-model-six-check-request-fits-four-step-quota', async () => {
    const previous = resumeExisting ? savedThreads.find(thread => thread.targetId === target.id
      && thread.messages.some(message => message.role === 'user' && message.content.startsWith('请对当前授权目标做信息收集和目录扫描，整体考虑 TCP'))) : undefined;
    broad = previous ? { thread: previous, message: previous.messages.filter(message => message.role === 'assistant').at(-1) }
      : await newConversation('请对当前授权目标做信息收集和目录扫描，整体考虑 TCP 端口探测、Nmap 服务识别、HTTP 响应头检查、HTTP 技术栈信息检查、站点链接爬取、目录扫描这六类检查。请遵守项目和目标当前任务额度，先提交本批能执行的完整方案供我确认；超出额度的其余检查留到后续分批，不能省略本批必需依赖。', target, false);
    assert.ok(broad.message.steps.length > 0 && broad.message.steps.length <= 4);
    assert.equal(broad.message.taskIds.length, 0);
    await dismissApproval();
    assert.equal((await apiGet('/tasks')).length, baseline.length);
    return { steps: broad.message.steps.length, tools: broad.message.steps.map(step => step.toolCode),
      approvalId: broad.message.approvalId, provider: broad.message.provider,
      modelCalls: broad.message.modelUsage?.modelCalls, beforeConfirmationTasksAdded: 0 };
  });

  let small;
  await check('four-built-in-checks-reach-administrator-approval', async () => {
    small = await newConversation('请立即执行当前授权目标的这一批四项检查：HTTP 安全响应头检查（http_headers）、HTTP 技术栈信息泄露检查（http_security_check，check=disclosure）、站点链接爬取（site_crawl）、目录扫描（dir_scan，dictionary=dirb-small，concurrency=2，depth=0）。范围就这四项，请提交执行确认申请，等待管理员在审批窗口允许执行。', target);
    const codes = small.message.steps.map(step => step.toolCode);
    assert.ok(codes.includes('dir_scan'), 'Directory scan explicitly requested but not proposed');
    assert.ok(codes.every(code => ['http_headers', 'http_security_check', 'site_crawl', 'dir_scan'].includes(code)), 'Unexpected tool: ' + codes);
    assert.equal((await apiGet('/tasks')).length, baseline.length);
    return { approvalId: small.message.approvalId, steps: codes.length, tools: codes };
  });

  let dispatched;
  await check('ui-confirmation-dispatches-the-exact-approved-batch', async () => {
    const dialog = page.locator('.ai-approval-modal:visible');
    if (!await dialog.count()) await page.getByRole('button', { name: '查看方案详情' }).last().click();
    await page.locator('.ai-approval-modal:visible').getByRole('button', { name: '允许执行', exact: true }).click();
    dispatched = await until(async () => executionResponses.find(item => item.url.includes('/' + small.message.approvalId + '/execute')), Boolean, 210000);
    assert.equal(dispatched.status, 200, JSON.stringify(dispatched.data));
    assert.equal(dispatched.data.taskIds.length, small.message.steps.length);
    assert.equal(new Set(dispatched.data.taskIds).size, dispatched.data.taskIds.length);
    assert.deepEqual(dispatched.data.plan.steps.map(step => step.toolCode), small.message.steps.map(step => step.toolCode));
    return { approvalId: small.message.approvalId, taskIds: dispatched.data.taskIds, steps: small.message.steps.length };
  });

  await check('real-detection-tasks-finish-and-appear-in-desktop', async () => {
    const records = await until(() => apiGet('/tasks'), items => dispatched.data.taskIds.every(id =>
      items.some(task => task.id === id && terminal.has(task.status))), 300000);
    const related = records.filter(task => dispatched.data.taskIds.includes(task.id));
    fs.writeFileSync(path.join(out, 'executed-tasks.json'), JSON.stringify(related, null, 2));
    assert.equal(records.length, baseline.length + dispatched.data.taskIds.length, 'Unexpected extra tasks');
    await navigate('/tasks');
    await until(() => page.locator('body').innerText(), text => /Web 目录|目录.*探测/.test(text), 30000);
    assert.ok(related.every(task => task.status === 'SUCCESS'), JSON.stringify(related.map(task => ({ id: task.id, tool: task.toolCode, status: task.status, error: task.errorMessage }))));
    return related.map(task => ({ id: task.id, tool: task.toolCode, status: task.status }));
  });
  assert.deepEqual(pageErrors, []);
  await shot('tasks-completed');
  checkpoint('completed');
})().catch(error => {
  console.error(error.stack || error);
  if (!results.some(result => result.status === 'FAIL')) results.push({ name: 'setup-or-final-verification', status: 'FAIL', detail: error.message });
  process.exitCode = 1;
}).finally(async () => {
  fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify({ scope: 'Real rebuilt packaged desktop; existing user profile and authorized test target; real configured LLM; UI-only business writes',
    target: targetValue, elapsedMs: Date.now() - started, results, pageErrors, executionResponses }, null, 2));
  console.log('Evidence: ' + out);
  // Close only the application instance launched by this test, never unrelated processes.
  if (process.env.QUOTA_KEEP_DESKTOP_OPEN !== 'true') await app?.close().catch(() => {});
  if (resumeExisting) process.exit(process.exitCode || 0);
});
