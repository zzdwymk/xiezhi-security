/** Packaged EXE: real-model chat, quote cancellation/history, scoped memory deletion.
 * Prepare/use only an independent AI本机闭环验收 project. All business actions are DOM
 * clicks/inputs; response inspection is passive. No API calls, storage access, scans,
 * conversation deletion, global clear, or browser.close(). The EXE remains open.
 *
 * New independent project/target:
 *   node tests/e2e/verify-ai-memory-references-live.cjs
 * Explicit existing fixture scope (all four arguments required):
 *   node tests/e2e/verify-ai-memory-references-live.cjs --project=123 \
 *     --project-name=AI本机闭环验收-... --target=456 --target-name=AI本机HTTP夹具-...
 * --only=references|memory|references,memory (default both).
 * Memory mode deletes this run's seed summary and clears ALL remaining summaries
 * in the explicitly selected fixture project. Local conversations/tasks are retained.
 * Deleting retrieval summaries does not erase model context or local chat history;
 * this script never treats fresh-session amnesia as proof that deletion succeeded.
 */
const fs = require('node:fs');
const path = require('node:path');
const harness = require('./verify-ai-local-fixture.cjs');
const { navigate, waitRow, sleep } = require('./lib/ui.cjs');
const PREFIX = 'AI本机闭环验收-';
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const marker = `记忆引用验收 ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }).replace(/\//g, '-')}`;
const out = path.resolve(__dirname, '../../../.run/ai-memory-references', stamp);
const results = [];
const ownedMemories = [];
let page, scope, sessionId, historyTitle, seed;
function arg(name) { return process.argv.find(v => v.startsWith(`--${name}=`))?.slice(name.length + 3); }
const requested = { projectId: arg('project') || arg('project-id'), projectName: arg('project-name'),
  targetId: arg('target') || arg('target-id'), targetName: arg('target-name') };
const selected = new Set((arg('only') || 'references,memory').split(','));
function assert(ok, message, detail) {
  if (!ok) { const error = new Error(message); error.detail = detail; throw error; }
}
function save() {
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify({ updatedAt: new Date().toISOString(),
    method: 'Packaged EXE DOM actions; passive response inspection; real model required',
    scope, marker, sessionId, historyTitle, ownedMemories, selected: [...selected], results }, null, 2));
}
async function step(id, fn) {
  const start = Date.now();
  console.log('START ' + id);
  try {
    const detail = await fn();
    if (page) await page.screenshot({ path: path.join(out, `${id}.png`), fullPage: true,
      mask: [page.locator('input[type="password"]')] });
    results.push({ id, status: 'PASS', seconds: +((Date.now() - start) / 1000).toFixed(1), ...detail });
    save();
  } catch (error) {
    if (page) await page.screenshot({ path: path.join(out, `${id}-failed.png`), fullPage: true,
      mask: [page.locator('input[type="password"]')] }).catch(() => {});
    results.push({ id, status: 'FAIL', seconds: +((Date.now() - start) / 1000).toFixed(1),
      error: String(error.message), detail: error.detail });
    save(); throw error;
  }
}
function composer() { return page.locator('.welcome-composer textarea:visible, .thread-composer textarea:visible').first(); }
function urlOf(response) { return new URL(response.url()); }
function memoryResponse(method, docId) {
  const suffix = docId ? `/ai/memories/${encodeURIComponent(docId)}` : '/ai/memories';
  return page.waitForResponse(response => response.request().method() === method
    && urlOf(response).pathname.endsWith(suffix)
    && Number(urlOf(response).searchParams.get('projectId')) === scope.projectId,
  { timeout: 30000 }).catch(error => ({ waitError: error.message }));
}
async function jsonResponse(pending, label) {
  const response = await pending;
  assert(response && !response.waitError, label + ' 未观察到界面响应', response);
  assert(response.ok(), label + ' HTTP ' + response.status());
  return response.json();
}
async function send(prompt) {
  await composer().waitFor({ state: 'visible' });
  const sw = page.getByRole('switch', { name: 'AI 执行模式' });
  const legacyMode = await sw.count() > 0;
  if (legacyMode && await sw.getAttribute('aria-checked') === 'true')
    await page.locator('.el-switch').filter({ has: sw }).locator('.el-switch__core').click();
  if (legacyMode) assert(await sw.getAttribute('aria-checked') === 'false', '必须关闭AI执行模式');
  await composer().fill(prompt);
  const streamPending = page.waitForResponse(r => /\/ai\/agent\/stream(?:\?|$)/.test(r.url())
    && r.request().method() === 'POST', { timeout: 30000 }).catch(error => ({ waitError: error.message }));
  // Wait for the UI's best-effort persistence before navigation/deletion to avoid late writes.
  const memoryPending = page.waitForResponse(r => urlOf(r).pathname.endsWith('/ai/memories')
    && r.request().method() === 'POST' && r.request().postDataJSON()?.prompt === prompt,
  { timeout: 240000 }).catch(error => ({ waitError: error.message }));
  await page.locator('.send-button:visible').click();
  const response = await streamPending;
  assert(!response.waitError && response.ok(), 'AI流响应失败', response.waitError);
  const request = response.request().postDataJSON();
  assert(Number(request.projectId) === scope.projectId && Number(request.targetId) === scope.targetId
    && (legacyMode ? request.execute === false : request.executionIntent === 'AUTO' && request.userPrompt === prompt), 'AI请求超出明确的夹具作用域');
  if (sessionId) assert(request.sessionId === sessionId, '对话会话ID意外变化');
  sessionId = request.sessionId;
  const wire = harness.parseWire(await response.text());
  const terminal = wire.findLast(event => event.type === 'done')?.data;
  assert(terminal && !wire.some(event => event.type === 'error'), 'AI流缺少完成事件或包含错误', {
    httpStatus: response.status(), errors: wire.filter(event => event.type === 'error'),
  });
  assert(terminal.plannerSource === 'langchain-grounded', '必须取得真实模型langchain-grounded回答');
  assert(!(terminal.executed || terminal.response?.executed)
    && !(terminal.taskIds || terminal.response?.taskIds || []).length, '文字验收意外创建检测任务');
  await page.locator('.thread-composer textarea:enabled').waitFor({ timeout: 30000 });
  const answer = await page.locator('article.chat-message.assistant .message-bubble.markdown-body').last().innerText();
  assert(answer.trim().length > 15, '模型正文缺失或过短');
  const memoryResponse = await memoryPending;
  assert(!memoryResponse.waitError && memoryResponse.ok(), '模型回答未完成真实记忆持久化', memoryResponse.waitError);
  const memoryRequest = memoryResponse.request().postDataJSON();
  assert(Number(memoryRequest.projectId) === scope.projectId && Number(memoryRequest.targetId) === scope.targetId
    && memoryRequest.conversationId === sessionId, '记忆保存的项目/目标/会话边界错误');
  const memory = await memoryResponse.json();
  assert(memory.id && memory.title, '记忆保存未返回ID与摘要标题');
  ownedMemories.push({ id: memory.id, title: memory.title });
  return { prompt, answer, memory, requestPrompt: request.prompt, answerSource: terminal.plannerSource,
    request: { projectId: request.projectId, targetId: request.targetId, sessionId, execute: request.execute } };
}
async function openScopedChat() {
  await navigate(page, 'AI 安全助手');
  await page.getByRole('button', { name: '新对话', exact: true }).click();
  const targetList = page.waitForResponse(r => urlOf(r).pathname.endsWith('/targets')
    && !/\/projects\//.test(urlOf(r).pathname) && r.request().method() === 'GET', { timeout: 30000 })
    .catch(error => ({ waitError: error.message }));
  const projectLinks = page.waitForResponse(r => urlOf(r).pathname.endsWith(`/projects/${scope.projectId}/targets`)
    && r.request().method() === 'GET', { timeout: 30000 }).catch(error => ({ waitError: error.message }));
  await navigate(page, '授权目标');
  const targetRows = await jsonResponse(targetList, '界面加载授权目标');
  const links = await jsonResponse(projectLinks, '界面加载项目目标绑定');
  const target = targetRows.find(item => Number(item.id) === scope.targetId && item.name === scope.targetName);
  assert(target && new URL(target.targetValue).hostname === '127.0.0.1', '目标ID、名称或本机地址不一致');
  assert(links.some(item => Number(item.targetId) === scope.targetId), '指定目标不属于明确的夹具项目');
  await page.getByPlaceholder('搜索名称 / 地址 / 类型 / 授权记录').fill(scope.targetName);
  const row = await waitRow(page, scope.targetName, 15000);
  assert(await row.count() === 1, '目标名称必须唯一');
  assert((await row.innerText()).includes(target.targetValue), '目标行地址与已核对的记录不一致');
  await row.getByRole('button', { name: 'AI 规划', exact: true }).click();
  await composer().waitFor({ state: 'visible' });
  await page.locator('.target-picker').filter({ hasText: harness.displayedTargetName(scope.targetName) }).waitFor({ state: 'visible', timeout: 30000 });
  assert((await page.locator('.target-picker').innerText()).includes(harness.displayedTargetName(scope.targetName)), 'AI入口选中了其他目标');
}
async function assertMemoryScope() {
  assert(scope.projectName.startsWith(PREFIX) && Number.isSafeInteger(scope.projectId)
    && scope.projectId > 0, '拒绝触及非独立验收项目');
  const expectedName = new RegExp('^' + scope.projectName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$');
  await page.locator('.project-detail-page .section-head h3').filter({ hasText: expectedName })
    .waitFor({ state: 'visible', timeout: 30000 });
  await page.locator('.project-detail-page > .el-loading-mask:visible').waitFor({ state: 'hidden', timeout: 60000 });
  const heading = await page.locator('.project-detail-page .section-head h3').innerText();
  assert(heading.trim() === scope.projectName, '当前项目标题与明确作用域不一致');
  const route = page.url().split('#')[1] || '';
  assert(new RegExp(`^/projects/${scope.projectId}(?:[/?]|$)`).test(route), '当前项目路由ID不一致');
}
async function listMemoryByUi() {
  await assertMemoryScope();
  const pending = memoryResponse('GET');
  await page.getByRole('button', { name: '刷新记忆', exact: true }).click();
  const rows = await jsonResponse(pending, '刷新项目记忆');
  assert(Array.isArray(rows), '项目记忆列表不是数组');
  await page.locator('#pane-memory .el-loading-mask:visible').waitFor({ state: 'hidden' }).catch(() => {});
  return rows;
}
async function ownedMemoryRow(memory, total) {
  assert(ownedMemories.some(item => item.id === memory.id && item.title === memory.title), '拒绝删除本轮未创建的单条摘要');
  const pane = page.locator('#pane-memory');
  const firstPage = pane.locator('.el-pager li.number').filter({ hasText: /^1$/ });
  if (await firstPage.count()) await firstPage.click();
  const row = pane.locator('.el-table__row').filter({ hasText: memory.title });
  for (let pageIndex = 0; pageIndex <= Math.ceil(total / 20); pageIndex++) {
    if (await row.count() === 1) return row;
    assert(await row.count() === 0, '本次种子摘要标题重复，拒绝删除');
    const next = pane.locator('.el-pagination .btn-next');
    if (!await next.count() || await next.isDisabled()) break;
    await next.click(); await sleep(150);
  }
  throw new Error('通过记忆表格分页未找到本轮种子摘要，拒绝删除其他行');
}
async function openMemories() {
  await navigate(page, '评估项目');
  await page.getByPlaceholder('搜索项目名称 / 负责人 / 说明').fill(scope.projectName);
  const row = await waitRow(page, scope.projectName, 15000);
  assert(await row.count() === 1, '项目名称必须唯一');
  await row.getByRole('button', { name: '进入项目', exact: true }).click();
  await page.locator('.project-detail-page .section-head h3').waitFor();
  await assertMemoryScope();
  await page.getByRole('tab', { name: 'AI 记忆', exact: true }).click();
  return listMemoryByUi();
}
function confirmation() { return page.locator('.el-message-box:visible'); }
async function cancelAndAssertNoDelete(open, expectedTitle) {
  const deletes = [];
  const observer = response => { if (response.request().method() === 'DELETE'
    && /\/ai\/memories(?:\/|$)/.test(urlOf(response).pathname)) deletes.push(response.url()); };
  page.on('response', observer);
  try {
    await open();
    assert((await confirmation().innerText()).includes(expectedTitle), '确认框与当前操作不一致');
    await confirmation().getByRole('button', { name: '取消', exact: true }).click();
    await confirmation().waitFor({ state: 'hidden' });
    await listMemoryByUi();
    assert(deletes.length === 0, '取消后仍发送了删除请求', { deletes });
  } finally { page.off('response', observer); }
}
async function references() {
  const firstAssistant = page.locator('article.chat-message.assistant').first();
  await step('reference-cancel', async () => {
    await firstAssistant.getByRole('button', { name: '引用', exact: true }).click();
    await page.locator('.composer-quote').waitFor();
    const prompt = `${marker}-取消引用：仅文字回答，请计算19加23，并说明没有执行任何检测。`;
    await composer().fill(prompt);
    await page.getByRole('button', { name: '取消引用', exact: true }).click();
    assert(await page.locator('.composer-quote').count() === 0, '取消后引用草稿仍显示');
    assert(await composer().inputValue() === prompt, '取消引用误清空了正文草稿');
    const result = await send(prompt);
    assert(!result.requestPrompt.includes('[引用的助手消息]') && !result.requestPrompt.includes('[引用的用户消息]'),
      '取消的引用仍被发送给模型');
    assert(await page.locator('article.chat-message.user').last().locator('.message-quote').count() === 0,
      '取消后发送的消息仍显示引用卡片');
    assert(result.answer.includes('42'), '真实模型未正确回答取消引用后的问题');
    return result;
  });
  await step('reference-send', async () => {
    await firstAssistant.getByRole('button', { name: '引用', exact: true }).click();
    const result = await send(`${marker}-保留引用：请根据引用的助手消息复述代号和测试数字，只做文字回答，不执行检测。`);
    const quotedText = result.requestPrompt.match(/\[引用的助手消息\]\n([\s\S]*?)\n\[引用结束\]/)?.[1] || '';
    assert(quotedText.includes('栖霞') && quotedText.includes('71'), '已发送引用未传递种子助手消息内容');
    assert(await page.locator('article.chat-message.user').last().locator('.message-quote').isVisible(), '发送后缺少引用卡片');
    assert(await page.locator('.composer-quote').count() === 0, '发送后引用草稿未复位');
    return result;
  });
  await step('history-restore', async () => {
    historyTitle = (await page.locator('.chat-header > div > strong').first().innerText()).trim();
    const beforeMessages = await page.locator('article.chat-message').count();
    await page.getByRole('button', { name: '新对话', exact: true }).click();
    assert(await page.locator('.composer-quote').count() === 0 && await composer().inputValue() === '', '新对话残留旧草稿');
    const history = page.locator('.desktop-v2-recent-open').filter({ has: page.getByText(historyTitle, { exact: true }) });
    assert(await history.count() === 1, '本次新建会话的历史入口不唯一');
    await history.click();
    await page.locator('.thread-composer').waitFor();
    await page.waitForURL(url => {
      const query = url.hash.startsWith('#/') ? url.hash.slice(url.hash.indexOf('?') + 1) : url.search;
      return new URLSearchParams(query).get('conversation') === sessionId;
    }, { timeout: 10000 });
    assert(await page.locator('article.chat-message').count() === beforeMessages, '历史恢复丢失消息');
    assert(await page.locator('article.chat-message.user .message-quote').count() === 1, '历史恢复丢失或增加已发送引用');
    assert(await page.locator('.composer-quote').count() === 0, '历史恢复错误恢复了已消费的引用草稿');
    const result = await send(`${marker}-历史追问：依据这段会话已有记录，复述最初代号，并把最初测试数字乘以3。仅回答文字，不执行检测。`);
    assert(result.answer.includes('栖霞') && result.answer.includes('213'), '历史会话的真实模型未正确延续上下文');
    return { ...result, beforeMessages, note: '恢复原会话、目标、全部历史消息和已发送引用；不恢复已消费引用草稿。' };
  });
}
async function memories() {
  await step('memory-delete', async () => {
    const before = await openMemories();
    assert(before.some(row => row.id === seed.memory.id), '本次真实模型种子摘要未出现在项目记忆');
    const row = await ownedMemoryRow(seed.memory, before.length);
    await cancelAndAssertNoDelete(() => row.getByRole('button', { name: '删除', exact: true }).click(), '确认删除');
    const afterCancel = await listMemoryByUi();
    assert(afterCancel.some(item => item.id === seed.memory.id), '取消删除后种子摘要已消失');
    await assertMemoryScope();
    await row.getByRole('button', { name: '删除', exact: true }).click();
    assert((await confirmation().innerText()).includes('删除这条对话记忆'), '缺少单条记忆删除确认');
    const pending = memoryResponse('DELETE', seed.memory.id);
    await confirmation().getByRole('button', { name: /^(确定|确认|OK)$/ }).click();
    const deleted = await jsonResponse(pending, '删除本次种子记忆');
    assert(deleted.deleted === true, '服务端未确认单条删除成功');
    const after = await listMemoryByUi();
    assert(!after.some(item => item.id === seed.memory.id), '刷新后仍存在已删除的摘要ID');
    assert(await row.count() === 0, '删除后UI仍显示种子摘要');
    return { deletedMemoryId: seed.memory.id, beforeCount: before.length, afterCount: after.length };
  });
  await step('memory-clear', async () => {
    const before = await listMemoryByUi();
    assert(before.length > 0, '清空验收需要至少一条剩余的真实模型记忆');
    await cancelAndAssertNoDelete(() => page.getByRole('button', { name: '清空记忆', exact: true }).click(), '清空 AI 记忆');
    const afterCancel = await listMemoryByUi();
    assert(JSON.stringify(afterCancel.map(r => r.id).sort()) === JSON.stringify(before.map(r => r.id).sort()),
      '取消清空后记忆列表发生变化');
    await assertMemoryScope();
    await page.getByRole('button', { name: '清空记忆', exact: true }).click();
    assert((await confirmation().innerText()).includes(`本项目全部 ${before.length} 条`), '清空确认数量不一致');
    const pending = memoryResponse('DELETE');
    await confirmation().getByRole('button', { name: '全部清空', exact: true }).click();
    const cleared = await jsonResponse(pending, '清空明确指定的夹具项目记忆');
    assert(Number(cleared.projectId) === scope.projectId && Number(cleared.deleted) === before.length, '清空结果项目或数量错误');
    const after = await listMemoryByUi();
    assert(after.length === 0, '刷新后项目记忆未清空');
    await page.getByText('暂无项目级 AI 记忆', { exact: true }).waitFor();
    assert(await page.getByRole('button', { name: '清空记忆', exact: true }).isDisabled(), '空列表清空按钮仍可用');
    return { projectId: scope.projectId, clearedCount: cleared.deleted,
      note: '仅清空明确选中的夹具项目摘要；保留本机聊天、任务和其他项目。未发送后续消息以免重新生成摘要。' };
  });
  await step('memory-clear-retains-history', async () => {
    const history = page.locator('.desktop-v2-recent-open').filter({ has: page.getByText(historyTitle, { exact: true }) });
    assert(await history.count() === 1, '清空摘要意外删除了本轮聊天历史入口');
    await history.click();
    await page.locator('.thread-composer').waitFor();
    const firstAnswer = await page.locator('article.chat-message.assistant .message-bubble.markdown-body').first().innerText();
    assert(firstAnswer === seed.answer, '清空检索摘要意外修改了本机历史消息');
    return { sessionId, note: '已清空的服务端摘要与保留的本机聊天历史语义独立；未向模型再次发送消息。' };
  });
}
async function main() {
  assert(selected.size && [...selected].every(value => ['references', 'memory'].includes(value)), '--only只支持references,memory');
  if (Object.values(requested).some(Boolean)) {
    assert(Object.values(requested).every(Boolean), '使用现有项目必须同时明确传入项目ID/名称和目标ID/名称');
    scope = { ...requested, projectId: Number(requested.projectId), targetId: Number(requested.targetId), explicit: true };
    assert(scope.projectName.startsWith(PREFIX) && Number.isSafeInteger(scope.projectId) && scope.projectId > 0
      && Number.isSafeInteger(scope.targetId) && scope.targetId > 0, '现有项目必须是明确指定的AI本机闭环验收项目');
  }
  save(); console.log('RESULTS ' + out);
  await step('exe-attach', async () => { const result = await harness.attach(); page = harness.state().page; return result; });
  await step('fixture-scope', async () => {
    if (!scope) {
      await harness.createProject(); await harness.activateProject(); await harness.createTarget();
      const current = harness.state();
      scope = { projectId: current.projectId, projectName: current.projectName,
        targetId: current.targetId, targetName: current.targetName, createdByThisRun: true };
    }
    await openMemories(); // Check project identity before any model activity or delete controls.
    await openScopedChat();
    return { scope, note: '仅文字对话；不启动夹具HTTP服务器、不扫描。' };
  });
  await step('real-model-memory-seed', async () => {
    seed = await send(`${marker}：仅做文字记录，不执行检测。请记住代号栖霞、测试数字71，复述两项内容并说明仅作对话验收。`);
    assert(seed.answer.includes('栖霞') && seed.answer.includes('71'), '真实模型未复述种子记录');
    historyTitle = (await page.locator('.chat-header > div > strong').first().innerText()).trim();
    return seed;
  });
  if (selected.has('references')) await references();
  else await step('real-model-followup', async () => {
    const result = await send(`${marker}-追问：只做文字回答，把上一轮测试数字乘以3，并复述代号。`);
    assert(result.answer.includes('栖霞') && result.answer.includes('213'), '真实模型未正确延续会话');
    return result;
  });
  if (selected.has('memory')) await memories();
  console.log('COMPLETE ' + out);
}
if (require.main === module) main().then(() => process.exit(0)).catch(error => {
  console.error(String(error.message)); save(); process.exit(1);
});
