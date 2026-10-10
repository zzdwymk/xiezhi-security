/** Packaged EXE acceptance (CDP 19229). Three authorized text-only model turns.
 * All mutations use visible DOM controls: no business API, app state, storage,
 * cookies, headers, approval clicks, record deletion or viewport changes.
 * Run only after packaging and user login: node tests/e2e/verify-message-edit-live.cjs
 * The source and branch remain available; the EXE is never closed by this script.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const { navigate } = require('./lib/ui.cjs');
const { captureAiWire } = require('./lib/ai-wire.cjs');
const out = path.resolve(__dirname, '../../../.run/message-edit-live', new Date().toISOString().replace(/[:.]/g, '-'));
const stamp = new Date().toISOString().replace(/\D/g, '').slice(4, 14);
const seed = `消息编辑验收${stamp}。请仅用 Markdown 回复：第一行二级标题“编辑验收”，第二段加粗“仅文字回复”。不要运行扫描、工具或修改业务数据。`;
const oldMarker = `旧分支后续文字${stamp}`;
const followup = `请仅用一句话回复“${oldMarker}”。不调用工具，不扫描，不执行任何操作。`;
const edited = `消息编辑新分支${stamp}。请基于前一轮回复，用一条 Markdown 列表说明“编辑创建新分支”。只进行文字回答，不扫描、不调用工具、不修改业务数据。`;
const results = [];
let page;
fs.mkdirSync(out, { recursive: true });
function save() { fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify({ method:'Packaged EXE DOM interaction and passive AI wire; no API/storage access', results }, null, 2)); }
async function check(name, run) {
  try { results.push({ name, status:'PASS', ...await run() }); }
  catch (error) { results.push({ name, status:'FAIL', error:error.message }); save(); throw error; }
  save(); console.log(JSON.stringify(results.at(-1)));
}
const composer = () => page.locator('.welcome-composer textarea:visible, .thread-composer textarea:visible').first();
const users = () => page.locator('article.chat-message.user');
const assistants = () => page.locator('article.chat-message.assistant');
async function shot(name) { await page.screenshot({ path:path.join(out, name + '.png'), fullPage:true, mask:[page.locator('input[type="password"]')], timeout:15000 }); }
function parseWire(bytes) { return bytes.toString('utf8').split(/\r?\n/).flatMap(line => { try { return [JSON.parse(line.replace(/^data:\s*/, ''))]; } catch { return []; } }); }
async function send(text) {
  if (text !== undefined) await composer().fill(text);
  const originalInput = await composer().inputValue();
  const capture = await captureAiWire(page);
  const responsePromise = page.waitForResponse(response => response.request().method() === 'POST' && /\/ai\/(agent|dispatches)\/stream(?:\?|$)/.test(response.url()), { timeout:20000 });
  let response, wire;
  try {
    await page.locator('.send-button:visible').click();
    response = await responsePromise;
    wire = parseWire(await capture.body(response));
  } finally { await capture.close(); }
  assert.ok(response.ok(), `模型请求 HTTP ${response.status()}`);
  const errors = wire.filter(event => event.type === 'error');
  assert.deepEqual(errors.map(event => event.message), [], '模型请求未成功结束');
  const terminal = wire.findLast(event => event.type === 'done' && !event.data?.recorded)?.data;
  assert.ok(terminal?.response, '未收到完整模型终态');
  assert.equal(terminal.plannerSource, 'langchain-grounded', '没有真实模型回答证明');
  assert.equal(terminal.executed === true || terminal.response.executed === true, false, '文字验收意外进入执行');
  assert.deepEqual(terminal.response.taskIds || [], [], '文字验收意外创建检测任务');
  const request = response.request().postDataJSON();
  assert.equal(request.userPrompt, originalInput, '发送的当前原句与输入不一致');
  await composer().waitFor({ state:'visible' });
  await page.waitForFunction(() => { const input=document.querySelector('.thread-composer textarea'); return input && !input.disabled; }, undefined, { timeout:20000 });
  await assistants().last().locator('.message-bubble').waitFor({ state:'visible' });
  return { request, answer:terminal.response.answer, requestEvidence:{ sessionId:request.sessionId, turnId:request.turnId, targetId:request.targetId, projectId:request.projectId, executionIntent:request.executionIntent }, source:terminal.plannerSource };
}
async function snapshotMessages() {
  return page.locator('article.chat-message').evaluateAll(elements => elements.map(element => ({
    role:element.classList.contains('user')?'user':'assistant',
    content:element.querySelector('.message-bubble')?.textContent || '',
    quote:element.querySelector('.message-quote')?.textContent || '',
  })));
}
(async () => {
  console.log('RESULTS ' + out); save();
  const browser = await chromium.connectOverCDP('http://127.0.0.1:19229', { timeout:10000 });
  page = browser.contexts().flatMap(context => context.pages()).find(candidate => candidate.url().includes('app.asar') && !/startup\.html|capture-browser\.html/.test(candidate.url()));
  assert.ok(page, '未找到真实打包 EXE 主页面'); page.setDefaultTimeout(15000);
  await page.locator('#desktop-v2-primary-navigation').waitFor({ state:'visible', timeout:60000 });
  assert.equal(await page.locator('.el-overlay:visible').count(), 0, '存在用户尚未处理的窗口，未继续操作');
  if (await composer().count()) assert.equal((await composer().inputValue()).trim(), '', '当前有未发送草稿，未覆盖草稿');
  assert.equal(await page.locator('.composer-quote:visible, .composer-edit-notice:visible').count(), 0, '当前有引用或编辑草稿，未覆盖草稿');
  await navigate(page, 'AI 安全助手');
  assert.equal((await composer().inputValue()).trim(), '', '助手中有未发送草稿，未创建验收对话');
  assert.equal(await page.locator('.composer-quote:visible, .composer-edit-notice:visible').count(), 0, '助手中有引用或编辑草稿，未创建验收对话');
  await page.getByRole('button', { name:'新对话', exact:true }).click();
  let first, second, branch, sourceTitle, sourceTarget, sourceMessages;
  await check('create-two-text-only-turns-with-quote', async () => {
    first = await send(seed);
    sourceTitle = (await page.locator('.chat-header > div > strong').first().innerText()).trim();
    sourceTarget = (await page.locator('.thread-target strong').innerText()).trim();
    await assistants().first().hover();
    await assistants().first().getByRole('button', { name:'引用消息', exact:true }).click();
    assert.ok((await page.locator('.composer-quote').innerText()).includes('安全助手'));
    second = await send(followup);
    assert.equal(second.request.sessionId, first.request.sessionId);
    assert.notEqual(second.request.turnId, first.request.turnId);
    sourceMessages = await snapshotMessages(); assert.equal(sourceMessages.length, 4);
    return { first:first.requestEvidence, second:second.requestEvidence, sourceTitle, sourceTarget };
  });
  await check('hover-focus-icons-and-copy-format-options', async () => {
    const user = users().first(); await user.hover();
    assert.equal(await user.getByRole('button').count(), 3);
    assert.equal(await assistants().first().getByRole('button').count(), 2);
    await page.mouse.move(0, 0); await user.getByRole('button', { name:'选择复制格式', exact:true }).focus();
    assert.equal(await user.locator('.message-actions').evaluate(element => getComputedStyle(element).pointerEvents), 'auto');
    await user.getByRole('button', { name:'选择复制格式', exact:true }).click();
    await page.getByRole('menuitem', { name:'复制 Markdown', exact:true }).click();
    await composer().focus(); await composer().press('Control+V'); assert.equal(await composer().inputValue(), seed);
    await composer().fill(''); await assistants().first().hover();
    await assistants().first().getByRole('button', { name:'选择复制格式', exact:true }).click();
    await page.getByRole('menuitem', { name:'复制 Markdown', exact:true }).click();
    await composer().focus(); await composer().press('Control+V');
    assert.equal(await composer().inputValue(), first.answer, 'AI 复制内容不是原始 Markdown');
    await composer().fill(''); await assistants().first().hover();
    await assistants().first().getByRole('button', { name:'选择复制格式', exact:true }).click();
    await shot('copy-format-menu');
    await page.getByRole('menuitem', { name:'复制无格式文本', exact:true }).click();
    await composer().focus(); await composer().press('Control+V');
    const visibleText = await assistants().first().locator('.message-bubble').innerText();
    assert.equal((await composer().inputValue()).replace(/\s+/g, ' ').trim(), visibleText.replace(/\s+/g, ' ').trim(), '无格式复制与可见回答文字不一致');
    await composer().fill(''); await shot('toolbar-hover-focus');
    return { copy:'User/assistant raw Markdown and assistant plain text verified by real clipboard paste', sourceMessageCount:sourceMessages.length };
  });
  await check('edit-cancel-restores-draft-and-quote-without-changing-history', async () => {
    await users().first().hover(); await users().first().getByRole('button', { name:'引用消息', exact:true }).click();
    const oldQuote = await page.locator('.composer-quote').innerText();
    await composer().fill('编辑前的未发送草稿 **保留**');
    await users().nth(1).hover(); await users().nth(1).getByRole('button', { name:'编辑消息', exact:true }).click();
    assert.equal(await composer().inputValue(), followup);
    assert.match(await page.locator('.composer-edit-notice').innerText(), /原对话及后续消息保留/);
    assert.ok((await page.locator('.composer-quote').innerText()).includes('安全助手'));
    await composer().fill('取消前的临时修改'); await page.getByRole('button', { name:'取消编辑', exact:true }).click();
    assert.equal(await composer().inputValue(), '编辑前的未发送草稿 **保留**');
    assert.equal(await page.locator('.composer-quote').innerText(), oldQuote);
    assert.deepEqual(await snapshotMessages(), sourceMessages);
    await composer().fill(''); await page.getByRole('button', { name:'取消引用', exact:true }).click();
    return { restoredDraft:true, restoredQuote:true, historyUnchanged:true };
  });
  await check('edited-submit-creates-fresh-session-and-turn-with-prefix-only-context', async () => {
    await users().nth(1).hover(); await users().nth(1).getByRole('button', { name:'编辑消息', exact:true }).click();
    await composer().fill(edited); await shot('before-edited-submit');
    branch = await send();
    assert.notEqual(branch.request.sessionId, first.request.sessionId);
    assert.notEqual(branch.request.turnId, second.request.turnId);
    assert.equal(branch.request.targetId, first.request.targetId); assert.equal(branch.request.projectId, first.request.projectId);
    assert.ok(String(branch.request.prompt).includes(seed), '编辑前的历史没有保留');
    assert.ok(!String(branch.request.prompt).includes(oldMarker), '原消息或后续回答进入了新上下文');
    assert.ok(String(branch.request.prompt).includes('[引用的助手消息]'), '原消息引用没有保留');
    assert.ok(!branch.request.approvalId && !branch.request.confirmationToken, '新请求携带旧审批');
    assert.equal((await page.locator('.thread-target strong').innerText()).trim(), sourceTarget);
    const branchMessages = await snapshotMessages(); assert.equal(branchMessages.length, 4);
    assert.deepEqual(branchMessages.slice(0, 2), sourceMessages.slice(0, 2));
    assert.equal(branchMessages[2].content.trim(), edited);
    assert.equal(branchMessages[2].quote, sourceMessages[2].quote);
    await shot('new-branch');
    return { branch:branch.requestEvidence, earlierMessagesPreserved:true, originalMessageAndLaterReplyExcluded:true, quotePreserved:true };
  });
  await check('source-conversation-remains-unchanged-in-visible-history', async () => {
    const toggle=page.locator('button[aria-controls="desktop-v2-recents-list"]');
    if (await toggle.getAttribute('aria-expanded') !== 'true') await toggle.click();
    const title = page.locator('.desktop-v2-recent-open strong').filter({ hasText:new RegExp('^' + sourceTitle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$') });
    await title.scrollIntoViewIfNeeded(); await title.click();
    await page.waitForFunction(expected => document.querySelector('.chat-header > div > strong')?.textContent.trim() === expected, sourceTitle);
    assert.deepEqual(await snapshotMessages(), sourceMessages);
    await shot('original-retained');
    return { sourceTitle, sourceMessageCount:sourceMessages.length, sourceUnchanged:true };
  });
  console.log('PASS ' + out);
})().catch(async error => {
  if (!results.some(result => result.status === 'FAIL')) results.push({ name:'setup', status:'FAIL', error:error.message });
  save(); if (page) await shot('failure').catch(() => {}); console.error(error.stack); process.exitCode=1;
}).finally(() => { save(); process.exit(process.exitCode || 0); });
