/** Live EXE check: one DOM-only text request, passive SSE observation.
 * No storage/cookies/credentials, API calls, route interception, or fake messages.
 * Usage (EXE already logged in, with a selected AI conversation scope):
 *   node tests/e2e/verify-ai-timing-live.cjs
 * Leaves the EXE open. Output: .run/ai-timing-live/<timestamp>/
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const { navigate, sleep } = require('./lib/ui.cjs');
const OUT = path.resolve(__dirname, '../../../.run/ai-timing-live', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(OUT, { recursive: true });
const result = { status: 'RUNNING', method: 'One real DOM request; passive SSE; DOM text and screenshots', checks: [] };
let page;
function save() { fs.writeFileSync(path.join(OUT, 'result.json'), JSON.stringify(result, null, 2)); }
function check(name, condition, detail) {
  result.checks.push({ name, status: condition ? 'PASS' : 'FAIL', detail }); save();
  assert.ok(condition, name + ': ' + JSON.stringify(detail));
}
function elapsedSeconds(text) {
  if (text.trim() === '不足 1 秒') return 0;
  const minutes = /([0-9]+)\s*分/.exec(text), seconds = /([0-9]+)\s*秒/.exec(text);
  return minutes || seconds ? Number(minutes?.[1] || 0) * 60 + Number(seconds?.[1] || 0) : NaN;
}
function parseSSE(text) {
  try { return [JSON.parse(text)]; } catch {}
  // The Electron relay can expose newline-delimited JSON as well as SSE data lines.
  return text.split(/\r?\n/).flatMap(line => {
    try { return [JSON.parse(line.replace(/^data:\s*/, ''))]; } catch { return []; }
  });
}
(async () => {
  const browser = await chromium.connectOverCDP('http://127.0.0.1:19229', { timeout: 10000 });
  page = browser.contexts().flatMap(context => context.pages()).find(p => p.url().includes('app.asar') && !/startup\.html|capture-browser\.html/.test(p.url()));
  assert.ok(page, '未找到打包 EXE 主页面');
  page.setDefaultTimeout(15000);
  await page.locator('#desktop-v2-primary-navigation').waitFor({ state: 'visible' });
  await navigate(page, 'AI 安全助手');
  const composer = page.locator('.welcome-composer textarea:visible, .thread-composer textarea:visible').first();
  await composer.waitFor();
  assert.ok(await composer.isEnabled(), '当前已有请求运行；没有发送新的请求');
  assert.equal((await composer.inputValue()).trim(), '', '输入框已有草稿，保留草稿并停止');
  const prompt = '本轮仅作文字问答，不执行扫描、不访问地址、不调用检测工具、不创建检测任务。请用两句话解释参数化查询为什么能够防止 SQL 注入。';
  await composer.fill(prompt);
  const countBefore = await page.locator('article.chat-message.assistant').count();
  let requestStart, requestEnd;
  const streamPattern = /\/ai\/(agent|dispatches)\/stream(?:\?|$)/;
  page.on('request', request => { if (streamPattern.test(request.url()) && request.method() === 'POST') requestStart = performance.now(); });
  page.on('requestfinished', request => { if (streamPattern.test(request.url()) && request.method() === 'POST') requestEnd = performance.now(); });
  const responsePromise = page.waitForResponse(response => streamPattern.test(response.url()) && response.request().method() === 'POST', { timeout: 20000 });
  const clickStart = performance.now();
  result.sentAt = new Date().toISOString();
  await page.locator('.send-button:visible').click();
  const response = await responsePromise;
  const wire = parseSSE((await Promise.race([response.body(), sleep(180000).then(() => { throw new Error('SSE 超过180秒未结束'); })])).toString('utf8'));
  const bodyReadEnd = performance.now();
  check('received actual SSE', response.status() === 200 && wire.length > 0, { status: response.status(), events: wire.length });
  await page.waitForFunction(before => document.querySelectorAll('article.chat-message.assistant').length > before, countBefore);
  const article = page.locator('article.chat-message.assistant').last();
  const panel = article.locator('.ai-progress-panel');
  await panel.waitFor();
  for (let i = 0; i < 120; i++) {
    if (await composer.isEnabled() && !await panel.locator('[role="progressbar"]').count()) break;
    await sleep(250);
  }
  const observedFinished = performance.now();
  check('terminal UI observed', await composer.isEnabled() && !await panel.locator('[role="progressbar"]').count(), await panel.innerText());
  const label = await panel.locator('.progress-elapsed').innerText();
  const seconds = elapsedSeconds(label);
  const wireSeconds = ((requestEnd || bodyReadEnd) - clickStart) / 1000;
  result.timing = { displayed: label, displayedSeconds: seconds, clickToStreamEndSeconds: wireSeconds, requestSeconds: requestStart ? ((requestEnd || bodyReadEnd) - requestStart) / 1000 : null, clickToTerminalObservationSeconds: (observedFinished - clickStart) / 1000, toleranceSeconds: 2 };
  check('display agrees with observed request wall time within 2 seconds', Number.isFinite(seconds) && Math.abs(seconds - wireSeconds) <= 2, result.timing);
  await sleep(3100);
  const laterLabel = await panel.locator('.progress-elapsed').innerText();
  check('completed elapsed stays fixed after 3 seconds', laterLabel === label, { before: label, after: laterLabel });
  const eventSummary = wire.map(event => ({ type: event.type, status: event.status, recorded: event.recorded || event.data?.recorded || false, eventTiming: event.eventTiming || event.data?.eventTiming }));
  result.events = eventSummary;
  const taskIds = wire.flatMap(event => [event.taskIds, event.data?.taskIds, event.data?.response?.taskIds].flatMap(value => Array.isArray(value) ? value : []));
  check('ordinary answer created no detected tasks', taskIds.length === 0 && await panel.locator('.progress-tool-call').count() === 0, { taskIds });
  check('no live stream error', !eventSummary.some(event => event.type === 'error' && !event.recorded && event.eventTiming !== 'VERIFIED_RECORD'), eventSummary.filter(event => event.type === 'error'));
  const toggle = panel.locator('.progress-toggle');
  if (await toggle.getAttribute('aria-expanded') !== 'true') await toggle.click();
  const rows = await panel.locator('.progress-timeline li').allTextContents();
  result.displayedRecords = rows;
  check('historical rows are not active after completion', await panel.locator('.progress-timeline li.active, .progress-milestones li.active').count() === 0, { rows: rows.length });
  const replayCount = eventSummary.filter(event => event.recorded || event.eventTiming === 'VERIFIED_RECORD').length;
  if (replayCount) check('actual verified replay is visibly labelled', rows.some(text => text.includes('补发记录')), { wireReplayCount: replayCount, labelledRows: rows.filter(text => text.includes('补发记录')).length });
  else result.checks.push({ name: 'actual verified replay is visibly labelled', status: 'NOT_OBSERVED', detail: '本次服务端未返回补发事件，不能据此验证补发标签' });
  check('timing explanation does not equate events with actions', (await panel.locator('.progress-note').innerText()).includes('流程记录数量不等于模型调用或实际检测次数'), await panel.locator('.progress-note').innerText());
  await panel.scrollIntoViewIfNeeded();
  await page.screenshot({ path: path.join(OUT, 'expanded-conversation.png'), fullPage: true });
  await article.screenshot({ path: path.join(OUT, 'assistant-avatar-and-progress.png') });
  const avatars = page.locator('article.chat-message .conversation-avatar');
  check('real user and assistant avatars are rendered', await article.locator('.conversation-avatar').count() === 1 && await page.locator('article.chat-message.user .conversation-avatar').count() > 0, { count: await avatars.count() });
  result.answer = await article.locator('.message-bubble').innerText();
  result.status = 'PASS'; save(); console.log(JSON.stringify({ status: result.status, output: OUT, timing: result.timing }));
})().catch(async error => {
  result.status = 'FAIL'; result.error = error.message;
  if (page) await page.screenshot({ path: path.join(OUT, 'failure.png'), fullPage: true }).catch(() => {});
  save(); console.error(error); process.exitCode = 1;
}).finally(() => { console.log('Evidence: ' + OUT); process.exit(process.exitCode || 0); });
