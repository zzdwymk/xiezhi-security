/** Real DOM/stream acceptance against the signed-in desktop app. No scanner execution. */
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require('playwright-core');
const { captureAiWire } = require('../tests/e2e/lib/ai-wire.cjs');

const target = process.env.AI_PLAN_TARGET || '负向目标1-Bing公网域名';
const output = path.resolve(__dirname, '../../.run/target-ai-planning');
const prompt = '评估这个授权目标的检测范围，并生成一份由低风险到高价值、严格遵守端口白名单的检测计划。';
fs.mkdirSync(output, { recursive: true });

(async () => {
  const browser = await chromium.connectOverCDP(process.env.AI_PLAN_CDP || 'http://127.0.0.1:19229');
  const page = browser.contexts().flatMap(context => context.pages())
    .find(candidate => candidate.url().includes('app.asar') && !candidate.url().includes('startup.html'));
  assert(page, 'Desktop main page is not ready');
  page.setDefaultTimeout(15000);
  if (process.env.AI_PLAN_RESTORE_SESSION === '1') {
    const login = page.getByRole('button', { name: '使用本机安全凭据登录', exact: true });
    for (let attempt = 0; attempt < 90; attempt++) {
      if (await page.locator('#desktop-v2-primary-navigation').isVisible()) break;
      if (await login.isVisible()) { await login.click(); break; }
      await page.waitForTimeout(500);
    }
  }
  await page.locator('#desktop-v2-primary-navigation').waitFor({ timeout: 45000 });
  const composer = page.locator('.welcome-composer textarea:visible, .thread-composer textarea:visible').first();
  if (await composer.count()) assert.equal((await composer.inputValue()).trim(), '', 'Preserve existing draft');
  await page.getByRole('button', { name: '新建对话', exact: true }).click();
  await page.getByRole('button', { name: '授权目标', exact: true }).click();
  await page.getByPlaceholder('搜索名称 / 地址 / 类型 / 授权记录').fill(target);
  const row = page.locator('.el-table__row').filter({ hasText: target });
  await row.first().waitFor();
  assert.equal(await row.count(), 1, 'Select exactly one authorized target');
  await row.getByRole('button', { name: 'AI 规划', exact: true }).click();
  await composer.waitFor();
  await page.waitForFunction(expected => Array.from(document.querySelectorAll('textarea')).some(e => e.value === expected), prompt);
  assert.equal(await composer.inputValue(), prompt);
  const capture = await captureAiWire(page);
  const started = Date.now();
  let result;
  try {
    const pending = page.waitForResponse(response => /\/ai\/agent\/stream(?:\?|$)/.test(response.url()) && response.request().method() === 'POST');
    await page.locator('.send-button:visible').click();
    const response = await pending;
    const request = response.request().postDataJSON();
    const events = (await capture.body(response)).toString('utf8').split(/\r?\n/).flatMap(line => {
      try { return [JSON.parse(line.replace(/^data:\s*/, ''))]; } catch { return []; }
    });
    const done = events.findLast(event => event.type === 'done');
    const errors = events.filter(event => event.type === 'error' && !event.data?.recorded);
    result = {
      timestamp: new Date().toISOString(), target, prompt, seconds: (Date.now() - started) / 1000,
      method: 'Playwright DOM clicks against packaged desktop; real backend and model',
      request: { mode: request.mode, executionIntent: request.executionIntent, execute: request.execute,
        targetId: request.targetId, projectId: request.projectId, userPrompt: request.userPrompt },
      httpStatus: response.status(), errors, done,
    };
    fs.writeFileSync(path.join(output, 'result.json'), JSON.stringify(result, null, 2));
    assert(response.ok(), 'AI request HTTP status');
    assert.equal(request.mode, 'plan');
    assert.equal(request.executionIntent, 'AUTO');
    assert.equal(request.userPrompt, prompt);
    assert.equal(errors.length, 0, 'AI stream must finish without error');
    assert(done, 'AI stream must have a done event');
    const reply = done.data?.response || done.data;
    assert.equal(reply.executed, false, 'Planning must not execute');
    assert(!(reply.taskIds || []).length && !(reply.tasks || []).length, 'Planning must not create tasks');
    assert(!reply.approvalId && !(reply.approvalIds || []).length, 'Planning must not submit execution approval');
    assert(reply.message?.trim(), 'Planning must return a reply');
    await composer.waitFor({ state: 'visible' });
    await page.screenshot({ path: path.join(output, 'result.png'), fullPage: true });
    console.log(JSON.stringify({ status: 'PASS', target, seconds: result.seconds, output, message: reply.message,
      executed: reply.executed, taskIds: reply.taskIds, plannerSource: done.data?.plannerSource }, null, 2));
  } finally {
    await capture.close();
    // Disconnect only; keep the user's desktop app and new conversation open.
  }
})().then(() => process.exit(0)).catch(error => { console.error(error.message); process.exit(1); });
