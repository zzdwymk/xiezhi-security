/** Read-only display acceptance in the packaged EXE (CDP 19229).
 * Opens only known local-test conversations through the visible sidebar.
 * No prompts, approvals, deletion, storage/cookie reads, viewport changes, or browser.close().
 * Run after packaging: node tests/e2e/verify-chat-display-live.cjs
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const out = path.resolve(__dirname, '../../../.run/chat-display-live', new Date().toISOString().replace(/[:.]/g, '-'));
const expectedTarget = 'AI 本机 HTTP 测试目标 · 2026-10-01 20:38:32'; // Existing target #298 from the reported screenshot.
const knownTitle = /记忆引用验收|请用 fscan/;
const rawCode = /\b(?:fscan_|nmap_service_|nuclei_|afrog_|xray_|zap_|sqlmap_|msf_|http_headers|http_security_check|tcp_ports|retrieve_project_context)/i;
const allowedReferenceLabels = new Set(['授权目标', '检测任务', '安全发现', '漏洞知识', '流量会话', '审计记录', 'AI 服务状态', '功能引用']);
const results = [], modelRequests = [];
let page, selected;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function save() {
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify({
    method: 'Packaged EXE; visible navigation, hover and DOM geometry only',
    expectedTargetId: 298, expectedTarget, selected, results, modelRequests,
  }, null, 2));
}
async function screenshot(name) {
  await page.screenshot({path:path.join(out, name + '.png'), fullPage:true, mask:[page.locator('input[type="password"]')], timeout:15000});
}
async function check(name, run) {
  try { const detail = await run(); results.push({name, status:'PASS', ...detail}); }
  catch (error) { results.push({name, status:'FAIL', error:error.message}); save(); throw error; }
  save(); console.log(JSON.stringify(results.at(-1)));
}
async function openKnownConversation() {
  // Do not dismiss or answer any existing modal on the user's behalf.
  assert.equal(await page.locator('.el-overlay:visible').count(), 0, '请先完成或关闭当前模态窗口后再运行显示验收');
  const nav = page.locator('#desktop-v2-primary-navigation');
  const aiGroup = nav.locator('#nav-group-ai-workspace');
  if (await aiGroup.getAttribute('aria-expanded') !== 'true') await aiGroup.click();
  await nav.locator('button.desktop-v2-nav-item', {hasText:'AI 安全助手'}).click();
  await page.locator('.chat-page').waitFor({state:'visible'});
  const toggle = page.locator('button[aria-controls="desktop-v2-recents-list"]');
  if (await toggle.getAttribute('aria-expanded') !== 'true') await toggle.click();
  const rows = page.locator('.desktop-v2-recent-item');
  const candidates = [];
  for (let index = 0; index < await rows.count(); index++) {
    const title = (await rows.nth(index).locator('.desktop-v2-recent-open strong').innerText()).trim();
    if (knownTitle.test(title)) candidates.push({index, title});
  }
  assert.ok(candidates.length, '最近对话没有“记忆引用验收”或“请用 fscan”本机测试会话；未打开其他会话');
  const inspected = [];
  for (const candidate of candidates) {
    const entry = rows.nth(candidate.index).locator('.desktop-v2-recent-open');
    await entry.scrollIntoViewIfNeeded(); await entry.click();
    await page.locator('.chat-page.has-thread').waitFor({state:'visible'});
    const title = page.locator('.chat-header > div > strong').first();
    for (let attempt = 0; attempt < 40 && (await title.innerText()).trim() !== candidate.title; attempt++) await sleep(100);
    assert.equal((await title.innerText()).trim(), candidate.title, '点击后会话标题未完成切换');
    const target = (await page.locator('.thread-target strong').innerText()).trim();
    const referenceLabels = (await page.locator('.copilot-reference-card header code').allTextContents()).map(value => value.trim());
    inspected.push({...candidate, target, referenceLabels});
    if (target === expectedTarget && referenceLabels.includes('授权目标')) {
      selected = {...candidate, target, referenceLabels};
      return rows.nth(candidate.index);
    }
  }
  throw new Error('已知会话未出现目标298的友好时间和授权目标引用：' + JSON.stringify(inspected));
}
(async () => {
  save(); console.log('RESULTS ' + out);
  const browser = await chromium.connectOverCDP('http://127.0.0.1:19229', {timeout:10000});
  page = browser.contexts().flatMap(context => context.pages()).find(item => item.url().includes('app.asar') && !/startup\.html|capture-browser\.html/.test(item.url()));
  assert.ok(page, '未找到真实打包 EXE 主页面'); page.setDefaultTimeout(15000);
  const navigation = page.locator('#desktop-v2-primary-navigation');
  if (!await navigation.isVisible()) console.log('WAITING_MANUAL_LOGIN');
  await navigation.waitFor({state:'visible', timeout:600000});
  page.on('request', request => {
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'POST' && /\/ai\/(?:agent|dispatches|answers?|plans)(?:\/|$)/.test(pathname)) modelRequests.push({method:request.method(), pathname});
  });
  const row = await openKnownConversation();
  await check('target298-friendly-date-reference-label-and-title', async () => {
    const header = await page.locator('.chat-header').innerText();
    assert.ok(header.includes(expectedTarget));
    assert.ok(!/AI本机HTTP夹具-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z/.test(header));
    assert.ok(!rawCode.test(selected.title), '顶部/最近对话标题仍露出内部工具代码：' + selected.title);
    assert.ok(selected.referenceLabels.every(label => allowedReferenceLabels.has(label)), '引用类型仍含原始枚举');
    await page.locator('.copilot-reference-card').filter({has:page.locator('header code').filter({hasText:/^授权目标$/})}).first().scrollIntoViewIfNeeded();
    await screenshot('friendly-date-and-reference');
    return {header, targetIdEvidence:'已知目标298的唯一旧名称对应北京时间20:38:32；通过实际聊天目标名称和引用卡核对', referenceLabels:selected.referenceLabels};
  });
  await check('recent-delete-icon-centered-on-hover', async () => {
    await row.scrollIntoViewIfNeeded(); await row.hover();
    const button = row.getByRole('button', {name:'删除对话', exact:true});
    await button.hover();
    const geometry = await button.evaluate(element => {
      const rect = node => {const r=node.getBoundingClientRect();return{x:r.x,y:r.y,width:r.width,height:r.height};};
      return {button:rect(element), icon:rect(element.querySelector('.el-icon')), glyph:rect(element.querySelector('.fluent-system-icon')), opacity:getComputedStyle(element).opacity};
    });
    assert.equal(Number(geometry.opacity), 1);
    const center = rect => ({x:rect.x+rect.width/2, y:rect.y+rect.height/2});
    const buttonCenter = center(geometry.button);
    for (const [name, rect] of [['icon', geometry.icon], ['glyph', geometry.glyph]]) {
      const actual = center(rect);
      assert.ok(Math.abs(actual.x-buttonCenter.x)<=0.5 && Math.abs(actual.y-buttonCenter.y)<=0.5, name+'未居中：'+JSON.stringify(geometry));
    }
    await screenshot('recent-delete-hover-centered');
    return {geometry};
  });
  assert.deepEqual(modelRequests, [], '显示验收期间出现模型请求');
  save(); console.log('PASS ' + out);
})().catch(async error => {
  if (!results.some(result => result.status === 'FAIL')) results.push({name:'setup-or-navigation', status:'FAIL', error:error.message});
  save(); if (page) await screenshot('failure').catch(() => {});
  console.error(error.stack); process.exitCode=1;
}).finally(() => {
  // Exiting this test process disconnects CDP without closing the user's EXE.
  save(); process.exit(process.exitCode || 0);
});
