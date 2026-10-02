// Configure only the reviewed HTTP HEAD module through the real workflow UI.
// No scanning, business API calls, storage reads, or login automation.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require('playwright-core');
const { navigate, selectOn, sleep } = require('./lib/ui.cjs');
const OUT = path.resolve(__dirname, '../../../.run/workflow-msf-configuration', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(OUT, { recursive: true });
const MODULE = 'auxiliary/scanner/http/http_header';
const NODE = 'tool-msf_scan-discovery-1';
const result = { status: 'RUNNING', executed: false, saved: false };
function verify(before, after) {
  assert.equal(after.steps.length, before.steps.length);
  assert.equal(after.graph.nodes.length, before.graph.nodes.length);
  assert.deepEqual(after.graph.edges, before.graph.edges);
  for (const section of ['steps', 'graph']) {
    const oldList = section === 'steps' ? before.steps : before.graph.nodes;
    const newList = section === 'steps' ? after.steps : after.graph.nodes;
    for (const old of oldList) {
      const id = section === 'steps' ? 'nodeId' : 'id';
      const next = newList.find(n => n[id] === old[id]); assert.ok(next);
      if (old[id] !== NODE) { assert.deepEqual(next, old); continue; }
      assert.deepEqual({ ...next, parameters: null }, { ...old, parameters: null });
      if (section === 'steps' || next.parameters !== undefined) assert.deepEqual(next.parameters,
        { modules: [MODULE], options: { HTTP_METHOD: 'HEAD', TARGETURI: '/' } });
    }
  }
}
const write = (name, value) => fs.writeFileSync(path.join(OUT, name), JSON.stringify(value, null, 2));
function matches(r, method) { const u = new URL(r.url()); return u.pathname.endsWith('/ai/workflow') && u.searchParams.get('projectId') === '131' && r.request().method() === method; }
function spec(raw) { const s = raw?.data?.graph ? raw.data : raw; assert.ok(s?.steps && s.graph?.nodes); return s; }
let page;
(async () => {
  const browser = await chromium.connectOverCDP('http://127.0.0.1:19229');
  page = browser.contexts().flatMap(c => c.pages()).find(p => p.url().includes('app.asar') && !/startup.html|capture-browser.html/.test(p.url()));
  assert.ok(page); page.setDefaultTimeout(20000);
  assert.ok(await page.locator('#desktop-v2-primary-navigation').isVisible(), 'Login required');
  page.on('response', async r => {
    if (r.request().method() === 'GET' && /msf.*(module|catalog)|(module|catalog).*msf/i.test(new URL(r.url()).pathname)) {
      try { write('catalog-' + Date.now() + '.json', { url: r.url(), body: await r.json() }); } catch {}
    }
  });
  await navigate(page, '红队工作流');
  await page.locator('.editor-head-actions').getByRole('button', { name: '工作流配置', exact: true }).click();
  await selectOn(page, page.locator('#workflow-config-panel .project-select'), '四目标实战全景测试项目-049988', { exact: true });
  await page.getByRole('button', { name: '关闭工作流配置', exact: true }).click();
  const pending = page.waitForResponse(r => matches(r, 'GET'));
  await page.locator('.editor-head-actions').getByRole('button', { name: '重新加载', exact: true }).click();
  const loaded = await pending; assert.ok(loaded.ok());
  const before = spec(await loaded.json()); write('original-get-response.json', before);
  assert.equal(before.revision, 5, 'Review any intervening workflow revision before editing');
  const step = before.steps.find(s => s.nodeId === NODE);
  assert.ok(step && step.tool === 'msf_scan'); assert.equal(step.risk, 'CAUTION'); assert.equal(step.requiresApproval, true);
  assert.deepEqual(step.parameters, {modules:[MODULE]}, 'Existing MSF configuration must be reviewed');
  await sleep(400);
  await page.getByRole('button', { name: '适应画布', exact: true }).click();
  await page.locator(`.vue-flow__node[data-id="${NODE}"] .node-main`).click();
  await page.locator('.workflow-library-tabs').getByText('节点配置', { exact: true }).click();
  const editor = page.locator('[aria-label="已选节点参数"]');
  const input = editor.locator('.el-select').first().locator('input.el-select__input');
  await input.waitFor({ state: 'visible', timeout: 90000 });
  await editor.locator('.el-select').first().click();
  await input.fill(MODULE);
  const option = page.locator('.workflow-msf-select-popper:visible .el-select-dropdown__item').filter({ hasText: MODULE });
  await option.first().waitFor({ state: 'visible' });
  assert.equal(await option.count(), 1, 'Reviewed module must exist uniquely in real catalog');
  if(await option.getAttribute('aria-selected')!=='true' && !(await option.getAttribute('class')||'').includes('is-selected'))await option.click();
  await page.keyboard.press('Escape');
  const rows = editor.locator('.msf-option-row');
  for (const [name, value] of Object.entries({ HTTP_METHOD: 'HEAD', TARGETURI: '/' })) {
    const row = rows.filter({ has: page.locator('.msf-option-name', { hasText: new RegExp('^' + name + '$') }) });
    await row.waitFor({ state: 'visible', timeout: 90000 });
    await row.locator('input').fill(value+' ');
    await row.locator('input').press('Tab');
  }
  await page.screenshot({ path: path.join(OUT, 'reviewed-msf-options.png'), fullPage: true });
  result.visibleOptions = await rows.allInnerTexts();
  // Parent enables only after packaging the reviewed single-module options fix.
  assert.ok(process.argv.includes('--save-reviewed-options'), 'NOT SAVED: --save-reviewed-options requires the newly packaged single-module options fix');
  const savePending = page.waitForResponse(r => matches(r, 'PUT'));
  await page.getByRole('button', { name: '保存工作流', exact: true }).click();
  const saved = await savePending;
  write('submitted-put-request.json', JSON.parse(saved.request().postData()));
  const after = spec(await saved.json()); write('saved-put-response.json', after);
  assert.ok(saved.ok()); verify(before, after); result.saved = true;
  const readPending = page.waitForResponse(r => matches(r, 'GET'));
  await page.locator('.editor-head-actions').getByRole('button', { name: '重新加载', exact: true }).click();
  const reread = await readPending; assert.ok(reread.ok());
  const persisted = spec(await reread.json()); write('new-get-response.json', persisted); verify(before, persisted);
  Object.assign(result, { status: 'PASS', savedRevision: persisted.revision });
  write('results.json', result); console.log('COMPLETE ' + OUT); process.exit(0);
})().catch(async error => {
  Object.assign(result, { status: 'BLOCKED', error: error.message }); write('results.json', result);
  if (page) await page.screenshot({ path: path.join(OUT, 'stopped.png'), fullPage: true }).catch(() => {});
  console.error(error.message); console.log('EVIDENCE ' + OUT); process.exit(1);
});
