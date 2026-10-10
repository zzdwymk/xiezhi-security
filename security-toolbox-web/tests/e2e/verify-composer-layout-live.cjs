/** Actual packaged Electron composer layout acceptance, CDP 19229.
 * DOM controls only. No navigation, sends, API/storage access or resizing.
 * Requires an already visible, empty, wide AI composer; preserves user drafts.
 */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const out = path.resolve(__dirname, '../../../.run/composer-layout-live', new Date().toISOString().replace(/[:.]/g, '-'));
const marker = `预览末行验收-${Date.now()}`;
const source = '# 输入布局验收\n\n**仅本地预览，不发送消息。**\n\n' + Array.from({ length:45 }, (_, i) => `- 第 ${i + 1} 行：左右两栏分别滚动，编辑原文保持完整。`).join('\n') + `\n\n${marker}`;
const results = [];
let page, editor, parent, initialUrl, originalExpanded, inserted = false;
fs.mkdirSync(out, { recursive:true });
function save() { fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify({ method:'Packaged Electron visible DOM only; synthetic unsent draft; no navigation/API/storage', results }, null, 2)); }
async function shot(name) { await page.screenshot({ path:path.join(out, name + '.png'), fullPage:true, mask:[page.locator('input[type="password"]')], timeout:15000 }); }
async function check(name, action) {
  try { results.push({ name, status:'PASS', ...await action() }); }
  catch (error) { results.push({ name, status:'FAIL', error:error.message }); throw error; }
  finally { save(); }
  console.log(JSON.stringify(results.at(-1)));
}
async function guard(expected) {
  assert.equal(page.url(), initialUrl, '页面已变化，停止操作');
  assert.equal(await page.locator('.el-overlay:visible, [role="dialog"]:visible, .composer-quote:visible, .composer-edit-notice:visible').count(), 0, '出现用户对话框、引用或编辑状态，停止操作');
  assert.equal(await editor.evaluate(el => el.isConnected && !el.disabled && el.getClientRects().length > 0), true, '原编辑框不再可用');
  assert.equal(await editor.inputValue(), expected, '用户草稿已变化，停止操作并保留');
}
async function geometry() {
  return parent.evaluate(el => {
    const input = el.querySelector('textarea');
    const preview = el.querySelector('.composer-preview');
    const rect = node => { const r=node.getBoundingClientRect(); return { x:r.x, y:r.y, width:r.width, height:r.height, right:r.right, bottom:r.bottom }; };
    const style = getComputedStyle(preview);
    return { editor:rect(input), preview:rect(preview), toggle:rect(preview.querySelector('button')), marginTop:parseFloat(style.marginTop), marginBottom:parseFloat(style.marginBottom), maxHeight:getComputedStyle(input).maxHeight, overflowY:getComputedStyle(input).overflowY };
  });
}
(async () => {
  console.log('RESULTS ' + out); save();
  const browser = await chromium.connectOverCDP('http://127.0.0.1:19229', { timeout:10000 });
  page = browser.contexts().flatMap(context => context.pages()).find(candidate => candidate.url().includes('app.asar') && !/startup\.html|capture-browser\.html/.test(candidate.url()));
  assert.ok(page, '未找到已启动的发行版主页面'); page.setDefaultTimeout(10000); initialUrl=page.url();
  assert.ok(await page.locator('#desktop-v2-primary-navigation:visible').count(), '尚未登录，不操作登录界面');
  const candidates = page.locator('.welcome-composer textarea:visible, .thread-composer textarea:visible');
  assert.equal(await candidates.count(), 1, '当前没有唯一可见输入框，不切换页面');
  editor=await candidates.elementHandle(); parent=page.locator('.welcome-composer:visible, .thread-composer:visible').filter({ has:page.locator('textarea:visible') });
  assert.equal(await parent.count(), 1);
  await guard('');
  const width=await parent.evaluate(el => el.clientWidth - parseFloat(getComputedStyle(el).paddingLeft) - parseFloat(getComputedStyle(el).paddingRight));
  assert.ok(width >= 580, `当前输入区宽 ${width}px，不改变用户窗口；请在宽布局中运行`);
  await editor.fill(source); inserted=true;
  const toggle=parent.locator('.composer-preview-toggle'); await toggle.waitFor({ state:'visible' });
  originalExpanded=await toggle.getAttribute('aria-expanded');
  await guard(source);
  if (originalExpanded !== 'true') await toggle.click();
  await check('expanded-equal-height-and-independent-scroll', async () => {
    await guard(source);
    const box=await geometry(); console.log(JSON.stringify(box));
    assert.ok(box.preview.x >= box.editor.right - 2, '预览没有位于编辑框右侧');
    assert.ok(Math.abs(box.editor.height - box.preview.height - box.marginTop - box.marginBottom) <= 3, '编辑框未填满预览所在行');
    assert.equal(box.maxHeight, 'none', '旧的编辑框高度上限仍生效');
    assert.ok(['auto','scroll'].includes(box.overflowY));
    const previewBody=parent.locator('.composer-preview-body');
    assert.ok((await previewBody.innerText()).includes(marker));
    const previewScroll=await previewBody.evaluate(el => ({ overflowY:getComputedStyle(el).overflowY, clientHeight:el.clientHeight, scrollHeight:el.scrollHeight }));
    assert.ok(['auto','scroll'].includes(previewScroll.overflowY));
    assert.ok(previewScroll.scrollHeight > previewScroll.clientHeight, '长预览没有独立滚动区域');
    assert.equal(await editor.inputValue(), source);
    await shot('expanded'); return { width, geometry:box, previewScroll };
  });
  await check('editor-last-line-accessible', async () => {
    await guard(source); await editor.focus(); await editor.press('Control+End');
    // Wait on observed layout, not an app state hook or a forced scroll assignment.
    await page.waitForFunction(el => el.scrollTop + el.clientHeight >= el.scrollHeight - parseFloat(getComputedStyle(el).paddingBottom) - 3, editor);
    const state=await editor.evaluate(el => ({ scrollTop:el.scrollTop, clientHeight:el.clientHeight, scrollHeight:el.scrollHeight, paddingBottom:parseFloat(getComputedStyle(el).paddingBottom), selectionStart:el.selectionStart, selectionEnd:el.selectionEnd }));
    assert.ok(state.scrollHeight > state.clientHeight, '长输入没有产生独立滚动');
    assert.equal(state.selectionStart, source.length); assert.equal(state.selectionEnd, source.length);
    assert.equal(await editor.inputValue(), source); await shot('last-line'); return state;
  });
  await check('collapsed-toggle-remains-right', async () => {
    await guard(source); const expanded=await geometry(); await toggle.click();
    assert.equal(await toggle.getAttribute('aria-expanded'), 'false');
    assert.equal(await parent.locator('.composer-preview-body').isVisible(), false);
    const collapsed=await geometry();
    assert.ok(collapsed.toggle.x >= collapsed.editor.right - 2, '收起开关移到了编辑框下方');
    assert.ok(collapsed.toggle.y < collapsed.editor.bottom && collapsed.toggle.bottom > collapsed.editor.y, '收起开关与编辑框不在同一行');
    assert.ok(collapsed.editor.width > expanded.editor.width, '收起后编辑框没有利用释放的宽度');
    assert.equal(await editor.inputValue(), source); await shot('collapsed-right'); return { geometry:collapsed };
  });
})().catch(async error => {
  if (!results.some(result => result.status === 'FAIL')) results.push({ name:'setup', status:'FAIL', error:error.message });
  console.error(error.stack);
  // Do not capture unrelated user pages or drafts when setup/precondition fails.
  if (inserted && page?.url() === initialUrl && await editor.inputValue().catch(() => null) === source) await shot('failure').catch(() => {});
  process.exitCode=1;
}).finally(async () => {
  if (inserted) {
    try {
      await guard(source);
      const toggle=parent.locator('.composer-preview-toggle');
      if (originalExpanded != null && await toggle.getAttribute('aria-expanded') !== originalExpanded) await toggle.click();
      await guard(source); await editor.fill('');
      assert.equal(await editor.inputValue(), '');
      results.push({ name:'restore-empty-draft', status:'PASS' });
    } catch (error) {
      results.push({ name:'restore-empty-draft', status:'STOPPED', error:error.message, note:'未清空已变化的用户现场' }); process.exitCode=1;
    }
  }
  save(); console.log((process.exitCode ? 'FAIL ' : 'PASS ') + out); process.exit(process.exitCode || 0);
});

