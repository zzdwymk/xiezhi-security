/** UI 真实创建：评估项目 + Web 授权目标（仅首次运行需要）。 */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const { navigate, sleep, dialog, dialogButton, fillByLabel, selectOption, pickDateTimeNow, pickDateTimeFuture, confirmBoxIfPresent, dismissStrayModal } = require('./lib/ui.cjs');

const ROOT = path.resolve(__dirname, '../../..');
const CRED = path.join(ROOT, '.run', 'desktop-login-runtime.json');
const STAMP = Date.now().toString().slice(-6);
const PROJECT = `路由根治实测项目-${STAMP}`;
const TARGET = {
  name: `实测Web靶标-${STAMP}`,
  type: 'URL',
  address: 'http://192.168.222.150',
  auth: `已获得书面授权（编号 AUTH-${STAMP}），允许针对指定目标开展受控安全性检验。`,
};

(async () => {
  const creds = JSON.parse(fs.readFileSync(CRED, 'utf8').replace(/^\uFEFF/, ''));
  const browser = await chromium.connectOverCDP('http://127.0.0.1:19229', { timeout: 15000 });
  const page = browser.contexts()[0].pages().find(p => /5199/.test(p.url()));
  await page.bringToFront().catch(() => {});

  // 登录（若未登录）
  if (/\/login/.test(page.url())) {
    await page.locator('input[type="text"]').first().fill(creds.username || 'admin');
    await page.locator('input[type="password"]').first().fill(creds.password);
    await page.locator('input[type="password"]').first().press('Enter');
    await sleep(3000);
    for (let i = 0; i < 15; i++) { if (!/\/login/.test(page.url())) break; await sleep(800); }
  }
  // 过向导（若出现）
  for (let i = 0; i < 15; i++) {
    if (!/\/setup/.test(page.url())) break;
    const btn = page.getByRole('button', { name: /进入安全工作台|下一步|继续|开始使用/ }).first();
    if (await btn.isVisible().catch(() => false)) await btn.click().catch(() => {});
    await sleep(1500);
  }
  console.log('at:', page.url());

  // ── 建项目 ──
  await navigate(page, '评估项目');
  await sleep(1500);
  await page.locator('button', { hasText: '新建评估项目' }).first().click();
  await sleep(1500);
  const dlg = await dialog(page, '新建安全评估项目');
  await fillByLabel(dlg, page, '项目名称', PROJECT);
  await fillByLabel(dlg, page, '负责人', '安全评估测试员');
  await fillByLabel(dlg, page, '授权声明', TARGET.auth);
  await pickDateTimeNow(dlg, page, '授权开始');
  await pickDateTimeFuture(dlg, page, '授权结束', { monthsAhead: 2, day: 15 });
  await dialogButton(dlg, '创建项目');
  await sleep(2000);
  await confirmBoxIfPresent(page, ['确认并保存', '确定']);
  await sleep(1500);
  console.log('project created:', PROJECT);

  // 激活为进行中
  const editBtn = page.locator('.el-table__row', { hasText: PROJECT }).locator('button', { hasText: '编辑' }).first();
  await editBtn.waitFor({ state: 'visible', timeout: 10000 });
  await editBtn.click();
  await sleep(1500);
  const editDlg = await dialog(page, '编辑评估项目');
  await selectOption(editDlg, page, '项目状态', '进行中');
  await dialogButton(editDlg, '保存修改');
  await sleep(1500);
  await confirmBoxIfPresent(page, ['确认并保存', '确定']);
  await sleep(1500);
  console.log('project activated');

  // ── 建目标 ──
  await navigate(page, '授权目标');
  await sleep(1500);
  await page.locator('button', { hasText: '新增目标' }).first().click();
  await sleep(1500);
  const tdlg = await dialog(page, '新增授权目标');
  await selectOption(tdlg, page, '归属评估项目', PROJECT);
  await fillByLabel(tdlg, page, '名称', TARGET.name);
  await selectOption(tdlg, page, '目标类型', TARGET.type);
  await fillByLabel(tdlg, page, '地址', TARGET.address);
  await fillByLabel(tdlg, page, '授权记录', TARGET.auth);
  await tdlg.locator('button', { hasText: '保存目标' }).last().click();
  await sleep(2000);
  await confirmBoxIfPresent(page, ['确认并保存', '确定']);
  await sleep(1500);
  const stillOpen = await tdlg.isVisible().catch(() => false);
  if (stillOpen) {
    const errs = await page.locator('.el-form-item__error').allTextContents();
    throw new Error('目标对话框未关闭：' + errs.join('; '));
  }
  console.log('target created:', TARGET.address);
  console.log('PROJECT_NAME=' + PROJECT);
  await page.screenshot({ path: path.join(ROOT, '.run', 'route-fix-scope-created.png'), fullPage: true }).catch(() => {});
  await browser.close();
})().catch(e => { console.error('ERR', e.message); process.exit(1); });
