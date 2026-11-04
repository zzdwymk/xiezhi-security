/** 桌面真窗口单会话实测：登录 → 向导 → 建项目/目标 → AI 路由三用例。
 * 全程一次 CDP 连接完成，避免跨会话页面状态丢失。
 */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const { navigate, sleep, dialog, dialogButton, fillByLabel, selectOption, pickDateTimeNow, pickDateTimeFuture, confirmBoxIfPresent, dismissStrayModal } = require('./lib/ui.cjs');
const { captureAiWire } = require('./lib/ai-wire.cjs');

const ROOT = path.resolve(__dirname, '../../..');
const OUT = path.join(ROOT, '.run', `route-fix-live-${new Date().toISOString().replace(/[:.]/g, '-')}`);
const CRED = path.join(ROOT, '.run', 'desktop-login-runtime.json');
const results = [];
let page;

function save() { fs.writeFileSync(path.join(OUT, 'results.json'), JSON.stringify({ createdAt: new Date().toISOString(), results }, null, 2)); }
function record(id, status, detail = {}) {
  results.push({ id, status, ...detail });
  console.log(`[${status}] ${id} ${detail.error ? '- ' + String(detail.error).slice(0, 260) : ''}`);
  save();
}
async function shot(name) { await page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: true, timeout: 15000 }).catch(() => {}); }

function parseWire(text) {
  try { return [JSON.parse(text)]; } catch {}
  return text.split(/\r?\n/).map(l => l.replace(/^data:\s*/, '')).flatMap(l => { try { return [JSON.parse(l)]; } catch { return []; } });
}
const EV_KEYS = /^(provider|plannerSource|fallback|executed|executionIntent|executionDecision|intent|terminationReason|taskIds|retrievalMethod|status|stage|reason|source|method|mode)$/;
function evidence(value, trail = '', out = []) {
  if (!value || typeof value !== 'object') return out;
  for (const [k, v] of Object.entries(value)) {
    const key = trail ? `${trail}.${k}` : k;
    if (EV_KEYS.test(k) && (v == null || typeof v !== 'object' || k === 'taskIds')) out.push({ field: key, value: typeof v === 'string' ? v.slice(0, 300) : v });
    if (v && typeof v === 'object' && key.split('.').length < 12) evidence(v, key, out);
  }
  return out;
}

async function login() {
  const creds = JSON.parse(fs.readFileSync(CRED, 'utf8').replace(/^\uFEFF/, ''));
  for (let attempt = 0; attempt < 4; attempt++) {
    if (!/\/login/.test(page.url())) return;
    const user = page.locator('input[type="text"]').first();
    if (!(await user.isVisible().catch(() => false))) { await sleep(1500); continue; }
    await user.fill(creds.username || 'admin');
    const pass = page.locator('input[type="password"]').first();
    await pass.fill(creds.password);
    await pass.press('Enter');
    await sleep(3500);
    const msgs = await page.locator('.el-message').allTextContents().catch(() => []);
    console.log(`login attempt ${attempt + 1}: url=${page.url().slice(-40)} msgs=${JSON.stringify(msgs)}`);
  }
  if (/\/login/.test(page.url())) throw new Error('登录失败：仍停在登录页');
}

async function passWizard() {
  for (let i = 0; i < 40; i++) {
    if (!/\/setup/.test(page.url())) { console.log('wizard done'); return; }
    const next = page.getByRole('button', { name: /进入安全工作台|下一步，进入工具箱|继续|开始使用/ }).first();
    if (await next.isVisible().catch(() => false) && await next.isEnabled().catch(() => false)) {
      await next.click().catch(() => {});
      await sleep(2000);
    } else {
      await sleep(2500);
    }
  }
  if (/\/setup/.test(page.url())) throw new Error('向导未能通过');
}

function composer() { return page.locator('.welcome-composer textarea:visible, .thread-composer textarea:visible').first(); }

async function send(prompt) {
  const startedAt = Date.now();
  await composer().waitFor({ state: 'visible', timeout: 30000 });
  await composer().fill(prompt);
  const capture = await captureAiWire(page);
  const responsePromise = page.waitForResponse(r => /\/ai\/(agent|dispatches)\/stream(?:\?|$)/.test(r.url()) && r.request().method() === 'POST', { timeout: 90000 });
  await page.locator('.send-button:visible').click();
  let response, wire;
  try {
    response = await responsePromise;
    try {
      wire = parseWire((await capture.body(response)).toString('utf8'));
    } catch (e) {
      // 流响应体可能因页面重渲染不可读：回退到仅用 DOM 回答判定
      console.log('wire capture fallback:', String(e.message).slice(0, 120));
      wire = [];
    }
  } finally { await capture.close(); }
  for (let i = 0; i < 300; i++) { if (await composer().isEnabled().catch(() => false)) break; await sleep(500); }
  await sleep(1200);
  const msg = page.locator('article.chat-message.assistant').last();
  const body = msg.locator('.message-bubble.markdown-body');
  const answer = (await body.count() ? await body.innerText() : '') || (await msg.innerText().catch(() => ''));
  const route = wire.find(v => v.type === 'route')?.data || {};
  const done = wire.findLast(v => v.type === 'done')?.data || {};
  const allEvidence = wire.flatMap(v => evidence(v));
  const result = {
    prompt, seconds: Math.round((Date.now() - startedAt) / 1000),
    answer: answer.slice(0, 2500),
    routeIntent: route.intent || allEvidence.find(x => x.field === 'intent')?.value || '',
    executionDecision: route.executionDecision || '',
    planSteps: (done.response?.plan?.steps || []).map(s => s.title || s.code || ''),
    evidence: allEvidence.slice(0, 60),
  };
  await shot(`after-${prompt.slice(0, 12).replace(/\s/g, '')}`);
  return result;
}

async function newChat() {
  await navigate(page, 'AI 安全助手');
  const btn = page.getByRole('button', { name: '新对话', exact: true });
  if (await btn.isVisible().catch(() => false)) { await btn.click(); await sleep(1200); }
  await composer().waitFor({ state: 'visible', timeout: 20000 });
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.connectOverCDP('http://127.0.0.1:19229', { timeout: 30000 });
  const context = browser.contexts()[0];
  page = context.pages().find(p => !p.isClosed() && /5199/.test(p.url())) || (await context.newPage());
  await page.bringToFront().catch(() => {});
  console.log('start url:', page.url());
  // 登录与向导可能互相接力（后端重启会话失效→向导→登录），循环直到稳定进入主界面
  for (let round = 0; round < 6; round++) {
    if (/\/login/.test(page.url())) await login();
    if (/\/setup/.test(page.url())) await passWizard();
    if (!/\/(login|setup)/.test(page.url())) break;
  }
  if (/\/(login|setup)/.test(page.url())) throw new Error('未能进入主界面: ' + page.url());
  await sleep(2000);
  await shot('01-main');
  record('setup', 'PASS', { note: '登录+向导完成 url=' + page.url() });

  // ── 建项目 ──
  const STAMP = Date.now().toString().slice(-6);
  const PROJECT = `路由根治实测项目-${STAMP}`;
  const AUTH = `已获得书面授权（编号 AUTH-${STAMP}），允许针对指定目标开展受控安全性检验。`;
  const TARGET_ADDR = 'http://192.168.222.150';
  const TARGET_NAME = `实测Web靶标-${STAMP}`;
  await navigate(page, '评估项目');
  await sleep(1500);
  await page.locator('button', { hasText: '新建评估项目' }).first().click();
  await sleep(1500);
  const dlg = await dialog(page, '新建安全评估项目');
  await fillByLabel(dlg, page, '项目名称', PROJECT);
  await fillByLabel(dlg, page, '负责人', '安全评估测试员');
  await fillByLabel(dlg, page, '授权声明', AUTH);
  await pickDateTimeNow(dlg, page, '授权开始');
  await pickDateTimeFuture(dlg, page, '授权结束', { monthsAhead: 2, day: 15 });
  await dialogButton(dlg, '创建项目');
  await sleep(2000);
  await confirmBoxIfPresent(page, ['确认并保存', '确定']);
  await sleep(1500);
  const editBtn = page.locator('.el-table__row', { hasText: PROJECT }).locator('button', { hasText: '编辑' }).first();
  await editBtn.waitFor({ state: 'visible', timeout: 15000 });
  await editBtn.click();
  await sleep(1500);
  const editDlg = await dialog(page, '编辑评估项目');
  await selectOption(editDlg, page, '项目状态', '进行中');
  await dialogButton(editDlg, '保存修改');
  await sleep(1500);
  await confirmBoxIfPresent(page, ['确认并保存', '确定']);
  await sleep(1500);
  record('create-project', 'PASS', { note: PROJECT });
  await shot('02-project');

  // ── 建目标 ──
  await navigate(page, '授权目标');
  await sleep(1500);
  await page.locator('button', { hasText: '新增目标' }).first().click();
  await sleep(1500);
  const tdlg = await dialog(page, '新增授权目标');
  await selectOption(tdlg, page, '归属评估项目', PROJECT);
  await fillByLabel(tdlg, page, '名称', TARGET_NAME);
  await selectOption(tdlg, page, '目标类型', 'URL');
  await fillByLabel(tdlg, page, '地址', TARGET_ADDR);
  await fillByLabel(tdlg, page, '授权记录', AUTH);
  await tdlg.locator('button', { hasText: '保存目标' }).last().click();
  await sleep(2000);
  await confirmBoxIfPresent(page, ['确认并保存', '确定']);
  await sleep(1500);
  if (await tdlg.isVisible().catch(() => false)) {
    const errs = await page.locator('.el-form-item__error').allTextContents();
    throw new Error('目标对话框未关闭：' + errs.join('; '));
  }
  record('create-target', 'PASS', { note: `${TARGET_NAME} ${TARGET_ADDR}` });
  await shot('03-target');

  // ── 用例：从授权目标行进入 AI 规划对话 ──
  await sleep(1000);
  const rows = page.locator('.el-table__row');
  const row = rows.filter({ hasText: TARGET_ADDR }).first();
  const planBtn = row.getByRole('button', { name: 'AI 规划', exact: true });
  await planBtn.waitFor({ state: 'visible', timeout: 15000 });
  await planBtn.click();
  await sleep(2500);
  await composer().waitFor({ state: 'visible', timeout: 30000 });
  await shot('04-chat-ready');
  record('enter-chat', 'PASS', { note: '已进入绑定目标的 AI 对话' });

  // ── 用例1：这个项目怎么打 ──
  try {
    const r = await send('这个项目怎么打');
    const boiler = /不能直接生成检测动作|一般性知识问答/.test(r.answer);
    const domPlan = /受控检测草案|检测方案|待审批|待你审批|审阅/.test(r.answer)
      && /(TCP 端口探测|端口探测|Nmap|服务识别)/.test(r.answer);
    const isAction = /ACTION_PLAN/.test(String(r.routeIntent)) || r.planSteps.length > 0
      || r.evidence.some(x => /executionDecision/.test(x.field) && x.value === 'PLAN_ONLY')
      || (r.routeIntent === '' && domPlan); // wire 不可读时以 DOM 回答为准
    record('case1-这个项目怎么打', !boiler && isAction ? 'PASS' : 'FAIL',
      { seconds: r.seconds, routeIntent: r.routeIntent || '(wire 不可读，按 DOM 判定)', executionDecision: r.executionDecision, planSteps: r.planSteps, answerHead: r.answer.slice(0, 260), boilerplate: boiler });
  } catch (e) { await shot('case1-fail'); record('case1-这个项目怎么打', 'FAIL', { error: e.message }); }

  await newChat();

  // ── 用例2：从哪开始 ──
  try {
    const r = await send('从哪开始');
    const isAction = /ACTION_PLAN/.test(String(r.routeIntent)) || r.planSteps.length > 0
      || r.evidence.some(x => /executionDecision/.test(x.field) && x.value === 'PLAN_ONLY');
    record('case2-从哪开始', isAction ? 'PASS' : 'FAIL',
      { seconds: r.seconds, routeIntent: r.routeIntent, executionDecision: r.executionDecision, planSteps: r.planSteps, answerHead: r.answer.slice(0, 260) });
  } catch (e) { await shot('case2-fail'); record('case2-从哪开始', 'FAIL', { error: e.message }); }

  await newChat();

  // ── 用例3：能力探询负例 ──
  try {
    const r = await send('你能扫描端口吗');
    const isGeneral = /GENERAL_QA/.test(String(r.routeIntent));
    const noTasks = !r.evidence.some(x => /taskIds/.test(x.field) && Array.isArray(x.value) && x.value.length);
    const noExec = !r.evidence.some(x => /executionDecision/.test(x.field) && x.value === 'EXECUTE');
    record('case3-你能扫描端口吗', isGeneral && noTasks && noExec ? 'PASS' : 'FAIL',
      { seconds: r.seconds, routeIntent: r.routeIntent, executionDecision: r.executionDecision, answerHead: r.answer.slice(0, 260) });
  } catch (e) { await shot('case3-fail'); record('case3-你能扫描端口吗', 'FAIL', { error: e.message }); }

  await shot('99-final');
  save();
  const pass = results.filter(r => r.status === 'PASS').length;
  console.log(`\nDONE: ${pass}/${results.length} PASS. 证据目录: ${OUT}`);
})().catch(e => { console.error('FATAL', e.message); record('fatal', 'FAIL', { error: e.message }); save(); process.exit(1); });
