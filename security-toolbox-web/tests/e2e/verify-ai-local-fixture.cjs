/** Packaged EXE AI acceptance against a script-owned loopback HTTP fixture.
 * Start the EXE with CDP 19229 and log in manually before running this script.
 * Default: one nmap_service_scan plan -> explicit execution -> real task -> AI analysis.
 * Optional: --only=nmap_service_scan,http_headers,http_security_check
 * All business operations use UI clicks/inputs; response inspection is passive.
 * No storage/cookies/login access, business API calls, deletion, or browser.close().
 * The independent project, target, conversations and task results are preserved.
 */
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright-core');
const { navigate, dialog, fillByLabel, selectOption, selectOn, pickDateTimeNow,
  pickDateTimeFuture, confirmBoxIfPresent, waitRow, sleep } = require('./lib/ui.cjs');

const STAMP = new Date().toISOString().replace(/[:.]/g, '-');
const DISPLAY_TIME = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }).replace(/\//g, '-');
const OUT = path.resolve(__dirname, '../../../.run/ai-local-fixture', STAMP);
const HOST = '127.0.0.1';
const PORT = 18888;
const URL = `http://${HOST}:${PORT}`;
let PROJECT = `AI本机闭环验收-${DISPLAY_TIME}`;
let TARGET = `AI本机HTTP夹具-${DISPLAY_TIME}`;
const supported = ['nmap_service_scan', 'http_headers', 'http_security_check', 'tcp_ports'];
const onlyArg = process.argv.find(x => x.startsWith('--only='));
const selected = [...new Set(onlyArg ? onlyArg.slice(7).split(',') : ['nmap_service_scan'])];
const results = [];
const fixture = { host: HOST, port: PORT, connections: 0, requests: 0, methods: {}, clientErrors: 0, listening: false };
let server, page, projectId, targetId;
fs.mkdirSync(OUT, { recursive: true });

function assert(ok, message, detail) {
  if (!ok) { const error = new Error(message); error.detail = detail; throw error; }
}
function displayedTargetName(name) {
  const legacy = /^AI本机HTTP夹具-(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z$/.exec(name);
  if (!legacy) return name;
  const time = new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', year: 'numeric',
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' })
    .format(new Date(`${legacy[1]}T${legacy[2]}:${legacy[3]}:${legacy[4]}.${legacy[5]}Z`)).replace(/\//g, '-');
  return `AI 本机 HTTP 测试目标 · ${time}`;
}
function save() {
  fs.writeFileSync(path.join(OUT, 'results.json'), JSON.stringify({
    updatedAt: new Date().toISOString(), method: 'Actual EXE DOM clicks/input; passive response inspection',
    projectName: PROJECT, projectId, targetName: TARGET, targetId, targetUrl: URL,
    allowedPorts: String(PORT), selected, fixture, results,
  }, null, 2));
  fs.writeFileSync(path.join(OUT, 'results.md'), '# 本机 AI 闭环验收\n\n'
    + `项目：${PROJECT}（${projectId || '未创建'}）\n\n目标：${URL}（${targetId || '未创建'}），仅端口 ${PORT}。\n\n`
    + '| 步骤 | 结果 | 秒 | 说明 |\n| --- | --- | ---: | --- |\n'
    + results.map(r => `| ${r.id} | ${r.status} | ${r.seconds} | ${(r.error || r.note || r.answer || '').slice(0, 260).replace(/[\r\n|]/g, ' ')} |`).join('\n'));
}
async function shot(id) {
  if (page) await page.screenshot({ path: path.join(OUT, `${id}.png`), fullPage: true,
    mask: [page.locator('input[type="password"]')], timeout: 15000 });
}
async function step(id, fn) {
  const start = Date.now();
  console.log('START ' + id);
  let result, failure;
  try { result = { id, status: 'PASS', ...await fn() }; }
  catch (error) { failure = error; result = { id, status: error.code === 'EADDRINUSE' ? 'BLOCKED' : 'FAIL',
    ...error.detail, error: String(error.message).slice(0, 3000) }; }
  try { await shot(id); } catch (error) {
    result.screenshotError = String(error.message);
    if (!failure) { failure = error; result.status = 'FAIL'; result.error = '截图取证失败：' + error.message; }
  }
  result.seconds = +((Date.now() - start) / 1000).toFixed(1);
  results.push(result); save();
  console.log(JSON.stringify({ id, status: result.status, seconds: result.seconds, error: result.error, note: result.note }));
  if (failure) throw failure;
  return result;
}
async function startFixture() {
  server = http.createServer((req, res) => {
    fixture.requests++;
    fixture.methods[req.method] = (fixture.methods[req.method] || 0) + 1;
    const health = req.url?.split('?')[0] === '/health';
    const body = health ? '{"fixture":"xiezhi-ai-local","ok":true}\n'
      : '<!doctype html><html lang="en"><head><title>Xiezhi local AI fixture</title></head><body><h1>Xiezhi local AI fixture</h1><p>Public deterministic acceptance content.</p></body></html>\n';
    res.writeHead(200, {
      'Content-Type': health ? 'application/json; charset=utf-8' : 'text/html; charset=utf-8',
      'Content-Length': Buffer.byteLength(body), 'X-Fixture': 'xiezhi-ai-local',
      'Set-Cookie': 'fixture_marker=public-demo; SameSite=Lax',
      'Cache-Control': 'no-store', 'Allow': 'GET, HEAD, OPTIONS', 'Connection': 'close',
    });
    res.end(req.method === 'HEAD' ? undefined : body);
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.on('connection', () => { fixture.connections++; });
  server.on('clientError', (_error, socket) => { fixture.clientErrors++; socket.destroy(); });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(PORT, HOST, () => { server.removeListener('error', reject); fixture.listening = true; resolve(); });
  });
  return { note: `脚本独占监听 ${URL}；端口冲突时不使用其他端口，不停止已有监听器。` };
}
async function attach() {
  const browser = await chromium.connectOverCDP('http://127.0.0.1:19229', { timeout: 10000 });
  page = browser.contexts().flatMap(c => c.pages()).find(p => p.url().includes('app.asar')
    && !/startup\.html|capture-browser\.html/.test(p.url()));
  assert(page, '未找到已打包 EXE 主页面');
  page.setDefaultTimeout(15000);
  if (!await page.locator('#desktop-v2-primary-navigation').isVisible()) console.log('WAITING_MANUAL_LOGIN');
  await page.locator('#desktop-v2-primary-navigation').waitFor({ state: 'visible', timeout: 600000 });
  return { note: '已连接 EXE；仅等待人工登录，不读取登录数据。' };
}
function passiveResponse(suffix, method = 'POST') {
  return page.waitForResponse(r => r.url().split('?')[0].endsWith(suffix) && r.request().method() === method,
    { timeout: 25000 });
}
async function restoreScope(record) {
  assert(/^AI本机闭环验收-/.test(record.projectName || '') && /^AI本机HTTP夹具-/.test(record.targetName || ''), '仅能恢复本机验收专用记录');
  assert(Number.isSafeInteger(record.projectId) && record.projectId > 0 && Number.isSafeInteger(record.targetId) && record.targetId > 0, '恢复记录缺少有效项目/目标编号');
  assert(record.targetUrl === URL && String(record.allowedPorts) === String(PORT), '恢复记录不是固定本机地址和单端口');
  // Confirm visible names and scope, then cross-check IDs against passive responses.
  const projectPending = passiveResponse('/projects', 'GET');
  await navigate(page, '评估项目');
  await page.getByPlaceholder('搜索项目名称 / 负责人 / 说明').fill(record.projectName);
  const projectRow = await waitRow(page, record.projectName, 15000);
  assert((await projectRow.locator('td').first().innerText()).trim() === record.projectName && /进行中/.test(await projectRow.innerText()), '恢复项目名称或活动状态不符');
  const projects = await (await projectPending).json();
  assert(Array.isArray(projects) && projects.some(p => p.id === record.projectId && p.name === record.projectName && p.status === 'ACTIVE'), '恢复项目编号与界面项目不符');
  const targetPending = passiveResponse('/targets', 'GET');
  const linksPending = passiveResponse(`/projects/${record.projectId}/targets`, 'GET');
  void linksPending.catch(() => {});
  await navigate(page, '授权目标');
  await page.getByPlaceholder('搜索名称 / 地址 / 类型 / 授权记录').fill(record.targetName);
  const targetRow = await waitRow(page, record.targetName, 15000);
  assert((await targetRow.locator('td').nth(1).innerText()).trim() === record.targetName
    && (await targetRow.locator('td').nth(2).innerText()).trim() === URL
    && (await targetRow.locator('td').nth(4).innerText()).trim() === String(PORT), '恢复目标界面的名称/地址/端口不符');
  const targets = await (await targetPending).json();
  assert(Array.isArray(targets) && targets.some(t => t.id === record.targetId
    && t.name === record.targetName && t.targetValue === URL && t.allowedPorts === String(PORT) && t.enabled), '恢复目标编号、归属或授权范围不符');
  const links = await (await linksPending).json();
  assert(Array.isArray(links) && links.some(link => Number(link.targetId) === record.targetId), '恢复目标未关联到该专用项目');
  PROJECT = record.projectName; TARGET = record.targetName; projectId = record.projectId; targetId = record.targetId;
  return { projectId, targetId, note: '已通过可见项目/目标行及被动响应核对专用项目、固定本机地址和单端口；未恢复旧审批。' };
}
async function createProject() {
  await navigate(page, '评估项目');
  await page.getByRole('button', { name: '新建评估项目', exact: true }).click();
  const dlg = await dialog(page, '新建安全评估项目');
  await fillByLabel(dlg, page, '项目名称', PROJECT);
  await fillByLabel(dlg, page, '负责人', '本机验收');
  await fillByLabel(dlg, page, '授权声明', `仅授权本脚本创建并持有的 ${URL} HTTP夹具，仅TCP端口${PORT}；仅允许TCP连接、服务识别、HTTP响应头和Cookie配置检查，以及fscan SAFE模式（禁止爆破、POC和模糊测试）。禁止其他地址、端口和全库扫描。`);
  await pickDateTimeNow(dlg, page, '授权开始');
  await pickDateTimeFuture(dlg, page, '授权结束', { monthsAhead: 1, day: 15 });
  await fillByLabel(dlg, page, '项目说明', '真实EXE界面AI验收；固定公开本机测试内容；保留独立项目、目标、会话和检测结果供复核。');
  await shot('project-form');
  const pending = passiveResponse('/projects');
  await dlg.getByRole('button', { name: '创建项目', exact: true }).click();
  const response = await pending;
  assert(response.ok(), '创建项目失败 HTTP ' + response.status());
  const data = await response.json();
  assert(data.name === PROJECT && Number(data.id) > 0, '创建项目响应与独立项目不一致');
  projectId = Number(data.id);
  await dlg.waitFor({ state: 'hidden' });
  await page.getByPlaceholder('搜索项目名称 / 负责人 / 说明').fill(PROJECT);
  const row = await waitRow(page, PROJECT, 15000);
  assert(/草稿|DRAFT/.test(await row.innerText()), '新项目未以草稿创建');
  return { projectId, note: '独立项目已通过界面创建，初始状态为草稿。' };
}
async function activateProject() {
  const row = await waitRow(page, PROJECT, 15000);
  await row.getByRole('button', { name: '编辑', exact: true }).click();
  const dlg = await dialog(page, '编辑评估项目');
  await selectOption(dlg, page, '项目状态', '进行中', { exact: true });
  const pending = passiveResponse(`/projects/${projectId}/status`);
  await dlg.getByRole('button', { name: '保存修改', exact: true }).click();
  await confirmBoxIfPresent(page, '确认并保存', { timeout: 5000 });
  const response = await pending;
  assert(response.ok() && (await response.json()).status === 'ACTIVE', '新项目未成功激活');
  await dlg.waitFor({ state: 'hidden' });
  assert(/进行中/.test(await (await waitRow(page, PROJECT, 15000)).innerText()), '列表未显示进行中');
  return { note: '仅激活本次新建项目。' };
}
async function createTarget() {
  await navigate(page, '授权目标');
  await page.getByRole('button', { name: '新增目标', exact: true }).click();
  const dlg = await dialog(page, '新增授权目标');
  await selectOption(dlg, page, '归属评估项目', PROJECT);
  await fillByLabel(dlg, page, '名称', TARGET);
  await selectOption(dlg, page, '目标类型', 'URL', { exact: true });
  await fillByLabel(dlg, page, '地址', URL);
  await fillByLabel(dlg, page, '授权记录', `本次验收脚本持有的本机HTTP夹具，限${URL}，只允许端口${PORT}的TCP连接、服务识别、响应头和Cookie检查及fscan SAFE（不爆破、不POC）。`);
  const picker = dlg.locator('.port-picker');
  assert(await picker.getByRole('switch').getAttribute('aria-checked') === 'false', '全端口开关必须关闭');
  const sel = picker.locator('.el-select');
  // collapse-tags hides the second selected port; remove the visible first tag repeatedly.
  for (let i = 0; i < 10 && await sel.locator('.el-tag__close:visible').count(); i++) {
    await sel.locator('.el-tag__close:visible').first().click();
    await sleep(150);
  }
  assert(await sel.locator('.el-tag').count() === 0, '默认80/443端口未全部移除');
  await sel.locator('input').first().fill(String(PORT));
  await page.keyboard.press('Enter');
  await dlg.getByText('允许测试的指定服务端口：', { exact: true }).click();
  assert(await sel.locator('.el-tag').count() === 1
    && (await sel.locator('.el-tag').innerText()).trim() === String(PORT), '端口选择器不等于唯一18888');
  await shot('target-form-only-18888');
  const pending = passiveResponse('/targets');
  await dlg.getByRole('button', { name: '保存目标', exact: true }).click();
  const response = await pending;
  const request = response.request().postDataJSON();
  assert(request.targetValue === URL && request.targetType === 'url' && request.allowedPorts === String(PORT)
    && Number(request.projectId) === projectId, '目标创建请求超出独立本机范围', { request });
  assert(response.ok(), '创建目标失败 HTTP ' + response.status());
  const data = await response.json();
  assert(Number(data.id) > 0 && data.targetValue === URL && data.allowedPorts === String(PORT), '新目标响应不一致');
  targetId = Number(data.id);
  await dlg.waitFor({ state: 'hidden' });
  await page.getByPlaceholder('搜索名称 / 地址 / 类型 / 授权记录').fill(TARGET);
  const row = await waitRow(page, TARGET, 15000);
  assert((await row.locator('td').nth(4).innerText()).trim() === String(PORT), '目标列表端口不等于18888');
  return { targetId, request, note: '仅授权本机URL及单个端口18888；80/443默认值已移除。' };
}
function composer() { return page.locator('.welcome-composer textarea:visible, .thread-composer textarea:visible').first(); }
function parseWire(body) {
  try { return [JSON.parse(body)]; } catch {}
  return body.split(/\r?\n/).flatMap(line => { try { return [JSON.parse(line.replace(/^data:\s*/, ''))]; } catch { return []; } });
}
async function send(prompt, execute = false) {
  await composer().waitFor({ state: 'visible' });
  const sw = page.getByRole('switch', { name: 'AI 执行模式' });
  const legacyMode = await sw.count() > 0;
  if (legacyMode && await sw.getAttribute('aria-checked') !== String(execute))
    await page.locator('.el-switch').filter({ has: sw }).locator('.el-switch__core').click();
  if (legacyMode) assert(await sw.getAttribute('aria-checked') === String(execute), 'AI执行开关状态不正确');
  await composer().fill(prompt);
  const pending = page.waitForResponse(r => /\/ai\/(agent|dispatches)\/stream(?:\?|$)/.test(r.url())
    && r.request().method() === 'POST', { timeout: 25000 });
  await page.locator('.send-button:visible').click();
  const response = await pending;
  const request = response.request().postDataJSON();
  const safeRequest = { projectId: request.projectId, targetId: request.targetId, sessionId: request.sessionId,
    execute: request.execute, mode: request.mode, refs: (request.refs || []).map(r => ({ type: r.type, id: r.id })) };
  assert(Number(request.projectId) === projectId && Number(request.targetId) === targetId
    && (legacyMode ? request.execute === execute : request.executionIntent === 'AUTO' && request.userPrompt === prompt), 'AI请求作用域或执行意图不符合本次验收', { request: safeRequest });
  const wire = parseWire(await response.text());
  const terminal = wire.findLast(event => event.type === 'done')?.data;
  const errors = wire.filter(event => event.type === 'error').map(event => ({ message: event.message, data: event.data }));
  for (let i = 0; i < 240 && !await composer().isEnabled(); i++) await sleep(500);
  await sleep(500);
  const answer = await page.locator('article.chat-message.assistant .message-bubble.markdown-body').last().innerText();
  const taskIds = [...new Set((terminal?.response?.taskIds || terminal?.taskIds || []).map(Number))];
  const detail = { prompt, answer, request: safeRequest, httpStatus: response.status(), errors,
    answerSource: terminal?.plannerSource, planSteps: terminal?.response?.plan?.steps || terminal?.plan?.steps || [], taskIds,
    executed: terminal?.executed ?? terminal?.response?.executed,
    approvalId: terminal?.approvalId || terminal?.response?.approvalId,
    approvalStatus: terminal?.approvalStatus || terminal?.response?.approvalStatus };
  assert(response.ok() && terminal && !errors.length, 'AI流未正常完成', detail);
  assert(terminal.plannerSource === 'langchain-grounded', '未取得真实模型回答来源langchain-grounded', detail);
  assert(answer.trim().length > 15 && !/模型服务.{0,12}(不可用|未能|失败)|模型调用失败|请求失败/.test(answer), 'AI界面回答缺失或显示模型错误', detail);
  assert(execute || (detail.executed !== true && taskIds.length === 0), '仅规划/分析意外执行新任务', detail);
  return detail;
}
function checkPlan(detail, tool) {
  const steps = detail.planSteps;
  assert(steps.length === 1 && steps[0].toolCode === tool, '计划必须恰好包含指定工具一项', detail);
  const params = steps[0].parameters || {};
  if (tool === 'nmap_service_scan') {
    assert(params.ports === String(PORT), 'nmap端口必须严格等于18888', detail);
    assert(params.mode === 'service', 'nmap模式必须明确为service', detail);
    assert(Object.keys(params).every(key => ['ports', 'mode'].includes(key)), 'nmap计划出现额外参数', detail);
  }
  if (tool === 'http_security_check') assert(params.check === 'cookies' && Object.keys(params).length === 1, 'HTTP安全检查必须仅check=cookies', detail);
  if (tool === 'http_headers') assert(Object.keys(params).length === 0, '响应头检查出现额外参数', detail);
  if (tool === 'tcp_ports') assert(params.ports === String(PORT) && Object.keys(params).length === 1, 'TCP只允许唯一端口18888', detail);
  for (const key of ['url', 'target', 'targetValue', 'host'])
    assert(!params[key] || [URL, HOST].includes(params[key]), '计划包含其他目标：' + key, detail);
}
async function openTargetAi() {
  await navigate(page, 'AI 安全助手');
  await page.getByRole('button', { name: '新对话', exact: true }).click();
  await navigate(page, '授权目标');
  await page.getByPlaceholder('搜索名称 / 地址 / 类型 / 授权记录').fill(TARGET);
  await (await waitRow(page, TARGET, 15000)).getByRole('button', { name: 'AI 规划', exact: true }).click();
  await composer().waitFor({ state: 'visible' });
  await page.locator('.target-picker').filter({ hasText: displayedTargetName(TARGET) }).waitFor({ state: 'visible', timeout: 30000 });
}
async function waitTask(taskId, tool) {
  await navigate(page, '检测任务');
  const clearFilters = page.getByRole('button', { name: '清除筛选', exact: true });
  if (await clearFilters.isVisible()) await clearFilters.click();
  const projectSelect = page.locator('.el-select').filter({ has: page.getByRole('combobox', { name: '按项目筛选' }) });
  if (await projectSelect.count()) await selectOn(page, projectSelect, PROJECT);
  await page.getByPlaceholder('搜任务 ID / 工具').fill(String(taskId));
  let text = '', status = '', row;
  for (let i = 0; i < 240; i++) {
    row = page.locator('.el-table__row').filter({ has: page.locator('td:first-child .cell').filter({ hasText: new RegExp(`^\\s*${taskId}\\s*$`) }) });
    if (await row.count() === 1) {
      text = await row.innerText();
      const names = { nmap_service_scan: 'Nmap 服务识别', http_headers: 'HTTP 安全响应头检查', http_security_check: 'HTTP 常见安全检查', tcp_ports: 'TCP 端口探测', fscan_scan: 'fscan 主机扫描' };
      const displayed = (await row.locator('td').nth(1).innerText()).trim();
      assert(displayed === tool || displayed === names[tool], '实际任务工具不一致', { taskId, taskText: text });
      assert(Number((await row.locator('td').nth(2).innerText()).trim()) === targetId, '实际任务目标不一致', { taskId, taskText: text });
      status = (await row.locator('td').nth(3).innerText()).trim();
      if (['成功', '失败', '超时', '拒绝', '已取消', '取消'].includes(status)) break;
    }
    await sleep(1000);
  }
  assert(status === '成功', '真实检测任务未成功：' + text, { taskId, taskStatus: status, taskText: text });
  return { taskId, taskStatus: status, taskText: text, fixture: { ...fixture, methods: { ...fixture.methods } } };
}
async function runTool(tool) {
  let execution;
  const toolName = { nmap_service_scan: 'Nmap 服务识别', tcp_ports: 'TCP 端口探测',
    http_security_check: 'HTTP 常见安全检查', http_headers: 'HTTP 安全响应头检查' }[tool];
  const parameters = tool === 'nmap_service_scan' ? '仅识别18888端口的服务'
    : tool === 'tcp_ports' ? '只对18888端口做TCP连接探测'
    : tool === 'http_security_check' ? '只检查Cookie属性' : '只获取HTTP响应头，无需额外参数';
  const scope = `当前独立项目${projectId}的唯一目标${targetId}，${URL}，授权仅端口${PORT}。`;
  const before = { requests: fixture.requests, connections: fixture.connections };
  try {
    await step(`${tool}-plan`, async () => {
      await openTargetAi();
      const result = await send(`请仅规划${scope}恰好一项${toolName}，${parameters}。不要执行，不调用其他工具，不创建多步骤或全库扫描。`);
      checkPlan(result, tool); return result;
    });
    execution = await step(`${tool}-execute`, async () => {
      const result = await send(`确认执行上面的唯一一项${toolName}。${scope}${parameters}。仅创建一次任务，不调用其他工具、不扩展扫描范围。`, true);
      checkPlan(result, tool);
      assert(result.taskIds.length === 1 && Number.isSafeInteger(result.taskIds[0]) && result.taskIds[0] > 0, '必须派发恰好一个真实任务', result);
      return result;
    });
    const taskId = execution.taskIds[0];
    await step(`${tool}-task`, async () => {
      const result = await waitTask(taskId, tool);
      assert(fixture.connections > before.connections, '任务成功但本机夹具没有新连接', result);
      if (['http_headers', 'http_security_check'].includes(tool)) assert(fixture.requests > before.requests, 'HTTP任务成功但夹具没有新HTTP请求', result);
      return result;
    });
    await step(`${tool}-summary`, async () => {
      const row = page.locator('.el-table__row').filter({ has: page.locator('td:first-child .cell').filter({ hasText: new RegExp(`^\\s*${taskId}\\s*$`) }) });
      await row.getByRole('button', { name: 'AI 分析', exact: true }).click();
      const result = await send(`仅分析刚成功完成的检测任务${taskId}（${toolName}）。${scope}结合实际结果给出可见证据、局限和下一步建议；不要创建或执行任何任务。`);
      assert(result.request.refs.some(ref => ref.type === 'task' && String(ref.id) === String(taskId)), 'AI分析未引用本次实际任务', result);
      return { ...result, analyzedTaskId: taskId, note: '真实任务成功后的AI结果分析已完成；无新任务。' };
    });
  } catch (error) {
    const plannedIds = [`${tool}-plan`, `${tool}-execute`, `${tool}-task`, `${tool}-summary`];
    for (const id of plannedIds.filter(id => !results.some(result => result.id === id)))
      results.push({ id, status: 'BLOCKED', seconds: 0, note: '前置步骤未通过，未继续该工具闭环。' });
    save();
  }
}
async function main() {
  console.log('RESULTS ' + OUT);
  assert(selected.length > 0 && selected.every(tool => supported.includes(tool)), '只允许工具：' + supported.join(','));
  try {
    await step('fixture-start', startFixture);
    await step('exe-attach', attach);
    await step('project-create', createProject);
    await step('project-activate', activateProject);
    await step('target-create', createTarget);
    for (const tool of selected) await runTool(tool);
  } catch (error) {
    for (const tool of selected) if (!results.some(result => result.id === `${tool}-plan`))
      results.push({ id: `${tool}-plan`, status: 'BLOCKED', seconds: 0, note: '本机夹具/独立项目/目标前置步骤失败，未发送AI执行请求。' });
  } finally {
    if (server?.listening) {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
      fixture.listening = false;
    }
    save();
  }
  console.log('COMPLETE ' + OUT);
  // No browser.close(): leave the EXE, session and all acceptance business data with the user.
  process.exit(results.some(result => result.status !== 'PASS') ? 1 : 0);
}
module.exports = { step, startFixture, attach, createProject, activateProject, createTarget, restoreScope, openTargetAi,
  send, waitTask, shot, parseWire, runTool, save, results, fixture, displayedTargetName,
  state: () => ({ page, projectId, targetId, projectName: PROJECT, targetName: TARGET, out: OUT, url: URL, port: PORT }),
  closeFixture: async () => { if (server?.listening) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); fixture.listening = false; } },
};
if (require.main === module) main().catch(error => { console.error(String(error)); save(); process.exit(2); });
