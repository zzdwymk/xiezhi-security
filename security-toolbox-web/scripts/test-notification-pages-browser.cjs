// Exercise actual notification route handlers in mounted pages; all API operations are fixtures.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '../.run/notification-pages');
fs.mkdirSync(output, { recursive: true });
let server, browser;
const errors = [], failures = [];
const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module">
import {createApp} from 'vue';import {createPinia} from 'pinia';import {createRouter,createMemoryHistory,RouterView} from 'vue-router';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';import '/src/desktop-v2.css';import '/src/unified-theme.css';
import Tasks from '/src/views/Tasks.vue';import Workflow from '/src/views/Workflow.vue';import Project from '/src/views/ProjectDetail.vue';import {endpoints} from '/src/api';import {useAuthStore} from '/src/stores/auth';
sessionStorage.setItem('security_toolbox_session_token','fixture');
window.calls=[];window.planDelays={};
const projects=[1,2,3].map(id=>({id,name:'Project '+id,status:'ACTIVE',authorizationStatement:'Fixture only',authorizationValidFrom:'2020-01-01T00:00:00',authorizationExpiresAt:'2099-01-01T00:00:00'}));
const target={id:9,name:'Fixture target',targetValue:'fixture.invalid',targetType:'domain',allowedPorts:'80',enabled:true};
const task=id=>({id,projectId:3,targetId:9,toolCode:'http_probe',status:'SUCCESS',progress:100,progressDeterminate:true,createdAt:'2026-10-01T12:00:00',resultJson:JSON.stringify({summary:'TASK_RESULT_'+id,data:{marker:'AUTHORITATIVE_'+id},findings:[]})});
const spec=id=>({version:2,workflowId:'fixture-'+id,scopeId:2,revision:1,specDigest:'snapshot-'+id,steps:[{nodeId:'saved-'+id,tool:'http_probe',parameters:{}}],graph:{nodes:[{id:'__start__',type:'system',label:'开始',position:{x:20,y:100}},{id:'saved-'+id,type:'tool',tool:'http_probe',label:'SAVED_SNAPSHOT_'+id,position:{x:280,y:100}},{id:'__end__',type:'system',label:'结束',position:{x:550,y:100}}],edges:[{source:'__start__',target:'saved-'+id},{source:'saved-'+id,target:'__end__'}]}});
const run=id=>({run:{id,projectId:id===501?2:3,targetId:9,status:'COMPLETED',progress:100,message:'RUN_RESULT_'+id,workflowDigest:'snapshot-'+id,createdAt:'2026-10-01T12:00:00'},spec:spec(id),tasks:[{...task(id+1000),workflowNodeId:'saved-'+id}]});
const approvals=[41,42].map(id=>({id,projectId:3,action:'AI_PLAN_EXECUTION',status:'PENDING',requestedBy:'fixture',createdAt:'2026-10-01T12:00:00'}));
const respond={
  projects:()=>projects,targets:()=>[target],project:id=>projects.find(p=>p.id===id),
  projectTargets:id=>[{projectId:id,targetId:9,target}],
  projectSummary:id=>({project:projects.find(p=>p.id===id),targetCount:1,taskCount:0,vulnerabilityCount:0,retestCount:0,auditCount:0}),
  tasks:()=>[task(1)],task,
  taskControlStatus:()=>({runningTaskCount:0,pendingTaskCount:0,maxConcurrentTasks:3}),
  scanSchedules:()=>Array.from({length:30},(_,i)=>({id:100+i,projectId:3,targetId:9,toolCode:'http_probe',cronExpression:'0 0 3 * * *',enabled:true,createdAt:'2026-10-01T12:00:00'})),
  dependencies:()=>({os:'fixture',architecture:'x64',dependencies:[]}),
  getWorkflowSpec:()=>spec('CURRENT'),workflowRuns:()=>[],workflowRun:run,
  projectApprovals:()=>approvals,
  projectReportSummary:id=>({project:projects.find(p=>p.id===id),targets:[target],vulnerabilityDiscovery:[],findings:[],approvals,verification:{},approvalAndAudit:{}}),
  projectAiApprovalPlan:async(projectId,id)=>{if(window.planDelays[id])await new Promise(resolve=>setTimeout(resolve,window.planDelays[id]));return {targetId:9,status:'PENDING',plan:{summary:'SAVED_PLAN_'+id,steps:[{toolCode:'http_probe',title:'PLAN_STEP_'+id,reason:'Fixture only',risk:'CAUTION',requiresApproval:true,parameters:{ports:'80'}}]},dispatch:null};},
};
for(const key of Object.keys(endpoints))endpoints[key]=async(...args)=>{window.calls.push([key,...args]);return {data:respond[key]?await respond[key](...args):[]};};
const router=createRouter({history:createMemoryHistory(),routes:[{path:'/tasks',component:Tasks},{path:'/workflow',component:Workflow},{path:'/projects/:id',component:Project}]});
const app=createApp(RouterView);app.use(createPinia());app.use(router);app.use(ElementPlus);useAuthStore().user={username:'admin',role:'ADMIN'};
window.fixtureNavigate=to=>router.push(to);await router.push(new URL(location.href).searchParams.get('start')||'/tasks');await router.isReady();app.mount('#app');window.fixtureReady=true;
</script></body></html>`;

async function test(name, body) {
  try { await body(); console.log('PASS ' + name); }
  catch (error) { failures.push(name + ': ' + error.message); console.error('FAIL ' + name + ': ' + error.message); }
}

async function pageFor(start) {
  const page = await browser.newPage({ viewport: { width: 1480, height: 1000 } });
  page.setDefaultTimeout(12000);
  page.on('pageerror', error => errors.push(error.message));
  // No request can reach an actual backend, target, scanner or approval endpoint.
  await page.route('**/api/**', route => route.fulfill({ status: 200, contentType: 'text/event-stream', body: '' }));
  await page.goto('http://127.0.0.1:' + server.httpServer.address().port + '/__notification_pages?start=' + encodeURIComponent(start));
  await page.waitForFunction(() => window.fixtureReady);
  return page;
}

function assertNoExecution(calls) {
  assert.deepEqual(calls.filter(([key]) => /^(createTask|retryTask|cancelTask|runAgent|runWorkflow|executeWorkflow|startWorkflow|stopWorkflow|preflightWorkflow|saveWorkflowSpec|createScanSchedule|decideProjectApproval|resumeProjectAiApproval|dispatchAi)/.test(key)), []);
}

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.join(output, 'cache'),
    optimizeDeps: { entries: [], include: ['vue', 'element-plus', 'pinia', 'vue-router'], noDiscovery: true },
    plugins: [vue(), { name: 'notification-pages-fixture', configureServer(s) { s.middlewares.use(async (req, res, next) => {
      if (req.url?.split('?')[0] !== '/__notification_pages') return next();
      res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.end(await s.transformIndexHtml(req.url, html));
    }); } }], server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/dist/**', '**/desktop-release/**'] } }, logLevel: 'error' });
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.NOTIFICATION_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless: true });

  await test('taskId loads authoritative details outside the current list and supports another notification', async () => {
    const page = await pageFor('/tasks?taskId=77');
    const dialog = page.getByRole('dialog', { name: '任务详情', exact: true });
    await dialog.getByText('TASK_RESULT_77', { exact: true }).waitFor();
    assert.match(await dialog.innerText(), /77/);
    await page.evaluate(() => window.fixtureNavigate('/tasks?taskId=78&_notice=2'));
    await dialog.getByText('TASK_RESULT_78', { exact: true }).waitFor();
    assert.equal(await dialog.getByText('TASK_RESULT_77', { exact: true }).count(), 0);
    assertNoExecution(await page.evaluate(() => window.calls));
    await page.close();
  });

  await test('scheduleId opens the manager and moves to the highlighted row on page two', async () => {
    const page = await pageFor('/tasks?scheduleId=125');
    const dialog = page.getByRole('dialog', { name: '定时任务管理', exact: true });
    const row = dialog.locator('.notification-schedule-row');
    await row.waitFor();
    assert.match(await row.innerText(), /125/);
    assert.equal(await dialog.locator('.el-pager .is-active').innerText(), '2');
    assertNoExecution(await page.evaluate(() => window.calls));
    await page.close();
  });

  await test('runId selects its project and restores the saved graph and run details', async () => {
    const page = await pageFor('/workflow?runId=501');
    await page.getByRole('button', { name: '返回当前工作流', exact: true }).waitFor();
    await page.getByText('SAVED_SNAPSHOT_501', { exact: true }).first().waitFor();
    assert.match(await page.getByLabel('当前工作流配置', { exact: true }).innerText(), /Project 2/);
    assert.match(await page.locator('.run-history-select').innerText(), /#501/);
    await page.getByRole('button', { name: '展开运行日志', exact: true }).click();
    assert.match(await page.getByLabel('工作流执行日志', { exact: true }).inputValue(), /RUN_RESULT_501/);
    const calls = await page.evaluate(() => window.calls);
    assert.ok(calls.some(([key, projectId]) => key === 'projectTargets' && projectId === 2));
    assertNoExecution(calls);
    await page.screenshot({ path: path.join(output, 'workflow-snapshot.png'), fullPage: true });
    await page.close();
  });

  await test('approvalId opens the requested pending plan, including one outside the current list, without execution', async () => {
    const page = await pageFor('/projects/3?approvalId=42');
    const dialog = page.getByRole('dialog', { name: 'AI 行动方案与执行确认', exact: true });
    const fullPlan = dialog.getByLabel('完整方案，只读', { exact: true });
    await dialog.waitFor();
    assert.match(await fullPlan.inputValue(), /SAVED_PLAN_42/);
    assert.equal(await page.getByRole('tab', { name: '执行确认与审计', exact: true }).getAttribute('aria-selected'), 'true');
    assert.equal(await dialog.getByRole('button', { name: '允许执行', exact: true }).isEnabled(), true);
    await page.evaluate(() => window.fixtureNavigate('/projects/3?approvalId=99&_notice=next'));
    await page.waitForFunction(() => [...document.querySelectorAll('textarea')].some(el => el.value.includes('SAVED_PLAN_99')));
    assert.match(await fullPlan.inputValue(), /SAVED_PLAN_99/);
    const beforeReopen = await page.evaluate(() => window.calls.filter(([key, projectId, id]) => key === 'projectAiApprovalPlan' && id === 99).length);
    await dialog.getByRole('button', { name: '关闭', exact: true }).click();
    await dialog.waitFor({ state: 'hidden' });
    await page.evaluate(() => window.fixtureNavigate('/projects/3?approvalId=99&_notice=reopen'));
    await dialog.waitFor();
    assert.match(await fullPlan.inputValue(), /SAVED_PLAN_99/);
    assert.equal(await page.evaluate(() => window.calls.filter(([key, projectId, id]) => key === 'projectAiApprovalPlan' && id === 99).length), beforeReopen + 1);
    assertNoExecution(await page.evaluate(() => window.calls));
    await page.close();
  });

  await test('a newer approval notification wins while an older plan is still loading', async () => {
    const page = await pageFor('/projects/3');
    await page.waitForFunction(() => window.calls.some(([key]) => key === 'projectApprovals'));
    await page.evaluate(() => { window.planDelays[41] = 700; return window.fixtureNavigate('/projects/3?approvalId=41'); });
    await page.waitForFunction(() => window.calls.some(([key, projectId, id]) => key === 'projectAiApprovalPlan' && id === 41));
    await page.evaluate(() => window.fixtureNavigate('/projects/3?approvalId=99&_notice=latest'));
    const dialog = page.getByRole('dialog', { name: 'AI 行动方案与执行确认', exact: true });
    await dialog.waitFor();
    await page.waitForTimeout(900);
    assert.match(await dialog.getByLabel('完整方案，只读', { exact: true }).inputValue(), /SAVED_PLAN_99/);
    assertNoExecution(await page.evaluate(() => window.calls));
    await page.close();
  });
  assert.deepEqual(errors, [], 'No Vue/browser errors');
  if (failures.length) throw new Error(failures.join('\n'));
  console.log('PASS notification page deep links; no live scans or approval actions');
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  await browser?.close(); await server?.close();
});
