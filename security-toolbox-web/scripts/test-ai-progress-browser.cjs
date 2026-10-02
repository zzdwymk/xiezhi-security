// Isolated real Vue component. Uses a fresh headless browser profile and a local
// Vite server; it never opens or connects to the running desktop application.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '../.run/ai-progress-fluent2', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(output, { recursive: true });
const html = `<!doctype html><html lang="zh-CN" data-system-theme="light" data-window-material="none" style="height:auto;overflow:auto"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Isolated AI progress component</title><style>body{margin:8px;background:var(--app-surface-strong);color:var(--app-text)}#fixture{width:100%;max-width:720px}</style></head><body style="margin:8px;width:auto;height:auto;min-height:100vh;overflow:visible"><div id="fixture"></div><script type="module">
import { createApp, h, reactive } from 'vue';
import Panel from '/src/components/AiProgressPanel.vue';
import '/src/unified-theme.css';
const start = new Date(Date.now()-8000).toISOString();
const state = reactive({message:{id:'fixture',role:'assistant',content:'',status:'running',taskIds:[],steps:[],createdAt:start,updatedAt:start,agentEvents:[{type:'session',summary:'已载入授权目标',createdAt:start},{type:'evidence',stage:'retrieving',evidenceCount:5,summary:'检索到与当前请求有关的资料',createdAt:start},{type:'plan',stage:'generating',summary:'正在根据证据整理回答',createdAt:start}]},tasks:[]});
window.progressFixture = state;
window.progressFixtureTaskClicks=0;
createApp({setup:()=>()=>h(Panel,{...state,onOpenTasks:()=>{window.progressFixtureTaskClicks++;}})}).mount('#fixture');
</script></body></html>`;
let browser, server;
const results = [];
async function check(name, run) { const detail = await run(); results.push({ name, status: 'PASS', detail }); console.log('PASS ' + name); }
function ratio(foreground, background) {
  const luminance = value => {
    const channels = value.match(/[a-f0-9]{2}/gi).map(hex => parseInt(hex,16)/255).map(value => value <= .04045 ? value/12.92 : ((value+.055)/1.055)**2.4);
    return channels[0]*.2126 + channels[1]*.7152 + channels[2]*.0722;
  };
  const a = luminance(foreground), b = luminance(background);
  return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);
}
(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile: false, root, cacheDir: path.join(output,'vite-cache'), optimizeDeps:{entries:[],include:['vue'],noDiscovery:true}, plugins: [vue(), { name:'isolated-progress-fixture', configureServer(instance) {
    instance.middlewares.use(async (req,res,next) => {
      if (req.url !== '/__ai-progress-fixture') return next();
      res.setHeader('Content-Type','text/html; charset=utf-8'); res.end(await instance.transformIndexHtml(req.url,html));
    });
  } }], server: { host:'127.0.0.1', port:0, hmr:false, watch:{ignored:['**/desktop-release/**','**/dist/**']} }, logLevel:'error' });
  await server.listen();
  const port = server.httpServer.address().port;
  browser = await chromium.launch({ executablePath:process.env.AI_PROGRESS_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', headless:true });
  const page = await browser.newPage({ viewport:{width:736,height:900}, colorScheme:'light' });
  const consoleErrors = [];
  page.on('pageerror', error => consoleErrors.push(error.message));
  await page.goto(`http://127.0.0.1:${port}/__ai-progress-fixture`);
  await page.locator('.progress-spinner').waitFor();
  await check('default status is lightweight and a completed question occupies one 44px line', async () => {
    assert.equal(await page.locator('.progress-facts').isVisible(),false);
    assert.equal(await page.locator('.progress-milestones').isVisible(),false);
    const style=await page.locator('.ai-progress-panel').evaluate(element=>({background:getComputedStyle(element).backgroundColor,border:getComputedStyle(element).borderTopWidth,titleFont:getComputedStyle(element.querySelector('.progress-heading strong')).fontSize,activityFont:getComputedStyle(element.querySelector('.progress-activity')).fontSize}));
    assert.equal(style.background,'rgba(0, 0, 0, 0)'); assert.equal(style.border,'0px'); assert.equal(style.titleFont,'14px'); assert.equal(style.activityFont,'14px');
    await page.evaluate(()=>{window.progressFixture.message.status='completed';});
    assert.equal(await page.locator('.progress-activity').count(),0);
    const bounds=await page.locator('.ai-progress-panel').boundingBox(); assert.ok(bounds.height>=44&&bounds.height<=48,JSON.stringify(bounds));
    await page.screenshot({path:path.join(output,'completed-no-tools.png'),fullPage:true});
    await page.evaluate(()=>{window.progressFixture.message.status='running';}); return {...style,completedHeight:bounds.height};
  });
  await check('real Vue disclosure responds to keyboard and retains visible focus', async () => {
    const toggle = page.locator('.progress-toggle');
    await toggle.focus(); await page.keyboard.press('Enter');
    await page.locator('.progress-timeline').waitFor({state:'visible'});
    assert.equal(await toggle.getAttribute('aria-expanded'),'true');
    const focus = await toggle.evaluate(element => ({ width:getComputedStyle(element).outlineWidth, style:getComputedStyle(element).outlineStyle, focused:document.activeElement===element }));
    assert.equal(focus.width,'2px'); assert.equal(focus.style,'solid'); assert.equal(focus.focused,true);
    await page.keyboard.press('Enter');
    assert.equal(await toggle.getAttribute('aria-expanded'),'false');
    await page.screenshot({path:path.join(output,'light-720.png'),fullPage:true}); return focus;
  });
  async function layout() {
    return page.evaluate(() => {
      const panel=document.querySelector('.ai-progress-panel'), bounds=panel.getBoundingClientRect();
      const overflow=[...panel.querySelectorAll('p,strong,time,.task-heading>span,.milestone-fact,.progress-toggle')].filter(element=>element.getClientRects().length).filter(element=>element.getBoundingClientRect().right>bounds.right+1||element.getBoundingClientRect().left<bounds.left-1).map(element=>({tag:element.tagName,text:element.textContent.slice(0,80)}));
      return {viewport:innerWidth,documentWidth:document.documentElement.scrollWidth,panelWidth:bounds.width,overflow};
    });
  }
  await page.setViewportSize({width:320,height:900});
  await page.evaluate(() => {
    const state=window.progressFixture;
    state.message.taskIds=[11,12,13]; state.message.executionDecision='EXECUTE';
    state.tasks=['RUNNING','FAILED','SUCCESS'].map((status,index)=>({id:11+index,toolCode:index===0?'authorized_long_tool_name_without_spaces_for_reflow':'http_security_check',status,createdAt:state.message.createdAt,progressMessage:'正在验证授权目标的响应证据：https://example.test/very/long/path/with/parameters?evidence=abcdefghijklmnopqrstuv'}));
  });
  await check('320px viewport reflows actual task and progress content without horizontal clipping', async () => {
    await page.getByRole('button',{name:'查看详细过程'}).click();
    const result=await layout(); assert.ok(result.documentWidth<=320,JSON.stringify(result)); assert.deepEqual(result.overflow,[]);
    await page.screenshot({path:path.join(output,'light-320-expanded.png'),fullPage:true}); return result;
  });
  await check('completed actual tool calls remain as compact rows with expandable results and task navigation', async () => {
    await page.getByRole('button',{name:'收起详细过程'}).click();
    await page.evaluate(()=>{window.progressFixture.message.status='completed';window.progressFixture.tasks.forEach(task=>{task.status='SUCCESS';});});
    assert.equal(await page.locator('.progress-tool-call').count(),3);
    assert.equal(await page.locator('.progress-activity').count(),0);
    assert.equal(await page.locator('.progress-facts').isVisible(),false);
    const first=page.locator('.progress-tool-call').first();
    assert.match(await first.locator('summary').innerText(),/成功/);
    await first.locator('summary').click(); assert.equal(await first.locator('.tool-detail p').isVisible(),true);
    await first.getByRole('button',{name:'查看任务'}).click(); assert.equal(await page.evaluate(()=>window.progressFixtureTaskClicks),1);
    await first.locator('summary').click();
    await page.screenshot({path:path.join(output,'completed-tool-calls.png'),fullPage:true});
    await page.evaluate(()=>{window.progressFixture.message.status='running';window.progressFixture.tasks.forEach((task,index)=>{task.status=['RUNNING','FAILED','SUCCESS'][index];});});
    await page.getByRole('button',{name:'查看详细过程'}).click(); return {calls:3,taskNavigationEmitted:true};
  });
  await check('200 percent component text size remains readable at 320px', async () => {
    await page.locator('.ai-progress-panel').evaluate(element=>{
      for (const [token,value] of Object.entries({'--fontSizeBase200':'24px','--lineHeightBase200':'32px','--fontSizeBase300':'28px','--lineHeightBase300':'40px'})) element.style.setProperty(token,value);
    });
    const result=await layout(); assert.ok(result.documentWidth<=320,JSON.stringify(result)); assert.deepEqual(result.overflow,[]);
    const font=await page.locator('.progress-heading strong').evaluate(element=>getComputedStyle(element).fontSize);
    assert.equal(font,'28px');
    await page.locator('.progress-toggle').scrollIntoViewIfNeeded();
    const button=await page.locator('.progress-toggle').boundingBox(); assert.ok(button.y>=0&&button.y+button.height<=900);
    await page.screenshot({path:path.join(output,'light-320-text-200.png'),fullPage:true}); return {...result,font,detailControlReachable:true,method:'2x component typography tokens; not browser-toolbar zoom'};
  });
  await check('official status foreground values pass contrast on both supported base surfaces', async () => {
    const entries=[['danger','#6e0811','#eeacb2'],['success','#0e700e','#54b054'],['warning','#bc4b09','#faa06b']];
    const contrast=entries.map(([name,light,dark])=>({name,light,lightRatio:ratio(light,'#ffffff'),dark,darkRatio:ratio(dark,'#242430'),darkAltRatio:ratio(dark,'#1c1c24')}));
    assert.ok(contrast.every(entry=>entry.lightRatio>=4.5&&entry.darkRatio>=4.5&&entry.darkAltRatio>=4.5));
    async function renderedTokens() {
      return page.locator('.ai-progress-panel').evaluate(panel=>{
        const sample=document.createElement('span'); panel.append(sample);
        const colors=['colorStatusDangerForeground2','colorStatusSuccessForeground1','colorStatusWarningForeground1'].map(token=>{
          sample.style.color=`var(--${token})`; return getComputedStyle(sample).color;
        }); sample.remove(); return colors;
      });
    }
    const lightRendered=await renderedTokens();
    assert.deepEqual(lightRendered,['rgb(110, 8, 17)','rgb(14, 112, 14)','rgb(188, 75, 9)']);
    await page.emulateMedia({colorScheme:'dark'});
    await page.evaluate(()=>{document.documentElement.dataset.systemTheme='dark';window.progressFixture.message.status='failed';window.progressFixture.message.content='模型连接超时，请检查连接后重试';});
    const color=await page.locator('.progress-tool-call.failed .tool-state').evaluate(element=>getComputedStyle(element).color);
    assert.equal(color,'rgb(238, 172, 178)');
    const darkRendered=await renderedTokens();
    assert.deepEqual(darkRendered,['rgb(238, 172, 178)','rgb(84, 176, 84)','rgb(250, 160, 107)']);
    await page.screenshot({path:path.join(output,'dark-320-text-200.png'),fullPage:true}); return {contrast,lightRendered,darkRendered,renderedDanger:color};
  });
  await check('forced colors retain icons and keyboard focus while reduced motion stops spinning', async () => {
    await page.emulateMedia({forcedColors:'active',reducedMotion:'reduce'});
    await page.evaluate(()=>{window.progressFixture.message.status='running';});
    await page.getByRole('button',{name:'收起详细过程'}).focus();
    const state=await page.evaluate(()=>{
      const spinner=getComputedStyle(document.querySelector('.progress-spinner'));
      const icon=getComputedStyle(document.querySelector('.progress-milestones .fluent-system-icon')||document.querySelector('.progress-tool-call .fluent-system-icon'));
      const button=getComputedStyle(document.querySelector('.progress-toggle'));
      return {animation:spinner.animationName,spinnerColor:spinner.borderTopColor,spinnerTrack:spinner.borderBottomColor,iconColor:icon.backgroundColor,focus:button.outlineWidth,forced:matchMedia('(forced-colors: active)').matches,reduced:matchMedia('(prefers-reduced-motion: reduce)').matches};
    });
    assert.equal(state.animation,'none'); assert.equal(state.forced,true); assert.equal(state.reduced,true); assert.notEqual(state.iconColor,'rgba(0, 0, 0, 0)'); assert.ok(parseFloat(state.focus)>=2);
    await page.screenshot({path:path.join(output,'forced-colors-reduced-motion.png'),fullPage:true}); return state;
  });
  assert.deepEqual(consoleErrors,[]);
  fs.writeFileSync(path.join(output,'results.json'),JSON.stringify({scope:'isolated real Vue component, fresh headless Edge; no live product session',results,consoleErrors},null,2));
  console.log(`${results.length} browser checks passed. Evidence: ${output}`);
})().catch(error=>{fs.writeFileSync(path.join(output,'results.json'),JSON.stringify({results,error:String(error.stack||error)},null,2));console.error(error);process.exitCode=1;}).finally(async()=>{await browser?.close();await server?.close();});


