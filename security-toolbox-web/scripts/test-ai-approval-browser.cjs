// Fresh headless Edge + isolated Vite; never connects to the packaged app.
const assert=require('node:assert/strict');
const fs=require('node:fs');const path=require('node:path');
const {chromium}=require('playwright-core');
const root=path.resolve(__dirname,'..');
const out=path.resolve(root,'../.run/ai-approval-dialog',new Date().toISOString().replace(/[:.]/g,'-'));
fs.mkdirSync(out,{recursive:true});
const html=`<!doctype html><html lang="zh-CN" style="--desktop-sidebar-width:0px"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="app"></div><script type="module">
import {createApp,h,reactive} from 'vue';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';
import '/src/unified-theme.css';
import Dialog from '/src/components/AiApprovalDialog.vue';import Panel from '/src/components/AiProgressPanel.vue';
import {createAiApprovalPromptGate,isAwaitingAiApproval} from '/src/utils/aiApproval.ts';
const gate=createAiApprovalPromptGate();
const state=reactive({visible:false,busy:false,native:false,active:'current',decisions:[],message:{id:'answer',role:'assistant',content:'请审核',status:'completed',approvalId:40,approvalStatus:'REQUIRED',taskIds:[],steps:[{toolCode:'nuclei_scan',parameters:{},requiresApproval:true,risk:'CAUTION'}],createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()}});
window.fixture=state;window.deliver=(thread)=>{if(gate(state.active,thread,state.message))state.visible=true;};
createApp({setup:()=>()=>h('main',[
h('div',{class:state.native?'desktop-v2-native-frame':undefined,style:{display:'none'}}),
h('button',{onClick:()=>state.visible=true},'查看审批详情'),h(Panel,{message:state.message,tasks:[]}),
h(Dialog,{visible:state.visible,message:state.message,targetName:'本地验收目标',targetValue:'192.168.136.132',allowedPorts:'80',busy:state.busy,'onUpdate:visible':v=>state.visible=v,onDecide:d=>{state.decisions.push(d);state.visible=false;}})
])}).use(ElementPlus).mount('#app');
</script></body></html>`;
let browser,server;const results=[];const errors=[];
async function check(name,run){await run();results.push({name,status:'PASS'});console.log('PASS '+name);}
(async()=>{
 const {createServer}=await import('vite');const vue=(await import('@vitejs/plugin-vue')).default;
 server=await createServer({configFile:false,root,cacheDir:path.join(out,'cache'),optimizeDeps:{entries:[],include:['vue','element-plus'],noDiscovery:true},plugins:[vue(),{name:'approval-fixture',configureServer(s){s.middlewares.use(async(req,res,next)=>{if(req.url!=='/__approval')return next();res.setHeader('Content-Type','text/html; charset=utf-8');res.end(await s.transformIndexHtml(req.url,html));});}}],server:{host:'127.0.0.1',port:0,hmr:false,watch:{ignored:['**/desktop-release/**','**/dist/**']}},logLevel:'error'});
 await server.listen();browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:720,height:850}});page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:'+server.httpServer.address().port+'/__approval');await page.getByRole('button',{name:'查看审批详情'}).waitFor();
 const dialog=page.getByRole('dialog',{name:'确认本次检测',exact:true});
 await check('history restoration does not auto-open; newly delivered current approval opens with exact identity',async()=>{
  assert.equal(await dialog.isVisible(),false);await page.evaluate(()=>window.deliver('other'));assert.equal(await dialog.isVisible(),false);
  await page.evaluate(()=>window.deliver('current'));await dialog.waitFor();
  assert.equal(await dialog.locator('[data-approval-id]').getAttribute('data-approval-id'),'40');
  const text=await dialog.innerText();assert.match(text,/审批单 #40/);assert.match(text,/192\.168\.136\.132/);assert.match(text,/默认安全模板/);assert.match(text,/需人工确认/);
  assert.match(await page.locator('.ai-progress-panel').innerText(),/等待确认执行计划/);
  await page.screenshot({path:path.join(out,'approval-nuclei.png'),fullPage:true,animations:'disabled'});
 });
 await check('closing remains pending and a duplicate event does not reopen; inline entry does',async()=>{
  await dialog.getByRole('button',{name:'关闭，继续等待',exact:true}).click();await dialog.waitFor({state:'hidden'});
  await page.evaluate(()=>window.deliver('current'));assert.equal(await dialog.isVisible(),false);
  assert.equal(await page.evaluate(()=>window.fixture.message.approvalStatus),'REQUIRED');assert.deepEqual(await page.evaluate(()=>window.fixture.decisions),[]);
  await page.getByRole('button',{name:'查看审批详情'}).click();await dialog.waitFor();
 });
 await check('busy approval disables every decision and close control',async()=>{
  await page.evaluate(()=>window.fixture.busy=true);
  for(const name of ['批准本次执行','拒绝','关闭，继续等待'])assert.equal(await dialog.getByRole('button',{name,exact:true}).isDisabled(),true);
  await page.keyboard.press('Escape');assert.equal(await dialog.isVisible(),true);assert.equal(await page.evaluate(()=>window.fixture.decisions.length),0);
  await page.evaluate(()=>window.fixture.busy=false);
 });
 await check('approval and rejection emit their existing handler decisions once',async()=>{
  await dialog.getByRole('button',{name:'批准本次执行',exact:true}).click();await dialog.waitFor({state:'hidden'});
  assert.deepEqual(await page.evaluate(()=>window.fixture.decisions),['APPROVED']);
  await page.getByRole('button',{name:'查看审批详情'}).click();await dialog.getByRole('button',{name:'拒绝',exact:true}).click();await dialog.waitFor({state:'hidden'});
  assert.deepEqual(await page.evaluate(()=>window.fixture.decisions),['APPROVED','REJECTED']);
 });
 await check('actual plan parameters retain false/LOW and ports/SAFE as readable Chinese at 320px',async()=>{
  await page.evaluate(()=>{window.fixture.message.approvalId=41;window.fixture.message.approvalStatus='PENDING';window.fixture.message.steps=[{toolCode:'fscan_scan',parameters:{ports:'80',vulnMode:'SAFE'},requiresApproval:true},{toolCode:'zap_scan',parameters:{spider:false,strength:'LOW'},requiresApproval:true}];window.deliver('current');});
  await page.setViewportSize({width:320,height:900});await dialog.waitFor();
  const text=await dialog.innerText();for(const pattern of [/扫描端口/,/80/,/扫描模式/,/安全/,/自动爬取/,/否/,/扫描强度/,/低/])assert.match(text,pattern);
  assert.equal(await dialog.locator('[data-approval-id]').getAttribute('data-approval-id'),'41');
  const rect=await dialog.boundingBox();assert.ok(rect.x>=0&&rect.x+rect.width<=321);
  await page.screenshot({path:path.join(out,'approval-320.png'),fullPage:true,animations:'disabled'});
 });
 for(const scenario of [
  {name:'web workspace',width:1280,height:900,sidebar:260,native:false,long:false},
  {name:'native caption and sidebar',width:1280,height:900,sidebar:260,native:true,long:false},
  {name:'short native window with long parameters',width:900,height:480,sidebar:260,native:true,long:true},
  {name:'narrow web window with long parameters',width:320,height:520,sidebar:0,native:false,long:true},
 ])await check('dialog is centered and footer reachable: '+scenario.name,async()=>{
  await page.setViewportSize({width:scenario.width,height:scenario.height});
  await page.evaluate(async scenario=>{
   document.documentElement.style.setProperty('--desktop-sidebar-width',scenario.sidebar+'px');
   window.fixture.native=scenario.native;
   window.fixture.message.steps=Array.from({length:scenario.long?24:1},(_,index)=>({id:'layout-'+index,toolCode:'msf_scan',requiresApproval:true,risk:'CAUTION',parameters:{module:'auxiliary/scanner/http/http_header',options:{HTTP_METHOD:'HEAD',TARGETURI:'/'+('long-path/'.repeat(scenario.long?12:1))}}}));
   await new Promise(requestAnimationFrame);
  },scenario);
  await dialog.waitFor();
  assert.match(await dialog.innerText(),/模块参数/);
  const layout=await dialog.evaluate(element=>{
   const rect=value=>{const r=value.getBoundingClientRect();return{x:r.x,y:r.y,width:r.width,height:r.height};};
   element=element.matches('.el-dialog')?element:element.querySelector('.el-dialog');
   const body=element.querySelector('.el-dialog__body'),footer=element.querySelector('.el-dialog__footer');
   return{dialog:rect(element),overlay:rect(element.closest('.el-overlay')),workspaceGap:parseFloat(getComputedStyle(element).getPropertyValue('--desktop-workspace-gap'))||0,body:rect(body),footer:rect(footer),bodyOverflow:getComputedStyle(body).overflowY,bodyScrollHeight:body.scrollHeight,bodyClientHeight:body.clientHeight,buttons:[...footer.querySelectorAll('button')].map(rect),documentWidth:document.documentElement.scrollWidth};
  });
  const top=scenario.native?38:0;
  // The shared desktop workspace leaves an intentional right/bottom inset.
  // Verify the mask boundaries first, then centering within that actual work area.
  assert.equal(layout.overlay.x,scenario.sidebar);assert.equal(layout.overlay.y,top);
  assert.equal(layout.overlay.x+layout.overlay.width,scenario.width-layout.workspaceGap);
  assert.equal(layout.overlay.y+layout.overlay.height,scenario.height-layout.workspaceGap);
  assert.ok(Math.abs(layout.dialog.x+layout.dialog.width/2-(layout.overlay.x+layout.overlay.width/2))<=1,JSON.stringify(layout));
  assert.ok(Math.abs(layout.dialog.y+layout.dialog.height/2-(layout.overlay.y+layout.overlay.height/2))<=1,JSON.stringify(layout));
  assert.ok(layout.dialog.x>=scenario.sidebar+15&&layout.dialog.y>=top+15,JSON.stringify(layout));
  assert.ok(layout.dialog.y+layout.dialog.height<=scenario.height-15,JSON.stringify(layout));
  for(const button of layout.buttons)assert.ok(button.y>=top&&button.y+button.height<=scenario.height&&button.x>=scenario.sidebar&&button.x+button.width<=scenario.width,JSON.stringify(layout));
  if(scenario.long){assert.equal(layout.bodyOverflow,'auto');assert.ok(layout.bodyScrollHeight>layout.bodyClientHeight,JSON.stringify(layout));}
  assert.ok(layout.documentWidth<=scenario.width,JSON.stringify(layout));
  await page.screenshot({path:path.join(out,'layout-'+scenario.width+'-'+scenario.height+'-'+(scenario.native?'native':'web')+'.png'),fullPage:true,animations:'disabled'});
  results.push({name:'layout measurements: '+scenario.name,status:'PASS',layout});
 });
 assert.deepEqual(errors,[]);console.log('EVIDENCE '+out);
})().catch(e=>{results.push({status:'FAIL',error:e.stack});console.error(e);process.exitCode=1;}).finally(async()=>{fs.writeFileSync(path.join(out,'results.json'),JSON.stringify({scope:'isolated real Vue and Element Plus; no actual approval API',results,errors},null,2));if(browser)await browser.close();if(server)await server.close();});
