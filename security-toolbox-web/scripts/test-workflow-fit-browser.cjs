// Render the actual Workflow.vue and Vue Flow in an isolated headless profile.
// API replies below are fixtures; no live project, app, or scanner is contacted.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../.run/workflow-fit', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(out, { recursive: true });
const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
html,body{margin:0!important;height:auto!important;overflow:auto!important}#fixture-sidebar{position:fixed;left:0;top:0;bottom:0;width:260px;background:#eef2f6;z-index:100}#app{margin-left:260px!important;width:calc(100% - 260px)!important;height:auto!important;padding:24px;box-sizing:border-box;min-height:100vh}
</style></head><body><aside id="fixture-sidebar">隔离测试侧栏</aside><div id="app"></div><script type="module">
import {createApp} from 'vue';import {createRouter,createMemoryHistory} from 'vue-router';import {createPinia} from 'pinia';
import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';import '/src/unified-theme.css';
import Workflow from '/src/views/Workflow.vue';
const router=createRouter({history:createMemoryHistory(),routes:[{path:'/',component:{template:'<div />'}}]});
createApp(Workflow).use(router).use(createPinia()).use(ElementPlus).mount('#app');
</script></body></html>`;
const compact = { scopeId: 1, workflowId: 'fixture', revision: 1, specDigest: 'sha256:' + 'a'.repeat(64), version: 2,
  steps: [{nodeId:'context',tool:'retrieve_project_context',label:'项目情报检索',parameters:{},group:0}],
  graph: { nodes: [
    {id:'__start__',type:'start',label:'开始',phase:'engagement',position:{x:0,y:100}},
    {id:'context',type:'tool',tool:'retrieve_project_context',label:'项目情报检索',phase:'recon',position:{x:220,y:100}},
    {id:'__end__',type:'end',label:'结束',phase:'report',position:{x:640,y:100}},
  ], edges:[{id:'start-context',source:'__start__',target:'context'},{id:'context-end',source:'context',target:'__end__'}] } };
let browser, server;
const results = [], errors = [], unexpected = [];
async function check(name, fn) { const detail = await fn(); results.push({name,status:'PASS',detail}); console.log('PASS '+name); }
async function measure(page) {
  return page.locator('.flow-canvas').evaluate(canvas => {
    const box = el => {const r=el.getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,right:r.right,bottom:r.bottom};};
    const bounds=box(canvas), nodes=[...canvas.querySelectorAll('.vue-flow__node')].map(node=>({id:node.dataset.id,...box(node)}));
    const transform=getComputedStyle(canvas.querySelector('.vue-flow__transformationpane')).transform;
    return {canvas:bounds,zoom:new DOMMatrixReadOnly(transform).a,nodes,outside:nodes.filter(n=>n.x<bounds.x-1||n.right>bounds.right+1||n.y<bounds.y-1||n.bottom>bounds.bottom+1)};
  });
}
async function fit(page) {
  await page.getByRole('button',{name:'适应画布',exact:true}).click();
  await page.waitForFunction(() => {
    const canvas=document.querySelector('.flow-canvas'); if(!canvas)return false;
    const bounds=canvas.getBoundingClientRect(),nodes=[...canvas.querySelectorAll('.vue-flow__node')];
    return nodes.length>0&&nodes.every(node=>{const n=node.getBoundingClientRect();return n.width>0&&n.left>=bounds.left-1&&n.right<=bounds.right+1&&n.top>=bounds.top-1&&n.bottom<=bounds.bottom+1;});
  },null,{timeout:10000});
  const result=await measure(page);assert.deepEqual(result.outside,[]);return result;
}
async function newPage(small=false) {
  const page=await browser.newPage({viewport:{width:1440,height:900}});
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/api/**',async route=>{
    const pathname=new URL(route.request().url()).pathname;
    let data;
    if(pathname==='/api/projects')data=small?[{id:1,name:'隔离布局项目',status:'ACTIVE'}]:[];
    else if(pathname==='/api/system/dependencies')data={dependencies:[]};
    else if(pathname==='/api/ai/workflow/suggest')return route.fulfill({contentType:'text/event-stream',body:'data: {"type":"done","source":"fixture"}\n\n'});
    else if(small&&pathname==='/api/ai/workflow')data=compact;
    else if(small&&['/api/targets','/api/projects/1/targets','/api/workflow-runs'].includes(pathname))data=[];
    else {unexpected.push(pathname);return route.abort();}
    return route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
  });
  await page.goto('http://127.0.0.1:'+server.httpServer.address().port+'/__workflow-fit');
  await page.locator('.vue-flow__node').first().waitFor();
  await page.waitForTimeout(500); // Initial node measurement and the existing focus animation.
  return page;
}
(async()=>{
  const {createServer}=await import('vite');const vue=(await import('@vitejs/plugin-vue')).default;
  server=await createServer({configFile:false,root,cacheDir:path.join(out,'cache'),plugins:[vue(),{name:'workflow-fit-fixture',configureServer(s){s.middlewares.use(async(req,res,next)=>{if(req.url!=='/__workflow-fit')return next();res.setHeader('Content-Type','text/html; charset=utf-8');res.end(await s.transformIndexHtml(req.url,html));});}}],server:{host:'127.0.0.1',port:0,hmr:false,watch:{ignored:['**/desktop-release/**','**/dist/**']}},logLevel:'error'});
  await server.listen();browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
  const page=await newPage();
  for(const width of [2070,1440,1180])await check('all default workflow nodes fit the actual canvas at '+width+'px',async()=>{
    await page.setViewportSize({width,height:1000});const result=await fit(page);
    assert.ok(result.nodes.length>=18,'Must render the real standard workflow');if(width<=1440)assert.ok(result.zoom<0.2);
    assert.ok(result.canvas.x>=260);
    // The start and earliest stage must receive pointer input instead of hitting the sidebar.
    for(const id of ['__start__','engage']) {
      const direct=page.locator(`.vue-flow__node[data-id="${id}"]`);
      assert.equal(await direct.count(),1,'Expected default node '+id);await direct.hover({timeout:3000});
    }
    await page.screenshot({path:path.join(out,'standard-'+width+'.png'),fullPage:true});return result;
  });
  await check('zoom-out after fit never jumps in and zoom-in remains incremental',async()=>{
    const before=await fit(page);await page.getByRole('button',{name:'缩小',exact:true}).click();
    const smaller=await measure(page);assert.ok(smaller.zoom<=before.zoom+0.000001);assert.deepEqual(smaller.outside,[]);
    await page.getByRole('button',{name:'放大',exact:true}).click();const bigger=await measure(page);
    assert.ok(bigger.zoom>smaller.zoom&&bigger.zoom<smaller.zoom*1.5);return{before:before.zoom,smaller:smaller.zoom,bigger:bigger.zoom};
  });
  await check('window resize refits automatically into the smaller canvas',async()=>{
    await page.setViewportSize({width:1640,height:950});await fit(page);
    await page.setViewportSize({width:1200,height:800});await page.waitForTimeout(300);
    const result=await measure(page);assert.deepEqual(result.outside,[]);return result;
  });
  const smallPage=await newPage(true);
  await check('ordinary small workflows keep the existing 20 percent manual floor and 160 percent ceiling',async()=>{
    const fitted=await fit(smallPage);assert.equal(fitted.nodes.length,3);assert.ok(fitted.zoom>=0.2&&fitted.zoom<=0.95);
    for(let i=0;i<18;i++)await smallPage.getByRole('button',{name:'缩小',exact:true}).click();
    const low=(await measure(smallPage)).zoom;assert.ok(Math.abs(low-0.2)<0.000001);
    for(let i=0;i<20;i++)await smallPage.getByRole('button',{name:'放大',exact:true}).click();
    const high=(await measure(smallPage)).zoom;assert.ok(Math.abs(high-1.6)<0.000001);return{fitted:fitted.zoom,low,high};
  });
  assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[]);console.log('EVIDENCE '+out);
})().catch(error=>{results.push({status:'FAIL',error:error.stack});console.error(error);process.exitCode=1;}).finally(async()=>{fs.writeFileSync(path.join(out,'results.json'),JSON.stringify({scope:'actual Workflow.vue + Vue Flow, isolated headless Edge, intercepted API fixtures',results,errors,unexpected},null,2));await browser?.close();await server?.close();});
