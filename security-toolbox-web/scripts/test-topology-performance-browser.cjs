// Actual AssetTopology.vue + Element Plus; deterministic data, no API/network access.
// Run TOPOLOGY_PERF_BASELINE=1 to record timings without performance ceilings.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../.run/topology-performance', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(out, { recursive: true });
const baseline = process.env.TOPOLOGY_PERF_BASELINE === '1';
const budgetScale = Number(process.env.TOPOLOGY_PERF_BUDGET_SCALE || 1);
assert.ok(Number.isFinite(budgetScale) && budgetScale > 0, 'performance budget scale must be positive');
const sourcePath = process.env.TOPOLOGY_PERF_SOURCE || path.join(root, 'src/components/AssetTopology.vue');
const componentSource = fs.readFileSync(sourcePath, 'utf8');
const sourceSha256 = createHash('sha256').update(componentSource).digest('hex');
const sizes = (process.env.TOPOLOGY_PERF_SIZES || '500,1000').split(',').map(Number);
const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
html,body{margin:0!important;height:100%!important}#app{padding:24px!important;height:100vh!important;box-sizing:border-box}.asset-topology-container{height:calc(100vh - 48px)!important}
</style></head><body><div id="app"></div><script type="module">
import {createApp,nextTick,h,shallowRef} from 'vue';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';
import '/src/desktop-v2.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';import '/src/motion.css';
import AssetTopology from '/src/components/AssetTopology.vue';
const params=new URL(location.href).searchParams;
const count=Number(params.get('count'));
const shared=params.get('shared')==='1';
const assets=Array.from({length:count},(_,i)=>({id:i+1,projectId:1,targetId:shared?1:i+1,url:shared?'https://shared.fixture.test/'+(i?'path-'+i:''):'https://asset-'+(i+1)+'.fixture.test/',server:'Fixture/1.0'}));
const findings=assets.flatMap(asset=>Array.from({length:3},(_,i)=>({id:asset.id*10+i,projectId:1,targetId:asset.targetId,title:'Fixture finding '+asset.id+' '+i,severity:i===0?'HIGH':'LOW',sourceTool:i===0?'fixture':'http_headers',description:'Independent fixture security finding',evidence:asset.url+'\\n'+(shared&&asset.id===1&&i===0?'Long fixture evidence line\\n'.repeat(30):'Fixture evidence '.repeat(12)),remediation:'Fixture remediation',status:'OPEN'})));
const state=shallowRef({projectId:1,hubLabel:'性能测试项目',assets,findings});
window.__fixtureFindings=findings;
const app=createApp({setup:()=>()=>h(AssetTopology,state.value)});
window.__setFixtures=async value=>{state.value={...state.value,...value};await nextTick();};
performance.mark('fixture-mount-start');app.use(ElementPlus).mount('#app');await nextTick();
requestAnimationFrame(()=>requestAnimationFrame(()=>{performance.measure('fixture-mount','fixture-mount-start');window.__fixtureReady=true;}));
window.__nextTick=nextTick;
</script></body></html>`;
let server, browser, page;
const results = [], errors = [], unexpected = [];
async function twoFrames() { await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))); }
async function closeDrawer() {
  await page.locator('.el-drawer__close-btn').click();
  await page.locator('.asset-detail-drawer').waitFor({ state: 'hidden' });
  await twoFrames();
}
async function drawerScreenshot(filename) {
  // Latency above stops at the first frames; screenshots wait for the CSS slide transition.
  await page.waitForFunction(()=>{
    const drawer=document.querySelector('.asset-detail-drawer');
    if(!drawer)return false;
    const rect=drawer.getBoundingClientRect();
    return rect.right<=innerWidth+0.5&&Math.abs(rect.width-Math.min(420,innerWidth))<2;
  });
  await twoFrames();
  await page.screenshot({path:path.join(out,filename),fullPage:true});
}
async function action(kind, index = 0) {
  return page.evaluate(async ({ kind, index }) => {
    const node = document.querySelectorAll('.node-card-group')[index];
    const started = performance.now();
    if (kind === 'hover') node.dispatchEvent(new MouseEvent('mouseenter'));
    else if (kind === 'leave') node.dispatchEvent(new MouseEvent('mouseleave'));
    else if (kind === 'keyboard') node.dispatchEvent(new KeyboardEvent('keydown', { key:'Enter', bubbles:true }));
    else node.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await window.__nextTick();
    const updateMs = performance.now() - started;
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    const frameMs = performance.now() - started;
    const drawer = document.querySelector('.asset-detail-drawer');
    return {updateMs,frameMs,hovered:node.classList.contains('is-hovered'),selected:node.classList.contains('is-selected'),drawerVisible:!!drawer&&drawer.getClientRects().length>0&&getComputedStyle(drawer).visibility!=='hidden',url:node.getAttribute('aria-label'),host:document.querySelector('.hero-host')?.textContent,findings:document.querySelectorAll('.topology-finding-card').length};
  }, { kind, index });
}
async function openFixture(origin, query) {
  page=await browser.newPage({viewport:{width:1440,height:1000}});
  page.setDefaultTimeout(30000);
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',route=>{
    const url=new URL(route.request().url());
    if(url.origin!==origin||url.pathname.startsWith('/api/')){unexpected.push(url.href);return route.abort();}
    return route.continue();
  });
  await page.goto(origin+'/__topology-performance?'+query,{timeout:120000});
  await page.waitForFunction(()=>window.__fixtureReady,{},{timeout:120000});
}
async function nodeIndex(url) {
  return page.evaluate(url=>[...document.querySelectorAll('.node-card-group')].findIndex(node=>node.getAttribute('aria-label')===url),url);
}
async function drawerMotion() {
  return page.evaluate(() => ['.asset-detail-drawer', '.asset-detail-overlay'].map(selector => {
    const element = document.querySelector(selector);
    if (!element) throw new Error('Missing ' + selector);
    const style = getComputedStyle(element);
    return {selector, durationMs: Math.max(...style.transitionDuration.split(',').map(value => parseFloat(value) * (value.trim().endsWith('ms') ? 1 : 1000)))};
  }));
}
async function mouseClickRegression(origin) {
  await openFixture(origin,'count=1');
  await page.evaluate(() => {
    window.__mouseResult = null;
    document.querySelector('.node-card-group').addEventListener('click', async event => {
      const started = performance.now();
      await window.__nextTick();
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      window.__mouseResult = {trusted:event.isTrusted,frameMs:performance.now()-started};
    }, {once:true,capture:true});
  });
  await page.locator('.node-card-group').click();
  await page.waitForFunction(() => window.__mouseResult);
  const click = await page.evaluate(() => window.__mouseResult);
  assert.equal(click.trusted,true,'real mouse input must open asset details');
  assert.equal(await page.locator('.hero-host').textContent(),'asset-1.fixture.test');
  withinBudget(click.frameMs,500,'real mouse click first frames');
  const motion = await drawerMotion();
  for (const entry of motion) assert.ok(entry.durationMs > 0 && entry.durationMs <= 180, `${entry.selector} must use a short transition`);
  await closeDrawer();
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.locator('.node-card-group').click();
  for (const entry of await drawerMotion()) assert.ok(entry.durationMs <= 0.01, `${entry.selector} must respect reduced motion`);
  await closeDrawer();
  await page.emulateMedia({reducedMotion:'no-preference'});
  await page.evaluate(() => document.documentElement.setAttribute('data-anim-decorative','off'));
  await page.locator('.node-card-group').click();
  for (const entry of await drawerMotion()) assert.ok(entry.durationMs <= 0.01, `${entry.selector} must respect animation settings`);
  results.push({scenario:'real mouse click and drawer motion preferences',status:'PASS',click,motion});
  await page.close();page=null;
}
async function burstDrag(url) {
  return page.evaluate(async url=>{
    const node=[...document.querySelectorAll('.node-card-group')].find(node=>node.getAttribute('aria-label')===url);
    const before=node.transform.baseVal.getItem(0).matrix;
    const start={x:before.e,y:before.f};
    const scale=node.getScreenCTM().a;
    const rect=node.getBoundingClientRect();
    const x=rect.x+rect.width/2,y=rect.y+rect.height/2;
    node.dispatchEvent(new MouseEvent('mousedown',{bubbles:true,button:0,clientX:x,clientY:y}));
    for(let step=1;step<=6;step++)document.dispatchEvent(new MouseEvent('mousemove',{bubbles:true,buttons:1,clientX:x+step*5,clientY:y+step*3}));
    // Mouseup in the same task must flush the pending rAF movement.
    document.dispatchEvent(new MouseEvent('mouseup',{bubbles:true,button:0,clientX:x+30,clientY:y+18}));
    await window.__nextTick();
    await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
    const end=node.transform.baseVal.getItem(0).matrix;
    return {actual:{x:end.e,y:end.f},expected:{x:start.x+30/scale,y:start.y+18/scale}};
  },url);
}
function withinBudget(value, milliseconds, label) {
  if (!baseline) assert.ok(value < milliseconds * budgetScale, `${label}: ${value.toFixed(1)} ms exceeds ${milliseconds * budgetScale} ms`);
}
async function semanticRegressions(origin) {
  await openFixture(origin,'count=1');
  const assets=[
    {id:101,projectId:1,targetId:1,url:'https://first.fixture.test/',server:'First'},
    {id:202,projectId:2,targetId:1,url:'https://second.fixture.test/',server:'Second'},
    {id:303,projectId:1,targetId:3,url:'https://path.fixture.test/admin',server:'Path',_assetKind:'path'},
  ];
  const first={id:1,projectId:1,targetId:1,title:'First project vulnerability',severity:'HIGH',sourceTool:'fixture',description:'Only first project',evidence:'First evidence',remediation:'Fix first'};
  const findings=[first,{...first,id:2},{...first,id:3,projectId:2,title:'Second project vulnerability',description:'Only second project',evidence:'Second evidence'},
    {...first,id:4,targetId:3,title:'Path vulnerability',evidence:'Path evidence'},
    {...first,id:5,targetId:99,title:'Path host fallback',evidence:'https://path.fixture.test/admin',severity:'LOW'},
  ];
  await page.evaluate(value=>window.__setFixtures(value),{projectId:'all',projects:[{id:1,name:'First'},{id:2,name:'Second'}],assets,findings});
  await twoFrames();
  assert.equal(await page.locator('.node-card-group').count(),4,'missing root host must be synthesized');
  for(const [url,title] of [[assets[0].url,first.title],[assets[1].url,'Second project vulnerability']]){
    const click=await action('click',await nodeIndex(url));
    assert.equal(click.findings,1,'project guard and exact content deduplication');
    assert.equal(await page.locator('.finding-card-title').textContent(),title);
    await closeDrawer();
  }
  const host=await action('click',await nodeIndex('https://path.fixture.test'));
  assert.equal(host.drawerVisible,true);assert.equal(host.host,'path.fixture.test');assert.equal(host.findings,2);
  await closeDrawer();
  await action('click',await nodeIndex(assets[0].url));
  const refreshedAssets=assets.map(asset=>asset.id===101?{...asset,url:'https://refreshed.fixture.test/',server:'Refreshed'}:asset);
  const refreshedFindings=findings.map(finding=>finding.projectId===1&&finding.targetId===1?{...finding,title:'Refreshed project risk',severity:'LOW'}:finding);
  await page.evaluate(value=>window.__setFixtures(value),{assets:refreshedAssets,findings:refreshedFindings});
  await twoFrames();
  assert.equal(await page.locator('.hero-host').textContent(),'refreshed.fixture.test');
  assert.equal(await page.locator('.finding-card-title').textContent(),'Refreshed project risk');
  const refreshed=page.locator('.node-card-group[aria-label="https://refreshed.fixture.test/"]');
  assert.equal(await refreshed.locator('.card--has-risk').count(),1,'memoized node must update severity badge after props change');
  assert.equal(await refreshed.locator('.card--has-vuln').count(),0);
  assert.equal(await page.locator('.topology-finding-card').count(),1);
  await drawerScreenshot('details-refreshed.png');
  await closeDrawer();
  await page.getByRole('button',{name:'适应画布',exact:true}).click();
  for(let step=0;step<20&&Number((await page.locator('.zoom-level').textContent()).replace('%',''))<70;step++)await page.getByRole('button',{name:'放大',exact:true}).click();
  await page.screenshot({path:path.join(out,'readable-zoom.png'),fullPage:true});
  const burst=await burstDrag(refreshedAssets[0].url);
  assert.ok(Math.abs(burst.actual.x-burst.expected.x)<0.1,'mouseup must retain the last queued horizontal movement');
  assert.ok(Math.abs(burst.actual.y-burst.expected.y)<0.1,'mouseup must retain the last queued vertical movement');
  const pathOnly=[{id:401,projectId:1,targetId:401,url:'https://a.fixture.test/path'}, {id:402,projectId:1,targetId:402,url:'https://b.fixture.test/path'}];
  await page.evaluate(value=>window.__setFixtures(value),{assets:pathOnly,findings:[]});
  await twoFrames();
  const firstSynthetic=await action('keyboard',await nodeIndex('https://a.fixture.test'));
  assert.equal(firstSynthetic.host,'a.fixture.test');assert.equal(firstSynthetic.drawerVisible,true);
  await page.evaluate(value=>window.__setFixtures(value),{assets:[pathOnly[1]]});
  await page.locator('.asset-detail-drawer').waitFor({state:'hidden'});
  assert.equal(await page.locator('.node-card-group.is-selected').count(),0,'reused synthetic id must not select another host');
  const remainingSynthetic=await action('keyboard',await nodeIndex('https://b.fixture.test'));
  assert.equal(remainingSynthetic.host,'b.fixture.test');assert.equal(remainingSynthetic.drawerVisible,true);
  await closeDrawer();
  results.push({scenario:'project isolation, content deduplication, synthetic host details/id reuse, refreshed props, mouseup flush',status:'PASS'});
  await page.close();page=null;
}
async function drag(index = 0) {
  return page.evaluate(async index => {
    const node = document.querySelectorAll('.node-card-group')[index];
    const before = node.getAttribute('transform');
    const rect = node.getBoundingClientRect();
    const x = rect.x + rect.width / 2, y = rect.y + rect.height / 2;
    node.dispatchEvent(new MouseEvent('mousedown', { bubbles:true, button:0, clientX:x, clientY:y }));
    await window.__nextTick();
    const frameMs = [];
    for (let step=1;step<=5;step++) {
      const start = performance.now();
      document.dispatchEvent(new MouseEvent('mousemove',{bubbles:true,buttons:1,clientX:x+step*6,clientY:y+step*3}));
      await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
      frameMs.push(performance.now()-start);
    }
    document.dispatchEvent(new MouseEvent('mouseup',{bubbles:true,button:0,clientX:x+30,clientY:y+15}));
    await window.__nextTick();
    await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
    const after = node.getAttribute('transform');
    node.dispatchEvent(new MouseEvent('click',{bubbles:true}));
    await window.__nextTick();
    const drawer = document.querySelector('.asset-detail-drawer');
    return {before,after,frameMs,custom:node.classList.contains('is-custom-dragged'),drawerVisible:!!drawer&&drawer.getClientRects().length>0&&getComputedStyle(drawer).visibility!=='hidden'};
  }, index);
}
(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({configFile:false,root,cacheDir:path.join(out,'cache'),plugins:[
    {name:'freeze-topology-source',enforce:'pre',load(id){if(id.replaceAll('\\','/')===path.join(root,'src/components/AssetTopology.vue').replaceAll('\\','/'))return componentSource;}},
    vue(),{name:'topology-performance-fixture',configureServer(s){s.middlewares.use(async(req,res,next)=>{
      if(!req.url.startsWith('/__topology-performance'))return next();
      res.setHeader('Content-Type','text/html; charset=utf-8');res.end(await s.transformIndexHtml(req.url,html));
    });}}],server:{host:'127.0.0.1',port:0,hmr:false,watch:{ignored:['**/desktop-release/**','**/dist/**']}},logLevel:'error'});
  await server.listen();
  const origin='http://127.0.0.1:'+server.httpServer.address().port;
  browser=await chromium.launch({executablePath:process.env.EDGE_PATH||'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
  for(const count of sizes){
    await openFixture(origin,'count='+count);
    assert.equal(await page.locator('.node-card-group').count(),count);
    const mountMs=await page.evaluate(()=>performance.getEntriesByName('fixture-mount')[0].duration);
    const hover=await action('hover');assert.equal(hover.hovered,true);
    const leave=await action('leave');assert.equal(leave.hovered,false);
    const clicks=[];
    for(const index of [0,Math.floor(count/2),count-1]){
      const click=await action('click',index);assert.equal(click.selected,true);assert.equal(click.drawerVisible,true);
      assert.equal(click.host,new URL(click.url).host);assert.equal(click.findings,3);
      clicks.push(click);await closeDrawer();
    }
    const dragging=await drag();assert.notEqual(dragging.before,dragging.after);assert.equal(dragging.custom,true);assert.equal(dragging.drawerVisible,false);
    const result={count,findings:count*3,mountMs,hover,leave,clicks,dragging};results.push(result);
    console.log(JSON.stringify(result));
    // Broad ceilings detect visible stalls without asserting frame-perfect timing on shared machines.
    withinBudget(hover.updateMs,100,'hover update');
    clicks.forEach(click=>withinBudget(click.updateMs,500,'node click update'));
    dragging.frameMs.forEach(duration=>withinBudget(duration,800,'drag frame'));
    await page.screenshot({path:path.join(out,'topology-'+count+'.png'),fullPage:true});
    await page.close();page=null;
  }
  if(!baseline){
    await openFixture(origin,'count=60&shared=1');
    const dense=await action('click',await nodeIndex('https://shared.fixture.test/'));
    assert.equal(dense.drawerVisible,true);assert.equal(dense.findings,20,'dense details initially render one page');
    results.push({scenario:'60 assets sharing a target with 180 findings',...dense});
    console.log('DENSE '+JSON.stringify(dense));
    withinBudget(dense.frameMs,1500,'dense drawer first frames');
    await drawerScreenshot('dense-findings.png');
    const evidence=await page.locator('.finding-evidence-textarea').first().evaluate(el=>({
      value:el.value,readOnly:el.readOnly,height:el.getBoundingClientRect().height,
      scrollHeight:el.scrollHeight,clientHeight:el.clientHeight,overflow:getComputedStyle(el).overflowY,
    }));
    assert.equal(evidence.value,'https://shared.fixture.test/\n'+'Long fixture evidence line\n'.repeat(30));
    assert.equal(evidence.readOnly,true);assert.ok(evidence.height<=144.5);
    assert.ok(evidence.scrollHeight>evidence.clientHeight);assert.equal(evidence.overflow,'auto');
    results.push({scenario:'readonly evidence preserves all text and scrolls within eight lines',status:'PASS',evidence});
    const pagination=page.locator('.findings-pagination');
    assert.equal(await pagination.locator('.el-pagination__total').count(),1,'shared pagination shows the total');
    assert.equal(await pagination.locator('.el-pagination__sizes').count(),1,'shared pagination provides page sizes');
    assert.equal(await pagination.locator('.el-pagination--small').count(),0,'shared pagination retains the standard size');
    const placement=await page.evaluate(()=>{
      const footer=document.querySelector('.findings-pagination').getBoundingClientRect();
      const cards=document.querySelectorAll('.topology-finding-card');
      return {footerTop:footer.top,lastCardBottom:cards[cards.length-1].getBoundingClientRect().bottom};
    });
    assert.ok(placement.footerTop>=placement.lastCardBottom,'pagination is placed after the findings list');
    const firstPageTitles=await page.locator('.finding-card-title').allTextContents();
    const visitedTitles=new Set(firstPageTitles);
    assert.equal(await pagination.locator('.btn-prev').isDisabled(),true);
    for(let current=2;current<=9;current++){
      await pagination.locator('.btn-next').click();
      assert.equal(await page.locator('.topology-finding-card').count(),20,'pagination keeps the DOM bounded to one page');
      assert.equal((await pagination.locator('.el-pager .is-active').textContent()).trim(),String(current));
      for(const title of await page.locator('.finding-card-title').allTextContents()){
        assert.equal(visitedTitles.has(title),false,'each finding belongs to exactly one page');
        visitedTitles.add(title);
      }
    }
    assert.equal(visitedTitles.size,180,'all findings remain accessible');
    assert.equal(await pagination.locator('.btn-next').isDisabled(),true);
    await pagination.locator('.btn-prev').click();
    assert.equal((await pagination.locator('.el-pager .is-active').textContent()).trim(),'8');
    await pagination.locator('.el-pager li').first().click();
    assert.deepEqual(await page.locator('.finding-card-title').allTextContents(),firstPageTitles,'returning to page one restores the original findings');
    for(const size of [50,100,20]){
      await pagination.locator('.btn-next').click();
      await pagination.locator('.el-select').click();
      await page.getByRole('option').filter({hasText:new RegExp('^'+size+'\\s*/')}).click();
      await page.getByRole('option').filter({hasText:new RegExp('^'+size+'\\s*/')}).waitFor({state:'hidden'});
      assert.equal(await page.locator('.topology-finding-card').count(),size,'shared page-size selector controls visible findings');
      assert.equal((await pagination.locator('.el-pager .is-active').textContent()).trim(),'1','changing page size resets to page one');
    }
    await pagination.scrollIntoViewIfNeeded();
    await page.screenshot({path:path.join(out,'dense-pagination-footer.png'),fullPage:true});
    await page.setViewportSize({width:375,height:900});
    // This isolated fixture has no desktop sidebar. Global app CSS still reserves
    // its 260px rail, so remove that offset only for narrow drawer content QA.
    const narrowFixtureStyle=await page.addStyleTag({content:'.asset-detail-overlay { left: 0 !important; right: 0 !important; }'});
    await twoFrames();
    await pagination.scrollIntoViewIfNeeded();
    const narrow=await page.evaluate(()=>{
      const body=document.querySelector('.asset-detail-drawer .el-drawer__body');
      const pagination=document.querySelector('.findings-pagination');
      const bounds=body.getBoundingClientRect();
      const footer=pagination.getBoundingClientRect();
      return {bodyWidth:body.clientWidth,bodyScrollWidth:body.scrollWidth,footerWidth:pagination.clientWidth,footerScrollWidth:pagination.scrollWidth,left:footer.left,right:footer.right,bodyLeft:bounds.left,bodyRight:bounds.right};
    });
    assert.ok(narrow.bodyScrollWidth<=narrow.bodyWidth+1,'narrow drawer has no horizontal overflow');
    assert.ok(narrow.footerScrollWidth<=narrow.footerWidth+1,'shared pagination wraps within the narrow drawer');
    assert.ok(narrow.left>=narrow.bodyLeft-1&&narrow.right<=narrow.bodyRight+1,'pagination remains inside the drawer');
    await page.screenshot({path:path.join(out,'dense-pagination-narrow.png'),fullPage:false});
    await narrowFixtureStyle.evaluate(element=>element.remove());
    await page.setViewportSize({width:1440,height:1000});
    await twoFrames();
    await pagination.locator('.btn-next').click();
    await page.keyboard.press('Escape');
    await page.locator('.asset-detail-drawer').waitFor({state:'hidden'});
    await action('click',await nodeIndex('https://shared.fixture.test/'));
    assert.equal(await page.locator('.topology-finding-card').count(),20,'reopening the same asset resets the findings page');
    assert.deepEqual(await page.locator('.finding-card-title').allTextContents(),firstPageTitles);
    await pagination.locator('.btn-next').click();
    await closeDrawer();
    await action('click',await nodeIndex('https://shared.fixture.test/path-1'));
    assert.equal(await page.locator('.topology-finding-card').count(),20,'changing asset resets the findings page');
    assert.deepEqual(await page.locator('.finding-card-title').allTextContents(),firstPageTitles);
    await pagination.locator('.el-pager li').last().click();
    await page.evaluate(()=>window.__setFixtures({findings:window.__fixtureFindings.slice(0,25)}));
    await twoFrames();
    assert.equal((await pagination.locator('.el-pager .is-active').textContent()).trim(),'2','shrinking findings clamps the current page');
    assert.equal(await page.locator('.topology-finding-card').count(),5,'last page contains only remaining findings');
    await page.evaluate(()=>window.__setFixtures({findings:window.__fixtureFindings.slice(0,3)}));
    await twoFrames();
    assert.equal(await page.locator('.topology-finding-card').count(),3,'shrinking to a single page preserves its findings');
    assert.equal(await pagination.isVisible(),true,'shared pagination remains visible for a nonempty single page');
    assert.equal(await pagination.locator('.btn-prev').isDisabled(),true);
    assert.equal(await pagination.locator('.btn-next').isDisabled(),true);
    results.push({scenario:'shared findings pagination preserves all rows, supports page sizes, resets and clamps pages, and fits narrow drawers',status:'PASS',narrow});
    await page.close();page=null;
    await mouseClickRegression(origin);
    await semanticRegressions(origin);
  }
  assert.deepEqual(errors,[]);assert.deepEqual(unexpected,[]);
  console.log('PASS topology performance/function regression'+(baseline?' (baseline)':''));
  console.log('EVIDENCE '+out);
})().catch(async error=>{results.push({status:'FAIL',error:error.stack});if(page)await page.screenshot({path:path.join(out,'failure.png')}).catch(()=>{});console.error(error);process.exitCode=1;}).finally(async()=>{
  fs.writeFileSync(path.join(out,'results.json'),JSON.stringify({scope:'actual AssetTopology + Element Plus, fixed props, blocked APIs, synthetic DOM events timed inside browser',baseline,sourcePath,sourceSha256,results,errors,unexpected},null,2));
  await browser?.close();await server?.close();
});
