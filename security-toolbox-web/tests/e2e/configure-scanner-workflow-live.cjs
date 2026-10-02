/** Authorized additive configuration only. Never executes a workflow or scanner.
 * Uses visible DOM controls and mouse connections. Business responses are only
 * observed after UI actions; no API calls, storage reads, or Vue state access.
 * Retains the new acceptance revision; never deletes records or rolls back.
 */
const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const {chromium}=require('playwright-core');
const {navigate,selectOn,formItem,sleep}=require('./lib/ui.cjs');
const OUT=path.resolve(__dirname,'../../../.run/workflow-scanner-configuration',new Date().toISOString().replace(/[:.]/g,'-'));
const PROJECT_ID='131';
const PROJECT_NAME='四目标实战全景测试项目-049988';
const TOOLS=process.argv.includes('--two-tools')?['fscan_scan','zap_scan']:['fscan_scan','zap_scan','msf_scan'];
fs.mkdirSync(OUT,{recursive:true});
const result={status:'RUNNING',projectId:PROJECT_ID,tools:TOOLS,retainsNewRevision:true,executed:false,steps:[]};
const write=(name,value)=>fs.writeFileSync(path.join(OUT,name),JSON.stringify(value,null,2));
const note=text=>{result.steps.push(text);write('results.json',result);console.log(text);};
function matches(response,method){const url=new URL(response.url());return url.pathname.endsWith('/ai/workflow')&&url.searchParams.get('projectId')===PROJECT_ID&&response.request().method()===method;}
function specFrom(raw){const spec=raw?.data?.graph?raw.data:raw;assert.ok(spec?.graph?.nodes&&spec?.graph?.edges&&Array.isArray(spec.steps),'Expected complete workflow response');return spec;}
function canonical(value){if(Array.isArray(value))return value.map(canonical);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));return value;}
function same(actual,expected,message){assert.deepEqual(canonical(actual),canonical(expected),message);}
let page;
(async()=>{
  const browser=await chromium.connectOverCDP('http://127.0.0.1:19229');
  page=browser.contexts().flatMap(c=>c.pages()).find(p=>p.url().includes('app.asar')&&!/startup.html|capture-browser.html/.test(p.url()));
  assert.ok(page,'Packaged application page absent');page.setDefaultTimeout(15000);
  assert.ok(await page.locator('#desktop-v2-primary-navigation').isVisible(),'User login is required; this script never logs in');
  await navigate(page,'红队工作流');
  await page.locator('.editor-head-actions').getByRole('button',{name:'工作流配置',exact:true}).click();
  const config=page.locator('#workflow-config-panel');
  await selectOn(page,config.locator('.project-select'),PROJECT_NAME,{exact:true});
  await page.getByRole('button',{name:'关闭工作流配置',exact:true}).click();
  // Reload is a visible application action and guarantees a complete baseline response.
  const beforeResponsePromise=page.waitForResponse(r=>matches(r,'GET'));
  await page.locator('.editor-head-actions').getByRole('button',{name:'重新加载',exact:true}).click();
  const beforeResponse=await beforeResponsePromise;
  assert.ok(beforeResponse.ok(),'Workflow load failed');
  const beforeRaw=JSON.parse((await beforeResponse.body()).toString('utf8'));
  write('original-response.json',beforeRaw);
  const before=specFrom(beforeRaw);
  assert.equal(before.steps.length,8,'Expected original eight tools; stop rather than duplicate a previous acceptance revision');
  assert.ok(before.graph.nodes.some(n=>n.id==='context'&&n.tool==='retrieve_project_context'),'Original context node absent');
  assert.ok(before.graph.nodes.some(n=>n.id==='__start__')&&before.graph.nodes.some(n=>n.id==='__end__'),'Fixed endpoints absent');
  assert.ok(!before.graph.nodes.some(n=>n.type==='phase'),'This script targets the known zero-stage legacy graph only');
  assert.ok(!before.steps.some(s=>TOOLS.includes(s.tool)),'One of the added tools already exists');
  await sleep(400);
  const scopeBefore=(await page.locator('[aria-label="当前工作流配置"]').innerText()).trim();
  result.originalRevision=before.revision;result.originalDigest=before.specDigest;
  note('Complete original workflow response saved; eight original tools and zero phases confirmed.');
  const nodeIds=()=>page.locator('.vue-flow__node').evaluateAll(elements=>elements.map(e=>e.getAttribute('data-id')));
  const node=id=>page.locator(`.vue-flow__node[data-id=${JSON.stringify(id)}]`);
  const libraryTab=()=>page.locator('.workflow-library-tabs').getByText('阶段与能力库',{exact:true}).click();
  async function openLibrary(){
    await libraryTab();
    const toggle=page.locator('button[aria-controls="workflow-capability-library-body"]');
    if(await toggle.getAttribute('aria-expanded')==='false')await toggle.click();
    await selectOn(page,page.locator('.capability-library-head .el-select'),'漏洞发现',{exact:true});
  }
  const added={};
  for(const tool of TOOLS){
    await openLibrary();
    const oldIds=new Set(await nodeIds());
    const item=page.locator(`.library-item[data-tool=${JSON.stringify(tool)}]`);
    await item.getByRole('button',{name:'加入选定阶段',exact:true}).click();
    await sleep(200);
    const fresh=(await nodeIds()).filter(id=>!oldIds.has(id));
    assert.equal(fresh.length,1,'Adding a tool must produce exactly one visible graph node');
    added[tool]=fresh[0];
    assert.match(await node(fresh[0]).innerText(),/需确认/,'CAUTION approval must remain enabled');
    if(tool==='fscan_scan'){
      await page.locator('.workflow-library-tabs').getByText('节点配置',{exact:true}).click();
      const editor=page.locator('[aria-label="已选节点参数"]');
      await selectOn(page,formItem(editor,page,'扫描端口').locator('.el-select'),'HTTP · 80',{exact:true});
      await page.keyboard.press('Escape');
      await editor.getByText('安全（默认）',{exact:true}).click();
      assert.match(await formItem(editor,page,'扫描端口').innerText(),/HTTP · 80/);
    }
    note('Added '+tool+' through its visible library control; no execution requested.');
  }
  // Add tools BEFORE the phase: otherwise the editor auto-wires to an absent next phase.
  await libraryTab();
  const phaseToggle=page.locator('button[aria-controls="workflow-phase-library-body"]');
  if(await phaseToggle.count()&&await phaseToggle.getAttribute('aria-expanded')==='false')await phaseToggle.click();
  const idsBeforePhase=new Set(await nodeIds());
  await page.getByRole('button',{name:'加回漏洞发现阶段',exact:true}).click();
  const phaseIds=(await nodeIds()).filter(id=>!idsBeforePhase.has(id));
  assert.equal(phaseIds.length,1);const phaseId=phaseIds[0];
  const newEdges=[['context',phaseId],[phaseId,'__end__'],...TOOLS.flatMap(t=>[[phaseId,added[t]],[added[t],'__end__']])];
  for(const [source,target] of newEdges){
    await page.getByRole('button',{name:'适应画布',exact:true}).click();await sleep(300);
    const a=await node(source).locator('.node-handle--source').boundingBox();
    const b=await node(target).locator('.node-handle--target').boundingBox();
    assert.ok(a&&b,'Both visible connection handles must exist');
    const count=await page.locator('.vue-flow__edge').count();
    await page.mouse.move(a.x+a.width/2,a.y+a.height/2);await page.mouse.down();
    await page.mouse.move(b.x+b.width/2,b.y+b.height/2,{steps:18});await page.mouse.up();
    await sleep(200);
    assert.equal(await page.locator('.vue-flow__edge').count(),count+1,'Mouse connection failed: '+source+' → '+target);
    note('Connected '+source+' → '+target);
  }
  assert.equal(await page.locator('.graph-validation:visible').count(),0,'Graph still fails validation; do not save');
  assert.equal((await page.locator('[aria-label="当前工作流配置"]').innerText()).trim(),scopeBefore,'Project, target or template changed');
  await page.screenshot({path:path.join(OUT,'prepared.png'),fullPage:true});
  const savedResponsePromise=page.waitForResponse(r=>matches(r,'PUT'),{timeout:30000});
  await page.getByRole('button',{name:'保存工作流',exact:true}).click();
  const savedResponse=await savedResponsePromise;
  const submitted=JSON.parse(savedResponse.request().postData());write('submitted-spec.json',submitted);
  const afterRaw=JSON.parse((await savedResponse.body()).toString('utf8'));write('saved-response.json',afterRaw);
  assert.ok(savedResponse.ok(),'Save rejected; original response retained');
  const after=specFrom(afterRaw);
  for(const old of before.steps){
    for(const candidate of [submitted,after]){
      const saved=candidate.steps.find(s=>s.nodeId===old.nodeId);assert.ok(saved,'Original tool removed: '+old.nodeId);
      for(const key of ['tool','parameters','risk','requiresApproval'])same(saved[key],old[key],'Original '+old.nodeId+' '+key+' changed');
    }
  }
  for(const old of before.graph.nodes){
    const saved=after.graph.nodes.find(n=>n.id===old.id);assert.ok(saved,'Original graph node removed');
    for(const key of ['type','tool','phase','label']) {
      const migratedEndpoint=key==='type'&&['__start__','__end__'].includes(old.id)
        &&['start','end'].includes(old.type)&&saved.type==='system';
      if(!migratedEndpoint)same(saved[key],old[key],'Original graph node metadata changed: '+old.id+' '+key);
    }
  }
  for(const old of before.graph.edges)assert.ok(after.graph.edges.some(e=>e.source===old.source&&e.target===old.target),'Original dependency removed');
  assert.equal(after.steps.length,before.steps.length+TOOLS.length);
  assert.equal(after.graph.nodes.length,before.graph.nodes.length+TOOLS.length+1);
  assert.equal(after.graph.edges.length,before.graph.edges.length+newEdges.length);
  for(const tool of TOOLS){
    const step=after.steps.find(s=>s.nodeId===added[tool]);assert.ok(step);
    assert.equal(step.tool,tool);assert.equal(step.risk,'CAUTION');assert.equal(step.requiresApproval,true);
    same(step.parameters,tool==='fscan_scan'?{ports:'80',vulnMode:'SAFE'}:{},'Unexpected scanner parameters');
  }
  assert.ok(after.revision>before.revision,'Expected a new retained workflow revision');
  await page.screenshot({path:path.join(OUT,'saved.png'),fullPage:true});
  Object.assign(result,{status:'PASS',savedRevision:after.revision,savedDigest:after.specDigest,addedNodeIds:added,phaseId});
  note('Saved and retained the additive acceptance revision. No workflow or scanner was executed.');
  console.log('COMPLETE '+OUT);process.exit(0);
})().catch(async error=>{
  Object.assign(result,{status:'FAIL',error:error.message,stack:error.stack});write('results.json',result);
  if(page)await page.screenshot({path:path.join(OUT,'failure.png'),fullPage:true}).catch(()=>{});
  console.error(error);console.error('EVIDENCE '+OUT);process.exit(1);
});
