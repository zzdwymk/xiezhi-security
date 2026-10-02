/** Prepare/run visible UI dependency edits only. No workflow or scanner execution.
 * Usage: node tests/e2e/configure-independent-scanners-live.cjs --configure-confirmed
 * Without the flag, this script does not connect to the application.
 */
const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const {chromium}=require('playwright-core');
const {navigate,selectOn,sleep}=require('./lib/ui.cjs');
if(!process.argv.includes('--configure-confirmed')){console.log('Prepared only; no UI connection or changes.');process.exit(0);}
assert.ok(process.argv.slice(2).every(arg=>arg==='--configure-confirmed'),'Unknown argument');
const OUT=path.resolve(__dirname,'../../../.run/workflow-independent-scanners',new Date().toISOString().replace(/[:.]/g,'-'));
fs.mkdirSync(OUT,{recursive:true});
const PROJECT_ID='131',PROJECT_NAME='四目标实战全景测试项目-049988';
const TOOLS=['fscan_scan','zap_scan','msf_scan'];
const result={status:'RUNNING',executed:false,projectId:PROJECT_ID,steps:[]};
const write=(name,value)=>fs.writeFileSync(path.join(OUT,name),JSON.stringify(value,null,2));
const note=message=>{result.steps.push(message);write('results.json',result);console.log(message);};
function matches(response,method){const url=new URL(response.url());return url.pathname.endsWith('/ai/workflow')&&url.searchParams.get('projectId')===PROJECT_ID&&response.request().method()===method;}
function spec(raw){const value=raw?.data?.graph?raw.data:raw;assert.ok(value?.graph?.nodes&&value.graph.edges&&value.steps,'Complete workflow required');return value;}
function canonical(value){if(Array.isArray(value))return value.map(canonical);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));return value;}
function same(actual,expected,message){assert.deepEqual(canonical(actual),canonical(expected),message);}
function verify(before,after,changes,editableRequest=false){
  same(after.graph.nodes,before.graph.nodes,'No node metadata or layout may change');
  assert.equal(after.steps.length,before.steps.length,'Tool count changed');
  const context=before.steps.find(step=>step.nodeId==='context');
  for(const original of before.steps){
    const saved=after.steps.find(step=>step.nodeId===original.nodeId);assert.ok(saved,'Tool removed');
    if(!changes.some(change=>change.nodeId===original.nodeId)){
      same({...saved,dependsOnNodeIds:editableRequest?null:saved.dependsOnNodeIds||[]},{...original,dependsOnNodeIds:editableRequest?null:original.dependsOnNodeIds||[]},'Existing tool changed: '+original.nodeId);continue;
    }
    same({...saved,dependsOnNodeIds:null,group:null},{...original,dependsOnNodeIds:null,group:null},'Scanner settings or approval changed');
    if(!editableRequest)same(saved.dependsOnNodeIds,['context'],'Scanner must depend only on context');
    assert.equal(saved.group,context.group+1,'Derived dependency group must immediately follow context');
  }
  const removedIds=new Set(changes.map(change=>change.oldEdge.id));
  for(const edge of before.graph.edges.filter(edge=>!removedIds.has(edge.id)))
    same(after.graph.edges.find(item=>item.id===edge.id),edge,'Existing edge changed: '+edge.id);
  assert.equal(after.graph.edges.length,before.graph.edges.length,'Edge count changed');
  for(const change of changes){
    assert.ok(!after.graph.edges.some(edge=>edge.id===change.oldEdge.id),'Old dependency edge retained');
    const incoming=after.graph.edges.filter(edge=>edge.target===change.nodeId);
    assert.equal(incoming.length,1,'Unexpected additional prerequisite');
    assert.equal(incoming[0].source,'context','Connection originated at an overlapping node');
    assert.equal(incoming[0].id,change.newEdgeId,'Unexpected new edge');
  }
  for(const key of Object.keys(before)){
    if(['graph','steps','revision','specDigest','updatedAt','createdAt'].includes(key))continue;
    same(after[key],before[key],'Workflow scope or metadata changed: '+key);
  }
}
let page;
(async()=>{
  const browser=await chromium.connectOverCDP('http://127.0.0.1:19229');
  page=browser.contexts().flatMap(context=>context.pages()).find(item=>item.url().includes('app.asar')&&!/startup.html|capture-browser.html/.test(item.url()));
  assert.ok(page,'Packaged application absent');page.setDefaultTimeout(15000);
  assert.ok(await page.locator('#desktop-v2-primary-navigation').isVisible(),'Manual login required; this script never logs in');
  await navigate(page,'红队工作流');
  await page.locator('.editor-head-actions').getByRole('button',{name:'工作流配置',exact:true}).click();
  await selectOn(page,page.locator('#workflow-config-panel .project-select'),PROJECT_NAME,{exact:true});
  await page.getByRole('button',{name:'关闭工作流配置',exact:true}).click();
  async function reload(filename){
    const pending=page.waitForResponse(response=>matches(response,'GET'));
    await page.locator('.editor-head-actions').getByRole('button',{name:'重新加载',exact:true}).click();
    const response=await pending;assert.ok(response.ok(),'Workflow load failed');
    const raw=await response.json();write(filename,raw);await sleep(400);return spec(raw);
  }
  const before=await reload('original-response.json');
  assert.ok(before.revision>=2,'Expected revision2 or its reviewed PoC successor');
  assert.equal(before.steps.length,11,'Expected exactly the existing eleven tools');
  assert.ok(before.steps.some(step=>step.nodeId==='context'&&step.tool==='retrieve_project_context'),'Context node absent');
  const changes=TOOLS.map(tool=>{
    const steps=before.steps.filter(step=>step.tool===tool);assert.equal(steps.length,1,'Scanner missing or ambiguous');
    const step=steps[0];same(step.dependsOnNodeIds,['xray'],'Expected original Xray dependency; do not repeat edits');
    assert.equal(step.requiresApproval,true);assert.equal(step.risk,'CAUTION');
    const incoming=before.graph.edges.filter(edge=>edge.target===step.nodeId);assert.equal(incoming.length,1);
    assert.equal(incoming[0].source,'discovery','Unexpected prerequisite graph shape');
    return {tool,nodeId:step.nodeId,oldEdge:incoming[0]};
  });
  result.originalRevision=before.revision;result.changes=changes;
  const scope=(await page.locator('[aria-label="当前工作流配置"]').innerText()).trim();
  const node=id=>page.locator(`.vue-flow__node[data-id=${JSON.stringify(id)}]`);
  const edge=id=>page.locator(`.vue-flow__edge[data-id=${JSON.stringify(id)}]`);
  const edgeIds=async()=>{const ids=[];const edges=page.locator('.vue-flow__edge');for(let index=0;index<await edges.count();index++)ids.push(await edges.nth(index).getAttribute('data-id'));return ids;};
  for(const change of changes){
    await page.getByRole('button',{name:'适应画布',exact:true}).click();await sleep(400);
    const count=await page.locator('.vue-flow__node').count();
    // Normal pointer selection updates the app's selectedEdgeId. Merely focusing
    // an SVG edge would not clear a selected node and could make Delete remove it.
    const point=await edge(change.oldEdge.id).locator('.vue-flow__edge-interaction').evaluate(path=>{
      const matrix=path.getScreenCTM(),length=path.getTotalLength();
      if(!matrix)return null;
      for(const fraction of [.4,.3,.6,.2,.7,.8]){
        const local=path.getPointAtLength(length*fraction),screen=new DOMPoint(local.x,local.y).matrixTransform(matrix);
        if(document.elementFromPoint(screen.x,screen.y)?.closest('.vue-flow__edge')===path.closest('.vue-flow__edge'))
          return {x:screen.x,y:screen.y};
      }
      return null;
    });
    assert.ok(point,'No exposed stroke of the intended edge; stop without deletion');
    await page.mouse.click(point.x,point.y);
    await sleep(150);
    assert.ok(await page.getByText('已选连线：按 Delete 或点击连线上的 ✕ 删除',{exact:true}).isVisible(),'Edge selection not confirmed; do not press Delete');
    assert.equal(await page.locator('.vue-flow__node.selected').count(),0,'A node remains selected; do not press Delete');
    const remove=page.locator('.wf-edge-badge:visible').getByRole('button',{name:'删除连线',exact:true});
    assert.equal(await remove.count(),1,'Expected only the selected edge delete affordance');
    await remove.click();await sleep(250);
    assert.equal(await edge(change.oldEdge.id).count(),0,'Specified old edge was not removed');
    assert.equal(await page.locator('.vue-flow__node').count(),count,'A node was removed; stop without saving');
    const context=node('context');
    await context.focus();await context.press('Enter');await sleep(200);
    const source=context.locator('.node-handle--source'),target=node(change.nodeId).locator('.node-handle--target');
    // Trial performs hit-testing only. An occluded legacy context handle must not
    // silently create another Xray/Afrog edge as happened in the original graph.
    await source.click({trial:true});await target.click({trial:true});
    const a=await source.boundingBox(),b=await target.boundingBox();assert.ok(a&&b,'Connection handles unavailable');
    const previous=new Set(await edgeIds());
    await page.mouse.move(a.x+a.width/2,a.y+a.height/2);await page.mouse.down();
    try{await page.mouse.move(b.x+b.width/2,b.y+b.height/2,{steps:20});}finally{await page.mouse.up();}
    await sleep(250);
    const added=(await edgeIds()).filter(id=>!previous.has(id));assert.equal(added.length,1,'Expected one new dependency connection');
    change.newEdgeId=added[0];
    assert.ok(change.newEdgeId.startsWith('edge-context-'+change.nodeId),'Connection came from the wrong overlapping node');
    note('Replaced discovery → '+change.nodeId+' with context → '+change.nodeId+' through visible controls.');
  }
  assert.equal((await page.locator('[aria-label="当前工作流配置"]').innerText()).trim(),scope,'Scope changed');
  assert.equal(await page.locator('.graph-validation:visible').count(),0,'Workflow validation failed; do not save');
  await page.screenshot({path:path.join(OUT,'prepared.png'),fullPage:true});
  const pending=page.waitForResponse(response=>matches(response,'PUT'),{timeout:30000});
  await page.getByRole('button',{name:'保存工作流',exact:true}).click();
  const response=await pending,submitted=response.request().postDataJSON();write('submitted-request.json',submitted);
  const raw=await response.json();write('saved-response.json',raw);assert.ok(response.ok(),'Workflow save failed');
  // PUT contains editable settings/graph only; dependency arrays and identity
  // fields are derived by the server and checked in both saved and reloaded GETs.
  verify({version:before.version,preset:before.preset,steps:before.steps,graph:before.graph},spec(submitted),changes,true);
  verify(before,spec(raw),changes);
  const after=await reload('verified-response.json');verify(before,after,changes);
  assert.ok(after.revision>before.revision,'New revision missing');
  Object.assign(result,{status:'PASS',savedRevision:after.revision,savedDigest:after.specDigest});
  note('Only the three scanner prerequisites and their derived groups changed. All approval, parameters, old tools and node layouts retained.');
  console.log('COMPLETE '+OUT);process.exit(0);
})().catch(async error=>{
  Object.assign(result,{status:'FAIL',error:error.message});write('results.json',result);
  if(page)await page.screenshot({path:path.join(OUT,'stopped.png'),fullPage:true}).catch(()=>{});
  console.error(error.message);console.error('EVIDENCE '+OUT);process.exit(1);
});
