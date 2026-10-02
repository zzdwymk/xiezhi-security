/** Visible UI configuration only. Run after the parent finishes packaging and
 * additive scanner-node configuration. Never executes scans, downloads libraries,
 * calls business APIs, reads storage, or alters authorization/approval settings.
 * Usage: node tests/e2e/configure-scanner-pocs-live.cjs --configure-confirmed
 */
const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const {chromium}=require('playwright-core');
const {navigate,selectOn,sleep}=require('./lib/ui.cjs');
if(!process.argv.includes('--configure-confirmed')){
  console.log('Prepared only. Parent must complete packaging and node configuration before --configure-confirmed.');
  process.exit(0);
}
const OUT=path.resolve(__dirname,'../../../.run/workflow-poc-configuration',new Date().toISOString().replace(/[:.]/g,'-'));
fs.mkdirSync(OUT,{recursive:true});
const PROJECT_ID='131', PROJECT_NAME='四目标实战全景测试项目-049988';
const candidates=[
  {tool:'xray_scan',source:'XRAY',query:'docker-registry-api-unauth',code:'XP-577D08DBE1BF06E5442CA3DF',file:'docker-registry-api-unauth.yml'},
  {tool:'afrog_scan',source:'AFROG',query:'1panel-detect',file:'fingerprinting/1panel-detect.yaml',externalId:'1panel-detect'},
];
const result={status:'RUNNING',executed:false,projectId:PROJECT_ID,steps:[],selected:[]};
const write=(name,value)=>fs.writeFileSync(path.join(OUT,name),JSON.stringify(value,null,2));
const note=text=>{result.steps.push(text);write('results.json',result);console.log(text);};
function blocked(message){const error=new Error(message);error.blocked=true;throw error;}
function workflowResponse(r,method){const u=new URL(r.url());return u.pathname.endsWith('/ai/workflow')&&u.searchParams.get('projectId')===PROJECT_ID&&r.request().method()===method;}
function spec(raw){const value=raw?.data?.graph?raw.data:raw;assert.ok(value?.graph?.nodes&&value.graph.edges&&value.steps,'Complete workflow response required');return value;}
function canonical(v){if(Array.isArray(v))return v.map(canonical);if(v&&typeof v==='object')return Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])]));return v;}
function same(a,b,message){assert.deepEqual(canonical(a),canonical(b),message);}
function withoutPocs(parameters){const copy={...parameters};delete copy.allPocs;delete copy.pocCodes;return copy;}
function verifyPreserved(before,after,selected){
  assert.equal(after.steps.length,before.steps.length,'Tool count changed');
  assert.equal(after.graph.nodes.length,before.graph.nodes.length,'Node count changed');
  same(after.graph.edges,before.graph.edges,'Edges changed');
  for(const old of before.steps){
    const next=after.steps.find(s=>s.nodeId===old.nodeId);assert.ok(next,'Step removed');
    const choice=selected.find(c=>c.nodeId===old.nodeId);
    if(!choice){same(next,old,'Unrelated step changed: '+old.nodeId);continue;}
    same({...next,parameters:null},{...old,parameters:null},'Approval/dependencies/metadata changed');
    same(withoutPocs(next.parameters),withoutPocs(old.parameters),'Other scanner parameters changed');
    same(next.parameters.pocCodes,[choice.code],'Expected exactly reviewed PoC');
    assert.notEqual(next.parameters.allPocs,true,'allPocs must be disabled');
    assert.equal(next.risk,'CAUTION');assert.equal(next.requiresApproval,true);
  }
  for(const old of before.graph.nodes){
    const next=after.graph.nodes.find(n=>n.id===old.id);assert.ok(next,'Node removed');
    const choice=selected.find(c=>c.nodeId===old.id);
    if(!choice){same(next,old,'Unrelated graph node changed: '+old.id);continue;}
    if(choice.tool==='xray_scan'&&choice.layoutMoved){
      same({...next,parameters:null,position:null},{...old,parameters:null,position:null},'Selected Xray metadata changed');
      assert.ok(Number.isFinite(next.position?.x)&&Number.isFinite(next.position?.y),'Xray layout must retain finite coordinates');
      assert.notDeepEqual(next.position,old.position,'Reviewed Xray move was not persisted');
    }else same({...next,parameters:null},{...old,parameters:null},'Selected node metadata changed');
    same(withoutPocs(next.parameters),withoutPocs(old.parameters),'Other graph parameters changed');
    if(next.parameters !== undefined) {
      same(next.parameters.pocCodes,[choice.code],'Graph PoC selection mismatch');
      assert.notEqual(next.parameters.allPocs,true);
    }
  }
  for(const key of Object.keys(before)){
    if(['graph','steps','revision','specDigest','updatedAt','createdAt'].includes(key))continue;
    same(after[key],before[key],'Workflow scope/metadata changed: '+key);
  }
}
let page;
function boxesOverlap(a,b,padding=0){
  return a.x<aRight(b)+padding&&aRight(a)+padding>b.x&&a.y<b.y+b.height+padding&&a.y+a.height+padding>b.y;
}
function aRight(box){return box.x+box.width;}
async function revealAfrogByMovingXray(xrayNode,choice,before){
  const afrog=before.steps.find(step=>step.tool==='afrog_scan');
  if(!afrog)blocked('Afrog node missing before layout adjustment');
  const afrogNode=page.locator(`.vue-flow__node[data-id=${JSON.stringify(afrog.nodeId)}]`);
  const original=await xrayNode.boundingBox(),covered=await afrogNode.boundingBox();
  if(!original||!covered)blocked('Scanner node bounds unavailable');
  if(!boxesOverlap(original,covered))return;
  const canvas=await page.locator('.flow-canvas').boundingBox();
  if(!canvas)blocked('Visible canvas bounds unavailable');
  const obstacles=[];
  const nodes=page.locator('.flow-canvas .vue-flow__node');
  for(let index=0;index<await nodes.count();index++){
    const other=nodes.nth(index);
    if(await other.getAttribute('data-id')===choice.nodeId)continue;
    const box=await other.boundingBox();if(box)obstacles.push(box);
  }
  // Find empty space in the upper-right visible canvas, leaving edge/control margins.
  let destination;
  for(const yOffset of [60,100,150,200]){
    for(const xOffset of [45,100,160,220]){
      const box={x:canvas.x+canvas.width-original.width-xOffset,y:canvas.y+yOffset,width:original.width,height:original.height};
      if(box.x<canvas.x+70||box.y+box.height>canvas.y+canvas.height-45)continue;
      if(!obstacles.some(other=>boxesOverlap(box,other,20))){destination=box;break;}
    }
    if(destination)break;
  }
  if(!destination)blocked('No clear upper-right canvas position for Xray; no drag performed');
  // A normal click ensures only Xray is selected. Pointer drag follows the same
  // VueFlow path as a person; no force clicks, internal state writes, or injected events.
  await xrayNode.locator('.node-main').click();
  const handle=await xrayNode.locator('.node-main').boundingBox();
  if(!handle)blocked('Xray drag surface unavailable');
  const start={x:handle.x+handle.width/2,y:handle.y+handle.height/2};
  await page.mouse.move(start.x,start.y);
  await page.mouse.down();
  try{await page.mouse.move(start.x+destination.x-original.x,start.y+destination.y-original.y,{steps:24});}
  finally{await page.mouse.up();}
  await sleep(500);
  const moved=await xrayNode.boundingBox(),afrogAfter=await afrogNode.boundingBox();
  if(!moved||!afrogAfter||boxesOverlap(moved,afrogAfter)||Math.hypot(moved.x-original.x,moved.y-original.y)<30)
    blocked('Real pointer drag did not expose Afrog; do not save');
  choice.layoutMoved=true;
  result.xrayLayoutMove={from:original,to:moved};
  await page.screenshot({path:path.join(OUT,'xray-moved-to-reveal-afrog.png'),fullPage:true});
  note('Moved only Xray into clear upper-right canvas space with the mouse, exposing Afrog.');
}
(async()=>{
  const browser=await chromium.connectOverCDP('http://127.0.0.1:19229');
  page=browser.contexts().flatMap(c=>c.pages()).find(p=>p.url().includes('app.asar')&&!/startup.html|capture-browser.html/.test(p.url()));
  assert.ok(page,'Packaged application absent');page.setDefaultTimeout(15000);
  assert.ok(await page.locator('#desktop-v2-primary-navigation').isVisible(),'Login required; this script never logs in');
  const leftover=page.getByRole('dialog').filter({hasText:/选择 .*PoC \/ 模板/});
  if(await leftover.isVisible())await leftover.getByRole('button',{name:'取消',exact:true}).click();
  await navigate(page,'红队工作流');
  await page.locator('.editor-head-actions').getByRole('button',{name:'工作流配置',exact:true}).click();
  await selectOn(page,page.locator('#workflow-config-panel .project-select'),PROJECT_NAME,{exact:true});
  await page.getByRole('button',{name:'关闭工作流配置',exact:true}).click();
  async function reload(filename){
    const pending=page.waitForResponse(r=>workflowResponse(r,'GET'));
    await page.locator('.editor-head-actions').getByRole('button',{name:'重新加载',exact:true}).click();
    const response=await pending;assert.ok(response.ok(),'Workflow load failed');
    const raw=JSON.parse((await response.body()).toString('utf8'));write(filename,raw);await sleep(400);return spec(raw);
  }
  const before=await reload('original-get-response.json');
  if(!before.graph.nodes.some(n=>n.type==='phase'))blocked('Parent additive phase configuration is not yet complete');
  const scope=(await page.locator('[aria-label="当前工作流配置"]').innerText()).trim();
  result.originalRevision=before.revision;
  for(const candidate of candidates){
    const matches=before.steps.filter(s=>s.tool===candidate.tool);
    if(matches.length!==1)blocked('Expected exactly one existing '+candidate.tool+' node');
    const step=matches[0];
    if(step.risk!=='CAUTION'||step.requiresApproval!==true)blocked('Existing scanner approval is not CAUTION/required');
    await page.getByRole('button',{name:'适应画布',exact:true}).click();
    const node=page.locator(`.vue-flow__node[data-id=${JSON.stringify(step.nodeId)}]`);
    await node.locator('.node-main').click();
    await sleep(700);
    await page.locator('.workflow-library-tabs').getByText('节点配置',{exact:true}).click();
    const editor=page.locator('[aria-label="已选节点参数"]');
    assert.ok((await editor.innerText()).toLowerCase().includes(candidate.source.toLowerCase()),'Selected editor is not '+candidate.source);
    const all=editor.getByRole('checkbox',{name:'使用已同步且启用的全部 PoC / 模板',exact:true});
    if(await all.isChecked())await editor.getByText('使用已同步且启用的全部 PoC / 模板',{exact:true}).click();
    assert.equal(await all.isChecked(),false,'All templates must be disabled');
    const selector=editor.locator('.workflow-poc-selector');
    const choose=selector.getByRole('button',{name:'选择 PoC / 模板',exact:true});
    if(await choose.count())await choose.click();else await selector.getByRole('button',{name:'修改',exact:true}).click();
    const dialog=page.locator('.poc-picker-dialog:visible');
    const responsePending=page.waitForResponse(r=>{
      const u=new URL(r.url());return r.request().method()==='GET'&&u.pathname.endsWith('/vulnerabilities')&&u.searchParams.get('source')===candidate.source&&u.searchParams.get('query')===candidate.query;
    });
    await dialog.getByPlaceholder('搜索 CVE 编号、名称或标签...').fill(candidate.query);
    const response=await responsePending;assert.ok(response.ok(),'Catalog search failed');
    const raw=JSON.parse((await response.body()).toString('utf8'));write(candidate.source.toLowerCase()+'-catalog-response.json',raw);
    const entries=raw.content||raw.data?.content||[];
    const matching=entries.filter(v=>candidate.code?v.vulnerabilityCode===candidate.code:v.sourceExternalId===candidate.externalId);
    if(matching.length!==1)blocked(candidate.source+' exact registered candidate absent or ambiguous');
    const entry=matching[0];
    const relative=String(entry.templateRelativePath||'').replace(/\\/g,'/');
    if(entry.sourceType!==candidate.source||entry.scanSafety!=='SAFE'||entry.enabled!==true||entry.sourceActive!==true||!(relative===candidate.file||relative.endsWith('/'+candidate.file)))blocked(candidate.source+' registered identity, enabled state or reviewed template path mismatch');
    if(!entry.vulnerabilityCode)blocked('Catalog returned no real vulnerability code');
    await sleep(400);
    const rows=dialog.locator('.el-table__body tr').filter({has:page.locator('.poc-dialog-code',{hasText:entry.sourceExternalId||entry.vulnerabilityCode})});
    if(await rows.count()!==1)blocked('Exact candidate cannot be uniquely selected in visible UI');
    assert.match(await rows.innerText(),/安全/);
    await dialog.getByRole('button',{name:'清空',exact:true}).click();
    await rows.locator('.el-checkbox__inner').click();
    assert.equal(await rows.getByRole('checkbox').isChecked(),true);
    await dialog.getByRole('button',{name:'保存选择 (1)',exact:true}).click();
    const choice={nodeId:step.nodeId,tool:candidate.tool,code:entry.vulnerabilityCode,templateRelativePath:entry.templateRelativePath};
    result.selected.push(choice);
    await page.screenshot({path:path.join(OUT,candidate.source.toLowerCase()+'-prepared.png'),fullPage:true});
    note('Selected one reviewed '+candidate.source+' template through UI; no execution requested.');
    if(candidate.source==='XRAY')await revealAfrogByMovingXray(node,choice,before);
  }
  assert.equal((await page.locator('[aria-label="当前工作流配置"]').innerText()).trim(),scope,'Scope changed');
  assert.equal(await page.locator('.graph-validation:visible').count(),0,'Workflow validation failed');
  const savePending=page.waitForResponse(r=>workflowResponse(r,'PUT'),{timeout:30000});
  await page.getByRole('button',{name:'保存工作流',exact:true}).click();
  const saved=await savePending;
  write('submitted-put-request.json',JSON.parse(saved.request().postData()));
  const savedRaw=JSON.parse((await saved.body()).toString('utf8'));write('saved-put-response.json',savedRaw);
  assert.ok(saved.ok(),'Save failed');
  const after=await reload('new-get-response.json');
  verifyPreserved(before,after,result.selected);
  verifyPreserved(before,spec(savedRaw),result.selected);
  assert.ok(after.revision>before.revision,'New revision absent');
  Object.assign(result,{status:'PASS',savedRevision:after.revision,savedDigest:after.specDigest});
  note('Saved the two scanner PoC selections and, if needed, only the Xray layout move; full GET/PUT/new GET retained. No scanner or workflow executed.');
  console.log('COMPLETE '+OUT);process.exit(0);
})().catch(async error=>{
  Object.assign(result,{status:error.blocked?'BLOCKED':'FAIL',error:error.message,stack:error.stack});write('results.json',result);
  if(page)await page.screenshot({path:path.join(OUT,'stopped.png'),fullPage:true}).catch(()=>{});
  console.error(error.message);console.error('EVIDENCE '+OUT);process.exit(1);
});
