/** Actual packaged UI, restricted to the existing local acceptance project 133 / target 298.
 * Saves a new workflow revision containing only the read-only project retrieval node.
 * The previous revision is retained. No scanner, external host, business API shortcut or storage access.
 */
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {chromium}=require('playwright-core');
const {navigate,selectOn}=require('./lib/ui.cjs');
const out=path.resolve(__dirname,'../../../.run/workflow-retrieval-live',new Date().toISOString().replace(/[:.]/g,'-'));
fs.mkdirSync(out,{recursive:true});
const project='AI本机闭环验收-2026-10-01T12-38-32-728Z', target='AI本机HTTP夹具-2026-10-01T12-38-32-728Z';
const results=[]; let page;
const save=(name,value)=>fs.writeFileSync(path.join(out,name+'.json'),JSON.stringify(value,null,2));
async function check(name,fn){try{const data=await fn();results.push({name,status:'PASS',data});console.log('PASS '+name);}catch(error){results.push({name,status:'FAIL',error:error.message});throw error;}finally{save('results',results);}}
const response=(suffix,method='GET')=>page.waitForResponse(r=>new URL(r.url()).pathname.endsWith(suffix)&&r.request().method()===method,{timeout:90000});
const node=id=>page.locator('.vue-flow__node').filter({has:page.locator(':scope')}).and(page.locator(`[data-id=${JSON.stringify(id)}]`));
(async()=>{
  console.log('RESULTS '+out);
  const browser=await chromium.connectOverCDP('http://127.0.0.1:19229');
  page=browser.contexts().flatMap(c=>c.pages()).find(p=>p.url().includes('app.asar')&&!/startup.html|capture-browser.html/.test(p.url()));
  assert.ok(page);page.setDefaultTimeout(15000);
  await page.locator('#desktop-v2-primary-navigation').waitFor({state:'visible',timeout:60000});
  assert.equal(await page.locator('.el-overlay:visible').count(),0,'Pending user dialog');
  await navigate(page,'红队工作流');
  await page.locator('.editor-head-actions').getByRole('button',{name:'工作流配置',exact:true}).click();
  await selectOn(page,page.locator('#workflow-config-panel .project-select'),project,{exact:true});
  const targetSelect=page.locator('#workflow-config-panel .el-select').filter({has:page.getByRole('combobox',{name:'授权目标',exact:true})});
  if(await targetSelect.count()) await selectOn(page,targetSelect,target,{exact:false});
  await page.getByRole('button',{name:'关闭工作流配置',exact:true}).click();
  const loaded=response('/ai/workflow');
  await page.locator('.editor-head-actions').getByRole('button',{name:'重新加载',exact:true}).click();
  const original=await (await loaded).json();save('original-revision',original);
  assert.equal(Number(original.projectId),133);
  const contexts=original.steps.filter(s=>s.tool==='retrieve_project_context');assert.equal(contexts.length,1);
  const context=contexts[0].nodeId;
  await check('configure-only-a-real-retrieval-node',async()=>{
    for(const item of original.graph.nodes.filter(n=>!['__start__','__end__',context].includes(n.id))) {
      await page.getByRole('button',{name:'适应画布',exact:true}).first().click();
      const current=node(item.id);await current.hover();await current.getByRole('button',{name:'删除节点',exact:true}).click();
    }
    await page.getByRole('button',{name:'适应画布',exact:true}).first().click();
    for(const [from,to] of [['__start__',context],[context,'__end__']]) {
      const edges=page.locator('.vue-flow__edge');
      const existing=await edges.evaluateAll((els,pair)=>els.some(el=>el.classList.contains('source-'+pair[0])&&el.classList.contains('target-'+pair[1])),[from,to]);
      if(!existing) await node(from).locator('.node-handle--source').dragTo(node(to).locator('.node-handle--target'));
    }
    await node(context).locator('.workflow-node').click();
    await page.getByPlaceholder('当前目标的授权范围、扫描发现与待核实证据',{exact:true}).fill('响应头');
    const saving=response('/ai/workflow','PUT');
    await page.getByRole('button',{name:'保存工作流',exact:true}).click();
    const reply=await saving;assert.ok(reply.ok(),await reply.text());
    const spec=await reply.json();save('retrieval-revision',spec);
    assert.equal(Number(spec.projectId),133);assert.equal(spec.steps.length,1);assert.equal(spec.steps[0].tool,'retrieve_project_context');
    assert.deepEqual(spec.steps[0].parameters,{query:'响应头'});
    assert.equal((await page.locator('[aria-label="当前工作流配置"]').innerText()).includes('127.0.0.1:18888'),true);
    return {projectId:133,targetId:298,revision:spec.revision,tool:'retrieve_project_context'};
  });
  let runId;
  await check('execute-one-read-only-task-and-preserve-its-result',async()=>{
    await page.getByRole('button',{name:'执行工作流',exact:true}).click();
    const dialog=page.locator('.el-message-box:visible');await dialog.waitFor();
    assert.match(await dialog.innerText(),/1 个步骤/);
    const started=response('/workflow-runs','POST');
    await dialog.locator('.el-message-box__btns .el-button--primary').click();
    const reply=await started;assert.ok(reply.ok(),await reply.text());
    const request=reply.request().postDataJSON();assert.equal(Number(request.projectId),133);assert.equal(Number(request.targetId),298);
    let detail=await reply.json();save('started',detail);runId=detail.run.id;
    assert.equal(detail.tasks.length,1);assert.equal(detail.tasks[0].toolCode,'retrieve_project_context');
    const deadline=Date.now()+90000;
    while(!['COMPLETED','FAILED','PARTIAL_FAILED','STOPPED'].includes(detail.run.status)&&Date.now()<deadline) {
      detail=await (await response('/workflow-runs/'+runId)).json();
    }
    save('completed',detail);assert.equal(detail.run.status,'COMPLETED');
    const task=detail.tasks[0];assert.equal(task.status,'SUCCESS');assert.equal(task.workflowNodeId,context);
    const result=JSON.parse(task.resultJson);assert.equal(Number(result.data.projectId),133);assert.equal(Number(result.data.targetId),298);
    assert.equal(result.data.query,'响应头');assert.ok(result.data.items.length>0,'Owned fixture evidence should match the real query');
    assert.ok(result.data.items.every(item=>Number(item.targetId)===298&&item.source!=='conversation'));
    await node(context).locator('.node-run-status').click();
    await page.locator('.project-evidence-result').waitFor();
    assert.equal(await page.locator('.project-evidence-result .evidence-item').count(),result.data.items.length);
    assert.doesNotMatch(await page.locator('.node-detail-body').innerText(),/indexRevision|contentDigest|ev-[a-f0-9]{24}/);
    await page.screenshot({path:path.join(out,'real-retrieval-result.png'),fullPage:true});
    await page.getByRole('dialog').filter({has:page.locator('.project-evidence-result')}).getByRole('button',{name:'Close this dialog',exact:true}).click();
    return {runId,taskId:task.id,count:result.data.items.length,method:result.data.retrievalMethod};
  });
})().catch(async error=>{console.error(error.stack);save('failure',{error:error.message});if(page)await page.screenshot({path:path.join(out,'failure.png'),fullPage:true}).catch(()=>{});process.exitCode=1;}).finally(()=>{save('results',results);process.exit(process.exitCode||0);});
