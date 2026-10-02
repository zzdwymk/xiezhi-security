// Isolate the user-added working model through settings UI only.
// Saves/restores enabled flags, never reads or changes credentials or model IDs.
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require('playwright-core');
const {openSettings,sleep}=require('./lib/ui.cjs');
const snapshot=path.resolve(__dirname,'../../../.run/ai-ui-test/verification-provider-flags.json');
(async()=>{
  const restore=process.argv.includes('--restore');
  const keepWeixin=process.argv.includes('--keep-weixin');
  if(restore&&keepWeixin)throw Error('不能同时保留weixin与恢复旧配置');
  if(restore&&fs.existsSync(snapshot)&&JSON.parse(fs.readFileSync(snapshot,'utf8')).userDecision==='KEEP_WEIXIN_ONLY')throw Error('用户已明确选择只保留weixin；不得恢复旧线路');
  const b=await chromium.connectOverCDP('http://127.0.0.1:19229');
  const p=b.contexts().flatMap(c=>c.pages()).find(p=>p.url().includes('app.asar')&&!p.url().includes('startup.html'));
  p.setDefaultTimeout(12000);
  const d=p.getByRole('dialog',{name:'AI 模型服务',exact:true});
  if(!await d.isVisible()){
    await openSettings(p);
    await p.locator('button.settings-row').filter({hasText:'AI 模型服务'}).click();
  }
  await d.getByRole('tab',{name:'API 线路',exact:true}).click();
  const rows=d.locator('.relay-list-item');
  const before=[];
  for(let i=0;i<await rows.count();i++){
    const name=await rows.nth(i).locator('strong').innerText();
    const label=await rows.nth(i).locator('small').innerText();
    before.push({name,label,enabled:label.startsWith('已启用')});
  }
  if(before.filter(x=>x.name==='weixin').length!==1)throw Error('新线路名未唯一匹配；没有修改');
  if(!restore&&!keepWeixin){
    if(fs.existsSync(snapshot))throw Error('已有待恢复快照，不能覆盖');
    fs.writeFileSync(snapshot,JSON.stringify({before,createdAt:new Date().toISOString()},null,2));
  }
  const desired=restore?JSON.parse(fs.readFileSync(snapshot,'utf8')).before:before.map(x=>({...x,enabled:x.name==='weixin'}));
  if(desired.length!==before.length||desired.some((x,i)=>x.name!==before[i].name))throw Error('线路列表已变化，停止自动恢复');
  for(let i=0;i<before.length;i++){
    await rows.nth(i).click();
    const box=d.locator('.relay-form .el-switch').filter({hasText:'启用此线路'});
    const checked=await box.getByRole('switch').getAttribute('aria-checked')==='true';
    if(checked!==desired[i].enabled)await box.locator('.el-switch__core').click();
  }
  const save=d.getByRole('button',{name:'保存',exact:true});
  if(await save.isEnabled()){
    await save.click();
    await d.getByText('线路配置已保存。',{exact:true}).waitFor({timeout:30000});
  }
  const after=await rows.allInnerTexts();
  console.log(JSON.stringify({mode:keepWeixin?'KEEP_WEIXIN_ONLY':restore?'RESTORED':'ISOLATED',after}));
  const previous=fs.existsSync(snapshot)?JSON.parse(fs.readFileSync(snapshot,'utf8')):{};
  fs.writeFileSync(snapshot,JSON.stringify(keepWeixin?{...previous,userDecision:'KEEP_WEIXIN_ONLY',confirmedAt:new Date().toISOString(),after}: {before:desired.map((x,i)=>restore?x:before[i]),createdAt:new Date().toISOString(),restored:restore},null,2));
  await d.getByRole('button',{name:'取消',exact:true}).click();
  await d.waitFor({state:'hidden'});
  await sleep(500);
  process.exit();
})().catch(e=>{console.error(e.message);process.exit(1);});
