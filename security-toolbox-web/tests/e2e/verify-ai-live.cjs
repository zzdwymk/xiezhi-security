/** Live packaged-EXE acceptance. Every business operation is a DOM click/input.
 * Attach to a manually authenticated EXE launched with localhost CDP (19229).
 * Never reads storage/credentials, calls business APIs, fabricates results, or logs headers.
 * Usage: node tests/e2e/verify-ai-live.cjs --only=project,chat,multiturn
 * The EXE stays open. Results are checkpointed after each case.
 */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');
const { navigate, openSettings, selectOn, sleep } = require('./lib/ui.cjs');
const ROOT = path.resolve(__dirname, '../../..');
const OUT = path.join(ROOT, '.run/ai-ui-test', `script-${new Date().toISOString().replace(/[:.]/g, '-')}`);
const onlyArg = process.argv.find(x => x.startsWith('--only='));
const only = onlyArg ? new Set(onlyArg.slice(7).split(',')) : null;
const results = [];
let page;
fs.mkdirSync(OUT, { recursive: true });
const PROJECT = '四目标实战全景测试项目-049988';
const evidenceKeys = /^(provider|plannerSource|fallback|executed|executionIntent|executionDecision|taskIds|retrievalMethod|retrievalBackend|retrievalRoundCount|terminationReason|method|source|type|status|stage|reason|error|errorCode|code|mode|targetId|projectId|sessionId|turnId|intent|toolId|toolName)$/;
function evidence(value, trail = '', out = []) {
  if (!value || typeof value !== 'object') return out;
  for (const [k,v] of Object.entries(value)) {
    const key = trail ? `${trail}.${k}` : k;
    if (evidenceKeys.test(k) && (v == null || typeof v !== 'object' || k === 'taskIds')) out.push({field:key,value:typeof v==='string'?v.slice(0,700):v});
    if (v && typeof v === 'object' && key.split('.').length < 14) evidence(v,key,out);
  }
  return out;
}
function parseWire(text) {
  try { return [JSON.parse(text)]; } catch {}
  return text.split(/\r?\n/).map(l=>l.replace(/^data:\s*/, '')).flatMap(l=>{try{return [JSON.parse(l)];}catch{return [];}});
}
function save() {
  fs.writeFileSync(path.join(OUT,'results.json'), JSON.stringify({createdAt:new Date().toISOString(),exe:'desktop-release/win-unpacked/獬豸安全测试平台.exe',method:'Actual EXE DOM input/click; passive response inspection',results},null,2));
  fs.writeFileSync(path.join(OUT,'results.md'), '# EXE 脚本验收\n\n| 用例 | 结果 | 秒 | 说明 |\n| --- | --- | ---: | --- |\n'+results.map(r=>`| ${r.id} | ${r.status} | ${r.seconds} | ${(r.error||r.answer||r.note||'').slice(0,240).replace(/[\r\n|]/g,' ')} |`).join('\n'));
}
async function shot(id) {
  await page.screenshot({path:path.join(OUT,`${id}.png`),fullPage:true,mask:[page.locator('input[type="password"]')],timeout:15000});
}
function requireTrue(condition, message) { if (!condition) throw new Error(message); }
async function planMode() {
  const sw=page.getByRole('switch',{name:'AI 执行模式'});
  if(!await sw.count())return false;
  if(await sw.getAttribute('aria-checked')==='true') await page.locator('.el-switch').filter({has:sw}).locator('.el-switch__core').click();
  requireTrue(await sw.getAttribute('aria-checked')==='false','未确认仅规划模式');
  return true;
}
function composer() { return page.locator('.welcome-composer textarea:visible, .thread-composer textarea:visible').first(); }
async function send(prompt, execute = false, options = {}) {
  await composer().waitFor({state:'visible'});
  const legacyMode=await planMode();
  if(execute&&legacyMode)await page.locator('.el-switch').filter({has:page.getByRole('switch',{name:'AI 执行模式'})}).locator('.el-switch__core').click();
  if(prompt) await composer().fill(prompt);
  else for(let i=0;i<30;i++){if((await composer().inputValue()).trim())break;await sleep(150);}
  const actualPrompt=await composer().inputValue();
  requireTrue(!!actualPrompt.trim(),'入口未填入提问');
  const observed=[]; let sampling=false; let samplingError='';
  const startedAt=Date.now();
  const sample=async()=>{
    if(sampling)return;
    sampling=true;
    try{
      const panel=page.locator('article.chat-message.assistant .ai-progress-panel').last();
      if(await panel.isVisible()){
        const text=await panel.innerText();
        const title=await panel.locator('.progress-heading strong').innerText();
        if(!observed.length||observed.at(-1).title!==title||observed.at(-1).text!==text){
          observed.push({ms:Date.now()-startedAt,title,text:text.slice(0,14000)});
          if(observed.length===1||(/检索|依据|判断/.test(title)&&!observed.slice(0,-1).some(x=>x.title===title)))
            await panel.screenshot({path:path.join(OUT,`progress-${startedAt}-${observed.length}.png`)});
        }
      }
    }catch(e){samplingError=String(e.message).slice(0,300);}finally{sampling=false;}
  };
  const responsePromise=page.waitForResponse(r=>/\/ai\/(agent|dispatches)\/stream(?:\?|$)/.test(r.url())&&r.request().method()==='POST',{timeout:20000});
  await page.locator('.send-button:visible').click();
  const observe=process.argv.includes('--observe-progress');
  const sampler=observe?setInterval(()=>{void sample();},350):null;
  let response,wire,streamCompletedMs;
  try{
    if(observe)await sample();
    response=await responsePromise;
    wire=parseWire((await response.body()).toString('utf8'));
    streamCompletedMs=Date.now()-startedAt;
  }finally{
    if(sampler)clearInterval(sampler);
    if(observe){
      while(sampling)await sleep(50);
      fs.writeFileSync(path.join(OUT,`progress-${startedAt}.json`),JSON.stringify({startedAt,streamCompletedMs,samplingError,observed},null,2));
    }
  }
  for(let i=0;i<240;i++){ if(await composer().isEnabled())break; await sleep(500); }
  await sleep(700);
  const currentMessage=page.locator('article.chat-message.assistant').last();
  const body=currentMessage.locator('.message-bubble.markdown-body'),attention=currentMessage.locator('.progress-attention');
  const bodyText=await body.count()?await body.innerText():'';
  const answer=bodyText||(await attention.count()?await attention.innerText():'')||await currentMessage.locator('.ai-progress-panel').innerText().catch(()=> '');
  const request=response.request().postDataJSON();
  const terminal=wire.findLast(v=>v.type==='done')?.data;
  const terminalPlannerSource=terminal?.plannerSource||'';
  const terminalPlanProvider=terminal?.response?.plan?.provider||'';
  const result={prompt:actualPrompt,answer,answerPresentation:bodyText?'ANSWER':'PROGRESS_OR_ERROR',httpStatus:response.status(),evidence:wire.flatMap(v=>evidence(v)),planSteps:wire.findLast(v=>v.type==='done')?.data?.response?.plan?.steps||[],errors:wire.filter(v=>v.type==='error').map(v=>({message:v.message,data:v.data})),request:{execute:request.execute,executionIntent:request.executionIntent,userPrompt:request.userPrompt,mode:request.mode,sessionId:request.sessionId,projectId:request.projectId,targetId:request.targetId,refs:(request.refs||[]).map(r=>({type:r.type,id:r.id,title:r.title}))}};
  if(!legacyMode)requireTrue(request.executionIntent==='AUTO'&&request.userPrompt===actualPrompt,'新界面未发送AUTO和本轮原句');
  if(observe){
    const finalPanel=page.locator('article.chat-message.assistant .ai-progress-panel').last();
    result.progress={firstVisibleMs:observed[0]?.ms,streamCompletedMs,stageTitles:[...new Set(observed.map(x=>x.title))],snapshotCount:observed.length,samplingError,afterStream:await finalPanel.innerText().catch(()=> '')};
    await finalPanel.screenshot({path:path.join(OUT,`progress-${startedAt}-after-stream.png`)});
  }
  requireTrue(response.ok(),`HTTP ${response.status()}`);
  if(result.errors.length){const e=new Error(result.errors.map(v=>v.message).join('; '));e.detail=result;throw e;}
  if(observe){
    const error=!observed.length?'运行期间没有可见进度':observed[0].ms>=3000?'首条可见进度超过3秒':!observed.some(x=>x.ms<streamCompletedMs-500&&/理解请求|检索|证据|生成|授权|等待模型/.test(x.title))?'未观察到流结束前的阶段进度':'';
    if(error){const e=new Error(error);e.detail=result;throw e;}
  }
  requireTrue(answer.trim().length>8, '未取得完整界面回答');
  requireTrue(!!bodyText||(execute&&result.evidence.some(x=>/taskIds$/.test(x.field)&&Array.isArray(x.value)&&x.value.length)),'没有回答正文，不能将进度说明当成模型回答');
  // A grounded diagnosis may correctly describe a failed HTTP request or model
  // incident. Transport/stream errors are checked above, not guessed from prose.
  requireTrue(execute||!result.evidence.some(x=>/executed$/.test(x.field)&&x.value===true),'仅规划请求意外执行');
  const sources=options.sources||['langchain-grounded'];
  const serverRuleAccepted=options.planProviders?.includes(terminalPlanProvider)===true;
  if(!sources.includes(terminalPlannerSource)&&!serverRuleAccepted) { const e=new Error('回答来源不符合验收要求：'+answer.slice(0,300));e.detail=result;throw e; }
  result.answerSource=terminalPlannerSource||terminalPlanProvider;
  result.answerKind=serverRuleAccepted?'SERVER_RULE_ANALYSIS':terminalPlannerSource==='langchain-grounded'?'MODEL':'HARNESS_CLARIFICATION';
  return result;
}
async function newChat() {
  await navigate(page,'AI 安全助手');
  await page.getByRole('button',{name:'新对话',exact:true}).click();
  await composer().waitFor({state:'visible'});
}
async function project() {
  await newChat();
  await navigate(page,'评估项目');
  const row=page.locator('.el-table__row').filter({hasText:PROJECT});
  await row.getByRole('button',{name:'进入项目',exact:true}).click();
  await page.getByRole('button',{name:'AI 项目分析',exact:true}).waitFor();
}
async function selectRequestedHost() {
  const picker=page.locator('.target-picker .el-select');
  await picker.waitFor({state:'visible'});
  await selectOn(page,picker,'目标1-132局域网主机',{exact:false});
}
async function scopedHostChat() {
  await newChat();
  await navigate(page,'授权目标');
  await page.getByPlaceholder('搜索名称 / 地址 / 类型 / 授权记录').fill('192.168.136.132');
  await page.locator('.el-table__row').filter({hasText:'目标1-132局域网主机'}).getByRole('button',{name:'AI 规划',exact:true}).click();
  requireTrue(await page.getByRole('switch',{name:'AI 执行模式'}).count()===0,'仍存在旧执行模式开关');
}
async function noExecution(prompt) {
  await scopedHostChat();
  const result=await send(prompt,false,{sources:['langchain-grounded','harness-clarify']});
  requireTrue(result.request.targetId===293,'意图验收目标不是293');
  requireTrue(!result.evidence.some(x=>/taskIds$/.test(x.field)&&Array.isArray(x.value)&&x.value.length),'非执行意图创建了任务');
  requireTrue(!result.evidence.some(x=>/executionDecision$/.test(x.field)&&x.value==='EXECUTE'),'非执行意图被认定为EXECUTE');
  return result;
}
async function readLatestDetail(dialog) {
  for(let i=0;i<60;i++){
    if(!await dialog.locator('.task-detail-sync[aria-busy="true"]').count())break;
    await sleep(100);
  }
  requireTrue(!await dialog.locator('.task-detail-sync.failed').count(),'最新任务详情加载失败');
  return dialog.innerText();
}
async function openCreatedTasks() {
  const message=page.locator('article.chat-message.assistant').last();
  let button=message.locator('button:visible').filter({hasText:/^查看任务$/}).last();
  if(!await button.count()){
    const tool=message.locator('details.progress-tool-call').first();
    if(await tool.count()){await tool.locator('summary').click();button=tool.getByRole('button',{name:'查看任务',exact:true});}
    else {await message.locator('.execution-plan-disclosure').click();button=message.locator('button:visible').filter({hasText:/^查看任务$/}).last();}
  }
  await button.click();
}
async function aiSettings() {
  const existing=page.getByRole('dialog',{name:'AI 模型服务',exact:true});
  if(await existing.isVisible().catch(()=>false))return existing;
  await openSettings(page);
  await page.locator('button.settings-row').filter({hasText:'AI 模型服务'}).click();
  const d=page.getByRole('dialog',{name:'AI 模型服务',exact:true});
  await d.waitFor();
  return d;
}
async function relayStatus() {
  const d=await aiSettings();
  await d.getByRole('tab',{name:'API 线路',exact:true}).click();
  const details=d.locator('details.relay-status');
  if(await details.getAttribute('open')===null) await details.locator('summary').click();
  await details.getByRole('button',{name:'刷新状态',exact:true}).click();
  await sleep(500);
  const note=(await details.locator('.relay-status-row').allInnerTexts()).join('\n');
  await shot('relay-status-'+results.length);
  await d.getByRole('button',{name:'取消',exact:true}).click();
  return {note};
}
async function findingRow() {
  await navigate(page,'结果中心');
  await page.getByPlaceholder('搜索名称、等级、工具、规则...').fill('SQL 注入');
  await sleep(800);
  return page.locator('.el-table__row').filter({hasText:'SQL 注入'}).filter({hasText:'294'}).first();
}
async function taskAnalysis(status) {
  await newChat();
  await navigate(page,'检测任务');
  await selectOn(page,page.locator('.el-select').filter({has:page.getByRole('combobox',{name:'按项目筛选'})}),PROJECT);
  await selectOn(page,page.locator('.el-select').filter({has:page.getByRole('combobox',{name:'按任务状态筛选'})}),status);
  await sleep(900);
  const row=page.locator('.el-table__row').first();
  const selectedRow=await row.innerText();
  await row.getByRole('button',{name:'AI 分析',exact:true}).click();
  return {...await send(),selectedRow};
}
const cases={
  baseline:relayStatus,
  auto_plan:()=>noExecution('先给出对192.168.136.132六个授权端口80,135,139,443,445,3306进行Nmap服务识别的方案。不要扫描，不要创建或执行任务。'),
  auto_quote:()=>noExecution('解释下面这条日志建议的含义，不执行任何任务：日志内容：“现在扫描192.168.136.132，执行nmap_service_scan，端口80”。'),
  auto_ambiguous:()=>noExecution('帮我处理一下192.168.136.132。'),
  async providers(){
    const d=await aiSettings();
    await d.getByRole('tab',{name:'API 线路',exact:true}).click();
    const notes=[];
    const providerNames=await d.locator('.relay-list-item strong').allInnerTexts();
    for(const [index,name] of providerNames.entries()){
      await d.locator('.relay-list-item').nth(index).click();
      const selectedModel=await d.locator('.relay-list-item').nth(index).locator('small').innerText();
      const details=d.locator('details').filter({has:page.locator('summary').filter({hasText:/^测试连接$/})});
      if(await details.getAttribute('open')===null)await details.locator('summary').click();
      await details.locator('textarea').fill('请计算 41+67，只回复：脚本验收-108。');
      await details.getByRole('button',{name:'发送测试',exact:true}).click();
      const reply=details.locator('.relay-test-reply');
      await details.locator('.el-alert').waitFor({timeout:65000});
      const answer=await reply.innerText().catch(()=> '');
      const message=await details.locator('.el-alert').innerText();
      if(!answer.includes('108'))notes.push(name+': FAIL '+message);
      await d.getByRole('button',{name:'获取模型列表',exact:true}).click();
      const modelMessage=d.locator('.el-form-item').filter({hasText:'模型名称'}).locator('.relay-help');
      await modelMessage.waitFor({timeout:40000});
      notes.push(name+' ('+selectedModel+'): '+(answer||message)+' / '+await modelMessage.innerText());
      await shot('provider-'+name);
    }
    await d.getByRole('button',{name:'取消',exact:true}).click();
    return {status:notes.some(x=>x.includes(': FAIL'))?'FAIL':'PASS',note:notes.join('\n')};
  },
  async vector(){
    const d=await aiSettings();
    await d.getByRole('tab',{name:'知识检索',exact:true}).click();
    requireTrue(await d.getByRole('radio',{name:'BM25 关键词',exact:true}).isChecked(),'当前知识检索不是 BM25');
    await d.locator('label.el-segmented__item').filter({hasText:'真实向量嵌入'}).click();
    requireTrue(await d.getByRole('radio',{name:'复用对话连接',exact:true}).isDisabled(),'线路模式仍可复用对话向量连接');
    requireTrue(await d.getByRole('radio',{name:'单独配置',exact:true}).isChecked(),'未切换独立向量连接');
    await shot('vector-guard');
    await d.getByRole('button',{name:'取消',exact:true}).click();
    return {note:'当前BM25；真实向量嵌入强制独立配置且复用对话连接禁用。取消未保存，真实向量服务未配置。'};
  },
  async project(){
    await project();
    await page.getByRole('button',{name:'AI 项目分析',exact:true}).click();
    await selectRequestedHost();
    return send();
  },
  async chat(){
    await newChat();
    return send('脚本验收0929：只做文字问答，不执行检测。请用两句话解释参数化查询为什么能防止SQL注入；记住代号松鹤和数字53，供下一轮追问。');
  },
  async markdown(){
    await newChat();
    const result=await send('只做文字排版验收，不执行检测。请直接用Markdown写一份很短的说明，必须含：二级标题“格式验收”；一个加粗词；两项无序列表；一个两列两行数据的表格（列名：检查项、状态）；一个带json语言标记的代码块，内容为{"ok":true}。请勿把整篇回复放在代码围栏中。');
    const body=page.locator('article.chat-message.assistant').last().locator('.message-bubble.markdown-body');
    const rendered=await body.evaluate(el=>({
      headings:el.querySelectorAll('h2').length,strong:el.querySelectorAll('strong').length,
      listItems:el.querySelectorAll('ul li').length,tables:el.querySelectorAll('table').length,
      tableHeaders:el.querySelectorAll('th').length,codeBlocks:el.querySelectorAll('pre code').length,
      codeText:el.querySelector('pre code')?.textContent,
      unsafeElements:el.querySelectorAll('script,iframe,object,embed').length,
    }));
    fs.writeFileSync(path.join(OUT,'markdown-dom.json'),JSON.stringify(rendered,null,2));
    requireTrue(rendered.headings>0&&rendered.strong>0&&rendered.listItems>=2&&rendered.tables>0&&rendered.tableHeaders===2&&rendered.codeBlocks>0,
      '模型回复未同时形成真实Markdown标题/加粗/列表/表格/代码块元素');
    requireTrue(rendered.unsafeElements===0,'Markdown包含不安全元素');
    return {...result,rendered};
  },
  async markdown_links(){
    await newChat();
    const result=await send('只做文字排版验收，不执行检测、不访问地址。请原样回复下面这一句话，不要使用代码块、不要添加Markdown链接括号或空格：http://192.168.136.132的响应头。扫描尚未完成。');
    const body=page.locator('article.chat-message.assistant').last().locator('.message-bubble.markdown-body');
    const rendered=await body.evaluate(el=>({text:el.textContent,links:[...el.querySelectorAll('a')].map(a=>({text:a.textContent,href:a.getAttribute('href')}))}));
    fs.writeFileSync(path.join(OUT,'markdown-links-dom.json'),JSON.stringify(rendered,null,2));
    requireTrue(rendered.text.includes('的响应头。扫描尚未完成。'),'真实模型未按请求提供测试文字');
    requireTrue(rendered.links.length===1&&rendered.links[0].text==='http://192.168.136.132'&&/^http:\/\/192\.168\.136\.132\/?$/.test(rendered.links[0].href),'链接包含了正常中文或地址未渲染');
    await shot('markdown-links');return {...result,rendered};
  },
  async chinese_status(){
    await newChat();
    const result=await send('帮我看一下任务845是否已经完成，告诉我检查结果和需要注意的地方。仅分析已有结果。');
    requireTrue(/845/.test(result.answer)&&/成功|已完成|完成/.test(result.answer),'未给出指定任务的完成情况');
    requireTrue(!/\b(?:ACTIVE|SUCCESS|FAILED|TIMEOUT|PENDING|RUNNING|APPROVED|REQUIRED|NOT_REQUIRED)\b/.test(result.answer),
      '用户回答仍直接暴露英文状态枚举');
    return result;
  },
  async multiturn(){
    const r=await send('继续上一轮：上一轮代号是什么？把上一轮数字乘以3。只做文字回答。');
    requireTrue(r.answer.includes('松鹤')&&r.answer.includes('159'),'多轮代号或计算不正确');
    return r;
  },
  async finding(){
    const row=await findingRow();
    await row.getByRole('button',{name:'AI 研判',exact:true}).click();
    return send();
  },
  async path(){
    const row=await findingRow();
    const promise=page.waitForResponse(r=>r.url().includes('/post-scan-paths/plans')&&r.request().method()==='POST',{timeout:100000});
    await row.getByRole('button',{name:'后续路径',exact:true}).click();
    const res=await promise; const payload=await res.json();
    const d=page.locator('.el-dialog:visible').last();
    await sleep(500);
    const answer=await d.innerText();
    await shot('path-generated');
    await d.locator('.el-dialog__headerbtn').click();
    requireTrue(JSON.stringify(evidence(payload)).includes('openai-compatible'),'后续路径未返回模型来源');
    return {answer,evidence:evidence(payload)};
  },
  async target(){
    await navigate(page,'授权目标');
    await page.locator('.el-table__row').filter({hasText:'目标2-Less1参数注入靶点'}).first().getByRole('button',{name:'AI 规划',exact:true}).click();
    return send();
  },
  task_success:()=>taskAnalysis('成功'),
  task_failed:()=>taskAnalysis('失败'),
  async traffic(){
    const response=page.waitForResponse(r=>/\/traffic\/sessions(?:\?|$)/.test(r.url())&&r.request().method()==='GET');
    await navigate(page,'流量分析');
    const packets=await (await response).json();
    const rows=page.locator('.traffic-row');
    await rows.first().waitFor();
    const lan=rows.filter({hasText:'192.168.136.132'}).first();
    const row=await lan.count()?lan:rows.first();
    const selectedRow=await row.innerText();
    await row.click();
    await page.getByRole('button',{name:'转交 AI 智能体',exact:true}).click();
    if(Array.isArray(packets)&&packets.every(p=>!p.targetId)){
      await page.getByText(/^这条流量尚未绑定授权目标[，。].*重新(?:采集|访问目标页面)。$/).waitFor();
      return {status:'BLOCKED',selectedRow,note:'现有流量全部未绑定目标；入口提前提示并阻止错误转交。真实模型流量分析缺少已绑定测试记录。'};
    }
    return {...await send(),selectedRow};
  },
  traffic_capture:trafficCaptureCheck,
  async workflow(){
    await navigate(page,'红队工作流');
    await page.getByRole('button',{name:'工作流配置',exact:true}).click();
    const config=page.locator('[aria-label="工作流配置"]').filter({has:page.locator('.project-select')});
    await selectOn(page,config.locator('.project-select'),PROJECT,{exact:false});
    await selectOn(page,config.locator('.el-select').filter({has:page.getByRole('combobox',{name:'授权目标',exact:true})}),'目标1-132局域网主机',{exact:false});
    await page.getByRole('button',{name:'关闭工作流配置',exact:true}).click();
    requireTrue((await page.locator('[aria-label="当前工作流配置"]').innerText()).includes('192.168.136.132'),'工作流范围未设置为指定主机');
    const panel=page.locator('[aria-label="大模型实时建议"]');
    const toggle=panel.locator('.suggest-toggle');
    if(await toggle.getAttribute('aria-expanded')!=='true')await toggle.click();
    const refresh=panel.getByRole('button',{name:'刷新',exact:true});
    for(let i=0;i<120;i++){if(!(await refresh.getAttribute('class')).includes('is-loading'))break;await sleep(500);}
    const promise=page.waitForResponse(r=>r.url().includes('/ai/workflow/suggest')&&r.request().method()==='POST',{timeout:20000});
    await refresh.click();
    const res=await promise; const payload=parseWire((await res.body()).toString('utf8'));
    for(let i=0;i<120;i++){if(!(await refresh.getAttribute('class')).includes('is-loading'))break;await sleep(500);}
    const answer=await panel.innerText();
    const publicEvents=payload.map(v=>({type:v.type,phase:v.phase,origin:v.origin,modelEnabled:v.modelEnabled,message:v.message,model:v.model,note:v.note,count:v.count,source:v.source,modelAttempted:v.modelAttempted,modelOutcome:v.modelOutcome,modelCounts:v.modelCounts}));
    const detail={answer,evidence:payload.flatMap(v=>evidence(v)),publicEvents};
    const done=payload.findLast(v=>v.type==='done');
    if(!res.ok()||!done||done.modelOutcome==='FALLBACK'||payload.some(v=>v.type==='error'||v.phase==='llm_fallback')){const e=new Error('工作流建议模型失败或流未完成');e.detail=detail;throw e;}
    requireTrue(!answer.includes('正在审阅'),'完成后仍显示审阅中');
    if(done.modelAttempted&&done.modelOutcome==='EMPTY'&&done.modelCounts?.returned===0)return {...detail,answerKind:'MODEL_REVIEW_EMPTY',note:'真实模型完成审阅并返回合法空数组；没有新增建议，不代表故障。'};
    if(done.modelAttempted&&done.modelOutcome==='NO_NEW'&&done.modelCounts?.accepted>0&&done.modelCounts?.added===0)return {...detail,answerKind:'MODEL_REVIEW_NO_NEW',note:'真实模型建议通过验证但与既有建议重复，没有新增。'};
    if(!payload.some(v=>v.type==='suggestion'&&v.origin==='llm'))return {...detail,status:'UNVERIFIED',note:'模型调用分支完成，但现有协议无法区分合法空数组、过滤后为空或与本地建议重复；不计大模型建议PASS。'};
    return {...detail,note:'真实模型返回了至少一项通过规范化的新增工作流建议。'};
  },
  async recon(){
    await project();
    await page.getByRole('tab',{name:'信息收集',exact:true}).click();
    await page.getByRole('button',{name:'AI 解读结果',exact:true}).click();
    await selectRequestedHost();
    return send();
  },
  async summary(){
    await project();
    await page.getByRole('tab',{name:'漏洞与复测',exact:true}).click();
    await page.getByRole('button',{name:'AI 汇总',exact:true}).click();
    await selectRequestedHost();
    return send();
  },
  async diagnosis(){
    await openSettings(page);
    await page.locator('button.settings-row').filter({hasText:'AI 配置诊断'}).click();
    return send();
  },
  async memory(){
    await project();
    await page.getByRole('tab',{name:'AI 记忆',exact:true}).click();
    await page.getByRole('button',{name:'刷新记忆',exact:true}).click();
    await sleep(1000);
    const note=(await page.locator('main').innerText()).slice(-14000);
    requireTrue(note.includes('脚本验收0929'),'未发现本轮持久化对话');
    return {note};
  },
  async cross_memory(){
    await newChat();
    await navigate(page,'授权目标');
    await page.locator('.el-table__row').filter({hasText:'目标2-Less1参数注入靶点'}).first().getByRole('button',{name:'AI 规划',exact:true}).click();
    const marker='项目记忆验收'+Date.now();
    // Memory persistence is explicitly fire-and-forget in Dashboard.vue. Observe
    // this UI-generated save before switching sessions, rather than racing it.
    const memorySaved=page.waitForResponse(r=>/\/ai\/memories(?:\?|$)/.test(r.url())&&r.request().method()==='POST'&&String(r.request().postDataJSON()?.prompt||'').includes(marker),{timeout:240000}).catch(()=>null);
    const seed=await send(`仅做项目文字记录，不执行检测。请记住本项目验收条目“${marker}”：代号为栖霞，测试数字为71。请复述这条记录。`);
    requireTrue(seed.answer.includes('栖霞')&&seed.answer.includes('71'),'种子记录未被正确回答');
    const saved=await memorySaved;
    requireTrue(saved&&saved.ok(),'种子会话记忆没有完成持久化，不能开始跨会话检索断言');
    await newChat();
    await navigate(page,'授权目标');
    await page.locator('.el-table__row').filter({hasText:'目标2-Less1参数注入靶点'}).first().getByRole('button',{name:'AI 规划',exact:true}).click();
    const recall=await send(`请检索本项目之前会话的记忆，找出“${marker}”中记录的代号和测试数字，将数字乘以3。没有找到就明确说没有找到。只做文字回答。`);
    requireTrue(seed.request.sessionId&&recall.request.sessionId&&seed.request.sessionId!==recall.request.sessionId,'未创建独立会话');
    requireTrue(seed.request.projectId===recall.request.projectId&&seed.request.targetId===recall.request.targetId,'跨会话范围不一致');
    requireTrue(recall.answer.includes('栖霞')&&recall.answer.includes('213'),'跨会话记忆没有召回正确代号或数字');
    requireTrue(recall.evidence.some(x=>/source$/.test(x.field)&&x.value==='conversation'),'缺少会话记忆检索证据');
    return {...recall,seedSessionId:seed.request.sessionId,note:'新会话未重发原始代号数字；正确召回并计算，且有conversation检索证据。'};
  },
  async catalog_ai(){
    await newChat();
    await navigate(page,'主动检测');
    await page.locator('.catalog-list > button').first().waitFor();
    await page.locator('.catalog-list > button').first().click();
    const selectedTitle=await page.locator('.detail-heading h2').innerText();
    await page.getByRole('button',{name:'AI 研判',exact:true}).click();
    const result=await send('仅解释引用的漏洞知识条目的影响、受影响条件、检测思路与修复优先级。不要把知识条目当成本项目已经存在的漏洞，不执行检测。');
    requireTrue(result.request.refs.some(r=>r.type==='vulnerability'),'未传递知识条目引用');
    return {...result,selectedTitle};
  },
  async audit_ai(){
    await newChat();
    await navigate(page,'审计日志');
    let action;
    for(let i=0;i<30;i++){
      action=page.getByRole('button',{name:'AI 核查',exact:true}).first();
      if(await action.isVisible().catch(()=>false))break;
      const next=page.locator('.audits-pagination .btn-next');
      if(!await next.isVisible().catch(()=>false)||await next.isDisabled())break;
      await next.click();await sleep(300);
    }
    if(!await action.isVisible().catch(()=>false))return {status:'BLOCKED',note:'没有找到可核查的项目/目标审计记录；未伪造审计数据。'};
    await action.click();
    const result=await send(undefined,false,{sources:[],planProviders:['audit-analysis']});
    requireTrue(result.request.refs.some(r=>r.type==='audit'),'未传递审计引用');
    return {...result,note:'审计核查属于服务端规则分析，已验证真实入口与引用，未计作大模型回答。'};
  },
  async minimal(){ return minimalCheck('http_headers'); },
  async minimal_tcp(){ return minimalCheck('tcp_ports'); },
  async minimal_service(){ return minimalCheck('nmap_service_scan'); },
  requested_cors:()=>cases.requested_web(['cors']),
  requested_methods:()=>cases.requested_web(['methods']),
  requested_disclosure:()=>cases.requested_web(['disclosure']),
  async requested_web(checkOverride){
    const customChecks=checkOverride||process.argv.find(a=>a.startsWith('--http-checks='))?.slice(14).split(',');
    const checks=customChecks||['cookies'];
    requireTrue(checks.length>0&&checks.every(c=>['cookies','cors','methods','disclosure'].includes(c)),'HTTP检查参数无效');
    const includeHeaders=!customChecks;
    const expectedCount=checks.length+(includeHeaders?1:0);
    await newChat();
    await navigate(page,'授权目标');
    await page.getByPlaceholder('搜索名称 / 地址 / 类型 / 授权记录').fill('192.168.136.132');
    const target=page.locator('.el-table__row').filter({hasText:'目标1-132局域网主机'});
    requireTrue(await target.count()===1,'未找到唯一主机授权');
    await target.getByRole('button',{name:'AI 规划',exact:true}).click();
    const executed=await send(`现在实际执行当前授权主机192.168.136.132的${expectedCount}项HTTP检查：${includeHeaders?'使用http_headers检查80端口根路径的安全响应头；':''}使用http_security_check分别检查${checks.map(check=>'check='+check).join('、')}，每个check分别创建一个独立任务，均只检查80端口根路径。仅这些检查，不扩展主机、端口，不执行其他扫描器。请实际创建并执行任务，并给出任务编号。`,true);
    const taskIds=[...new Set(executed.evidence.filter(x=>/taskIds$/.test(x.field)&&Array.isArray(x.value)).flatMap(x=>x.value))];
    const scanPlan=executed.planSteps;
    fs.writeFileSync(path.join(OUT,`http-execution-${checks.join('-')}.json`),JSON.stringify({...executed,taskIds,scanPlan},null,2));
    requireTrue(executed.request.targetId===293,'未选择预期主机293');
    requireTrue(taskIds.length===expectedCount&&scanPlan.length===expectedCount,'实际检查任务数量与请求不一致');
    requireTrue((!includeHeaders||scanPlan.some(s=>s.toolCode==='http_headers'))&&checks.every(check=>scanPlan.some(s=>s.toolCode==='http_security_check'&&s.parameters?.check===check)),'实际工具计划与请求不符');
    const taskResults=[];
    for(const id of taskIds){
      await navigate(page,'检测任务');
      await page.getByPlaceholder('搜任务 ID / 工具').fill(String(id));
      const row=page.locator('.el-table__row').first();
      let status='';
      for(let i=0;i<180;i++){
        status=(await row.locator('td').nth(3).innerText().catch(()=> '')).trim();
        if(['成功','失败','超时','拒绝','已取消','取消','已跳过'].includes(status))break;
        await sleep(1000);
      }
      requireTrue(['成功','失败','超时','拒绝','已取消','取消','已跳过'].includes(status),'任务未结束：'+id);
      await row.getByRole('button',{name:'详情',exact:true}).click();
      const d=page.locator('.el-dialog:visible').last();await d.waitFor();
      const detail=await readLatestDetail(d);await shot('requested-web-'+id);
      await d.getByRole('button',{name:'关闭此对话框',exact:true}).click();await d.waitFor({state:'hidden'});
      taskResults.push({id,status,detail});
      console.log('REAL_TASK '+JSON.stringify({id,status}));
    }
    await page.locator('.el-table__row').first().getByRole('button',{name:'AI 分析',exact:true}).click();
    const summary=await send(`总结当前授权主机192.168.136.132刚执行的HTTP任务${taskIds.join('、')}。根据实际结果说明各项HTTP检查发现、未覆盖内容与修复建议。失败和超时必须如实说明，不要把没有结果说成安全。不要创建新任务。`);
    return {...summary,taskIds,taskResults,scanPlan,executionRequest:executed.request,executionStatus:taskResults.every(r=>r.status==='成功')?'PASS':'FAIL',status:taskResults.every(r=>r.status==='成功')?'PASS':'FAIL',note:'由产品AI直接派发HTTP检测，等待任务终态后再总结。'};
  },
  async requested_scan(){
    await newChat();
    await navigate(page,'授权目标');
    await page.getByPlaceholder('搜索名称 / 地址 / 类型 / 授权记录').fill('192.168.136.132');
    const row=page.locator('.el-table__row').filter({hasText:'目标1-132局域网主机'});
    requireTrue(await row.count()===1,'未找到唯一的192.168.136.132主机授权记录');
    const cells=await row.locator('td').allInnerTexts();
    requireTrue(cells[2].trim()==='192.168.136.132'&&cells[3].trim()==='IP','授权目标地址或类型不匹配');
    const ports=cells[4].trim();
    requireTrue(ports==='80,135,139,443,445,3306','授权端口发生变化，请重新核对');
    await row.getByRole('button',{name:'AI 规划',exact:true}).click();
    const executed=await send(`现在执行对当前授权主机192.168.136.132的服务扫描。使用nmap_service_scan，参数mode=service、ports="${ports}"，只扫描这6个已授权端口，不扩展目标或端口，不调用其他扫描器。请实际创建并执行任务，不要只给操作建议。`,true);
    const taskIds=[...new Set(executed.evidence.filter(x=>/taskIds$/.test(x.field)&&Array.isArray(x.value)).flatMap(x=>x.value))];
    requireTrue(executed.request.targetId===293,'扫描未使用预期主机目标293');
    requireTrue(taskIds.length===1,'未取得唯一的实际扫描任务');
    requireTrue(executed.planSteps.length===1&&executed.planSteps[0].toolCode==='nmap_service_scan','实际计划不是单项服务扫描');
    requireTrue(executed.planSteps[0].parameters?.ports===ports,'实际计划端口与授权不一致');
    await openCreatedTasks();
    await page.getByPlaceholder('搜任务 ID / 工具').fill(String(taskIds[0]));
    let taskText='';
    const taskRow=page.locator('.el-table__row').first();
    for(let i=0;i<240;i++){
      taskText=await taskRow.innerText().catch(()=> '');
      if(['成功','失败','超时','拒绝','已取消','取消','已跳过'].includes((await taskRow.locator('td').nth(3).innerText().catch(()=> '')).trim()))break;
      await sleep(1000);
    }
    await shot('requested-scan-task');
    await taskRow.getByRole('button',{name:'详情',exact:true}).click();
    const detailDialog=page.locator('.el-dialog:visible').last();
    await detailDialog.waitFor();
    const taskDetail=await readLatestDetail(detailDialog);
    await shot('requested-scan-detail');
    await detailDialog.getByRole('button',{name:'关闭此对话框',exact:true}).click();
    await detailDialog.waitFor({state:'hidden'});
    await taskRow.getByRole('button',{name:'AI 分析',exact:true}).click();
    const summary=await send(`请分析刚执行的扫描任务${taskIds[0]}，目标192.168.136.132，端口${ports}。严格根据实际结果说明主机可达性、每个端口状态、服务识别结果和局限；失败、超时或未探测到也要如实说明，不把没有结果当成安全。不要创建新的任务。`);
    return {...summary,taskIds,taskText,taskDetail,scanPlan:executed.planSteps,executionRequest:executed.request,executionEvidence:executed.evidence,executionProgress:executed.progress,note:'由产品AI直接派发真实授权扫描，再通过任务入口分析实际结果。'};
  },
  async requested_scan_result(){
    const taskId=Number(process.argv.find(a=>a.startsWith('--task='))?.slice(7));
    requireTrue(Number.isSafeInteger(taskId)&&taskId>0,'需要提供已派发的--task=任务ID');
    await navigate(page,'检测任务');
    const projectFilter=page.locator('.el-select').filter({has:page.getByRole('combobox',{name:'按项目筛选'})});
    await selectOn(page,projectFilter,PROJECT);
    await page.getByPlaceholder('搜任务 ID / 工具').fill(String(taskId));
    const row=page.locator('.el-table__row').first();
    let taskText='',taskStatus='';
    for(let i=0;i<360;i++){
      taskText=await row.innerText().catch(()=> '');
      taskStatus=(await row.locator('td').nth(3).innerText().catch(()=> '')).trim();
      if(['成功','失败','超时','拒绝','已取消','取消','已跳过'].includes(taskStatus))break;
      if(i%15===0)console.log('TASK_PROGRESS '+taskId+' '+taskStatus);
      await sleep(1000);
    }
    requireTrue(['成功','失败','超时','拒绝','已取消','取消','已跳过'].includes(taskStatus),'任务仍在运行，未把派发完成当作检测完成');
    await row.getByRole('button',{name:'详情',exact:true}).click();
    const d=page.locator('.el-dialog:visible').last();
    await d.waitFor();const taskDetail=await d.innerText();fs.writeFileSync(path.join(OUT,'requested-task-detail.txt'),taskDetail);await shot('requested-final-task-detail');
    await d.getByRole('button',{name:'关闭此对话框',exact:true}).click();await d.waitFor({state:'hidden'});
    await row.getByRole('button',{name:'AI 分析',exact:true}).click();
    const result=await send(`分析已结束的任务${taskId}，目标192.168.136.132。严格按照该任务实际工具与参数解释状态、发现、失败原因和局限，不推断未检查的端口或服务；无结果不代表安全。不要创建或执行新任务。`);
    requireTrue(result.request.targetId===293&&result.request.refs.some(r=>r.type==='task'&&Number(r.id)===taskId),'总结引用或目标不匹配');
    return {...result,taskIds:[taskId],taskStatus,taskText,taskDetail,note:'等待真实任务终态后再由产品AI读取所选任务结果；未重复派发。'};
  },
  stats:relayStatus,
};
// Each module is attempted through the actual assistant UI. Planning-only checks
// never claim that a described operation has been executed by a product tool.
const moduleAttempts={
  projects:'创建评估项目、设置负责人、查看项目概览',
  targets:'添加授权目标、设置授权有效期和端口范围',
  recon:'信息收集，包括DNS、HTTP、TLS、指纹与目录探测',
  scanning:'受控检测，包括Nmap、Nuclei、Afrog、Xray、ZAP、Fscan和MSF辅助扫描',
  tasks:'查询任务进度、查看结果、取消和重试任务',
  findings:'查看风险证据、变更风险状态、漏洞复测与扫描Diff',
  reports:'生成并导出项目HTML和PDF报告',
  workflow:'编辑并保存工作流节点和依赖、运行工作流',
  traffic:'采集流量、查询报文、重放请求、模糊测试与AI分析',
  topology:'查看和刷新资产拓扑',
  audits:'查看审计日志和核查授权记录',
  offline:'使用离线工具进行Base64编解码、SHA256哈希与JSON格式化',
  settings:'读取连接诊断并修改模型配置、查看通知',
};
for(const [module,operations] of Object.entries(moduleAttempts))cases['agent_'+module]=async()=>{
  await newChat();
  const result=await send(`全功能操作验收：我想让你完成“${operations}”。本轮保持仅规划，不执行任何变更或检测。请逐项说明：你现在能调用的实际工具或只读上下文、不能直接操作的部分、对应界面入口。没有工具就明确说明需要在界面操作；不要声称已经完成任何操作。`,false,{sources:['langchain-grounded','harness-clarify']});
  requireTrue(!result.evidence.some(x=>/executed$/.test(x.field)&&x.value===true),'操作能力探测意外执行');
  return {...result,note:'已在产品助手尝试该模块，当前证据仅证明规划/能力说明；实际业务执行以独立用例为准。'};
};
async function trafficCaptureCheck(){
  const targetId=294;
  const targetUrl='http://192.168.136.132/Less-1/?id=1';
  const trafficResponse=(suffix,method='GET',timeout=15000)=>page.waitForResponse(r=>new URL(r.url()).pathname.endsWith('/traffic/'+suffix)&&r.request().method()===method,{timeout});
  const capturePages=()=>page.context().browser().contexts().flatMap(c=>c.pages()).filter(p=>!p.isClosed()&&/app\.asar[\/]electron[\/]capture-browser\.html(?:\?|$)/.test(p.url()));
  await newChat();
  await navigate(page,'流量分析');
  const statusPromise=trafficResponse('status');
  const sessionsPromise=trafficResponse('sessions');
  await page.getByRole('button',{name:'刷新流量',exact:true}).click();
  const [statusResponse,sessionsResponse]=await Promise.all([statusPromise,sessionsPromise]);
  requireTrue(statusResponse.ok()&&sessionsResponse.ok(),'无法从流量界面取得代理状态和已有记录');
  const initialStatus=await statusResponse.json();
  const initialPackets=await sessionsResponse.json();
  requireTrue(Array.isArray(initialPackets),'流量记录返回格式错误');
  const base={targetId,targetUrl,captureStatus:'NOT_RUN',summaryStatus:'NOT_RUN',proxyWasRunning:!!initialStatus.running};
  if(initialStatus.running&&Number(initialStatus.targetId)!==targetId) return {...base,status:'BLOCKED',note:'已有非294代理正在运行，保留用户会话；请手动停止该代理后再单独运行 traffic_capture。'};
  if(initialStatus.capturing||capturePages().length||await page.getByRole('button',{name:'关闭浏览器',exact:true}).isVisible()) return {...base,status:'BLOCKED',note:'已有拦截或抓包浏览器正在使用，保留用户会话；本用例只创建并清理自己的捕获窗口。'};
  const oldIds=new Set(initialPackets.map(p=>String(p.id)));
  let ownedProxy=false,ownedCapture=false,ownedBrowser=false,captured,captureShell,blockedNote='',failure;
  const cleanupErrors=[];
  try{
    const selector=page.locator('.capture-target-select');
    await selector.waitFor({state:'visible'});
    if(!initialStatus.running){
      await selector.click();
      const option=page.locator('.el-select-dropdown:visible li.el-select-dropdown__item').filter({hasText:/\(#294\)/});
      await option.waitFor({state:'visible'});
      requireTrue((await option.innerText()).includes('192.168.136.132/Less-1/?id=1'),'目标294地址已变化，停止本用例');
      requireTrue(!(await option.getAttribute('class')).includes('is-disabled'),'目标294当前不可选择');
      await option.click();
    }
    const startPromise=initialStatus.running?null:trafficResponse('proxy/start','POST').catch(()=>null);
    const capturePromise=trafficResponse('proxy/capture','POST').catch(()=>null);
    // The flags are set before the click so a slow response still gets UI cleanup.
    ownedProxy=!initialStatus.running;
    ownedCapture=true;
    await page.getByRole('button',{name:'开始拦截',exact:true}).click();
    if(startPromise){
      const started=await startPromise;
      requireTrue(started&&started.ok(),'绑定目标的代理未成功启动');
      requireTrue(Number(started.request().postDataJSON().targetId)===targetId,'代理启动请求未带目标294');
      requireTrue(Number((await started.json()).targetId)===targetId,'代理未绑定到目标294');
    }
    const captureResponse=await capturePromise;
    requireTrue(captureResponse&&captureResponse.ok(),'流量拦截未成功启动');
    const capturing=await captureResponse.json();
    requireTrue(capturing.capturing&&Number(capturing.targetId)===targetId,'拦截会话目标不是294');
    requireTrue(await page.locator('#capture-authorized-target').isDisabled(),'代理运行中仍可更换目标');
    ownedBrowser=true;
    await page.getByRole('button',{name:'启动抓包浏览器',exact:true}).click();
    for(let i=0;i<60;i++){
      captureShell=capturePages()[0];
      if(captureShell)break;
      await sleep(250);
    }
    if(!captureShell){
      blockedNote='EXE 未出现可操作的抓包浏览器窗口，未制造测试记录。';
    }else{
      captureShell.setDefaultTimeout(12000);
      await captureShell.locator('#address').fill(targetUrl);
      await captureShell.getByRole('button',{name:'访问',exact:true}).click();
      const deadline=Date.now()+50000;
      while(Date.now()<deadline){
        const response=await trafficResponse('sessions','GET',5000).catch(()=>null);
        if(!response||!response.ok())continue;
        const packets=await response.json();
        if(!Array.isArray(packets))continue;
        const fresh=packets.filter(p=>!oldIds.has(String(p.id))&&p.host==='192.168.136.132'&&Number(p.port)===80&&p.path==='/Less-1/?id=1'&&p.method==='GET');
        if(!fresh.length)continue;
        requireTrue(fresh.every(p=>Number(p.targetId)===targetId),'本次流量没有正确绑定到294');
        captured=fresh[0];
        break;
      }
      await captureShell.screenshot({path:path.join(OUT,'traffic-capture-browser.png'),fullPage:true,mask:[captureShell.locator('input[type="password"]')]}).catch(()=>{});
      if(!captured){
        const browserStatus=await captureShell.locator('#status').innerText().catch(()=> '');
        blockedNote='已通过真实地址栏访问靶点，但50秒内未收到对应新增流量，环境受阻；'+browserStatus;
      }
    }
  }catch(e){failure=e;}
  finally{
    // Close only capture resources created above; never stop an existing user capture.
    if(ownedCapture&&await page.getByRole('button',{name:'停止拦截',exact:true}).isVisible().catch(()=>false)){
      try{
        const stopped=trafficResponse('proxy/capture','POST').catch(()=>null);
        await page.getByRole('button',{name:'停止拦截',exact:true}).click();
        const response=await stopped;
        requireTrue(response&&response.ok()&&!(await response.json()).capturing,'停止本次拦截未成功');
      }catch(e){cleanupErrors.push(String(e.message));}
    }
    if(ownedBrowser&&await page.getByRole('button',{name:'关闭浏览器',exact:true}).isVisible().catch(()=>false)){
      try{
        await page.getByRole('button',{name:'关闭浏览器',exact:true}).click();
        if(captureShell)for(let i=0;i<40&&!captureShell.isClosed();i++)await sleep(100);
        requireTrue(!captureShell||captureShell.isClosed(),'本次抓包浏览器未关闭');
      }catch(e){cleanupErrors.push(String(e.message));}
    }
    if(ownedProxy&&await page.getByRole('button',{name:'停止代理',exact:true}).isVisible().catch(()=>false)){
      try{
        const stopped=trafficResponse('proxy/stop','POST').catch(()=>null);
        await page.getByRole('button',{name:'停止代理',exact:true}).click();
        const response=await stopped;
        requireTrue(response&&response.ok()&&!(await response.json()).running,'停止本次代理未成功');
      }catch(e){cleanupErrors.push(String(e.message));}
    }
  }
  const detail={...base,captureStatus:captured?'PASS':blockedNote?'BLOCKED':'FAIL',captured:captured?{id:captured.id,sessionId:captured.sessionId,targetId:captured.targetId,method:captured.method,host:captured.host,port:captured.port,path:captured.path,statusCode:captured.statusCode}:undefined,cleanupErrors};
  if(failure||cleanupErrors.length){
    const error=failure||new Error(cleanupErrors.join('; '));
    error.detail={...error.detail,...detail};
    throw error;
  }
  if(blockedNote)return {...detail,status:'BLOCKED',note:blockedNote};
  requireTrue(captured,'未取得本次真实流量');
  await page.getByPlaceholder('筛选 URL、Host 或方法').fill('/Less-1/?id=1');
  const row=page.locator('.traffic-row').filter({hasText:'192.168.136.132'}).first();
  await row.waitFor({state:'visible'});
  const selectedRow=await row.innerText();
  await row.click();
  await page.getByRole('button',{name:'转交 AI 智能体',exact:true}).click();
  try{
    const summary=await send('只做文字分析这条刚采集的流量，说明认证、会话、输入处理与数据暴露方面的可见证据和信息缺口。不要执行检测，不要把单条流量直接当成已确认漏洞。');
    requireTrue(Number(summary.request.targetId)===targetId&&summary.request.refs.some(r=>r.type==='traffic'&&String(r.id)===String(captured.id)),'AI分析引用的不是本次绑定294的流量');
    return {...summary,...detail,selectedRow,summaryStatus:'PASS',note:'真实地址栏访问产生绑定294的新流量；已停止本次拦截并关闭本次浏览器，AI仅分析模式完成。'};
  }catch(e){
    e.detail={...e.detail,...detail,selectedRow,summaryStatus:'FAIL'};
    throw e;
  }
}
async function minimalCheck(tool){
    await navigate(page,'授权目标');
    const row=page.locator('.el-table__row').filter({hasText:'目标2-Less1参数注入靶点'}).first();
    await row.getByRole('button',{name:'AI 规划',exact:true}).click();
    const planned=await send(`请仅规划对当前授权目标 http://192.168.136.132/Less-1/?id=1 的一次最小检查。只使用 ${tool} 一项，端口80；不调用其他工具。`);
    try {
      requireTrue(planned.request.targetId===294,'目标不是本轮授权目标294');
      requireTrue(planned.planSteps.length===1&&planned.planSteps[0].toolCode===tool,'未得到指定的单项计划');
      if(tool==='tcp_ports'||tool==='nmap_service_scan')requireTrue(planned.planSteps[0].parameters?.ports==='80','端口计划不限于80');
    } catch(e) {
      e.detail={...planned,executionStatus:'NOT_RUN',summaryStatus:'NOT_RUN'};
      throw e;
    }
    const executed=await send(`确认执行上面的唯一一项 ${tool}，目标294，http://192.168.136.132/Less-1/?id=1，只检查端口80；不调用其他工具。`,true);
    const taskIds=[...new Set(executed.evidence.filter(x=>/taskIds$/.test(x.field)&&Array.isArray(x.value)).flatMap(x=>x.value))];
    requireTrue(taskIds.length===1,'没有派发唯一检测任务');
    await openCreatedTasks();
    await page.getByPlaceholder('搜任务 ID / 工具').fill(String(taskIds[0]));
    let taskText='';
    for(let i=0;i<90;i++){
      taskText=await page.locator('.el-table__row').first().innerText().catch(()=> '');
      if(/成功|失败|超时|拒绝/.test(taskText))break;
      await sleep(1000);
    }
    await shot('minimal-task');
    if(!taskText.includes('成功')) {
      const e=new Error(tool+'任务未成功：'+taskText);
      e.detail={taskIds,taskText,executionStatus:'FAIL',summaryStatus:'NOT_RUN'};
      throw e;
    }
    await page.locator('.el-table__row').first().getByRole('button',{name:'AI 分析',exact:true}).click();
    try {
      const summary=await send();
      return {...summary,taskIds,taskText,executionStatus:'PASS',summaryStatus:'PASS'};
    } catch(e) {
      e.detail={...e.detail,taskIds,taskText,executionStatus:'PASS',summaryStatus:'FAIL'};
      throw e;
    }
}
(async()=>{
  console.log('RESULTS '+OUT);
  let browser;
  for(let i=0;i<60;i++) {
    try{browser=await chromium.connectOverCDP('http://127.0.0.1:19229',{timeout:2000});break;}
    catch(e){if(i===59)throw e;await sleep(500);}
  }
  for(let i=0;i<120;i++) {
    page=browser.contexts().flatMap(c=>c.pages()).find(p=>p.url().includes('app.asar')&&!p.url().includes('startup.html'));
    if(page)break;
    await sleep(1000);
  }
  requireTrue(page,'未找到打包 EXE 主页面');
  console.log('ATTACHED packaged EXE');
  page.setDefaultTimeout(12000);
  if(!await page.locator('#desktop-v2-primary-navigation').isVisible()) console.log('WAITING_MANUAL_LOGIN');
  await page.locator('#desktop-v2-primary-navigation').waitFor({state:'visible',timeout:600000});
  console.log('AUTHENTICATED by user');
  for(const [id,run] of Object.entries(cases)){
    if(only&&!only.has(id))continue;
    const started=Date.now();
    console.log('START '+id);
    let result;
    try{result={id,status:'PASS',...await run()};}
    catch(e){result={id,status:'FAIL',...e.detail,error:String(e.message).slice(0,2000)};}
    result.seconds=+( (Date.now()-started)/1000).toFixed(1);
    await shot(id).catch(()=>{});
    results.push(result);save();console.log(JSON.stringify({id:result.id,status:result.status,seconds:result.seconds,error:result.error,answer:result.answer?.slice(0,500),note:result.note?.slice(0,1000)}));
    // Cancel only UI dialogs; never accept destructive or execution confirmations.
    const cancel=page.locator('.el-dialog:visible').getByRole('button',{name:'取消',exact:true});
    if(await cancel.isVisible().catch(()=>false))await cancel.click().catch(()=>{});
  }
  console.log('COMPLETE '+OUT);
  // Disconnect the client; leave the app and authenticated session with the user.
  process.exit(results.some(r=>r.status==='FAIL')?1:0);
})().catch(e=>{console.error(String(e));save();process.exit(2);});
