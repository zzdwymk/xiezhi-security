// Real store, Dashboard action/composer templates and functions; dispatch is an isolated recorder.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const ts=require('typescript'),{parse}=require('@vue/compiler-sfc'),{baseParse}=require('@vue/compiler-dom'),{chromium}=require('playwright-core');
const root=path.resolve(__dirname,'..'),out=path.resolve(root,'../.run/message-edit',new Date().toISOString().replace(/[:.]/g,'-'));
fs.mkdirSync(out,{recursive:true});
const dashboard=parse(fs.readFileSync(path.join(root,'src/views/Dashboard.vue'),'utf8')).descriptor;
const ast=ts.createSourceFile('Dashboard.ts',dashboard.scriptSetup.content,ts.ScriptTarget.Latest,true);
function code(name){const node=ast.statements.find(n=>ts.isFunctionDeclaration(n)?n.name?.text===name:ts.isVariableStatement(n)&&n.declarationList.declarations.some(d=>d.name.getText(ast)===name));assert.ok(node,name);return ts.transpileModule(node.getText(ast),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;}
function fragment(name){function walk(n){if(n.type===1&&n.props.some(p=>p.type===6&&p.name==='class'&&p.value?.content===name))return n.loc.source;for(const c of n.children||[]){const found=walk(c);if(found)return found;}}const result=walk(baseParse(dashboard.template.content));assert.ok(result,name);return result;}
function componentFragment(name){function walk(n){if(n.type===1&&n.tag===name)return n.loc.source;for(const c of n.children||[]){const found=walk(c);if(found)return found;}}const result=walk(baseParse(dashboard.template.content));assert.ok(result,name);return result;}
// This suite drives the card body the message actions belong to: the assistant
// progress panel and the user bubble. The reference, citation and plan cards
// have their own suites and their helpers are not part of this fixture.
function messageCardFragment(){function walk(n){if(n.type===1&&n.props.some(p=>p.type===6&&p.name==='class'&&p.value?.content==='message-response'))return n;for(const c of n.children||[]){const found=walk(c);if(found)return found;}}const card=walk(baseParse(dashboard.template.content));assert.ok(card,'message-response');const cls=n=>String(n.props.find(p=>p.type===6&&p.name==='class')?.value?.content||'');const keep=(card.children||[]).filter(n=>n.type===1&&(n.tag==='AiProgressPanel'||cls(n).startsWith('message-bubble')));assert.equal(keep.length,2,'assistant panel and user bubble');return card.loc.source.slice(0,card.loc.source.indexOf('>')+1)+keep.map(n=>n.loc.source).join('\n')+'</div>';}
const settings=parse(fs.readFileSync(path.join(root,'src/views/Settings.vue'),'utf8')).descriptor;
const settingsAst=ts.createSourceFile('Settings.ts',settings.scriptSetup.content,ts.ScriptTarget.Latest,true);
const diagnosticsWatch=settingsAst.statements.find(n=>ts.isExpressionStatement(n)&&n.getText(settingsAst).startsWith('watch(() => route.query.ai,'));assert.ok(diagnosticsWatch);
const fixtureId=path.join(root,'__message-edit.vue').replace(/\\/g,'/');
const sfc=`<script setup>
import {computed,nextTick,reactive,ref,watch} from 'vue';import {useConversationStore,ConversationStorageError} from '/src/stores/conversations';
import {CircleCheck,CopyDocument,EditPen,Refresh,Dismiss,Promotion} from '/src/components/fluentIcons';
import messageQuoteIcon from '@fluentui/svg-icons/icons/text_quote_24_regular.svg?url';
import MarkdownComposerPreview from '/src/components/MarkdownComposerPreview.vue';
import ConversationAvatar from '/src/components/ConversationAvatar.vue';import {markdownToPlainText,renderMarkdown} from '/src/utils/markdown';
import AiFailureNotice from '/src/components/AiFailureNotice.vue';import AiProgressPanel from '/src/components/AiProgressPanel.vue';import AiStatusStamp from '/src/components/AiStatusStamp.vue';
import {isAiStatusOutsideCard} from '/src/utils/aiStatus';
import FluentIcon from '/src/components/FluentIcon.vue';
import {displayKnownTestName,copilotReferenceTypeLabel} from '/src/utils/aiPresentation';
import {requireAiAnswer} from '/src/utils/aiAnswer';
const conversations=useConversationStore();const route=reactive({query:{conversation:'source'}});
const router={replace:async value=>{route.query=value.query||{};await nextTick()},push:async value=>{window.pushedRoute=value;route.query={...route.query,...value.query};await nextTick()}};
const aiSettingsTab=ref('relay'),aiDialog=ref(false);
${ts.transpileModule(diagnosticsWatch.getText(settingsAst),{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText}
const notices=[];const ElMessage=Object.fromEntries(['success','error','warning'].map(level=>[level,text=>notices.push({level,text})]));
const now='2026-10-02T00:00:00Z';const msg=(id,role,content,extra={})=>({id,role,content,status:'completed',taskIds:[],steps:[],createdAt:now,updatedAt:now,...extra});
const source={id:'source',title:'原始对话',projectId:7,targetId:9,targetName:'授权目标',createdAt:now,updatedAt:now,messages:[
msg('u1','user','此前的问题',{references:[{type:'target',id:9,data:{nested:{value:'original'}}}]}),
msg('a1','assistant','此前的 **Markdown** 回答',{replyToId:'u1',taskIds:[101],steps:[{toolCode:'tcp_ports',title:'旧任务',taskId:101}],approvalId:88,approvalStatus:'APPROVED',executionDecision:'APPROVED',agentEvents:[{type:'approval',approvalId:88}],modelStreamStatus:'completed'}),
msg('u2','user','待编辑的 **原始 Markdown**',{references:[{type:'finding',id:243,targetId:9}],copilotMode:'plan',quote:{messageId:'a1',role:'assistant',content:'此前的 **Markdown** 回答',createdAt:now},executionRequested:true}),
msg('a2','assistant','此后的回答绝不可自动带入',{replyToId:'u2',taskIds:[202],approvalId:99,approvalStatus:'APPROVED'}),
msg('u3','user','此后的问题也不可带入')]};
conversations.items=[source];conversations.updateMessage('source','u1',{});
const original=JSON.stringify(conversations.items[0]);
const selectedThread=computed(()=>conversations.items.find(t=>t.id===route.query.conversation));
const selectedTarget=ref({id:9,name:'授权目标'}),enabledTargets=ref([{id:9,name:'授权目标'}]),selectedTargetId=ref(9);
const prompt=ref('编辑前未发送的草稿'),activeDraft=ref({id:'draft',mode:'ask',refs:[{type:'target',id:19}],createdAt:1,expiresAt:9999999999999});
const composerInputRef=ref(),quotedMessage=ref({id:'saved-quote',role:'assistant',content:'原草稿引用',createdAt:now});
const editingMessage=ref(),copiedMessageId=ref(),sending=ref(false),retryingMessageIds=ref(new Set());let copiedMessageTimer;
const projectByTarget=ref({9:7}),tasks=ref([]);const scrollToBottom=async()=>{},readableConversationError=()=> '发送失败';
const answerRequests=[];const endpoints={answerAi:async request=>{answerRequests.push(request);return{data:{answer:'重新生成的回复'}}}};
const referencesPrompt=refs=>refs.length?JSON.stringify(refs):'';const displayedMessageContent=message=>message.content;
const auditScopeForMessage=async()=>undefined;
${['messageQuoteStyle','composerReferences','cloneMessageDraft','messageReferences','messageContextContent','buildContextPrompt','quoteMessage','focusComposer','clearQuotedMessage','quotePreview','editMessage','cancelMessageEdit','copyMessage','projectIdForTarget','sendPrompt','handlePromptKeydown','openAiDiagnostics','relatedTasks','isStatusOutsideAnswerCard','retryConversationMessage'].map(code).join('\n')}
const requests=[];async function dispatchConversationMessage(thread,user,assistant,projectId){requests.push({sessionId:thread.id,turnId:user.id,context:buildContextPrompt(thread,user.id),user:JSON.parse(JSON.stringify(user)),assistant:JSON.parse(JSON.stringify(assistant)),projectId});if(window.holdDispatch)await new Promise(resolve=>window.releaseDispatch=resolve);conversations.updateMessage(thread.id,assistant.id,{content:'分支的新回复',status:'completed'});}
Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async text=>{window.copiedMarkdown=text}}});
window.editFixture={conversations,route,selectedThread,prompt,activeDraft,quotedMessage,editingMessage,sending,requests,notices,original,editMessage,cancelMessageEdit,sendPrompt,handlePromptKeydown,copyMessage,tasks,answerRequests,aiSettingsTab,aiDialog};
</script><template><main class="desktop-v2-app-frame"><div class="desktop-v2-content"><div class="chat-page"><section class="messages-inner"><article v-for="message in selectedThread.messages" :key="message.id" class="chat-message" :class="message.role" :data-id="message.id"><ConversationAvatar class="message-avatar" :role="message.role" /><div class="message-column">${messageCardFragment()}${fragment('message-status')}${fragment('message-actions')}</div></article></section>${fragment('thread-composer')}</div></div></main></template>
${dashboard.styles.map(style=>'<style scoped>'+style.content+'</style>').join('\n')}`;
const html=`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><style>html,body{height:auto!important;overflow:auto!important}main{max-width:900px;margin:24px auto;padding:8px}.messages-inner{width:100%!important;padding:0!important}.thread-composer{margin-top:20px}</style></head><body class="desktop-v2-native-frame"><div id="app"></div><script type="module">
import {createApp} from 'vue';import {createPinia} from 'pinia';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';
import Fixture from '/__message-edit.vue';createApp(Fixture).use(createPinia()).use(ElementPlus).mount('#app');</script></body></html>`;
let server,browser;const results=[],errors=[];
async function check(name,fn){await fn();results.push({name,status:'PASS'});console.log('PASS '+name);}
(async()=>{const {createServer}=await import('vite');const vue=(await import('@vitejs/plugin-vue')).default;
const fixturePort=await new Promise((resolve,reject)=>{const probe=require('node:net').createServer();probe.once('error',reject);probe.listen(0,'127.0.0.1',()=>{const port=probe.address().port;probe.close(()=>resolve(port))})});
server=await createServer({configFile:false,root,cacheDir:path.join(out,'cache'),plugins:[{name:'message-edit',resolveId(id){if(id==='/__message-edit.vue')return fixtureId},load(id){if(id===fixtureId)return sfc},configureServer(s){s.middlewares.use(async(req,res,next)=>{if(req.url!=='/__message-edit')return next();res.setHeader('Content-Type','text/html;charset=utf-8');res.end(await s.transformIndexHtml(req.url,html))})}},vue()],optimizeDeps:{entries:[],include:['vue','pinia','element-plus','marked','dompurify'],noDiscovery:true},server:{host:'127.0.0.1',port:fixturePort,strictPort:true,hmr:false,watch:{ignored:['**/desktop-release/**','**/dist/**']}},logLevel:'error'});
await server.listen();browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
const page=await browser.newPage({viewport:{width:1100,height:950}});page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(180000);page.setDefaultNavigationTimeout(180000);
await page.goto('http://127.0.0.1:'+server.httpServer.address().port+'/__message-edit',{waitUntil:'domcontentloaded'});await page.locator('[data-id="u2"]').waitFor();
await check('message action icons reveal on hover and keyboard focus, with distinct assistant/user actions',async()=>{
 const user=page.locator('[data-id="u2"]'),assistant=page.locator('[data-id="a1"]');
 await page.mouse.move(0,0);assert.equal(await user.locator('.message-actions').evaluate(el=>getComputedStyle(el).opacity),'0');
 await user.hover();await page.waitForFunction(()=>getComputedStyle(document.querySelector('[data-id="u2"] .message-actions')).opacity==='1');
 assert.equal(await user.getByRole('button').count(),3);assert.equal(await assistant.getByRole('button').count(),2);
 await page.mouse.move(0,0);await user.getByRole('button',{name:'编辑消息',exact:true}).focus();
 assert.equal(await user.locator('.message-actions').evaluate(el=>getComputedStyle(el).pointerEvents),'auto');
 assert.notEqual(await user.locator('.message-quote-icon').evaluate(el=>getComputedStyle(el).maskImage),'none');
});
await check('copy menu supports raw Markdown and plain text; quoting retains the original source',async()=>{
 const assistant=page.locator('[data-id="a1"]');await assistant.hover();await assistant.getByRole('button',{name:'选择复制格式',exact:true}).click();
 await page.getByRole('menuitem',{name:'复制 Markdown',exact:true}).waitFor();
 await page.screenshot({path:path.join(out,'copy-format-menu.png'),fullPage:true});
 await page.getByRole('menuitem',{name:'复制 Markdown',exact:true}).click();
 assert.equal(await page.evaluate(()=>window.copiedMarkdown),'此前的 **Markdown** 回答');
 await assistant.getByRole('button',{name:'选择复制格式',exact:true}).click();
 const plain=page.getByRole('menuitem',{name:'复制无格式文本',exact:true});await plain.focus();await plain.press('Enter');
 assert.equal(await page.evaluate(()=>window.copiedMarkdown),'此前的 Markdown 回答');
 assert.equal(await page.evaluate(()=>window.editFixture.notices.at(-1).text),'已复制无格式文本');
 await page.screenshot({path:path.join(out,'copy-plain-text.png'),fullPage:true});
 await assistant.getByRole('button',{name:'引用消息',exact:true}).click();
 assert.equal(await page.evaluate(()=>window.editFixture.quotedMessage.value.id),'a1');
});
await check('plain text removes Markdown syntax and preserves paragraphs, tables, entities and code indentation',async()=>{
 const source='# 核查结果\n\n**正常** &amp; _需要复核_： [详情](https://example.test/a)\n\n- 第一项\n- 第二项\n\n| 项目 | 状态 |\n| --- | --- |\n| 日志 | 通过 |\n\n```python\n  if a < 2:\n    print("**保留代码**")\n```';
 await page.evaluate(async content=>{const f=window.editFixture;await f.copyMessage({id:'copy-fixture',content},'plain')},source);
 assert.equal(await page.evaluate(()=>window.copiedMarkdown),'核查结果\n\n正常 & 需要复核： 详情\n\n• 第一项\n• 第二项\n\n项目\t状态\n日志\t通过\n\n  if a < 2:\n    print("**保留代码**")');
 await page.evaluate(async content=>{const f=window.editFixture;await f.copyMessage({id:'copy-fixture',content},'markdown')},source);
 assert.equal(await page.evaluate(()=>window.copiedMarkdown),source);
});
await check('editing changes only the draft and cancel restores its text, quote and references',async()=>{
 await page.locator('[data-id="u2"]').hover();await page.locator('[data-id="u2"]').getByRole('button',{name:'编辑消息',exact:true}).click();
 assert.equal(await page.locator('textarea').inputValue(),'待编辑的 **原始 Markdown**');
 assert.equal(await page.evaluate(()=>JSON.stringify(window.editFixture.conversations.items[0])===window.editFixture.original),true);
 assert.match(await page.locator('.composer-edit-notice').innerText(),/原对话及后续消息保留/);
 const notice=await page.locator('.composer-edit-notice').evaluate(el=>({height:el.getBoundingClientRect().height,bg:getComputedStyle(el).backgroundColor,border:getComputedStyle(el).borderLeftWidth}));
 assert.ok(notice.height<=40,JSON.stringify(notice));assert.equal(notice.bg,'rgba(0, 0, 0, 0)');assert.equal(notice.border,'0px');
 await page.screenshot({path:path.join(out,'edit-bottom-composer.png'),fullPage:true});
 await page.locator('textarea').fill('未提交的编辑');await page.getByRole('button',{name:'取消编辑',exact:true}).click();
 assert.equal(await page.locator('textarea').inputValue(),'编辑前未发送的草稿');
 assert.equal(await page.evaluate(()=>window.editFixture.quotedMessage.value.id),'a1');
 assert.equal(await page.evaluate(()=>window.editFixture.activeDraft.value.refs[0].id),19);
 assert.equal(await page.evaluate(()=>window.editFixture.conversations.items.length),1);
});
await check('Escape cancels editing and IME Enter cannot accidentally send',async()=>{
 await page.locator('[data-id="u2"]').hover();await page.locator('[data-id="u2"]').getByRole('button',{name:'编辑消息',exact:true}).click();
 await page.evaluate(()=>window.editFixture.handlePromptKeydown(new KeyboardEvent('keydown',{key:'Enter',isComposing:true})));
 assert.equal(await page.evaluate(()=>window.editFixture.requests.length),0);
 await page.locator('textarea').press('Escape');assert.equal(await page.locator('textarea').inputValue(),'编辑前未发送的草稿');
});
await check('submit forks only earlier history, clears execution state, preserves source and issues a fresh turn',async()=>{
 await page.locator('[data-id="u2"]').hover();await page.locator('[data-id="u2"]').getByRole('button',{name:'编辑消息',exact:true}).click();
 await page.locator('textarea').fill('修改后的请求 **只给方案**');await page.evaluate(()=>{window.holdDispatch=true;void window.editFixture.sendPrompt();void window.editFixture.sendPrompt()});
 await page.waitForFunction(()=>window.editFixture.requests.length===1);
 const actual=await page.evaluate(()=>{const f=window.editFixture,b=f.selectedThread.value;return{sourceIntact:JSON.stringify(f.conversations.items.find(t=>t.id==='source'))===f.original,branch:JSON.parse(JSON.stringify(b)),request:f.requests[0],count:f.conversations.items.length}});
 assert.equal(actual.sourceIntact,true);assert.equal(actual.count,2);assert.notEqual(actual.branch.id,'source');assert.equal(actual.branch.targetId,9);assert.equal(actual.branch.projectId,7);
 assert.deepEqual(actual.branch.messages.slice(0,2).map(m=>m.content),['此前的问题','此前的 **Markdown** 回答']);
 for(const message of actual.branch.messages.slice(0,2)){assert.deepEqual(message.taskIds,[]);assert.deepEqual(message.steps,[]);for(const key of ['approvalId','approvalStatus','executionRequested','executionIntent','executionDecision','agentEvents','modelStreamStatus'])assert.equal(message[key],undefined,key);}
 assert.notEqual(actual.branch.messages[0].id,'u1');assert.notEqual(actual.branch.messages[1].id,'a1');assert.equal(actual.branch.messages[1].replyToId,actual.branch.messages[0].id);
 assert.equal(actual.request.sessionId,actual.branch.id);assert.notEqual(actual.request.turnId,'u2');assert.equal(actual.request.projectId,7);assert.deepEqual(actual.request.user.references,[{type:'finding',id:243,targetId:9}]);
 assert.equal(actual.request.user.copilotMode,'plan');assert.equal(actual.request.user.quote.messageId,'a1');assert.ok(!actual.request.context.includes('此后的'));assert.ok(!actual.request.context.includes('待编辑的'));assert.match(actual.request.context,/修改后的请求/);
 await page.evaluate(()=>{window.holdDispatch=false;window.releaseDispatch()});await page.waitForFunction(()=>!window.editFixture.sending.value);
 assert.equal(await page.locator('.composer-edit-notice').count(),0);
});
await check('branch history references are detached copies and invalid/storage-failed forks preserve all records',async()=>{
 const result=await page.evaluate(()=>{const f=window.editFixture,b=f.selectedThread.value;b.messages[0].references[0].data.nested.value='branch';const detached=f.conversations.items.find(t=>t.id==='source').messages[0].references[0].data.nested.value==='original';const before=JSON.stringify(f.conversations.items);let invalid=false,failed=false;try{f.conversations.forkBeforeMessage('source','a1','bad')}catch{invalid=true}const setter=Storage.prototype.setItem;Storage.prototype.setItem=()=>{throw new Error('quota')};try{f.conversations.forkBeforeMessage('source','u2','new')}catch{failed=true}finally{Storage.prototype.setItem=setter}return{detached,invalid,failed,intact:before===JSON.stringify(f.conversations.items)}});
 assert.deepEqual(result,{detached:true,invalid:true,failed:true,intact:true});
});
await check('narrow screens keep message actions visible with touch-sized controls',async()=>{
 await page.setViewportSize({width:520,height:900});await page.mouse.move(0,0);await page.locator('textarea').focus();
 await page.waitForFunction(()=>getComputedStyle(document.querySelector('.message-actions')).opacity==='1');
 const geometry=await page.locator('.message-actions').first().evaluate(el=>({opacity:getComputedStyle(el).opacity,width:el.querySelector('button').getBoundingClientRect().width,height:el.querySelector('button').getBoundingClientRect().height}));
 assert.equal(geometry.opacity,'1');assert.ok(geometry.width>=40&&geometry.height>=40,JSON.stringify(geometry));
 await page.screenshot({path:path.join(out,'actions-520.png'),fullPage:true});
});
await check('failed reply keeps real task state, hides long detail by default and connects edit/diagnostics/retry',async()=>{
 await page.setViewportSize({width:1100,height:950});
 await page.evaluate(()=>{const f=window.editFixture;f.route.query={conversation:'source'};f.tasks.value=[{id:303,targetId:9,toolCode:'tcp_ports',status:'RUNNING',progress:40,createdAt:new Date().toISOString(),startedAt:new Date().toISOString()}];f.conversations.appendMessage('source',{role:'assistant',content:'本轮没有执行检测；模型未返回有效回复，请检查配置。',status:'failed',replyToId:'u3',taskIds:[303],steps:[],modelStreamStatus:'failed'});});
 const failed=page.locator('.chat-message').filter({has:page.locator('.ai-failure-notice')});
 // The execution disclosure is collapsed by default, so read the recorded task
 // state from the disclosure's markup instead of its rendered text.
 assert.match(await failed.locator('.tool-state').evaluate(el=>el.textContent),/执行中/);
 assert.equal(await failed.locator('.progress-attention,.progress-activity').count(),0);
 assert.equal(await failed.locator('.failure-details > p').isVisible(),false);
 await failed.locator('.failure-details summary').focus();await page.keyboard.press('Enter');
 await page.waitForFunction(()=>document.querySelector('.failure-details > p')?.innerText.length>0);
 const detail=await failed.locator('.failure-details > p').innerText();assert.doesNotMatch(detail,/没有执行检测/);assert.match(detail,/已创建任务的状态请以任务中心为准/);
 await page.evaluate(()=>{const f=window.editFixture;const message=f.selectedThread.value.messages.at(-1);f.conversations.updateMessage('source',message.id,{content:'回答未通过检查，尚未提交审批申请，未创建检测任务，未执行任何检测。请重试。'});});
 assert.doesNotMatch(await failed.locator('.failure-details > p').innerText(),/尚未提交审批申请|未创建检测任务|未执行任何检测/);
 assert.equal(await failed.locator('.ai-failure-notice button').count(),0);
 assert.equal(await failed.getByRole('button',{name:/编辑/}).count(),0);
 const originalUser=page.locator('[data-id="u3"]');await originalUser.hover();await originalUser.getByRole('button',{name:'编辑消息',exact:true}).click();assert.equal(await page.locator('textarea').inputValue(),'此后的问题也不可带入');
 assert.equal(await page.locator('.thread-composer .composer-edit-notice').count(),1);await page.getByRole('button',{name:'取消编辑',exact:true}).click();
 await failed.getByRole('button',{name:'配置诊断',exact:true}).click();
 assert.deepEqual(await page.evaluate(()=>({route:window.pushedRoute,tab:window.editFixture.aiSettingsTab.value,open:window.editFixture.aiDialog.value})),{route:{path:'/settings',query:{ai:'diagnostics'}},tab:'diagnostics',open:true});
 await page.screenshot({path:path.join(out,'failure-recovery.png'),fullPage:true});
 const before=await page.evaluate(()=>window.editFixture.requests.length);
 await failed.getByRole('button',{name:'重新生成回复',exact:true}).click();
 await page.waitForFunction(()=>window.editFixture.answerRequests.length===1&&!window.editFixture.sending.value);
 assert.equal(await page.evaluate(()=>window.editFixture.requests.length),before);
 assert.deepEqual(await page.evaluate(()=>window.editFixture.answerRequests[0].taskIds),[303]);
 assert.equal(await page.evaluate(()=>window.editFixture.tasks.value[0].status),'RUNNING');
 assert.equal(await page.locator('.ai-failure-notice').count(),0);
});
await check('failure without tasks retries its original turn and unknown source offers no edit action',async()=>{
 await page.evaluate(()=>{const f=window.editFixture;f.conversations.appendMessage('source',{role:'assistant',content:'<think>private payload</think>',status:'failed',replyToId:'u3',taskIds:[],steps:[]});});
 const failed=page.locator('.chat-message').filter({has:page.locator('.ai-failure-notice')});await failed.locator('.failure-details summary').click();
 await page.waitForFunction(()=>document.querySelector('.failure-details > p')?.innerText.length>0);
 assert.doesNotMatch(await failed.innerText(),/private payload/);assert.match(await failed.locator('.failure-details > p').innerText(),/服务未返回可显示的错误说明/);
 const before=await page.evaluate(()=>window.editFixture.requests.length);await failed.getByRole('button',{name:'重试回复',exact:true}).click();
 await page.waitForFunction(count=>window.editFixture.requests.length===count+1&&!window.editFixture.sending.value,before);
 assert.deepEqual(await page.evaluate(()=>{const req=window.editFixture.requests.at(-1);return{session:req.sessionId,turn:req.turnId}}),{session:'source',turn:'u3'});
 await page.evaluate(()=>window.editFixture.conversations.appendMessage('source',{role:'assistant',content:'请求失败',status:'failed',replyToId:'missing',taskIds:[],steps:[]}));
 assert.equal(await page.locator('.ai-failure-notice').getByRole('button',{name:'编辑原问题',exact:true}).count(),0);
 assert.doesNotMatch(await page.locator('.ai-failure-notice > p').innerText(),/编辑原问题/);
 await page.evaluate(()=>{window.editFixture.sending.value=true});assert.equal(await failed.getByRole('button',{name:'重试回复',exact:true}).isDisabled(),true);assert.equal(await failed.getByRole('button',{name:'配置诊断',exact:true}).isDisabled(),true);await page.evaluate(()=>{window.editFixture.sending.value=false});
});
await check('18-second failure uses one bounded card with header, actions and footer in both themes',async()=>{
 await page.evaluate(()=>{const f=window.editFixture,message=f.selectedThread.value.messages.at(-1),now=Date.now();f.conversations.updateMessage('source',message.id,{replyToId:'u3',agentEvents:[{type:'progress',stage:'ASSESSED',source:'runtime-public-progress',eventTiming:'LIVE',assessmentSource:'MODEL',modelDecision:'FINALIZE',evidenceDecision:'FINALIZE',reasonCodes:['DIRECT_SUPPORT'],summary:'已有证据足以形成当前回复。',createdAt:new Date(now-2000).toISOString()}],content:'AI 生成的回答或检测方案未通过完整性与一致性检查，本轮已安全停止。请重试；如持续失败，请查看 AI 诊断记录。',progressStartedAt:new Date(now-18000).toISOString(),progressFinishedAt:new Date(now).toISOString(),createdAt:new Date(now-18000).toISOString(),updatedAt:new Date(now).toISOString(),modelStreamStatus:'failed'});});
 for(const theme of ['light','dark'])for(const width of [1100,460]){
  await page.setViewportSize({width,height:950});await page.evaluate(theme=>document.documentElement.dataset.systemTheme=theme,theme);
  const card=page.locator('.message-response.is-failed');await card.scrollIntoViewIfNeeded();
  const geometry=await card.evaluate(el=>{const c=getComputedStyle(el),r=el.getBoundingClientRect(),header=el.querySelector('.ai-progress-panel'),footer=el.nextElementSibling&&el.nextElementSibling.classList.contains('message-actions')?el.nextElementSibling:null;return{width:r.width,border:c.borderTopWidth,radius:c.borderTopLeftRadius,headerBorder:getComputedStyle(header).borderBottomWidth,footerBorder:footer?getComputedStyle(footer).borderTopWidth:'missing',actions:footer?[...footer.querySelectorAll('button')].map(button=>{const rect=button.getBoundingClientRect();return{label:button.getAttribute('aria-label'),top:rect.top,width:rect.width,height:rect.height}}):[],overflow:el.scrollWidth>el.clientWidth,footerVisible:footer?getComputedStyle(footer).opacity:'missing'}});
  assert.ok(geometry.width<=720&&geometry.width>250,JSON.stringify(geometry));assert.equal(geometry.border,'1px');assert.equal(geometry.radius,'8px');
  // The failure card is bounded by its own body plus the action bar that follows
  // it as the next sibling; the panel inside the card draws no border of its own.
  assert.equal(geometry.headerBorder,'0px',JSON.stringify(geometry));assert.equal(geometry.footerBorder,'1px',JSON.stringify(geometry));assert.equal(geometry.overflow,false);assert.equal(geometry.footerVisible,'1');
  assert.deepEqual(geometry.actions.map(action=>action.label).sort(),['引用消息','选择复制格式','重试回复','配置诊断'].sort());
  for(const action of geometry.actions){assert.ok(Math.abs(action.top-geometry.actions[0].top)<=1,JSON.stringify(geometry));assert.equal(action.width,geometry.actions[0].width);assert.equal(action.height,geometry.actions[0].height);if(width<640)assert.ok(action.width>=40&&action.height>=40);}
  assert.equal(await card.locator('.ai-failure-notice button,.failure-actions').count(),0);
  assert.equal(await card.locator('.failure-details > p').isVisible(),false);assert.match(await card.innerText(),/18 秒/);
  await card.screenshot({path:path.join(out,'failure-card-'+theme+'-'+width+'.png')});
  await card.locator('.failure-details summary').click();
  const detailGeometry=await card.locator('.failure-details > p').evaluate(el=>{const text=el.getBoundingClientRect(),available=el.parentElement.getBoundingClientRect();return{width:text.width,available:available.width,left:text.left-available.left,right:available.right-text.right,overflow:el.scrollWidth>el.clientWidth}});
  assert.ok(Math.abs(detailGeometry.left)<=1&&Math.abs(detailGeometry.right)<=1,JSON.stringify({theme,viewport:width,...detailGeometry}));assert.equal(detailGeometry.overflow,false);
  await card.screenshot({path:path.join(out,'failure-card-expanded-'+theme+'-'+width+'.png')});
  await card.locator('.failure-details summary').click();
 }
 await page.evaluate(()=>document.documentElement.dataset.systemTheme='light');
});
await check('source remains available when oldest among a full local history',async()=>{
 const actual=await page.evaluate(()=>{const f=window.editFixture,source=f.conversations.items.find(t=>t.id==='source');f.conversations.items=[...Array.from({length:29},(_,i)=>({...source,id:'other-'+i,messages:[]})),source];const branch=f.conversations.forkBeforeMessage('source','u1','新的开头');f.conversations.appendMessage(branch.id,{role:'user',content:'新的开头',status:'completed',taskIds:[],steps:[]});f.conversations.createThread(9,'授权目标','普通新对话',7);return{source:f.conversations.items.some(t=>t.id==='source'),branch:f.conversations.items.some(t=>t.id===branch.id),prefix:branch.messages.length,stored:JSON.parse(localStorage.getItem('security_toolbox_ai_conversations_v2')).some(t=>t.id==='source')}});
 assert.deepEqual(actual,{source:true,branch:true,prefix:1,stored:true});
});
assert.deepEqual(errors,[]);console.log('EVIDENCE '+out);
})().catch(error=>{results.push({status:'FAIL',error:error.stack});console.error(error);process.exitCode=1}).finally(async()=>{fs.writeFileSync(path.join(out,'results.json'),JSON.stringify({results,errors},null,2));await browser?.close();await server?.close()});

