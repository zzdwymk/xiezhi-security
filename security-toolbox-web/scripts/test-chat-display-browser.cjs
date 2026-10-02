// Isolated rendering of the actual App/Dashboard template fragments and helpers.
// No live desktop session, business API or stored conversation is accessed.
const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');
const {parse}=require('@vue/compiler-sfc');const {baseParse}=require('@vue/compiler-dom');const ts=require('typescript');
const {chromium}=require('playwright-core');const root=path.resolve(__dirname,'..');
const out=path.resolve(root,'../.run/chat-display',new Date().toISOString().replace(/[:.]/g,'-'));fs.mkdirSync(out,{recursive:true});
const fixtureId=path.join(root,'__chat-display.vue').replace(/\\/g,'/');
function read(name){return parse(fs.readFileSync(path.join(root,'src',name),'utf8')).descriptor;}
function fragment(descriptor,className){
  const walk=node=>{if(node.type===1&&node.props.some(p=>p.type===6&&p.name==='class'&&p.value?.content===className))return node.loc.source;for(const child of node.children||[]){const found=walk(child);if(found)return found;}};
  const result=walk(baseParse(descriptor.template.content));assert.ok(result,'Missing actual template '+className);return result;
}
const app=read('App.vue'),dashboard=read('views/Dashboard.vue');
const ast=ts.createSourceFile('Dashboard.ts',dashboard.scriptSetup.content,ts.ScriptTarget.Latest,true);
const display=ast.statements.find(n=>ts.isFunctionDeclaration(n)&&n.name?.text==='displayedMessageContent');
const displayCode=ts.transpileModule(display.getText(ast),{compilerOptions:{target:ts.ScriptTarget.ES2020}}).outputText;
const vue=`<script setup>
import {reactive} from 'vue';import {ChatDotRound,Delete} from '/src/components/fluentIcons';
import {renderMarkdown} from '/src/utils/markdown';import {displayKnownTestName,displayConversationTitle,localizeAiToolCodes,copilotReferenceTypeLabel,aiProgressFailureText,localizeAiRuntimeFailure} from '/src/utils/aiPresentation';
const legacy='AI本机HTTP夹具-2026-10-01T12-38-32-728Z';
const conversations=reactive({recent:[{id:'recent',title:'使用 fscan_scan 检查本机目标',targetName:legacy,messages:[]}],taskIds:()=>[]});const route={query:{}};window.conversationFixture=conversations;
const openConversation=()=>{},removeConversation=()=>{};
const message=reactive({id:'message',role:'assistant',status:'completed',content:'',taskIds:[],refs:[{type:'target',title:legacy,id:298}]});
const genericReferences=message=>message.refs;window.chatFixture=message;
${displayCode}
</script><template><main><section class="desktop-v2-app-frame" style="display:block;position:relative;width:280px;min-height:0;height:auto"><section class="desktop-v2-recents" style="display:block">${fragment(app,'desktop-v2-recent-item')}</section></section>
<section class="test-message">${fragment(dashboard,'message-bubble markdown-body')}${fragment(dashboard,'message-bubble')}${fragment(dashboard,'copilot-reference-card')}</section></main></template>`;
const html=`<!doctype html><html lang="zh-CN" data-system-theme="light" data-window-material="none"><head><meta charset="utf-8"><style>html,body{height:auto!important;overflow:auto!important}body{margin:24px!important}.test-message{max-width:700px;margin-top:32px}.copilot-reference-card{padding:12px;border:1px solid #ddd}.copilot-reference-card code{margin-left:12px}</style></head><body><div id="fixture"></div><script type="module">
import {createApp} from 'vue';import ElementPlus from 'element-plus';import 'element-plus/dist/index.css';
import '/src/desktop-v2.css';import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';import '/src/motion.css';import Fixture from '/__chat-display.vue';createApp(Fixture).use(ElementPlus).mount('#fixture');
</script></body></html>`;
let browser,server;const results=[],errors=[];
async function check(name,fn){await fn();results.push({name,status:'PASS'});console.log('PASS '+name);}
(async()=>{const {createServer}=await import('vite');const pluginVue=(await import('@vitejs/plugin-vue')).default;
server=await createServer({configFile:false,root,cacheDir:path.join(out,'cache'),plugins:[{name:'chat-fragments',resolveId(id){if(id==='/__chat-display.vue')return fixtureId;},load(id){if(id===fixtureId)return vue;},configureServer(s){s.middlewares.use(async(req,res,next)=>{if(req.url!=='/__chat-display')return next();res.setHeader('Content-Type','text/html; charset=utf-8');res.end(await s.transformIndexHtml(req.url,html));});}},pluginVue()],server:{host:'127.0.0.1',port:0,hmr:false,watch:{ignored:['**/desktop-release/**','**/dist/**']}},logLevel:'error'});
await server.listen();browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
const page=await browser.newPage({viewport:{width:1000,height:650}});page.on('pageerror',e=>errors.push(e.message));
await page.goto('http://127.0.0.1:'+server.httpServer.address().port+'/__chat-display');await page.locator('.desktop-v2-recent-item').waitFor();
await check('recent delete glyph is centered horizontally and vertically with all production CSS',async()=>{
 const button=page.getByRole('button',{name:'删除对话',exact:true});await page.locator('.desktop-v2-recent-item').hover();await button.hover();
 const geometry=await button.evaluate(el=>{const rect=e=>{const r=e.getBoundingClientRect();return{x:r.x,y:r.y,width:r.width,height:r.height}};return{button:rect(el),icon:rect(el.querySelector('.el-icon')),glyph:rect(el.querySelector('.fluent-system-icon')),padding:getComputedStyle(el).padding};});
 for(const rect of [geometry.icon,geometry.glyph]){assert.ok(Math.abs(rect.x+rect.width/2-(geometry.button.x+geometry.button.width/2))<=0.5,JSON.stringify(geometry));assert.ok(Math.abs(rect.y+rect.height/2-(geometry.button.y+geometry.button.height/2))<=0.5,JSON.stringify(geometry));}
 assert.equal(geometry.padding,'0px');results.push({name:'delete-button-geometry',geometry});await page.screenshot({path:path.join(out,'delete-centered.png'),fullPage:true});
});
await check('legacy names display Beijing time and the actual reference card shows Chinese type',async()=>{
 assert.equal(await page.locator('.desktop-v2-recent-item strong').innerText(),'使用 fscan 主机扫描 检查本机目标');
 assert.equal(await page.evaluate(()=>window.conversationFixture.recent[0].title),'使用 fscan_scan 检查本机目标');
 assert.match(await page.locator('.desktop-v2-recent-item small').textContent(),/2026-10-01 20:38:32/);
 assert.match(await page.locator('.copilot-reference-card').innerText(),/AI 本机 HTTP 测试目标 · 2026-10-01 20:38:32/);
 assert.equal(await page.locator('.copilot-reference-card header code').innerText(),'授权目标');
 assert.equal(await page.evaluate(()=>window.chatFixture.refs[0].title),'AI本机HTTP夹具-2026-10-01T12-38-32-728Z');
});
const content='使用 fscan_scan 检查；**nmap_service_scan** 用于识别。\n\n`fscan_scan --ports 18888`\n\n```json\n{"tool":"fscan_scan","vulnMode":"SAFE"}\n```\n\nhttps://example.test/fscan_scan';
await check('legacy title truncated inside a tool code is rebuilt from its exact first user prompt',async()=>{
 const prompt='请执行当前项目133目标298的唯一一项fscan_scan';
 const stored=prompt.slice(0,28)+'…';
 await page.evaluate(({prompt,stored})=>{const thread=window.conversationFixture.recent[0];thread.title=stored;thread.messages=[{role:'user',content:prompt}];},{prompt,stored});
 const title=await page.locator('.desktop-v2-recent-item strong').innerText();
 assert.equal(title,('请执行当前项目133目标298的唯一一项fscan 主机扫描').slice(0,28)+'…');
 assert.ok(!title.includes('fscan_sc'));
 assert.deepEqual(await page.evaluate(()=>({title:window.conversationFixture.recent[0].title,prompt:window.conversationFixture.recent[0].messages[0].content})),{title:stored,prompt});
 await page.screenshot({path:path.join(out,'legacy-title-localized.png'),fullPage:true});
});
await check('actual assistant message translates prose while code and URL evidence stay exact',async()=>{
 await page.evaluate(content=>{window.chatFixture.content=content;window.chatFixture.role='assistant';},content);
 const bubble=page.locator('.message-bubble');await bubble.locator('pre code').waitFor();
 assert.match(await bubble.innerText(),/fscan 主机扫描/);assert.equal(await bubble.locator('strong').innerText(),'Nmap 服务识别');
 assert.equal((await bubble.locator('pre code').innerText()).trim(),'{"tool":"fscan_scan","vulnMode":"SAFE"}');
 assert.equal(await bubble.locator('p code').innerText(),'fscan_scan --ports 18888');assert.equal(await bubble.locator('a').getAttribute('href'),'https://example.test/fscan_scan');
 assert.equal(await page.evaluate(()=>window.chatFixture.content),content);
});
await check('actual user bubble preserves original input and cache modes cannot bleed',async()=>{
 await page.evaluate(()=>window.chatFixture.role='user');assert.equal(await page.locator('.message-bubble').textContent(),content);
 const modes=await page.evaluate(async()=>{const {renderMarkdown}=await import('/src/utils/markdown.ts');return[renderMarkdown('fscan_scan'),renderMarkdown('fscan_scan',{localizeToolCodes:true}),renderMarkdown('fscan_scan')];});
 assert.match(modes[0],/fscan_scan/);assert.match(modes[1],/fscan 主机扫描/);assert.equal(modes[0],modes[2]);
 await page.screenshot({path:path.join(out,'references-and-original-input.png'),fullPage:true});
});
assert.deepEqual(errors,[]);console.log('EVIDENCE '+out);
})().catch(e=>{results.push({status:'FAIL',error:e.stack});console.error(e);process.exitCode=1;}).finally(async()=>{fs.writeFileSync(path.join(out,'results.json'),JSON.stringify({results,errors},null,2));await browser?.close();await server?.close();});
