/** Inspect the real packaged progress panel after live AI cases.
 * Uses DOM interactions and read-only computed layout. No synthetic events,
 * business API requests, authentication or persisted-message modifications.
 * Responsive viewports and media preferences are emulated, then restored.
 */
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {chromium}=require('playwright-core');
const {navigate,openSettings,selectOn,sleep}=require('./lib/ui.cjs');
const OUT=path.resolve(__dirname,'../../../.run/ai-fluent-exe',new Date().toISOString().replace(/[:.]/g,'-'));
fs.mkdirSync(OUT,{recursive:true});
const results=[];
function must(value,message){if(!value)throw Error(message);}
(async()=>{
  const browser=await chromium.connectOverCDP('http://127.0.0.1:19229');
  const page=browser.contexts().flatMap(c=>c.pages()).find(p=>p.url().includes('app.asar')&&!/startup.html|capture-browser.html/.test(p.url()));
  must(page,'没有真实EXE页面');page.setDefaultTimeout(15000);
  must(await page.locator('#desktop-v2-primary-navigation').isVisible(),'请先由用户完成登录');
  const originalViewport=page.viewportSize();
  let originalTheme;
  let selectedConversation;
  const assistant=()=>page.locator('article.chat-message.assistant').filter({has:page.locator('.message-bubble.markdown-body')}).last();
  const panel=()=>assistant().locator('.ai-progress-panel');
  const persist=()=>fs.writeFileSync(path.join(OUT,'results.json'),JSON.stringify({method:'Real packaged Vue panel; visible recent conversations; DOM keys/settings; emulated viewport/media',selectedConversation,results},null,2));
  async function openAnsweredConversation(){
    await navigate(page,'AI 安全助手');
    const recentToggle=page.locator('button[aria-controls="desktop-v2-recents-list"]');
    if(await recentToggle.getAttribute('aria-expanded')==='false')await recentToggle.click();
    const entries=page.locator('#desktop-v2-recents-list .desktop-v2-recent-open');
    const count=await entries.count();
    must(count>0,'可见最近会话列表为空，无法验收真实回答');
    for(let index=0;index<count;index++){
      const entry=entries.nth(index),title=(await entry.locator('strong').innerText()).trim();
      if(selectedConversation&&title!==selectedConversation.title)continue;
      await entry.scrollIntoViewIfNeeded();await entry.click();
      await page.locator('.chat-page.has-thread').waitFor({state:'visible'});
      for(let attempt=0;attempt<30&&(await page.locator('.chat-header > div > strong').first().innerText()).trim()!==title;attempt++)await sleep(100);
      must((await page.locator('.chat-header > div > strong').first().innerText()).trim()===title,'会话标题尚未完成切换');
      if(selectedConversation&&page.url()!==selectedConversation.url)continue;
      const answer=assistant().locator('.message-bubble.markdown-body');
      const ready=await panel().waitFor({state:'visible',timeout:15000}).then(()=>true,()=>false);
      if(ready&&await answer.count()&&(await answer.innerText()).trim()){
        const answerHash=createHash('sha256').update((await answer.innerText()).trim()).digest('hex');
        if(!selectedConversation)selectedConversation={title,url:page.url(),recentIndex:index,answerHash};
        else must(answerHash===selectedConversation.answerHash,'返回会话后真实回答内容发生变化');
        return;
      }
      if(selectedConversation)throw Error('已选会话的真实回答或过程面板消失');
    }
    throw Error(selectedConversation?'可见列表中无法重新打开同一会话':'最近会话中没有带过程面板的真实完成回答');
  }
  async function capture(id){await panel().scrollIntoViewIfNeeded();await page.screenshot({path:path.join(OUT,id+'.png'),fullPage:true,mask:[page.locator('input[type="password"]')]});}
  async function check(id,run){try{results.push({id,status:'PASS',...await run()});}catch(e){results.push({id,status:'FAIL',error:e.message});}persist();console.log(JSON.stringify(results.at(-1)));}
  async function theme(value){
    await openSettings(page);
    const row=page.locator('.settings-row').filter({has:page.locator('strong').filter({hasText:/^色彩主题$/})});
    if(!originalTheme)originalTheme=(await row.locator('.el-select__selected-item.el-select__placeholder').innerText()).trim();
    await selectOn(page,row.locator('.el-select'),value);
    await sleep(300);await openAnsweredConversation();
  }
  try{
    await openAnsweredConversation();
    persist();
    await check('structure',async()=>{
      must(await page.getByRole('switch',{name:'AI 执行模式'}).count()===0,'模式开关未移除');
      const p=panel(),toggle=p.locator('.progress-toggle');
      must(await toggle.getAttribute('aria-expanded')==='false','详细过程默认未折叠');
      must(await p.locator('.progress-milestones > li').count()<=5,'关键阶段超过5个');
      must(await p.locator('.progress-heading').getAttribute('role')==='status','缺少阶段读屏状态');
      must(await p.locator('.progress-heading').getAttribute('aria-live')==='polite','阶段播报不为polite');
      must(await p.locator('.progress-elapsed[aria-live]').count()===0,'秒表不应持续播报');
      const layout=await p.evaluate(e=>{const h=e.querySelector('.progress-heading strong'),s=getComputedStyle(h),box=getComputedStyle(e),answer=e.parentElement.querySelector('.message-bubble.markdown-body');return{title:h.textContent,font:s.fontFamily,fontSize:s.fontSize,lineHeight:s.lineHeight,width:e.clientWidth,scrollWidth:e.scrollWidth,height:e.getBoundingClientRect().height,background:box.backgroundColor,borders:[box.borderTopWidth,box.borderRightWidth,box.borderBottomWidth,box.borderLeftWidth],shadow:box.boxShadow,beforeAnswer:!!answer&&!!(e.compareDocumentPosition(answer)&Node.DOCUMENT_POSITION_FOLLOWING),toolCalls:e.querySelectorAll('.progress-tool-call').length,attention:!!e.querySelector('.progress-attention')};});
      must(layout.fontSize==='14px'&&layout.lineHeight==='20px','正文字号行高不符合14/20');
      must(layout.background==='rgba(0, 0, 0, 0)'&&layout.borders.every(x=>x==='0px')&&layout.shadow==='none','进度区仍带独立卡片背景/边框/阴影');
      must(layout.beforeAnswer,'处理状态未位于正式回答之前');
      must(!await p.locator('.progress-timeline-wrap').isVisible(),'折叠后的过程内容仍然可见');
      must(await p.locator('.progress-footer').count()===0,'轻量消息流不应有独立页脚');
      if(!layout.toolCalls&&!layout.attention)must(Math.abs(layout.height-44)<=1,'普通完成问答未保持44px状态行');
      await capture('normal-collapsed');return{layout,text:await p.innerText()};
    });
    await check('keyboard',async()=>{
      const toggle=panel().locator('.progress-toggle');
      if(await toggle.getAttribute('aria-expanded')==='true')await toggle.click();
      await toggle.focus();await page.keyboard.press('Enter');
      must(await toggle.getAttribute('aria-expanded')==='true','Enter未展开');
      const outline=await toggle.evaluate(e=>({focus:e===document.activeElement,style:getComputedStyle(e).outlineStyle,width:getComputedStyle(e).outlineWidth}));
      must(outline.focus&&outline.style!=='none'&&outline.width!=='0px','键盘焦点不可见');
      const timeline=panel().getByRole('list',{name:'完整公开阶段记录，可滚动查看'});
      let timelineCheck='NOT_OBSERVED: 当前真实回答没有已保存的公开阶段记录';
      if(await timeline.count()){
        must(await timeline.getAttribute('tabindex')==='0','长过程不可键盘访问');
        const tabLimit=await panel().locator('button,a[href],input,select,textarea,summary,[tabindex]:not([tabindex="-1"])').count()+2;
        for(let i=0;i<tabLimit;i++){await page.keyboard.press('Tab');if(await timeline.evaluate(e=>e===document.activeElement))break;}
        must(await timeline.evaluate(e=>e===document.activeElement),'Tab未进入完整过程');
        timelineCheck='PASS';
      }
      await capture('keyboard-expanded');await toggle.focus();await page.keyboard.press('Space');
      must(await toggle.getAttribute('aria-expanded')==='false','Space未收起');
      return{outline,timelineCheck};
    });
    for(const label of ['浅色模式','深色模式'])await check(label,async()=>{
      await theme(label);
      const expected=label==='浅色模式'?'light':'dark';
      for(let i=0;i<30&&await page.locator('html').getAttribute('data-system-theme')!==expected;i++)await sleep(100);
      must(await page.locator('html').getAttribute('data-system-theme')===expected,'实际主题未切换');
      await capture(label==='浅色模式'?'light':'dark');
      return{theme:expected,style:await panel().evaluate(e=>({foreground:getComputedStyle(e).color,background:getComputedStyle(e).backgroundColor}))};
    });
    await check('responsive-640',async()=>{
      await openAnsweredConversation();
      await page.setViewportSize({width:640,height:900});await sleep(300);
      const toggle=panel().locator('.progress-toggle');if(await toggle.getAttribute('aria-expanded')!=='true')await toggle.click();
      await panel().scrollIntoViewIfNeeded();
      const layout=await panel().evaluate(e=>({width:e.clientWidth,scrollWidth:e.scrollWidth,rect:e.getBoundingClientRect().toJSON(),viewport:innerWidth,container:e.closest('.chat-messages')?.getBoundingClientRect().toJSON(),toggle:e.querySelector('button').getBoundingClientRect().toJSON()}));
      must(layout.scrollWidth<=layout.width+1,'进度卡片水平溢出');
      must(layout.rect.left>=-1&&layout.rect.right<=layout.viewport+1,'进度区被窗口水平裁切');
      if(layout.container)must(layout.rect.left>=layout.container.left-1&&layout.rect.right<=layout.container.right+1,'进度区被聊天容器水平裁切');
      await capture('responsive-640-expanded');return{layout};
    });
    await check('forced-colors-reduced-motion',async()=>{
      await openAnsweredConversation();
      await page.emulateMedia({forcedColors:'active',reducedMotion:'reduce'});
      await panel().locator('.progress-toggle').focus();
      const style=await panel().evaluate(e=>({forced:matchMedia('(forced-colors: active)').matches,reduced:matchMedia('(prefers-reduced-motion: reduce)').matches,background:getComputedStyle(e).backgroundColor,outline:getComputedStyle(e.querySelector('button')).outlineColor,animations:[...e.querySelectorAll('.progress-spinner')].filter(x=>x.getBoundingClientRect().width>0).map(x=>getComputedStyle(x).animationName),icons:[...e.querySelectorAll('.fluent-system-icon')].filter(x=>x.getBoundingClientRect().width>0).map(x=>({width:x.getBoundingClientRect().width,color:getComputedStyle(x).backgroundColor}))}));
      must(style.forced&&style.reduced,'媒体模拟未生效');
      must(style.animations.every(a=>a==='none'),'减少动画下仍有spinner动画');
      must(style.icons.length&&style.icons.every(x=>x.width>0&&x.color!=='rgba(0, 0, 0, 0)'),'强制色下图标不可见');
      await capture('forced-colors-reduced-motion');return{style,animationCheck:style.animations.length?'PASS':'NOT_OBSERVED: 当前消息无运行中spinner'};
    });
  }catch(e){
    results.push({id:'setup-or-run',status:'FAIL',error:e.message,stack:e.stack});persist();console.error(e);
    await page.screenshot({path:path.join(OUT,'failure.png'),fullPage:true,mask:[page.locator('input[type="password"]')]}).catch(()=>{});
  }finally{
    // Each restoration is independent; an absent panel must not hide the original error.
    async function restore(id,run){try{await run();}catch(e){results.push({id:'restore-'+id,status:'FAIL',error:e.message});console.error('restore-'+id+': '+e.message);}persist();}
    await restore('media',()=>page.emulateMedia({forcedColors:null,reducedMotion:null}));
    await restore('viewport',async()=>{
      if(originalViewport)await page.setViewportSize(originalViewport);
      else {const cdp=await page.context().newCDPSession(page);try{await cdp.send('Emulation.clearDeviceMetricsOverride');}finally{await cdp.detach();}}
    });
    if(originalTheme)await restore('theme',()=>theme(originalTheme));
    await restore('disclosure',async()=>{
      const toggle=panel().locator('.progress-toggle');
      if(await toggle.count()&&await toggle.isVisible()&&await toggle.getAttribute('aria-expanded')==='true')await toggle.click();
    });
  }
  console.log('COMPLETE '+OUT);process.exit(results.some(r=>r.status==='FAIL')?1:0);
})().catch(e=>{
  results.push({id:'connect-or-initialize',status:'FAIL',error:e.message,stack:e.stack});
  fs.writeFileSync(path.join(OUT,'results.json'),JSON.stringify({method:'Real packaged UI; initialization did not complete',results},null,2));
  console.error(e);console.error('EVIDENCE '+OUT);process.exit(2);
});
