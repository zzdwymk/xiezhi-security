// Actual Vue preview, avatars and production theme in an isolated local fixture.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { parse, compileStyle } = require('@vue/compiler-sfc');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../.run/composer-preview', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(out, { recursive: true });
const dashboard = parse(fs.readFileSync(path.join(root, 'src/views/Dashboard.vue'), 'utf8')).descriptor;
const dashboardCss = dashboard.styles.map(style => compileStyle({ source:style.content, id:'data-v-fixture', scoped:true }).code).join('\n');
const html = `<!doctype html><html lang="zh-CN" data-system-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${dashboardCss}</style><style>html,body{height:auto!important;overflow:auto!important;min-width:0!important;width:auto!important}body{margin:12px!important}main{max-width:960px;height:calc(100vh - 24px)}.desktop-v2-content{height:100%;width:100%}.fixture-panel:not(.chat-welcome){width:100%}textarea{box-sizing:border-box}.avatars{display:flex;gap:12px}</style></head><body class="desktop-v2-native-frame"><div id="fixture"></div><script type="module">
import {createApp,h,ref} from 'vue'; import Preview from '/src/components/MarkdownComposerPreview.vue'; import Avatar from '/src/components/ConversationAvatar.vue'; import '/src/unified-theme.css';import '/src/fluent-design-2.css';import '/src/fluent-design-3.css';
const scoped=(tag,props,children)=>h(tag,{'data-v-fixture':'',...props},children);
createApp({setup(){const text=ref('');return ()=>scoped('main',{class:'desktop-v2-app-frame'},[scoped('div',{class:'desktop-v2-content'},[scoped('div',{class:'chat-page'},[h('div',{class:'avatars'},[h(Avatar,{role:'user'}),h(Avatar,{role:'assistant'})]),scoped('section',{class:'fixture-panel'},[scoped('div',{class:'thread-composer'},[scoped('div',{class:'composer-quote'},'引用内容'),scoped('textarea',{'aria-label':'编辑消息',value:text.value,onInput:e=>text.value=e.target.value}),h(Preview,{content:text.value,'data-v-fixture':''}),scoped('div',{class:'thread-composer-footer'},[h('button',{type:'button'},'发送')])])])])])]);}}).mount('#fixture');
</script></body></html>`;
let server, browser; const results = [], errors = [];
async function check(name, run) { await run(); results.push({ name, status:'PASS' }); console.log('PASS ' + name); }
(async () => {
  const { createServer } = await import('vite'); const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({ configFile:false, root, cacheDir:path.join(out,'cache'), plugins:[vue(), { name:'preview-fixture', configureServer(s) { s.middlewares.use(async (req,res,next) => {
    if(req.url!=='/__preview') return next(); res.setHeader('Content-Type','text/html'); res.end(await s.transformIndexHtml(req.url,html));
  }); }}], server:{host:'127.0.0.1',port:0,hmr:false,watch:{ignored:['**/desktop-release/**','**/dist/**']}},logLevel:'error' });
  await server.listen(); browser = await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
  const page = await browser.newPage({ viewport:{width:1000,height:800} }); page.on('pageerror',e=>errors.push(e.message));
  await page.goto('http://127.0.0.1:'+server.httpServer.address().port+'/__preview');
  // Dashboard loads after its imported preview component in the production bundle.
  await page.addStyleTag({content:dashboardCss});
  const input=page.getByRole('textbox',{name:'编辑消息'}), preview=page.locator('.composer-preview-body');
  async function assertToggle(expanded, wide) {
    const label=expanded?'收起实时预览':'展开实时预览';
    const toggle=page.getByRole('button',{name:label,exact:true});
    assert.equal(await toggle.getAttribute('title'),label);
    assert.equal(await toggle.getAttribute('aria-expanded'),String(expanded));
    const icon=await toggle.locator('.fluent-system-icon').evaluate(el=>({transform:getComputedStyle(el).transform,mask:getComputedStyle(el).getPropertyValue('--fluent-icon-mask')}));
    assert.equal(icon.transform,wide?'matrix(0, 1, -1, 0, 0, 0)':'none','Chevron direction must match the actual layout');
    const encoded=icon.mask.match(/data:image\/svg\+xml(?:;base64)?,([^"]+)/);
    const svg=encoded ? (icon.mask.includes(';base64,')?Buffer.from(encoded[1],'base64').toString('utf8'):decodeURIComponent(encoded[1])) : icon.mask;
    const name=expanded?'chevron_up_24_regular.svg':'chevron_down_24_regular.svg';
    const expectedSvg=fs.readFileSync(require.resolve('@fluentui/svg-icons/icons/'+name),'utf8');
    assert.ok(svg.includes(expectedSvg.match(/\bd="([^"]+)"/)[1]) || icon.mask.includes(name),'Chevron must use the matching expand/collapse glyph: '+icon.mask);
  }
  const markdown='## 预览标题\n\n**fscan_scan**\n\n- 一\n- 二\n\n| 字段 | 状态 |\n| --- | --- |\n| 原文 | ACTIVE |\n\n```json\n{"tool":"fscan_scan"}\n```';
  await check('input edits immediately render safe Markdown without changing source or focus',async()=>{
    assert.equal(await page.locator('.composer-preview').count(),0);
    await input.fill(markdown); await preview.locator('h2').waitFor();
    assert.equal(await preview.locator('h2').innerText(),'预览标题');
    assert.equal(await preview.locator('strong').innerText(),'fscan_scan');
    assert.equal(await preview.locator('li').count(),2); assert.equal(await preview.locator('table').count(),1);
    assert.equal((await preview.locator('pre code').innerText()).trim(),'{"tool":"fscan_scan"}');
    assert.equal(await input.inputValue(),markdown); assert.equal(await input.evaluate(el=>el===document.activeElement),true);
    await input.fill('### 实时更新\n\n*新的内容*'); await preview.locator('h3').waitFor();
    assert.equal(await preview.locator('table').count(),0); assert.equal(await preview.locator('em').innerText(),'新的内容');
  });
  await check('wide composers show editor left and preview right with full-width quote and footer',async()=>{
    await input.fill(markdown);
    for(const composerClass of ['thread-composer','welcome-composer']) {
      await page.locator('.fixture-panel').evaluate((el,name)=>el.className='fixture-panel'+(name==='welcome-composer'?' chat-welcome':''),composerClass);
      await page.locator('.thread-composer,.welcome-composer').evaluate((el,name)=>el.className=name,composerClass);
      const editorBox=await input.boundingBox(),previewBox=await page.locator('.composer-preview').boundingBox();
      const quoteBox=await page.locator('.composer-quote').boundingBox(),footerBox=await page.locator('.thread-composer-footer').boundingBox();
      assert.ok(editorBox.x+editorBox.width<=previewBox.x+1,JSON.stringify({editorBox,previewBox}));
      assert.ok(Math.abs(editorBox.y-previewBox.y)<=9,JSON.stringify({editorBox,previewBox}));
      assert.ok(editorBox.height>=previewBox.height,'Editor must fill the preview row, without the old 130px cap');
      assert.ok(quoteBox.y+quoteBox.height<=editorBox.y+1); assert.ok(footerBox.y>=previewBox.y+previewBox.height);
      assert.ok(quoteBox.width>editorBox.width*1.8 && footerBox.width>editorBox.width*1.8);
      await assertToggle(true,true);
      await page.screenshot({path:path.join(out,composerClass+'-wide.png'),fullPage:true});
    }
    await page.locator('.welcome-composer').evaluate(el=>el.className='thread-composer');
    await page.locator('.fixture-panel').evaluate(el=>el.className='fixture-panel');
    await page.locator('main').evaluate(el=>el.style.maxWidth='420px');
    const narrowInput=await input.boundingBox(),narrowPreview=await page.locator('.composer-preview').boundingBox();
    assert.ok(narrowPreview.y>=narrowInput.y+narrowInput.height); // Wide window, narrow actual composer.
    await assertToggle(true,false);
    await page.locator('main').evaluate(el=>el.style.maxWidth='');
    await input.fill('### 实时更新\n\n*新的内容*');
  });
  await check('long editor content reaches the last line without a clipped lower half',async()=>{
    const long=Array.from({length:45},(_,i)=>'第 '+i+' 行内容').join('\n')+'\n最后一行';
    await input.fill(long);
    for(const composerClass of ['thread-composer','welcome-composer']) {
    await page.locator('.fixture-panel').evaluate((el,name)=>el.className='fixture-panel'+(name==='welcome-composer'?' chat-welcome':''),composerClass);
    await page.locator('.thread-composer,.welcome-composer').evaluate((el,name)=>el.className=name,composerClass);
    const editorBox=await input.boundingBox(),previewBox=await page.locator('.composer-preview').boundingBox();
    assert.ok(editorBox.height>=previewBox.height);
    assert.equal(await input.evaluate(el=>getComputedStyle(el).maxHeight),'none');
    await input.press('Control+Home'); await input.press('Control+End');
    const state=await input.evaluate(el=>({source:el.value,caret:el.selectionStart,top:el.scrollTop,height:el.clientHeight,total:el.scrollHeight,paddingBottom:parseFloat(getComputedStyle(el).paddingBottom)}));
    assert.equal(state.source,long);assert.equal(state.caret,long.length);
    assert.ok(state.top+state.height>=state.total-state.paddingBottom-3,'Last line must be scrollable into view: '+JSON.stringify({composerClass,...state}));
    await page.screenshot({path:path.join(out,composerClass+'-long-editor-bottom.png'),fullPage:true});
    }
    await page.locator('.welcome-composer').evaluate(el=>el.className='thread-composer');
    await page.locator('.fixture-panel').evaluate(el=>el.className='fixture-panel');
    await input.fill('### 实时更新\n\n*新的内容*');
  });
  await check('preview collapses without losing input and hides after clearing',async()=>{
    const toggle=page.locator('.composer-preview-toggle'); await assertToggle(true,true); await toggle.click();
    assert.equal(await toggle.getAttribute('aria-expanded'),'false'); assert.equal(await preview.isVisible(),false);
    await assertToggle(false,true);
    const inputBox=await input.boundingBox(),composerBox=await page.locator('.thread-composer').boundingBox(),toggleBox=await toggle.boundingBox();
    assert.ok(inputBox.width>composerBox.width*0.7,'Collapsed preview gives its space back to the editor');
    assert.ok(toggleBox.x>=inputBox.x+inputBox.width,'Collapsed preview control stays on the right');
    assert.ok(Math.abs(toggleBox.y-inputBox.y)<20,'Collapsing must not create a new row');
    assert.equal(await input.inputValue(),'### 实时更新\n\n*新的内容*'); await toggle.click();
    await input.fill(''); assert.equal(await page.locator('.composer-preview').count(),0);
  });
  await check('incomplete Markdown and hostile markup remain editable and cannot execute',async()=>{
    await input.fill('```json\n{"incomplete":'); await preview.locator('pre code').waitFor();
    assert.ok((await preview.innerText()).includes('incomplete'));
    const hostile='<script>window.previewAttack=1</script><img src=x onerror="window.previewAttack=2">\n\n[unsafe](javascript:alert(1))';
    await input.fill(hostile); await page.waitForTimeout(30);
    assert.equal(await preview.locator('script,img,iframe,[onerror],[onclick]').count(),0);
    assert.equal(await preview.locator('a[href^="javascript:"]').count(),0);
    assert.equal(await page.evaluate(()=>window.previewAttack),undefined); assert.equal(await input.inputValue(),hostile);
  });
  await check('user and assistant avatars share an identical circular frame',async()=>{
    const shapes=await page.locator('.conversation-avatar').evaluateAll(els=>els.map(el=>({radius:getComputedStyle(el).borderRadius,width:el.getBoundingClientRect().width,height:el.getBoundingClientRect().height})));
    assert.equal(shapes.length,2); assert.deepEqual(shapes[0],shapes[1]); assert.equal(shapes[0].radius,'50%'); assert.equal(shapes[0].width,shapes[0].height);
  });
  await check('preview scrolls and leaves send reachable at narrow sizes in light and dark themes',async()=>{
    for(const theme of ['light','dark']) {
      await page.emulateMedia({colorScheme:theme}); await page.evaluate(t=>document.documentElement.dataset.systemTheme=t,theme);
      await page.setViewportSize({width:360,height:640}); await input.fill(markdown+'\n\n'+Array.from({length:30},(_,i)=>'- 行'+i).join('\n'));
      await preview.locator('li').first().waitFor();
      await assertToggle(true,false);
      await page.getByRole('button',{name:'收起实时预览',exact:true}).click();
      await assertToggle(false,false);
      await page.getByRole('button',{name:'展开实时预览',exact:true}).click();
      const size=await preview.evaluate(el=>({height:el.clientHeight,scroll:el.scrollHeight}));
      assert.ok(size.scroll>size.height); assert.ok(size.height<=190);
      const widths=await page.evaluate(()=>({document:document.documentElement.scrollWidth,viewport:innerWidth,body:document.body.getBoundingClientRect().width})); assert.ok(widths.document<=widths.viewport,JSON.stringify(widths));
      await page.getByRole('button',{name:'发送',exact:true}).scrollIntoViewIfNeeded();
      await page.screenshot({path:path.join(out,theme+'-preview.png'),fullPage:true});
    }
  });
  assert.deepEqual(errors,[]); console.log(`${results.length} composer preview checks passed. ${out}`);
})().catch(e=>{console.error(e);errors.push(String(e));process.exitCode=1;}).finally(async()=>{fs.writeFileSync(path.join(out,'results.json'),JSON.stringify({results,errors},null,2));await browser?.close();await server?.close();});

