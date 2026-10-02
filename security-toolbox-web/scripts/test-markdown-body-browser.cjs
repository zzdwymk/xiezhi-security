// Runs the real Vue component in an isolated browser, without desktop sessions or APIs.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '../.run/markdown-body', new Date().toISOString().replace(/[:.]/g, '-'));
fs.mkdirSync(output, { recursive: true });
const fixture = `<!doctype html><html><head><meta charset="utf-8"></head><body><main style="width:280px"><div id="fixture"></div></main><script type="module">
import {createApp,h,reactive} from 'vue';
import MarkdownBody from '/src/components/MarkdownBody.vue';
import '/src/unified-theme.css';
window.fixture = reactive({content:''});
createApp({setup:()=>()=>h(MarkdownBody,{content:window.fixture.content})}).mount('#fixture');
</script></body></html>`;
let server, browser;
(async () => {
  const {createServer} = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({configFile:false,root,cacheDir:path.join(output,'vite-cache'),plugins:[vue(),{
    name:'isolated-markdown-fixture',configureServer(instance){
      instance.middlewares.use(async(req,res,next)=>{
        if(req.url!=='/__markdown-fixture') return next();
        res.setHeader('Content-Type','text/html; charset=utf-8');
        res.end(await instance.transformIndexHtml(req.url,fixture));
      });
    }
  }],optimizeDeps:{entries:[],include:['vue','marked','dompurify'],noDiscovery:true},server:{host:'127.0.0.1',port:0,hmr:false,watch:{ignored:['**/desktop-release/**','**/dist/**']}},logLevel:'error'});
  await server.listen();
  browser = await chromium.launch({executablePath:process.env.AI_PROGRESS_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
  const page = await browser.newPage({viewport:{width:320,height:800}});
  const errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__markdown-fixture`);
  await page.locator('.markdown-body').waitFor({state:'attached'});
  const code='const value = "'+'x'.repeat(160)+'";';
  const markdown=['# 标题','正文 **重点**','- 第一项','- 第二项','| 列一 | 列二 |','| --- | --- |','| 数据 | 值 |','```js',code,'```','[安全链接](https://example.test)'].join('\n\n').replace('| 列一 | 列二 |\n\n| --- | --- |\n\n| 数据 | 值 |','| 列一 | 列二 |\n| --- | --- |\n| 数据 | 值 |');
  await page.evaluate(content=>{window.fixture.content=content;},markdown);
  await page.locator('h1').waitFor();
  assert.equal(await page.locator('h1').innerText(),'标题');
  assert.equal(await page.locator('strong').innerText(),'重点');
  assert.equal(await page.locator('li').count(),2);
  assert.equal(await page.locator('table td').count(),2);
  assert.equal((await page.locator('pre code').textContent()).trim(),code);
  assert.equal(await page.locator('a').getAttribute('target'),'_blank');
  assert.equal(await page.locator('a').getAttribute('rel'),'noopener noreferrer');
  const layout=await page.locator('.markdown-body').evaluate(el=>({font:getComputedStyle(el).fontSize,width:el.getBoundingClientRect().width,codeOverflow:getComputedStyle(el.querySelector('pre')).overflowX,tableOverflow:getComputedStyle(el.querySelector('table')).overflowX,codeScroll:el.querySelector('pre').scrollWidth>el.querySelector('pre').clientWidth,documentWidth:document.documentElement.scrollWidth}));
  assert.equal(layout.font,'14px'); assert.equal(layout.codeOverflow,'auto'); assert.equal(layout.tableOverflow,'auto'); assert.equal(layout.codeScroll,true); assert.ok(layout.documentWidth<=320,JSON.stringify(layout));
  await page.screenshot({path:path.join(output,'markdown-320.png'),fullPage:true});
  console.log('PASS real headings, emphasis, lists, table, fenced code, links and narrow layout');
  const linkCases=[
    {name:'real assistant response without a space before Chinese prose',content:'历史证据显示该工具已成功获取http://192.168.136.132的响应头。建议改用http_headers节点执行。',hrefs:['http://192.168.136.132'],labels:['http://192.168.136.132'],plain:'的响应头。建议改用http_headers节点执行。'},
    {name:'Chinese comma and full stop',content:'目标为http://192.168.136.132，扫描尚未完成。',hrefs:['http://192.168.136.132'],labels:['http://192.168.136.132'],plain:'，扫描尚未完成。'},
    {name:'fullwidth parentheses',content:'http://192.168.136.132（仅授权目标）',hrefs:['http://192.168.136.132'],labels:['http://192.168.136.132'],plain:'（仅授权目标）'},
    {name:'bare www and adjacent Chinese',content:'普通文本：www.example.com后面的文字。',hrefs:['http://www.example.com'],labels:['www.example.com'],plain:'后面的文字。'},
    {name:'remaining prose continues normal Markdown parsing',content:'访问https://example.com/path。然后查看**真实结果**。',hrefs:['https://example.com/path'],labels:['https://example.com/path'],plain:'。然后查看',strong:'真实结果'},
    {name:'explicit Unicode links retain their full destinations',content:'[中文页面](https://example.com/中文页面) <https://example.com/中文路径>',hrefs:['https://example.com/%E4%B8%AD%E6%96%87%E9%A1%B5%E9%9D%A2','https://example.com/%E4%B8%AD%E6%96%87%E8%B7%AF%E5%BE%84'],labels:['中文页面','https://example.com/中文路径']},
    {name:'ASCII URL query and percent encoded paths stay complete',content:'https://example.com/%E4%B8%AD%E6%96%87?q=a%20b&n=2，完成。',hrefs:['https://example.com/%E4%B8%AD%E6%96%87?q=a%20b&n=2'],labels:['https://example.com/%E4%B8%AD%E6%96%87?q=a%20b&n=2'],plain:'，完成。'},
    {name:'inline and fenced code remain unlinked',content:'`http://192.168.136.132的响应头`\n\n```text\nhttps://example.com，普通文字\n```',hrefs:[],labels:[]},
  ];
  const linkResults=[];
  for(const item of linkCases){
    await page.evaluate(async content=>{window.fixture.content=content;await new Promise(requestAnimationFrame);},item.content);
    const actual=await page.locator('.markdown-body').evaluate(element=>({
      hrefs:[...element.querySelectorAll('a')].map(anchor=>anchor.getAttribute('href')),
      labels:[...element.querySelectorAll('a')].map(anchor=>anchor.textContent),
      text:element.textContent,
      plain:[...element.querySelectorAll('p')].flatMap(paragraph=>[...paragraph.childNodes].filter(node=>node.nodeType===Node.TEXT_NODE).map(node=>node.textContent)).join(''),
      strong:element.querySelector('strong')?.textContent,
    }));
    assert.deepEqual(actual.hrefs,item.hrefs,item.name);assert.deepEqual(actual.labels,item.labels,item.name);
    if(item.plain)assert.ok(actual.plain.includes(item.plain),item.name+': prose must remain outside anchors');
    if(item.strong)assert.equal(actual.strong,item.strong,item.name);
    linkResults.push({name:item.name,status:'PASS',...actual});
  }
  console.log('PASS 8 link-boundary regressions including actual assistant wording, explicit Unicode URLs and code');
  const payload='<script>window.markdownXss=1</script><img src="https://example.test/tracker" onerror="window.markdownXss=1"><iframe srcdoc="bad"></iframe><p onclick="window.markdownXss=1" style="position:fixed">safe</p><a href="javascript:alert(1)">unsafe</a><a href="file:///private">file</a><a href="#section">anchor</a>';
  await page.evaluate(content=>{window.fixture.content=content;},payload);
  await page.waitForFunction(()=>document.querySelector('.markdown-body p')?.textContent==='safe');
  assert.equal(await page.locator('.markdown-body script,.markdown-body img,.markdown-body iframe,.markdown-body [onclick],.markdown-body [style]').count(),0);
  assert.equal(await page.getByText('unsafe',{exact:true}).getAttribute('href'),null);
  assert.equal(await page.getByText('file',{exact:true}).getAttribute('href'),null);
  assert.equal(await page.getByText('anchor',{exact:true}).getAttribute('href'),'#section');
  assert.equal(await page.evaluate(()=>window.markdownXss),undefined);
  assert.deepEqual(errors,[]);
  console.log('PASS reactive updates and DOMPurify XSS, remote resource, URL filtering');
  fs.writeFileSync(path.join(output,'result.json'),JSON.stringify({status:'PASS',layout,linkResults,errors},null,2));
  console.log(output);
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(async()=>{await browser?.close();await server?.close();});
