'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),ts=require('typescript');
const root=path.resolve(__dirname,'..');
const helperSource=fs.readFileSync(path.join(root,'src/utils/errorMessage.ts'),'utf8');
const helperModule={exports:{}};
vm.runInNewContext(ts.transpileModule(helperSource,{compilerOptions:{module:ts.ModuleKind.CommonJS}}).outputText,{module:helperModule,exports:helperModule.exports});
const source=fs.readFileSync(path.join(root,'src/views/Vulnerabilities.vue'),'utf8');
const start=source.indexOf('function describeCatalogLoadError('),end=source.indexOf('\nfunction searchCatalog()',start);
assert(start>=0&&end>start,'Actual catalog error function boundary');
const context={toErrorMessage:helperModule.exports.toErrorMessage};
vm.createContext(context);vm.runInContext(ts.transpileModule(source.slice(start,end),{compilerOptions:{target:ts.ScriptTarget.ES2020}}).outputText,context);
const describe=context.describeCatalogLoadError;
const error=(status,message)=>({response:{status,data:{message}},config:{url:'/vulnerabilities'}});
let count=0;
for(const message of ['漏洞年份必须为四位数字','漏洞库检索词不能包含空字符（NUL）']){
 assert.equal(describe(error(400,message)),`无法加载漏洞库：${message}（接口 /vulnerabilities）`);count++;
}
for(const message of ['java.lang.IllegalArgumentException: private-path','非法参数 at x.y(Source.java:123)','非法参数 D:\\private\\config']){
 const output=describe(error(400,message));assert(!output.includes(message));assert(output.includes('HTTP 400'));count++;
}
for(const status of [401,403]){assert(describe(error(status,'private')).includes('登录状态已失效'));count++;}
assert.equal(describe(error(500,'数据库实现细节')),'无法加载漏洞库：本地服务返回 500 错误（接口 /vulnerabilities）');count++;
assert(describe({code:'ECONNABORTED'}).includes('响应超时'));count++;
assert(describe({code:'ERR_NETWORK'}).includes('无法连接本地服务'));count++;
console.log(`PASS: ${count} actual catalog error message scenarios; safe validation reasons retained`);
