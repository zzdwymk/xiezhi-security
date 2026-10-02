const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const filename = path.resolve(__dirname, '../src/views/Workflow.vue');
const source = parse(fs.readFileSync(filename, 'utf8')).descriptor.scriptSetup.content;
const ast = ts.createSourceFile(filename + '.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const names = ['normalizeSingleMsfParameters', 'workflowToolParameters', 'nodeData', 'makeNode', 'toEditorNode', 'serializeGraph', 'graphSpecNodes', 'graphSpecEdges'];
const functions = ast.statements.filter(n => ts.isFunctionDeclaration(n) && names.includes(n.name?.text));
assert.equal(functions.length, names.length, 'test must execute actual editor load/create/save functions');
const body = functions.map(n => n.getText(ast)).join('\n');
const code = ts.transpileModule(body, {compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.CommonJS}}).outputText;
const fixture = {
  nodes: {value:[]}, edges:{value:[]}, preset:{value:'standard'},
  PHASES:[{code:'discovery'}], Position:{Right:'right',Left:'left'},
  phaseOf:()=>({label:'Discovery',desc:'fixture',icon:'beaker'}),
  agentOf:tool=>({name:tool,desc:'fixture',icon:'beaker',risk:['nuclei_scan','fscan_scan','zap_scan'].includes(tool)?'CAUTION':'SAFE'}),
  inferPhase:()=> 'discovery',
  topologicalGroups:()=>({level:new Map(fixture.nodes.value.map(n=>[n.id,0]))}),
};
Object.defineProperty(fixture,'toolNodes',{get:()=>({value:fixture.nodes.value.filter(n=>n.data.nodeKind==='tool')})});
vm.createContext(fixture);vm.runInContext(code, fixture);
const plain=value=>JSON.parse(JSON.stringify(value));
let passed=0;
function test(name,run){run();passed++;console.log('PASS '+name);}
function load(tool,parameters){return fixture.toEditorNode({id:tool,type:'tool',tool,phase:'discovery',label:tool,position:{x:10,y:20}},parameters);}
test('existing explicit empty parameters survive editor load, save and reload',()=>{
  const tools=['nmap_service_scan','http_security_check','nuclei_scan','afrog_scan','xray_scan','fscan_scan','zap_scan'];
  fixture.nodes.value=tools.map(tool=>load(tool,{}));
  const saved=plain(fixture.serializeGraph());
  assert.deepEqual(saved.steps.map(s=>s.parameters),tools.map(()=>({})));
  fixture.nodes.value=saved.graph.nodes.map(n=>fixture.toEditorNode(n,saved.steps.find(s=>s.nodeId===n.id).parameters));
  assert.deepEqual(plain(fixture.serializeGraph()).steps,saved.steps);
});
test('new nodes retain intended defaults without broadening an explicitly configured node',()=>{
  const expected={nuclei_scan:{allPocs:true},fscan_scan:{vulnMode:'SAFE'},http_security_check:{check:'cookies'},nmap_service_scan:{mode:'quick'},zap_scan:{}};
  for(const [tool,parameters] of Object.entries(expected)){
    const created=fixture.makeNode(tool,'tool','discovery',{x:0,y:0},undefined,tool);
    assert.deepEqual(plain(created.data.parameters),parameters);
    assert.deepEqual(plain(load(tool,{}).data.parameters),{});
  }
});
test('explicit narrow scan parameters retain false values and nested options across save',()=>{
  const original={allPocs:false,pocCodes:['one-template'],ports:'80',spider:false,strength:'LOW',custom:{enabled:false}};
  fixture.nodes.value=[load('nuclei_scan',original)];
  assert.deepEqual(plain(fixture.serializeGraph()).steps[0].parameters,original);
  assert.deepEqual(original,{allPocs:false,pocCodes:['one-template'],ports:'80',spider:false,strength:'LOW',custom:{enabled:false}});
});
test('missing legacy parameters stay empty on load and serialization never introduces defaults',()=>{
  fixture.nodes.value=[load('nuclei_scan',undefined)];
  assert.deepEqual(plain(fixture.serializeGraph()).steps[0].parameters,{});
  delete fixture.nodes.value[0].data.parameters;
  assert.deepEqual(plain(fixture.serializeGraph()).steps[0].parameters,{});
});
test('single MSF legacy options migrate through actual load/save without adding tool defaults',()=>{
  const module='auxiliary/scanner/http/http_header';
  const original={modules:[module],msfOptions:{[module]:{HTTP_METHOD:'HEAD',TARGETURI:'/'}}};
  fixture.nodes.value=[load('msf_scan',original)];
  const saved=plain(fixture.serializeGraph());
  assert.deepEqual(saved.steps[0].parameters,{modules:[module],options:{HTTP_METHOD:'HEAD',TARGETURI:'/'}});
  fixture.nodes.value=saved.graph.nodes.map(n=>fixture.toEditorNode(n,saved.steps.find(s=>s.nodeId===n.id).parameters));
  assert.deepEqual(plain(fixture.serializeGraph()).steps,saved.steps);
  assert.deepEqual(Object.keys(original),['modules','msfOptions'],'input must not be mutated');
});
test('multi-module MSF settings survive unchanged, including unselected saved modules',()=>{
  const original={modules:['auxiliary/scanner/http/http_header','auxiliary/scanner/http/http_version'], options:{THREADS:'1'},msfOptions:{'auxiliary/scanner/http/http_header':{HTTP_METHOD:'HEAD'},'auxiliary/scanner/http/http_version':{TARGETURI:'/'}}};
  fixture.nodes.value=[load('msf_scan',original)];
  assert.deepEqual(plain(fixture.serializeGraph()).steps[0].parameters,original);
  const single={...original,modules:[original.modules[0]]};
  fixture.nodes.value=[load('msf_scan',single)];
  assert.deepEqual(plain(fixture.serializeGraph()).steps[0].parameters,single);
});
console.log(`${passed} workflow parameter roundtrip checks passed.`);
