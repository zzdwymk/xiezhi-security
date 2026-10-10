'use strict';
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm'), assert = require('node:assert/strict');
const ts = require('typescript');
const { parse } = require('@vue/compiler-sfc');
const root = path.resolve(__dirname, '..');
const transpile = text => ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
const helperModule = { exports: {} };
vm.runInNewContext(`(function(module,exports){${transpile(fs.readFileSync(path.join(root, 'src/utils/trafficFuzzDraft.ts'), 'utf8'))}})`, { URL })(helperModule, helperModule.exports);
const { resolveFuzzAddress, replaceFuzzNameMarker } = helperModule.exports;
const sfc = parse(fs.readFileSync(path.join(root, 'src/views/Traffic.vue'), 'utf8'));
assert.equal(sfc.errors.length, 0);
const script = sfc.descriptor.scriptSetup.content;
const ast = ts.createSourceFile('Traffic.vue', script, ts.ScriptTarget.Latest, true);
const func = (name, context) => {
  const node = ast.statements.find(x => ts.isFunctionDeclaration(x) && x.name?.text === name); assert(node, name);
  return vm.runInNewContext(`${transpile(node.getText(ast))}\n${name}`, { ...helperModule.exports, ...context });
};
const HOST = 'http://192.168.136.132';
const base = `${HOST}/?qa_traffic_semantics=§name§`;
const last = `${HOST}/?qa_traffic_semantics_url=§name§`;
const raw = `GET ${base} HTTP/1.1\r\nHost: 192.168.136.132\r\nX-QA: baseline\r\n\r\nbody=unchanged`;
const checks = [];
async function check(name, fn) { await fn(); checks.push({ name, status: 'PASS' }); }
function fixture(url, packet, edited) {
  const ref = value => ({ value }); const calls = [], approvals = [];
  const context = {
    actionSessions: () => [{ id: 327 }], fuzzForm: ref({ method: 'GET', url, headers: '', body: '' }), fuzzRawPacket: ref(packet), fuzzAddressEdited: ref(edited),
    fuzzRunning: ref(false), fuzzVariables: ref(['name']), isSinglePayloadMode: ref(true), fuzzSharedPayload: ref('A'), fuzzCombination: ref('SNIPER'), fuzzEngine: ref('loop'),
    ensureFuzzGroups() {}, splitFuzzPacket() {}, fuzzError: ref(''), fuzzBatchResults: ref({}), fuzzFocusPacketId: ref(327), selectedId: ref(327), fuzzResult: ref(), trafficAlive: true,
    chooseOperationTarget: async url => { approvals.push(url); return 308; }, api: { post: async (url, input) => { calls.push({ url, input }); return { data: { batchId: 'unit-contract-only', status: 'COMPLETED', results: {} } }; } },
    ElMessage: { warning() {}, success() {}, error(message) { throw new Error(message); } }, readableError: String, fuzzRequestCount: () => 0,
    syncUrlEditorScroll() {}, syncRawEditorScroll() {},
  };
  context.parseRawFuzzPacket = func('parseRawFuzzPacket', context);
  return { context, calls, approvals, run: func('runFuzz', context) };
}
function replayFixture() {
  const calls = [], notices = [], warnings = [], tab = { value: 'fuzz' };
  const context = {
    fuzzFocusPacketId: { value: 327 }, selectedId: { value: 999 }, sessions: { value: [{ id: 327 }] }, packetTab: tab,
    createReplayTab: (...args) => calls.push(args), composeReplayPacket: func('composeReplayPacket', {}),
    ElMessage: { info: text => notices.push(text), warning: text => warnings.push(text) },
  };
  // Any read from the editable form would reproduce the original stale-binding bug.
  context.fuzzForm = { get value() { throw new Error('Replaying a hit must never read the current Fuzz form'); } };
  return { calls, notices, warnings, tab, run: func('fuzzHitToReplay', context) };
}
(async () => {
  await check('original last URL edit preserves exact markers and whole raw suffix', () => {
    const out = resolveFuzzAddress(last, raw, 'url'); assert.equal(out.url, last); assert.equal(out.raw, raw.replace(base, last));
  });
  await check('raw absolute edit becomes visible URL', () => { const out = resolveFuzzAddress(base, raw.replace(base, last), 'raw'); assert.equal(out.url, last); assert.equal(out.raw, raw.replace(base, last)); });
  await check('raw relative edit keeps origin and literal markers', () => { assert.equal(resolveFuzzAddress(base, 'GET /?raw=§name§ HTTP/1.1\nHost: 192.168.136.132\n\n', 'raw').url, `${HOST}/?raw=§name§`); });
  await check('URL edit rewrites relative raw target and preserves body', () => { const out = resolveFuzzAddress(last, 'POST /old HTTP/1.1\nX-QA: keep\n\nbody', 'url'); assert.equal(out.raw, `POST ${last} HTTP/1.1\nX-QA: keep\n\nbody`); });
  await check('empty raw preserves valid URL', () => { assert.equal(resolveFuzzAddress(last, '', 'raw').url, last); assert.equal(resolveFuzzAddress(last, '', 'url').raw, ''); });
  await check('Unicode, reserved characters and repeated markers are not URI-encoded', () => { const url = `${HOST}/中文😀?a=§name§&b=§name§&x=%25`; const out = resolveFuzzAddress(url, raw, 'url'); assert.equal(out.url, url); assert(out.raw.includes(url)); });
  await check('explicit port remains intact for relative raw', () => { assert.equal(resolveFuzzAddress(`${HOST}:80/old`, 'GET /next?x=§name§ HTTP/1.1', 'raw').url, `${HOST}:80/next?x=§name§`); });
  await check('URL/raw input handlers record the latest editor', () => { const f = fixture(base, raw, 'raw'); func('onFuzzUrlInput', f.context)(); assert.equal(f.context.fuzzAddressEdited.value, 'url'); func('onFuzzRawInput', f.context)(); assert.equal(f.context.fuzzAddressEdited.value, 'raw'); });
  await check('real runFuzz function: approval and submitted URL follow last URL input', async () => {
    const f = fixture(last, raw, 'url'); await f.run(); assert.deepEqual(f.approvals, [last]); assert.equal(f.calls.length, 1); assert.equal(f.calls[0].input.request.url, last); assert.equal(f.context.fuzzRawPacket.value, raw.replace(base, last)); assert.equal(f.calls[0].input.request.body, 'body=unchanged');
  });
  await check('real runFuzz function: relative raw path reaches approval and POST together', async () => {
    const f = fixture(base, 'GET /?raw=§name§ HTTP/1.1\nHost: 192.168.136.132\n\n', 'raw'); await f.run(); assert.equal(f.approvals[0], `${HOST}/?raw=§name§`); assert.equal(f.calls[0].input.request.url, f.approvals[0]); assert.equal(f.context.fuzzForm.value.url, f.approvals[0]);
  });
  await check('real runFuzz function: absolute raw edit reaches approval and POST together', async () => {
    const f = fixture(base, raw.replace(base, last), 'raw'); await f.run(); assert.equal(f.approvals[0], last); assert.equal(f.calls[0].input.request.url, last);
  });
  await check('both input elements are wired to editor-intent handlers', () => { assert.match(sfc.descriptor.template.content, /ref="fuzzUrlInput"[\s\S]*?@input="onFuzzUrlInput"/); assert.match(sfc.descriptor.template.content, /ref="fuzzRawInput"[\s\S]*?@input="onFuzzRawInput"/); });
  await check('repeated marker payload is literal, including replacement metacharacters', () => {
    for (const payload of ['A', '', '$&', "$$-$`-$'", '中文🙂', '§name§']) {
      assert.equal(replaceFuzzNameMarker('first=§name§&again=§name§', payload), 'first=' + payload + '&again=' + payload);
    }
  });
  await check('unrelated named markers and marker-free text remain unchanged', () => {
    assert.equal(replaceFuzzNameMarker('id=§id§&plain=value', 'A'), 'id=§id§&plain=value');
  });
  const snapshot = (overrides = {}) => ({ method: 'GET', url: `${HOST}/A?repeat=A`, headers: 'Host: 192.168.136.132\nX-QA: A\nX-Repeat: A', body: 'first=A&again=A', ...overrides });
  await check('real fuzzHitToReplay reuses repeated payload request without reading the editable form', async () => {
    const f = replayFixture(), request = snapshot();
    await f.run({ payload: 'A', changed: true, request });
    assert.equal(f.calls.length, 1); const [form, raw, source] = f.calls[0];
    assert.deepEqual(JSON.parse(JSON.stringify(form)), request); assert.equal(source, 327);
    assert.equal(raw, request.headers + '\n\n' + request.body); assert.equal(f.tab.value, 'replay'); assert.equal(f.notices.length, 1);
  });
  await check('non-name id marker uses captured request and never reconstructs from label', async () => {
    const f = replayFixture(), request = snapshot({ url: `${HOST}/?id=actual-id`, headers: 'X-Id: actual-id', body: 'id=actual-id' });
    await f.run({ payload: 'id=display-label', changed: true, request });
    assert.deepEqual(JSON.parse(JSON.stringify(f.calls[0][0])), request);
  });
  await check('multi-variable Sniper keeps literal values separate from its display summary', async () => {
    const f = replayFixture(), request = snapshot({ method: 'POST', url: `${HOST}/?name=$&id=%E4%B8%AD`, headers: "X-Name: $&\r\nX-Id: $$-$`-$'", body: 'name=$&\r\nid=中文🙂\r\n' });
    await f.run({ payload: 'name=truncated…; id=summary…', changed: true, request });
    assert.deepEqual(JSON.parse(JSON.stringify(f.calls[0][0])), request);
  });
  await check('257-character payload remains complete despite a 48-character display label', async () => {
    const f = replayFixture(), payload = 'L'.repeat(257), request = snapshot({ url: `${HOST}/?id=${payload}`, headers: `X-Id: ${payload}`, body: `id=${payload}` });
    await f.run({ payload: payload.slice(0, 48) + '…', changed: true, request });
    assert.deepEqual(JSON.parse(JSON.stringify(f.calls[0][0])), request); assert.equal(f.calls[0][0].body.length, 260);
  });
  await check('editing the created draft cannot mutate the saved Fuzz result', async () => {
    const f = replayFixture(), request = snapshot(), before = JSON.stringify(request);
    await f.run({ payload: 'A', changed: true, request });
    f.calls[0][0].url = `${HOST}/edited`; f.calls[0][0].headers = ''; f.calls[0][0].body = 'edited';
    assert.equal(JSON.stringify(request), before);
  });
  await check('legacy and malformed requests produce a clear message without a replay draft', async () => {
    for (const request of [undefined, null, {}, snapshot({ body: undefined }), snapshot({ headers: null }), snapshot({ method: 'GET\r\nX: bad' }), snapshot({ url: 'file:///test' }), snapshot({ url: `${HOST}/bad\nurl` }), snapshot({ url: '/relative' })]) {
      const f = replayFixture(); await f.run({ payload: 'A', changed: true, request });
      assert.equal(f.calls.length, 0); assert.equal(f.tab.value, 'fuzz'); assert.deepEqual(f.warnings, [helperModule.exports.FUZZ_REPLAY_UNAVAILABLE]);
    }
  });
  await check('only complete requests receive the visible replay action; other changed rows explain why', () => {
    assert.match(sfc.descriptor.template.content, /v-if="hit.changed && readFuzzReplayRequest\(hit.request\)"/);
    assert.match(sfc.descriptor.template.content, /v-else-if="hit.changed"[^>]*>\{\{ FUZZ_REPLAY_UNAVAILABLE \}\}/);
  });
  await check('sendReplay preserves unedited captured CRLF and trailing bytes, then honors explicit packet edits', async () => {
    const request = snapshot({ method: 'POST', headers: 'Host: 192.168.136.132\r\nX-QA: literal  ', body: 'first=A\r\nsecond=B\r\n\r\n' });
    const tab = { sourcePacketId: 327, form: { ...request } }, calls = [], compose = func('composeReplayPacket', {});
    const packet = { value: compose(request.headers, request.body) };
    const context = { activeReplayTab: { value: tab }, replaying: { value: false }, replayPacket: packet, composeReplayPacket: compose,
      splitReplayPacket: func('splitReplayPacket', {}), chooseOperationTarget: async () => 308,
      api: { post: async (url, input) => { calls.push({ url, input }); return { data: { statusCode: 200 } }; } },
      ElMessage: { success() {}, error(message) { throw new Error(message); } }, readableError: String };
    const send = func('sendReplay', context); await send();
    assert.equal(calls[0].input.headers, request.headers); assert.equal(calls[0].input.body, request.body);
    assert.equal(calls[0].input.url, request.url); assert.equal(calls[0].input.method, request.method);
    packet.value = 'X-QA: edited\n\nexplicitly edited body\n'; tab.form.url = `${HOST}/edited`; await send();
    assert.equal(calls[1].input.headers, 'X-QA: edited'); assert.equal(calls[1].input.body, 'explicitly edited body\n'); assert.equal(calls[1].input.url, `${HOST}/edited`);
    assert.equal(request.body, 'first=A\r\nsecond=B\r\n\r\n');
  });
  console.log(JSON.stringify({ status: 'PASS', count: checks.length, layer: 'isolated production-function contract tests; mocked submission is never desktop/network evidence', checks }, null, 2));
})().catch(e => { console.error(e); process.exitCode = 1; });
