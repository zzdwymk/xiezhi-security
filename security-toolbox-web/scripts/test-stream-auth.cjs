const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');

const root = path.resolve(__dirname, '..');
function createClient({ desktop = false, persistent = true, response }) {
  const cache = new Map();
  const requests = [], redirects = [], events = [], fallbacks = [];
  function storage() {
    const values = new Map();
    return {
      getItem: key => values.get(key) ?? null,
      setItem: (key, value) => values.set(key, value),
      removeItem: key => values.delete(key),
    };
  }
  const localStorage = storage(), sessionStorage = storage();
  (persistent ? localStorage : sessionStorage).setItem(
    persistent ? 'security_toolbox_token' : 'security_toolbox_session_token', 'test-user-token');
  const location = {
    search: desktop ? '?desktop=1&backend=http%3A%2F%2F127.0.0.1%3A18080%2Fapi' : '',
    origin: 'http://localhost:5173', pathname: '/traffic', hash: desktop ? '#/traffic' : '',
    assign: url => redirects.push(url),
  };
  const window = { location, dispatchEvent: event => events.push(event.type) };
  const axios = { create: () => ({
    interceptors: { request: { use() {} }, response: { use() {} } },
    post: (...args) => { fallbacks.push(args); throw new Error('Unexpected fallback request'); },
  }) };
  function load(file) {
    if (cache.has(file)) return cache.get(file).exports;
    const module = { exports: {} }; cache.set(file, module);
    const code = ts.transpileModule(fs.readFileSync(file, 'utf8'), {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
    }).outputText;
    const localRequire = name => {
      if (name === 'axios') return { default: axios };
      if (name === './utils/taskbarProgress') return { taskbarProgress: new Proxy({}, { get: () => () => {} }) };
      return name.startsWith('.') ? load(path.resolve(path.dirname(file), name + '.ts')) : require(name);
    };
    vm.runInNewContext(`(function(require,module,exports){${code}\n})`, {
      fetch: async (url, init) => { requests.push({ url, init }); return response(); },
      window, location, localStorage, sessionStorage, URL, URLSearchParams,
      Event, Headers, Request, AbortController, TextDecoder, setTimeout, clearTimeout, console,
    }, { filename: file })(localRequire, module, module.exports);
    return module.exports;
  }
  return { client: load(path.join(root, 'src/api.ts')), localStorage, sessionStorage, location, redirects, events, requests, fallbacks };
}

const streams = [
  ['task', c => c.streamTaskEvents(1, () => {}, new AbortController().signal)],
  ['all tasks', c => c.streamAllTaskEvents(() => {}, new AbortController().signal)],
  ['workflow suggestions', c => c.streamWorkflowSuggestions({ graph: { nodes: [], edges: [] } }, () => {})],
  ['AI agent', c => c.dispatchAiStreaming({ projectId: 1, targetId: 2, prompt: 'test' }, () => {})],
  ['sqlmap', c => c.streamSqlmapScan(1, { targetId: 2 }, () => {})],
  ['ZAP', c => c.streamZapScan(1, { targetId: 2 }, () => {})],
  ['Xray', c => c.streamXrayScan(1, { targetId: 2 }, () => {})],
];
let passed = 0;
async function test(name, run) { await run(); passed++; console.log('PASS ' + name); }
(async () => {
  for (const desktop of [false, true]) {
    for (const [name, invoke] of streams) {
      await test(`${name}: 401 clears ${desktop ? 'desktop session' : 'web persistent'} login and redirects`, async () => {
        const state = createClient({ desktop, persistent: !desktop,
          // An empty unauthorized body must not trigger the AI compatibility fallback.
          response: () => new Response(null, { status: 401 }) });
        await assert.rejects(invoke(state.client), /登录已失效/);
        assert.equal(state.requests.length, 1);
        assert.deepEqual(state.fallbacks, []);
        assert.equal(state.requests[0].init.headers.Authorization, 'Bearer test-user-token');
        assert.equal(state.localStorage.getItem('security_toolbox_token'), null);
        assert.equal(state.sessionStorage.getItem('security_toolbox_session_token'), null);
        assert.deepEqual(state.events, ['security-toolbox-auth-expired']);
        if (desktop) assert.equal(state.location.hash, '#/login?redirect=%2Ftraffic');
        else assert.deepEqual(state.redirects, ['/login?redirect=%2Ftraffic']);
      });
    }
  }
  for (const [name, invoke] of streams) {
    for (const body of [null, JSON.stringify({ message: '无权访问该授权目标' })]) {
    await test(`${name}: ${body ? 'JSON' : 'empty'} 403 neither logs out nor retries the request`, async () => {
      const state = createClient({ response: () => new Response(body, { status: 403 }) });
      await assert.rejects(invoke(state.client));
      assert.deepEqual(state.fallbacks, []);
      assert.equal(state.localStorage.getItem('security_toolbox_token'), 'test-user-token');
      assert.deepEqual(state.events, []); assert.deepEqual(state.redirects, []);
    });
    }
  }
  for (const engine of ['sqlmap', 'ZAP', 'Xray']) {
    const invoke = streams.find(([name]) => name === engine)[1];
    await test(`${engine}: SSE application error preserves login and propagates failure`, async () => {
      const state = createClient({ response: () => new Response('data: {"type":"error","message":"请先登录后再继续操作"}\n\n',
        { headers: { 'content-type': 'text/event-stream' } }) });
      await assert.rejects(invoke(state.client), /请先登录/);
      assert.equal(state.localStorage.getItem('security_toolbox_token'), 'test-user-token');
      assert.deepEqual(state.events, []); assert.deepEqual(state.redirects, []);
    });
    await test(`${engine}: successful completion remains a completed scan`, async () => {
      const state = createClient({ response: () => new Response('data: {"type":"complete","result":{"status":"COMPLETED","hits":[],"probes":[]}}\n\n',
        { headers: { 'content-type': 'text/event-stream' } }) });
      assert.equal((await invoke(state.client)).status, 'COMPLETED');
      assert.equal(state.localStorage.getItem('security_toolbox_token'), 'test-user-token');
      assert.deepEqual(state.events, []);
    });
    for (const terminal of ['complete', 'error']) {
      await test(`${engine}: ${terminal} ends and releases a stream without socket EOF`, async () => {
        let cancelled = false;
        const event = terminal === 'complete'
          ? { type: terminal, result: { status: 'COMPLETED', hits: [], probes: [] } }
          : { type: terminal, message: '检测工具停止响应' };
        const body = new ReadableStream({
          start(controller) { controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(event)}\n\n`)); },
          cancel() { cancelled = true; },
        });
        const state = createClient({ response: () => new Response(body, { headers: { 'content-type': 'text/event-stream' } }) });
        let timeout;
        try {
          const pending = Promise.race([invoke(state.client), new Promise((_, reject) => {
            timeout = setTimeout(() => reject(new Error('terminal event waited for socket EOF')), 1000);
          })]);
          if (terminal === 'complete') assert.equal((await pending).status, 'COMPLETED');
          else await assert.rejects(pending, /检测工具停止响应/);
          assert.equal(cancelled, true);
          assert.equal(body.locked, false);
        } finally { clearTimeout(timeout); }
      });
    }
  }
  console.log(`${passed} stream authentication checks passed.`);
})().catch(error => { console.error(error); process.exitCode = 1; });
