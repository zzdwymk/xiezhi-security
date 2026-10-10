const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const base = path.join(__dirname, '../src/utils');
function harness() {
  const storage = new Map(), timers = new Map(), modules = new Map();
  const shown = [], native = [], navigated = [], browser = [], settings = {};
  let hidden = false, current = true, timerId = 0, permissionRequests = 0;
  class BrowserNotification {
    static permission = 'granted';
    static requestPermission() { permissionRequests++; return Promise.resolve('granted'); }
    constructor(title, payload) { this.title = title; this.payload = payload; browser.push(this); }
    close() {}
  }
  const window = { dispatchEvent() {}, focus() {}, Notification: BrowserNotification };
  const context = vm.createContext({ window, document: { get hidden() { return hidden; }, hasFocus: () => !hidden },
    Notification: BrowserNotification, URL, Event, AbortController, console,
    localStorage: { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value) },
    setTimeout: fn => { const id = ++timerId; timers.set(id, fn); return id; }, clearTimeout: id => timers.delete(id),
  });
  function load(name) {
    if (name === './aiPresentation') return { severityLabel: s => ({HIGH: '高危', CRITICAL: '严重', MEDIUM: '中危'}[s] || s) };
    if (name === './errorMessage') return { toErrorMessage: (value, fallback) => value || fallback };
    if (modules.has(name)) return modules.get(name).exports;
    const module = { exports: {} }; modules.set(name, module);
    const source = path.join(base, name.replace('./', '') + '.ts');
    const code = ts.transpileModule(fs.readFileSync(source, 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 } }).outputText;
    vm.runInContext(`(function(module,exports,require){${code}\n})`, context, {filename: source})(module, module.exports, load);
    return module.exports;
  }
  const utils = load('./notifications');
  const delivery = load('./notificationDelivery').createNotificationDelivery({
    present: (notice, open) => shown.push({ notice, open }), navigate: route => navigated.push(route), isCurrent: () => current,
  });
  function desktop(response = { delivered: true }) {
    window.toolboxDesktop = { getNotificationSettings: async () => utils.normalizeNotificationPreferences(settings),
      saveNotificationSettings: async value => { Object.assign(settings, value); return settings; },
      showTaskNotification: async value => { native.push(value); if (response instanceof Error) throw response; return response; },
    };
  }
  return { utils, delivery, desktop, settings, shown, native, navigated, browser, storage, timers, window, load,
    background: () => hidden = true, expire: () => current = false, permissionRequests: () => permissionRequests };
}
const notice = (id, extra = {}) => ({ id, eventKey: 'task:' + id, category: 'task', outcome: 'success', title: '任务完成', body: '结果已保存', route: '/tasks?taskId=' + id, severities: [], ...extra });
let passed = 0;
async function test(name, run) { await run(); console.log('PASS ' + name); passed++; }
(async () => {
  await test('master switch and independent categories, including findings-only mode', () => {
    const h = harness(), prefs = h.utils.normalizeNotificationPreferences({ taskCompleteNotifications: false });
    assert.equal(h.utils.shouldNotify(notice(1), prefs), false);
    assert.equal(h.utils.shouldNotify(notice(1, {severities:['HIGH']}), prefs), true);
    assert.equal(h.utils.shouldNotify(notice(1, {severities:['LOW']}), prefs), false);
    assert.equal(h.utils.shouldNotify(notice(1, {outcome:'error'}), prefs), true);
    for (const [category, flag] of Object.entries({workflow:'workflowCompleteNotifications', workflow_skip:'workflowSkipNotifications', approval:'approvalNotifications', schedule:'scheduleNotifications', traffic:'trafficNotifications', service:'serviceNotifications'})) {
      assert.equal(h.utils.shouldNotify(notice(1, {category}), {...prefs,[flag]:false}), false);
      assert.equal(h.utils.shouldNotify(notice(1, {category}), {...prefs,enabled:false}), false);
    }
  });
  await test('saved high-risk partial results still notify when completion and failure alerts are off', async () => {
    const h = harness(); h.desktop();
    Object.assign(h.settings, {taskCompleteNotifications:false,taskFailureNotifications:false,workflowCompleteNotifications:false});
    await h.delivery([notice(1,{outcome:'error',severities:['HIGH']}), notice(2,{category:'workflow',severities:['HIGH']})]);
    assert.equal(h.shown.length,2); assert.match(h.shown[0].notice.body,/高危/);
  });
  await test('empty severity selection and independent browser preferences survive reload', async () => {
    const h = harness(); await h.utils.saveNotificationPreferences({severities:[], taskFailureNotifications:false});
    const saved = await h.utils.loadNotificationPreferences();
    assert.equal(saved.severities.length, 0); assert.equal(saved.taskFailureNotifications, false);
    assert.equal(saved.approvalNotifications, true);
  });
  await test('simultaneous duplicate deliveries show once without native foreground popup', async () => {
    const h = harness(); h.desktop(); await Promise.all([h.delivery([notice(1)]), h.delivery([notice(1)])]);
    assert.equal(h.shown.length, 1); assert.equal(h.native.length, 0); h.shown[0].open();
    assert.equal(h.navigated[0], '/tasks?taskId=1');
  });
  await test('background uses native once and unsupported native falls back in app', async () => {
    const h = harness(); h.desktop(); h.background(); await h.delivery([notice(1)]);
    assert.equal(h.native.length, 1); assert.equal(h.shown.length, 0);
    const fallback = harness(); fallback.desktop({delivered:false,reason:'unsupported'}); fallback.background();
    await fallback.delivery([notice(1)]); assert.equal(fallback.shown.length, 1);
  });
  await test('native disabled or duplicate response does not bypass policy with a toast', async () => {
    for (const reason of ['disabled', 'duplicate']) {
      const h = harness(); h.desktop({delivered:false,reason}); h.background(); await h.delivery([notice(1)]);
      assert.equal(h.shown.length, 0);
    }
  });
  await test('browser notification navigates only internal routes and never asks permission automatically', async () => {
    const h = harness(); h.background(); await h.delivery([notice(1)]);
    assert.equal(h.browser.length, 1); h.browser[0].onclick(); assert.equal(h.navigated[0], '/tasks?taskId=1');
    assert.equal(h.permissionRequests(), 0);
    for (const route of ['https://evil.example/', '//evil.example/tasks', '/tasks\\evil', '/login', 'javascript:alert(1)']) {
      assert.equal(h.utils.notificationRoute(route), undefined);
    }
  });
  await test('large completion batches aggregate after category filtering, exceptions stay actionable', async () => {
    const h = harness(); h.desktop();
    await h.delivery([...Array.from({length:6},(_,i)=>notice(i)),notice(7,{category:'approval',outcome:'warning'})]);
    assert.equal(h.shown.length, 2); assert.match(h.shown[0].notice.title,/6/); assert.equal(h.shown[0].notice.route,'/tasks');
    assert.equal(h.shown[1].notice.category,'approval');
  });
  await test('late preference response after logout cannot show previous user events', async () => {
    const h = harness(); let release;
    h.window.toolboxDesktop = {getNotificationSettings: () => new Promise(resolve => release = resolve)};
    const pending = h.delivery([notice(1)]); h.expire(); release({}); await pending;
    assert.equal(h.shown.length,0);
  });
  await test('a failed notification bridge cannot reject workflow submission', async () => {
    const h=harness(); h.utils.setNotificationDispatcher(async()=>{throw Error('bridge unavailable');});
    await h.utils.notifyWorkflowSkipped({count:2,labels:['A','B']});
  });
  await test('feed retains cursor across network errors and does not advance before delivery', async () => {
    const h = harness(), requests = [], saved = []; let fail = true, release;
    const feed = h.load('./notificationFeed').startNotificationFeed({
      readCursor:()=>9, saveCursor:c=>saved.push(c),
      fetchPage:async after=>{requests.push(after); if(fail) throw Error('offline'); return {items:[notice(10)],cursor:10};},
      deliver:()=>new Promise(resolve=>release=resolve),
    });
    await feed.poll(); assert.equal(saved.length,0); fail=false;
    const pending=feed.poll(); await new Promise(setImmediate); assert.equal(saved.length,0);
    release(); await pending; assert.equal(saved[0],10); assert.equal(requests.join(','),'9,9'); feed.stop();
    assert.equal(h.timers.size,0);
  });
  await test('stopped feed ignores delayed response, cancels request, and cannot restart', async () => {
    const h=harness(); let release, signal; const delivered=[],saved=[];
    const feed=h.load('./notificationFeed').startNotificationFeed({readCursor:()=>undefined, saveCursor:c=>saved.push(c),
      fetchPage:(_,s)=>{signal=s;return new Promise(resolve=>release=resolve);},deliver:async items=>delivered.push(...items)});
    const pending=feed.poll(); feed.stop(); assert.equal(signal.aborted,true); release({items:[notice(1)],cursor:1}); await pending; await feed.poll();
    assert.equal(delivered.length,0); assert.equal(saved.length,0); assert.equal(h.timers.size,0);
  });
  console.log(`${passed} unified notification behavior checks passed.`);
})().catch(error=>{ console.error(error); process.exitCode=1; });

