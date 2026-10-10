const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');

// Run the actual lifecycle functions with in-memory Electron doubles. Never
// load Electron, open a real window, or access the user's browser/profile.
const mainSource = fs.readFileSync(path.join(__dirname, '../electron/main.cjs'), 'utf8');
const start = mainSource.indexOf('function normalizeCaptureTargetUrl(');
const end = mainSource.indexOf('const ICP_QUERY_URL', start);
assert.ok(start >= 0 && end > start, 'Capture browser lifecycle functions must exist');
const lifecycleSource = mainSource.slice(start, end);
const baseOptions = { proxyHost: '127.0.0.1', proxyPort: 19080, targetUrl: 'http://example.test/login' };
const flushCleanup = () => new Promise(resolve => setImmediate(resolve));

function createHarness({ failLoad = false } = {}) {
  const windows = [], sessions = [], notifications = [], requestedTimeouts = [];
  class FakeSession {
    constructor(partition, options) {
      this.partition = partition;
      this.options = options;
      this.proxies = [];
      this.verifiers = [];
      this.connectionsClosed = 0;
      this.storageCleared = 0;
      this.cacheCleared = 0;
      this.storage = new Map([['login-cookie', 'keep-me']]);
    }
    setCertificateVerifyProc(value) { this.verifiers.push(value); }
    async setProxy(value) { this.proxies.push(value); }
    async closeAllConnections() { this.connectionsClosed++; }
    async clearStorageData() { this.storageCleared++; this.storage.clear(); }
    async clearCache() { this.cacheCleared++; }
  }
  class FakeWindow extends EventEmitter {
    constructor(options) {
      super();
      this.options = options;
      this.destroyed = false;
      this.minimized = false;
      this.closeMode = 'deferred';
      this.closeCalls = this.destroyCalls = this.restoreCalls = this.showCalls = this.focusCalls = 0;
      this.loads = [];
      this.scripts = [];
      this.webContents = new EventEmitter();
      this.webContents.setWindowOpenHandler = () => {};
      this.webContents.executeJavaScript = async source => { this.scripts.push(source); };
      windows.push(this);
    }
    isDestroyed() { return this.destroyed; }
    isMinimized() { return this.minimized; }
    restore() { this.restoreCalls++; this.minimized = false; }
    show() { this.showCalls++; }
    focus() { this.focusCalls++; }
    async loadFile(file, options) {
      this.loads.push({ file, options });
      if (failLoad) throw new Error('shell load failed');
    }
    close() {
      this.closeCalls++;
      if (this.closeMode === 'throw') throw new Error('close rejected');
      // A cancelled or deferred close leaves the window alive. Tests emit the
      // actual closed event explicitly to model Electron's asynchronous close.
    }
    completeClose() { this.destroyed = true; this.emit('closed'); }
    destroy() { this.destroyCalls++; this.completeClose(); }
  }
  const context = vm.createContext({
    URL, path, __dirname: path.join(__dirname, '../electron'),
    UserFacingError: Error,
    crypto: { randomUUID: () => `test-${sessions.length + 1}` },
    electronSession: { fromPartition(partition, options) { const value = new FakeSession(partition, options); sessions.push(value); return value; } },
    BrowserWindow: FakeWindow,
    app: { isPackaged: false },
    currentSystemTheme: () => ({ transparencyEnabled: false }),
    windowBackgroundColor: () => '#ffffff',
    applySystemThemeToStaticWindow: () => {},
    isTrustedLocalFileUrl: () => true,
    mainWindow: { isDestroyed: () => false, webContents: { send: (...args) => notifications.push(args) } },
    captureBrowserWindow: undefined,
    captureBrowserSession: undefined,
    captureBrowserPartition: undefined,
    captureBrowserConfig: undefined,
    captureProxyState: { running: null, capturing: false },
    captureBrowserOperation: Promise.resolve(),
    setImmediate,
    // Advance only the close-cancellation timeout; no real 1.5 second wait.
    setTimeout: (callback, delay) => { requestedTimeouts.push(delay); return setTimeout(callback, 0); },
    clearTimeout,
  });
  vm.runInContext(lifecycleSource, context, { filename: 'capture-browser-lifecycle-extracted.cjs' });
  return { context, windows, sessions, notifications, requestedTimeouts };
}

function latestPublishedState(window) {
  const source = window.scripts.at(-1);
  assert.ok(source.startsWith('window.setCaptureProxyState?.('));
  return JSON.parse(source.slice('window.setCaptureProxyState?.('.length, -1));
}

async function verifyReuse() {
  const { context: ctx, windows, sessions } = createHarness();
  await ctx.launchCaptureBrowser(baseOptions);
  const window = windows[0], session = sessions[0];
  const partition = ctx.captureBrowserPartition;
  window.minimized = true;
  await ctx.setCaptureBrowserProxyState({ running: true, capturing: true });
  const result = await ctx.launchCaptureBrowser({ ...baseOptions, targetUrl: 'about:blank' });
  assert.equal(windows.length, 1, 'Reopening must reuse the existing window');
  assert.equal(sessions.length, 1, 'Reopening must reuse the existing browser session');
  assert.equal(ctx.captureBrowserWindow, window);
  assert.equal(ctx.captureBrowserSession, session);
  assert.equal(ctx.captureBrowserPartition, partition);
  assert.equal(result.targetUrl, baseOptions.targetUrl, 'Reopening must preserve the current document');
  assert.equal(window.loads.length, 1, 'Reopening must not reload the shell');
  assert.equal(window.restoreCalls, 1);
  assert.equal(window.showCalls, 1);
  assert.equal(window.focusCalls, 1);
  assert.equal(window.closeCalls + window.destroyCalls, 0);
  assert.equal(session.proxies.length, 1, 'An unchanged proxy must not be reconfigured');
  assert.equal(session.connectionsClosed, 1);
  assert.equal(session.storageCleared + session.cacheCleared, 0);
  assert.equal(session.storage.get('login-cookie'), 'keep-me');
  assert.deepEqual(latestPublishedState(window), { running: true, capturing: true, proxy: '127.0.0.1:19080' });

  await ctx.launchCaptureBrowser({ ...baseOptions, proxyPort: 19081, caFingerprint: 'ab'.repeat(32), targetUrl: 'about:blank' });
  assert.equal(windows.length, 1, 'A changed proxy must keep the existing window');
  assert.equal(ctx.captureBrowserSession, session);
  assert.equal(session.proxies.length, 2);
  assert.equal(session.proxies[1].proxyRules, 'http=127.0.0.1:19081;https=127.0.0.1:19081');
  assert.equal(session.connectionsClosed, 2, 'Changing the endpoint must retire existing connections');
  assert.equal(typeof session.verifiers.at(-1), 'function');
  assert.equal(ctx.captureBrowserConfig.targetUrl, baseOptions.targetUrl);
  assert.equal(window.loads.length, 1);
  assert.equal(window.closeCalls + window.destroyCalls + session.storageCleared + session.cacheCleared, 0);
  assert.equal(session.storage.get('login-cookie'), 'keep-me');
  assert.equal(latestPublishedState(window).proxy, '127.0.0.1:19081');
  await ctx.setCaptureBrowserProxyState({ running: false, capturing: true });
  assert.deepEqual(latestPublishedState(window), { running: false, capturing: false, proxy: '127.0.0.1:19081' });
  await ctx.setCaptureBrowserProxyState({ running: 'invalid', capturing: true });
  assert.equal(latestPublishedState(window).running, null);
  assert.equal(latestPublishedState(window).capturing, false);
}

async function verifyClose() {
  const { context: ctx, windows, sessions, notifications, requestedTimeouts } = createHarness();
  await ctx.launchCaptureBrowser(baseOptions);
  const window = windows[0], session = sessions[0], config = ctx.captureBrowserConfig;
  window.closeMode = 'cancel';
  assert.equal((await ctx.closeCaptureBrowser()).running, true);
  assert.equal(ctx.captureBrowserWindow, window);
  assert.equal(ctx.captureBrowserSession, session);
  assert.equal(ctx.captureBrowserConfig, config);
  assert.equal(session.storageCleared, 0);
  assert.equal(notifications.length, 0);
  assert.equal(window.listenerCount('closed'), 1, 'Cancelled close must remove its temporary listener');
  window.closeMode = 'throw';
  await assert.rejects(ctx.closeCaptureBrowser(), /close rejected/);
  assert.equal(ctx.captureBrowserWindow, window);
  assert.equal(ctx.captureBrowserSession, session);
  assert.equal(ctx.captureBrowserConfig, config);
  assert.equal(session.storage.get('login-cookie'), 'keep-me');
  assert.equal(window.listenerCount('closed'), 1, 'Rejected close must remove its temporary listener');
  window.closeMode = 'deferred';
  const closing = ctx.closeCaptureBrowser();
  assert.equal(ctx.captureBrowserWindow, window, 'Calling close alone must not release session state');
  assert.equal(session.storageCleared, 0);
  window.completeClose();
  assert.equal((await closing).running, false);
  await flushCleanup();
  assert.equal(ctx.captureBrowserWindow, undefined);
  assert.equal(ctx.captureBrowserSession, undefined);
  assert.equal(ctx.captureBrowserPartition, undefined);
  assert.equal(ctx.captureBrowserConfig, undefined);
  assert.equal(session.proxies.at(-1).mode, 'direct');
  assert.equal(session.storageCleared, 1);
  assert.equal(session.cacheCleared, 1);
  assert.equal(session.verifiers.at(-1), null);
  assert.deepEqual(notifications, [['toolbox:capture-browser-closed']]);
  assert.ok(requestedTimeouts.every(delay => delay === 1500));
  assert.equal((await ctx.closeCaptureBrowser()).running, false);
  assert.equal(notifications.length, 1, 'Repeated close must not send duplicate closed events');
}

async function verifyFailedShellLoad() {
  const { context: ctx, windows, sessions } = createHarness({ failLoad: true });
  await assert.rejects(ctx.launchCaptureBrowser(baseOptions), /shell load failed/);
  await flushCleanup();
  assert.equal(windows[0].destroyCalls, 1);
  assert.equal(windows[0].closeCalls, 0, 'A failed new shell must be destroyed even if close could be cancelled');
  assert.equal(ctx.captureBrowserStatus().running, false);
  assert.equal(sessions[0].storageCleared, 1);
}

async function verifySerializedOperations() {
  const { context: ctx } = createHarness();
  const order = [];
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const first = ctx.serializeCaptureBrowserOperation(async () => { order.push('first-start'); await pending; order.push('first-end'); throw new Error('operation rejected'); });
  const rejection = assert.rejects(first, /operation rejected/);
  const second = ctx.serializeCaptureBrowserOperation(async () => { order.push('second'); return 'finished'; });
  await Promise.resolve();
  assert.deepEqual(order, ['first-start']);
  release();
  await rejection;
  assert.equal(await second, 'finished');
  assert.deepEqual(order, ['first-start', 'first-end', 'second'], 'A rejected operation must not block later queued operations');
}

function verifyShellFailureStatus() {
  const html = fs.readFileSync(path.join(__dirname, '../electron/capture-browser.html'), 'utf8');
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)];
  assert.equal(scripts.length, 1, 'Capture shell must have one inline controller');
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) {
      const value = new EventEmitter();
      const classes = new Set();
      Object.assign(value, { textContent: '', value: '', attributes: {},
        classList: { toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); }, contains: name => classes.has(name) },
        addEventListener: value.on.bind(value),
        setAttribute(name, content) { this.attributes[name] = content; },
        canGoBack: () => false, canGoForward: () => false, getURL: () => 'http://example.test/',
      });
      elements.set(id, value);
    }
    return elements.get(id);
  }
  const shell = { URL, URLSearchParams, location: { search: '?target=about%3Ablank&proxy=127.0.0.1%3A19080' }, document: { getElementById: element }, window: {} };
  vm.runInNewContext(scripts[0][1], shell, { filename: 'capture-browser-shell-extracted.js' });
  const browser = element('browser'), status = element('status');
  browser.emit('did-start-loading');
  browser.emit('did-fail-load', { errorCode: -130, isMainFrame: true });
  const failure = status.textContent;
  assert.match(failure, /加载失败/);
  browser.emit('did-stop-loading');
  assert.equal(status.textContent, failure, 'Loading completion must not overwrite the failure message');
  assert.equal(status.classList.contains('error'), true);
  browser.emit('did-start-loading');
  browser.emit('did-stop-loading');
  assert.equal(status.textContent, '页面加载完成');
  assert.equal(status.classList.contains('error'), false);
  shell.window.setCaptureProxyState({ running: false, capturing: false, proxy: '127.0.0.1:19081' });
  assert.match(element('proxy-state').textContent, /代理已关闭/);
  assert.equal(element('proxy').textContent, '127.0.0.1:19081');
  shell.window.setCaptureProxyState({ running: true, capturing: false });
  assert.match(element('proxy-state').textContent, /记录暂停/);
}

(async () => {
  for (const [name, verify] of [
    ['reuse and proxy reconfiguration preserve browsing state', verifyReuse],
    ['only actual closed events dispose the session', verifyClose],
    ['failed shell load releases its new window', verifyFailedShellLoad],
    ['launch and close operations remain serialized after failures', verifySerializedOperations],
    ['shell keeps load errors and displays live proxy state', verifyShellFailureStatus],
  ]) {
    await verify();
    console.log(`PASS ${name}`);
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
