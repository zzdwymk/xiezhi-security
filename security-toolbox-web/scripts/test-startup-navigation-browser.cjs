// Real main.ts, App.vue, router, Setup/Login, Pinia auth, and HTTP/SSE clients.
// Only unrelated workspace views and external HTTP/desktop services are fixtures.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const output = path.resolve(root, '../.run');
fs.mkdirSync(output, { recursive: true });
let browser, server;
const errors = [];
const readyCore = { name: 'Java', required: true, installed: true, status: 'ready' };
const nextButton = page => page.getByRole('button', { name: '下一步，进入工具箱', exact: true });
const html = `<!doctype html><html><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module">
import '/src/main.ts';
import { nextTick } from 'vue';
import router from '/src/router.ts';
import { useAuthStore } from '/src/stores/auth.ts';
import { api, apiFetch, apiUrl } from '/src/apiClient.ts';
import { readAuthToken, storeAuthToken } from '/src/authToken.ts';
Object.assign(window.fixture, { router, auth: useAuthStore, api, apiFetch, apiUrl, readAuthToken, storeAuthToken });
router.afterEach(to => window.fixture.navigation.push(to.fullPath));
window.fixture.flush = async () => {
  await nextTick();
  await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  await nextTick();
};
</script></body></html>`;

async function openFixture(options = {}) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(({ oldSetup, oldToken, autoContinue, desktop, holdDecoration }) => {
    localStorage.clear();
    sessionStorage.clear();
    if (oldSetup) localStorage.setItem('security_toolbox_setup_complete_v2', 'true');
    if (oldToken) localStorage.setItem('security_toolbox_token', oldToken);
    localStorage.setItem('security_toolbox_setup_auto_continue_v1', String(autoContinue));
    const fixture = window.fixture = { sources: [], feeds: [], navigation: [], probes: {}, holdDecoration };
    window.EventSource = class extends EventTarget {
      constructor(url) {
        super();
        this.url = url;
        this.closed = false;
        fixture.sources.push(this);
      }
      close() { this.closed = true; }
      emit(type, data) {
        const event = new MessageEvent(type, { data: JSON.stringify(data) });
        if (type === 'message') this.onmessage?.(event);
        else if (type === 'error') this.onerror?.(event);
        else this.dispatchEvent(event);
      }
    };
    const realFetch = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      const request = new Request(input, init);
      if (new URL(request.url).pathname !== '/api/tasks/events') return realFetch(input, init);
      const feed = { authorization: request.headers.get('Authorization'), route: fixture.router?.currentRoute.value.fullPath, aborted: false };
      fixture.feeds.push(feed);
      if (!feed.authorization) return new Response('{}', { status: 401, headers: { 'Content-Type': 'application/json' } });
      const body = new ReadableStream({
        start(controller) {
          request.signal.addEventListener('abort', () => {
            feed.aborted = true;
            controller.error(new DOMException('Fixture stream aborted', 'AbortError'));
          }, { once: true });
        },
      });
      return new Response(body, { headers: { 'Content-Type': 'text/event-stream' } });
    };
    window.toolboxDesktop = {
      isDesktop: desktop,
      getToolsDirectory: async () => {
        if (fixture.holdDecoration) await new Promise(resolve => fixture.finishDecoration = resolve);
        return 'C:/startup-test/tools';
      },
      listInstallableDependencies: async () => [],
      getDesktopLoginBinding: async () => ({ bound: true, configured: true }),
      getDesktopLoginCredentials: async () => ({ username: 'admin', password: 'fixture-password' }),
      loginWithWindowsHello: async () => ({ verified: true, credentials: { username: 'admin', password: 'fixture-password' } }),
    };
  }, {
    oldSetup: options.oldSetup ?? false, oldToken: options.oldToken || '',
    autoContinue: options.autoContinue ?? true, desktop: options.desktop ?? true,
    holdDecoration: options.holdDecoration ?? false,
  });
  const requests = [];
  const pending = new Map();
  const loginStatuses = [...(options.loginStatuses || [200])];
  let loginCount = 0;
  await page.route('**/api/**', async route => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    requests.push({ pathname, authorization: request.headers().authorization, body: request.postDataJSON() });
    if (pathname.startsWith('/api/probe/')) {
      pending.set(pathname.slice('/api/probe/'.length), route);
    } else if (pathname === '/api/auth/login') {
      const status = loginStatuses.shift() ?? 200;
      loginCount++;
      await route.fulfill({ status, json: status === 200
        ? { token: `new-token-${loginCount}`, tokenType: 'Bearer', expiresIn: 3600, user: { username: 'admin', role: 'ADMIN' } }
        : { message: 'Incorrect credentials' } });
    } else if (pathname === '/api/auth/me') {
      await route.fulfill({ json: { username: 'admin', role: 'ADMIN' } });
    } else if (pathname === '/api/system/health') {
      await route.fulfill({ json: { status: 'UP' } });
    } else {
      errors.push(`Unexpected API request: ${pathname}`);
      await route.fulfill({ status: 500, json: { message: 'Unexpected fixture request' } });
    }
  });
  const route = options.route || '/tasks?status=RUNNING';
  const desktop = options.desktop ?? true;
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}${desktop ? `/__startup#${route}` : route}`);
  await page.waitForFunction(() => Boolean(window.fixture.flush && document.querySelector('#app').__vue_app__));
  await page.evaluate(() => window.fixture.flush());
  return {
    page, requests,
    emit: (type, data) => page.evaluate(({ type, data }) => window.fixture.sources.at(-1).emit(type, data), { type, data }),
    startProbe: async (id, transport) => {
      await page.evaluate(({ id, transport }) => {
        const f = window.fixture;
        const token = f.readAuthToken();
        f.probes[id] = (transport === 'fetch'
          ? f.apiFetch(f.apiUrl(`/probe/${id}`), { headers: token ? { Authorization: `Bearer ${token}` } : {} })
          : f.api.get(`/probe/${id}`)).then(() => 'resolved', () => 'rejected');
      }, { id, transport });
      for (let attempt = 0; attempt < 100 && !pending.has(id); attempt++) await page.waitForTimeout(20);
      assert.ok(pending.has(id), `Expected held ${transport} probe ${id}`);
    },
    respondProbe: async (id, status = 401) => {
      await pending.get(id).fulfill({ status, json: { message: 'Expired fixture request' } });
      pending.delete(id);
      assert.equal(await page.evaluate(id => window.fixture.probes[id], id), 'rejected');
      await page.evaluate(() => window.fixture.flush());
    },
    close: () => context.close(),
  };
}

async function routeIs(page, path) {
  await page.waitForFunction(expected => window.fixture.router.currentRoute.value.path === expected, path);
  await page.evaluate(() => window.fixture.flush());
}

async function noFeed(page) {
  await page.evaluate(() => window.fixture.flush());
  assert.deepEqual(await page.evaluate(() => window.fixture.feeds), []);
}

async function completeSetup(fixture, manual = false) {
  const { page, emit } = fixture;
  await page.waitForFunction(() => window.fixture.sources.length > 0);
  await emit('message', readyCore);
  await page.getByText('Java', { exact: true }).waitFor();
  assert.equal(await nextButton(page).isDisabled(), true);
  await emit('complete', {});
  if (manual) {
    await page.getByText('核心依赖已满足，可以进入工具箱。', { exact: true }).waitFor();
    await nextButton(page).click();
  }
}

async function login(page, method = 'password') {
  await routeIs(page, '/login');
  if (method === 'password') {
    await page.getByPlaceholder('请输入用户名', { exact: true }).fill('admin');
    await page.getByPlaceholder('请输入密码', { exact: true }).fill('fixture-password');
    await page.getByRole('button', { name: '账号密码登录', exact: true }).click();
  } else {
    await page.getByRole('button', { name: method === 'credentials' ? '使用本机安全凭据登录' : '使用 Windows Hello（PIN）登录', exact: true }).click();
  }
}

async function workspace(page, destination = '/tasks?status=RUNNING') {
  await page.getByTestId('workspace').waitFor();
  assert.equal(await page.evaluate(() => window.fixture.router.currentRoute.value.fullPath), destination);
  await page.waitForFunction(() => window.fixture.feeds.length > 0);
  const feeds = await page.evaluate(() => window.fixture.feeds);
  assert.ok(feeds.every(feed => feed.authorization && !/^\/(setup|login)(?:\?|$)/.test(feed.route)), 'Task feeds must start only in an authenticated workspace');
}

async function check(name, options, run) {
  const fixture = await openFixture(options);
  try {
    await run(fixture);
    console.log('PASS ' + name);
  } catch (error) {
    await fixture.page.screenshot({ path: path.join(output, 'startup-navigation-failure.png'), fullPage: true });
    console.error('FAIL', name, await fixture.page.evaluate(() => ({ route: window.fixture.router.currentRoute.value.fullPath, body: document.body.innerText, navigation: window.fixture.navigation })), errors);
    throw error;
  } finally {
    await fixture.close();
  }
}

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  const Components = (await import('unplugin-vue-components/vite')).default;
  const { ElementPlusResolver } = await import('unplugin-vue-components/resolvers');
  server = await createServer({
    configFile: false, root, cacheDir: path.join(output, 'startup-navigation-cache'),
    plugins: [{
      name: 'startup-workspace-fixtures', enforce: 'pre',
      load(id) {
        const normalized = id.replaceAll('\\', '/');
        if (/\/src\/views\/[^/]+\.vue$/.test(normalized) && !/\/(Setup|Login)\.vue$/.test(normalized))
          return '<template><main data-testid="workspace">Workspace {{ $route.fullPath }}</main></template>';
      },
      configureServer(s) {
        s.middlewares.use(async (req, res, next) => {
          if (req.headers.accept?.includes('text/html') !== true) return next();
          res.setHeader('Content-Type', 'text/html');
          res.end(await s.transformIndexHtml(req.url, html));
        });
      },
    }, vue(), Components({ dts: false, resolvers: [ElementPlusResolver({ importStyle: 'css' })] })],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/dist/**', '**/desktop-release/**'] } },
    logLevel: 'error',
  });
  await server.listen();
  browser = await chromium.launch({
    executablePath: process.env.SETUP_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });

  await check('desktop clears stale completion/token and waits for full setup before login; logout aborts task feed', {
    oldSetup: true, oldToken: 'previous-launch-token', holdDecoration: true,
  }, async f => {
    const { page, emit } = f;
    await routeIs(page, '/setup');
    assert.equal(await page.evaluate(() => localStorage.getItem('security_toolbox_setup_complete_v2')), null);
    assert.equal(await page.evaluate(() => window.fixture.auth().token), '');
    await noFeed(page);
    await emit('message', readyCore);
    await page.getByText('Java', { exact: true }).waitFor();
    await routeIs(page, '/setup');
    assert.equal(await nextButton(page).isDisabled(), true);
    await noFeed(page);
    await emit('complete', {});
    await page.waitForFunction(() => Boolean(window.fixture.finishDecoration));
    await routeIs(page, '/setup');
    await noFeed(page);
    await page.evaluate(() => window.fixture.finishDecoration());
    await routeIs(page, '/login');
    assert.equal(await page.evaluate(() => window.fixture.router.currentRoute.value.query.redirect), '/tasks?status=RUNNING');
    await noFeed(page);
    await login(page);
    await workspace(page);
    assert.deepEqual(await page.evaluate(() => window.fixture.navigation.map(item => item.split('?')[0])), ['/setup', '/login', '/tasks']);
    await page.locator('.desktop-v2-user').click();
    await page.getByRole('menuitem', { name: '注销登录', exact: true }).click();
    await routeIs(page, '/login');
    await page.waitForFunction(() => window.fixture.feeds.every(feed => feed.aborted));
    assert.equal(await page.evaluate(() => window.fixture.auth().token), '');
    assert.equal(await page.evaluate(() => window.fixture.sources.length), 1);
  });

  await check('failed password login preserves final redirect and never restarts setup', { loginStatuses: [401, 200] }, async f => {
    await completeSetup(f);
    await login(f.page);
    await f.page.getByText('用户名或密码错误，请确认后重试', { exact: true }).waitFor();
    await routeIs(f.page, '/login');
    assert.equal(await f.page.evaluate(() => window.fixture.router.currentRoute.value.query.redirect), '/tasks?status=RUNNING');
    await noFeed(f.page);
    await login(f.page);
    await workspace(f.page);
    assert.equal(await f.page.evaluate(() => window.fixture.sources.length), 1);
  });

  for (const transport of ['axios', 'fetch']) {
    await check(`${transport} unauthenticated 401 cannot interrupt setup`, {}, async f => {
      await routeIs(f.page, '/setup');
      await f.emit('message', readyCore);
      await f.startProbe('public-setup', transport);
      await f.respondProbe('public-setup');
      await routeIs(f.page, '/setup');
      assert.equal(await nextButton(f.page).isDisabled(), true);
      assert.equal(await f.page.evaluate(() => window.fixture.sources[0].closed), false);
      await noFeed(f.page);
      await f.emit('complete', {});
      await routeIs(f.page, '/login');
    });

    await check(`${transport} current-token 401 clears expired auth but leaves an active setup check in place`, {}, async f => {
      await routeIs(f.page, '/setup');
      await f.page.evaluate(() => {
        window.fixture.auth().token = 'expired-during-recheck';
        window.fixture.auth().checked = true;
        window.fixture.storeAuthToken('expired-during-recheck', false);
      });
      await f.emit('message', readyCore);
      await f.startProbe('expired-in-setup', transport);
      await f.respondProbe('expired-in-setup');
      await routeIs(f.page, '/setup');
      assert.equal(await f.page.evaluate(() => window.fixture.auth().token), '');
      assert.equal(await f.page.evaluate(() => window.fixture.sources[0].closed), false);
      assert.equal(await nextButton(f.page).isDisabled(), true);
      await noFeed(f.page);
      await f.emit('complete', {});
      await routeIs(f.page, '/login');
    });

    await check(`${transport} current workspace token expiry still logs out and preserves the requested page`, {}, async f => {
      await completeSetup(f);
      await login(f.page);
      await workspace(f.page);
      await f.startProbe('expired-workspace', transport);
      await f.respondProbe('expired-workspace');
      await routeIs(f.page, '/login');
      assert.equal(await f.page.evaluate(() => window.fixture.auth().token), '');
      assert.equal(await f.page.evaluate(() => window.fixture.readAuthToken()), '');
      assert.equal(await f.page.evaluate(() => window.fixture.router.currentRoute.value.query.redirect), '/tasks?status=RUNNING');
      await f.page.waitForFunction(() => window.fixture.feeds.every(feed => feed.aborted));
      assert.equal(await f.page.evaluate(() => window.fixture.sources.length), 1);
    });

    for (const initialToken of ['', 'old-request-token']) {
      await check(`${transport} delayed ${initialToken ? 'old-token' : 'anonymous'} 401 cannot erase a new login`, {}, async f => {
        await routeIs(f.page, '/setup');
        if (initialToken) await f.page.evaluate(token => {
          window.fixture.auth().token = token;
          window.fixture.auth().checked = true;
          window.fixture.storeAuthToken(token, false);
        }, initialToken);
        await f.startProbe('late-request', transport);
        if (initialToken) await f.page.evaluate(() => window.fixture.auth().clear());
        await completeSetup(f);
        await login(f.page);
        await workspace(f.page);
        await f.respondProbe('late-request');
        await workspace(f.page);
        assert.equal(await f.page.evaluate(() => window.fixture.auth().token), 'new-token-1');
        assert.equal(await f.page.evaluate(() => window.fixture.readAuthToken()), 'new-token-1');
        assert.equal(await f.page.evaluate(() => window.fixture.feeds.some(feed => feed.aborted)), false);
      });
    }
  }

  await check('login recheck invalidates completion, blocks back-navigation bypass, and preserves business destination', {}, async f => {
    await completeSetup(f);
    await routeIs(f.page, '/login');
    await f.page.getByRole('button', { name: '重新检测', exact: true }).click();
    await routeIs(f.page, '/setup');
    assert.equal(await f.page.evaluate(() => localStorage.getItem('security_toolbox_setup_complete_v2')), null);
    assert.equal(await f.page.evaluate(() => window.fixture.router.currentRoute.value.query.redirect), '/tasks?status=RUNNING');
    await f.page.evaluate(() => window.fixture.router.push('/login?redirect=%2Ftasks%3Fstatus%3DRUNNING'));
    await routeIs(f.page, '/setup');
    assert.equal(await nextButton(f.page).isDisabled(), true);
    await completeSetup(f);
    await login(f.page);
    await workspace(f.page);
  });

  await check('workspace recheck pauses the feed and returns to the same business page', {}, async f => {
    await completeSetup(f);
    await login(f.page);
    await workspace(f.page);
    await f.page.locator('.desktop-v2-user').click();
    await f.page.getByRole('menuitem', { name: '重新检测系统依赖', exact: true }).click();
    await routeIs(f.page, '/setup');
    assert.equal(await f.page.evaluate(() => localStorage.getItem('security_toolbox_setup_complete_v2')), null);
    await f.page.waitForFunction(() => window.fixture.feeds.every(feed => feed.aborted));
    await completeSetup(f, true);
    await workspace(f.page);
    assert.equal(await f.page.evaluate(() => window.fixture.feeds.length), 2);
  });

  for (const [redirect, destination] of [
    ['/setup', '/'],
    ['/setup?redirect=%2Flogin%3Fredirect%3D%252Ftraffic%253Ftab%253Drequests', '/traffic?tab=requests'],
    ['/login?redirect=%2Fsetup%3Fredirect%3D%252Fprojects%252F42%253Ftab%253Drecon', '/projects/42?tab=recon'],
  ]) {
    await check(`historic login redirect ${redirect} resolves to ${destination}`, { route: `/login?redirect=${encodeURIComponent(redirect)}` }, async f => {
      await routeIs(f.page, '/setup');
      await completeSetup(f);
      await login(f.page);
      await workspace(f.page, destination);
      assert.equal(await f.page.evaluate(() => window.fixture.sources.length), 1);
    });
  }

  await check('a historical nested redirect on the login page itself resolves directly to the workspace', {
    desktop: false, oldSetup: true,
    route: '/login?redirect=' + encodeURIComponent('/setup?redirect=' + encodeURIComponent('/login?redirect=' + encodeURIComponent('/traffic?tab=requests'))),
  }, async f => {
    await routeIs(f.page, '/login');
    assert.equal(await f.page.evaluate(() => window.fixture.sources.length), 0);
    await noFeed(f.page);
    await login(f.page);
    await workspace(f.page, '/traffic?tab=requests');
    assert.equal(await f.page.evaluate(() => window.fixture.sources.length), 0);
  });

  await check('a direct setup URL unwraps its historical nested destination on completion', {
    oldSetup: true, route: '/setup?startup=1&redirect=' + encodeURIComponent('/setup?redirect=' + encodeURIComponent('/login?redirect=' + encodeURIComponent('/projects/42?tab=recon'))),
  }, async f => {
    await routeIs(f.page, '/setup');
    assert.equal(await f.page.evaluate(() => localStorage.getItem('security_toolbox_setup_complete_v2')), null);
    await completeSetup(f);
    await login(f.page);
    await workspace(f.page, '/projects/42?tab=recon');
    assert.equal(await f.page.evaluate(() => window.fixture.sources.length), 1);
  });

  for (const method of ['credentials', 'hello']) {
    await check(`${method} desktop login follows the same completed-setup destination`, {}, async f => {
      await completeSetup(f);
      await noFeed(f.page);
      await login(f.page, method);
      await workspace(f.page);
    });
  }

  await check('web remembered session retains its completed setup and enters the requested workspace', {
    desktop: false, oldSetup: true, oldToken: 'remembered-web-token',
  }, async f => {
    await workspace(f.page);
    assert.equal(await f.page.evaluate(() => window.fixture.sources.length), 0);
    assert.equal(await f.page.evaluate(() => window.fixture.auth().token), 'remembered-web-token');
    assert.equal(f.requests.filter(request => request.pathname === '/api/auth/me').length, 1);
  });

  assert.deepEqual(errors, []);
  console.log('PASS no Vue/browser runtime errors or unexpected API requests');
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
}).finally(async () => {
  await browser?.close();
  await server?.close();
});
