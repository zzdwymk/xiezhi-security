// Real Setup.vue and Vue Router, isolated SSE/HTTP/desktop fixtures. No local backend is used.
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
const missingCore = { name: 'Nmap', required: true, installed: false, status: 'missing' };
const missingOptional = { name: 'Metasploit', required: false, installed: false, status: 'missing' };
const dependencyManifest = dependencies => dependencies.map(({ name, required }) => ({
  name, required, category: required ? 'core' : 'optional',
  installed: null, status: null, version: null, path: null,
}));
const nextButton = page => page.getByRole('button', { name: '下一步，进入工具箱', exact: true });
const autoCheckbox = page => page.getByRole('checkbox', { name: '下次依赖满足时自动进入', exact: true });
const html = `<!doctype html><html><head><meta charset="utf-8"></head><body><div id="app"></div><script type="module">
import {createApp, h, nextTick} from 'vue';
import {createRouter, createMemoryHistory, RouterView} from 'vue-router';
import ElementPlus from 'element-plus';
import 'element-plus/dist/index.css';
import Setup from '/src/views/Setup.vue';
const router = createRouter({history:createMemoryHistory(),routes:[
  {path:'/',redirect:'/login'},
  {path:'/setup',component:Setup},
  {path:'/login',component:{render:()=>h('div',{'data-testid':'destination'},'工具箱登录')}},
  {path:'/other',component:{render:()=>h('div',{'data-testid':'other'},'其他页面')}}
]});
window.fixture.router = router;
window.fixture.flush = async () => {
  await nextTick();
  await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  await nextTick();
};
await router.push('/setup?startup=1');
await router.isReady();
createApp(RouterView).use(router).use(ElementPlus).mount('#app');
</script></body></html>`;

async function openFixture(options = {}) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(({ autoContinue, holdDecoration }) => {
    localStorage.clear();
    localStorage.setItem('security_toolbox_setup_auto_continue_v1', String(autoContinue));
    const fixture = window.fixture = { sources: [], holdDecoration, decorationCalls: 0 };
    const originalTimeout = window.setTimeout.bind(window);
    // Trigger the actual stream deadline deterministically, without waiting 90 real seconds.
    window.setTimeout = (callback, delay, ...args) => {
      const id = originalTimeout(callback, delay, ...args);
      if (delay === 90_000) fixture.expireStream = () => {
        clearTimeout(id);
        callback(...args);
      };
      return id;
    };
    window.EventSource = class extends EventTarget {
      constructor(url) {
        super();
        this.url = url;
        this.closed = false;
        fixture.sources.push(this);
      }
      close() { this.closed = true; }
      emit(type, data) {
        const event = new MessageEvent(type, { data: typeof data === 'string' ? data : JSON.stringify(data) });
        if (type === 'message') this.onmessage?.(event);
        else if (type === 'error') this.onerror?.(event);
        else this.dispatchEvent(event);
      }
    };
    window.toolboxDesktop = {
      getToolsDirectory: async () => {
        fixture.decorationCalls++;
        if (fixture.holdDecoration) await new Promise(resolve => fixture.finishDecoration = resolve);
        return 'C:/setup-test/tools';
      },
      listInstallableDependencies: async () => [],
      chooseToolsDirectory: async () => ({ changed: true, toolsDirectory: 'C:/setup-test/new-tools' }),
      resetToolsDirectory: async () => ({ changed: true, toolsDirectory: 'C:/setup-test/tools' }),
    };
  }, { autoContinue: options.autoContinue ?? true, holdDecoration: options.holdDecoration ?? false });
  const pending = [];
  const requests = [];
  await page.route('**/api/**', async route => {
    const api = new URL(route.request().url()).pathname;
    requests.push(api);
    if (api === '/api/system/dependencies') pending.push(route);
    else {
      errors.push(`Unexpected API request: ${api}`);
      await route.fulfill({ status: 500, json: { message: 'Unexpected fixture request' } });
    }
  });
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__setup`);
  await page.waitForFunction(() => window.fixture.sources.length === 1 && Boolean(window.fixture.flush));
  await autoCheckbox(page).waitFor({ state: 'attached' });
  return {
    page, requests,
    emit: (type, data) => page.evaluate(({ type, data }) => window.fixture.sources.at(-1).emit(type, data), { type, data }),
    respond: async (data, status = 200) => {
      await waitForFallback(pending, page);
      const response = page.waitForResponse(result => new URL(result.url()).pathname === '/api/system/dependencies');
      await pending.shift().fulfill({ status, json: data });
      await (await response).finished();
    },
    waitFallback: () => waitForFallback(pending, page),
    close: () => context.close(),
  };
}

// Wait for the intercepted request itself; a paused response must leave setup blocked.
async function waitForFallback(pending, page) {
  for (let attempt = 0; attempt < 80 && !pending.length; attempt++) await page.waitForTimeout(25);
  assert.ok(pending.length, 'Stream interruption must request the full HTTP dependency result');
}

async function stayOnSetup(page, disabled = true) {
  await page.evaluate(() => window.fixture.flush());
  assert.equal(await page.evaluate(() => window.fixture.router.currentRoute.value.path), '/setup');
  assert.equal(await page.evaluate(() => localStorage.getItem('security_toolbox_setup_complete_v2')), null);
  assert.equal(await nextButton(page).isDisabled(), disabled);
}

async function entered(page) {
  await page.getByTestId('destination').waitFor();
  assert.equal(await page.evaluate(() => window.fixture.router.currentRoute.value.path), '/login');
  assert.equal(await page.evaluate(() => localStorage.getItem('security_toolbox_setup_complete_v2')), 'true');
}

async function dependencyRows(page) {
  await page.evaluate(() => window.fixture.flush());
  return page.locator('.dependency-row').evaluateAll(rows => rows.map(row => ({
    name: row.querySelector('.dep-main b')?.textContent.trim(),
    status: row.querySelector('.el-tag')?.textContent.trim(),
  })));
}

async function dependencyCounts(page) {
  return page.locator('.dependency-group-head em').evaluateAll(counts =>
    counts.map(count => count.textContent.replace(/\s+/g, ' ').trim()));
}

async function check(name, options, run) {
  const fixture = await openFixture(options);
  try {
    await run(fixture);
    console.log('PASS ' + name);
  } finally {
    await fixture.close();
  }
}

(async () => {
  const { createServer } = await import('vite');
  const vue = (await import('@vitejs/plugin-vue')).default;
  server = await createServer({
    configFile: false, root, cacheDir: path.join(output, 'setup-auto-continue-cache'),
    plugins: [vue(), {
      name: 'setup-auto-continue-fixture',
      configureServer(s) {
        s.middlewares.use(async (req, res, next) => {
          if (req.url !== '/__setup') return next();
          res.setHeader('Content-Type', 'text/html');
          res.end(await s.transformIndexHtml(req.url, html));
        });
      },
    }],
    server: { host: '127.0.0.1', port: 0, hmr: false, watch: { ignored: ['**/dist/**', '**/desktop-release/**'] } },
    logLevel: 'error',
  });
  await server.listen();
  browser = await chromium.launch({
    executablePath: process.env.SETUP_TEST_BROWSER || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    headless: true,
  });

  await check('manifest renders every row once and unordered results update stable rows and totals', { autoContinue: false }, async ({ page, emit, requests }) => {
    const allReady = [
      readyCore,
      { ...missingCore, installed: true, status: 'ready' },
      { name: 'Afrog', required: false, installed: true, status: 'ready' },
      { ...missingOptional, installed: true, status: 'ready' },
    ];
    await emit('manifest', dependencyManifest(allReady));
    assert.deepEqual(await dependencyRows(page), allReady.map(({ name }) => ({ name, status: '检测中' })));
    assert.deepEqual(await dependencyCounts(page), ['0 / 2 可用', '0 / 2 可用']);
    assert.equal(await page.locator('.el-alert--warning').count(), 0, 'Pending core tools must not be reported missing');
    assert.equal(await page.getByText('缺失', { exact: true }).count(), 0);
    assert.equal(await page.getByRole('button', { name: '下载并安装', exact: true }).count(), 0);
    assert.equal(await page.getByText('暂不支持', { exact: true }).count(), 0);
    assert.equal(await page.getByText('Metasploit 正在检测', { exact: true }).count(), 0, 'No separate Metasploit placeholder may be appended');
    await stayOnSetup(page);
    await page.evaluate(() => window.fixture.manifestRows = Array.from(document.querySelectorAll('.dependency-row')));

    const completed = new Set();
    for (const result of [allReady[3], allReady[1], allReady[2], allReady[0]]) {
      await emit('message', result);
      completed.add(result.name);
      assert.deepEqual(await dependencyRows(page), allReady.map(({ name }) => ({ name, status: completed.has(name) ? '可用' : '检测中' })));
      assert.deepEqual(await dependencyCounts(page), [
        `${allReady.filter(item => item.required && completed.has(item.name)).length} / 2 可用`,
        `${allReady.filter(item => !item.required && completed.has(item.name)).length} / 2 可用`,
      ]);
      assert.equal(await page.evaluate(() => {
        const currentRows = Array.from(document.querySelectorAll('.dependency-row'));
        return currentRows.length === window.fixture.manifestRows.length &&
          currentRows.every((row, index) => row === window.fixture.manifestRows[index]);
      }), true, 'Results must update existing rows without moving or replacing their DOM nodes');
      assert.equal(await page.getByText('Metasploit', { exact: true }).count(), 1);
      assert.equal(await page.locator('.el-alert--warning').count(), 0);
      await stayOnSetup(page);
    }
    await emit('complete', {});
    await page.getByText('核心依赖已满足，可以进入工具箱。', { exact: true }).waitFor();
    await stayOnSetup(page, false);
    assert.deepEqual(requests, []);

    await page.getByRole('button', { name: '重新检测', exact: true }).click();
    await page.waitForFunction(() => window.fixture.sources.length === 2);
    const nextManifest = [allReady[0], allReady[1], allReady[3], { name: 'Xray', required: false }];
    await emit('manifest', dependencyManifest(nextManifest));
    assert.deepEqual(await dependencyRows(page), nextManifest.map(({ name }) => ({ name, status: '检测中' })));
    assert.deepEqual(await dependencyCounts(page), ['0 / 2 可用', '0 / 2 可用']);
    assert.equal(await page.getByText('Afrog', { exact: true }).count(), 0, 'A new manifest must not retain removed tools or stale ready states');
    assert.equal(await page.locator('.el-alert--warning').count(), 0);
    await stayOnSetup(page);
  });

  for (const pendingDependency of [missingCore, missingOptional]) {
    await check(`complete with pending ${pendingDependency.required ? 'core' : 'optional'} manifest entries waits for HTTP fallback`, {}, async ({ page, emit, waitFallback, respond, requests }) => {
      await emit('manifest', dependencyManifest([readyCore, pendingDependency]));
      await emit('message', readyCore);
      assert.deepEqual(await dependencyRows(page), [
        { name: readyCore.name, status: '可用' },
        { name: pendingDependency.name, status: '检测中' },
      ]);
      await emit('complete', {});
      await waitFallback();
      await stayOnSetup(page);
      assert.equal(await page.evaluate(() => window.fixture.sources[0].closed), true);
      assert.equal(await page.evaluate(() => window.fixture.decorationCalls), 0, 'An incomplete manifest cannot reach successful-check decoration');
      await respond({ dependencies: [readyCore, pendingDependency], developmentMode: false });
      if (pendingDependency.required) {
        await page.getByText('请先安装缺失的核心依赖，再重新检测。', { exact: true }).waitFor();
        await stayOnSetup(page);
      } else {
        await entered(page);
      }
      assert.deepEqual(requests, ['/api/system/dependencies']);
    });
  }

  await check('invalid manifest cannot seed dependency rows and falls back to the complete HTTP result', {}, async ({ page, emit, respond, requests }) => {
    await emit('manifest', { dependencies: dependencyManifest([readyCore]) });
    await stayOnSetup(page);
    await respond({ dependencies: [readyCore], developmentMode: false });
    await entered(page);
    assert.deepEqual(requests, ['/api/system/dependencies']);
  });

  await check('auto-continue waits for complete and desktop decoration; missing optional tools are allowed', { holdDecoration: true }, async ({ page, emit, requests }) => {
    assert.equal(await autoCheckbox(page).isChecked(), true);
    await stayOnSetup(page);
    await emit('message', readyCore);
    await page.getByText('Java', { exact: true }).waitFor();
    await stayOnSetup(page);
    await emit('message', missingOptional);
    await stayOnSetup(page);
    await emit('complete', {});
    await page.waitForFunction(() => Boolean(window.fixture.finishDecoration));
    await stayOnSetup(page);
    await page.evaluate(() => window.fixture.finishDecoration());
    await entered(page);
    assert.deepEqual(requests, []);
  });

  for (const interruption of ['error', 'timeout']) {
    await check(`${interruption} after ready core waits for HTTP fallback and respects missing core`, {}, async ({ page, emit, waitFallback, respond, requests }) => {
      await emit('message', readyCore);
      await stayOnSetup(page);
      if (interruption === 'timeout') await page.evaluate(() => window.fixture.expireStream());
      else await emit('error', {});
      await waitFallback();
      await stayOnSetup(page);
      assert.equal(await page.evaluate(() => window.fixture.sources[0].closed), true);
      // A queued complete from the abandoned stream cannot release the HTTP check.
      await emit('complete', {});
      await stayOnSetup(page);
      await respond({ dependencies: [readyCore, missingCore], developmentMode: false });
      await page.getByText('请先安装缺失的核心依赖，再重新检测。', { exact: true }).waitFor();
      await stayOnSetup(page);
      assert.deepEqual(requests, ['/api/system/dependencies']);
    });
  }

  await check('HTTP fallback failure cannot mark setup complete', {}, async ({ page, emit, respond }) => {
    await emit('message', readyCore);
    await emit('error', {});
    await respond({ message: 'Dependency service unavailable' }, 503);
    await page.getByText('后端依赖检查失败（HTTP 503）。', { exact: true }).waitFor();
    await stayOnSetup(page);
  });

  await check('unchecked auto-continue permits manual navigation only after the full check', { autoContinue: false }, async ({ page, emit }) => {
    assert.equal(await autoCheckbox(page).isChecked(), false);
    await stayOnSetup(page);
    await emit('message', readyCore);
    await stayOnSetup(page);
    await emit('complete', {});
    await page.getByText('核心依赖已满足，可以进入工具箱。', { exact: true }).waitFor();
    await stayOnSetup(page, false);
    await nextButton(page).click();
    await entered(page);
  });

  for (const transport of ['stream', 'HTTP']) {
    await check(`empty ${transport} result cannot advance`, {}, async ({ page, emit, respond }) => {
      if (transport === 'stream') await emit('complete', {});
      else {
        await emit('message', readyCore);
        await emit('error', {});
        await respond({ dependencies: [], developmentMode: true });
      }
      await page.getByText('依赖检查未返回有效结果，请重新检测。', { exact: true }).waitFor();
      await stayOnSetup(page);
    });
  }

  await check('development mode does not automatically bypass missing core dependencies', {}, async ({ page, emit }) => {
    await emit('message', readyCore);
    await emit('message', missingCore);
    await emit('complete', {});
    await page.getByText('开发模式允许依赖不完整时继续，部分检测任务可能无法执行。', { exact: true }).waitFor();
    await stayOnSetup(page, false);
  });

  await check('malformed stream result falls back and complete HTTP results can automatically advance', {}, async ({ page, emit, respond }) => {
    await emit('message', readyCore);
    await emit('message', '{invalid json');
    await stayOnSetup(page);
    await respond({ dependencies: [readyCore, missingOptional], developmentMode: false });
    await entered(page);
  });

  await check('a new check clears previous completion before enabling auto-continue', { autoContinue: false }, async ({ page, emit }) => {
    await emit('message', readyCore);
    await emit('complete', {});
    await page.getByText('核心依赖已满足，可以进入工具箱。', { exact: true }).waitFor();
    await stayOnSetup(page, false);
    await page.getByRole('button', { name: '重新检测', exact: true }).click();
    await page.waitForFunction(() => window.fixture.sources.length === 2);
    await page.getByText('下次依赖满足时自动进入', { exact: true }).click();
    assert.equal(await page.evaluate(() => localStorage.getItem('security_toolbox_setup_auto_continue_v1')), 'true');
    await stayOnSetup(page);
    await emit('message', readyCore);
    await stayOnSetup(page);
    await emit('complete', {});
    await entered(page);
  });

  await check('an old HTTP result cannot complete a new check after changing the tools directory', {}, async ({ page, emit, waitFallback, respond }) => {
    await emit('message', readyCore);
    await emit('error', {});
    await waitFallback();
    await page.getByRole('button', { name: '选择目录', exact: true }).click();
    await page.waitForFunction(() => window.fixture.sources.length === 2);
    await respond({ dependencies: [readyCore], developmentMode: false });
    await stayOnSetup(page);
    assert.equal(await page.getByText('Java', { exact: true }).count(), 0);
    await emit('message', readyCore);
    await stayOnSetup(page);
    await emit('complete', {});
    await entered(page);
  });

  await check('leaving setup closes the stream and discards late completion', {}, async ({ page, emit, requests }) => {
    await emit('message', readyCore);
    await page.evaluate(() => window.fixture.router.push('/other'));
    await page.getByTestId('other').waitFor();
    assert.equal(await page.evaluate(() => window.fixture.sources[0].closed), true);
    await emit('complete', {});
    await emit('error', {});
    await page.evaluate(() => window.fixture.flush());
    assert.equal(await page.evaluate(() => window.fixture.router.currentRoute.value.path), '/other');
    assert.equal(await page.evaluate(() => localStorage.getItem('security_toolbox_setup_complete_v2')), null);
    assert.deepEqual(requests, []);
  });

  await check('a completed stream cannot navigate after setup unmounts during desktop decoration', { holdDecoration: true }, async ({ page, emit }) => {
    await emit('message', readyCore);
    await emit('complete', {});
    await page.waitForFunction(() => Boolean(window.fixture.finishDecoration));
    await page.evaluate(() => window.fixture.router.push('/other'));
    await page.getByTestId('other').waitFor();
    await page.evaluate(() => window.fixture.finishDecoration());
    await page.evaluate(() => window.fixture.flush());
    assert.equal(await page.evaluate(() => window.fixture.router.currentRoute.value.path), '/other');
    assert.equal(await page.evaluate(() => localStorage.getItem('security_toolbox_setup_complete_v2')), null);
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
