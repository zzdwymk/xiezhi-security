const assert = require("node:assert/strict");
const http = require("node:http");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const { test } = require("node:test");
const { createDesktopDevRunner } = require("../electron/dev-runner.cjs");

function listen(server, port) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.removeListener("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.removeListener("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, "127.0.0.1");
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error && error.code !== "ERR_SERVER_NOT_RUNNING") reject(error);
      else resolve();
    });
  });
}

function harness({ createError, listenError, spawnError, platform = "win32" } = {}) {
  const calls = [], kills = [], errors = [], exitCodes = [];
  const runtime = new EventEmitter();
  runtime.platform = platform;
  runtime.env = { npm_execpath: "fixture-npm.cjs", PRESERVED_ENV: "test" };
  let resolveExit;
  const exited = new Promise((resolve) => { resolveExit = resolve; });
  runtime.exit = (code) => {
    exitCodes.push(code);
    runtime.emit("exit", code);
    resolveExit(code);
  };
  const child = new EventEmitter();
  Object.assign(child, { pid: 123456, exitCode: null, signalCode: null });
  child.kill = (signal) => {
    kills.push({ pid: child.pid, signal });
    child.signalCode = signal;
    child.emit("exit", null, signal);
  };
  let closeCount = 0;
  const httpServer = http.createServer((_request, response) => response.end("owned-vite"));
  const runner = createDesktopDevRunner({
    runtime,
    electronPath: "fixture-electron.exe",
    logger: { error: (error) => errors.push(error) },
    createViteServer: async (options) => {
      assert.equal(options.server.host, "127.0.0.1");
      assert.equal(options.server.port, 5173);
      assert.equal(options.server.strictPort, false);
      if (createError) throw createError;
      return {
        httpServer,
        async listen() {
          if (listenError) throw listenError;
          for (let port = options.server.port; ; port++) {
            try { await listen(httpServer, port); return; }
            catch (error) { if (error.code !== "EADDRINUSE") throw error; }
          }
        },
        async close() { closeCount++; await close(httpServer); },
      };
    },
    spawnProcess: (executable, args, options) => {
      if (spawnError) throw spawnError;
      assert.equal(httpServer.listening, true, "Electron must wait for its own Vite listener");
      calls.push({ executable, args, options });
      return child;
    },
    spawnSyncProcess: (executable, args, options) => {
      kills.push({ executable, args, options });
      assert.equal(executable, "taskkill.exe");
      assert.deepEqual(args, ["/PID", String(child.pid), "/T", "/F"]);
      assert.equal(options.windowsHide, true);
      child.signalCode = "SIGTERM";
      child.emit("exit", null, "SIGTERM");
    },
  });
  return { runner, calls, kills, errors, exitCodes, exited, child, runtime, httpServer,
    get closeCount() { return closeCount; } };
}

test("occupied 5173 cannot select an old frontend; Electron uses this runner's listener", { timeout: 10000 }, async (t) => {
  let oldRequests = 0;
  const oldServer = http.createServer((_request, response) => { oldRequests++; response.end("old-vite"); });
  try {
    await listen(oldServer, 5173);
    t.after(() => close(oldServer));
  } catch (error) {
    // Another local process may already own 5173. Preserve it and still verify
    // the runner opens its own socket without contacting the shared listener.
    if (error.code !== "EADDRINUSE") throw error;
  }
  const state = harness();
  t.after(() => state.runner.stop());
  await state.runner.run();
  assert.equal(state.calls.length, 1);
  const call = state.calls[0];
  assert.equal(call.executable, "fixture-electron.exe");
  assert.deepEqual(call.args, ["."]);
  const url = new URL(call.options.env.TOOLBOX_DEV_URL);
  assert.equal(url.hostname, "127.0.0.1");
  assert.notEqual(url.port, "5173");
  assert.equal(Number(url.port), state.httpServer.address().port);
  assert.equal(call.options.env.PRESERVED_ENV, "test");
  assert.equal(call.options.env.TOOLBOX_PROJECT_ROOT, call.options.cwd);
  assert.equal(await (await fetch(url)).text(), "owned-vite");
  assert.equal(oldRequests, 0);
});

for (const phase of ["create", "listen"]) {
  test(`Vite ${phase} failure never starts Electron`, { timeout: 10000 }, async () => {
    const failure = new Error(`fixture-${phase}-failure`);
    const state = harness({ [phase === "create" ? "createError" : "listenError"]: failure });
    await state.runner.run();
    assert.deepEqual(state.calls, []);
    assert.deepEqual(state.kills, []);
    assert.deepEqual(state.errors, [failure]);
    assert.deepEqual(state.exitCodes, [1]);
    assert.equal(state.closeCount, phase === "create" ? 0 : 1);
    assert.equal(state.httpServer.listening, false);
  });
}

test("Electron spawn failure closes the owned Vite server", { timeout: 10000 }, async () => {
  const failure = new Error("fixture-spawn-failure");
  const state = harness({ spawnError: failure });
  await state.runner.run();
  assert.deepEqual(state.errors, [failure]);
  assert.deepEqual(state.exitCodes, [1]);
  assert.equal(state.closeCount, 1);
  assert.equal(state.httpServer.listening, false);
});

test("Electron asynchronous startup error cleans up only its own process and server", { timeout: 10000 }, async () => {
  const state = harness();
  await state.runner.run();
  state.child.emit("error", new Error("fixture-child-error"));
  assert.equal(await state.exited, 1);
  assert.equal(state.kills.length, 1);
  assert.equal(state.closeCount, 1);
  assert.equal(state.httpServer.listening, false);
});

test("Electron exit preserves its status and releases Vite without killing an exited PID", { timeout: 10000 }, async () => {
  const state = harness();
  await state.runner.run();
  state.child.exitCode = 7;
  state.child.emit("exit", 7);
  assert.equal(await state.exited, 7);
  assert.deepEqual(state.kills, []);
  assert.equal(state.closeCount, 1);
  assert.equal(state.httpServer.listening, false);
});

for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143]]) {
  test(`${signal} closes Vite and terminates only this runner's Electron once`, { timeout: 10000 }, async () => {
    const state = harness();
    await state.runner.run();
    state.runtime.emit(signal);
    assert.equal(await state.exited, code);
    await state.runner.stop();
    assert.equal(state.kills.length, 1);
    assert.equal(state.closeCount, 1);
    assert.deepEqual(state.exitCodes, [code]);
  });
}

test("non-Windows shutdown signals only the Electron child", { timeout: 10000 }, async () => {
  const state = harness({ platform: "linux" });
  await state.runner.run();
  await state.runner.stop();
  assert.deepEqual(state.kills, [{ pid: state.child.pid, signal: "SIGTERM" }]);
  assert.equal(state.closeCount, 1);
});

test("real Vite loads project config and passes its actual fallback port to simulated Electron", { timeout: 20000 }, async (t) => {
  const { createServer } = await import("vite");
  const oldServer = http.createServer((_request, response) => response.end("old-vite"));
  try {
    await listen(oldServer, 5173);
    t.after(() => close(oldServer));
  } catch (error) {
    if (error.code !== "EADDRINUSE") throw error;
  }
  const runtime = new EventEmitter();
  runtime.env = { npm_execpath: "fixture-npm.cjs" };
  runtime.platform = process.platform;
  const exitCodes = [];
  runtime.exit = (code) => exitCodes.push(code);
  let vite, desktopUrl;
  const runner = createDesktopDevRunner({
    runtime,
    electronPath: "fixture-electron.exe",
    logger: { error: (error) => { throw error; } },
    createViteServer: async (options) => {
      vite = await createServer({
        ...options,
        logLevel: "silent",
        // Keep project config resolution real without scanning dependencies or
        // keeping filesystem watchers alive in this isolated socket test.
        optimizeDeps: { noDiscovery: true, include: [] },
        server: { ...options.server, watch: null, hmr: false },
      });
      return vite;
    },
    spawnProcess: (_executable, _args, options) => {
      desktopUrl = options.env.TOOLBOX_DEV_URL;
      return new EventEmitter();
    },
    spawnSyncProcess: () => { throw new Error("No real process may be killed"); },
  });
  t.after(() => runner.stop());
  await runner.run();
  assert.equal(path.resolve(vite.config.configFile), path.resolve(__dirname, "../vite.config.ts"));
  assert.ok(desktopUrl, "Vite must finish binding before simulated Electron starts");
  assert.notEqual(new URL(desktopUrl).port, "5173");
  assert.equal(Number(new URL(desktopUrl).port), vite.httpServer.address().port);
  assert.equal((await fetch(desktopUrl, { headers: { Accept: "text/x-vite-ping" } })).status, 204);
  await runner.stop();
  assert.equal(vite.httpServer.listening, false);
  assert.deepEqual(exitCodes, [0]);
});
