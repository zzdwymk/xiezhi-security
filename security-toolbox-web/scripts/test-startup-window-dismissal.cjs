const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// 启动页（startup.html）必须无条件在主窗口出现时消失。
//
// 回归背景：启动页原先只在 mainWindow 的 ready-to-show 里 close()，而主窗口首帧一旦
// 被拖到 85 秒（开发模式下 Vite 首次依赖预构建叠加后端冷启动），回调就不会执行，
// 启动页会一直浮在最上面，看起来像"卡在检测工具依赖这一步"。这里把 main.cjs 里
// 真实的 dismissStartupWindow / createStartupWindow / createMainWindow 抽出来，用
// 假的 BrowserWindow 跑三条路径：正常显示、首帧超时兜底、启动页渲染进程崩溃/无响应。
const mainSource = fs.readFileSync(
  path.join(__dirname, "../electron/main.cjs"),
  "utf8",
);

const fallbackSource = (mainSource.match(/const MAIN_WINDOW_FIRST_PAINT_FALLBACK_MS = ([^;]+);/) || [])[1];
// 常量本身是表达式（60 * 1000）：在同一个上下文里求值，保证断言用的是真实上限。
const fallbackValue = fallbackSource ? Function(`return (${fallbackSource});`)() : NaN;
const sourceConstants = `const MAIN_WINDOW_FIRST_PAINT_FALLBACK_MS = ${fallbackSource};`;

class FakeWebContents {
  constructor() {
    this.handlers = new Map();
    this.destroyed = false;
    this.scripts = [];
  }
  on(event, handler) {
    this.handlers.set(event, handler);
  }
  setWindowOpenHandler() {}
  isDestroyed() {
    return this.destroyed;
  }
  executeJavaScript(script) {
    this.scripts.push(script);
    return Promise.resolve();
  }
  emit(event, ...args) {
    const handler = this.handlers.get(event);
    if (handler) handler(...args);
  }
}

class FakeWindow {
  constructor() {
    this.events = new Map();
    this.webContents = new FakeWebContents();
    this.visible = false;
    this.destroyed = false;
    this.calls = [];
  }
  isDestroyed() {
    return this.destroyed;
  }
  isVisible() {
    return this.visible;
  }
  show() {
    if (this.destroyed) throw new Error("Object has been destroyed");
    this.calls.push("show");
    this.visible = true;
  }
  hide() {
    this.calls.push("hide");
    this.visible = false;
  }
  close() {
    this.calls.push("close");
  }
  destroy() {
    this.calls.push("destroy");
    this.destroyed = true;
    this.visible = false;
  }
  moveTop() {
    this.calls.push("moveTop");
  }
  focus() {
    this.calls.push("focus");
  }
  loadURL(url) {
    this.calls.push(`loadURL:${url}`);
  }
  loadFile(file) {
    this.calls.push(`loadFile:${file}`);
  }
  on(event, handler) {
    this.events.set(event, handler);
  }
  once(event, handler) {
    this.events.set(event, handler);
  }
  emit(event, ...args) {
    const handler = this.events.get(event);
    if (handler) return handler(...args);
    return undefined;
  }
}

function buildHarness() {
  const diagnostics = [];
  const immediates = [];
  const timers = [];
  const windows = [];
  const webRequest = { onBeforeSendHeaders: () => {} };
  const theme = {
    dark: false,
    captionMode: "auto",
    windowMaterial: "none",
    transparencyEnabled: false,
    highContrast: false,
  };
  const context = {
    process: { env: { TOOLBOX_DEV_URL: "http://127.0.0.1:5199" }, platform: "win32" },
    console,
    JSON,
    Map,
    Promise,
    URL,
    setTimeout: (callback, delay) => {
      const timer = { callback, delay, cancelled: false };
      timers.push(timer);
      return timer;
    },
    clearTimeout: (timer) => {
      timer.cancelled = true;
    },
    setImmediate: (callback) => {
      immediates.push(callback);
      return immediates.length;
    },
    electronSession: {
      fromPartition: () => ({ webRequest }),
      defaultSession: { webRequest },
    },
    app: { getAppPath: () => "C:\\app", isPackaged: false },
    BrowserWindow: function BrowserWindow() {
      const window = new FakeWindow();
      windows.push(window);
      return window;
    },
    shell: { openExternal: () => {} },
    path: path.win32,
    __dirname: "C:\\app\\electron",
    WINDOW_ICON: "icon.ico",
    currentSystemTheme: () => theme,
    titleBarOverlay: () => ({}),
    windowBackgroundColor: () => "#ffffff",
    sharedChromeSurface: () => ({ accent: "#0078d4" }),
    applyWindowIcon: () => {},
    applySystemThemeToStaticWindow: () => {},
    applyMotionToStartupWindow: () => {},
    isTrustedLocalFileUrl: () => true,
    isTrustedMainRendererUrl: () => true,
    closeCaptureBrowser: async () => {},
    closeIcpBrowser: () => {},
    writeDesktopStartupDiagnostic: (stage, error, detail) => {
      diagnostics.push({ stage, message: String(error?.message || error), detail });
    },
    writeDesktopStartupLog: (stage, message) => {
      diagnostics.push({ stage, message });
    },
  };
  vm.createContext(context);
  const start = mainSource.indexOf("function dismissStartupWindow(");
  const end = mainSource.indexOf("\nasync function boot(");
  assert.ok(start >= 0 && end > start, "main.cjs 必须包含启动页/主窗口的创建函数");
  vm.runInContext(
    [
      // 被 let 声明的模块级窗口变量要先在作用域里存在，片段才能引用它们。
      "let mainWindow;",
      "let startupWindow;",
      "let captureBrowserWindow;",
      sourceConstants,
      mainSource.slice(start, end),
      // 取回被 let 声明的模块级变量，便于断言。
      "globalThis.readStartup = () => startupWindow;",
      "globalThis.readMain = () => mainWindow;",
    ].join("\n"),
    context,
  );
  return {
    context,
    diagnostics,
    timers,
    windows,
    flushImmediates: () => {
      while (immediates.length) immediates.shift()();
    },
  };
}

async function settle() {
  for (let index = 0; index < 8; index += 1) await Promise.resolve();
}

/** 模拟一次完整启动：先创建启动页，再创建主窗口。 */
function bootWindows(harness) {
  harness.context.createStartupWindow();
  const startup = harness.windows.at(-1);
  startup.show();
  assert.equal(harness.context.readStartup(), startup);
  harness.context.createMainWindow(18080);
  const main = harness.windows.at(-1);
  assert.equal(harness.context.readMain(), main);
  assert.notEqual(main, startup);
  return { startup, main };
}

function assertStartupGone(harness, startup, reason) {
  assert.equal(harness.context.readStartup(), undefined, `${reason}：必须清空全局 startupWindow`);
  assert.ok(startup.calls.includes("hide"), `${reason}：必须先立即隐藏启动页`);
  harness.flushImmediates();
  assert.ok(startup.calls.includes("destroy"), `${reason}：close() 未生效时必须 destroy() 兜底`);
  assert.equal(startup.isDestroyed(), true, `${reason}：启动页最终必须被销毁`);
}

async function normalPath() {
  const harness = buildHarness();
  const { startup, main } = bootWindows(harness);
  const fallbackTimer = harness.timers.at(-1);
  assert.equal(fallbackTimer.delay, fallbackValue);
  assert.ok(fallbackValue <= 60_000, "首帧兜底上限不应超过 1 分钟");
  main.emit("ready-to-show");
  await settle();
  assert.deepEqual(
    main.calls.filter((call) => !call.startsWith("load")),
    ["show", "moveTop", "focus"],
    "主窗口必须显示、抬到顶层并抢回焦点",
  );
  assert.ok(
    main.webContents.scripts.some((script) => script.includes("--shared-chrome-surface")),
    "共享窗口背景色仍需在主窗口显示前写入",
  );
  assertStartupGone(harness, startup, "正常显示");
  assert.equal(fallbackTimer.cancelled, true, "主窗口显示后必须取消首帧兜底计时器");
}

async function firstPaintTimeoutPath() {
  const harness = buildHarness();
  const { startup, main } = bootWindows(harness);
  // 主窗口渲染进程始终不产生首帧：ready-to-show 不会触发。
  harness.timers.at(-1).callback();
  await settle();
  assert.ok(main.calls.includes("show"), "首帧超时后必须强制显示主窗口");
  assertStartupGone(harness, startup, "首帧超时兜底");
  assert.ok(
    harness.diagnostics.some((item) => item.stage === "main-window-reveal-fallback"),
    "兜底路径必须留下诊断日志",
  );
  // 兜底已经关闭启动页之后，迟到的首帧不得重新弹出启动页或让流程出错。
  main.emit("ready-to-show");
  await settle();
  assert.equal(startup.calls.filter((call) => call === "show").length, 1);
}

async function lateSplashReadyToShow() {
  const harness = buildHarness();
  harness.context.createStartupWindow();
  const startup = harness.windows.at(-1);
  // 主窗口已先显示（例如首帧兜底），启动页自己的 ready-to-show 迟到。
  harness.context.createMainWindow(18080);
  const main = harness.windows.at(-1);
  main.show();
  startup.emit("ready-to-show");
  assert.ok(!startup.calls.includes("show"), "主窗口已显示时不得再显示启动页");
  assert.equal(startup.isDestroyed(), false, "迟到回调不得触碰已销毁的启动页");
}

function brokenStartupRenderer() {
  for (const [event, reason] of [
    ["render-process-gone", "crashed"],
    ["unresponsive", "hang"],
  ]) {
    const harness = buildHarness();
    harness.context.createStartupWindow();
    const startup = harness.windows.at(-1);
    startup.emit("ready-to-show");
    assert.ok(startup.calls.includes("show"), "主窗口未显示时启动页必须正常显示");
    if (event === "render-process-gone")
      startup.webContents.emit(event, {}, { reason, exitCode: 5 });
    else startup.webContents.emit(event);
    assertStartupGone(harness, startup, `启动页 ${event}`);
    const expected =
      event === "render-process-gone" ? "startup-renderer-gone" : "startup-renderer-unresponsive";
    assert.ok(
      harness.diagnostics.some((item) => item.stage === expected),
      `启动页 ${event} 必须写入诊断日志`,
    );
  }
}

// 静态守卫：关闭启动页只能走 dismissStartupWindow，且 start.bat 不再直接 close()。
assert.ok(
  !/mainWindow\.show\(\);[\s\S]{0,80}startupWindow\.close\(\)/.test(mainSource),
  "主窗口显示后不得再直接 startupWindow.close()，必须走 dismissStartupWindow",
);

(async () => {
  assert.ok(Number.isFinite(fallbackValue) && fallbackValue > 0, "首帧兜底常量必须存在");
  await normalPath();
  await firstPaintTimeoutPath();
  await lateSplashReadyToShow();
  brokenStartupRenderer();
  console.log(
    "PASS 启动页关闭：正常显示 / 首帧超时兜底 / 迟到 ready-to-show / 渲染进程崩溃与无响应",
  );
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
