"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");
const vm = require("node:vm");
const { spawn } = require("node:child_process");
const { createRuntimeLogManager, runtimeLogDirectory } = require("../electron/runtime-log-manager.cjs");
const { diagnosticError } = require("../electron/public-error.cjs");
async function temporary(t) {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), "toolbox-log-integration-"));
  t.after(async () => {
    assert(path.dirname(root) === path.resolve(os.tmpdir()) && path.basename(root).startsWith("toolbox-log-integration-"));
    await fs.promises.rm(root, { recursive: true, force: true });
  });
  return root;
}
async function restore(directory) {
  const records = [];
  for (const name of await fs.promises.readdir(directory)) if (name.endsWith(".log.json")) records.push(JSON.parse(await fs.promises.readFile(path.join(directory, name))));
  records.sort((a, b) => a.segment === b.segment ? a.sequence - b.sequence : a.segment === "async" ? -1 : 1);
  return Buffer.concat(await Promise.all(records.map(async ref => zlib.gunzipSync(await fs.promises.readFile(ref.payloadPath)))));
}
test("AUXILIARY: real disposable child stdout/stderr drain fully before manager close", async t => {
  const root = await temporary(t), profilePath = path.join(root, "business-profile"), notices = [];
  await fs.promises.mkdir(profilePath);
  await fs.promises.writeFile(path.join(profilePath, "conversation.json"), "unchanged business data");
  const manager = createRuntimeLogManager({ profilePath, onFault: fault => notices.push(fault), writerOptions: { maxQueueBytes: 32, maxVolumeBytes: 4096 } });
  const stdout = "complete stdout error\n".repeat(3000), stderr = "complete stderr error\n".repeat(3000);
  const child = spawn(process.execPath, ["-e", "process.stdout.write('complete stdout error\\n'.repeat(3000));process.stderr.write('complete stderr error\\n'.repeat(3000));"], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  manager.attachChild(child, "service");
  const final = await manager.close();
  assert.equal(final.activeChildren, 0);
  assert.equal((await restore(path.join(manager.directory, "service.out"))).toString(), stdout);
  assert.equal((await restore(path.join(manager.directory, "service.err"))).toString(), stderr);
  assert.equal(await fs.promises.readFile(path.join(profilePath, "conversation.json"), "utf8"), "unchanged business data");
  assert(notices.some(fault => fault.code === "REQUIRED_DURABLE_FALLBACK"));
  assert.equal(JSON.parse(await fs.promises.readFile(manager.healthFile)).status, "DEGRADED");
  assert.throws(() => runtimeLogDirectory(profilePath, path.join(profilePath, "logs")), /outside/);
});

test("AUXILIARY: Settings runtime-log browser is confined to the log root and tails safely", async t => {
  const root = await temporary(t), profilePath = path.join(root, "business-profile");
  await fs.promises.mkdir(profilePath);
  const manager = createRuntimeLogManager({ profilePath, baseDirectory: path.join(root, "runtime-logs") });
  manager.write("logging", "first line\nsecond line\nthird line\n");
  await manager.flush();
  const source = await fs.promises.readFile(path.join(__dirname, "../electron/main.cjs"), "utf8");
  const begin = source.indexOf("// ---- Runtime log access");
  const end = source.indexOf('handleRendererIpc("toolbox:get-runtime-logs"');
  assert(begin > 0 && end > begin, "runtime log helpers must stay extractable");
  class UserFacingError extends Error {}
  const opened = [];
  const context = vm.createContext({
    fs, path, Buffer, UserFacingError, console,
    require: name => { assert.equal(name, "zlib"); return zlib; },
    desktopRuntimeLogs: () => manager,
    shell: { openPath: async target => { opened.push(target); return ""; } },
    RUNTIME_LOG_MAX_READ_BYTES: 2 * 1024 * 1024, RUNTIME_LOG_MAX_ENTRIES: 400,
    RUNTIME_LOG_ALLOWED_NAME: /^[A-Za-z0-9][A-Za-z0-9._-]{0,180}$/,
  });
  vm.runInContext(source.slice(begin, end) + "\nthis.list=listRuntimeLogs;this.read=readRuntimeLog;this.open=openRuntimeLogDirectory;this.assertPath=assertRuntimeLogPath;", context);
  const listing = await context.list();
  assert.equal(listing.directory, manager.directory);
  // Sessions with only metadata (no raw/archive payload) must never be listed.
  assert.ok(listing.entries.every(entry => entry.kind === "raw" || entry.kind === "archive"), "only readable sessions are listed");
  const rawComponent = listing.entries.find(entry => entry.kind === "raw");
  assert(rawComponent, "a raw text log must be listed from its component subdirectory");
  assert.equal(rawComponent.relativePath.split("/").length, 2, "relativePath is component/file");
  assert.match(rawComponent.label, /第 001 段/, "sessions get a friendly label instead of the UUID filename");
  assert.equal(rawComponent.encoding, "text");
  const content = await context.read(rawComponent.relativePath);
  assert.match(content.text, /third line/, "the newest line must be present in the read");
  assert.equal(content.truncated, false, "small logs are read whole");
  assert.equal(content.encoding, "text");
  // Traversal must be rejected before any filesystem touch.
  for (const bad of ["../escape.log", "..", "", "nested/../../x.log"]) {
    assert.throws(() => context.assertPath(bad), /路径/, `must reject ${JSON.stringify(bad)}`);
  }
  assert.throws(() => context.assertPath(path.join(root, "outside.log")), /路径/);
  // Round 324：日志根目录内的链接（junction/symlink）不得指向外部目录。
  const outsideDir = path.join(root, "outside-logs");
  await fs.promises.mkdir(outsideDir, { recursive: true });
  await fs.promises.writeFile(path.join(outsideDir, "secret.log"), "TOP SECRET\n");
  const linkPath = path.join(manager.directory, "linked");
  let linkCreated = false;
  try {
    await fs.promises.symlink(outsideDir, linkPath, "junction");
    linkCreated = true;
  } catch {
    linkCreated = false;
  }
  if (linkCreated) {
    await assert.rejects(
      () => context.read("linked/secret.log"),
      /路径|不合法/,
      "日志目录内的链接不得逃逸到根目录之外",
    );
  }
  await context.open();
  assert.equal(opened.at(-1), manager.directory);
  await manager.close();
});

test("AUXILIARY: current main logging helpers retain long original stack and show native fault even with muted notifications", async t => {
  const root = await temporary(t), profilePath = path.join(root, "business-profile"), dialogs = [];
  await fs.promises.mkdir(profilePath);
  const source = await fs.promises.readFile(path.join(__dirname, "../electron/main.cjs"), "utf8");
  const snippet = "let runtimeLogManager; const shownRuntimeLogFaultSeverities = new Set();\n" + source.slice(source.indexOf("function reportRuntimeLogFault("), source.indexOf("function waitForAiRuntime("));
  assert(snippet.includes("writeDesktopStartupDiagnostic"));
  const context = vm.createContext({ createRuntimeLogManager, diagnosticError, console,
    app: { getPath: () => profilePath, whenReady: () => Promise.resolve() },
    process: { env: { TOOLBOX_RUNTIME_LOG_ROOT: path.join(profilePath, "invalid-log-location") } },
    mainWindow: null, startupWindow: null, notificationCenter: { show: () => ({ delivered: false, reason: "disabled" }) },
    dialog: { showMessageBox: async options => { dialogs.push(options); return { response: 0 }; } },
  });
  vm.runInContext(snippet + "\nthis.logs = desktopRuntimeLogs; this.record = writeDesktopStartupDiagnostic;", context);
  const error = new Error("FIRST ORIGINAL FAILURE " + "x".repeat(6000));
  context.record("original-failure", error, { approvalId: 60, originalStatus: "failed" });
  const manager = context.logs(); await manager.close();
  const retained = JSON.parse((await restore(path.join(manager.directory, "desktop-startup"))).toString());
  assert.equal(retained.message, diagnosticError(error));
  assert.equal(retained.stack, error.stack);
  assert.equal(retained.approvalId, 60);
  assert(dialogs.some(dialog => dialog.title === "运行日志保存异常"));
  assert.equal(JSON.parse(await fs.promises.readFile(manager.healthFile)).status, "DEGRADED");
});
