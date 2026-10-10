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
