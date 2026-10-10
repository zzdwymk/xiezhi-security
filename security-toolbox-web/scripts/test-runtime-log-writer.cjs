"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const { PassThrough } = require("node:stream");
const { spawnSync } = require("node:child_process");
const { RuntimeLogWriter, inspectRuntimeRecovery, atomicJson } = require("../electron/runtime-log-writer.cjs");

async function temporary(t) {
  if (process.env.QA_LOGGING_FIXTURES_ROOT) {
    const base = path.resolve(process.env.QA_LOGGING_FIXTURES_ROOT); await fs.promises.mkdir(base, { recursive: true });
    const root = await fs.promises.mkdtemp(path.join(base, 'runtime-')); t.diagnostic('Retained auxiliary fixture: ' + root); return root;
  }
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), "toolbox-runtime-log-test-"));
  t.after(async () => {
    assert(path.dirname(root) === path.resolve(os.tmpdir()) && path.basename(root).startsWith("toolbox-runtime-log-test-"));
    await fs.promises.rm(root, { recursive: true, force: true });
  });
  return root;
}
test("AUXILIARY: byte-exact size rotation and gzip proofs survive reopening", async t => {
  const directory = await temporary(t);
  const input = crypto.randomBytes(32791);
  const writer = new RuntimeLogWriter({ directory, component: "server.out", maxVolumeBytes: 4096 });
  assert.equal(writer.write(input), true);
  const [closed, concurrentClose] = await Promise.all([writer.close(), writer.close()]);
  assert.deepEqual(closed, concurrentClose);
  assert.equal(closed.closedVolumes, Math.ceil(input.length / 4096));
  assert.equal(closed.status, "CLOSED");
  assert.equal(closed.writtenBytes, input.length);
  assert.equal(closed.omittedBytes, 0);
  const receipts = (await fs.promises.readdir(directory)).filter(name => name.endsWith(".log.json")).sort();
  const restored = [];
  for (const receipt of receipts) {
    const proof = JSON.parse(await fs.promises.readFile(path.join(directory, receipt)));
    const gzip = await fs.promises.readFile(proof.payloadPath);
    const raw = zlib.gunzipSync(gzip);
    assert(raw.length <= 4096);
    assert.equal(crypto.createHash("sha256").update(raw).digest("hex"), proof.sha256);
    assert.equal(crypto.createHash("sha256").update(gzip).digest("hex"), proof.compressedSha256);
    restored.push(raw);
  }
  assert.deepEqual(Buffer.concat(restored), input);
  assert.equal((await inspectRuntimeRecovery(directory)).complete, true);
  const before = await fs.promises.readdir(directory);
  const second = new RuntimeLogWriter({ directory, component: "server.out" });
  second.write("new session\n"); await second.close();
  for (const name of before) assert(fs.existsSync(path.join(directory, name)));
});

test("AUXILIARY: queue limit reports omissions and child pipe remains drainable", async t => {
  const directory = await temporary(t), faults = [];
  const writer = new RuntimeLogWriter({ directory, component: "ai.err", maxQueueBytes: 8, onFault: error => faults.push(error) });
  const pipe = new PassThrough();
  writer.attach(pipe);
  assert.equal(writer.write("123456789"), false);
  assert.equal(writer.status().queuedBytes, 0);
  await assert.rejects(writer.close(), /pipe still active/);
  pipe.end("ok");
  await new Promise(resolve => pipe.once("end", resolve));
  const status = await writer.close();
  assert.equal(status.omittedBytes, 9);
  assert.equal(status.omittedChunks, 1);
  assert.equal(status.status, "DEGRADED");
  assert.equal(status.writtenBytes, 2);
  assert.equal(faults[0].code, "DIAGNOSTIC_QUEUE_OVERFLOW");
  assert.equal(pipe.destroyed, true); // normal stream auto-destroy after end
  assert.equal((await inspectRuntimeRecovery(directory)).complete, false);
});

test("AUXILIARY: injected ENOSPC is explicit and preserves recoverable raw volume", async t => {
  const directory = await temporary(t), faults = [];
  const writer = new RuntimeLogWriter({ directory, component: "electron", onFault: error => faults.push(error) });
  await writer.openVolume();
  writer.handle.write = async () => { throw Object.assign(new Error("disposable-copy ENOSPC injection"), { code: "ENOSPC" }); };
  writer.write("necessary-to-observe-failure");
  await writer.flush();
  assert.equal(writer.status().fatal, true);
  assert.equal(writer.status().firstFault.code, "ENOSPC");
  assert.equal(writer.status().omittedBytes, Buffer.byteLength("necessary-to-observe-failure"));
  assert.equal(faults.length, 1);
  await writer.close();
  const recovery = await inspectRuntimeRecovery(directory);
  assert.equal(recovery.complete, false);
  assert(recovery.recoverable.some(item => item.path.endsWith(".log")));
});

test("AUXILIARY: real filesystem open failure reaches caller and fault callback", async t => {
  const root = await temporary(t), directory = path.join(root, "not-a-directory"), faults = [];
  await fs.promises.writeFile(directory, "preserve this file");
  const writer = new RuntimeLogWriter({ directory, component: "electron", onFault: fault => faults.push(fault) });
  writer.write("failure");
  await assert.rejects(writer.close());
  assert.equal(writer.status().fatal, true);
  assert(faults.length > 0);
  assert.equal(await fs.promises.readFile(directory, "utf8"), "preserve this file");
});

test("AUXILIARY: isolated abrupt helper exit retains raw bytes and marks recovery uncertain", async t => {
  const directory = await temporary(t);
  const modulePath = path.resolve(__dirname, "../electron/runtime-log-writer.cjs");
  const script = `const {RuntimeLogWriter}=require(${JSON.stringify(modulePath)});(async()=>{const w=new RuntimeLogWriter({directory:${JSON.stringify(directory)},component:'crash'});w.write('saved-before-abrupt-exit');await w.flush();process.exit(29);})()`;
  const result = spawnSync(process.execPath, ["-e", script], { windowsHide: true, encoding: "utf8" });
  assert.equal(result.status, 29, result.stderr);
  const recovery = await inspectRuntimeRecovery(directory);
  assert.equal(recovery.complete, false);
  const raw = recovery.recoverable.find(item => item.path.endsWith(".log"));
  assert.equal(await fs.promises.readFile(raw.path, "utf8"), "saved-before-abrupt-exit");
  const second = new RuntimeLogWriter({ directory, component: "crash" });
  second.write("after restart"); await second.close();
  assert.equal(await fs.promises.readFile(raw.path, "utf8"), "saved-before-abrupt-exit");
});

test("AUXILIARY: Windows atomic replacement retries are bounded and never delete previous target", async t => {
  const root = await temporary(t), file = path.join(root, "status.json");
  await atomicJson(file, { version: "old" });
  const delays = [], faults = ["EPERM", "EACCES", "EBUSY"];
  let calls = 0;
  await atomicJson(file, { version: "new" }, {
    wait: async delay => { delays.push(delay); },
    rename: async (from, to) => {
      const code = faults[calls++];
      if (code) {
        assert.equal(JSON.parse(await fs.promises.readFile(file)).version, "old");
        throw Object.assign(new Error("transient Windows replace fault"), { code });
      }
      return fs.promises.rename(from, to);
    },
  });
  assert.deepEqual(delays, [10, 25, 50]);
  assert.equal(calls, 4);
  assert.equal(JSON.parse(await fs.promises.readFile(file)).version, "new");
  calls = 0;
  await assert.rejects(atomicJson(file, { version: "unpublished" }, {
    wait: async () => {},
    rename: async () => { calls++; throw Object.assign(new Error("persistent replace denial"), { code: "EPERM" }); },
  }), /persistent replace denial/);
  assert.equal(calls, 6);
  assert.equal(JSON.parse(await fs.promises.readFile(file)).version, "new");
  assert((await fs.promises.readdir(root)).some(name => name.endsWith(".partial")));
});

test("AUXILIARY: persistent status replacement failure becomes DEGRADED and leaves old status", async t => {
  const directory = await temporary(t), faults = [];
  const writer = new RuntimeLogWriter({ directory, component: "replace", onFault: fault => faults.push(fault) });
  writer.write("retained bytes before replace failure");
  await writer.flush();
  const before = await fs.promises.readFile(writer.statusFile);
  const rename = fs.promises.rename;
  fs.promises.rename = async (from, to) => {
    if (to === writer.statusFile) throw Object.assign(new Error("injected persistent status EPERM"), { code: "EPERM" });
    return rename(from, to);
  };
  try { await assert.rejects(writer.close(), /persistent status EPERM/); }
  finally { fs.promises.rename = rename; }
  assert.equal(writer.status().status, "DEGRADED");
  assert.equal(writer.status().fatal, true);
  assert.equal(faults[0].code, "LOG_STATUS_WRITE_FAILED");
  assert.deepEqual(await fs.promises.readFile(writer.statusFile), before);
  assert.equal((await inspectRuntimeRecovery(directory)).complete, false);
});

test("AUXILIARY: required diagnostics spill without omitting a cross-queue error and retain byte order", async t => {
  const directory = await temporary(t), faults = [];
  const writer = new RuntimeLogWriter({ directory, component: "required", required: true,
    maxQueueBytes: 4, maxVolumeBytes: 4096, onFault: fault => faults.push(fault) });
  const before = Buffer.from("pre\n"), originalError = Buffer.from("FIRST ERROR\n" + "original stack and response\n".repeat(2000));
  assert.equal(writer.write(before), true);
  assert.equal(writer.write(originalError), true);
  assert.equal(writer.write("END\n"), true);
  const status = await writer.close();
  assert.equal(status.omittedBytes, 0);
  assert.equal(status.omittedChunks, 0);
  assert.equal(status.missingRequiredBytes, 0);
  assert.equal(status.writtenBytes, before.length + originalError.length + 4);
  assert(status.requiredCompressedVolumes > 1);
  const receipts = [];
  for (const name of await fs.promises.readdir(directory)) if (name.endsWith(".log.json")) receipts.push(JSON.parse(await fs.promises.readFile(path.join(directory, name))));
  receipts.sort((a, b) => (a.segment === b.segment ? a.sequence - b.sequence : a.segment === "async" ? -1 : 1));
  const restored = Buffer.concat(await Promise.all(receipts.map(async receipt => zlib.gunzipSync(await fs.promises.readFile(receipt.payloadPath)))));
  assert.deepEqual(restored, Buffer.concat([before, originalError, Buffer.from("END\n")]));
  assert.equal(faults[0].code, "REQUIRED_DURABLE_FALLBACK");
});

test("AUXILIARY: required async write failure retries unwritten error bytes through durable spill", async t => {
  const directory = await temporary(t);
  const writer = new RuntimeLogWriter({ directory, component: "required-recovery", required: true });
  await writer.openVolume();
  writer.handle.write = async () => { throw Object.assign(new Error("isolated async handle failure"), { code: "EIO" }); };
  writer.write("first complete error must survive");
  const status = await writer.close();
  assert.equal(status.missingRequiredBytes, 0);
  assert.equal(status.omittedBytes, 0);
  assert.equal(status.writtenBytes, Buffer.byteLength("first complete error must survive"));
  const receiptFile = (await fs.promises.readdir(directory)).find(name => name.includes("-required-") && name.endsWith(".log.json"));
  const receipt = JSON.parse(await fs.promises.readFile(path.join(directory, receiptFile)));
  assert.equal(zlib.gunzipSync(await fs.promises.readFile(receipt.payloadPath)).toString(), "first complete error must survive");
  assert.equal(status.fatal, true); // original async failure remains visible
});
