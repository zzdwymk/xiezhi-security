"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const { PassThrough } = require("node:stream");
const { EventEmitter } = require("node:events");
const { spawnSync } = require("node:child_process");
const { preparePostgresLogPolicy, readPostgresStartupTail, planPostgresLogArchives } = require("../electron/postgres-log-policy.cjs");
const { observeMigrationProgress } = require("../electron/migration-progress-stream.cjs");
async function temporary(t) {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), "toolbox-native-log-test-"));
  t.after(async () => {
    assert(path.dirname(root) === path.resolve(os.tmpdir()) && path.basename(root).startsWith("toolbox-native-log-test-"));
    await fs.promises.rm(root, { recursive: true, force: true });
  });
  return root;
}

test("AUXILIARY: PostgreSQL native policy isolates starts, preserves old bootstrap and only plans closed files", async t => {
  const root = await temporary(t), dataDirectory = path.join(root, "cluster");
  await fs.promises.mkdir(dataDirectory); await fs.promises.writeFile(path.join(dataDirectory, "business.db"), "original database fixture");
  const first = preparePostgresLogPolicy({ runtimeDirectory: path.join(root, "runtime with spaces"), dataDirectory });
  await fs.promises.writeFile(first.bootstrapFile, "first original startup failure\n");
  const second = preparePostgresLogPolicy({ runtimeDirectory: path.join(root, "runtime with spaces"), dataDirectory });
  assert.notEqual(first.bootstrapFile, second.bootstrapFile);
  assert.equal(first.settings.logging_collector, "on");
  assert.equal(first.settings.log_rotation_size, "20480kB");
  assert.equal(first.settings.log_rotation_age, "60min");
  assert.equal(first.settings.log_truncate_on_rotation, "off");
  const current = path.join(first.nativeDirectory, `${first.prefix}20261006-120100.log`), closed = path.join(first.nativeDirectory, `${first.prefix}20261006-120000.log`);
  await fs.promises.writeFile(current, "current native file"); await fs.promises.writeFile(closed, "closed raw original log");
  const plan = planPostgresLogArchives({ policy: first, processRunning: true, currentLogfiles: `stderr ${current}\n` });
  assert.equal(plan.deleteAuthorized, false);
  assert.deepEqual(plan.candidates.map(item => item.path), [closed]);
  assert(plan.protected.some(item => item.path === first.bootstrapFile));
  assert.equal(planPostgresLogArchives({ policy: first, processRunning: true }).candidates.length, 0);
  assert.equal(planPostgresLogArchives({ policy: first, processRunning: false }).candidates.length, 3);
  assert(readPostgresStartupTail(first).includes("first original startup failure"));
  assert.equal(await fs.promises.readFile(first.bootstrapFile, "utf8"), "first original startup failure\n");
  assert.equal(await fs.promises.readFile(path.join(dataDirectory, "business.db"), "utf8"), "original database fixture");
});

test("AUXILIARY: current main pg_ctl launch keeps original network/socket/ignore-stdio and adds only diagnostic options", async t => {
  const root = await temporary(t), source = await fs.promises.readFile(path.join(__dirname, "../electron/main.cjs"), "utf8");
  const snippet = source.slice(source.indexOf("async function startDesktopPostgres("), source.indexOf("async function ensureDesktopPostgresRunning("));
  const launches = [], faults = [];
  const context = vm.createContext({ preparePostgresLogPolicy, readPostgresStartupTail, path,
    process: { platform: "win32" }, UserFacingError: Error, diagnosticError: error => error.message,
    desktopRuntimeLogs: () => ({ directory: path.join(root, "runtime"), recordFault: (...args) => faults.push(args) }),
    spawn: (file, args, options) => { launches.push({ file, args, options }); const child = new EventEmitter(); child.unref = () => {}; return child; },
    pgSqlReady: async () => true, pgSleep: async () => { throw new Error("SQL should be ready in this mock"); },
  });
  vm.runInContext(snippet + "\nthis.start = startDesktopPostgres;", context);
  const dataDirectory = path.join(root, "cluster");
  await context.start(path.join(root, "postgres-bin"), dataDirectory, { port: 15432, host: "127.0.0.1" });
  assert.equal(launches.length, 1);
  assert.deepEqual(Array.from(launches[0].args.slice(0, 2)), ["-D", dataDirectory]);
  assert.equal(launches[0].options.stdio, "ignore");
  assert.equal(launches[0].options.windowsHide, true);
  assert.equal(launches[0].args.at(-1), "start");
  const options = launches[0].args[launches[0].args.indexOf("-o") + 1];
  assert(options.startsWith("-p 15432 -h 127.0.0.1 -c unix_socket_directories= "));
  assert(options.includes('logging_collector="on"'));
  assert(options.includes('log_truncate_on_rotation="off"'));
  assert.equal(faults.length, 0);
});

test("AUXILIARY: bundled PostgreSQL supports every native logging setting through read-only --describe-config", t => {
  const binary = path.join(__dirname, "../desktop-release/win-unpacked/tools/postgres/pgsql/bin/postgres.exe");
  if (!fs.existsSync(binary)) return t.skip("Standalone source checkout has no bundled PostgreSQL runtime");
  const result = spawnSync(binary, ["--describe-config"], { encoding: "utf8", windowsHide: true });
  assert.equal(result.status, 0, result.stderr);
  const keys = new Set(result.stdout.split(/\r?\n/).map(line => line.split("\t")[0]));
  for (const key of ["logging_collector", "log_destination", "log_directory", "log_filename", "log_rotation_size", "log_rotation_age", "log_truncate_on_rotation"]) assert(keys.has(key), key);
});

test("AUXILIARY: migration progress reuses stdout across UTF-8 and marker boundaries without a duplicate file", async () => {
  const stream = new PassThrough(), messages = [], faults = [];
  const observer = observeMigrationProgress(stream, { onProgress: text => messages.push(text), onFault: error => faults.push(error) });
  const expected = ["开始导入🙂", "全部导入完成，事务已提交。"];
  const bytes = Buffer.from(`INFO other ignored\n2026 INFO LegacyPostgresCopier : MIGRATE: ${expected[0]}\nMIGRATE: ${expected[1]}\n`);
  const ended = new Promise(resolve => stream.once("end", resolve));
  for (const byte of bytes) stream.write(Buffer.from([byte]));
  stream.end(); await ended;
  assert.deepEqual(messages, expected);
  assert.equal(faults.length, 0);
  assert.equal(observer.state().bufferedCharacters, 0);
  assert.equal(observer.state().stopped, true);
});

test("AUXILIARY: oversized migration error forwards bounded fragments without discarding content or closing the source", async () => {
  const stream = new PassThrough(), messages = [];
  const observer = observeMigrationProgress(stream, { maxFragmentCharacters: 32, onProgress: text => messages.push(text) });
  const original = "原始失败🙂".repeat(1000);
  stream.write(Buffer.from("MIGRATE: " + original));
  assert(observer.state().bufferedCharacters <= 32);
  const ended = new Promise(resolve => stream.once("end", resolve)); stream.end("\n"); await ended;
  assert.equal(messages.join(""), original);
  assert(messages.every(message => message.length <= 32));
  assert.equal(observer.state().stopped, true);
});
