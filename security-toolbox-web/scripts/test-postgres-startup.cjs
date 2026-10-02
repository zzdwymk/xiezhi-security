const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// Exercise the actual Electron startup function without loading Electron or
// touching the user's cluster, settings, credentials, or running processes.
const mainSource = fs.readFileSync(path.join(__dirname, "../electron/main.cjs"), "utf8");
const start = mainSource.indexOf("async function startDesktopPostgres(");
const end = mainSource.indexOf("async function ensureDesktopPostgresRunning(", start);
assert.ok(start >= 0 && end > start, "PostgreSQL startup function must exist");
const startupSource = mainSource.slice(start, end);

async function verifyStartup(platform, dataDir) {
  const platformPath = platform === "win32" ? path.win32 : path.posix;
  const binDir = platform === "win32" ? "C:\\Tool Box\\postgres\\bin" : "/opt/toolbox/postgres/bin";
  const userData = platform === "win32" ? "C:\\Users\\Test\\AppData\\Roaming\\toolbox" : "/tmp/toolbox-test";
  const calls = [];
  const config = Object.freeze({ port: 15432, host: "127.0.0.1" });
  let readinessChecks = 0;
  const context = vm.createContext({
    path: platformPath,
    process: { platform },
    app: { getPath: () => userData },
    fs: { mkdirSync: () => {} },
    spawn: (executable, args, options) => {
      calls.push({ executable, args: Array.from(args), options });
      return { on: () => {}, unref: () => {} };
    },
    pgSqlReady: async (received) => {
      assert.equal(received, config);
      readinessChecks++;
      return true;
    },
    pgSleep: async () => { throw new Error("Ready database must not sleep"); },
    UserFacingError: Error,
  });
  vm.runInContext(startupSource, context);
  await context.startDesktopPostgres(binDir, dataDir, config);
  assert.equal(calls.length, 1);
  assert.equal(readinessChecks, 1, "TCP readiness must still be verified with SQL");
  const call = calls[0];
  assert.equal(call.executable, platformPath.join(binDir, "pg_ctl.exe"));
  assert.equal(call.args[call.args.indexOf("-D") + 1], dataDir, "existing cluster must be reused");
  assert.equal(call.args.at(-1), "start");
  assert.equal(call.options.windowsHide, true);
  assert.equal(call.options.stdio, "ignore");
  const postgresOptions = call.args[call.args.indexOf("-o") + 1];
  assert.match(postgresOptions, /^-p 15432 -h 127\.0\.0\.1 /);
  if (platform === "win32") {
    assert.equal(postgresOptions, "-p 15432 -h 127.0.0.1 -c unix_socket_directories=");
    assert.ok(!postgresOptions.includes(dataDir), "Windows must not create a socket in the profile path");
  } else {
    assert.ok(postgresOptions.endsWith(`-k "${dataDir}"`));
  }
}

(async () => {
  await verifyStartup("win32", "C:\\Users\\Test\\AppData\\Roaming\\security-toolbox-desktop\\postgresql-cluster");
  await verifyStartup("win32", "C:\\Users\\测试 用户\\" + "long-profile-".repeat(12) + "\\postgresql-cluster");
  await verifyStartup("linux", "/tmp/toolbox test/postgresql-cluster");
  console.log("PostgreSQL startup: 3 platform/path cases passed; existing cluster and TCP SQL readiness preserved.");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
