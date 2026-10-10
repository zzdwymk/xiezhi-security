"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

function inside(root, file) {
  const relative = path.relative(path.resolve(root), path.resolve(file));
  return relative === "" || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`));
}
function quotePostgresValue(value, { strftime = false } = {}) {
  const text = String(value).replace(/\\/g, "/");
  // pg_ctl forwards -o via its command launcher. Do not permit quotes, line
  // breaks or environment/shell expansion characters in a diagnostic path.
  const checked = strftime ? text.replace(/%[YmdHMS]/g, "") : text;
  if (/["\r\n\0`$%!]/.test(checked)) throw new Error("PostgreSQL log path contains unsupported command expansion characters");
  return `"${text}"`;
}

function preparePostgresLogPolicy({ runtimeDirectory, dataDirectory, now = new Date(), sessionId = crypto.randomUUID() }) {
  if (!/^[a-zA-Z0-9-]{1,80}$/.test(sessionId)) throw new Error("Invalid PostgreSQL log session id");
  const root = path.join(path.resolve(runtimeDirectory), "postgres");
  if (inside(dataDirectory, root)) throw new Error("PostgreSQL diagnostics must be outside the database cluster");
  const nativeDirectory = path.join(root, "native"), bootstrapDirectory = path.join(root, "bootstrap");
  const id = `${now.toISOString().replace(/[^0-9]/g, "")}-${sessionId}`;
  const prefix = `postgres-${id}-`;
  const bootstrapFile = path.join(bootstrapDirectory, `${prefix}bootstrap.log`);
  const filePattern = `${prefix}%Y%m%d-%H%M%S.log`;
  const settings = { logging_collector: "on", log_destination: "stderr", log_directory: nativeDirectory,
    log_filename: filePattern, log_rotation_size: "20480kB", log_rotation_age: "60min", log_truncate_on_rotation: "off" };
  const options = Object.entries(settings).map(([key, value]) => `-c ${key}=${quotePostgresValue(value, { strftime: key === "log_filename" })}`).join(" ");
  fs.mkdirSync(nativeDirectory, { recursive: true }); fs.mkdirSync(bootstrapDirectory, { recursive: true });
  const policy = { schemaVersion: 1, createdAt: now.toISOString(), sessionId: id, root, nativeDirectory, bootstrapFile,
    filePattern, prefix, dataDirectory: path.resolve(dataDirectory), settings, options,
    collectorBehavior: "Native PostgreSQL size/time rotation; one oversized entry or same-second rotations may exceed the nominal 20 MiB target",
    bootstrapBehavior: "Unique per start; only stderr before logging_collector redirection, never reused across starts",
    retention: "No deletion; only read-only archive planning; preserve bootstrap until owner process is confirmed stopped" };
  fs.writeFileSync(path.join(root, `${prefix}policy.json`), JSON.stringify(policy, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  return policy;
}

function tailFile(file, maxBytes = 32768) {
  const fd = fs.openSync(file, "r");
  try {
    const size = fs.fstatSync(fd).size, bytes = Math.min(size, maxBytes), buffer = Buffer.alloc(bytes);
    const read = fs.readSync(fd, buffer, 0, bytes, size - bytes);
    return buffer.subarray(0, read).toString("utf8").split(/\r?\n/).slice(-12).join("\n");
  } finally { fs.closeSync(fd); }
}
function readPostgresStartupTail(policy) {
  const candidates = [policy.bootstrapFile];
  try {
    const native = fs.readdirSync(policy.nativeDirectory).filter(name => name.startsWith(policy.prefix) && name.endsWith(".log"))
      .map(name => { const file = path.join(policy.nativeDirectory, name); return { file, mtime: fs.statSync(file).mtimeMs }; })
      .sort((a, b) => b.mtime - a.mtime);
    if (native.length) candidates.push(native[0].file);
  } catch (error) { return `[native log index unavailable: ${error.code || error.message}]`; }
  return candidates.map(file => {
    try { return `${file}\n${tailFile(file)}`; }
    catch (error) { return `${file}\n[log unavailable: ${error.code || error.message}]`; }
  }).join("\n");
}

function planPostgresLogArchives({ policy, processRunning, currentLogfiles }) {
  const plan = { schemaVersion: 1, readOnly: true, deleteAuthorized: false, root: policy.root,
    candidates: [], protected: [], warnings: [], requiresFreshProcessAndHashVerification: true };
  const active = new Set();
  if (processRunning === true) {
    for (const line of String(currentLogfiles || "").split(/\r?\n/)) {
      const match = /^stderr\s+(.+)$/.exec(line);
      if (match) active.add(path.resolve(policy.dataDirectory, match[1]));
    }
  }
  const knownState = processRunning === false || (processRunning === true && active.size > 0 && [...active].every(file => inside(policy.nativeDirectory, file)));
  for (const directory of [policy.nativeDirectory, path.dirname(policy.bootstrapFile)]) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (!entry.name.startsWith(policy.prefix) || !entry.name.endsWith(".log")) continue;
      const file = path.join(directory, entry.name), stat = fs.lstatSync(file);
      const record = { path: file, bytes: stat.size, modifiedAt: stat.mtime.toISOString() };
      const reason = !knownState ? "PostgreSQL owner/current log file is unknown" : !stat.isFile() || stat.isSymbolicLink() ? "Special or symlink entry" : active.has(file) ? "Current native collector file" : file === policy.bootstrapFile && processRunning !== false ? "Bootstrap handle may still be inherited by PostgreSQL" : null;
      if (reason) plan.protected.push({ ...record, reason });
      else plan.candidates.push({ ...record, action: "Archive/pin review only; no raw-file deletion" });
      if (stat.size > 20 * 1024 * 1024) plan.warnings.push({ ...record, reason: "Native rotation target exceeded; preserve bytes and review large entries/rotation cadence" });
    }
  }
  return plan;
}

module.exports = { preparePostgresLogPolicy, readPostgresStartupTail, planPostgresLogArchives, quotePostgresValue };
