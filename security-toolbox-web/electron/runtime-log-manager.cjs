"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { RuntimeLogWriter, atomicJson } = require("./runtime-log-writer.cjs");

function runtimeLogDirectory(profilePath, baseDirectory) {
  const profile = path.resolve(profilePath);
  if (baseDirectory && !path.isAbsolute(baseDirectory)) throw new Error("TOOLBOX_RUNTIME_LOG_ROOT must be an absolute path");
  const base = path.resolve(baseDirectory || path.join(path.dirname(profile), "security-toolbox-runtime-logs"));
  const relative = path.relative(profile, base);
  if (relative === "" || (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`))) throw new Error("Runtime logs must be outside the business profile");
  const identity = crypto.createHash("sha256").update(process.platform === "win32" ? profile.toLowerCase() : profile).digest("hex").slice(0, 24);
  return path.join(base, identity);
}

function createRuntimeLogManager({ profilePath, baseDirectory, onFault, writerOptions = {} }) {
  const directory = runtimeLogDirectory(profilePath, baseDirectory);
  const profile = path.resolve(profilePath);
  const healthFile = path.join(directory, "runtime-logging-health.json");
  const writers = new Set(), startup = new Map(), children = new Map(), faults = new Map();
  let closing = false, closed = false, healthDirty = false, healthTask, closePromise;
  const report = (component, fault) => {
    const key = `${component}/${fault.code}`;
    const prior = faults.get(key);
    faults.set(key, { ...fault, component, firstSeen: prior?.firstSeen || fault.at, count: (prior?.count || 0) + 1 });
    if (!prior) {
      try { onFault?.({ ...fault, component, directory, healthFile }); } catch {}
    }
    persistHealth();
  };
  function status() {
    return { schemaVersion: 1, profile, directory, healthFile, updatedAt: new Date().toISOString(),
      status: faults.size ? "DEGRADED" : closed ? "CLOSED" : closing ? "CLOSING" : "OPEN", faults: [...faults.values()],
      activeChildren: children.size, activeWriters: writers.size,
      collectionPolicy: "required-runtime-with-durable-overflow", businessDataTouched: false };
  }
  function persistHealth() {
    healthDirty = true;
    if (healthTask) return healthTask;
    healthTask = (async () => {
      while (healthDirty) {
        healthDirty = false;
        await fs.promises.mkdir(directory, { recursive: true });
        await atomicJson(healthFile, status());
      }
    })().catch(error => {
      const failure = { component: "logging-health", code: "RUNTIME_HEALTH_WRITE_FAILED", message: error.message,
        at: new Date().toISOString(), fatal: true, directory, healthFile };
      const first = !faults.has("logging-health/persistence");
      faults.set("logging-health/persistence", failure);
      try { process.stderr.write(`[runtime-logging] ${failure.code}: ${failure.message}\n`); } catch {}
      if (first) { try { onFault?.(failure); } catch {} }
    }).finally(() => { healthTask = undefined; });
    return healthTask;
  }
  function createWriter(component) {
    if (closing) throw new Error("Runtime logging is closing");
    const writer = new RuntimeLogWriter({ ...writerOptions, directory: path.join(directory, component), component,
      required: true, onFault: fault => report(component, fault) });
    writers.add(writer);
    return writer;
  }
  function write(component, text) {
    let writer = startup.get(component);
    if (!writer) { writer = createWriter(component); startup.set(component, writer); }
    return writer.write(text);
  }
  function attachChild(child, component) {
    const output = createWriter(`${component}.out`), error = createWriter(`${component}.err`);
    output.attach(child.stdout); error.attach(child.stderr);
    const completion = new Promise(resolve => child.once("close", resolve)).then(async () => {
      const results = await Promise.allSettled([output.close(), error.close()]);
      for (const result of results) if (result.status === "rejected") report(component, { code: "RUNTIME_CHILD_LOG_CLOSE_FAILED", message: result.reason.message, at: new Date().toISOString(), fatal: true });
      writers.delete(output); writers.delete(error); children.delete(child);
      await persistHealth();
      return results;
    });
    children.set(child, completion);
    return completion;
  }
  async function flush() {
    const results = await Promise.allSettled([...writers].map(writer => writer.flush()));
    for (const result of results) if (result.status === "rejected") report("logging", { code: "RUNTIME_LOG_FLUSH_FAILED", message: result.reason.message, at: new Date().toISOString(), fatal: true });
    await persistHealth();
    return status();
  }
  function close() {
    if (closePromise) return closePromise;
    closing = true;
    closePromise = (async () => {
      // This observes natural child close. It never stops services or AI.
      await Promise.all([...children.values()]);
      const results = await Promise.allSettled([...writers].map(writer => writer.close()));
      for (const result of results) if (result.status === "rejected") report("logging", { code: "RUNTIME_LOG_CLOSE_FAILED", message: result.reason.message, at: new Date().toISOString(), fatal: true });
      writers.clear();
      closed = true;
      await persistHealth();
      return status();
    })();
    return closePromise;
  }
  return { directory, healthFile, write, attachChild, flush, close, status, recordFault: report };
}

module.exports = { createRuntimeLogManager, runtimeLogDirectory };
