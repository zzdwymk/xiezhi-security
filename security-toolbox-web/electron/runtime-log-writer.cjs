"use strict";

// Ordinary diagnostics may be omitted only in the default mode. Desktop child
// output uses required:true: overload spills synchronously to owned raw volumes
// without dropping errors or backpressuring/killing the model process.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const { pipeline } = require("node:stream/promises");

let compressionTail = Promise.resolve();
function compressOne(action) {
  const result = compressionTail.then(action, action);
  compressionTail = result.catch(() => {});
  return result;
}
async function hashFile(file, gzip = false) {
  const input = fs.createReadStream(file);
  const hash = crypto.createHash("sha256");
  let bytes = 0;
  await pipeline(input, ...(gzip ? [zlib.createGunzip()] : []), async function* (source) {
    for await (const chunk of source) { hash.update(chunk); bytes += chunk.length; }
  });
  return { sha256: hash.digest("hex"), bytes };
}
async function atomicJson(file, value, options = {}) {
  const temporary = `${file}.${crypto.randomUUID()}.partial`;
  const handle = await fs.promises.open(temporary, "wx", 0o600);
  try { await handle.writeFile(JSON.stringify(value, null, 2) + "\n"); await handle.sync(); }
  finally { await handle.close(); }
  await renameWithRetry(temporary, file, options);
}
async function renameWithRetry(temporary, file, options = {}) {
  const rename = options.rename || fs.promises.rename;
  const wait = options.wait || (milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)));
  const delays = [10, 25, 50, 100, 200];
  for (let attempt = 0; ; attempt++) {
    try { await rename(temporary, file); break; }
    catch (error) {
      if (!["EPERM", "EACCES", "EBUSY"].includes(error.code) || attempt >= delays.length) throw error;
      // Keep the previous target and this fsynced candidate intact. Windows
      // indexers/AV can briefly hold a replaceable file; never unlink it first.
      await wait(delays[attempt]);
    }
  }
}
function positiveInteger(value, fallback, name) {
  const number = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(number) || number < 1) throw new TypeError(`${name} must be a positive integer`);
  return number;
}

class RuntimeLogWriter {
  constructor(options) {
    if (!options || !options.directory) throw new TypeError("directory is required");
    if (!/^[a-z0-9][a-z0-9.-]{0,63}$/.test(options.component)) throw new TypeError("Invalid log component");
    this.directory = path.resolve(options.directory);
    this.component = options.component;
    this.maxVolumeBytes = positiveInteger(options.maxVolumeBytes, 20 * 1024 * 1024, "maxVolumeBytes");
    this.maxQueueBytes = positiveInteger(options.maxQueueBytes, 4 * 1024 * 1024, "maxQueueBytes");
    this.sessionId = `${new Date().toISOString().replace(/[^0-9]/g, "")}-${process.pid}-${crypto.randomUUID()}`;
    this.prefix = `${this.component}-${this.sessionId}`;
    this.statusFile = path.join(this.directory, `${this.prefix}.status.json`);
    this.onFault = options.onFault;
    this.required = options.required === true;
    this.requiredFallback = null;
    this.requiredFd = null;
    this.requiredSequence = 0;
    this.requiredClosedSequence = 0;
    this.requiredCompressedSequence = 0;
    this.requiredCompression = null;
    this.requiredCompressionFailed = false;
    this.missingRequiredBytes = 0;
    this.queue = [];
    this.queuedBytes = 0;
    this.sequence = 0;
    this.acceptedBytes = 0;
    this.writtenBytes = 0;
    this.omittedBytes = 0;
    this.omittedChunks = 0;
    this.failureCount = 0;
    this.closedVolumes = 0;
    this.closing = false;
    this.closed = false;
    this.fatal = false;
    this.firstFault = null;
    this.lastFault = null;
    this.handle = null;
    this.volume = null;
    this.pumpPromise = null;
    this.attachments = new Set();
    this.statusTail = Promise.resolve();
    this.statusPending = 0;
    this.timer = setInterval(() => { if (!this.statusPending) this.persistStatus().catch(() => {}); }, positiveInteger(options.statusIntervalMs, 30000, "statusIntervalMs"));
    this.timer.unref();
  }

  fault(code, error, fatal = false) {
    const fault = { code, message: String(error?.message || error), at: new Date().toISOString(), fatal };
    this.failureCount++;
    if (!this.firstFault) this.firstFault = fault;
    const changed = this.lastFault?.code !== code;
    this.lastFault = fault;
    this.fatal ||= fatal;
    if (changed) {
      // Never route this through the same writer, including on ENOSPC.
      try { process.stderr.write(`[runtime-log:${this.component}] ${code}: ${fault.message}\n`); } catch {}
      try { this.onFault?.(fault); } catch (callbackError) {
        try { process.stderr.write(`[runtime-log] onFault failed: ${callbackError.message}\n`); } catch {}
      }
    }
    return false;
  }

  write(chunk) {
    if (this.closing || this.closed) return this.fault("WRITE_AFTER_CLOSE", "Runtime logger has closed", true);
    const bytes = Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(String(chunk));
    if (this.required && (this.requiredFallback || this.fatal || bytes > this.maxQueueBytes - this.queuedBytes)) return this.spoolRequired(chunk);
    if (this.fatal || bytes > this.maxQueueBytes - this.queuedBytes) {
      this.omittedBytes += bytes;
      this.omittedChunks++;
      return this.fault(this.fatal ? "WRITE_UNAVAILABLE" : "DIAGNOSTIC_QUEUE_OVERFLOW", `${bytes} ordinary diagnostic bytes omitted; required evidence must be collected separately`);
    }
    if (!bytes) return true;
    this.queue.push(Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(String(chunk)));
    this.queuedBytes += bytes;
    this.acceptedBytes += bytes;
    this.startPump();
    return true;
  }

  startPump() {
    if (this.pumpPromise) return;
    this.pumpPromise = this.pump().finally(() => {
      this.pumpPromise = null;
      if (this.queue.length && !this.fatal) this.startPump();
    });
  }

  async openVolume() {
    await fs.promises.mkdir(this.directory, { recursive: true });
    const rawPath = path.join(this.directory, `${this.prefix}-${String(++this.sequence).padStart(6, "0")}.log`);
    this.handle = await fs.promises.open(rawPath, "wx", 0o600);
    this.volume = { rawPath, bytes: 0, hash: crypto.createHash("sha256"), openedAt: new Date().toISOString() };
  }

  async pump() {
    try {
      while (this.queue.length) {
        const chunk = this.queue[0];
        this.queueHeadWritten = 0;
        let offset = 0;
        while (offset < chunk.length) {
          if (!this.handle) await this.openVolume();
          const size = Math.min(chunk.length - offset, this.maxVolumeBytes - this.volume.bytes);
          const slice = chunk.subarray(offset, offset + size);
          let cursor = 0;
          while (cursor < size) {
            const result = await this.handle.write(slice, cursor, size - cursor);
            if (!result.bytesWritten) throw new Error("Log write made no progress");
            this.volume.hash.update(slice.subarray(cursor, cursor + result.bytesWritten));
            this.volume.bytes += result.bytesWritten;
            this.writtenBytes += result.bytesWritten;
            this.queueHeadWritten += result.bytesWritten;
            cursor += result.bytesWritten;
          }
          offset += size;
          if (this.volume.bytes === this.maxVolumeBytes) await this.closeVolume();
        }
        this.queue.shift();
        this.queuedBytes -= chunk.length;
      }
    } catch (error) {
      // Raw/partial files remain recoverable. Do not stop the child process.
      this.fault(error.code || "LOG_WRITE_FAILED", error, true);
      const missing = Math.max(0, this.acceptedBytes - this.writtenBytes - (this.acceptedOmittedBytes || 0));
      if (this.required) {
        this.acceptedBytes -= missing;
        for (let index = 0; index < this.queue.length; index++) {
          const remaining = index === 0 ? this.queue[index].subarray(this.queueHeadWritten || 0) : this.queue[index];
          if (remaining.length) this.spoolRequired(remaining);
        }
      } else this.omittedBytes += missing;
      this.acceptedOmittedBytes = this.acceptedBytes - this.writtenBytes;
      if (!this.required) this.omittedChunks += this.queue.length;
      this.queue.length = 0;
      this.queuedBytes = 0;
      if (this.handle) { await this.handle.close().catch(() => {}); this.handle = null; }
    }
  }

  async closeVolume() {
    if (!this.handle) return;
    const volume = this.volume;
    await this.handle.sync();
    await this.handle.close();
    this.handle = null;
    this.volume = null;
    const sha256 = volume.hash.digest("hex");
    await this.compressVolume({ ...volume, sha256, sequence: this.sequence, segment: "async" });
  }

  async compressVolume(volume) {
    const sha256 = volume.sha256;
    await compressOne(async () => {
      const partialPath = `${volume.rawPath}.gz.partial`;
      const gzipPath = `${volume.rawPath}.gz`;
      await pipeline(fs.createReadStream(volume.rawPath), zlib.createGzip({ level: 1 }), fs.createWriteStream(partialPath, { flags: "wx", mode: 0o600 }));
      const compressedHandle = await fs.promises.open(partialPath, "r+");
      try { await compressedHandle.sync(); } finally { await compressedHandle.close(); }
      const proof = await hashFile(partialPath, true);
      if (proof.sha256 !== sha256 || proof.bytes !== volume.bytes) throw new Error("Compressed runtime log hash mismatch; raw log retained");
      await renameWithRetry(partialPath, gzipPath);
      const compressed = await hashFile(gzipPath);
      await atomicJson(`${volume.rawPath}.json`, {
        schemaVersion: 1, kind: this.required ? "required-runtime-diagnostic" : "ordinary-runtime-diagnostic", component: this.component,
        sessionId: this.sessionId, sequence: volume.sequence, segment: volume.segment, openedAt: volume.openedAt,
        closedAt: new Date().toISOString(), payloadPath: gzipPath, encoding: "gzip",
        sha256, bytes: volume.bytes, compressedSha256: compressed.sha256, compressedBytes: compressed.bytes,
        hashVerified: true, retention: "review-only; no automatic deletion", collectionPolicy: this.required ? "required-runtime-with-durable-overflow" : "bounded-diagnostics-not-required-evidence",
      });
      // Only this instance's newly-created immutable raw volume is replaced.
      // No historic file, active profile data, or evidence pool is removed.
      await fs.promises.unlink(volume.rawPath);
      this.closedVolumes++;
    });
  }

  requiredPath(sequence) {
    return path.join(this.directory, `${this.prefix}-required-${String(sequence).padStart(6, "0")}.log`);
  }

  spoolRequired(chunk) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    if (!buffer.length) return true;
    if (!this.requiredFallback) {
      this.requiredFallback = { at: new Date().toISOString(), priorAsyncBytes: this.acceptedBytes,
        ordering: "All async segment volumes, then required segment volumes in sequence order" };
      this.fault("REQUIRED_DURABLE_FALLBACK", "Required diagnostics switched to synchronous disk spill; no intentional omission; review IO pressure");
    }
    let offset = 0;
    try {
      fs.mkdirSync(this.directory, { recursive: true });
      while (offset < buffer.length) {
        if (this.requiredFd === null) {
          this.requiredFd = fs.openSync(this.requiredPath(++this.requiredSequence), "wx", 0o600);
          this.requiredVolumeBytes = 0;
        }
        const size = Math.min(buffer.length - offset, this.maxVolumeBytes - this.requiredVolumeBytes);
        const written = fs.writeSync(this.requiredFd, buffer, offset, size);
        if (!written) throw new Error("Required runtime write made no progress");
        offset += written; this.requiredVolumeBytes += written;
        this.acceptedBytes += written; this.writtenBytes += written;
        if (this.requiredVolumeBytes === this.maxVolumeBytes) this.sealRequiredVolume();
      }
      if (this.requiredFd !== null) fs.fsyncSync(this.requiredFd);
      return true;
    } catch (error) {
      this.missingRequiredBytes += buffer.length - offset;
      this.fault("REQUIRED_RUNTIME_WRITE_FAILED", error, true);
      if (this.requiredFd !== null) { try { fs.closeSync(this.requiredFd); } catch {} this.requiredFd = null; }
      return false;
    }
  }

  sealRequiredVolume() {
    if (this.requiredFd === null) return;
    fs.fsyncSync(this.requiredFd); fs.closeSync(this.requiredFd); this.requiredFd = null;
    this.requiredClosedSequence = this.requiredSequence;
    this.startRequiredCompression();
  }

  startRequiredCompression() {
    if (this.requiredCompression || this.requiredCompressionFailed) return;
    this.requiredCompression = (async () => {
      while (this.requiredCompressedSequence < this.requiredClosedSequence) {
        const sequence = this.requiredCompressedSequence + 1, rawPath = this.requiredPath(sequence);
        const proof = await hashFile(rawPath);
        await this.compressVolume({ rawPath, ...proof, sequence, segment: "required", openedAt: this.requiredFallback.at });
        this.requiredCompressedSequence = sequence;
      }
    })().catch(error => {
      this.requiredCompressionFailed = true;
      this.fault("REQUIRED_RUNTIME_COMPRESSION_FAILED", error, true);
    }).finally(() => {
      this.requiredCompression = null;
      if (!this.requiredCompressionFailed && this.requiredCompressedSequence < this.requiredClosedSequence) this.startRequiredCompression();
    });
  }

  attach(readable) {
    if (this.closing) throw new Error("Cannot attach after close");
    const attachment = { ended: false };
    this.attachments.add(attachment);
    readable.on("data", chunk => { this.write(chunk); });
    readable.once("end", () => { attachment.ended = true; });
    readable.once("close", () => { attachment.ended = true; });
    readable.on("error", error => { this.fault("CHILD_LOG_PIPE_ERROR", error, true); });
    // No pause/destroy/unpipe on overload: a logging fault must not deadlock AI.
    return attachment;
  }

  status() {
    return { schemaVersion: 1, component: this.component, sessionId: this.sessionId,
      status: this.firstFault ? "DEGRADED" : this.closed ? "CLOSED" : "OPEN",
      closed: this.closed,
      collectionPolicy: this.required ? "required-runtime-with-durable-overflow" : "bounded-diagnostics-not-required-evidence", acceptedBytes: this.acceptedBytes,
      writtenBytes: this.writtenBytes, queuedBytes: this.queuedBytes, omittedBytes: this.omittedBytes,
      omittedChunks: this.omittedChunks, closedVolumes: this.closedVolumes,
      currentVolume: this.volume?.rawPath || null, failureCount: this.failureCount,
      firstFault: this.firstFault, lastFault: this.lastFault, fatal: this.fatal,
      activePipes: [...this.attachments].filter(item => !item.ended).length,
      maxQueueBytes: this.maxQueueBytes, maxVolumeBytes: this.maxVolumeBytes,
      required: this.required, missingRequiredBytes: this.missingRequiredBytes, requiredFallback: this.requiredFallback,
      requiredVolumes: this.requiredSequence, requiredCompressedVolumes: this.requiredCompressedSequence,
      updatedAt: new Date().toISOString() };
  }

  persistStatus() {
    this.statusPending++;
    const action = async () => {
      try { await fs.promises.mkdir(this.directory, { recursive: true }); await atomicJson(this.statusFile, this.status()); }
      catch (error) { this.fault("LOG_STATUS_WRITE_FAILED", error, true); throw error; }
    };
    const result = this.statusTail.then(action, action).finally(() => { this.statusPending--; });
    this.statusTail = result.catch(() => {});
    return result;
  }

  async flush() {
    while (this.pumpPromise) await this.pumpPromise;
    if (this.handle) {
      try { await this.handle.sync(); }
      catch (error) { this.fault("LOG_FLUSH_FAILED", error, true); }
    }
    if (this.requiredFd !== null) {
      try { fs.fsyncSync(this.requiredFd); }
      catch (error) { this.fault("REQUIRED_RUNTIME_FLUSH_FAILED", error, true); }
    }
    await this.persistStatus();
    return this.status();
  }

  async close() {
    if (this.closed) return this.status();
    if (this.closePromise) return this.closePromise;
    if ([...this.attachments].some(item => !item.ended)) throw new Error("Runtime log pipe still active; wait for natural child close, never interrupt in-flight AI");
    this.closing = true;
    clearInterval(this.timer);
    this.closePromise = (async () => {
      while (this.pumpPromise) await this.pumpPromise;
      try { await this.closeVolume(); }
      catch (error) {
        this.fault("LOG_CLOSE_FAILED", error, true);
        if (this.handle) { await this.handle.close().catch(() => {}); this.handle = null; }
      }
      try { this.sealRequiredVolume(); }
      catch (error) {
        this.fault("REQUIRED_RUNTIME_CLOSE_FAILED", error, true);
        if (this.requiredFd !== null) { try { fs.closeSync(this.requiredFd); } catch {} this.requiredFd = null; }
      }
      while (this.requiredCompression) await this.requiredCompression;
      this.closed = true;
      await this.persistStatus();
      return this.status();
    })();
    return this.closePromise;
  }
}

async function inspectRuntimeRecovery(directory) {
  const output = { readOnly: true, complete: true, recoverable: [], faults: [] };
  for (const entry of await fs.promises.readdir(directory, { withFileTypes: true }).catch(error => {
    if (error.code === "ENOENT") return [];
    throw error;
  })) {
    const file = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      output.complete = false;
      output.faults.push({ path: file, error: "Symlink/reparse entry requires explicit recovery review" });
      continue;
    }
    if (!entry.isFile()) continue;
    if (/\.log$|\.partial$/.test(entry.name)) {
      output.complete = false;
      output.recoverable.push({ path: file, bytes: (await fs.promises.stat(file)).size, action: "retain; verify owner process ended before recovery" });
    } else if (/\.log\.gz$/.test(entry.name)) {
      if (!fs.existsSync(file.slice(0, -3) + ".json")) {
        output.complete = false;
        output.recoverable.push({ path: file, action: "Compressed volume lacks durable receipt; retain and verify" });
      }
    } else if (/\.status\.json$/.test(entry.name)) {
      try {
        const status = JSON.parse(await fs.promises.readFile(file, "utf8"));
        if (status.closed !== true || status.status !== "CLOSED" || status.fatal || status.omittedBytes > 0) {
          output.complete = false;
          output.faults.push({ path: file, error: "Session did not confirm clean close or had a logging fault; inspect before accepting completeness" });
        }
      } catch (error) { output.complete = false; output.faults.push({ path: file, error: error.message }); }
    } else if (/\.log\.json$/.test(entry.name)) {
      try {
        const receipt = JSON.parse(await fs.promises.readFile(file, "utf8"));
        const expectedPayload = file.slice(0, -5) + ".gz";
        if (path.resolve(receipt.payloadPath) !== path.resolve(expectedPayload)) throw new Error("Receipt payload is outside its volume");
        const proof = await hashFile(expectedPayload, true);
        if (proof.sha256 !== receipt.sha256 || proof.bytes !== receipt.bytes) throw new Error("Recovery hash mismatch");
        const compressed = await hashFile(expectedPayload);
        if (compressed.sha256 !== receipt.compressedSha256 || compressed.bytes !== receipt.compressedBytes) throw new Error("Compressed recovery hash mismatch");
      } catch (error) { output.complete = false; output.faults.push({ path: file, error: error.message }); }
    }
  }
  return output;
}

module.exports = { RuntimeLogWriter, inspectRuntimeRecovery, hashFile, atomicJson };
