"use strict";
const path = require("node:path");

// Only report-preview files are allowed through the desktop "open exported file" helper.
// The renderer can produce arbitrary base64; allowing .exe/.bat/.ps1 here would turn a
// compromised renderer into arbitrary local code execution via shell.openPath().
const ALLOWED_EXTENSIONS = new Set([".html", ".htm", ".pdf"]);
const MAX_EXPORTED_FILE_BYTES = 50 * 1024 * 1024;

function prepareExportedFile(payload, downloadsDir) {
  if (!payload || typeof payload !== "object") return null;
  const rawFilename = String(payload.filename || "security-report.pdf").trim();
  const safeFilename = path.basename(rawFilename).replace(/[\\/:*?"<>|]/g, "_");
  const extension = path.extname(safeFilename).toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(extension)) return null;

  const base64 = String(payload.base64 || "");
  if (!base64) return null;
  // Check encoded length before Buffer.from to avoid allocating an oversized payload first.
  if (base64.length > Math.ceil((MAX_EXPORTED_FILE_BYTES * 4) / 3) + 8) return null;
  if (base64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) return null;
  const buffer = Buffer.from(base64, "base64");
  if (buffer.length < 1 || buffer.length > MAX_EXPORTED_FILE_BYTES) return null;

  const root = path.resolve(downloadsDir);
  const targetPath = path.resolve(root, safeFilename);
  if (path.dirname(targetPath) !== root || path.basename(targetPath) !== safeFilename) return null;
  return { targetPath, buffer };
}

module.exports = {
  ALLOWED_EXTENSIONS: [...ALLOWED_EXTENSIONS],
  MAX_EXPORTED_FILE_BYTES,
  prepareExportedFile,
};
