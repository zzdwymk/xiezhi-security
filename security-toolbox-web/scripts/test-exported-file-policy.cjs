"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  ALLOWED_EXTENSIONS,
  MAX_EXPORTED_FILE_BYTES,
  prepareExportedFile,
} = require("../electron/exported-file-policy.cjs");

const downloads = fs.mkdtempSync(path.join(os.tmpdir(), "xiezhi-export-policy-"));
const base64 = Buffer.from("report-content").toString("base64");

function allowed(filename) {
  const prepared = prepareExportedFile({ filename, base64 }, downloads);
  assert.ok(prepared, `${filename} 应被允许`);
  assert.equal(path.dirname(prepared.targetPath), path.resolve(downloads));
  assert.equal(path.basename(prepared.targetPath), path.basename(filename));
}

function rejected(filename, payload = { filename, base64 }) {
  assert.equal(prepareExportedFile(payload, downloads), null, `${filename} 应被拒绝`);
}

assert.deepEqual(new Set(ALLOWED_EXTENSIONS), new Set([".html", ".htm", ".pdf"]));
allowed("report.pdf");
allowed("report.html");
allowed("report.HTM");
allowed("../../report.pdf");
assert.equal(
  prepareExportedFile({ filename: "../../report.pdf", base64 }, downloads).targetPath,
  path.join(downloads, "report.pdf"),
);

for (const name of ["evil.exe", "evil.bat", "evil.ps1", "evil.js", "report.pdf.exe", "no-extension"]) {
  rejected(name);
}
rejected("report.pdf", { filename: "report.pdf", base64: "" });
rejected("report.pdf", { filename: "report.pdf", base64: "not-base64!" });
rejected("report.pdf", {
  filename: "report.pdf",
  base64: "A".repeat(Math.ceil((MAX_EXPORTED_FILE_BYTES * 4) / 3) + 20),
});

console.log("PASS: exported-file-policy blocks executables, keeps html/pdf, confines path and size");
