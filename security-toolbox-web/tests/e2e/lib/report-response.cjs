const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

// Register before the UI click. No injected renderer globals, direct API request or CSP bypass.
async function captureReport(page, H, locator, expectedPath, label, timeout = 60000) {
  const pending = page.waitForResponse(r => new URL(r.url()).pathname === expectedPath && r.request().method() === "GET", { timeout })
    .then(response => ({ response }), error => ({ error }));
  await locator.scrollIntoViewIfNeeded().catch(() => {});
  await locator.click();
  const observed = await pending;
  if (observed.error) throw new Error(`未观察到报告响应 ${expectedPath}: ${observed.error.message}`);
  const response = observed.response;
  const bytes = await response.body();
  const dir = path.join(H.dir, "report-artifacts");
  fs.mkdirSync(dir, { recursive: true });
  const artifact = path.join(dir, `${label}-${Date.now()}-${crypto.randomUUID()}.${expectedPath.endsWith(".pdf") ? "pdf" : "html"}`);
  fs.writeFileSync(artifact, bytes, { flag: "wx" });
  const rec = { url: response.url(), status: response.status(), contentType: response.headers()["content-type"] || "",
    size: bytes.length, sha256: crypto.createHash("sha256").update(bytes).digest("hex"), artifact,
    signature: bytes.subarray(0, 16).toString("utf8"), verificationDepth: "response-body-only",
    nativeDownloadVerified: false, recordedAt: new Date().toISOString() };
  fs.writeFileSync(artifact + ".json", JSON.stringify(rec, null, 2), { flag: "wx" });
  return rec;
}

module.exports = { captureReport };
