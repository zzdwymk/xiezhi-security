const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const frontendDir = path.resolve(__dirname, "..");
const viteBin = path.join(frontendDir, "node_modules", "vite", "bin", "vite.js");
const temporaryRoot = fs.mkdtempSync(
  path.join(os.tmpdir(), "xiezhi-renderer-paths-"),
);

function build(mode, outputDirectory) {
  const result = spawnSync(
    process.execPath,
    [
      viteBin,
      "build",
      "--mode",
      mode,
      "--outDir",
      outputDirectory,
      "--emptyOutDir",
    ],
    { cwd: frontendDir, stdio: "inherit" },
  );
  assert.equal(result.status, 0, `${mode} renderer build should succeed`);
}

function assetReferences(outputDirectory) {
  const indexPath = path.join(outputDirectory, "index.html");
  assert.ok(fs.existsSync(indexPath), `missing renderer entry: ${indexPath}`);
  const html = fs.readFileSync(indexPath, "utf8");
  const references = [
    ...html.matchAll(/<(?:script|link)\b[^>]+(?:src|href)="([^"]+)"/gi),
  ]
    .map((match) => match[1])
    .filter((value) => !/^(?:[a-z]+:|\/\/|#|data:)/i.test(value));
  assert.ok(references.length >= 2, "renderer entry should reference JS and CSS");
  for (const reference of references) {
    const relativePath = reference
      .split(/[?#]/, 1)[0]
      .replace(/^\.\//, "")
      .replace(/^\//, "");
    assert.ok(
      fs.existsSync(path.join(outputDirectory, relativePath)),
      `missing built asset for ${reference}`,
    );
  }
  return references;
}

function webOutputFromArguments() {
  const option = process.argv.find((value) => value.startsWith("--web-dist="));
  if (!option) return null;
  const supplied = option.slice("--web-dist=".length).trim();
  assert.ok(supplied, "--web-dist must name an existing Web build directory");
  return path.resolve(frontendDir, supplied);
}

try {
  const suppliedWebOutput = webOutputFromArguments();
  const webOutput = suppliedWebOutput || path.join(temporaryRoot, "web");
  if (!suppliedWebOutput) build("production", webOutput);

  const webReferences = assetReferences(webOutput);
  for (const reference of webReferences) {
    assert.match(reference, /^\/assets\//, `Web asset must be root-relative: ${reference}`);
    const resolved = new URL(reference, "http://127.0.0.1:4173/projects/1");
    assert.match(
      resolved.pathname,
      /^\/assets\//,
      `nested Web routes must still load root assets: ${resolved.pathname}`,
    );
  }

  const desktopOutput = path.join(temporaryRoot, "desktop");
  build("desktop", desktopOutput);
  const desktopReferences = assetReferences(desktopOutput);
  for (const reference of desktopReferences) {
    assert.match(
      reference,
      /^\.\/assets\//,
      `Electron asset must remain relative: ${reference}`,
    );
    const resolved = new URL(
      reference,
      "file:///C:/Program%20Files/Xiezhi/resources/app.asar/dist/index.html",
    );
    assert.match(
      resolved.pathname,
      /\/resources\/app\.asar\/dist\/assets\//,
      `Electron asset must resolve beside dist/index.html: ${resolved.pathname}`,
    );
  }

  console.log("Web deep-link and Electron file asset path verification passed.");
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}
