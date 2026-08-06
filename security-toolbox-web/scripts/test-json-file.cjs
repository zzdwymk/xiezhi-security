const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  readJsonFile,
  writeJsonFileAtomic,
} = require("../electron/json-file.cjs");
const {
  UserFacingError,
  diagnosticError,
  publicErrorMessage,
} = require("../electron/public-error.cjs");

const testDirectory = fs.mkdtempSync(
  path.join(os.tmpdir(), "security-toolbox-json-file-"),
);

try {
  const target = path.join(testDirectory, "nested", "settings.json");
  const value = { enabled: true, retries: 3, labels: ["中文", "desktop"] };

  writeJsonFileAtomic(target, value);

  assert.deepEqual(readJsonFile(target), value);
  assert.equal(fs.readFileSync(target, "utf8"), JSON.stringify(value, null, 2));
  assert.equal(fs.existsSync(`${target}.${process.pid}.tmp`), false);

  const replacement = { enabled: false, retries: 1 };
  writeJsonFileAtomic(target, replacement);
  assert.deepEqual(readJsonFile(target), replacement);
  assert.equal(fs.existsSync(`${target}.${process.pid}.tmp`), false);

  const fallback = { status: "fallback" };
  assert.strictEqual(
    readJsonFile(path.join(testDirectory, "missing.json"), fallback),
    fallback,
  );

  const invalidJson = path.join(testDirectory, "invalid.json");
  fs.writeFileSync(invalidJson, "{invalid", "utf8");
  assert.strictEqual(readJsonFile(invalidJson, fallback), fallback);
  assert.deepEqual(
    readJsonFile(path.join(testDirectory, "missing-default.json")),
    {},
  );

  const privateError = new Error("private-node-detail C:\\sensitive\\file");
  assert.equal(
    publicErrorMessage(privateError, "操作失败，请稍后重试"),
    "操作失败，请稍后重试",
  );
  assert.equal(
    publicErrorMessage(new UserFacingError("参数格式不正确"), "操作失败"),
    "参数格式不正确",
  );
  assert.equal(
    diagnosticError(privateError),
    "Error: private-node-detail C:\\sensitive\\file",
  );

  const electronDirectory = path.resolve(__dirname, "..", "electron");
  const captureBrowserSource = fs.readFileSync(
    path.join(electronDirectory, "capture-browser.html"),
    "utf8",
  );
  assert.doesNotMatch(
    captureBrowserSource,
    /errorDescription\s*\|\|\s*event\.errorCode/,
  );
  assert.match(captureBrowserSource, /页面加载失败，请检查目标地址和网络连接/);
  const captureScript = captureBrowserSource.match(
    /<script>([\s\S]*?)<\/script>/,
  )?.[1];
  assert.ok(captureScript);
  assert.doesNotThrow(() => new Function(captureScript));

  const electronMainSource = fs.readFileSync(
    path.join(electronDirectory, "main.cjs"),
    "utf8",
  );
  assert.doesNotMatch(electronMainSource, /reason:\s*'spawn:'\s*\+/);
  assert.doesNotMatch(
    electronMainSource,
    /const detail = \(await response\.text\(\)\)/,
  );
  assert.match(
    electronMainSource,
    /function handleRendererIpc\(channel, handler\)/,
  );
  assert.match(
    electronMainSource,
    /工作区页面加载失败，请重新启动应用或查看桌面日志/,
  );

  console.log("JSON 文件与用户错误边界测试通过（19 项断言）。");
} finally {
  fs.rmSync(testDirectory, { recursive: true, force: true });
}
