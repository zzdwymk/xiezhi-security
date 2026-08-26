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
const {
  createInvalidatableCache,
} = require("../electron/invalidatable-cache.cjs");
const {
  compareStableVersions,
  evaluateInstalledRelease,
  parseStableVersion,
} = require("../electron/dependency-version.cjs");

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

  let cacheLoads = 0;
  const cache = createInvalidatableCache(() => ({ generation: ++cacheLoads }));
  assert.strictEqual(cache.get(), cache.get());
  assert.equal(cacheLoads, 1);
  cache.invalidate();
  assert.equal(cache.get().generation, 2);
  const cachedReplacement = { generation: 9 };
  assert.strictEqual(cache.replace(cachedReplacement), cachedReplacement);
  assert.strictEqual(cache.get(), cachedReplacement);
  assert.equal(cacheLoads, 2);

  assert.equal(parseStableVersion("v3.5.6").normalized, "3.5.6");
  assert.equal(parseStableVersion("latest"), undefined);
  assert.equal(compareStableVersions("3.5.6", "3.5.6"), 0);
  assert.equal(compareStableVersions("3.5.7", "3.5.6"), 1);
  assert.equal(compareStableVersions("3.4.9", "3.5.0"), -1);
  assert.deepEqual(
    evaluateInstalledRelease({
      metadata: { repository: "zan8in/afrog", version: "v3.5.6" },
      repository: "zan8in/afrog",
      latestVersion: "3.5.6",
      payloadExists: true,
    }),
    {
      managed: true,
      installedVersion: "3.5.6",
      latestVersion: "3.5.6",
      comparison: 0,
      upToDate: true,
      updateAvailable: false,
    },
  );

  const privateError = new Error("private-node-detail test-data\\private\\file");
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
    "Error: private-node-detail test-data\\private\\file",
 );

  const electronDirectory = path.resolve(__dirname, "..", "electron");
  const packageManifest = JSON.parse(
    fs.readFileSync(path.resolve(__dirname, "..", "package.json"), "utf8"),
  );
  assert.deepEqual(packageManifest.dependencies, { "adm-zip": "^0.6.0" });
  for (const dependency of [
    "@fluentui/svg-icons",
    "@vue-flow/core",
    "axios",
    "dompurify",
    "element-plus",
    "marked",
    "pinia",
    "vue",
    "vue-router",
  ]) {
    assert.ok(packageManifest.devDependencies[dependency], dependency);
  }
  for (const unusedDependency of [
    "@element-plus/icons-vue",
    "@vue-flow/background",
    "echarts",
    "vue-echarts",
  ]) {
    assert.equal(packageManifest.dependencies[unusedDependency], undefined);
    assert.equal(packageManifest.devDependencies[unusedDependency], undefined);
  }
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
  assert.doesNotMatch(
    electronMainSource,
    /spawnSync\("java", \["-version"\]/,
  );
  assert.match(
    electronMainSource,
    /backendStartError = new Error\(`无法启动本地 Java 服务：\$\{error\.message\}`\)/,
  );
  assert.match(
    electronMainSource,
    /systemThemeCache\.invalidate\(\);\s*broadcastSystemTheme\(\);/,
  );
  assert.match(
    electronMainSource,
    /desktopSettingsCache\.replace\(settings\);\s*systemThemeCache\.invalidate\(\);/,
  );
  const dependencyInstallSource = electronMainSource.slice(
    electronMainSource.indexOf("async function installPortableDependency"),
    electronMainSource.indexOf("async function controlDependencyInstall"),
  );
  assert.doesNotMatch(
    dependencyInstallSource,
    /postBackendJson|\/api\/vulnerabilities\/sync\//,
    "a completed binary install must not become a failure because an unauthenticated catalog sync returned 401",
  );
  assert.doesNotMatch(electronMainSource, /postBackendJson|checkVulnerabilityCatalogOnStartup/);
  assert.match(electronMainSource, /status:\s*"up-to-date"/);
  assert.match(electronMainSource, /toolbox:uninstall-dependency/);
  assert.match(electronMainSource, /只能卸载应用管理的可选依赖/);

  const setupSource = fs.readFileSync(
    path.resolve(__dirname, "..", "src", "views", "Setup.vue"),
    "utf8",
  );
  assert.match(setupSource, /await check\(true\)/);
  const vulnerabilitiesSource = fs.readFileSync(
    path.resolve(__dirname, "..", "src", "views", "Vulnerabilities.vue"),
    "utf8",
  );
  const catalogSyncStoreSource = fs.readFileSync(
    path.resolve(__dirname, "..", "src", "stores", "catalogSync.ts"),
    "utf8",
  );
  assert.match(
    vulnerabilitiesSource,
    /useCatalogSyncStore/,
  );
  assert.match(
    vulnerabilitiesSource,
    /catalogSync\.start\(sources\)/,
    "catalog sync must remain owned by the global store when the route unmounts",
  );
  assert.match(
    catalogSyncStoreSource,
    /installDependency\(\s*source\.toLowerCase\(\),\s*\{\s*refreshCatalog:\s*true\s*\}/,
  );
  assert.match(
    catalogSyncStoreSource,
    /catalogFilesUpdated\s*===\s*false[\s\S]*catalogCount\(stats,\s*source\)\s*>\s*0[\s\S]*continue;/,
    "an unchanged installed catalog with existing database rows must skip metadata re-import",
  );
  assert.match(catalogSyncStoreSource, /vulnerabilitySyncStatus\(\)/);
  assert.doesNotMatch(
    vulnerabilitiesSource,
    /<el-option label="獬豸内置" value="BUILTIN"/,
  );
  const workflowSource = fs.readFileSync(
    path.resolve(__dirname, "..", "src", "views", "Workflow.vue"),
    "utf8",
  );
  assert.match(
    workflowSource,
    /SUBAGENTS\.filter\(\(agent\) => agent\.phase === selectedPhase\.value\)/,
    "workflow capability library must filter cards by the selected phase",
  );
  assert.match(workflowSource, /v-for="agent in filteredAgents"/);
  assert.doesNotMatch(workflowSource, /v-for="agent in SUBAGENTS"/);
  assert.match(workflowSource, /<h5>已选节点<\/h5>/);
  assert.match(workflowSource, /<h4>能力库<\/h4>/);
  assert.match(workflowSource, /<h5>流程阶段<\/h5>/);
  assert.match(workflowSource, /流程阶段 · 用于组织能力和依赖/);
  assert.match(workflowSource, /v-for="phase in PHASES"/);
  assert.match(
    workflowSource,
    /function hasCanonicalPhaseNode|const hasCanonicalPhaseNode/,
    "workflow phase library must distinguish phases already present on the canvas",
  );
  assert.match(
    workflowSource,
    /const existingId = phaseNodeId\(phase\)[\s\S]*makeNode\(existingId, "phase", phase, position\)/,
    "restoring a phase must reuse its stable canonical node id",
  );
  assert.doesNotMatch(workflowSource, /\$\{meta\.label\}（自定义）/);
  assert.match(
    workflowSource,
    /type LibraryDropPayload =\s*\| \{ type: "phase"; phase: PhaseCode \}\s*\| \{ type: "tool"; tool: string; phase: PhaseCode \}/,
    "workflow library drag payload must support both phase and tool entries",
  );
  assert.match(workflowSource, /application\/x-workflow-tool/);
  const appSource = fs.readFileSync(
    path.resolve(__dirname, "..", "src", "App.vue"),
    "utf8",
  );
  assert.match(appSource, /class="desktop-v2-recents-head"/);
  assert.match(
    appSource,
    /class="[^"]*\bdesktop-v2-recents-clear\b[^"]*"[\s\S]*?<span>清空<\/span>/,
    "the compact clear action must live beside the recent conversation heading",
  );
  assert.doesNotMatch(appSource, /<span>清空最近对话<\/span>/);

  console.log("JSON 文件、启动缓存与用户错误边界测试通过。");
} finally {
  fs.rmSync(testDirectory, { recursive: true, force: true });
}
