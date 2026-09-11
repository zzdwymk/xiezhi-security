/*
 * 资产拓扑算法契约回归检查。
 *
 * 该检查不启动桌面壳，也不访问后端；它从当前 Vue SFC 的 script setup
 * 中编译并执行 URL 规范化/资产合并函数，再用小型固定夹具锁住几个容易
 * 被无意改坏的边界条件。浏览器 UI 阶段由 suite/j-topology.cjs 覆盖。
 *
 * 运行：node tests/e2e/verify-topology-contract.cjs
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const ts = require("typescript");

const WEB_ROOT = path.resolve(__dirname, "..", "..");
const TOPOLOGY_VIEW = path.join(WEB_ROOT, "src", "views", "AssetsTopology.vue");
const TOPOLOGY_COMPONENT = path.join(WEB_ROOT, "src", "components", "AssetTopology.vue");

function readScriptSetup(file) {
  const source = fs.readFileSync(file, "utf8");
  const match = source.match(/<script\s+setup(?:\s[^>]*)?>([\s\S]*?)<\/script>/i);
  if (!match) throw new Error(`未找到 script setup: ${file}`);
  return { source, script: match[1] };
}

function topLevelFunctions(script) {
  const sourceFile = ts.createSourceFile(
    "topology-contract.ts",
    script,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const result = new Map();
  for (const statement of sourceFile.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name) {
      result.set(statement.name.text, script.slice(statement.pos, statement.end));
    }
  }
  return result;
}

function topLevelVariables(script) {
  const sourceFile = ts.createSourceFile(
    "topology-contract-vars.ts",
    script,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const result = new Map();
  for (const statement of sourceFile.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name)) {
        result.set(declaration.name.text, script.slice(statement.pos, statement.end));
      }
    }
  }
  return result;
}

function compileSelectedFunctions({ file, script, required, dependencies = [] }) {
  const functions = topLevelFunctions(script);
  const variables = topLevelVariables(script);
  const missing = required.filter((name) => !functions.has(name));
  if (missing.length) throw new Error(`${file} 缺少可测试函数: ${missing.join(", ")}`);
  const missingDependencies = dependencies.filter((name) => !variables.has(name) && !functions.has(name));
  if (missingDependencies.length) {
    throw new Error(`${file} 缺少可测试依赖: ${missingDependencies.join(", ")}`);
  }
  const snippet = [
    ...dependencies.map((name) => variables.get(name) || functions.get(name)),
    ...required.map((name) => functions.get(name)),
  ].join("\n\n");
  const compiled = ts.transpileModule(
    `${snippet}\nmodule.exports = { ${required.join(", ")} };`,
    {
      compilerOptions: {
        target: ts.ScriptTarget.ES2020,
        module: ts.ModuleKind.CommonJS,
        strict: false,
      },
      fileName: path.basename(file) + ".ts",
    },
  ).outputText;
  const sandbox = {
    module: { exports: {} },
    exports: {},
    URL,
    console,
  };
  vm.runInNewContext(compiled, sandbox, { filename: file });
  return sandbox.module.exports;
}

function loadTopologyFunctions() {
  const { source: viewSource, script: viewScript } = readScriptSetup(TOPOLOGY_VIEW);
  const required = ["normalizeAssetUrl", "canonicalAssetUrl", "assetPriority", "mergeProjectAssets"];
  // 只编译本次契约所需的纯函数；不会执行组件挂载、网络请求或副作用代码。
  const dependencies = ["ASSET_DETAIL_KEYS", "hasAssetValue"];
  const fns = compileSelectedFunctions({
    file: TOPOLOGY_VIEW,
    script: viewScript,
    required,
    dependencies,
  });
  const { source: componentSource, script: componentScript } = readScriptSetup(TOPOLOGY_COMPONENT);
  const componentFns = compileSelectedFunctions({
    file: TOPOLOGY_COMPONENT,
    script: componentScript,
    required: ["normalizeAssetUrl", "stripHostPort", "isIpAddress", "extractRootDomain", "parseHost"],
    dependencies: ["IPV4_REGEX", "DOUBLE_TLDS"],
  });
  return { source: viewSource, componentSource, fns, componentFns };
}

function assertSourceContracts(viewSource, componentSource) {
  assert.match(
    viewSource,
    /const\s+projectId\s*=\s*ref<number\s*\|\s*"all">\s*\(\s*"all"\s*\)/,
    "资产拓扑默认项目必须是 all",
  );
  assert.match(
    viewSource,
    /<el-option\s+label="全部项目"\s+value="all"\s*\/>/,
    "项目选择器必须提供全部项目选项",
  );
  assert.match(
    componentSource,
    /const\s+isAll\s*=\s*props\.projectId\s*===\s*"all"/,
    "组件必须显式区分全部项目模式",
  );
  assert.match(
    componentSource,
    /pAssets\s*=\s*allAssets\.filter\(\(a\)\s*=>\s*a\.projectId\s*===\s*pid\)/,
    "全部项目模式必须按 projectId 分配资产中心",
  );
  assert.match(
    componentSource,
    /(?:findingProjectId\s*!==\s*asset\.projectId|Number\(findingProjectId\)\s*!==\s*Number\(asset\.projectId\))/,
    "漏洞关联必须限制在资产所属项目",
  );
  assert.match(
    componentSource,
    /function\s+getAssetRemovalAction[\s\S]*?const\s+kind\s*=\s*getAssetKind\(asset\)[\s\S]*?kind\s*===\s*"path"[\s\S]*?return\s*"none"/,
    "删除动作必须先按资产来源类型保护路径节点",
  );
  assert.match(
    componentSource,
    /getAssetRemovalAction[\s\S]*?_probeResultId\s*\?\?\s*asset\.id/,
    "项目详情页的原始探测记录必须回退使用自身 id",
  );

  // 同优先级记录按后端时间倒序输入时，先出现的记录是最新记录，不能被后
  // 到的旧记录覆盖。允许实现改成显式时间比较，但禁止回归到 >=。
  assert.doesNotMatch(
    viewSource,
    /assetPriority\(asset\)\s*>=\s*assetPriority\(current\)/,
    "同优先级资产不能用 >= 覆盖较新的首条记录",
  );
  assert.match(
    viewSource,
    /assetPriority\(asset\)\s*>\s*assetPriority\(current\)|detectedAt|discoveredAt/,
    "资产合并必须保留首条新记录或显式比较时间",
  );

  // IPv6 是冒号分隔的完整主机名，禁止在主机解析/发现关联路径上用
  // split(":")[0] 这种只适用于 IPv4/端口的截断方式。
  assert.doesNotMatch(
    componentSource,
    /parseHost\([^\n]+\)\.host\.split\(\s*":"\s*\)\s*\[\s*0\s*\]/,
    "漏洞关联不能截断 IPv6 主机",
  );
  assert.doesNotMatch(
    componentSource,
    /replace\(\/\^\\\[\|\\\]\$\/g,\s*""\s*\)\.split\(":"\)\[0\]/,
    "主机解析不能用冒号截断 IPv6",
  );
}

function runContractChecks() {
  const loaded = loadTopologyFunctions();
  assertSourceContracts(loaded.source, loaded.componentSource);
  const { normalizeAssetUrl, canonicalAssetUrl, mergeProjectAssets } = loaded.fns;
  const {
    normalizeAssetUrl: componentNormalizeAssetUrl,
    stripHostPort,
    isIpAddress,
    parseHost,
  } = loaded.componentFns;

  const cases = [];
  const check = (name, fn) => {
    try {
      fn();
      cases.push({ name, status: "PASS" });
      console.log(`[PASS] ${name}`);
    } catch (error) {
      cases.push({ name, status: "FAIL", error: error.message });
      console.error(`[FAIL] ${name} — ${error.message}`);
    }
  };

  check("裸 IPv6 会被规范化为带方括号的 URL", () => {
    assert.equal(
      normalizeAssetUrl("2001:db8::1/admin?q=1"),
      "http://[2001:db8::1]/admin?q=1",
      "裸 IPv6 的路径应位于方括号之外",
    );
  });

  check("IPv6 URL 规范化保留端口、路径与查询串", () => {
    assert.equal(
      normalizeAssetUrl("https://[2001:db8::1]:8443/admin?q=1"),
      "https://[2001:db8::1]:8443/admin?q=1",
    );
    assert.equal(
      canonicalAssetUrl("https://[2001:DB8::1]:443/admin?q=1#top"),
      "https://[2001:db8::1]/admin?q=1#top",
    );
  });

  check("组件主机解析保留裸 IPv6、括号 IPv6 与端口", () => {
    assert.equal(stripHostPort("2001:db8::1"), "2001:db8::1");
    assert.equal(stripHostPort("[2001:db8::1]:8443"), "2001:db8::1");
    assert.equal(isIpAddress("2001:db8::1"), true);
    assert.equal(isIpAddress("[2001:db8::1]:8443"), true);

    const bare = parseHost("2001:db8::1/admin");
    assert.equal(bare.isIp, true);
    assert.equal(bare.rootDomain, "2001:db8::1");
    assert.match(bare.host, /2001:db8::1/);

    const bracketed = parseHost("https://[2001:db8::1]:8443/admin");
    assert.equal(bracketed.isIp, true);
    assert.equal(bracketed.rootDomain, "2001:db8::1");
    assert.match(bracketed.host, /\[2001:db8::1\]:8443/);
    assert.equal(componentNormalizeAssetUrl("2001:db8::1/admin"), "http://[2001:db8::1]/admin");
  });

  check("同 URL 同优先级时保留后端倒序返回的最新记录", () => {
    const newest = {
      id: 102,
      projectId: 7,
      url: "https://Example.test:443/",
      _assetKind: "probe",
      _probeResultId: 102,
      detectedAt: "2026-09-11T10:00:00Z",
      server: "new-server",
    };
    const older = {
      id: 101,
      projectId: 7,
      url: "https://example.test/",
      _assetKind: "probe",
      _probeResultId: 101,
      detectedAt: "2026-09-10T10:00:00Z",
      server: "old-server",
    };
    const merged = mergeProjectAssets(7, [newest, older]);
    assert.equal(merged.length, 1);
    assert.equal(merged[0].id, newest.id, "旧记录覆盖了新记录");
    assert.equal(merged[0].server, newest.server);
  });

  check("探测记录优先于同 URL 的路径和授权占位", () => {
    const target = {
      id: 5000000001,
      projectId: 7,
      url: "http://example.test",
      _assetKind: "target",
      _isTargetAsset: true,
      _targetLinkId: 33,
    };
    const webPath = {
      id: 1000000001,
      projectId: 7,
      url: "http://example.test/",
      _assetKind: "path",
      _webPath: true,
      _discoveredPathId: 44,
    };
    const probe = {
      id: 77,
      projectId: 7,
      url: "HTTP://EXAMPLE.TEST:80",
      _assetKind: "probe",
      _probeResultId: 77,
      framework: "Express",
    };
    const merged = mergeProjectAssets(7, [webPath, target, probe]);
    assert.equal(merged.length, 1);
    assert.equal(merged[0].id, probe.id);
    assert.equal(merged[0]._assetKind, "probe");
    assert.equal(merged[0].framework, "Express");
  });

  check("路径节点不会继承授权目标的删除标识", () => {
    const target = {
      id: 5000000002,
      projectId: 7,
      url: "http://path.example",
      _assetKind: "target",
      _isTargetAsset: true,
      _targetLinkId: 34,
    };
    const pathAsset = {
      id: 1000000002,
      projectId: 7,
      url: "http://path.example/",
      _assetKind: "path",
      _webPath: true,
      _discoveredPathId: 45,
    };
    const merged = mergeProjectAssets(7, [target, pathAsset]);
    assert.equal(merged.length, 1);
    assert.equal(merged[0]._assetKind, "path");
    assert.equal(merged[0]._webPath, true);
    assert.equal(merged[0]._targetLinkId, undefined);
    assert.equal(merged[0]._probeResultId, undefined);
    assert.equal(merged[0]._discoveredPathId, pathAsset._discoveredPathId);
  });

  check("不同项目的相同 URL 在各自合并边界内保持隔离", () => {
    const shared = "http://shared.example/";
    const p1 = mergeProjectAssets(1, [{ id: 1, projectId: 1, url: shared, _assetKind: "probe" }]);
    const p2 = mergeProjectAssets(2, [{ id: 2, projectId: 2, url: shared, _assetKind: "probe" }]);
    assert.equal(p1.length, 1);
    assert.equal(p2.length, 1);
    assert.equal(p1[0].projectId, 1);
    assert.equal(p2[0].projectId, 2);
    assert.notEqual(p1[0].id, p2[0].id);
  });

  const failed = cases.filter((item) => item.status === "FAIL");
  if (failed.length) {
    throw new Error(`${failed.length} 项拓扑契约检查失败`);
  }
  return cases;
}

if (require.main === module) {
  try {
    runContractChecks();
    console.log("拓扑契约检查通过");
  } catch (error) {
    console.error(`拓扑契约检查失败: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { runContractChecks };
