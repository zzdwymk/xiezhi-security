const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const ts = require("typescript");

globalThis.crypto ||= webcrypto;
globalThis.btoa ||= (value) => Buffer.from(value, "binary").toString("base64");
globalThis.atob ||= (value) => Buffer.from(value, "base64").toString("binary");

function loadTypescriptModule(relativePath) {
  const filename = path.resolve(__dirname, "..", relativePath);
  const source = fs.readFileSync(filename, "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.paths = Module._nodeModulePaths(path.dirname(filename));
  loaded._compile(output, filename);
  return loaded.exports;
}

async function verify() {
  const { nextTick, ref } = require("vue");
  const cryptoTools = loadTypescriptModule("src/utils/offlineCrypto.ts");
  const pentest = loadTypescriptModule("src/utils/offlinePentest.ts");
  const network = loadTypescriptModule("src/utils/networkSecurity.ts");
  const hexViewer = loadTypescriptModule("src/utils/fileHexViewer.ts");
  const pagination = loadTypescriptModule(
    "src/composables/useClientPagination.ts",
  );
  const errors = loadTypescriptModule("src/utils/errorMessage.ts");

  assert.equal(
    cryptoTools.decodeBase64(cryptoTools.encodeBase64("安全工具箱🔐")),
    "安全工具箱🔐",
  );
  assert.equal(
    cryptoTools.decodeHex(cryptoTools.encodeHex("獬豸安全")),
    "獬豸安全",
  );
  assert.equal(cryptoTools.md5Text("abc"), "900150983cd24fb0d6963f7d28e17f72");
  assert.equal(
    await cryptoTools.digestText("abc", "SHA-256"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  const encrypted = await cryptoTools.encryptAesGcm(
    "authorized-only 🔐",
    "strong-test-passphrase",
  );
  assert.equal(
    await cryptoTools.decryptAesGcm(encrypted, "strong-test-passphrase"),
    "authorized-only 🔐",
  );

  const cidr = network.calculateCidr("192.168.10.42/24");
  assert.deepEqual(
    [
      cidr.network,
      cidr.broadcast,
      cidr.firstHost,
      cidr.lastHost,
      cidr.usableHostCount,
    ],
    [
      "192.168.10.0/24",
      "192.168.10.255",
      "192.168.10.1",
      "192.168.10.254",
      254,
    ],
  );
  const request = network.parseHttpMessage(
    "GET /api HTTP/1.1\r\nHost: example.test\r\n\r\n",
  );
  assert.deepEqual(
    [request.type, request.method, request.target],
    ["request", "GET", "/api"],
  );
  const iocs = network.extractIocs(
    `https://example.com/a 203.0.113.7 CVE-2025-12345 ${"a".repeat(64)}`,
  );
  assert.equal(iocs.urls.includes("https://example.com/a"), true);
  assert.equal(iocs.ipv4.includes("203.0.113.7"), true);
  assert.equal(iocs.cves.includes("CVE-2025-12345"), true);
  assert.equal(iocs.sha256.includes("a".repeat(64)), true);
  assert.equal(
    network.refangIoc("hxxps://example[.]com/a"),
    "https://example.com/a",
  );

  assert.equal(hexViewer.parseHexOffset("0x200"), 512);
  assert.equal(hexViewer.parseHexOffset("512"), 512);
  assert.throws(() => hexViewer.parseHexOffset("12xz"), /偏移量/);
  assert.equal(hexViewer.clampHexOffset(900, 1000, 256), 744);
  assert.equal(hexViewer.formatHexOffset(0x2a, 0x100), "0000002A");
  const hexRows = hexViewer.buildHexRows(
    new Uint8Array([0x41, 0x00, 0x7e, 0x7f, 0xff]),
    0x20,
    0x100,
  );
  assert.equal(hexRows[0].offsetLabel, "00000020");
  assert.deepEqual(hexRows[0].hexCells.slice(0, 5), ["41", "00", "7E", "7F", "FF"]);
  assert.equal(hexRows[0].ascii, "A.~..");
  assert.equal(hexRows[0].hexCells.length, 16);

  const parsedUrl = pentest.parseUrlDetailed("example.com:8443/a?x=1");
  assert.deepEqual(
    [parsedUrl.protocol, parsedUrl.hostname, parsedUrl.port],
    ["https", "example.com", "8443"],
  );
  assert.equal(
    pentest.parseUrlDetailed("mailto:user@example.com").protocol,
    "mailto",
  );
  assert.throws(() => pentest.parseUrlDetailed("http://["), /URL 格式无效/);
  assert.deepEqual(
    pentest.parseQueryString(
      pentest.buildQueryString([
        { key: "a", value: "1 2" },
        { key: "a", value: "3" },
      ]),
    ),
    [
      { key: "a", value: "1 2" },
      { key: "a", value: "3" },
    ],
  );
  assert.equal(pentest.applyPayloadStep("😀", "unicode"), "\\ud83d\\ude00");
  assert.equal(pentest.applyPayloadStep("😀", "escape-js"), "\\ud83d\\ude00");
  assert.equal(pentest.testRegex("a(.)", "", "ab ac").count, 2);
  assert.throws(() => pentest.testRegex("(", "", "test"), /正则表达式无效/);
  assert.throws(
    () => pentest.radixToText("110000", "hex"),
    /Unicode 码点不能超过 U\+10FFFF/,
  );
  const xor = pentest.xorCrypt("獬豸安全", "key", "hex");
  assert.equal(pentest.xorDecryptHex(xor, "key"), "獬豸安全");

  const items = ref(Array.from({ length: 45 }, (_, index) => index + 1));
  const pageState = pagination.useClientPagination(items, 20);
  pageState.page.value = 3;
  assert.deepEqual(pageState.pagedItems.value, [41, 42, 43, 44, 45]);
  items.value = [1, 2];
  await nextTick();
  assert.equal(pageState.page.value, 1);
  assert.deepEqual(pageState.pagedItems.value, [1, 2]);

  assert.equal(
    errors.toErrorMessage(
      { code: "ERR_NETWORK", message: "Network Error" },
      "加载失败",
    ),
    "加载失败：无法连接本地服务",
  );
  assert.equal(
    errors.toErrorMessage(
      new Error("internal implementation detail"),
      "操作失败",
    ),
    "操作失败",
  );
  assert.equal(
    errors.toErrorMessage("Failed to fetch", "加载失败"),
    "加载失败：无法连接本地服务",
  );
  assert.equal(
    errors.toErrorMessage(
      { response: { status: 500, data: { message: "Internal Server Error" } } },
      "加载失败",
    ),
    "加载失败（HTTP 500）",
  );
  assert.equal(
    errors.toErrorMessage(
      { message: "处理失败：java.lang.IllegalStateException" },
      "操作失败",
    ),
    "操作失败",
  );
  assert.equal(
    errors.toErrorMessage("授权范围已失效，请重新检查项目", "操作失败"),
    "授权范围已失效，请重新检查项目",
  );
  assert.equal(
    errors.toErrorMessage(
      "Error invoking remote method 'save-settings': 保存失败，请检查配置",
      "操作失败",
    ),
    "保存失败，请检查配置",
  );

  const trafficSource = fs.readFileSync(
    path.resolve(__dirname, "../src/views/Traffic.vue"),
    "utf8",
  );
  assert.match(trafficSource, /v-for="item in pagedSessions"/);
  assert.match(trafficSource, /v-model:page="sessionPage"/);

  const offlineToolsSource = fs.readFileSync(
    path.resolve(__dirname, "../src/views/OfflineTools.vue"),
    "utf8",
  );
  const offlineToolsStyles = fs.readFileSync(
    path.resolve(__dirname, "../src/offline-tools.css"),
    "utf8",
  );
  assert.match(offlineToolsSource, /role="search"/);
  assert.match(offlineToolsSource, /aria-label="搜索离线工具"/);
  assert.match(offlineToolsSource, /aria-label="清除搜索"/);
  assert.match(offlineToolsSource, /v-if="query"/);
  assert.match(offlineToolsStyles, /\.offline-tool-search:focus-within/);
  assert.match(offlineToolsStyles, /inset 0 -2px 0 0 var\(--app-accent\)/);
  assert.match(offlineToolsStyles, /\.offline-tool-search-clear/);
  assert.match(offlineToolsSource, /FileHexViewer/);
  assert.match(offlineToolsSource, /activeToolId === 'hexfile'/);
  assert.match(offlineToolsSource, /文件十六进制查看/);

  const hexViewerSource = fs.readFileSync(
    path.resolve(__dirname, "../src/components/offline/FileHexViewer.vue"),
    "utf8",
  );
  const networkOfflineStyles = fs.readFileSync(
    path.resolve(__dirname, "../src/network-offline-tools.css"),
    "utf8",
  );
  assert.match(hexViewerSource, /\.slice\(safeOffset,/);
  assert.match(hexViewerSource, /上一页/);
  assert.match(hexViewerSource, /下一页/);
  assert.match(hexViewerSource, /跳转偏移/);
  assert.match(networkOfflineStyles, /\.hex-viewer-table/);

  console.log("Offline tools and shared frontend verification passed.");
}

verify().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
