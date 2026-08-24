<script setup lang="ts">
import { computed, markRaw, ref } from "vue";
import "../offline-tools.css";
import "../network-offline-tools.css";
import { ElMessage } from "element-plus";
import { formatDateTime } from "../utils/dateTime";
import {
  Clock,
  Coin,
  Compass,
  Connection,
  CopyDocument,
  DataAnalysis,
  Dismiss,
  Document,
  DocumentChecked,
  EditPen,
  Files,
  Filter,
  Flag,
  Key,
  List,
  Lock,
  MagicStick,
  RefreshLeft,
  Search,
  Switch,
  Tools,
  Warning,
} from "../components/fluentIcons";
import EndpointExtractor from "../components/offline/EndpointExtractor.vue";
import FileHexViewer from "../components/offline/FileHexViewer.vue";
import FileInspector from "../components/offline/FileInspector.vue";
import HttpMessageAnalyzer from "../components/offline/HttpMessageAnalyzer.vue";
import IocExtractor from "../components/offline/IocExtractor.vue";
import NetworkCalculator from "../components/offline/NetworkCalculator.vue";
import { toErrorMessage } from "../utils/errorMessage";
import { useSelectionIndicator } from "../composables/useSelectionIndicator";
import {
  bytesToBase64,
  decodeBase64,
  decodeHex,
  digestText,
  encodeBase64,
  encodeHex,
  encryptAesGcm,
  decryptAesGcm,
  hmacSha256,
  md5Text,
  randomBytes,
} from "../utils/offlineCrypto";
import {
  buildQueryString,
  buildUrl,
  COMMON_PORTS,
  identifyHash,
  lookupPort,
  parseQueryString,
  parseUrlDetailed,
  PAYLOAD_PRESETS,
  type PayloadStep,
  radixToText,
  runPayloadChain,
  testRegex,
  textToRadix,
  xorCrypt,
  xorDecryptHex,
} from "../utils/offlinePentest";

type ToolId =
  | "codec"
  | "hash"
  | "aes"
  | "classic"
  | "network"
  | "http"
  | "ioc"
  | "endpoints"
  | "file"
  | "hexfile"
  | "jwt"
  | "json"
  | "timestamp"
  | "generator"
  | "text"
  | "urlparse"
  | "hashid"
  | "payload"
  | "regex"
  | "radix"
  | "xor"
  | "ports";

interface ToolDefinition {
  id: ToolId;
  name: string;
  description: string;
  icon: ReturnType<typeof markRaw>;
  tags: string;
}

interface ToolGroup {
  name: string;
  tools: ToolDefinition[];
}

const groups: ToolGroup[] = [
  {
    name: "编码转换",
    tools: [
      {
        id: "codec",
        name: "编码转换",
        description: "Base64、Hex、URL 与 HTML 实体",
        icon: markRaw(Switch),
        tags: "base64 base64url hex url html 编码 解码",
      },
    ],
  },
  {
    name: "密码与摘要",
    tools: [
      {
        id: "hash",
        name: "哈希与 HMAC",
        description: "SHA 系列摘要与 HMAC-SHA256",
        icon: markRaw(Coin),
        tags: "sha hash hmac 摘要 哈希",
      },
      {
        id: "aes",
        name: "AES 加解密",
        description: "AES-256-GCM + PBKDF2 口令派生",
        icon: markRaw(Lock),
        tags: "aes gcm pbkdf2 加密 解密",
      },
      {
        id: "classic",
        name: "古典密码",
        description: "凯撒、ROT13 与 Atbash",
        icon: markRaw(Key),
        tags: "caesar rot13 atbash 凯撒 古典 密码",
      },
    ],
  },
  {
    name: "网络安全分析",
    tools: [
      {
        id: "network",
        name: "IPv4 / CIDR 计算",
        description: "子网、广播、掩码与地址范围",
        icon: markRaw(Compass),
        tags: "ip ipv4 cidr subnet netmask broadcast 网段 子网",
      },
      {
        id: "http",
        name: "HTTP 报文分析",
        description: "解析请求响应与检查安全响应头",
        icon: markRaw(DocumentChecked),
        tags: "http request response header cookie cors csp 报文 响应头",
      },
      {
        id: "ioc",
        name: "IOC 指标提取",
        description: "从日志中提取 IP、域名、哈希与 CVE",
        icon: markRaw(Filter),
        tags: "ioc ip domain url hash cve 威胁情报 日志",
      },
      {
        id: "endpoints",
        name: "URL / 接口提取",
        description: "从 HTML、JS 和文本中提取端点",
        icon: markRaw(DataAnalysis),
        tags: "url endpoint api javascript jsfinder 接口 域名",
      },
      {
        id: "file",
        name: "文件哈希与类型",
        description: "魔数、熵、MD5 与 SHA 文件摘要",
        icon: markRaw(Files),
        tags: "file hash md5 sha magic entropy 文件 类型 熵",
      },
      {
        id: "hexfile",
        name: "文件十六进制查看",
        description: "Offset、Hex 与 ASCII 分块对照",
        icon: markRaw(Document),
        tags: "file hex viewer offset ascii binary 文件 十六进制 偏移",
      },
    ],
  },
  {
    name: "数据处理",
    tools: [
      {
        id: "jwt",
        name: "JWT 解析",
        description: "离线查看 Header 与 Payload",
        icon: markRaw(Document),
        tags: "jwt token payload header 解析",
      },
      {
        id: "json",
        name: "JSON 工具",
        description: "格式化、压缩与键名排序",
        icon: markRaw(EditPen),
        tags: "json 格式化 压缩 排序",
      },
      {
        id: "timestamp",
        name: "时间戳转换",
        description: "秒、毫秒和本地时间互转",
        icon: markRaw(Clock),
        tags: "timestamp unix 时间戳 日期",
      },
      {
        id: "text",
        name: "文本处理",
        description: "大小写、去重、排序与命名转换",
        icon: markRaw(MagicStick),
        tags: "text case snake kebab camel 去重 排序",
      },
    ],
  },
  {
    name: "随机生成",
    tools: [
      {
        id: "generator",
        name: "安全随机生成",
        description: "UUID、随机密码与随机字节",
        icon: markRaw(RefreshLeft),
        tags: "uuid password random 随机 密码 字节",
      },
    ],
  },
  {
    name: "安全渗透辅助",
    tools: [
      {
        id: "urlparse",
        name: "URL / 参数解析",
        description: "拆解协议、主机、路径与查询参数",
        icon: markRaw(Connection),
        tags: "url querystring param 解析 构造 渗透",
      },
      {
        id: "hashid",
        name: "哈希类型识别",
        description: "根据长度与格式推断 MD5/SHA/NTLM/bcrypt 等",
        icon: markRaw(Search),
        tags: "hash identify md5 sha ntlm bcrypt 识别",
      },
      {
        id: "payload",
        name: "Payload 编码链",
        description: "URL/HTML/Unicode/Base64 串联编码，便于授权绕过实验",
        icon: markRaw(MagicStick),
        tags: "payload xss sqli ssti waf encode 编码链 绕过",
      },
      {
        id: "regex",
        name: "正则提取实验室",
        description: "在日志或响应中批量提取匹配与捕获组",
        icon: markRaw(Filter),
        tags: "regex regexp 正则 提取 match capture",
      },
      {
        id: "radix",
        name: "进制 / Unicode 转换",
        description: "ASCII、Hex、Bin、Oct 与码点互转",
        icon: markRaw(Switch),
        tags: "ascii hex bin oct unicode 进制 转换",
      },
      {
        id: "xor",
        name: "XOR 编解码",
        description: "按密钥循环异或，输出 Hex/Base64",
        icon: markRaw(Key),
        tags: "xor cipher 异或 编码 解码",
      },
      {
        id: "ports",
        name: "常见端口速查",
        description: "渗透常见服务端口与风险提示",
        icon: markRaw(Flag),
        tags: "port service 端口 服务 redis mongodb rdp smb",
      },
    ],
  },
];

const activeToolId = ref<ToolId>("codec");
const query = ref("");
const offlineToolSearchInput = ref<HTMLInputElement | null>(null);
const offlineToolIndex = ref<HTMLElement | null>(null);
const offlineToolGroups = ref<HTMLElement | null>(null);
const activeTool = computed(
  () =>
    groups
      .flatMap((group) => group.tools)
      .find((tool) => tool.id === activeToolId.value)!,
);
const filteredGroups = computed(() => {
  const keyword = query.value.trim().toLowerCase();
  if (!keyword) return groups;
  return groups
    .map((group) => ({
      ...group,
      tools: group.tools.filter((tool) =>
        `${tool.name} ${tool.description} ${tool.tags}`
          .toLowerCase()
          .includes(keyword),
      ),
    }))
    .filter((group) => group.tools.length);
});

async function copyText(value: string) {
  if (!value) return ElMessage.warning("暂无可复制内容");
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    textarea.remove();
  }
  ElMessage.success("已复制到剪贴板");
}

function errorMessage(error: unknown, fallback = "处理失败，请检查输入") {
  ElMessage.error(toErrorMessage(error, fallback));
}

const codecType = ref("base64");
const codecInput = ref("");
const codecOutput = ref("");
const codecFilterChinese = ref(false);

function filterChinese(value: string) {
  return value.replace(/[\u4e00-\u9fff\u3400-\u4dbf\uf900-\ufaff\u3000-\u303f\uff00-\uffef]/g, "");
}

function htmlEncode(value: string) {
  return value.replace(
    /[&<>"']/g,
    (char) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[char] || char,
  );
}

function htmlDecode(value: string) {
  const textarea = document.createElement("textarea");
  textarea.innerHTML = value;
  return textarea.value;
}

const urlToolTab = ref<"parse" | "build" | "query">("parse");
const urlInput = ref("https://example.com/path?id=1&debug=true#top");
const urlParsed = ref("");
const urlHost = ref("example.com");
const urlProtocol = ref("https");
const urlPath = ref("/path");
const urlSearch = ref("id=1&debug=true");
const urlHash = ref("top");
const urlBuilt = ref("");
const queryInput = ref("id=1&name=test&redirect=/admin");
const queryRows = ref<{ key: string; value: string }[]>([
  { key: "id", value: "1" },
  { key: "name", value: "test" },
]);
const queryBuilt = ref("");

const hashIdInput = ref("");
const hashIdHits = ref<{ name: string; confidence: string; note: string }[]>(
  [],
);

const payloadInput = ref("<scr" + "ipt>alert(1)</scr" + "ipt>");
const payloadSteps = ref<PayloadStep[]>(["url", "base64"]);
const payloadTrace = ref<{ step: string; output: string }[]>([]);
const payloadFinal = ref("");

const regexPattern = ref("https?:\\/\\/\\S+");
const regexFlags = ref("gi");
const regexInput = ref("");
const regexOutput = ref("");

const radixInput = ref("Xiezhi");
const radixMode = ref<"ascii" | "hex" | "bin" | "oct" | "codePoints">("hex");
const radixOutput = ref("");
const radixDecodeMode = ref<"ascii" | "hex" | "bin" | "oct">("hex");

const xorInput = ref("password");
const xorKey = ref("key");
const xorOutput = ref("");
const xorHexInput = ref("");
const xorDecryptOut = ref("");

const portQuery = ref("445");
const portHits = ref(COMMON_PORTS.slice(0, 8));

function runUrlParse() {
  try {
    const parsed = parseUrlDetailed(urlInput.value);
    urlParsed.value = JSON.stringify(parsed, null, 2);
    urlProtocol.value = parsed.protocol;
    urlHost.value = parsed.host;
    urlPath.value = parsed.pathname;
    urlSearch.value = parsed.search.replace(/^\?/, "");
    urlHash.value = parsed.hash.replace(/^#/, "");
  } catch (error: any) {
    errorMessage(error, "URL 解析失败");
  }
}

function runUrlBuild() {
  try {
    urlBuilt.value = buildUrl({
      protocol: urlProtocol.value,
      host: urlHost.value,
      pathname: urlPath.value,
      search: urlSearch.value,
      hash: urlHash.value,
    });
  } catch (error: any) {
    errorMessage(error, "URL 构造失败");
  }
}

function runQueryParse() {
  try {
    queryRows.value = parseQueryString(queryInput.value);
    if (!queryRows.value.length) queryRows.value = [{ key: "", value: "" }];
  } catch (error: any) {
    errorMessage(error, "查询参数解析失败");
  }
}

function runQueryBuild() {
  queryBuilt.value = buildQueryString(queryRows.value);
}

function addQueryRow() {
  queryRows.value.push({ key: "", value: "" });
}

function runHashId() {
  if (!hashIdInput.value.trim()) return ElMessage.warning("请粘贴待识别哈希");
  hashIdHits.value = identifyHash(hashIdInput.value);
}

function runPayload() {
  try {
    const result = runPayloadChain(
      payloadInput.value,
      payloadSteps.value.length ? payloadSteps.value : ["plain"],
    );
    payloadTrace.value = result.trace;
    payloadFinal.value = result.final;
  } catch (error: any) {
    errorMessage(error, "编码失败");
  }
}

function applyPayloadPreset(value: string) {
  payloadInput.value = value;
  runPayload();
}

function runRegex() {
  try {
    const result = testRegex(
      regexPattern.value,
      regexFlags.value,
      regexInput.value,
    );
    regexOutput.value = result.matches.length
      ? result.matches
          .map(
            (item, index) =>
              `#${index + 1} @${item.index}\n${item.text}${item.groups.length ? `\n groups: ${JSON.stringify(item.groups)}` : ""}`,
          )
          .join("\n\n")
      : "无匹配";
    ElMessage.success(`匹配 ${result.count} 处`);
  } catch (error: any) {
    errorMessage(error, "正则执行失败");
  }
}

function runRadixEncode() {
  try {
    radixOutput.value = textToRadix(radixInput.value, radixMode.value);
  } catch (error: any) {
    errorMessage(error, "转换失败");
  }
}

function runRadixDecode() {
  try {
    radixInput.value = radixToText(
      radixOutput.value || radixInput.value,
      radixDecodeMode.value,
    );
  } catch (error: any) {
    errorMessage(error, "解码失败");
  }
}

function runXorEncrypt() {
  try {
    xorOutput.value = xorCrypt(xorInput.value, xorKey.value, "hex");
  } catch (error: any) {
    errorMessage(error, "XOR 失败");
  }
}

function runXorDecrypt() {
  try {
    xorDecryptOut.value = xorDecryptHex(
      xorHexInput.value || xorOutput.value,
      xorKey.value,
    );
  } catch (error: any) {
    errorMessage(error, "XOR 解密失败");
  }
}

function runPortLookup() {
  const port = Number(portQuery.value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    portHits.value = COMMON_PORTS;
    return ElMessage.warning("端口需为 1-65535，已显示常用列表");
  }
  const hits = lookupPort(port);
  portHits.value = hits.length
    ? hits
    : [
        {
          port,
          service: "未知",
          note: "未在内置常见端口表中，请结合服务指纹继续判断",
        },
      ];
}

function runCodec(direction: "encode" | "decode") {
  try {
    let value = codecInput.value;
    if (direction === "encode" && codecFilterChinese.value)
      value = filterChinese(value);
    if (codecType.value === "base64")
      codecOutput.value =
        direction === "encode" ? encodeBase64(value) : decodeBase64(value);
    if (codecType.value === "base64url")
      codecOutput.value =
        direction === "encode"
          ? encodeBase64(value, true)
          : decodeBase64(value);
    if (codecType.value === "hex")
      codecOutput.value =
        direction === "encode" ? encodeHex(value) : decodeHex(value);
    if (codecType.value === "url")
      codecOutput.value =
        direction === "encode"
          ? encodeURIComponent(value)
          : decodeURIComponent(value);
    if (codecType.value === "html")
      codecOutput.value =
        direction === "encode" ? htmlEncode(value) : htmlDecode(value);
  } catch (error) {
    errorMessage(error);
  }
}

function swapCodec() {
  [codecInput.value, codecOutput.value] = [codecOutput.value, codecInput.value];
}

const hashInput = ref("");
const hmacSecret = ref("");
const hashResults = ref<Record<string, string>>({});
const hashing = ref(false);

useSelectionIndicator({
  container: offlineToolIndex,
  activeSelector: ".offline-tool-item.active",
  indicatorSelector: ".offline-tool-indicator",
  dependencies: [activeToolId, query, filteredGroups],
  scrollContainers: [offlineToolGroups],
});

function clearToolQuery() {
  query.value = "";
  offlineToolSearchInput.value?.focus();
}

async function calculateHashes() {
  hashing.value = true;
  try {
    const algorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"] as const;
    const values = await Promise.all(
      algorithms.map(
        async (algorithm) =>
          [algorithm, await digestText(hashInput.value, algorithm)] as const,
      ),
    );
    hashResults.value = {
      MD5: md5Text(hashInput.value),
      ...Object.fromEntries(values),
    };
    if (hmacSecret.value)
      hashResults.value["HMAC-SHA256"] = await hmacSha256(
        hashInput.value,
        hmacSecret.value,
      );
  } catch (error) {
    errorMessage(error);
  } finally {
    hashing.value = false;
  }
}

const aesInput = ref("");
const aesOutput = ref("");
const aesPassword = ref("");
const aesWorking = ref(false);

async function runAes(direction: "encrypt" | "decrypt") {
  aesWorking.value = true;
  try {
    aesOutput.value =
      direction === "encrypt"
        ? await encryptAesGcm(aesInput.value, aesPassword.value)
        : await decryptAesGcm(aesInput.value, aesPassword.value);
  } catch (error) {
    errorMessage(error);
  } finally {
    aesWorking.value = false;
  }
}

const classicType = ref("caesar");
const classicShift = ref(3);
const classicInput = ref("");
const classicOutput = ref("");

function rotateLatin(value: string, shift: number) {
  return value.replace(/[a-z]/gi, (char) => {
    const base = char <= "Z" ? 65 : 97;
    return String.fromCharCode(
      ((char.charCodeAt(0) - base + shift + 2600) % 26) + base,
    );
  });
}

function atbash(value: string) {
  return value.replace(/[a-z]/gi, (char) => {
    const base = char <= "Z" ? 65 : 97;
    return String.fromCharCode(base + 25 - (char.charCodeAt(0) - base));
  });
}

function runClassic(direction: "encrypt" | "decrypt") {
  const shift =
    classicType.value === "rot13" ? 13 : Number(classicShift.value) || 0;
  classicOutput.value =
    classicType.value === "atbash"
      ? atbash(classicInput.value)
      : rotateLatin(
          classicInput.value,
          direction === "encrypt" ? shift : -shift,
        );
}

const jwtInput = ref("");
const jwtHeader = ref("");
const jwtPayload = ref("");

function parseJwt() {
  try {
    const parts = jwtInput.value.trim().split(".");
    if (parts.length < 2)
      throw new Error("JWT 至少应包含 Header 和 Payload 两部分");
    jwtHeader.value = JSON.stringify(
      JSON.parse(decodeBase64(parts[0])),
      null,
      2,
    );
    jwtPayload.value = JSON.stringify(
      JSON.parse(decodeBase64(parts[1])),
      null,
      2,
    );
  } catch (error) {
    errorMessage(error);
  }
}

const jsonInput = ref("");
const jsonOutput = ref("");
const jsonIndent = ref(2);

function sortObject(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortObject);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, sortObject(item)]),
    );
  }
  return value;
}

function runJson(mode: "format" | "minify" | "sort") {
  try {
    const parsed = JSON.parse(jsonInput.value);
    const value = mode === "sort" ? sortObject(parsed) : parsed;
    jsonOutput.value = JSON.stringify(
      value,
      null,
      mode === "minify" ? 0 : Number(jsonIndent.value),
    );
  } catch (error) {
    errorMessage(error);
  }
}

const timestampInput = ref(String(Date.now()));
const dateInput = ref(new Date().toLocaleString("zh-CN", { hour12: false }));
const timestampResult = ref("");
const dateResult = ref("");

function timestampToDate() {
  const raw = Number(timestampInput.value.trim());
  if (!Number.isFinite(raw)) return ElMessage.error("请输入有效时间戳");
  const milliseconds = Math.abs(raw) < 100_000_000_000 ? raw * 1000 : raw;
  const date = new Date(milliseconds);
  if (Number.isNaN(date.getTime()))
    return ElMessage.error("时间戳超出有效范围");
  dateResult.value = `${formatDateTime(date.toISOString())}\n标准时间：${date.toISOString()}`;
}

function dateToTimestamp() {
  const date = new Date(dateInput.value);
  if (Number.isNaN(date.getTime()))
    return ElMessage.error(
      "请输入浏览器可识别的日期，例如 2026-07-13 23:30:00",
    );
  timestampResult.value = `秒：${Math.floor(date.getTime() / 1000)}\n毫秒：${date.getTime()}`;
}

const generatorLength = ref(24);
const includeUppercase = ref(true);
const includeLowercase = ref(true);
const includeNumbers = ref(true);
const includeSymbols = ref(true);
const generatorOutput = ref("");

function secureRandomIndex(max: number) {
  if (max <= 0) throw new Error("字符集不能为空");
  const limit = Math.floor(256 / max) * max;
  while (true) {
    const value = randomBytes(1)[0];
    if (value < limit) return value % max;
  }
}

function generatePassword() {
  try {
    let alphabet = "";
    if (includeUppercase.value) alphabet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (includeLowercase.value) alphabet += "abcdefghijklmnopqrstuvwxyz";
    if (includeNumbers.value) alphabet += "0123456789";
    if (includeSymbols.value) alphabet += "!@#$%^&*()-_=+[]{}:,.?";
    if (!alphabet) throw new Error("请至少选择一种字符类型");
    const length = Math.min(
      256,
      Math.max(4, Number(generatorLength.value) || 24),
    );
    generatorOutput.value = Array.from(
      { length },
      () => alphabet[secureRandomIndex(alphabet.length)],
    ).join("");
  } catch (error) {
    errorMessage(error);
  }
}

function generateUuid() {
  generatorOutput.value = crypto.randomUUID();
}

function generateRandomBytes() {
  generatorOutput.value = bytesToBase64(
    randomBytes(
      Math.min(1024, Math.max(1, Number(generatorLength.value) || 24)),
    ),
  );
}

const textInput = ref("");
const textOutput = ref("");
const textOperation = ref("dedupe");
const textStats = computed(() => ({
  chars: Array.from(textInput.value).length,
  bytes: new TextEncoder().encode(textInput.value).length,
  lines: textInput.value ? textInput.value.split(/\r?\n/).length : 0,
  words: textInput.value.trim()
    ? textInput.value.trim().split(/\s+/).length
    : 0,
}));

function words(value: string) {
  return value
    .trim()
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);
}

function runText() {
  const value = textInput.value;
  if (textOperation.value === "upper") textOutput.value = value.toUpperCase();
  if (textOperation.value === "lower") textOutput.value = value.toLowerCase();
  if (textOperation.value === "dedupe")
    textOutput.value = [...new Set(value.split(/\r?\n/))].join("\n");
  if (textOperation.value === "sort")
    textOutput.value = value
      .split(/\r?\n/)
      .sort((a, b) => a.localeCompare(b, "zh-CN"))
      .join("\n");
  if (textOperation.value === "reverse")
    textOutput.value = Array.from(value).reverse().join("");
  if (textOperation.value === "snake")
    textOutput.value = words(value)
      .map((item) => item.toLowerCase())
      .join("_");
  if (textOperation.value === "kebab")
    textOutput.value = words(value)
      .map((item) => item.toLowerCase())
      .join("-");
  if (textOperation.value === "camel") {
    const parts = words(value).map((item) => item.toLowerCase());
    textOutput.value = parts
      .map((item, index) =>
        index ? item[0]?.toUpperCase() + item.slice(1) : item,
      )
      .join("");
  }
}
</script>

<template>
  <div class="offline-tools-page">
    <header class="offline-tools-heading">
      <div>
        <span>LOCAL UTILITIES</span>
        <h1>离线工具集</h1>
        <p>编码、摘要、加解密与常用数据处理均在当前设备内完成。</p>
      </div>
      <div class="offline-privacy-badge"><i />输入内容不会上传</div>
    </header>

    <div class="offline-tools-layout">
      <aside ref="offlineToolIndex" class="offline-tool-index">
        <span
          class="fluent-selection-indicator offline-tool-indicator"
          aria-hidden="true"
        />
        <div class="offline-tool-search" role="search">
          <el-icon class="offline-tool-search-icon" aria-hidden="true"
            ><Search
          /></el-icon>
          <input
            ref="offlineToolSearchInput"
            v-model="query"
            type="search"
            aria-label="搜索离线工具"
            autocomplete="off"
            placeholder="搜索工具…"
          />
          <el-tooltip
            v-if="query"
            content="清除搜索"
            placement="top"
            :show-after="350"
          >
            <button
              type="button"
              class="offline-tool-search-clear"
              aria-label="清除搜索"
              @click="clearToolQuery"
            >
              <el-icon aria-hidden="true"><Dismiss /></el-icon>
            </button>
          </el-tooltip>
        </div>
        <div ref="offlineToolGroups" class="offline-tool-groups">
          <div v-if="!filteredGroups.length" class="offline-tool-empty">
            没有匹配的工具
          </div>
          <section v-for="group in filteredGroups" :key="group.name">
            <h2>{{ group.name }}</h2>
            <button
              v-for="tool in group.tools"
              :key="tool.id"
              type="button"
              class="offline-tool-item"
              :class="{ active: activeToolId === tool.id }"
              @click="activeToolId = tool.id"
            >
              <el-icon><component :is="tool.icon" /></el-icon>
              <span
                ><strong>{{ tool.name }}</strong
                ><small>{{ tool.description }}</small></span
              >
            </button>
          </section>
        </div>
      </aside>

      <section class="offline-workbench">
        <header class="offline-workbench-head">
          <span class="offline-workbench-icon"
            ><el-icon><component :is="activeTool.icon" /></el-icon
          ></span>
          <div>
            <h2>{{ activeTool.name }}</h2>
            <p>{{ activeTool.description }}</p>
          </div>
        </header>

        <div v-if="activeToolId === 'codec'" class="offline-tool-body">
          <div class="offline-control-row">
            <label
              >编码类型
              <el-select v-model="codecType" style="width: 180px">
                <el-option label="Base64" value="base64" />
                <el-option label="Base64 URL Safe" value="base64url" />
                <el-option label="Hex 十六进制" value="hex" />
                <el-option label="URL 百分号编码" value="url" />
                <el-option label="HTML 实体" value="html" />
              </el-select>
            </label>
            <el-checkbox v-model="codecFilterChinese">过滤中文字符</el-checkbox>
          </div>
          <div class="offline-editor-grid">
            <label
              >输入<el-input v-model="codecInput" type="textarea" :autosize="{ minRows: 3 }" placeholder="输入要编码或解码的文本" />
            </label>
            <label
              >结果<el-input v-model="codecOutput" type="textarea" :autosize="{ minRows: 3 }" readonly placeholder="处理结果会显示在这里" />
            </label>
          </div>
          <div class="offline-actions">
            <el-button type="primary" @click="runCodec('encode')"
              >编码</el-button
            >
            <el-button @click="runCodec('decode')">解码</el-button>
            <el-button :icon="Switch" @click="swapCodec">交换</el-button>
            <el-button :icon="CopyDocument" @click="copyText(codecOutput)"
              >复制结果</el-button
            >
            <el-button
              type="danger"
              plain
              @click="
                codecInput = '';
                codecOutput = '';
              "
              >清空</el-button
            >
          </div>
        </div>

        <div v-else-if="activeToolId === 'hash'" class="offline-tool-body">
          <label class="offline-field"
            >原文<el-input v-model="hashInput" type="textarea" :autosize="{ minRows: 3 }" placeholder="输入待计算摘要的文本" />
          </label>
          <label class="offline-field compact"
            >HMAC 密钥（可选）<el-input
              v-model="hmacSecret"
              type="password"
              show-password
              placeholder="填写后额外计算 HMAC-SHA256"
          /></label>
          <div class="offline-actions">
            <el-button
              type="primary"
              :loading="hashing"
              @click="calculateHashes"
              >计算摘要</el-button
            >
          </div>
          <div v-if="Object.keys(hashResults).length" class="hash-results">
            <article v-for="(value, name) in hashResults" :key="name">
              <header>
                <strong>{{ name }}</strong
                ><button
                  type="button"
                  class="offline-copy-action"
                  aria-label="复制摘要"
                  @click="copyText(value)"
                >
                  <el-icon><CopyDocument /></el-icon>复制
                </button>
              </header>
              <code>{{ value }}</code>
            </article>
          </div>
        </div>

        <div v-else-if="activeToolId === 'aes'" class="offline-tool-body">
          <div class="offline-notice">
            采用 AES-256-GCM 认证加密，口令通过 PBKDF2-SHA256
            派生；每次加密自动生成随机盐和 IV。
          </div>
          <label class="offline-field compact"
            >加密口令<el-input
              v-model="aesPassword"
              type="password"
              show-password
              placeholder="用于加密或解密"
          /></label>
          <div class="offline-editor-grid">
            <label
              >输入<el-input v-model="aesInput" type="textarea" :autosize="{ minRows: 3 }" placeholder="加密时输入原文；解密时粘贴本工具生成的 JSON 加密包" />
            </label>
            <label
              >结果<el-input v-model="aesOutput" type="textarea" :autosize="{ minRows: 3 }" readonly placeholder="加密包或解密后的原文" />
            </label>
          </div>
          <div class="offline-actions">
            <el-button
              type="primary"
              :loading="aesWorking"
              @click="runAes('encrypt')"
              >加密</el-button
            >
            <el-button :loading="aesWorking" @click="runAes('decrypt')"
              >解密</el-button
            >
            <el-button
              :icon="Switch"
              @click="
                aesInput = aesOutput;
                aesOutput = '';
              "
              >将结果作为输入</el-button
            >
            <el-button :icon="CopyDocument" @click="copyText(aesOutput)"
              >复制结果</el-button
            >
          </div>
        </div>

        <div v-else-if="activeToolId === 'classic'" class="offline-tool-body">
          <div class="offline-control-row">
            <label
              >算法<el-select v-model="classicType" style="width: 180px"
                ><el-option label="凯撒密码" value="caesar" /><el-option
                  label="ROT13"
                  value="rot13" /><el-option
                  label="Atbash"
                  value="atbash" /></el-select
            ></label>
            <label v-if="classicType === 'caesar'"
              >位移<el-input-number v-model="classicShift" :min="0" :max="25"
            /></label>
          </div>
          <div class="offline-editor-grid">
            <label>输入<el-input v-model="classicInput" type="textarea" :autosize="{ minRows: 3 }" /></label
            ><label>结果<el-input v-model="classicOutput" type="textarea" :autosize="{ minRows: 3 }" readonly /></label>
          </div>
          <div class="offline-actions">
            <el-button type="primary" @click="runClassic('encrypt')"
              >加密</el-button
            ><el-button @click="runClassic('decrypt')">解密</el-button
            ><el-button :icon="CopyDocument" @click="copyText(classicOutput)"
              >复制结果</el-button
            >
          </div>
        </div>

        <NetworkCalculator v-else-if="activeToolId === 'network'" />
        <HttpMessageAnalyzer v-else-if="activeToolId === 'http'" />
        <IocExtractor v-else-if="activeToolId === 'ioc'" />
        <EndpointExtractor v-else-if="activeToolId === 'endpoints'" />
        <FileInspector v-else-if="activeToolId === 'file'" />
        <FileHexViewer v-else-if="activeToolId === 'hexfile'" />

        <div
          v-else-if="activeToolId === 'urlparse'"
          class="offline-tool-body url-tool-body"
        >
          <div class="offline-notice">
            仅在本机解析
            URL，不会发网络请求。适合拆解重定向、钓鱼链接和带签名的回调地址。
          </div>
          <el-tabs v-model="urlToolTab" class="url-tool-tabs">
            <el-tab-pane label="URL 解析" name="parse">
              <label class="offline-field"
                >URL<el-input v-model="urlInput" type="textarea" :autosize="{ minRows: 3, maxRows: 8 }" placeholder="https://host/path?x=1" />
              </label>
              <div class="offline-actions">
                <el-button type="primary" @click="runUrlParse"
                  >解析 URL</el-button
                >
                <el-button :icon="CopyDocument" @click="copyText(urlParsed)"
                  >复制解析 JSON</el-button
                >
              </div>
              <label class="offline-field"
                >解析结果<el-input v-model="urlParsed" type="textarea" :autosize="{ minRows: 5, maxRows: 8 }" readonly />
              </label>
            </el-tab-pane>
            <el-tab-pane label="URL 构造" name="build">
              <div class="offline-editor-grid url-build-grid">
                <label>协议<el-input v-model="urlProtocol" /></label>
                <label>主机<el-input v-model="urlHost" /></label>
                <label>路径<el-input v-model="urlPath" /></label>
                <label>查询串（不含 ?）<el-input v-model="urlSearch" /></label>
              </div>
              <div class="offline-actions">
                <el-button type="primary" @click="runUrlBuild"
                  >构造 URL</el-button
                >
                <el-button :icon="CopyDocument" @click="copyText(urlBuilt)"
                  >复制构造结果</el-button
                >
              </div>
              <label class="offline-field"
                >构造结果<el-input v-model="urlBuilt" type="textarea" :autosize="{ minRows: 3, maxRows: 8 }" readonly />
              </label>
            </el-tab-pane>
            <el-tab-pane label="Query 参数" name="query">
              <label class="offline-field"
                >Query 字符串<el-input v-model="queryInput" type="textarea" :autosize="{ minRows: 3, maxRows: 8 }" />
              </label>
              <div class="offline-actions">
                <el-button type="primary" @click="runQueryParse"
                  >解析参数</el-button
                >
                <el-button @click="addQueryRow">新增参数行</el-button>
                <el-button @click="runQueryBuild">重新拼接</el-button>
                <el-button :icon="CopyDocument" @click="copyText(queryBuilt)"
                  >复制 Query</el-button
                >
              </div>
              <div class="query-parameter-list">
                <div
                  v-for="(row, index) in queryRows"
                  :key="index"
                  class="offline-control-row"
                >
                  <el-input
                    v-model="row.key"
                    placeholder="key"
                    style="max-width: 180px"
                  />
                  <el-input v-model="row.value" placeholder="value" />
                </div>
              </div>
              <label class="offline-field"
                >拼接结果<el-input v-model="queryBuilt" type="textarea" :autosize="{ minRows: 3, maxRows: 8 }" readonly />
              </label>
            </el-tab-pane>
          </el-tabs>
        </div>

        <div v-else-if="activeToolId === 'hashid'" class="offline-tool-body">
          <div class="offline-notice">
            根据长度与前缀做启发式识别，结果仅供授权测试与取证研判参考。
          </div>
          <label class="offline-field"
            >哈希 / 密文<el-input v-model="hashIdInput" type="textarea" :autosize="{ minRows: 3 }" placeholder="粘贴 md5/sha/ntlm/bcrypt 等" />
          </label>
          <div class="offline-actions">
            <el-button type="primary" @click="runHashId">识别类型</el-button>
          </div>
          <div v-if="hashIdHits.length" class="pentest-hit-list">
            <article
              v-for="item in hashIdHits"
              :key="item.name + item.note"
              class="pentest-hit-card"
              :data-level="item.confidence"
            >
              <header>
                <strong>{{ item.name }}</strong
                ><span>{{ item.confidence }}</span>
              </header>
              <p>{{ item.note }}</p>
            </article>
          </div>
        </div>

        <div v-else-if="activeToolId === 'payload'" class="offline-tool-body">
          <div class="offline-notice">
            仅用于授权范围内的安全测试与教学。请勿对未授权目标使用。
          </div>
          <div class="payload-presets">
            <el-button
              v-for="item in PAYLOAD_PRESETS"
              :key="item.name"
              size="small"
              @click="applyPayloadPreset(item.value)"
              >{{ item.name }}</el-button
            >
          </div>
          <label class="offline-field payload-input-field"
            >原始 Payload<el-input v-model="payloadInput" type="textarea" :autosize="{ minRows: 4 }" />
          </label>
          <label class="offline-field payload-chain-field">
            编码链（可多选，按顺序执行）
            <el-select
              v-model="payloadSteps"
              multiple
              collapse-tags
              style="width: 100%"
            >
              <el-option label="URL" value="url" />
              <el-option label="双重 URL" value="url2" />
              <el-option label="HTML 实体" value="html" />
              <el-option label="Base64" value="base64" />
              <el-option label="Hex" value="hex" />
              <el-option label="\\u Unicode" value="unicode" />
              <el-option label="&amp;#x HTML hex" value="unicode-hex" />
              <el-option label="JS \\x/\\u 转义" value="escape-js" />
            </el-select>
          </label>
          <div class="offline-actions payload-actions">
            <el-button type="primary" @click="runPayload">执行编码链</el-button>
            <el-button :icon="CopyDocument" @click="copyText(payloadFinal)"
              >复制最终结果</el-button
            >
          </div>
          <label class="offline-field payload-output-field"
            >最终输出<el-input v-model="payloadFinal" type="textarea" :autosize="{ minRows: 3 }" readonly />
          </label>
          <div v-if="payloadTrace.length" class="pentest-hit-list">
            <article
              v-for="(item, index) in payloadTrace"
              :key="index"
              class="pentest-hit-card"
            >
              <header>
                <strong>步骤 {{ index + 1 }} · {{ item.step }}</strong>
              </header>
              <pre>{{ item.output }}</pre>
            </article>
          </div>
        </div>

        <div v-else-if="activeToolId === 'regex'" class="offline-tool-body">
          <div class="offline-control-row">
            <label class="grow"
              >正则<el-input v-model="regexPattern" placeholder="https?:\/\/\S+" /></label>
            <label
              >标志<el-input
                v-model="regexFlags"
                placeholder="gi"
                style="width: 100px"
            /></label>
          </div>
          <div class="offline-editor-grid">
            <label
              >输入文本<el-input v-model="regexInput" type="textarea" :autosize="{ minRows: 3 }" placeholder="粘贴日志、HTML 或响应" />
            </label>
            <label>匹配结果<el-input v-model="regexOutput" type="textarea" :autosize="{ minRows: 3 }" readonly /></label>
          </div>
          <div class="offline-actions">
            <el-button type="primary" @click="runRegex">提取匹配</el-button>
            <el-button :icon="CopyDocument" @click="copyText(regexOutput)"
              >复制结果</el-button
            >
          </div>
        </div>

        <div v-else-if="activeToolId === 'radix'" class="offline-tool-body">
          <div class="offline-control-row">
            <label
              >编码方式
              <el-select v-model="radixMode" style="width: 160px">
                <el-option label="ASCII 码" value="ascii" />
                <el-option label="Hex" value="hex" />
                <el-option label="Binary" value="bin" />
                <el-option label="Octal" value="oct" />
                <el-option label="Unicode 码点" value="codePoints" />
              </el-select>
            </label>
            <label
              >解码方式
              <el-select v-model="radixDecodeMode" style="width: 140px">
                <el-option label="ASCII" value="ascii" />
                <el-option label="Hex" value="hex" />
                <el-option label="Binary" value="bin" />
                <el-option label="Octal" value="oct" />
              </el-select>
            </label>
          </div>
          <div class="offline-editor-grid">
            <label>文本<el-input v-model="radixInput" type="textarea" :autosize="{ minRows: 3 }" /></label>
            <label>编码结果<el-input v-model="radixOutput" type="textarea" :autosize="{ minRows: 3 }" /></label>
          </div>
          <div class="offline-actions">
            <el-button type="primary" @click="runRadixEncode"
              >文本 → 编码</el-button
            >
            <el-button @click="runRadixDecode">编码 → 文本</el-button>
            <el-button
              :icon="CopyDocument"
              @click="copyText(radixOutput || radixInput)"
              >复制</el-button
            >
          </div>
        </div>

        <div
          v-else-if="activeToolId === 'xor'"
          class="offline-tool-body xor-tool-body"
        >
          <div class="offline-notice">
            按密钥字节循环异或。常用于简单混淆分析，不提供密码学强度。
          </div>
          <label class="offline-field compact"
            >密钥<el-input v-model="xorKey" placeholder="xor key" />
          </label>
          <div class="xor-workspace-grid">
            <section class="offline-tool-section">
              <h3>文本编码</h3>
              <label class="offline-field"
                >明文 / 输入<el-input v-model="xorInput" type="textarea" :autosize="{ minRows: 3, maxRows: 8 }" />
              </label>
              <div class="offline-actions">
                <el-button type="primary" @click="runXorEncrypt"
                  >XOR → Hex</el-button
                >
                <el-button :icon="CopyDocument" @click="copyText(xorOutput)"
                  >复制 Hex</el-button
                >
              </div>
              <label class="offline-field"
                >Hex 输出<el-input v-model="xorOutput" type="textarea" :autosize="{ minRows: 3, maxRows: 8 }" />
              </label>
            </section>
            <section class="offline-tool-section">
              <h3>Hex 解码</h3>
              <label class="offline-field"
                >待解密 Hex<el-input v-model="xorHexInput" type="textarea" :autosize="{ minRows: 3, maxRows: 8 }" placeholder="默认可用左侧输出" />
              </label>
              <div class="offline-actions">
                <el-button type="primary" @click="runXorDecrypt"
                  >Hex → 文本</el-button
                >
                <el-button :icon="CopyDocument" @click="copyText(xorDecryptOut)"
                  >复制明文</el-button
                >
              </div>
              <label class="offline-field"
                >解密结果<el-input v-model="xorDecryptOut" type="textarea" :autosize="{ minRows: 3, maxRows: 8 }" readonly />
              </label>
            </section>
          </div>
        </div>

        <div v-else-if="activeToolId === 'ports'" class="offline-tool-body">
          <div class="offline-control-row">
            <label
              >端口<el-input
                v-model="portQuery"
                placeholder="445"
                style="width: 120px"
            /></label>
            <el-button type="primary" @click="runPortLookup">查询</el-button>
            <el-button @click="portHits = COMMON_PORTS"
              >显示全部常见端口</el-button
            >
          </div>
          <div class="pentest-hit-list port-hit-list">
            <article
              v-for="item in portHits"
              :key="item.port + item.service"
              class="pentest-hit-card"
            >
              <header>
                <strong>{{ item.port }} / {{ item.service }}</strong>
              </header>
              <p>{{ item.note }}</p>
            </article>
          </div>
        </div>

        <div v-else-if="activeToolId === 'jwt'" class="offline-tool-body">
          <div class="offline-notice">
            这里只解析 JWT 内容，不验证签名，也不代表令牌可信。
          </div>
          <label class="offline-field"
            >JWT<el-input v-model="jwtInput" type="textarea" :autosize="{ minRows: 3 }" placeholder="粘贴 eyJ... 格式的令牌" />
          </label>
          <div class="offline-actions">
            <el-button type="primary" @click="parseJwt">解析</el-button>
          </div>
          <div class="offline-editor-grid">
            <label>Header<el-input v-model="jwtHeader" type="textarea" :autosize="{ minRows: 3 }" readonly /></label
            ><label>Payload<el-input v-model="jwtPayload" type="textarea" :autosize="{ minRows: 3 }" readonly /></label>
          </div>
        </div>

        <div v-else-if="activeToolId === 'json'" class="offline-tool-body">
          <div class="offline-control-row">
            <label
              >缩进<el-select v-model="jsonIndent" style="width: 110px"
                ><el-option :label="'2 空格'" :value="2" /><el-option
                  :label="'4 空格'"
                  :value="4" /></el-select
            ></label>
          </div>
          <div class="offline-editor-grid">
            <label>JSON 输入<el-input v-model="jsonInput" type="textarea" :autosize="{ minRows: 3 }" /></label
            ><label>结果<el-input v-model="jsonOutput" type="textarea" :autosize="{ minRows: 3 }" readonly /></label>
          </div>
          <div class="offline-actions">
            <el-button type="primary" @click="runJson('format')"
              >格式化</el-button
            ><el-button @click="runJson('minify')">压缩</el-button
            ><el-button @click="runJson('sort')">排序键名</el-button
            ><el-button :icon="CopyDocument" @click="copyText(jsonOutput)"
              >复制结果</el-button
            >
          </div>
        </div>

        <div
          v-else-if="activeToolId === 'timestamp'"
          class="offline-tool-body timestamp-tools"
        >
          <article>
            <h3>时间戳 → 日期</h3>
            <p>自动识别秒级或毫秒级时间戳。</p>
            <el-input
              v-model="timestampInput"
              placeholder="例如 1783956600000"
            />
            <el-button type="primary" @click="timestampToDate">转换</el-button>
            <pre>{{ dateResult || "等待转换" }}</pre>
          </article>
          <article>
            <h3>日期 → 时间戳</h3>
            <p>按当前设备时区解析输入日期。</p>
            <el-input v-model="dateInput" placeholder="2026-07-13 23:30:00" />
            <el-button type="primary" @click="dateToTimestamp">转换</el-button>
            <pre>{{ timestampResult || "等待转换" }}</pre>
          </article>
        </div>

        <div v-else-if="activeToolId === 'generator'" class="offline-tool-body">
          <div class="generator-settings">
            <label
              >长度<el-input-number
                v-model="generatorLength"
                :min="4"
                :max="256"
            /></label>
            <el-checkbox v-model="includeUppercase">大写字母</el-checkbox
            ><el-checkbox v-model="includeLowercase">小写字母</el-checkbox
            ><el-checkbox v-model="includeNumbers">数字</el-checkbox
            ><el-checkbox v-model="includeSymbols">符号</el-checkbox>
          </div>
          <label class="offline-field"
            >生成结果<el-input v-model="generatorOutput" type="textarea" :autosize="{ minRows: 3 }" readonly />
          </label>
          <div class="offline-actions">
            <el-button type="primary" @click="generatePassword"
              >生成密码</el-button
            ><el-button @click="generateUuid">生成 UUID</el-button
            ><el-button @click="generateRandomBytes"
              >生成随机字节（Base64）</el-button
            ><el-button :icon="CopyDocument" @click="copyText(generatorOutput)"
              >复制</el-button
            >
          </div>
        </div>

        <div v-else class="offline-tool-body">
          <div class="text-stats">
            <span
              >字符 <b>{{ textStats.chars }}</b></span
            ><span
              >字节 <b>{{ textStats.bytes }}</b></span
            ><span
              >单词 <b>{{ textStats.words }}</b></span
            ><span
              >行数 <b>{{ textStats.lines }}</b></span
            >
          </div>
          <div class="offline-control-row">
            <label
              >处理方式<el-select v-model="textOperation" style="width: 180px"
                ><el-option label="行去重" value="dedupe" /><el-option
                  label="行排序"
                  value="sort" /><el-option
                  label="转大写"
                  value="upper" /><el-option
                  label="转小写"
                  value="lower" /><el-option
                  label="反转文本"
                  value="reverse" /><el-option
                  label="snake_case"
                  value="snake" /><el-option
                  label="kebab-case"
                  value="kebab" /><el-option
                  label="camelCase"
                  value="camel" /></el-select
            ></label>
          </div>
          <div class="offline-editor-grid">
            <label>输入<el-input v-model="textInput" type="textarea" :autosize="{ minRows: 3 }" /></label
            ><label>结果<el-input v-model="textOutput" type="textarea" :autosize="{ minRows: 3 }" readonly /></label>
          </div>
          <div class="offline-actions">
            <el-button type="primary" @click="runText">处理文本</el-button
            ><el-button :icon="CopyDocument" @click="copyText(textOutput)"
              >复制结果</el-button
            >
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.pentest-hit-list {
  display: grid;
  gap: 10px;
  margin-top: 0;
}
.pentest-hit-card {
  padding: 12px 14px;
  border: 1px solid var(--app-border);
  border-radius: 6px;
  background: var(--app-surface-soft);
}
</style>
