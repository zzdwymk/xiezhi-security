export interface CidrInfo {
  input: string;
  address: string;
  prefix: number;
  netmask: string;
  wildcard: string;
  network: string;
  broadcast: string;
  firstHost: string;
  lastHost: string;
  addressCount: number;
  usableHostCount: number;
  scope: string;
  integer: number;
  hexadecimal: string;
  binary: string;
}

export function parseIpv4(value: string) {
  const parts = value.trim().split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) {
    throw new Error("请输入有效的 IPv4 地址");
  }
  const numbers = parts.map(Number);
  if (numbers.some((part) => part < 0 || part > 255))
    throw new Error("IPv4 每段必须在 0 到 255 之间");
  return numbers.reduce((result, part) => result * 256 + part, 0);
}

export function intToIpv4(value: number) {
  const normalized = Math.max(0, Math.min(0xffffffff, Math.floor(value)));
  return [
    Math.floor(normalized / 0x1000000) % 256,
    Math.floor(normalized / 0x10000) % 256,
    Math.floor(normalized / 0x100) % 256,
    normalized % 256,
  ].join(".");
}

function ipv4Scope(value: number) {
  const first = Math.floor(value / 0x1000000);
  const second = Math.floor(value / 0x10000) % 256;
  const third = Math.floor(value / 0x100) % 256;
  if (
    first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  )
    return "私有地址";
  if (first === 127) return "环回地址";
  if (first === 169 && second === 254) return "链路本地地址";
  if (first === 100 && second >= 64 && second <= 127)
    return "运营商级 NAT 地址";
  if (first >= 224 && first <= 239) return "组播地址";
  if (first >= 240) return "保留地址";
  if (
    (first === 192 && second === 0 && third === 2) ||
    (first === 198 && second === 51 && third === 100) ||
    (first === 203 && second === 0 && third === 113)
  )
    return "文档示例地址";
  if (value === 0 || first === 0) return "未指定/当前网络地址";
  if (value === 0xffffffff) return "受限广播地址";
  return "公网地址";
}

export function calculateCidr(input: string): CidrInfo {
  const [addressText, prefixText = "32", ...rest] = input.trim().split("/");
  if (rest.length) throw new Error("CIDR 格式不正确");
  const addressValue = parseIpv4(addressText);
  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32)
    throw new Error("CIDR 前缀必须在 0 到 32 之间");
  const addressCount = 2 ** (32 - prefix);
  const networkValue = Math.floor(addressValue / addressCount) * addressCount;
  const broadcastValue = networkValue + addressCount - 1;
  const maskValue = 0xffffffff - (addressCount - 1);
  let firstHostValue = networkValue;
  let lastHostValue = broadcastValue;
  let usableHostCount = addressCount;
  if (prefix <= 30) {
    firstHostValue += 1;
    lastHostValue -= 1;
    usableHostCount = Math.max(0, addressCount - 2);
  }
  return {
    input: input.trim(),
    address: intToIpv4(addressValue),
    prefix,
    netmask: intToIpv4(maskValue),
    wildcard: intToIpv4(addressCount - 1),
    network: `${intToIpv4(networkValue)}/${prefix}`,
    broadcast: intToIpv4(broadcastValue),
    firstHost: intToIpv4(firstHostValue),
    lastHost: intToIpv4(lastHostValue),
    addressCount,
    usableHostCount,
    scope: ipv4Scope(addressValue),
    integer: addressValue,
    hexadecimal: `0x${addressValue.toString(16).padStart(8, "0").toUpperCase()}`,
    binary: addressValue
      .toString(2)
      .padStart(32, "0")
      .replace(/(.{8})(?=.)/g, "$1."),
  };
}

export interface HttpHeader {
  name: string;
  value: string;
}

export interface HeaderCheck {
  name: string;
  status: "good" | "warning" | "info";
  message: string;
}

export interface HttpMessageInfo {
  type: "request" | "response";
  startLine: string;
  method?: string;
  target?: string;
  version?: string;
  statusCode?: number;
  statusText?: string;
  headers: HttpHeader[];
  body: string;
  checks: HeaderCheck[];
}

function headerValues(headers: HttpHeader[], name: string) {
  return headers
    .filter((header) => header.name.toLowerCase() === name.toLowerCase())
    .map((header) => header.value);
}

function firstHeader(headers: HttpHeader[], name: string) {
  return headerValues(headers, name)[0] || "";
}

function analyzeResponseHeaders(headers: HttpHeader[]) {
  const checks: HeaderCheck[] = [];
  const recommended = [
    ["Content-Security-Policy", "限制脚本、样式和其他资源的加载来源"],
    ["Strict-Transport-Security", "强制浏览器后续使用 HTTPS"],
    ["X-Content-Type-Options", "建议设置为 nosniff"],
    ["Referrer-Policy", "限制 Referer 信息泄露"],
    ["Permissions-Policy", "限制摄像头、定位等浏览器能力"],
    ["X-Frame-Options", "减少点击劫持风险，也可由 CSP frame-ancestors 替代"],
  ] as const;
  for (const [name, description] of recommended) {
    const value = firstHeader(headers, name);
    checks.push(
      value
        ? { name, status: "good", message: value }
        : { name, status: "warning", message: `缺少：${description}` },
    );
  }
  const server = firstHeader(headers, "Server");
  if (server)
    checks.push({ name: "Server 信息暴露", status: "info", message: server });
  const poweredBy = firstHeader(headers, "X-Powered-By");
  if (poweredBy)
    checks.push({
      name: "X-Powered-By 信息暴露",
      status: "warning",
      message: poweredBy,
    });
  const allowOrigin = firstHeader(headers, "Access-Control-Allow-Origin");
  const allowCredentials = firstHeader(
    headers,
    "Access-Control-Allow-Credentials",
  );
  if (allowOrigin === "*" && allowCredentials.toLowerCase() === "true") {
    checks.push({
      name: "CORS 配置",
      status: "warning",
      message:
        "同时允许任意来源和凭据，浏览器通常会拒绝，但说明策略配置存在问题",
    });
  } else if (allowOrigin) {
    checks.push({
      name: "CORS 配置",
      status: "info",
      message: `允许来源：${allowOrigin}`,
    });
  }
  for (const cookie of headerValues(headers, "Set-Cookie")) {
    const missing = ["Secure", "HttpOnly", "SameSite"].filter(
      (flag) => !new RegExp(`(?:^|;)\\s*${flag}(?:=|;|$)`, "i").test(cookie),
    );
    checks.push({
      name: `Cookie ${cookie.split("=", 1)[0] || "未命名"}`,
      status: missing.length ? "warning" : "good",
      message: missing.length
        ? `缺少属性：${missing.join("、")}`
        : "已包含 Secure、HttpOnly 和 SameSite",
    });
  }
  return checks;
}

export function parseHttpMessage(source: string): HttpMessageInfo {
  const normalized = source.replace(/\r\n/g, "\n").trim();
  if (!normalized) throw new Error("请粘贴原始 HTTP 请求或响应");
  const lines = normalized.split("\n");
  const startLine = lines.shift()?.trim() || "";
  const headers: HttpHeader[] = [];
  let bodyIndex = lines.findIndex((line) => line === "");
  if (bodyIndex < 0) bodyIndex = lines.length;
  const headerLines = lines.slice(0, bodyIndex);
  for (const line of headerLines) {
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1].value += ` ${line.trim()}`;
      continue;
    }
    const separator = line.indexOf(":");
    if (separator <= 0) continue;
    headers.push({
      name: line.slice(0, separator).trim(),
      value: line.slice(separator + 1).trim(),
    });
  }
  const body = lines.slice(bodyIndex + 1).join("\n");
  const responseMatch = startLine.match(
    /^HTTP\/(\d(?:\.\d)?)\s+(\d{3})(?:\s+(.*))?$/i,
  );
  if (responseMatch) {
    return {
      type: "response",
      startLine,
      version: `HTTP/${responseMatch[1]}`,
      statusCode: Number(responseMatch[2]),
      statusText: responseMatch[3] || "",
      headers,
      body,
      checks: analyzeResponseHeaders(headers),
    };
  }
  const requestMatch = startLine.match(
    /^([A-Z]+)\s+(\S+)\s+(HTTP\/\d(?:\.\d)?)$/i,
  );
  if (!requestMatch) throw new Error("无法识别 HTTP 起始行");
  const checks: HeaderCheck[] = [];
  const authorization = firstHeader(headers, "Authorization");
  if (authorization)
    checks.push({
      name: "Authorization",
      status: "info",
      message: `包含 ${authorization.split(/\s+/, 1)[0]} 凭据，分享报文前请脱敏`,
    });
  if (firstHeader(headers, "Cookie"))
    checks.push({
      name: "Cookie",
      status: "info",
      message: "请求中包含 Cookie，分享报文前请脱敏",
    });
  if (
    !firstHeader(headers, "Host") &&
    requestMatch[3].toUpperCase() === "HTTP/1.1"
  )
    checks.push({
      name: "Host",
      status: "warning",
      message: "HTTP/1.1 请求缺少 Host 头",
    });
  return {
    type: "request",
    startLine,
    method: requestMatch[1].toUpperCase(),
    target: requestMatch[2],
    version: requestMatch[3].toUpperCase(),
    headers,
    body,
    checks,
  };
}

function uniqueSorted(values: Iterable<string>) {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b, "en"));
}

function cleanUrl(value: string) {
  return value.replace(/[),.;\]}]+$/g, "");
}

export interface IocResult {
  urls: string[];
  domains: string[];
  ipv4: string[];
  emails: string[];
  md5: string[];
  sha1: string[];
  sha256: string[];
  cves: string[];
}

export function extractIocs(source: string): IocResult {
  const urls = uniqueSorted(
    (source.match(/https?:\/\/[^\s<>"'`]+/gi) || []).map(cleanUrl),
  );
  const ipv4 = uniqueSorted(
    (source.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter((value) => {
      try {
        parseIpv4(value);
        return true;
      } catch {
        return false;
      }
    }),
  );
  const emails = uniqueSorted(
    source.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/gi) || [],
  );
  const domains = uniqueSorted(
    source.match(
      /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})\b/gi,
    ) || [],
  );
  return {
    urls,
    domains,
    ipv4,
    emails,
    md5: uniqueSorted(source.match(/\b[a-f0-9]{32}\b/gi) || []),
    sha1: uniqueSorted(source.match(/\b[a-f0-9]{40}\b/gi) || []),
    sha256: uniqueSorted(source.match(/\b[a-f0-9]{64}\b/gi) || []),
    cves: uniqueSorted(
      (source.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).map((value) =>
        value.toUpperCase(),
      ),
    ),
  };
}

export function defangIoc(value: string) {
  return value
    .replace(/^https:/i, "hxxps:")
    .replace(/^http:/i, "hxxp:")
    .replace(/@/g, "[@]")
    .replace(/\./g, "[.]");
}

export function refangIoc(value: string) {
  return value
    .replace(/^hxxps:/i, "https:")
    .replace(/^hxxp:/i, "http:")
    .replace(/\[@\]/g, "@")
    .replace(/\[\.\]/g, ".");
}

export interface EndpointResult {
  urls: string[];
  paths: string[];
  domains: string[];
}

export function extractEndpoints(source: string, baseUrl = ""): EndpointResult {
  const absolute = (source.match(/https?:\/\/[^\s<>"'`\\]+/gi) || []).map(
    cleanUrl,
  );
  const pathMatches: string[] = [];
  const quotedPath = /["'`]((?:\/|\.\.\/|\.\/)[^"'`\s<>]{1,500})["'`]/g;
  for (const match of source.matchAll(quotedPath)) {
    const value = cleanUrl(match[1]);
    if (!value.startsWith("//") && !value.startsWith("///"))
      pathMatches.push(value);
    if (value.startsWith("//")) absolute.push(`https:${value}`);
  }
  const paths = uniqueSorted(pathMatches);
  const urls = [...absolute];
  if (baseUrl.trim()) {
    let base: URL;
    try {
      base = new URL(baseUrl.trim());
    } catch {
      throw new Error("基础 URL 格式无效");
    }
    for (const path of paths) {
      try {
        urls.push(new URL(path, base).href);
      } catch {
        /* ignore malformed candidate */
      }
    }
  }
  const normalizedUrls = uniqueSorted(urls);
  const domains = uniqueSorted(
    normalizedUrls.flatMap((value) => {
      try {
        return [new URL(value).hostname];
      } catch {
        return [];
      }
    }),
  );
  return { urls: normalizedUrls, paths, domains };
}
