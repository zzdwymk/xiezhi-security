import type { MsfModuleOption } from "../api";

const OPTION_LABELS: Record<string, string> = {
  PASSWORD: "密码",
  USERNAME: "用户名",
  PROXIES: "代理链",
  SSL: "加密连接",
  VHOST: "虚拟主机",
  TARGETURI: "目标路径",
  HTTPUSERNAME: "HTTP 认证用户名",
  HTTPPASSWORD: "HTTP 认证密码",
  DOMAIN: "域名称",
  HTTP_METHOD: "HTTP 请求方法",
  IGN_HEADER: "忽略的响应头",
  THREADS: "并发线程数",
  TIMEOUT: "超时时间",
  VERBOSE: "详细输出",
  USER_FILE: "用户名字典文件",
  PASS_FILE: "密码字典文件",
  USERPASS_FILE: "用户名与密码字典文件",
  STOP_ON_SUCCESS: "成功后停止",
};

// Match descriptions rather than guessing from the key: PASSWORD can mean a
// login password, a replacement password, or a module-specific credential.
const OPTION_DESCRIPTIONS: Record<string, string> = {
  "the password to reset to": "设置密码重置后使用的新密码。",
  "negotiate ssl/tls for outgoing connections": "使用 SSL/TLS 加密出站连接。",
  "http server virtual host": "HTTP 服务使用的虚拟主机名。",
  "the username to authenticate as": "用于身份认证的用户名。",
  "the password for the specified username": "指定用户名对应的认证密码。",
  "the number of concurrent threads": "同时运行的线程数量。",
  "the number of concurrent threads (max one per host)": "同时运行的线程数量，每台主机最多使用一个线程。",
  "http username": "HTTP 认证使用的用户名。",
  "http password": "HTTP 认证使用的密码。",
  "the base path": "目标服务的基础路径。",
  "the uri to use": "请求使用的目标路径（URI）。",
  "http method to use, head or get (accepted: get, head)": "使用的 HTTP 请求方法，可选 GET 或 HEAD。",
  "list of headers to ignore, separated by comma": "需要忽略的响应头名称，多个名称以逗号分隔。",
};

export function msfOptionPresentation(option: MsfModuleOption) {
  const key = option.name.trim().toUpperCase();
  const description = String(option.description || "").trim();
  const normalizedDescription = description.replace(/\s+/g, " ").replace(/\.$/, "").toLowerCase();
  const proxyFormat = description.match(/^a proxy chain of format\s+(.+)$/i)?.[1];
  const proxyParts = proxyFormat?.split(/\.\s*Supported proxies:\s*/i);
  const type = String(option.type || "").trim().toLowerCase().split("::").pop();

  return {
    displayLabel: key === "PASSWORD" && normalizedDescription === "the password to reset to"
      ? "重置后的密码"
      : OPTION_LABELS[key] || option.name,
    // Preserve unfamiliar module-specific guidance verbatim until a precise
    // translation is available, including constraints and example values.
    displayDescription: OPTION_DESCRIPTIONS[normalizedDescription]
      || (key === "PROXIES" && proxyParts
        ? `代理链格式：${proxyParts[0]?.replace(/\btype:host:port\b/g, "类型:主机:端口")}（多个代理以逗号分隔）。${proxyParts[1] ? `支持的代理：${proxyParts[1]}。` : ""}`
        : description),
    booleanInput: ["bool", "boolean", "optbool"].includes(type || "")
      || (!type && key === "SSL" && /^(true|false)$/.test(option.defaultValue)),
  };
}
