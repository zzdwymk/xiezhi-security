import { toErrorMessage } from "./errorMessage";

const AI_TOOL_LABELS: Readonly<Record<string, string>> = {
  retrieve_project_context: "项目上下文检索",
  tcp_ports: "TCP 端口探测",
  nmap_service_scan: "Nmap 服务识别",
  http_headers: "HTTP 安全响应头检查",
  http_security_check: "HTTP 常见安全检查",
  tls_config: "TLS 基础配置检查",
  nuclei_scan: "Nuclei 通用漏洞扫描",
  afrog_scan: "Afrog 漏洞扫描",
  xray_scan: "Xray 漏洞扫描",
};

const AI_RUNTIME_LEDGER_FAILURE =
  /(?:本地\s*)?AI\s*Runtime[^\n]*(?:v3\s*)?Ledger[^\n]*(?:证据链|协议校验|安全停止)/i;

const AI_RUNTIME_PROTOCOL_FAILURE =
  /AI\s*Runtime[^\n]*(?:Harness\s*)?协议校验[^\n]*安全停止/i;

const RUNTIME_FAILURE_MESSAGE =
  "智能服务返回的内容格式不完整，系统未采用这次结果。请在当前消息下点击“重试”；若持续出现，请在设置中测试模型连接。";

const LEGACY_RUNTIME_FAILURE_MESSAGE =
  /智能服务返回的内容格式不完整[，。].*(?:未采用|请在当前消息)/i;

const LEGACY_MODEL_FAILURE_MESSAGE =
  "模型服务未能完成这次请求，系统没有采用该结果。请检查模型地址和访问权限，然后在设置中测试连接后重试。";

const AI_RUNTIME_TIMEOUT_FAILURE =
  /(?:超过时间预算|TURN_TIMEOUT|长时间没有返回|连接超时|请求超时)/i;

const RUNTIME_TIMEOUT_MESSAGE =
  "模型在规定时间内没有完成回答，本轮已停止，未执行任何检测。请检查模型连接后重试。";

const MODEL_PROVIDER_FAILURES: ReadonlyArray<readonly [RegExp, string]> = [
  [
    /MODEL_ACCESS_DENIED|模型服务拒绝了这次请求|HTTP\s*(?:401|403)/i,
    "模型服务拒绝了这次请求，本轮没有执行检测。请检查代理地址、模型权限，或更换兼容的 API 服务后重试。",
  ],
  [
    /MODEL_RATE_LIMITED|HTTP\s*429|请求过多/i,
    "模型服务当前请求过多，本轮没有执行检测。请稍后重试。",
  ],
  [
    /MODEL_TIMEOUT|模型服务连接超时|连接超时/i,
    "模型服务连接超时，本轮没有执行检测。请检查服务状态后重试。",
  ],
  [
    /MODEL_SERVICE_UNAVAILABLE|MODEL_REQUEST_FAILED|模型服务(?:暂时不可用|请求失败)/i,
    "模型服务暂时不可用，本轮没有执行检测。请检查模型地址和服务状态后重试。",
  ],
];

export function aiToolLabel(toolCode?: string, providedName?: string): string {
  const code = String(toolCode || "").trim();
  const name = String(providedName || "").trim();
  const localized = AI_TOOL_LABELS[code];
  if (localized && (!name || name === code)) return localized;
  return localizeAiToolCodes(name || localized || code) || "安全检查";
}

export function localizeAiToolCodes(value?: string): string {
  let result = String(value || "");
  for (const [code, label] of Object.entries(AI_TOOL_LABELS)) {
    result = result.replace(new RegExp(`\\b${code}\\b`, "g"), label);
  }
  return result;
}

export function localizeAiRuntimeFailure(value: string): string {
  const message = String(value || "").trim();
  if (AI_RUNTIME_TIMEOUT_FAILURE.test(message)) return RUNTIME_TIMEOUT_MESSAGE;
  for (const [pattern, replacement] of MODEL_PROVIDER_FAILURES) {
    if (pattern.test(message)) return replacement;
  }
  // Older conversations persisted the generic protocol wording. Keep those
  // records understandable after the provider error classification changed.
  if (LEGACY_RUNTIME_FAILURE_MESSAGE.test(message)) {
    return LEGACY_MODEL_FAILURE_MESSAGE;
  }
  return AI_RUNTIME_LEDGER_FAILURE.test(message) ||
    AI_RUNTIME_PROTOCOL_FAILURE.test(message)
    ? RUNTIME_FAILURE_MESSAGE
    : message;
}

export function readableAiConversationError(
  error: unknown,
  fallback: string,
): string {
  return localizeAiRuntimeFailure(toErrorMessage(error, fallback));
}
