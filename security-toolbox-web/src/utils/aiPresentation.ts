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
  zap_scan: "OWASP ZAP 主动扫描",
  zap_fuzz: "OWASP ZAP 模糊测试",
  sqlmap_scan: "sqlmap SQL 注入检测",
  fscan_scan: "fscan 主机扫描",
  msf_scan: "Metasploit 模块执行",
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

/** Execution risk is separate from a finding's vulnerability severity. */
export function actionRiskLabel(risk?: string): string {
  const code = String(risk || "").trim().toUpperCase();
  const labels: Record<string, string> = {
    SAFE: "低风险", LOW: "低风险", MEDIUM: "中等风险",
    CAUTION: "需谨慎", HIGH: "高风险", CRITICAL: "严重风险",
    BLOCKED: "已拦截",
  };
  return labels[code] || String(risk || "未知风险");
}

export function copilotReferenceTypeLabel(type?: string): string {
  const labels: Record<string, string> = {
    target: "授权目标", task: "检测任务", finding: "安全发现", vulnerability: "漏洞知识",
    traffic: "流量会话", "traffic-session": "流量会话", audit: "审计记录",
    "audit-log": "审计记录", "ai-settings-status": "AI 服务状态",
  };
  return labels[String(type || "")] || "功能引用";
}

/** Display only the strict legacy fixture name format; never rewrite stored names or messages. */
export function displayKnownTestName(value?: string): string {
  const name = String(value || "");
  const match = /^(AI本机HTTP夹具|AI本机闭环验收)-(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z$/.exec(name);
  if (!match) return name;
  const iso = `${match[2]}T${match[3]}:${match[4]}:${match[5]}.${match[6]}Z`;
  const date = new Date(iso);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== iso) return name;
  const time = new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
  }).format(date).replace(/\//g, "-");
  return `${match[1] === "AI本机HTTP夹具" ? "AI 本机 HTTP 测试目标" : "AI 本机闭环验收"} · ${time}`;
}

export function displayConversationTitle(thread?: {
  title: string;
  messages?: { role: string; content: string }[];
}): string {
  const stored = thread?.title || "";
  const prompt = thread?.messages?.find(message => message.role === "user")?.content.replace(/\s+/g, " ").trim() || "";
  const generated = prompt.length > 28 ? `${prompt.slice(0, 28)}…` : prompt;
  // Recover only titles still matching the original automatic truncation.
  // Localize the full source before truncation so fscan_sc… cannot leak through.
  const automatic = Boolean(prompt && stored === generated);
  const title = localizeAiToolCodes(displayKnownTestName(automatic ? prompt : stored));
  return automatic && title.length > 28 ? `${title.slice(0, 28)}…` : title;
}

/** Replace default scanner aliases, while preserving user-authored step names. */
export function actionStepLabel(toolCode?: string, label?: string): string {
  const name = String(label || "").trim();
  const code = String(toolCode || "").trim();
  const alias = code.replace(/_scan$/, "");
  if (!name || name.toLowerCase() === code.toLowerCase() || name.toLowerCase() === alias.toLowerCase()) {
    return aiToolLabel(code);
  }
  return localizeAiToolCodes(name);
}

/** Stable ZAP alert names only. Original titles and raw evidence stay intact. */
export function findingTitleLabel(title?: string, sourceTool?: string): string {
  const original = String(title || "");
  if (sourceTool !== "zap_scan") return original;
  const labels: Record<string, string> = {
    "Missing Anti-clickjacking Header": "缺少防点击劫持响应头",
    "Content Security Policy (CSP) Header Not Set": "未设置内容安全策略（CSP）响应头",
    'Server Leaks Version Information via "Server" HTTP Response Header Field': "Server 响应头泄露服务器版本信息",
    "X-Content-Type-Options Header Missing": "缺少 X-Content-Type-Options 响应头",
  };
  return labels[original] || original;
}

export function localizeAiToolCodes(value?: string): string {
  let result = String(value || "");
  for (const [code, label] of Object.entries(AI_TOOL_LABELS)) {
    result = result.replace(new RegExp(`\\b${code}\\b`, "g"), label);
  }
  return result;
}

const PUBLIC_PROGRESS_TYPES = new Set([
  "route", "evidence", "rewrite", "plan", "step", "stage", "progress", "status",
  "state", "guard", "review", "decision", "context", "session", "model",
  "tool_call", "tool_result", "approval", "retry", "citation", "done", "error",
]);

/** Public lifecycle summaries are separate from model reasoning and raw tool payloads. */
export function isPublicAiProgressEvent(event: { type?: string; stage?: string }) {
  return PUBLIC_PROGRESS_TYPES.has(String(event.type || "").toLowerCase())
    && !/reasoning|thinking|chain[_ -]?of[_ -]?thought|analysis_delta/i.test(`${event.type} ${event.stage || ""}`);
}

export function publicAiProgressText(value: unknown, limit = 480): string {
  if (typeof value !== "string") return "";
  // Never surface private-reasoning blocks, serialized protocol payloads or identifiers.
  if (/<\/?(?:think|thinking|reasoning|analysis)\b|(?:reasoning_content|chain_of_thought)\s*[:=]/i.test(value)) return "";
  const text = value.split(/\r?\n/)
    .filter(line => !/\b(?:runId|nodeRunId|workflowDigest|ledgerDigest|ledgerEntryDigest|toolCallId|sessionId)\b\s*[:=]/i.test(line))
    .join(" ").replace(/\s+/g, " ").trim();
  if (/^[\[{]/.test(text) || /\b(?:Harness|Ledger)\b.*(?:digest|协议|校验)/i.test(text)) return "";
  return localizeAiToolCodes(text).slice(0, limit);
}

export function aiElapsedLabel(milliseconds: number): string {
  const seconds = Number.isFinite(milliseconds) ? Math.max(0, Math.floor(milliseconds / 1000)) : 0;
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  return seconds % 60 ? `${minutes} 分 ${seconds % 60} 秒` : `${minutes} 分`;
}

export function aiProgressFailureText(value: unknown, hasTasks: boolean): string {
  const text = publicAiProgressText(typeof value === "string" ? localizeAiRuntimeFailure(value) : "");
  return hasTasks ? text.replace(/本轮(?:已停止[，,])?(?:没有执行检测|未执行任何检测)|未执行任何检测/g, "已创建任务的状态请以任务中心为准") : text;
}

export function localizeAiRuntimeFailure(value: string): string {
  const message = String(value || "").trim();
  // Streaming storage and message rendering both normalize errors. Preserve the
  // current format diagnosis when it passes through this function a second time.
  if (message === RUNTIME_FAILURE_MESSAGE) return message;
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

export const SEVERITY_LABELS: Readonly<Record<string, string>> = {
  CRITICAL: "严重",
  HIGH: "高危",
  MEDIUM: "中危",
  LOW: "低危",
  INFO: "提示",
};

export function severityLabel(severity?: string): string {
  if (!severity) return "未知";
  const key = String(severity).trim().toUpperCase();
  return SEVERITY_LABELS[key] || severity;
}
