import { toErrorMessage } from "./errorMessage";

const AI_TOOL_LABELS: Readonly<Record<string, string>> = {
  retrieve_project_context: "项目上下文检索",
  tcp_ports: "TCP 端口探测",
  nmap_service_scan: "Nmap 服务识别",
  http_headers: "HTTP 安全响应头检查",
  http_security_check: "HTTP 常见安全检查",
  tls_config: "TLS 基础配置检查",
  site_crawl: "站点链接爬取与信息收集",
  nuclei_scan: "Nuclei 通用漏洞扫描",
  afrog_scan: "Afrog 漏洞扫描",
  xray_scan: "Xray 漏洞扫描",
  zap_scan: "OWASP ZAP 主动扫描",
  zap_fuzz: "ZAP 单次参数变异验证",
  sqlmap_scan: "sqlmap SQL 注入检测",
  dir_scan: "Web 目录与路径探测",
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
  return labels[code] || "未知风险";
}

export function targetTypeLabel(type?: string): string {
  const labels: Record<string, string> = {
    IP: "IP 地址", DOMAIN: "域名", URL: "网址",
    ANY: "任意类型", WEB: "网页", HTTPS: "HTTPS 网址",
  };
  return labels[String(type || "").trim().toUpperCase()] || "未知类型";
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

const AI_DISPLAY_LABELS: Readonly<Record<string, string>> = {
  ...AI_TOOL_LABELS,
  PENDING: "待处理", QUEUED: "排队中", RUNNING: "执行中", SUCCESS: "已完成",
  FAILED: "失败", TIMEOUT: "超时", CANCELLED: "已取消", REJECTED: "已拒绝",
  SKIPPED: "已跳过", STOPPED: "已停止", COMPLETED: "已完成", APPROVED: "已通过", CONFIRMED: "已确认",
  NOT_REQUIRED: "无需确认", DRAFT: "草稿", DISPATCHED: "已下发", EXPIRED: "已过期",
  BLOCKED: "受阻", WAITING_TASKS: "等待前置任务", WAITING_APPROVAL: "等待审批",
  AWAITING_APPROVAL: "等待审批", AWAITING_CONFIRMATION: "等待确认",
  OPEN: "待确认", FALSE_POSITIVE: "误报", FIXED: "已修复", REOPENED: "已复现",
  FINALIZE: "形成结论", REWRITE_QUERY: "调整检索条件", CLARIFY: "需要补充信息",
  DIRECT_SUPPORT: "证据直接支持", PARTIAL_SUPPORT: "证据部分支持",
  NO_RELEVANT_EVIDENCE: "暂无相关证据", CONFLICTING_EVIDENCE: "证据存在冲突",
  SCOPE_MISMATCH: "证据与范围不符", QUERY_TOO_BROAD: "检索范围过宽",
  REWRITE_LIMIT_REACHED: "已达到检索调整次数上限", REWRITE_REJECTED: "检索调整未被采用",
  MODEL: "模型判断", LOCAL_RULE: "本地规则判断",
  SAFE: "安全", CAUTION: "需谨慎", CRITICAL: "严重", HIGH: "高", MEDIUM: "中", LOW: "低", INFO: "提示",
  "AI Runtime": "智能服务", "runtime-public-progress": "服务进度",
  "python-langgraph-runtime": "智能编排服务",
  nodeId: "节点", nodeIds: "节点列表", dependsOnNodeIds: "前置节点",
  nodeRunId: "节点运行", toolCallId: "工具调用", turnId: "对话轮次",
  workflowDigest: "工作流校验信息", ledgerDigest: "执行记录校验信息",
  ledgerEntryDigest: "执行条目校验信息", evidenceRefIds: "证据引用",
};

export interface AiDisplayTextOptions {
  /** Only IDs of nodes actually present in the displayed workflow. */
  nodeLabels?: Readonly<Record<string, string>>;
  /** Known terms belonging to this server-authored surface, such as workflow phases. */
  termLabels?: Readonly<Record<string, string>>;
}

function aiDisplayLabels(options: AiDisplayTextOptions) {
  return { ...AI_DISPLAY_LABELS, ...options.termLabels, ...options.nodeLabels };
}

const INTERNAL_EVIDENCE_ID = /^ev-[0-9a-f]{24}$/;
const INTERNAL_EVIDENCE_REFERENCE = /(^|[^A-Za-z0-9_./@?=&%#$+\\-])(?:证据\s*)?ev-[0-9a-f]{24}(?=$|[^A-Za-z0-9_./@?=&%#$+\\-])/g;

function replaceDisplayTokens(text: string, labels: Readonly<Record<string, string>>) {
  const keys = Object.keys(labels).filter(key => key && labels[key]).sort((a, b) => b.length - a.length);
  const escaped = keys.map(key => key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  // Treat filenames, paths and compound identifiers as a whole; do not translate a substring.
  const pattern = new RegExp(`(^|[^A-Za-z0-9_./@?=&%#$+\\\\-])(${escaped.join("|")})(?=$|[^A-Za-z0-9_./@?=&%#$+\\\\-])`, "g");
  const prose = text
    .replace(INTERNAL_EVIDENCE_REFERENCE, "$1相关证据")
    .replace(/\bAI\s+Runtime\b/g, "智能服务")
    .replace(/\bRuntime\b(?=\s*(?:协议|服务|连接|返回|请求|调用|校验|执行|进程))/g, "智能服务")
    .replace(/\bHarness\b(?=\s*(?:v\d+(?:\.\d+)*\s*)?(?:协议|校验|验证|执行|约束|检查|失败|错误|安全停止))/g, "执行校验")
    .replace(/\bLedger\b(?=\s*(?:摘要链|证据链|协议|校验|记录|条目|摘要|验证|失败|错误))/g, "执行记录")
    .replace(/\bTurn\s+ID\b/g, "对话轮次编号")
    .replace(/(本|当前|这一|上一个)\s*Turn\b/g, "$1轮对话")
    .replace(/\bTurn\b(?=\s*(?:编号|请求|预算|超时|完成|失败|结束|开始|已|尚未))/g, "对话轮次");
  return prose.replace(pattern, (_match, prefix: string, token: string) => prefix + labels[token]);
}

/** Known internal terms in server-authored prose only; callers must preserve user-authored input. */
export function localizeAiDisplayText(value?: string, options: AiDisplayTextOptions = {}): string {
  const source = String(value || "");
  const labels = aiDisplayLabels(options);
  // Plain-text callers can still contain quoted commands or URLs. Markdown surfaces additionally
  // operate on parsed text nodes, so fenced blocks, link destinations and code are never rewritten.
  const protectedParts = /(`+)[\s\S]*?\1|~~~[\s\S]*?~~~|(?:[a-z][a-z\d+.-]*:\/\/|www\.)[^\s<>"'`，。；！？]+/gi;
  let result = "";
  let start = 0;
  for (const match of source.matchAll(protectedParts)) {
    const ticks = match[1];
    const protectedText = ticks && ticks.length < 3
      ? ticks + localizeAiInlineIdentifier(match[0].slice(ticks.length, -ticks.length), options) + ticks
      : match[0];
    result += replaceDisplayTokens(source.slice(start, match.index), labels) + protectedText;
    start = match.index! + match[0].length;
  }
  return result + replaceDisplayTokens(source.slice(start), labels);
}

/** An inline code span is localizable only when its entire value is a known internal token. */
export function localizeAiInlineIdentifier(value: string, options: AiDisplayTextOptions = {}): string {
  const token = value.trim();
  if (INTERNAL_EVIDENCE_ID.test(token)) return value.replace(token, "相关证据");
  const labels = aiDisplayLabels(options);
  const label = Object.prototype.hasOwnProperty.call(labels, token) ? labels[token] : undefined;
  return label ? value.replace(token, () => label) : value;
}

export function aiProviderLabel(provider?: string): string {
  const labels: Record<string, string> = {
    "openai-compatible": "模型服务", "local-rule-fallback": "本地规则（未采用模型结果）",
    "local-rule": "本地规则", "local-rules": "本地规则", local: "本地规则",
    llm: "模型服务", "llm+local": "模型与本地规则",
  };
  const key = String(provider || "").trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(labels, key) ? labels[key] : "来源未说明";
}

const PUBLIC_PROGRESS_TYPES = new Set([
  "route", "evidence", "rewrite", "plan", "step", "stage", "progress", "status",
  "state", "guard", "review", "decision", "context", "session", "model",
  "tool_call", "tool_result", "approval", "retry", "citation", "done", "error",
]);

const EVIDENCE_DECISIONS = new Set(["FINALIZE", "REWRITE_QUERY", "CLARIFY"]);
const EVIDENCE_REASONS = new Set(["DIRECT_SUPPORT", "PARTIAL_SUPPORT", "NO_RELEVANT_EVIDENCE", "CONFLICTING_EVIDENCE", "SCOPE_MISMATCH", "QUERY_TOO_BROAD"]);

/** Only typed public decisions are retained, never model reasoning payloads. */
export function publicProgressProvenance(value: Record<string, unknown>) {
  const decision = (candidate: unknown) => typeof candidate === "string" && EVIDENCE_DECISIONS.has(candidate) ? candidate : undefined;
  return {
    source: ["runtime-public-progress", "python-langgraph-runtime"].includes(String(value.source)) ? String(value.source) : undefined,
    assessmentSource: value.assessmentSource === "MODEL" || value.assessmentSource === "LOCAL_RULE" ? value.assessmentSource : undefined,
    modelDecision: decision(value.modelDecision),
    evidenceDecision: decision(value.evidenceDecision),
    reasonCodes: Array.isArray(value.reasonCodes) ? [...new Set(value.reasonCodes.filter((reason): reason is string => typeof reason === "string" && EVIDENCE_REASONS.has(reason)))].slice(0, 6) : undefined,
    guardReason: value.guardReason === "REWRITE_LIMIT_REACHED" || value.guardReason === "REWRITE_REJECTED" ? value.guardReason : undefined,
  };
}

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
  return localizeAiDisplayText(text).slice(0, limit);
}

export function aiElapsedLabel(milliseconds: number): string {
  const seconds = Number.isFinite(milliseconds) ? Math.max(0, Math.floor(milliseconds / 1000)) : 0;
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  return seconds % 60 ? `${minutes} 分 ${seconds % 60} 秒` : `${minutes} 分`;
}

export function aiProgressFailureText(value: unknown, hasTasks: boolean): string {
  const text = publicAiProgressText(typeof value === "string" ? localizeAiRuntimeFailure(value) : "");
  if (!hasTasks) return text;
  // Persisted error text may predate task creation. The linked task records are
  // authoritative; do not repeat an old claim that no approval/task exists.
  return text.replace(/(?:尚未提交审批申请[，,、；;]\s*)?(?:未创建检测任务[，,、；;]\s*)?(?:本轮(?:已停止[，,])?)?(?:没有执行检测|未执行任何检测)|未创建检测任务/g,
    "已创建任务的状态请以任务中心为准");
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
    : localizeAiDisplayText(message);
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
  return SEVERITY_LABELS[key] || "未知";
}
