import type { ConversationMessage } from "../stores/conversations";

export function isAwaitingAiApproval(message?: ConversationMessage): boolean {
  return Boolean(message?.approvalId && message.steps.length && !message.taskIds.length
    && ["REQUIRED", "PENDING"].includes(message.approvalStatus || ""));
}

/** Approval alone does not prove that the server has created any tasks. */
export function isAwaitingAiDispatch(message?: ConversationMessage): boolean {
  return Boolean(message?.approvalId && message.steps.length && !message.taskIds.length
    && message.approvalStatus === "APPROVED" && message.approvalDispatchStatus !== "rejected");
}

export function isAiDispatchRejected(message?: ConversationMessage): boolean {
  return Boolean(message?.approvalId && message.approvalStatus === "APPROVED"
    && !message.taskIds.length && message.approvalDispatchStatus === "rejected");
}

/** These exact server errors occur before executeApprovedPlan; other failures leave the result unknown. */
export function aiDispatchFailureStatus(error: unknown): "rejected" | "unknown" {
  const response = (error as { response?: { status?: unknown; data?: { message?: unknown } } } | undefined)?.response;
  const beforeDispatchErrors = new Set([
    "授权目标已停用", "目标授权已过期", "目标授权尚未生效",
    "项目授权范围已变化或原审批未保存授权快照，请重新申请",
    "目标地址或授权范围已变化，原审批不能继续执行，请重新申请",
  ]);
  return response?.status === 400 && typeof response.data?.message === "string"
    && beforeDispatchErrors.has(response.data.message) ? "rejected" : "unknown";
}

/** Called only from a newly received turn, never while restoring chat history. */
export function createAiApprovalPromptGate() {
  const shown = new Set<string>();
  return (activeThreadId: string | undefined, threadId: string, message: ConversationMessage) => {
    if (activeThreadId !== threadId || !isAwaitingAiApproval(message)) return false;
    const key = `${threadId}:${message.approvalId}`;
    if (shown.has(key)) return false;
    shown.add(key);
    return true;
  };
}

export function approvalParameterRows(parameters: Record<string, unknown> = {}) {
  const labels: Record<string, string> = {
    ports: "扫描端口", mode: "识别模式", vulnMode: "扫描模式", check: "检查项目",
    allPocs: "全部模板", pocCodes: "指定模板", spider: "自动爬取", strength: "扫描强度",
    module: "模块", modules: "模块", modulePath: "模块路径", modulePaths: "模块路径",
    moduleOptions: "模块参数", msfOptions: "模块参数", options: "模块参数",
    url: "检测地址", path: "请求路径", query: "检索内容", topK: "检索条数",
    level: "检测级别", risk: "风险级别", technique: "检测技术", data: "请求体",
    method: "请求方法", fuzzRequestUrl: "变异请求地址", fuzzPostBody: "变异请求体",
    fuzzPayload: "变异测试值", fuzzTargetField: "变异目标字段", scanPolicy: "扫描策略",
    ajaxSpider: "动态页面爬取", openApiUrl: "接口文档地址", authType: "认证方式",
    authLoginUrl: "登录地址", authUsername: "认证用户名", authPassword: "认证密码",
    authUsernameField: "用户名字段", authPasswordField: "密码字段",
  };
  // Translate enumerated settings only; literal paths, payloads and module options must stay exact.
  const values: Record<string, Record<string, string>> = {
    mode: { quick: "快速探测", service: "服务识别", passive: "被动扫描", active: "主动扫描" },
    vulnMode: { SAFE: "安全检测", FINGERPRINT: "指纹识别", FULL: "完整检测" },
    strength: { LOW: "低", MEDIUM: "中", HIGH: "高", INSANE: "极高" },
    check: { cookies: "Cookie 安全属性", cors: "CORS 跨域策略", methods: "危险 HTTP 方法", disclosure: "技术栈信息泄露" },
    authType: { form: "表单认证", json: "JSON 认证" },
    scanPolicy: {
      "Default Policy": "默认策略", Developer: "开发者策略", "Security Baseline": "安全基线",
      Manager: "管理者策略", "Testing - HIGH": "高强度测试", "Testing - MEDIUM": "中强度测试", "Testing - LOW": "低强度测试",
    },
  };
  return Object.entries(parameters).map(([key, value]) => ({
    label: labels[key] || key,
    value: typeof value === "boolean" ? value ? "是" : "否" : typeof value === "string" ? values[key]?.[value] || value : JSON.stringify(value),
  }));
}
