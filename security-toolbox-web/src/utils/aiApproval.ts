import type { ConversationMessage } from "../stores/conversations";

export function isAwaitingAiApproval(message?: ConversationMessage): boolean {
  return Boolean(message?.approvalId && message.steps.length && !message.taskIds.length
    && ["REQUIRED", "PENDING"].includes(message.approvalStatus || ""));
}

/** Approval alone does not prove that the server has created any tasks. */
export function isAwaitingAiDispatch(message?: ConversationMessage): boolean {
  return Boolean(message?.approvalId && message.steps.length && !message.taskIds.length
    && message.approvalStatus === "APPROVED");
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
  const labels: Record<string, string> = { ports: "扫描端口", mode: "识别模式", vulnMode: "扫描模式", check: "检查项目", allPocs: "全部模板", pocCodes: "指定模板", spider: "自动爬取", strength: "扫描强度", module: "模块", modules: "模块", modulePath: "模块路径", modulePaths: "模块路径", moduleOptions: "模块参数", options: "模块参数", url: "检测地址", path: "请求路径" };
  const values: Record<string, string> = { SAFE: "安全", LOW: "低", MEDIUM: "中", HIGH: "高", quick: "快速探测", service: "服务识别", cookies: "Cookie 安全属性", cors: "CORS 跨域策略", methods: "危险 HTTP 方法", disclosure: "技术栈信息泄露" };
  return Object.entries(parameters).map(([key, value]) => ({
    label: labels[key] || key,
    value: typeof value === "boolean" ? value ? "是" : "否" : typeof value === "string" ? values[value] || value : JSON.stringify(value),
  }));
}
