export type AiExecutionIntent = "AUTO";
export type AiExecutionDecision = "EXECUTE" | "PLAN_ONLY" | "CLARIFY";

/** AUTO is a server decision, never a client-side permission to execute. Old
 * messages retain their original intent when retried, including approval resumes. */
export function aiExecutionRequest(message: {
  executionIntent?: AiExecutionIntent;
  executionRequested?: boolean;
  content?: string;
}) {
  if (message.executionIntent !== "AUTO") return { execute: message.executionRequested === true };
  const userPrompt = message.content?.trim() || "";
  if (!userPrompt || userPrompt.length > 4000) throw new Error("请提供 1 至 4000 字的本轮请求。");
  return { executionIntent: "AUTO" as const, userPrompt };
}

export function normalizeAiExecutionDecision(value: unknown): AiExecutionDecision | undefined {
  return value === "EXECUTE" || value === "PLAN_ONLY" || value === "CLARIFY" ? value : undefined;
}

export function assertAiLegacyFallbackAllowed(payload: { executionIntent?: AiExecutionIntent }) {
  if (payload.executionIntent === "AUTO")
    throw new Error("当前服务不支持根据对话判断执行意图。请确认目标已关联评估项目，并更新服务后重试。");
}
