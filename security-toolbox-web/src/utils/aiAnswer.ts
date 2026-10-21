/** Only final answer/plan fields qualify as a reply; progress text never does. */
export function requireAiAnswer(answer: unknown, summary?: unknown): string {
  const text = [answer, summary].find(value => typeof value === "string" && value.trim());
  if (typeof text !== "string") throw new Error("未获得模型回答，请重试或检查模型连接。");
  return text.trim();
}

export function aiAnswerSource(provider?: string, failed = false): string {
  if (failed) return "本轮未完成";
  const source = String(provider || "").trim().toLowerCase();
  if (source === "operation-receipt") return "操作回执";
  if (["local", "local-rule", "local-rules", "local-rule-fallback", "local-summary", "verified-audit-record"].includes(source))
    return "本地规则 · 未获得模型回答";
  if (["llm+local", "大模型+本地规则"].includes(source)) return "模型分析 · 规则参考";
  if (
    [
      "openai-compatible",
      "llm",
      "langgraph-runtime",
      "python-langgraph-runtime",
      "langchain-grounded",
      "langchain",
      "relay",
      "model",
    ].includes(source) ||
    source.includes("gemini") ||
    source.includes("gpt") ||
    source.includes("claude") ||
    source.includes("deepseek") ||
    source.includes("langgraph") ||
    source.includes("grounded")
  )
    return "模型回答";
  return "回答来源未说明";
}

export function isLocalAiAnswer(provider?: string): boolean {
  return aiAnswerSource(provider).includes("未获得模型回答") || provider === "operation-receipt";
}
