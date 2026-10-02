import type { ConversationStep } from "../stores/conversations";

export function aiEventStepStatus(event: { type?: string; status?: string; error?: unknown; recorded?: boolean }): string | undefined {
  const status = String(event.status || "").toUpperCase();
  if (["SUCCESS", "SUCCEEDED", "COMPLETED", "DONE"].includes(status)) return "success";
  if (["FAILED", "ERROR", "REJECTED", "CANCELLED", "TIMEOUT", "SKIPPED"].includes(status)) return status.toLowerCase();
  if (event.error || event.type === "error") return "failed";
  if (["APPROVAL_REQUIRED", "WAITING_APPROVAL", "PENDING_APPROVAL"].includes(status)) return "awaiting_approval";
  if (status === "NOT_REQUIRED" || status === "RECORDED" || event.recorded) return undefined;
  if (["RUNNING", "EXECUTING", "IN_PROGRESS"].includes(status) || event.type === "tool_call") return "running";
  if (["PENDING", "BLOCKED", "DISPATCHED", "QUEUED"].includes(status)) return status.toLowerCase();
  return undefined;
}

export function findMatchingAiStep(steps: ConversationStep[], incoming: Partial<ConversationStep>): ConversationStep | undefined {
  for (const key of ["taskId", "toolCallId", "id", "workflowNodeId"] as const) {
    const value = incoming[key];
    if (!value || (key === "id" && /^(?:agent-step|plan-step)-\d+$/.test(String(value)))) continue;
    const matches = steps.filter(step => step[key] === value && !(incoming.taskId && step.taskId && incoming.taskId !== step.taskId));
    if (matches.length === 1) return matches[0];
  }
  return undefined;
}

export function mergeAiStep(current: ConversationStep | undefined, incoming: ConversationStep): ConversationStep {
  if (!current) return incoming;
  const terminal = /^(success|completed|done|failed|error|rejected|cancelled|timeout|skipped)$/i.test(current.status || "");
  const retry = (incoming.attempt || 0) > (current.attempt || 0);
  return { ...current, ...incoming,
    status: terminal && !retry ? current.status : incoming.status || current.status,
    progress: terminal && !retry ? current.progress : incoming.progress ?? current.progress,
    taskId: incoming.taskId || current.taskId,
    parameters: incoming.parameters || current.parameters,
  };
}
