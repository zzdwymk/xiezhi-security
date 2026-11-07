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

function hasMeaningfulParameters(params?: Record<string, unknown>): boolean {
  return Boolean(params && typeof params === "object" && Object.keys(params).length > 0);
}

export function findMatchingAiStep(steps: ConversationStep[], incoming: Partial<ConversationStep>): ConversationStep | undefined {
  // actionId first: it is stable across replans of the same step, so a retry turn updates
  // the existing row instead of appending a duplicate.
  for (const key of ["actionId", "taskId", "toolCallId", "id", "workflowNodeId"] as const) {
    const value = incoming[key];
    if (!value || (key === "id" && /^(?:agent-step|plan-step)-\d+$/.test(String(value)))) continue;
    // An event that belongs to a different dispatched task must not be merged into this
    // row — except when the identity matched on actionId, which outranks a taskId change.
    const matches = steps.filter(step => step[key] === value
      && (key === "actionId" || !(incoming.taskId && step.taskId && incoming.taskId !== step.taskId)));
    if (matches.length === 1) return matches[0];
  }
  // When an incoming step or event only carries toolCode (e.g. approval event with minimal payload):
  // if exactly one step in the plan shares that toolCode and incoming does not carry conflicting parameters,
  // match that single step instead of appending a duplicate.
  if (incoming.toolCode && !hasMeaningfulParameters(incoming.parameters as Record<string, unknown> | undefined)) {
    const matches = steps.filter(step => step.toolCode === incoming.toolCode
      && !(incoming.taskId && step.taskId && incoming.taskId !== step.taskId));
    if (matches.length === 1) return matches[0];
  }
  return undefined;
}

export function mergeAiStep(current: ConversationStep | undefined, incoming: ConversationStep): ConversationStep {
  if (!current) return incoming;
  const terminal = /^(success|completed|done|failed|error|rejected|cancelled|timeout|skipped)$/i.test(current.status || "");
  const retry = (incoming.attempt || 0) > (current.attempt || 0);
  return {
    ...current,
    ...incoming,
    id: incoming.id || current.id,
    actionId: incoming.actionId || current.actionId,
    workflowNodeId: incoming.workflowNodeId || current.workflowNodeId,
    nodeRunId: incoming.nodeRunId || current.nodeRunId,
    toolCode: incoming.toolCode || current.toolCode,
    title: incoming.title || current.title,
    reason: incoming.reason || current.reason,
    risk: incoming.risk || current.risk,
    requiresApproval: incoming.requiresApproval !== undefined ? incoming.requiresApproval : current.requiresApproval,
    status: terminal && !retry ? current.status : incoming.status || current.status,
    progress: terminal && !retry ? current.progress : incoming.progress ?? current.progress,
    taskId: incoming.taskId || current.taskId,
    parameters: hasMeaningfulParameters(incoming.parameters) ? incoming.parameters : current.parameters,
  };
}

/** A step whose plan re-uses the same tool+parameters is the same step re-planned. */
export function planStepKey(step: ConversationStep): string {
  if (step.actionId) return `action:${step.actionId}`;
  if (step.workflowNodeId) return `node:${step.workflowNodeId}`;
  const parameters = step.parameters ? JSON.stringify(step.parameters) : "";
  return `shape:${step.toolCode}:${parameters}`;
}

/**
 * Merge an incoming plan into the current step list without duplicating steps.
 *
 * <p>The runtime re-delivers the complete plan on every execution turn, so a retry used to
 * append a second copy of every step. Steps keep their identity (actionId, else tool +
 * parameters) and only a higher attempt may replace a terminal status.
 */
export function mergePlanSteps(
  current: ConversationStep[],
  incoming: ConversationStep[],
): ConversationStep[] {
  const merged = [...current];
  for (const step of incoming) {
    const match = findMatchingAiStep(merged, step);
    if (match) {
      const idx = merged.indexOf(match);
      merged[idx] = mergeAiStep(merged[idx], step);
      continue;
    }
    const key = planStepKey(step);
    const index = merged.findIndex(item => planStepKey(item) === key);
    if (index >= 0) merged[index] = mergeAiStep(merged[index], step);
    else merged.push(step);
  }
  return merged;
}
