import type { ConversationMessage } from "../stores/conversations";
import { buildAiProgress, type AiProgressTask, type ProgressTone } from "./aiProgress";

type AiProgress = ReturnType<typeof buildAiProgress>;

export const AI_STATUS_LABELS: Record<ProgressTone, string> = {
  active: "进行中", success: "成功", failed: "失败", warning: "需要关注", neutral: "阶段反馈",
};

export interface AiStatusSummary {
  progress: AiProgress;
  tone: ProgressTone;
  title: string;
  spinning: boolean;
  completed: boolean;
  dispatchConcern: boolean;
  needsClarification: boolean;
}

// Older records can lack an approval ID or plan. A retained dispatch warning
// still prevents a generic completed message from presenting a success mark.
export function hasAiDispatchConcern(message: ConversationMessage, tone: ProgressTone): boolean {
  return tone === "success"
    && (["dispatching", "unknown", "rejected"].includes(message.approvalDispatchStatus || "")
      || (message.approvalStatus === "APPROVED" && !message.taskIds.length));
}

// One shared reading of a turn's state feeds both the in-card progress header
// and the finished-answer status stamp, so the two can never disagree.
export function buildAiStatusSummary(message: ConversationMessage, tasks: AiProgressTask[], now: number): AiStatusSummary {
  const progress = buildAiProgress(message, tasks, now);
  const progressTone = progress.tone as ProgressTone;
  const dispatchConcern = hasAiDispatchConcern(message, progressTone);
  const needsClarification = message.executionDecision === "CLARIFY"
    && !progress.active && !progress.interrupted && !progress.failed && !progress.waitingApproval
    && !dispatchConcern && progress.tone !== "warning" && !message.taskIds.length;
  const tone: ProgressTone = dispatchConcern
    ? message.approvalDispatchStatus === "rejected" ? "failed" : "warning"
    : needsClarification ? "warning" : progressTone;
  const completed = message.status === "completed" && tone === "success";
  const title = dispatchConcern
    ? message.approvalDispatchStatus === "rejected" ? "执行已拒绝，未派发任务"
      : message.approvalDispatchStatus === "unknown" ? "派发结果待核实" : "审批已通过，等待派发确认"
    : completed ? "已完成" : needsClarification ? "等待补充信息" : progress.currentTitle;
  return { progress, tone, title, spinning: tone === "active" && (progress.elapsed ?? 0) >= 1000, completed, dispatchConcern, needsClarification };
}

export function aiStatusIcon(tone: ProgressTone | string): string {
  return tone === "success" ? "checkmark-circle" : tone === "failed" ? "dismiss" : tone === "warning" ? "warning" : tone === "neutral" ? "info" : "clock";
}

/**
 * Sidebar badge for a conversation thread. It must read the same computed progress as the
 * in-card header, because a raw `modelStreamStatus === "running"` check cannot tell a live
 * stream from one whose connection already ended without a page reload.
 */
export function conversationStatusBadge(message: ConversationMessage, tasks: AiProgressTask[], now: number): { label: string; type: "running" | "completed" | "failed" } | null {
  const progress = buildAiProgress(message, tasks, now);
  const tone = progress.tone;
  if (progress.active) return { label: "回答中", type: "running" };
  if (progress.interrupted) return { label: "连接已结束", type: "failed" };
  if (progress.failed || tone === "failed") return { label: "失败", type: "failed" };
  if (progress.waitingApproval) return { label: "等待确认", type: "running" };
  const completed = message.status === "completed" && tone === "success";
  if (completed) return { label: "已完成", type: "completed" };
  return null;
}

// A finished turn keeps its status stamp with the message chrome rather than
// inside the response surface. A turn that can expand a model decision summary
// keeps the header in the card, so its toggle stays next to the summary it
// controls; that choice never depends on the clock.
export function isAiStatusOutsideCard(message: ConversationMessage, tasks: AiProgressTask[], now: number): boolean {
  if (message.role !== "assistant" || !["completed", "failed"].includes(message.status)) return false;
  return buildAiStatusSummary(message, tasks, now).progress.modelEntries.length === 0;
}
