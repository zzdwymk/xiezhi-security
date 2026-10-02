import type { ConversationAgentEvent, ConversationMessage } from "../stores/conversations";
import { aiToolLabel, aiProgressFailureText, isPublicAiProgressEvent, publicAiProgressText } from "./aiPresentation";
import { isAwaitingAiDispatch } from "./aiApproval";

export interface AiProgressTask {
  id: number;
  toolCode: string;
  status: string;
  progressMessage?: string;
  errorMessage?: string;
  startedAt?: string;
  finishedAt?: string;
  createdAt: string;
}
export type ProgressTone = "active" | "success" | "warning" | "failed" | "neutral";
export interface AiProgressEntry {
  key: string;
  title: string;
  detail: string;
  tone: ProgressTone;
  at?: number;
  event: ConversationAgentEvent;
}
const stages: Record<string, string> = {
  status: "准备处理", session: "恢复对话上下文", context: "整理项目上下文",
  route: "理解请求", router: "理解请求", scope: "确认授权范围", engage: "确认目标与计划",
  engagement: "确认目标与计划", authorization_guard: "核对授权范围",
  retrieve: "检索项目证据", retrieval: "检索项目证据", evidence: "检索项目证据",
  recon: "整理项目情报", reconnaissance: "整理项目情报", rewrite: "调整检索条件",
  planner: "生成检测计划", plan: "生成检测计划", planning: "生成检测计划",
  model: "等待模型回答", model_wait: "等待模型回答", model_request: "等待模型回答",
  routing: "理解请求", retrieving: "检索项目证据", evidence_ready: "已取得检索依据",
  assessing: "检查证据是否充分", assessed: "已完成证据判断", generating: "生成方案与回答",
  authorizing: "核对执行授权", contract_retry: "正在纠正输出格式",
  map: "发现端口与服务", mapping: "发现端口与服务", asset_mapping: "发现端口与服务",
  discover: "识别潜在漏洞", discovery: "识别潜在漏洞", vulnerability_discovery: "识别潜在漏洞",
  validate: "验证检测结果", validation: "验证检测结果", executor: "执行授权检测",
  execute: "执行授权检测", dispatch: "派发检测任务", impact: "评估风险影响",
  impact_assessment: "评估风险影响", retest: "核对证据与复测条件", remediation: "核对修复建议",
  report: "整理结论与建议", reporting: "整理结论与建议", reviewer: "复核证据与结论",
  review: "复核证据与结论", finish: "整理回答", completed: "处理完成",
};
const types: Record<string, string> = {
  route: "理解请求", evidence: "检索项目证据", rewrite: "调整检索条件", plan: "生成检测计划",
  guard: "核对授权范围", review: "复核证据与结论", decision: "判断与下一步",
  context: "整理项目上下文", session: "恢复对话上下文", model: "等待模型回答",
  citation: "找到参考资料", done: "本轮处理结束", error: "处理遇到问题", stage: "处理进展",
  step: "处理进展", progress: "处理进展", status: "处理进展", state: "处理进展",
};
const publicStatuses: Record<string, string> = {
  ROUTING: "理解请求与范围", RETRIEVING: "检索项目证据", GROUNDED: "形成依据与计划",
  WAITING_APPROVAL: "等待执行确认", EXECUTING: "执行授权检测", REVIEWED: "复核完成", FAILED: "处理遇到问题",
};
const terminalTasks = new Set(["SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "SKIPPED"]);

export function isRecordedAiEvent(event: ConversationAgentEvent): boolean {
  return event.recorded === true || event.eventTiming === "VERIFIED_RECORD";
}

export function aiTaskElapsed(task: AiProgressTask, now: number): number | undefined {
  const start = Date.parse(task.startedAt || "");
  const end = task.finishedAt ? Date.parse(task.finishedAt)
    : task.status === "RUNNING" ? now : NaN;
  return Number.isFinite(start) && Number.isFinite(end) && end >= start ? end - start : undefined;
}

export function aiProgressEventTitle(event: ConversationAgentEvent): string {
  if (event.type === "error") return "处理遇到问题";
  if (event.type === "retry") return /NOT_REQUIRED|SKIPPED|PENDING/i.test(event.status || "") ? "重试状态反馈" : "重试反馈";
  if (event.type === "approval") {
    return /APPROVED|CONFIRMED|NOT_REQUIRED/.test(event.approvalStatus || event.status || "")
      ? "执行条件已确认" : "等待执行确认";
  }
  if (event.type === "tool_call" || event.type === "tool_result")
    return `${event.type === "tool_call" ? "调用" : "返回"} · ${aiToolLabel(event.toolCode, event.toolName)}`;
  const stage = String(event.stage || "").toLowerCase();
  if (["map", "mapping", "asset_mapping", "discover", "discovery", "vulnerability_discovery", "validate", "validation", "impact", "impact_assessment", "retest", "remediation", "report", "reporting"].includes(stage))
    return `流程阶段 · ${stages[stage]}`;
  return stages[stage] || types[event.type]
    || publicStatuses[event.publicNodeStatus || ""] || "处理进展";
}
function tone(event: ConversationAgentEvent): ProgressTone {
  if (event.type === "error" || /failed|error|rejected|timeout|cancelled/i.test(event.status || "") || event.publicNodeStatus === "FAILED") return "failed";
  if (event.recorded || event.eventTiming === "VERIFIED_RECORD" || /skipped|not_applicable|not_required|recorded|dispatched/i.test(event.status || "")) return "neutral";
  if (event.type === "retry" || (event.type === "approval" && !/APPROVED|CONFIRMED|NOT_REQUIRED/.test(event.approvalStatus || event.status || ""))) return "warning";
  // A tool return can contain only an action proposal; task records own execution success.
  if (event.type === "tool_result") return "neutral";
  if (/success|completed|done|approved|confirmed/i.test(event.status || "") || event.type === "done") return "success";
  return "active";
}
function eventDetail(event: ConversationAgentEvent): string {
  const summary = publicAiProgressText(event.summary || event.message);
  const facts = [
    event.evidenceCount !== undefined ? `找到 ${event.evidenceCount} 条证据引用` : "",
    (event.actionCount || 0) > 0 ? `${event.actionCount} 项计划动作` : "",
    event.taskIds?.length ? `已关联 ${event.taskIds.length} 个检测任务` : "",
    (event.attempt || 0) > 0 ? `第 ${event.attempt} 次尝试${event.maxAttempts ? `，最多 ${event.maxAttempts} 次` : ""}` : "",
  ].filter(Boolean);
  if (event.type === "citation" && event.citation?.title) facts.push(publicAiProgressText(event.citation.title, 120));
  return [summary, ...facts.filter(fact => !summary.includes(fact))].filter(Boolean).join(" · ")
    || (event.type === "tool_call" ? "已收到工具调用记录。" : event.type === "tool_result" ? "已收到工具返回记录，执行状态以任务记录为准。" : "已收到此阶段的进展反馈。");
}

/** Keep the complete public log available, but summarize real work rather than
 * graph bookkeeping. A neutral milestone means feedback received, not success. */
function isRoutineProgress(entry: AiProgressEntry): boolean {
  if (entry.tone === "failed" || entry.tone === "warning") return false;
  return /skipped|not_applicable/i.test(entry.event.status || "")
    || /本阶段没有匹配|无需执行工具|不需要执行授权|本轮无需|没有失败动作|流程结束|准备交付/.test(entry.detail)
    || (entry.event.actionCount === 0 && ["plan", "guard", "review"].includes(entry.event.type))
    || entry.event.type === "done";
}

function milestoneGroup(entry: AiProgressEntry): string {
  const event = entry.event;
  const stage = String(event.stage || "").toLowerCase();
  if (["error", "retry", "approval", "tool_call", "tool_result"].includes(event.type))
    return `${event.type}:${event.toolCallId || event.taskId || entry.key}`;
  if (/retrieve|retriev|evidence|assess|rewrite/.test(stage) || ["evidence", "citation", "rewrite"].includes(event.type)) return "evidence";
  if (/generat|planner|planning|^plan$|model/.test(stage)) return "answer";
  if (/authoriz|guard/.test(stage) || event.type === "guard") return "authorization";
  if (/session|context|recon/.test(stage) || ["session", "context"].includes(event.type)) return "context";
  if (/route|routing|engage|scope|status/.test(stage) || event.type === "route") return "request";
  if (/report|review|finish|remediat|retest/.test(stage) || event.type === "review") return "review";
  if (event.type === "decision") return "decision";
  return entry.title;
}

export function summarizeAiProgress(entries: AiProgressEntry[], active: boolean): AiProgressEntry[] {
  const grouped = new Map<string, AiProgressEntry>();
  for (const entry of entries) {
    if (isRoutineProgress(entry)) continue;
    const group = milestoneGroup(entry);
    // A rewrite/assessment can revisit a previous group. Its newest feedback
    // must become current instead of highlighting the last first-seen group.
    grouped.delete(group);
    grouped.set(group, { ...entry, key: `summary-${group}` });
  }
  const summaries = [...grouped.values()];
  return summaries.map((entry, index) => ({ ...entry,
    tone: entry.tone === "active" && (!active || index < summaries.length - 1) ? "neutral" : entry.tone,
  })).slice(-5);
}

export function buildAiProgress(message: ConversationMessage, tasks: AiProgressTask[], now: number) {
  const start = Date.parse(message.progressStartedAt || message.createdAt);
  const related = tasks.filter(task => message.taskIds.includes(task.id));
  const activeTasks = related.filter(task => !terminalTasks.has(task.status));
  const unresolvedTasks = message.taskIds.filter(id => !related.some(task => task.id === id)).length;
  const interrupted = message.modelStreamStatus === "interrupted";
  const modelActive = message.status !== "failed" && (message.modelStreamStatus ? message.modelStreamStatus === "running"
    : ["sending", "planning", "running", "answering"].includes(message.status) && !(message.agentEvents || []).some(event => !event.recorded && event.eventTiming !== "VERIFIED_RECORD" && (event.type === "done" || event.type === "error")));
  const active = modelActive || activeTasks.length > 0;
  const unsuccessfulTasks = related.filter(task => terminalTasks.has(task.status) && task.status !== "SUCCESS");
  const entries: AiProgressEntry[] = [];
  for (const event of (message.agentEvents || []).filter(isPublicAiProgressEvent)) {
    const title = aiProgressEventTitle(event);
    const detail = eventDetail(event);
    const previous = entries[entries.length - 1];
    if (previous && previous.title === title && previous.detail === detail && previous.tone === tone(event)
      && previous.event.nodeRunId === event.nodeRunId && previous.event.toolCallId === event.toolCallId
      && previous.event.attempt === event.attempt && previous.event.taskId === event.taskId) continue;
    entries.push({ key: event.id || `progress-${entries.length}`, title, detail, tone: tone(event),
      at: Number.isFinite(Date.parse(event.createdAt || "")) ? Date.parse(event.createdAt!) : undefined, event });
  }
  // Historical RUNNING feedback records an observation, not a live stage.
  for (let index = 0; index < entries.length; index++) {
    if (entries[index].tone === "active" && (!modelActive || index < entries.length - 1)) entries[index].tone = "neutral";
  }
  const latest = entries[entries.length - 1];
  const failed = message.status === "failed" || message.modelStreamStatus === "failed";
  const waitingApproval = message.approvalStatus === "REQUIRED" || message.approvalStatus === "PENDING";
  const awaitingDispatch = isAwaitingAiDispatch(message);
  const rejectedApproval = message.approvalStatus === "REJECTED";
  const lastUpdate = latest?.at ?? start;
  const completionTimes = [
    Date.parse(message.progressFinishedAt || ""),
    ...related.filter(task => terminalTasks.has(task.status)).map(task => Date.parse(task.finishedAt || "")),
    ...entries.filter(entry => !entry.event.recorded && entry.event.eventTiming !== "VERIFIED_RECORD"
      && ["done", "error"].includes(entry.event.type)).map(entry => entry.at),
  ].filter((value): value is number => value !== undefined && Number.isFinite(value));
  // An ordinary event or an updatedAt value is not evidence that work ended.
  // An interrupted stream or unresolved/missing task finish is not a known end.
  const completionUnknown = interrupted || unresolvedTasks > 0
    || related.some(task => terminalTasks.has(task.status) && !Number.isFinite(Date.parse(task.finishedAt || "")));
  const end = active ? now : !completionUnknown && completionTimes.length ? Math.max(...completionTimes) : undefined;
  const decision = [...entries].reverse().find(entry => {
    const summary = publicAiProgressText(entry.event.summary || entry.event.message);
    return summary && !isRoutineProgress(entry) && (["decision", "guard", "review", "rewrite"].includes(entry.event.type)
      || String(entry.event.stage).toLowerCase() === "assessed"
      || (entry.event.type === "plan" && ((entry.event.actionCount || 0) > 0 || /已(?:形成|生成|确定|完成).*(?:计划|方案)/.test(summary))));
  });
  const latestEvidence = [...entries].reverse().find(entry => Number.isFinite(entry.event.evidenceCount));
  const evidenceCount = latestEvidence ? latestEvidence.event.evidenceCount : message.citations?.length || undefined;
  const summaryEntries = summarizeAiProgress(entries, active && !failed && !waitingApproval);
  const latestUseful = [...entries].reverse().find(entry => !isRoutineProgress(entry));
  const latestIsRecord = latestUseful?.event.recorded || latestUseful?.event.eventTiming === "VERIFIED_RECORD";
  const currentTitle = interrupted && !activeTasks.length ? "连接已结束，结果待确认" : failed ? message.taskIds.length ? "回答中断，请查看检测任务状态" : "本轮处理未完成" : rejectedApproval ? "执行方案已驳回" : waitingApproval ? "等待确认执行计划" : awaitingDispatch ? "审批已通过，等待派发确认"
    : message.status === "answering" && modelActive ? "等待模型回答"
    : activeTasks.length && active ? `${activeTasks.length} 个任务正在推进`
    : unresolvedTasks ? "正在同步检测任务状态"
    : !active ? unsuccessfulTasks.length ? "任务已结束，部分步骤未成功" : "本轮处理完成" : latestIsRecord ? "等待模型回答" : latestUseful?.title || "等待处理反馈";
  const currentDetail = interrupted ? "页面重载后无法恢复此前的模型连接；该轮是否完成尚未确认，请查看回答及关联任务。" : failed ? aiProgressFailureText(message.content, message.taskIds.length > 0)
    : rejectedApproval ? "该方案未获批准；如需调整，请在对话中说明新的要求。"
    : waitingApproval ? "计划已生成，确认后才会继续受控操作。"
    : awaitingDispatch ? "尚未确认任务派发结果。若一直没有任务，可在执行计划中点击“恢复原计划执行”。"
    : message.status === "answering" && modelActive ? "模型请求尚未完成。"
    : activeTasks.length && active ? activeTasks.map(task => `${aiToolLabel(task.toolCode)}：${task.status === "PENDING" ? "排队中" : task.status === "BLOCKED" ? "等待前置任务" : publicAiProgressText(task.progressMessage) || "执行中"}`).join("；")
    : unresolvedTasks ? `${unresolvedTasks} 个关联任务的状态尚未载入，可在任务中心查看。`
    : active ? latestIsRecord ? "已收到处理记录，模型请求尚未完成。" : latestUseful?.detail || "尚未收到阶段反馈。"
    : `${message.steps.length ? `${message.steps.length} 项计划` : "回答已生成"}${related.length ? `，${related.filter(task => task.status === "SUCCESS").length}/${related.length} 个任务成功` : ""}。可展开回看处理进展。`;
  return { active, modelActive, interrupted, failed, waitingApproval, entries, summaryEntries, currentTitle, currentDetail, startedAt: start,
    elapsed: Number.isFinite(start) && end !== undefined && Number.isFinite(end) && end >= start ? end - start : undefined, quietFor: active && Number.isFinite(lastUpdate) ? Math.max(0, now - lastUpdate) : 0,
    showQuietHint: active && !failed && !waitingApproval && !rejectedApproval && Number.isFinite(lastUpdate) && now - lastUpdate >= 15000,
    evidenceCount, decision: decision ? publicAiProgressText(decision.event.summary || decision.event.message) : "",
    related, unresolvedTasks, completeTasks: related.filter(task => terminalTasks.has(task.status)).length,
    tone: failed ? "failed" : interrupted ? "neutral" : waitingApproval || rejectedApproval || awaitingDispatch ? "warning" : active ? "active" : unresolvedTasks ? "neutral" : unsuccessfulTasks.length ? "warning" : "success" };
}
