<script setup lang="ts">
import {
  computed,
  nextTick,
  onBeforeUnmount,
  onMounted,
  ref,
  watch,
} from "vue";
import "../plans.css";
import { useRoute, useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Aim,
  ChatDotRound,
  CircleCheck,
  Connection,
  CopyDocument,
  Delete,
  Dismiss,
  DocumentChecked,
  EditPen,
  Plus,
  Promotion,
  Refresh,
  VideoPause,
} from "../components/fluentIcons";
import {
  connectTaskEventFeed,
  dispatchAiStreaming,
  endpoints,
  normalizeAgentEvent,
  safeGet,
  type AiDispatchStreamEvent,
  type AgentStreamEvent,
  type AssessmentProject,
  type JudgeVerdictDocument,
  type ProjectTarget,
  type ProjectTaskRecord,
  type Target,
  type TaskProgressEvent,
} from "../api";
import {
  useConversationStore,
  ConversationStorageError,
  type ConversationMessage,
  type ConversationThread,
  type ConversationAgentEvent,
  type ConversationCitation,
  type ConversationStep,
  type TrafficConversationReference,
} from "../stores/conversations";
import { useEngineStore } from "../stores/engine";
import { useCopilotStore } from "../stores/copilot";
import { formatDateTime, formatExecutionLog } from "../utils/dateTime";
import {
  actionStepLabel,
  aiToolLabel,
  copilotReferenceTypeLabel,
  displayKnownTestName,
  displayConversationTitle,
  localizeAiRuntimeFailure,
  localizeAiToolCodes,
  readableAiConversationError,
  publicProgressProvenance,
} from "../utils/aiPresentation";
import type { CopilotDraft, CopilotReference } from "../types/copilot";
import { markdownToPlainText, renderMarkdown } from "../utils/markdown";
import {
  taskProgressIndeterminate,
  taskProgressPercentage,
} from "../utils/taskProgress";
import { taskbarProgress } from "../utils/taskbarProgress";
import AiProgressPanel from "../components/AiProgressPanel.vue";
import AiStatusStamp from "../components/AiStatusStamp.vue";
import AiFailureNotice from "../components/AiFailureNotice.vue";
import AiDispatchNotice from "../components/AiDispatchNotice.vue";
import FluentIcon from "../components/FluentIcon.vue";
import MarkdownComposerPreview from "../components/MarkdownComposerPreview.vue";
import ConversationAvatar from "../components/ConversationAvatar.vue";
import AiApprovalDialog from "../components/AiApprovalDialog.vue";
import FluentCodeBlock from "../components/FluentCodeBlock.vue";
import { createAiApprovalPromptGate, isAwaitingAiApproval, isAwaitingAiDispatch, isAiDispatchRejected, aiDispatchFailureStatus, aiDispatchRejectedTitle, aiDispatchQuotaFailure } from "../utils/aiApproval";
import { aiEventStepStatus, findMatchingAiStep, mergeAiStep } from "../utils/aiStepState";
import { mergeTaskDetailSnapshot } from "../utils/taskDetail";
import { aiExecutionRequest } from "../utils/aiIntent";
import { isAiStatusOutsideCard, conversationStatusBadge } from "../utils/aiStatus";
import type { AiAwaitingStatus } from "../utils/aiProgress";
import { aiAnswerSource, isLocalAiAnswer, requireAiAnswer } from "../utils/aiAnswer";
import { resolveAuditConversationScope } from "../utils/auditConversationScope";
import { aiProgressFailureText, isPublicAiProgressEvent, publicAiProgressText } from "../utils/aiPresentation";
import messageQuoteIcon from "@fluentui/svg-icons/icons/text_quote_24_regular.svg?url";
import gaugeIcon from "@fluentui/svg-icons/icons/gauge_20_regular.svg?url";
import databaseIcon from "@fluentui/svg-icons/icons/database_20_regular.svg?url";
const messageQuoteStyle = { maskImage: `url("${messageQuoteIcon}")` };
const gaugeIconStyle = { maskImage: `url("${gaugeIcon}")`, WebkitMaskImage: `url("${gaugeIcon}")` };
const databaseIconStyle = { maskImage: `url("${databaseIcon}")`, WebkitMaskImage: `url("${databaseIcon}")` };

/**
 * 底部统计栏的三张卡片互斥展开。
 *
 * Element Plus 的 click 触发弹层只靠 document 上的"点到外面"判定来收起，
 * 而这个判定用的是触发元素的矩形。统计卡片是向上弹出的，展开后正好盖住
 * 相邻胶囊：第二次点击命中的是已展开的卡片而不是胶囊，触发元素与弹层
 * 都不认为自己点到了"外面"，于是两张卡片会同时留在屏幕上（1024~1440px
 * 宽度下必然复现）。
 *
 * 因此这三个弹层改为 trigger="manual"，可见性完全由 openStatsCard 决定：
 * 点胶囊切换唯一展开项，点页面空白或按 Esc 收起，从根本上杜绝两张同开。
 */
type StatsCardKey = "session" | "tokens" | "context";
const openStatsCard = ref<StatsCardKey | null>(null);

function statsCardVisible(key: StatsCardKey) {
  return openStatsCard.value === key;
}

// 点击胶囊切换该卡片；点开其它卡片会把当前这张顶掉，保证互斥。
function toggleStatsCardOnPillClick(key: StatsCardKey) {
  openStatsCard.value = openStatsCard.value === key ? null : key;
}

function closeStatsCards() {
  openStatsCard.value = null;
}

// 统计栏用 trigger="manual" 完全掌控可见性，避免 Element Plus 自带的 document
// 点击判定（它只认触发元素的矩形）在卡片向上弹出盖住相邻胶囊时误判，导致
// 两张卡片同时留在屏幕上。因此点击事件完全由这里处理：
//   - 点击胶囊：切换状态；
//   - 点击栏内其它空白：收起。
function handleStatsBarPointerDown(event: PointerEvent) {
  const target = event.target as Element | null;
  if (!target) return;
  if (target.closest(".stats-pill")) return; // 交给胶囊的 click 切换
  closeStatsCards();
}

// 点击页面其它空白处统一收起；胶囊和弹出卡片内部的点击不在此列。
function handleDocumentPointerDown(event: MouseEvent) {
  if (!openStatsCard.value) return;
  const target = event.target as Element | null;
  if (!target) return;
  if (target.closest(".composer-stats-bar") || target.closest(".stats-pill-popover")) return;
  closeStatsCards();
}

function handleDocumentKeydown(event: KeyboardEvent) {
  if (event.key === "Escape" && openStatsCard.value) closeStatsCards();
}

interface TaskRow {
  id: number;
  targetId: number;
  toolCode: string;
  status: string;
  progress: number;
  progressUpdatedAt?: string;
  workflowNodeId?: string;
  progressDeterminate?: boolean;
  progressCompleted?: number;
  progressTotal?: number;
  progressMessage?: string;
  executionLog?: string;
  errorMessage?: string;
  startedAt?: string;
  finishedAt?: string;
  createdAt: string;
}

const TERMINAL_STATUSES = new Set([
  "SUCCESS",
  "FAILED",
  "TIMEOUT",
  "REJECTED",
  "CANCELLED",
  "SKIPPED",
]);
const route = useRoute();
const router = useRouter();
const conversations = useConversationStore();
const engine = useEngineStore();
const copilot = useCopilotStore();
const tasks = ref<TaskRow[]>([]);
const targets = ref<Target[]>([]);
const projectByTarget = ref<Record<number, number>>({});
const selectedTargetId = ref<number>();
const prompt = ref("");
const composerInputRef = ref<HTMLTextAreaElement | null>(null);
type QuotedMessage = Pick<ConversationMessage, "id" | "role" | "content" | "createdAt">;
const quotedMessage = ref<QuotedMessage>();
interface MessageEditState {
  threadId: string;
  messageId: string;
  references: NonNullable<ConversationMessage["references"]>;
  mode?: ConversationMessage["copilotMode"];
  previous: { prompt: string; draft?: CopilotDraft; quote?: QuotedMessage };
}
const editingMessage = ref<MessageEditState>();
const copiedMessageId = ref<string>();
let copiedMessageTimer: ReturnType<typeof setTimeout> | undefined;
const loading = ref(false);
const activeSendingThreadIds = ref<Set<string>>(new Set());
const isSendingAny = ref(false);
const sending = computed({
  get: () => {
    const currentId = selectedThread.value?.id;
    return Boolean(isSendingAny.value || (currentId && activeSendingThreadIds.value.has(currentId)));
  },
  set: (val: boolean) => {
    const currentId = selectedThread.value?.id;
    if (val) {
      if (currentId) activeSendingThreadIds.value.add(currentId);
      isSendingAny.value = true;
    } else {
      if (currentId) activeSendingThreadIds.value.delete(currentId);
      isSendingAny.value = false;
    }
  },
});

const currentThreadStatus = computed(() => {
  const t = selectedThread.value;
  if (!t || !t.messages?.length) return null;
  const lastAssistant = [...t.messages].reverse().find((m) => m.role === "assistant");
  if (!lastAssistant) return null;
  const badge = conversationStatusBadge(lastAssistant, relatedTasks(lastAssistant), Date.now(), awaitingStatusForThread(t.id));
  // A live send in this window is authoritative even before its row is persisted.
  if (activeSendingThreadIds.value.has(t.id) && badge?.type !== "failed") {
    return { label: "回答中", type: "running" as const };
  }
  if (badge && badge.type === "completed" && lastAssistant.completionSeen) return null;
  return badge;
});
const messagesElement = ref<HTMLElement>();
const answeringMessages = new Set<string>();
const retryingMessageIds = ref(new Set<string>());
const activeDraft = ref<CopilotDraft>();
const composerReferences = computed(() => (editingMessage.value?.references || activeDraft.value?.refs || []) as CopilotReference[]);
let pollTimer: ReturnType<typeof setInterval> | undefined;
let stopTaskFeed: (() => void) | undefined;
// What the current thread's last turn is waiting on (scan tasks / scheduled
// resume), so the progress card can name it instead of a vague placeholder.
const awaitingByThreadId = ref<Record<string, AiAwaitingStatus>>({});
let awaitingPollTimer: ReturnType<typeof setInterval> | undefined;

/**
 * Poll the backend for what the selected thread is waiting on.
 *
 * Only the visible thread is polled, at a low rate, and only while the thread is
 * still in a non-terminal state. This closes the gap after a turn ends: without a
 * live model stream and before task rows exist locally, the UI had nothing to say
 * and showed "等待处理反馈".
 */
async function refreshAwaitingStatus() {
  const thread = selectedThread.value;
  if (!thread) {
    awaitingByThreadId.value = {};
    return;
  }
  try {
    const { data } = await endpoints.getAgentSessionStatus(thread.id);
    const next: AiAwaitingStatus = {
      phase: data?.phase === "waiting_tasks" ? "waiting_tasks" : "idle",
      nextAttemptAt: data?.nextAttemptAt ?? null,
      attempt: typeof data?.attempt === "number" ? data.attempt : 0,
      tasks: Array.isArray(data?.tasks) ? data.tasks : [],
    };
    awaitingByThreadId.value = { ...awaitingByThreadId.value, [thread.id]: next };
  } catch {
    // A failed status probe must never disturb the conversation view; the next
    // poll (or a task event) will refresh it.
  }
}

function awaitingStatusForThread(threadId: string): AiAwaitingStatus | undefined {
  return awaitingByThreadId.value[threadId];
}

const enabledTargets = computed(() =>
  targets.value.filter((item) => item.enabled),
);
const selectedThread = computed(() => {
  const id =
    typeof route.query.conversation === "string"
      ? route.query.conversation
      : "";
  return conversations.items.find((item) => item.id === id);
});
const selectedTarget = computed(() =>
  enabledTargets.value.find((item) => item.id === selectedTargetId.value),
);
const isConversation = computed(() => Boolean(selectedThread.value));
const offline = computed(() => engine.isOffline);

function projectIdForTarget(targetId: number, thread?: ConversationThread) {
  if (thread?.projectId) return thread.projectId;
  const routeProjectId = Number(route.query.projectId);
  if (routeProjectId > 0) return routeProjectId;
  const draftProjectId = Number(
    activeDraft.value?.refs.find((ref) => Number(ref.data?.projectId) > 0)?.data
      ?.projectId,
  );
  return draftProjectId > 0 ? draftProjectId : projectByTarget.value[targetId];
}

function auditScopeForMessage(
  references: ConversationMessage["references"],
  targetId?: number,
  projectId?: number,
) {
  return resolveAuditConversationScope(references as CopilotReference[] | undefined,
    targets.value, targetId, projectId, endpoints);
}

const quickActions = [
  {
    label: "分析代理流量",
    description: "捕获请求并生成安全建议",
    path: "/traffic",
    icon: Connection,
  },
  {
    label: "手动主动检测",
    description: "自行选择漏洞检测规则",
    path: "/vulnerabilities",
    icon: Aim,
  },
  {
    label: "查看检测结果",
    description: "审阅最近发现与风险",
    path: "/findings",
    icon: DocumentChecked,
  },
];

function formatTime(value: string) {
  return formatDateTime(value);
}

function relatedTasks(message: ConversationMessage) {
  return message.taskIds
    .map((id) => tasks.value.find((task) => task.id === id))
    .filter((item): item is TaskRow => Boolean(item));
}

function taskLogs(message: ConversationMessage) {
  return relatedTasks(message)
    .map((task) => formatExecutionLog(task.executionLog))
    .filter(Boolean)
    .join("\n");
}

// A finished answer shows its status stamp with the message chrome, below the
// answer card, instead of inside the answer surface.
function isStatusOutsideAnswerCard(message: ConversationMessage) {
  return !hasDispatchNotice(message) && isAiStatusOutsideCard(message, relatedTasks(message), Date.now(), awaitingStatusForThread(selectedThread.value?.id || ""));
}

function hasDispatchNotice(message: ConversationMessage) {
  return message.role === "assistant" && message.steps.length > 0
    && message.status !== "failed" && !["failed", "interrupted"].includes(message.modelStreamStatus || "")
    && (isAwaitingAiDispatch(message) || isAiDispatchRejected(message));
}

function displayAgentValue(value: unknown, limit = 1600) {
  if (value === undefined || value === null) return "";
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}

function taskState(message: ConversationMessage) {
  if (isAwaitingAiApproval(message)) return { label: "等待审批", progress: 0, className: "waiting", indeterminate: false };
  if (isAiDispatchRejected(message)) return { label: aiDispatchRejectedTitle(message), progress: 0, className: "failed", indeterminate: false };
  if (isAwaitingAiDispatch(message) && message.approvalDispatchStatus === "unknown") return { label: "派发结果待核实", progress: 0, className: "waiting", indeterminate: false };
  if (isAwaitingAiDispatch(message)) return { label: "已批准，等待派发确认", progress: 0, className: "waiting", indeterminate: false };
  if (message.approvalStatus === "REJECTED" && !message.taskIds.length) return { label: "方案已驳回", progress: 0, className: "failed", indeterminate: false };
  const related = relatedTasks(message);
  const progress = related.length
    ? Math.round(
        related.reduce((sum, item) => sum + taskProgressPercentage(item), 0) /
          related.length,
      )
    : 0;
  if (message.status === "planning")
    return {
      label: "正在生成执行计划",
      progress: 0,
      className: "running",
      indeterminate: true,
    };
  if (message.status === "answering")
    return {
      label: "任务结束，正在整理回答",
      progress,
      className: "running",
      indeterminate: true,
    };
  if (message.status === "failed")
    return {
      label: "处理失败",
      progress,
      className: "failed",
      indeterminate: false,
    };
  if (!message.taskIds.length)
    return {
      label: message.steps.length ? "计划已生成" : "已回答",
      progress: 100,
      className: "success",
      indeterminate: false,
    };
  if (!related.length)
    return {
      label: "等待任务状态",
      progress,
      className: "pending",
      indeterminate: false,
    };
  const failed = related.filter((item) =>
    ["FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "SKIPPED"].includes(item.status),
  ).length;
  if (related.every((item) => TERMINAL_STATUSES.has(item.status))) {
    return {
      label: failed
        ? `${related.length - failed}/${related.length} 个任务成功`
        : `${related.length} 个任务已完成`,
      progress,
      className: failed ? "failed" : "success",
      indeterminate: false,
    };
  }
  const running = related.filter((item) => item.status === "RUNNING").length;
  return {
    label: running ? `${running} 个任务执行中` : "任务排队中",
    progress,
    className: "running",
    indeterminate: related.some(taskProgressIndeterminate),
  };
}

type PlanStepVisualState = "pending" | "running" | "success" | "failed";

function planStepState(message: ConversationMessage, index: number) {
  const step = message.steps[index];
  const taskId = step?.taskId || message.taskIds[index];
  const task = tasks.value.find((item) => item.id === taskId);
  if (!task) {
    const status = String(step?.status || "").toLowerCase();
    if (!taskId && isAiDispatchRejected(message)) return { state: "failed" as PlanStepVisualState, label: "执行已拒绝", progress: 0, indeterminate: false };
    if (!taskId && message.approvalStatus === "REJECTED") {
      return { state: "failed" as PlanStepVisualState, label: "未获批准", progress: 0, indeterminate: false };
    }
    return {
      state: "pending" as PlanStepVisualState,
      label: taskId ? "等待任务状态" : isAwaitingAiApproval(message) || /approval/.test(status) ? "等待审批" : isAwaitingAiDispatch(message) ? "等待派发确认" : "待执行",
      progress: 0,
      indeterminate: false,
    };
  }
  if (task.status === "SUCCESS")
    return {
      state: "success" as PlanStepVisualState,
      label: "已完成",
      progress: 100,
      indeterminate: false,
    };
  if (task.status === "SKIPPED") return { state: "pending" as PlanStepVisualState, label: "已跳过", progress: 0, indeterminate: false };
  if (task.status === "BLOCKED") return { state: "pending" as PlanStepVisualState, label: "等待前置任务", progress: 0, indeterminate: false };
  if (["FAILED", "TIMEOUT", "REJECTED", "CANCELLED"].includes(task.status)) {
    return {
      state: "failed" as PlanStepVisualState,
      label:
        task.status === "REJECTED"
          ? "已拒绝"
          : task.status === "CANCELLED"
            ? "已取消"
            : task.status === "TIMEOUT"
              ? "已超时"
              : "失败",
      progress: taskProgressPercentage(task),
      indeterminate: false,
    };
  }
  if (task.status === "RUNNING")
    return {
      state: "running" as PlanStepVisualState,
      label: !taskProgressIndeterminate(task)
        ? `执行中 ${taskProgressPercentage(task)}%`
        : task.progressMessage || "执行中",
      progress: taskProgressPercentage(task),
      indeterminate: taskProgressIndeterminate(task),
    };
  return {
    state: "pending" as PlanStepVisualState,
    label: "排队中",
    progress: taskProgressPercentage(task),
    indeterminate: false,
  };
}

function planTaskSummary(message: ConversationMessage) {
  const related = tasks.value.filter(task => message.taskIds.includes(task.id));
  const ended = related.filter(task => ["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED", "REJECTED", "SKIPPED"].includes(task.status)).length;
  return `已结束 ${ended}/${message.taskIds.length} 个任务`;
}

function formatReferenceValue(value?: string) {
  return value?.trim() || "暂无数据";
}

function referencePromptValue(value?: string) {
  const text = formatReferenceValue(value);
  return text.length > 1800
    ? `${text.slice(0, 1800)}\n…[发送给智能体的引用已截断]`
    : text;
}

function trafficReferencePrompt(reference: TrafficConversationReference) {
  const parts = [
    `[流量会话引用 #${reference.packetId}]`,
    `请求：${reference.method} ${reference.url}`,
    reference.statusCode ? `响应状态：HTTP ${reference.statusCode}` : "",
    reference.contentType ? `内容类型：${reference.contentType}` : "",
    reference.durationMs ? `耗时：${reference.durationMs} ms` : "",
    `请求头：\n${referencePromptValue(reference.requestHeaders)}`,
    `请求体：\n${referencePromptValue(reference.requestBody)}`,
    `响应头：\n${referencePromptValue(reference.responseHeaders)}`,
    `响应体：\n${referencePromptValue(reference.responseBody)}`,
  ];
  return parts.filter(Boolean).join("\n");
}

function messageContextContent(message: ConversationMessage) {
  const context = referencesPrompt(messageReferences(message));
  const quote = message.quote
    ? `[引用的${message.quote.role === "user" ? "用户" : "助手"}消息]\n${message.quote.content.slice(0, 4000)}\n[引用结束]\n\n`
    : "";
  const supporting = [quote.trim(), context].filter(Boolean).join("\n\n");
  const bounded = supporting.length > 12000
    ? `${supporting.slice(0, 12000)}\n[引用与上下文已截断]` : supporting;
  return bounded ? `${message.content}\n\n${bounded}` : message.content;
}

function quoteMessage(message: ConversationMessage) {
  if (sending.value) return;
  quotedMessage.value = message;
  focusComposer();
}

function adjustDispatchPlan(message: ConversationMessage) {
  if (sending.value || editingMessage.value) return;
  const limit = aiDispatchQuotaFailure(message.approvalDispatchError)?.limit;
  if (!prompt.value.trim()) {
    prompt.value = `请将引用的原方案拆分为更小的计划${limit ? `，每份不超过 ${limit} 步` : "，避免超出目标或项目的任务额度"}。先给方案，不执行；新方案需要重新确认。`;
  }
  quoteMessage(message);
}

function cloneMessageDraft<T>(value: T): T {
  return value === undefined ? value : JSON.parse(JSON.stringify(value));
}

function editMessage(message: ConversationMessage) {
  const thread = selectedThread.value;
  if (sending.value || !thread || message.role !== "user" || !thread.messages.some(item => item.id === message.id)) return;
  const previous = editingMessage.value?.previous || {
    prompt: prompt.value, draft: cloneMessageDraft(activeDraft.value), quote: cloneMessageDraft(quotedMessage.value),
  };
  editingMessage.value = {
    threadId: thread.id, messageId: message.id, previous,
    references: cloneMessageDraft(messageReferences(message)), mode: message.copilotMode,
  };
  prompt.value = message.content;
  activeDraft.value = undefined;
  quotedMessage.value = message.quote ? {
    id: message.quote.messageId, role: message.quote.role, content: message.quote.content, createdAt: message.quote.createdAt,
  } : undefined;
  focusComposer();
}

function cancelMessageEdit() {
  const editing = editingMessage.value;
  if (!editing || sending.value) return;
  prompt.value = editing.previous.prompt;
  activeDraft.value = editing.previous.draft;
  quotedMessage.value = editing.previous.quote;
  editingMessage.value = undefined;
  focusComposer();
}

function openAiDiagnostics() {
  void router.push({ path: "/settings", query: { ai: "diagnostics" } });
}

async function copyMessage(message: ConversationMessage, format: "markdown" | "plain" = "markdown") {
  try {
    const text = format === "plain" ? markdownToPlainText(message.content) : message.content;
    await navigator.clipboard.writeText(text);
    copiedMessageId.value = message.id;
    if (copiedMessageTimer) clearTimeout(copiedMessageTimer);
    copiedMessageTimer = setTimeout(() => { copiedMessageId.value = undefined; }, 2000);
    ElMessage.success(format === "plain" ? "已复制无格式文本" : "已复制原始 Markdown");
  } catch {
    ElMessage.error("复制失败，请检查剪贴板权限后重试");
  }
}

onBeforeUnmount(() => { if (copiedMessageTimer) clearTimeout(copiedMessageTimer); });

function focusComposer() {
  void nextTick(() => {
    const el =
      composerInputRef.value ||
      document.querySelector<HTMLTextAreaElement>(
        ".welcome-composer textarea, .thread-composer textarea",
      );
    el?.focus({ preventScroll: true });
  });
}

function clearQuotedMessage() {
  quotedMessage.value = undefined;
}

function quotePreview(content: string) {
  const text = content.replace(/\s+/g, " ").trim();
  return text.length > 140 ? `${text.slice(0, 140)}…` : text;
}

function messageReferences(message: ConversationMessage) {
  return message.references?.length
    ? message.references
    : message.reference
      ? [message.reference]
      : [];
}

function isTrafficReference(
  reference: ConversationMessage["reference"],
): reference is TrafficConversationReference {
  return Boolean(
    reference?.type === "traffic-session" && "packetId" in reference,
  );
}

function genericReferences(message: ConversationMessage) {
  return (message.references || []) as CopilotReference[];
}

function agentCitations(message: ConversationMessage) {
  const junk = new Set([
    "citation",
    "llama-index",
    "llama_index",
    "reference",
    "source",
    "python-langgraph-runtime",
  ]);
  return (message.citations || [])
    .filter((citation) => {
      const title = String(citation.title || "").trim();
      const source = String(citation.source || "").trim();
      const summaryLength = citationSummaryLength(citation);
      const url = String(citation.url || "").trim();
      if (!title && !summaryLength && !url) return false;
      const titleKey = title.toLowerCase();
      const sourceKey = source.toLowerCase();
      if (
        junk.has(titleKey) &&
        (!source || junk.has(sourceKey)) &&
        !summaryLength &&
        !url
      )
        return false;
      if (
        junk.has(sourceKey) &&
        (!title || junk.has(titleKey)) &&
        !summaryLength &&
        !url
      )
        return false;
      return true;
    })
    .slice(0, 12);
}

function citationBubbleLabel(citation: ConversationCitation, index: number) {
  const title = String(citation.title || "").trim();
  const source = String(citation.source || "").trim();
  if (title && title.toLowerCase() !== source.toLowerCase()) return title;
  return title || source || `资料 ${index + 1}`;
}

function citationBubbleHint(citation: ConversationCitation) {
  const summaryLength = citationSummaryLength(citation);
  return [
    citation.source,
    citation.locator,
    summaryLength ? `摘要 ${summaryLength} 字符` : undefined,
  ]
    .filter(Boolean)
    .join(" · ")
    .slice(0, 160);
}

function displayedMessageContent(message: ConversationMessage) {
  return message.role === "assistant" && message.status === "failed"
    ? message.taskIds.length ? aiProgressFailureText(message.content, true) : localizeAiRuntimeFailure(message.content)
    : message.content;
}

const typedMessageContent = ref<Record<string, string>>({});
const activeTypingIds = ref<Set<string>>(new Set());
const historicalMessageIds = new Set<string>();
let typewriterInterval: ReturnType<typeof setInterval> | null = null;

function isAutomationEnvironment(): boolean {
  if (typeof window === "undefined") return false;
  return Boolean(
    (window as any).__PW_ENV__ ||
    (window as any).__playwright ||
    (window as any).__TEST_ENV__ ||
    navigator.webdriver
  );
}

function startTypewriterLoop() {
  if (typewriterInterval) return;
  typewriterInterval = setInterval(() => {
    let hasActive = false;
    const thread = selectedThread.value;
    if (!thread) return;

    for (const msg of thread.messages) {
      if (msg.role !== "assistant" || msg.status === "failed") continue;
      const full = displayedMessageContent(msg);
      if (!full) continue;

      if (historicalMessageIds.has(msg.id)) continue;

      const current = typedMessageContent.value[msg.id] ?? "";
      if (current.length < full.length) {
        hasActive = true;
        activeTypingIds.value.add(msg.id);
        const diff = full.length - current.length;
        const step = isAutomationEnvironment()
          ? diff
          : diff > 400
            ? 4
            : diff > 150
              ? 2
              : 1;
        const next = full.slice(0, current.length + step);
        typedMessageContent.value = {
          ...typedMessageContent.value,
          [msg.id]: next,
        };
        if (next.length >= full.length) {
          activeTypingIds.value.delete(msg.id);
        }
        void scrollToBottom();
      } else {
        activeTypingIds.value.delete(msg.id);
      }
    }

    if (!hasActive && activeTypingIds.value.size === 0) {
      if (typewriterInterval) {
        clearInterval(typewriterInterval);
        typewriterInterval = null;
      }
    }
  }, 16);
}

function displayedContentForMessage(message: ConversationMessage): string {
  const full = displayedMessageContent(message);
  if (isAutomationEnvironment()) return full;
  if (historicalMessageIds.has(message.id)) return full;
  if (typedMessageContent.value[message.id] !== undefined) {
    return typedMessageContent.value[message.id];
  }
  if (full) {
    typedMessageContent.value = {
      ...typedMessageContent.value,
      [message.id]: "",
    };
    startTypewriterLoop();
    return "";
  }
  return "";
}

function isMessageTyping(messageId: string): boolean {
  return activeTypingIds.value.has(messageId);
}

function displayedStepTitle(step: ConversationStep) {
  return actionStepLabel(step.toolCode, step.title);
}

function targetHoverText(name?: string, value?: string): string {
  const n = displayKnownTestName(name) || name || "";
  const v = value || "";
  if (n && v && n !== v) return `${n}\n${v}`;
  return n || v;
}

function displayedStepReason(step: ConversationStep) {
  const reason = publicAiProgressText(step.reason);
  return !reason || reason === displayedStepTitle(step) || reason === aiToolLabel(step.toolCode)
    || /^智能助手根据项目上下文提出[。.]?$/.test(reason) ? "" : reason;
}

function citationSummaryLength(citation: ConversationCitation) {
  const legacySnippet = (
    citation as ConversationCitation & { snippet?: unknown }
  ).snippet;
  return Math.max(
    0,
    Number(citation.summaryLength) ||
      (typeof legacySnippet === "string" ? legacySnippet.length : 0),
  );
}

function publicCitation(citation: ConversationCitation): ConversationCitation {
  return {
    id: citation.id ? String(citation.id).slice(0, 128) : undefined,
    title: citation.title ? String(citation.title).slice(0, 200) : undefined,
    source: citation.source ? String(citation.source).slice(0, 120) : undefined,
    url: citation.url ? String(citation.url).slice(0, 1000) : undefined,
    locator: citation.locator
      ? String(citation.locator).slice(0, 300)
      : undefined,
    summaryLength: citationSummaryLength(citation),
  };
}

function safeCitationUrl(citation: ConversationCitation) {
  if (!citation.url) return "";
  try {
    const url = new URL(citation.url, window.location.origin);
    return ["http:", "https:"].includes(url.protocol) ? url.toString() : "";
  } catch {
    return "";
  }
}

function genericReferencePrompt(reference: CopilotReference) {
  if (reference.type === "audit" || reference.type === "audit-log") {
    return [
      `[审计记录引用]`,
      `记录编号：${reference.id}`,
      "请以服务端重新查询并校验后的该条记录为准，不要使用其他项目资料代替。",
    ].join("\n");
  }
  const details =
    reference.data && Object.keys(reference.data).length
      ? JSON.stringify(reference.data, null, 2).slice(0, 5000)
      : "";
  return [
    `[功能引用：${reference.title || reference.label || reference.type}]`,
    reference.subtitle,
    reference.summary,
    details,
  ]
    .filter(Boolean)
    .join("\n");
}

function referencesPrompt(references: ConversationMessage["references"]) {
  return (references || [])
    .map((reference) =>
      isTrafficReference(reference)
        ? trafficReferencePrompt(reference)
        : genericReferencePrompt(reference),
    )
    .join("\n\n");
}

function agentContextReferences(references: ConversationMessage["references"]) {
  return (references || [])
    .map((reference) => {
      const item = reference as CopilotReference;
      const type =
        item.type === "audit-log" ? "audit" : String(item.type || "");
      const id = Number(item.id);
      if (!type || !Number.isInteger(id) || id <= 0) return undefined;
      return {
        type,
        id,
        targetId:
          Number(item.targetId) > 0
            ? Number(item.targetId)
            : undefined,
        title: item.title || item.label,
      };
    })
    .filter((reference): reference is NonNullable<typeof reference> =>
      Boolean(reference),
    );
}

function buildContextPrompt(thread: ConversationThread, userMessageId: string) {
  const messages = thread.messages
    .slice(
      0,
      thread.messages.findIndex((item) => item.id === userMessageId) + 1,
    )
    .filter((item) => item.status === "completed" && item.content.trim())
    .slice(-8);
  const current = messages[messages.length - 1]
    ? messageContextContent(messages[messages.length - 1])
    : "";
  if (messages.length <= 1) return current;
  const entries = messages.map(
    (item) =>
      `${item.role === "user" ? "用户" : "助手"}：${messageContextContent(item)}`,
  );
  const latest = entries[entries.length - 1]!;
  const heading = "这是同一授权目标下的连续对话，请结合上下文理解用户当前要求。历史和引用不代表本轮执行许可。\n";
  const history: string[] = [];
  let characters = heading.length + latest.length;
  for (const entry of entries.slice(0, -1).reverse()) {
    if (characters + entry.length + 1 > 20000) break;
    history.unshift(entry);
    characters += entry.length + 1;
  }
  return `${heading}${history.length ? history.join("\n") + "\n" : ""}${latest}`;
}

async function scrollToBottom() {
  await nextTick();
  const element = messagesElement.value;
  if (element) element.scrollTop = element.scrollHeight;
}

interface UserTurnItem {
  id: string;
  turn: number;
  preview: string;
  timeText: string;
}

const userTurns = computed<UserTurnItem[]>(() => {
  if (!selectedThread.value?.messages) return [];
  const turns: UserTurnItem[] = [];
  let turnNumber = 0;
  for (const message of selectedThread.value.messages) {
    if (message.role === "user") {
      turnNumber++;
      const text = (message.content || "").trim();
      const preview =
        text.length > 80 ? text.slice(0, 80) + "…" : (text || "（空消息）");
      turns.push({
        id: message.id,
        turn: turnNumber,
        preview,
        timeText: message.createdAt ? formatTime(message.createdAt) : "",
      });
    }
  }
  return turns;
});

const activeTurnId = ref<string>("");
const highlightedTurnId = ref<string>("");
let turnHighlightTimer: ReturnType<typeof setTimeout> | undefined;

/* 轮次导航的预览卡片是单例：整条导航条共用一个受控 el-tooltip。
   每个横条各挂一个实例时，Element Plus 会在每个实例里各跑一套
   show-after / hide-after 计时器与渐隐过渡，鼠标在两个只隔 17px 的横条之间
   划过，前一个实例还在渐隐、后一个实例已经弹出，于是两张卡片并存叠在一起。
   改成单例后「哪一轮被悬停」是唯一状态，卡片只会在两处内容之间切换。 */
const hoveredTurn = ref<UserTurnItem | null>(null);
const turnTooltipAnchor = ref<HTMLElement | null>(null);
const turnTooltipVisible = computed(
  () => hoveredTurn.value !== null && turnTooltipAnchor.value !== null,
);

function showTurnTooltip(event: Event, turn: UserTurnItem) {
  const mark = event.currentTarget as HTMLElement | null;
  if (mark) turnTooltipAnchor.value = mark;
  hoveredTurn.value = turn;
}

function clearTurnTooltip() {
  hoveredTurn.value = null;
  turnTooltipAnchor.value = null;
}

function updateActiveTurn() {
  const container = messagesElement.value;
  if (!container || !userTurns.value.length) return;
  const containerRect = container.getBoundingClientRect();

  const userArticles = container.querySelectorAll<HTMLElement>(
    "article.chat-message.user[data-message-id]",
  );
  if (!userArticles.length) return;

  let currentId = userTurns.value[0].id;
  for (const el of userArticles) {
    const rect = el.getBoundingClientRect();
    if (rect.top <= containerRect.top + containerRect.height * 0.45) {
      const id = el.getAttribute("data-message-id");
      if (id) currentId = id;
    } else {
      break;
    }
  }
  activeTurnId.value = currentId;
}

function jumpToTurn(turnId: string) {
  const container = messagesElement.value;
  if (!container) return;
  const target = container.querySelector<HTMLElement>(
    `article[data-message-id="${turnId}"]`,
  );
  if (!target) return;

  target.scrollIntoView({ behavior: "smooth", block: "start" });
  // 点击后立刻移除焦点，防止 focus 残留让旧 tooltip 常驻。
  if (document.activeElement instanceof HTMLElement) {
    document.activeElement.blur();
  }
  clearTurnTooltip();
  activeTurnId.value = turnId;

  highlightedTurnId.value = turnId;
  if (turnHighlightTimer) clearTimeout(turnHighlightTimer);
  turnHighlightTimer = setTimeout(() => {
    if (highlightedTurnId.value === turnId) {
      highlightedTurnId.value = "";
    }
  }, 1800);
}

watch(
  () => selectedThread.value?.id,
  () => {
    activeTurnId.value = "";
    highlightedTurnId.value = "";
    void nextTick(() => updateActiveTurn());
  },
);

watch(
  () => userTurns.value.length,
  () => {
    void nextTick(() => updateActiveTurn());
  },
);

/* Work events that represent real agent activity beyond executable plan steps.
 * "plan"/"done"/"approval"/"citation"/"error" are lifecycle or payload frames, not work.
 * "route"/"rewrite"/"retry"/"step" describe a unit of agent work in the graph. */
const AGENT_WORK_EVENT_TYPES = new Set([
  "route",
  "rewrite",
  "step",
  "tool_call",
  "tool_result",
  "retry",
]);

/**
 * How much real work one assistant turn performed *beyond* its plan steps.
 *
 * `message.steps` only holds *executable plan steps* — tasks that were planned
 * for dispatch. A turn that answered from retrieved context, evaluated evidence
 * and produced findings never populates that array, so counting it alone always
 * showed "0 步" for the platform's most common turn type.
 *
 * The caller already adds `message.steps.length`, so this returns only the
 * additional work those steps do not represent:
 *   1. dispatched tasks in excess of the plan (post-approval dispatch);
 *   2. tool calls recorded in the event stream (tool_call / tool_result);
 *   3. graph work nodes recorded by the orchestrator (route / rewrite / step / retry).
 *
 * `seen` must be a set owned by a single stats computation. It dedupes retried or
 * re-emitted frames of the same step across the whole thread; it must never be
 * shared between recomputations, or the second pass would count nothing.
 */
function countAssistantWorkItems(message: ConversationMessage, seen: Set<string>): number {
  const plannedSteps = Array.isArray(message.steps) ? message.steps.length : 0;
  const dispatched = Array.isArray(message.taskIds) ? message.taskIds.length : 0;
  const events = Array.isArray(message.agentEvents) ? message.agentEvents : [];
  let eventWork = 0;
  for (const event of events) {
    if (!AGENT_WORK_EVENT_TYPES.has(String(event.type || ""))) continue;
    const identity =
      event.toolCallId ||
      event.taskId ||
      event.stepId ||
      event.nodeRunId ||
      event.workflowNodeId ||
      event.id;
    if (identity === undefined) {
      eventWork += 1;
      continue;
    }
    const key = `${message.id}:${identity}`;
    if (!seen.has(key)) {
      seen.add(key);
      eventWork += 1;
    }
  }
  if (plannedSteps > 0) {
    // Plan steps already stand for the dispatched tasks; only count tasks that
    // were dispatched without a corresponding plan step (e.g. post-approval
    // dispatch into a turn whose plan was saved separately).
    return Math.max(0, Math.max(dispatched, eventWork) - plannedSteps);
  }
  return Math.max(dispatched, eventWork);
}

function formatTokensCompact(tokens: number): string {
  if (tokens >= 1_000_000_000) {
    return (tokens / 1_000_000_000).toFixed(1).replace(/\.0$/, "") + "B tok";
  }
  if (tokens >= 1_000_000) {
    return (tokens / 1_000_000).toFixed(1).replace(/\.0$/, "") + "M tok";
  }
  if (tokens >= 1_000) {
    return (tokens / 1_000).toFixed(1).replace(/\.0$/, "") + "k tok";
  }
  return tokens + " tok";
}

function formatTokensExact(tokens: number): string {
  return tokens.toLocaleString() + " tok";
}

function formatDurationCompact(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}毫秒`;
  const totalSeconds = Math.round(ms / 1000);
  if (totalSeconds < 60) return `${totalSeconds}秒`;
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return seconds > 0 ? `${minutes}分${seconds}秒` : `${minutes}秒`;
}

const sessionStats = computed(() => {
  const thread = selectedThread.value;
  if (!thread || !thread.messages || !thread.messages.length) return null;

  let turns = 0;
  let steps = 0;
  let totalOutputTokens = 0;
  let totalInputTokens = 0;
  let totalCachedTokens = 0;
  let totalCacheWriteTokens = 0;
  let totalTokens = 0;
  let llmMs = 0;
  let toolMs = 0;
  let lastContextWindowTokens = 0;
  let lastContextWindowUsed = 0;
  let lastContextRatePermille = 0;
  let latestTps = 0;
  // Dedupes retried/re-emitted work events across the whole thread. Owned by this
  // single computation so a recomputation always starts from a clean slate.
  const seenWorkEvents = new Set<string>();

  for (const msg of thread.messages) {
    if (msg.role === "user") {
      turns++;
    }
    if (msg.steps && msg.steps.length) {
      steps += msg.steps.length;
      for (const step of msg.steps) {
        if (step.taskId) {
          const task = tasks.value.find((t) => t.id === step.taskId);
          if (task?.startedAt && task?.finishedAt) {
            const start = Date.parse(task.startedAt);
            const end = Date.parse(task.finishedAt);
            if (!isNaN(start) && !isNaN(end) && end > start) {
              toolMs += end - start;
            }
          }
        }
      }
    }
    // A turn can do real work without ever becoming an executable plan step:
    // the model may retrieve project context, evaluate evidence, and answer,
    // which the orchestrator records as node events rather than plan steps.
    // Counting only msg.steps made every such turn show "0 步" even though
    // tokens, findings and elapsed time were all real.
    // NOTE: msg.steps.length is already added above, so this must return only
    // the work that plan steps do NOT already represent.
    if (msg.role === "assistant") {
      steps += countAssistantWorkItems(msg, seenWorkEvents);
      if (msg.progressStartedAt && msg.progressFinishedAt) {
        const start = Date.parse(msg.progressStartedAt);
        const end = Date.parse(msg.progressFinishedAt);
        if (!isNaN(start) && !isNaN(end) && end > start) {
          const duration = end - start;
          llmMs += duration;
          if (msg.modelUsage?.outputTokens) {
            const sec = duration / 1000;
            if (sec > 0) {
              latestTps = Math.round(msg.modelUsage.outputTokens / sec);
            }
          }
        }
      }

      if (msg.modelUsage && msg.modelUsage.available) {
        const u = msg.modelUsage;
        totalInputTokens += u.inputTokens || 0;
        totalOutputTokens += u.outputTokens || 0;
        totalCachedTokens += u.cachedInputTokens || 0;
        totalCacheWriteTokens += u.cacheWriteTokens || 0;
        totalTokens += u.totalTokens || ((u.inputTokens || 0) + (u.outputTokens || 0));

        if (u.contextWindowTokens) {
          lastContextWindowTokens = u.contextWindowTokens;
          lastContextWindowUsed = u.contextWindowUsedTokens || 0;
          lastContextRatePermille = u.contextWindowUsagePermille || 0;
        }
      }
    }
  }

  const avgTps = llmMs > 0 && totalOutputTokens > 0
    ? Math.round(totalOutputTokens / (llmMs / 1000))
    : latestTps;

  const totalBilledInput = totalInputTokens + totalCachedTokens;
  const cacheHitRate = totalBilledInput > 0
    ? Math.round((totalCachedTokens / totalBilledInput) * 100)
    : null;

  const contextPercent = lastContextRatePermille > 0
    ? Math.round(lastContextRatePermille / 10)
    : (lastContextWindowTokens > 0
        ? Math.round((lastContextWindowUsed / lastContextWindowTokens) * 100)
        : 0);

  if (turns === 0 && steps === 0 && totalTokens === 0) return null;

  return {
    turns,
    steps,
    tps: avgTps || latestTps || 0,
    llmMs,
    toolMs,
    totalTokens,
    uncachedInputTokens: totalInputTokens,
    cachedInputTokens: totalCachedTokens,
    cacheWriteTokens: totalCacheWriteTokens,
    outputTokens: totalOutputTokens,
    cacheHitRate,
    contextWindowTokens: lastContextWindowTokens,
    contextWindowUsed: lastContextWindowUsed,
    contextPercent: Math.min(100, Math.max(0, contextPercent)),
  };
});

function eventStepIndex(message: ConversationMessage, event: AgentStreamEvent) {
  const match = findMatchingAiStep(message.steps, { id: event.stepId, workflowNodeId: event.workflowNodeId, toolCallId: event.toolCallId, taskId: event.taskId });
  if (match) return message.steps.indexOf(match);
  return undefined;
}

function normalizedStep(
  raw: Record<string, unknown>,
  index: number,
): ConversationStep {
  const toolCode = String(
    raw.toolCode || raw.tool_code || raw.tool || "agent-step",
  );
  return {
    id:
      raw.id || raw.stepId || raw.step_id
        ? String(raw.id || raw.stepId || raw.step_id)
        : `agent-step-${index + 1}`,
    workflowNodeId:
      raw.workflowNodeId || raw.workflow_node_id || raw.nodeId
        ? String(raw.workflowNodeId || raw.workflow_node_id || raw.nodeId)
        : undefined,
    nodeRunId: raw.nodeRunId ? String(raw.nodeRunId) : undefined,
    group: raw.group !== undefined ? Number(raw.group) : undefined,
    dependsOnNodeIds: Array.isArray(raw.dependsOnNodeIds)
      ? raw.dependsOnNodeIds.map(String)
      : undefined,
    toolCode,
    title: String(raw.title || raw.name || raw.label || toolCode),
    parameters: raw.parameters && typeof raw.parameters === "object" && !Array.isArray(raw.parameters) ? raw.parameters as Record<string, unknown> : {},
    risk: raw.risk ? String(raw.risk) : undefined,
    reason:
      raw.reason || raw.description || raw.summary
        ? String(raw.reason || raw.description || raw.summary)
        : undefined,
    taskId:
      raw.taskId || raw.task_id ? Number(raw.taskId || raw.task_id) : undefined,
    status: raw.status ? String(raw.status) : "pending",
    progress:
      raw.progress !== undefined
        ? Math.max(0, Math.min(100, Number(raw.progress) || 0))
        : 0,
    command:
      raw.command || raw.cmd ? String(raw.command || raw.cmd) : undefined,
    toolCallId:
      raw.toolCallId || raw.tool_call_id
        ? String(raw.toolCallId || raw.tool_call_id)
        : undefined,
    requiresApproval: Boolean(raw.requiresApproval || raw.requires_approval),
  };
}

function formatUsageNumber(value: number) {
  return new Intl.NumberFormat("zh-CN").format(value);
}

function usageRate(value: number) {
  return `${(value / 10).toFixed(1)}%`;
}

function applyAgentEvent(
  threadId: string,
  messageId: string,
  incoming: AiDispatchStreamEvent,
) {
  const event = normalizeAgentEvent(incoming) as AgentStreamEvent | undefined;
  if (!event || !isPublicAiProgressEvent(event)) return;
  const thread = conversations.items.find((item) => item.id === threadId);
  const message = thread?.messages.find((item) => item.id === messageId);
  if (!message) return;

  const events = [...(message.agentEvents || [])];
  const eventRecord: ConversationAgentEvent = {
    ...publicProgressProvenance({ ...event }),
    id: event.id ? String(event.id) : `${Date.now()}-${events.length}`,
    type: event.type,
    stage: event.stage ? String(event.stage) : undefined,
    status: event.status ? String(event.status) : undefined,
    summary: publicAiProgressText(event.summary || event.message) || undefined,
    stepId: event.stepId ? String(event.stepId) : undefined,
    stepIndex:
      event.stepIndex !== undefined ? Number(event.stepIndex) : undefined,
    toolCode: event.toolCode ? String(event.toolCode) : undefined,
    toolName: event.toolName ? String(event.toolName) : undefined,
    toolCallId: event.toolCallId ? String(event.toolCallId) : undefined,
    taskId: event.taskId ? Number(event.taskId) : undefined,
    attempt: event.attempt !== undefined ? Number(event.attempt) : undefined,
    maxAttempts:
      event.maxAttempts !== undefined ? Number(event.maxAttempts) : undefined,
    approvalId: event.approvalId ? String(event.approvalId) : undefined,
    approvalStatus: event.approvalStatus
      ? String(event.approvalStatus)
      : undefined,
    executionDecision: event.executionDecision,
    modelUsage: event.modelUsage,
    citation: event.citation ? publicCitation(event.citation) : undefined,
    contractVersion:
      event.contractVersion !== undefined
        ? Number(event.contractVersion)
        : undefined,
    runId: event.runId ? String(event.runId) : undefined,
    workflowId: event.workflowId ? String(event.workflowId) : undefined,
    workflowRevision:
      event.workflowRevision !== undefined
        ? Number(event.workflowRevision)
        : undefined,
    workflowDigest: event.workflowDigest
      ? String(event.workflowDigest)
      : undefined,
    workflowNodeId: event.workflowNodeId
      ? String(event.workflowNodeId)
      : undefined,
    outerNodeId: event.outerNodeId ? String(event.outerNodeId) : undefined,
    nodeRunId: event.nodeRunId ? String(event.nodeRunId) : undefined,
    publicNodeStatus: event.publicNodeStatus,
    innerStep: event.innerStep ? String(event.innerStep) : undefined,
    ledgerSequence:
      event.ledgerSequence !== undefined
        ? Number(event.ledgerSequence)
        : undefined,
    ledgerEntryDigest: event.ledgerEntryDigest
      ? String(event.ledgerEntryDigest)
      : undefined,
    ledgerDigest: event.ledgerDigest ? String(event.ledgerDigest) : undefined,
    terminationReason: event.terminationReason
      ? String(event.terminationReason)
      : undefined,
    evidenceCount:
      event.evidenceCount !== undefined ? Number(event.evidenceCount) : undefined,
    actionCount:
      event.actionCount !== undefined ? Number(event.actionCount) : undefined,
    taskIds: Array.isArray(event.taskIds)
      ? event.taskIds.map(Number).filter((id) => Number.isFinite(id) && id > 0)
      : undefined,
    recoverable:
      typeof event.recoverable === "boolean" ? event.recoverable : undefined,
    createdAt: new Date().toISOString(),
    recorded: event.recorded,
    eventTiming: event.eventTiming,
  };
  const last = events[events.length - 1];
  const duplicate =
    last &&
    last.type === eventRecord.type &&
    last.stage === eventRecord.stage &&
    last.status === eventRecord.status &&
    last.evidenceCount === eventRecord.evidenceCount &&
    last.actionCount === eventRecord.actionCount &&
    last.executionDecision === eventRecord.executionDecision &&
    last.publicNodeStatus === eventRecord.publicNodeStatus &&
    last.stepId === eventRecord.stepId &&
    last.toolCallId === eventRecord.toolCallId &&
    last.summary === eventRecord.summary &&
    last.source === eventRecord.source &&
    last.assessmentSource === eventRecord.assessmentSource &&
    last.modelDecision === eventRecord.modelDecision &&
    last.evidenceDecision === eventRecord.evidenceDecision &&
    last.guardReason === eventRecord.guardReason &&
    JSON.stringify(last.reasonCodes) === JSON.stringify(eventRecord.reasonCodes) &&
    ![
      "tool_call",
      "tool_result",
      "approval",
      "retry",
      "citation",
      "error",
    ].includes(eventRecord.type);
  if (!duplicate) events.push(eventRecord);

  let steps = [...(message.steps || [])];
  const rawSteps = (event.steps ||
    event.plan?.steps ||
    (
      event as ConversationAgentEvent & {
        actions?: Array<Record<string, unknown>>;
      }
    ).actions) as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(rawSteps) && rawSteps.length) {
    steps = rawSteps.map((step, index) => {
      const incoming = normalizedStep(step, index);
      return mergeAiStep(findMatchingAiStep(steps, incoming), incoming);
    });
  }
  const index = eventStepIndex({ ...message, steps }, event);
  const stepStatus = aiEventStepStatus(event);
  const hasStepIdentity = Boolean(
    event.stepId ||
    event.toolCode ||
    event.toolName ||
    event.toolCallId ||
    event.taskId,
  );
  const isActionStepEvent =
    index !== undefined ||
    (hasStepIdentity &&
      ["step", "tool_call", "tool_result", "retry", "approval"].includes(
        event.type,
      ));
  if (isActionStepEvent) {
    const targetIndex = index !== undefined ? index : steps.length;
    if (!steps[targetIndex])
      steps[targetIndex] = normalizedStep(
        event as unknown as Record<string, unknown>,
        targetIndex,
      );
    const current = steps[targetIndex];
    steps[targetIndex] = mergeAiStep(current, {
      ...current,
      id: current.id || (event.stepId ? String(event.stepId) : undefined),
      workflowNodeId:
        current.workflowNodeId ||
        (event.workflowNodeId ? String(event.workflowNodeId) : undefined),
      nodeRunId:
        current.nodeRunId ||
        (event.nodeRunId ? String(event.nodeRunId) : undefined),
      toolCode:
        current.toolCode ||
        String(event.toolCode || event.toolName || "agent-step"),
      title:
        current.title ||
        String(
          event.toolName ||
            event.toolCode ||
            event.summary ||
            `步骤 ${targetIndex + 1}`,
        ),
      reason:
        current.reason || (event.summary ? String(event.summary) : undefined),
      status: stepStatus || current.status || "pending",
      progress:
        event.progress !== undefined
          ? Math.max(0, Math.min(100, Number(event.progress) || 0))
          : stepStatus === "success"
            ? 100
            : current.progress,
      command: event.command
        ? String(event.command).slice(0, 2000)
        : current.command,
      toolCallId: event.toolCallId
        ? String(event.toolCallId)
        : current.toolCallId,
      taskId: event.taskId ? Number(event.taskId) : current.taskId,
      output:
        event.output !== undefined
          ? displayAgentValue(event.output, 4000)
          : current.output,
      error: event.error ? String(event.error).slice(0, 800) : current.error,
      attempt:
        event.attempt !== undefined ? Number(event.attempt) : current.attempt,
      maxAttempts:
        event.maxAttempts !== undefined
          ? Number(event.maxAttempts)
          : current.maxAttempts,
      requiresApproval: event.type === "approval" || current.requiresApproval,
    });
  }

  const citations = [...(message.citations || [])];
  const incomingCitations = [
    ...(event.citations || []),
    ...(event.citation ? [event.citation] : []),
  ];
  for (const citation of incomingCitations) {
    if (!citation) continue;
    const safeCitation = publicCitation(citation);
    const key =
      safeCitation.id ||
      safeCitation.url ||
      safeCitation.title ||
      safeCitation.source;
    if (
      !key ||
      !citations.some(
        (item) => (item.id || item.url || item.title || item.source) === key,
      )
    )
      citations.push(safeCitation);
  }
  const progressSummary =
    eventRecord.summary ||
    (event.type === "tool_call"
      ? `正在调用 ${aiToolLabel(event.toolCode, event.toolName)}`
      : "");
  const stage = String(event.stage || event.node || "").toLowerCase();
  const stageLabel: Record<string, string> = {
    engagement: "正在启动项目并确认目标范围",
    engage: "正在启动项目并确认目标范围",
    scope: "正在启动项目并确认目标范围",
    reconnaissance: "正在进行侦察与项目情报整理",
    recon: "正在进行侦察与项目情报整理",
    mapping: "正在发现资产、端口与服务",
    map: "正在发现资产、端口与服务",
    asset_mapping: "正在发现资产、端口与服务",
    discovery: "正在识别指纹与潜在漏洞",
    vulnerability_discovery: "正在识别指纹与潜在漏洞",
    validation: "正在进行受控漏洞验证",
    validate: "正在进行受控漏洞验证",
    impact: "正在评估漏洞影响与攻击路径",
    impact_assessment: "正在评估漏洞影响与攻击路径",
    retest: "正在核对修复、证据与复测条件",
    remediation: "正在核对修复、证据与复测条件",
    reporting: "正在汇总证据并形成交付结论",
    report: "正在汇总证据并形成交付结论",
    finish: "正在汇总证据并形成交付结论",
    planner: "正在生成红队评估行动方案",
    executor: "正在推进受控检测阶段",
    reviewer: "正在整理证据与交付结论",
    authorization_guard: "正在核对当前阶段的授权范围",
    approval: "正在确认执行条件",
    approval_required: "等待确认后继续验证",
    session: "正在恢复项目对话记忆",
    retry: "已收到重试状态反馈",
    completed: "本轮模型处理结束",
  };
  const hasPlanSteps =
    (Array.isArray(event.steps) && event.steps.length > 0) ||
    Boolean(
      event.plan &&
      Array.isArray(event.plan.steps) &&
      event.plan.steps.length > 0,
    );
  const recordedEvent = event.recorded || event.eventTiming === "VERIFIED_RECORD";
  // 终态事件（done / error）代表这一轮模型交互已经结束，无论是否携带 answer
  // 正文都必须收尾；否则无关联任务的一轮会永久停留在进行中。
  const terminalDone = !recordedEvent && event.type === "done"
    && !["FAILED", "RECORDED"].includes(event.status || "");
  const status = recordedEvent ? message.status :
    event.type === "error"
      ? "failed"
      : terminalDone
        ? "completed"
        : event.type === "approval"
          ? "running"
          : event.type === "plan" && hasPlanSteps
            ? "planning"
            : event.type === "step" && hasPlanSteps
              ? "planning"
              : ["tool_call", "tool_result", "retry"].includes(event.type)
                ? "running"
                : message.status;
  let content = message.content;
  // 后端终态事件把模型正文放在 data.response.message。normalizeAgentEvent()
  // 已经把 data.response 摊平到事件对象上（见 api.ts 的 answer/approvalId/
  // taskIds 等字段），因此这里**不存在** event.data —— 之前读取
  // (event.data as any)?.response 是死代码，永远得到 undefined。
  // 正文顺序：event.answer（已由 api.ts 优先取 response.message）→ 计划摘要 → 事件消息。
  const doneAnswer = String(
    event.answer || event.plan?.summary || "",
  ).trim();
  if (event.type === "error" && !recordedEvent)
    content = readableAiConversationError(
      event.message || event.summary,
      "智能体执行失败。",
    ).slice(0, 2000);
  else if (terminalDone && doneAnswer)
    content = doneAnswer;
  else if (
    progressSummary &&
    ["planning", "running"].includes(status) &&
    // 已经拿到终态回答后，后续迟到的进度事件不得再把回答正文顶掉
    // （表现为回答先显示、随后被"正在调用…"这类状态句替换）。
    message.modelStreamStatus !== "completed"
  )
    content = progressSummary;
  conversations.updateMessage(threadId, messageId, {
    status: status as ConversationMessage["status"],
    content,
    modelUsage: event.modelUsage || message.modelUsage,
    agentEvents: events.slice(-100),
    citations: citations.slice(-30),
    steps,
    // 记录模型流的终态，供收尾逻辑判断"这一轮是否已经结束"。
    modelStreamStatus: terminalDone
      ? "completed"
      : event.type === "error" && !recordedEvent
        ? "failed"
        : message.modelStreamStatus,
    approvalId: !recordedEvent && event.approvalId || message.approvalId,
    approvalStatus: !recordedEvent && event.approvalStatus || message.approvalStatus,
    judge: (event.judge as JudgeVerdictDocument | undefined) || message.judge,
    executionDecision: event.executionDecision || message.executionDecision,
    // 终态事件会带回本轮是否真的派发了任务；无任务时保持空数组，
    // 使界面呈现"等待确认/未创建任务"而不是永久进行中。
    taskIds:
      !recordedEvent && Array.isArray(event.taskIds) && event.taskIds.length
        ? event.taskIds
        : message.taskIds,
    planningStage:
      event.stage || String(event.node || "") || message.planningStage,
    planningStatus:
      event.type === "plan" && steps.length
        ? `已生成 ${steps.length} 步执行计划`
        : String(progressSummary || stageLabel[stage] || message.planningStatus || ""),
  });
  // 终态事件到达后立即尝试收尾：无关联任务的一轮不会再有任务事件来触发
  // reconcileTaskMessages，必须在这里主动调用，否则界面停留在「尚未收到阶段反馈」。
  if (terminalDone || (event.type === "error" && !recordedEvent))
    void nextTick(() => {
      reconcileTaskMessages();
      // The turn just ended. Ask immediately what it is now waiting on (scan
      // tasks / scheduled continuation) instead of waiting for the next poll tick.
      void refreshAwaitingStatus();
    });
  void scrollToBottom();
}

function recordThinkingProgress(
  threadId: string,
  messageId: string,
  event: AiDispatchStreamEvent,
) {
  applyAgentEvent(threadId, messageId, event);
}

function readableConversationError(error: unknown) {
  const value = error as { code?: string };
  return value?.code === "ECONNABORTED"
    ? "智能体长时间没有返回新的分析进度，请稍后再试。"
    : readableAiConversationError(
        error,
        "智能体无法派发任务，请检查目标授权范围和后端配置。",
      );
}

async function dispatchConversationMessage(
  thread: ConversationThread,
  userMessage: ConversationMessage,
  assistantMessage: ConversationMessage,
  projectId = projectIdForTarget(thread.targetId, thread),
) {
  const requestPrompt = buildContextPrompt(thread, userMessage.id);
  const refs = messageReferences(userMessage);
  const workflow = await latestWorkflowIdentity(projectId);
  conversations.updateMessage(thread.id, assistantMessage.id, {
    modelStreamStatus: "running", progressStartedAt: new Date().toISOString(), progressFinishedAt: undefined,
  });
  let data;
  let streamedAnswer = "";
  try {
    data = await dispatchAiStreaming(
    {
      projectId,
      targetId: thread.targetId,
      sessionId: thread.id,
      turnId: userMessage.id,
      ...workflow,
      prompt: requestPrompt,
      ...aiExecutionRequest(userMessage),
      mode: userMessage.copilotMode,
      refs: agentContextReferences(refs),
    },
    (incoming) => {
      recordThinkingProgress(thread.id, assistantMessage.id, incoming);
      const event = normalizeAgentEvent(incoming);
      if (event?.type === "done" && !event.recorded &&
          event.eventTiming !== "VERIFIED_RECORD" &&
          !["FAILED", "RECORDED"].includes(event.status || "")) {
        streamedAnswer = [event.answer, event.plan?.summary]
          .find(value => typeof value === "string" && value.trim())?.trim() || "";
      }
    },
  );
    conversations.updateMessage(thread.id, assistantMessage.id, {
      modelStreamStatus: "completed", progressFinishedAt: new Date().toISOString(),
    });
  } catch (error) {
    conversations.updateMessage(thread.id, assistantMessage.id, {
      modelStreamStatus: "failed", progressFinishedAt: new Date().toISOString(),
    });
    throw error;
  }
  const streamedMessage = conversations.items
    .find((item) => item.id === thread.id)
    ?.messages.find((item) => item.id === assistantMessage.id);
  const planSteps = Array.isArray(data.plan?.steps) ? data.plan.steps : [];
  const finalSteps = (
    planSteps.length ? planSteps : streamedMessage?.steps || []
  ).map((step: any, index: number) => {
    const streamed =
      streamedMessage?.steps[index] ||
      streamedMessage?.steps.find(
        (item) => item.toolCode === (step.toolCode || step.tool),
      );
    const toolCode = String(
      step.toolCode || step.tool || streamed?.toolCode || `step-${index + 1}`,
    );
    return {
      id: streamed?.id || `plan-step-${index + 1}`,
      workflowNodeId: String(
        step.workflowNodeId ||
          step.nodeId ||
          streamed?.workflowNodeId ||
          "",
      ) || undefined,
      nodeRunId:
        String(step.nodeRunId || streamed?.nodeRunId || "") || undefined,
      group: step.group !== undefined ? Number(step.group) : streamed?.group,
      dependsOnNodeIds: Array.isArray(step.dependsOnNodeIds)
        ? step.dependsOnNodeIds.map(String)
        : streamed?.dependsOnNodeIds,
      toolCode,
      title: String(step.title || streamed?.title || toolCode),
      parameters: step.parameters || streamed?.parameters || {},
      risk: step.risk || streamed?.risk,
      reason: String(step.reason || streamed?.reason || toolCode),
      taskId: data.taskIds[index] || streamed?.taskId,
      status: data.taskIds[index]
        ? streamed?.status || "pending"
        : streamed?.status || "pending",
      requiresApproval: Boolean(
        step.requiresApproval ?? streamed?.requiresApproval,
      ),
    };
  });
  const finalCitations = [
    ...(streamedMessage?.citations || []),
    ...(data.citations || []),
  ].map(publicCitation).filter((citation, index, all) => {
    const key =
      citation.id || citation.url || citation.title || citation.source;
    return (
      !key ||
      all.findIndex(
        (item) => (item.id || item.url || item.title || item.source) === key,
      ) === index
    );
  });
  const planSummary = data.plan.summary?.trim();
  const answerText = data.answer?.trim() || planSummary || streamedAnswer;
  const operationalReceipt = !answerText && (data.taskIds.length > 0 || data.approvalId || streamedMessage?.approvalId);
  // Only a live terminal answer qualifies as a fallback, never stored progress
  // text or a replayed plan from an earlier turn.
  let finalContent: string;
  try {
    finalContent = operationalReceipt
      ? data.taskIds.length
        ? `已按授权范围派发 ${data.taskIds.length} 个任务。执行状态以任务记录为准，结束后将生成检测结论。`
        : "方案已提交确认，请查看本次操作和授权范围。"
      : requireAiAnswer(answerText);
  } catch (error) {
    conversations.updateMessage(thread.id, assistantMessage.id, { modelStreamStatus: "failed" });
    throw error;
  }
  conversations.updateMessage(thread.id, assistantMessage.id, {
    content: finalContent,
    status: data.taskIds.length ? "running" : "completed",
    provider: operationalReceipt
      ? "operation-receipt"
      : data.plan?.provider ||
        (data as any).provider ||
        streamedMessage?.provider ||
        "openai-compatible",
    taskIds: data.taskIds,
    approvalId: data.approvalId || streamedMessage?.approvalId,
    approvalStatus: data.approvalStatus || streamedMessage?.approvalStatus,
    steps:
      planSteps.length || data.taskIds.length
        ? finalSteps.length
          ? finalSteps
          : streamedMessage?.steps || []
        : [],
    citations: finalCitations.slice(-30),
    planningStage: "completed",
    planningStatus: data.taskIds.length
      ? "已创建任务，状态以任务记录为准"
      : "智能体已完成处理",
  });
  const finalMessage = conversations.items.find(item => item.id === thread.id)?.messages.find(item => item.id === assistantMessage.id);
  if (finalMessage && shouldPromptApproval(selectedThread.value?.id, thread.id, finalMessage)) {
    approvalDialogMessageId.value = finalMessage.id;
  }
  if (answerText && !isLocalAiAnswer(data.plan.provider))
    void saveConversationMemory(thread, userMessage.content, answerText);
  await loadTasks();
}

async function latestWorkflowIdentity(
  projectId?: number,
): Promise<{
  workflowId?: string;
  workflowRevision?: number;
  workflowDigest?: string;
}> {
  if (!projectId) return {};
  const { data } = await endpoints.getWorkflowSpec(projectId);
  const workflowId = data?.workflowId;
  const workflowRevision = data?.revision;
  const workflowDigest = data?.specDigest;
  const identityFields = [workflowId, workflowRevision, workflowDigest].filter(
    (value) => value !== undefined && value !== null && value !== "",
  ).length;
  if (!identityFields) return {};
  if (
    !workflowId ||
    !Number.isInteger(Number(workflowRevision)) ||
    Number(workflowRevision) <= 0 ||
    !/^sha256:[0-9a-f]{64}$/.test(String(workflowDigest))
  ) {
    throw new Error("项目工作流快照元数据不完整，已停止本次 Agent 运行");
  }
  return {
    workflowId,
    workflowRevision: Number(workflowRevision),
    workflowDigest,
  };
}

// 审批状态与操作加载中记录
const approvingMessageId = ref<string | null>(null);
const approvalDialogMessageId = ref<string | null>(null);
const shouldPromptApproval = createAiApprovalPromptGate();
const approvalDialogMessage = computed(() => selectedThread.value?.messages.find(message => message.id === approvalDialogMessageId.value && isAwaitingAiApproval(message)));
const approvalTarget = computed(() => targets.value.find(target => target.id === selectedThread.value?.targetId));
const approvalDialogVisible = computed({ get: () => Boolean(approvalDialogMessage.value), set: value => { if (!value) approvalDialogMessageId.value = null; } });
watch(() => selectedThread.value?.id, () => { approvalDialogMessageId.value = null; });
function reopenApproval(message: ConversationMessage) {
  if (isAwaitingAiApproval(message)) approvalDialogMessageId.value = message.id;
}
function decideDialogApproval(
  decision: "APPROVED" | "REJECTED",
  overrides?: Array<Record<string, unknown>>,
) {
  const message = approvalDialogMessage.value;
  if (message) void handleAgentApprovalDecision(message, decision, overrides);
}

async function handleAgentApprovalDecision(
  message: ConversationMessage,
  decision: "APPROVED" | "REJECTED",
  overrides?: Array<Record<string, unknown>>,
) {
  if (approvingMessageId.value || sending.value) return;
  const thread = selectedThread.value;
  if (!thread) return;
  const projectId = projectIdForTarget(thread.targetId, thread);
  if (!projectId) {
    ElMessage.error("未找到关联的评估项目，无法提交审批裁决");
    return;
  }
  const approvalId = message.approvalId ? Number(message.approvalId) : undefined;
  if (!approvalId) {
    ElMessage.warning("未检测到该计划关联的项目审批单号");
    return;
  }

  let dispatchStarted = false;
  let dispatchReceived = false;
  try {
    approvingMessageId.value = message.id;
    await endpoints.decideProjectApproval(projectId, approvalId, {
      status: decision,
      comment:
        decision === "APPROVED"
          ? "管理员在 AI 助手交互卡片中审核通过并授权执行"
          : "管理员在 AI 助手交互卡片中驳回执行",
      stepOverrides: overrides,
    });

    if (decision === "REJECTED") {
      conversations.updateMessage(thread.id, message.id, {
        approvalStatus: "REJECTED",
        planningStatus: "管理员已驳回执行方案",
        content: message.content + "\n\n**管理员已驳回本次行动方案**（确认记录 #" + approvalId + "）。未派发任何受控任务。",
      });
      ElMessage.info("已驳回该行动方案");
      return;
    }

    conversations.updateMessage(thread.id, message.id, {
      approvalStatus: "APPROVED",
      approvalDispatchStatus: "dispatching",
      approvalDispatchError: undefined,
      approvalDispatchUpdatedAt: new Date().toISOString(),
      planningStatus: "已确认，正在请求派发保存的原方案...",
    });
    // The server consumes the immutable approved plan. Never ask the model to re-plan.
    dispatchStarted = true;
    const { data } = await endpoints.resumeProjectAiApproval(projectId, approvalId);
    dispatchReceived = true;
    conversations.updateMessage(thread.id, message.id, {
      approvalStatus: "APPROVED",
      approvalDispatchStatus: "dispatched",
      approvalDispatchError: undefined,
      approvalDispatchUpdatedAt: new Date().toISOString(),
      status: data.taskIds.length ? "running" : "completed",
      modelStreamStatus: "completed",
      taskIds: data.taskIds,
      steps: data.plan.steps.map((step, index) => ({ ...step, taskId: data.taskIds[index] })),
      planningStatus: `已按确认的原方案派发 ${data.taskIds.length} 个任务`,
      content: message.content + `\n\n确认记录 #${approvalId} 已确认，原方案已关联 ${data.taskIds.length} 个任务。执行结果以任务记录为准。`,
    });
    await loadTasks();
    ElMessage.success(`确认记录 #${approvalId} 已按原计划派发`);
  } catch (error) {
    const detail = readableConversationError(error);
    if (dispatchStarted && !dispatchReceived) {
      const state = aiDispatchFailureStatus(error);
      conversations.updateMessage(thread.id, message.id, {
        approvalDispatchStatus: state,
        approvalDispatchError: detail,
        approvalDispatchUpdatedAt: new Date().toISOString(),
        planningStatus: state === "rejected" ? "执行已拒绝，未派发任务" : "派发结果待核实，请查看任务或恢复原审批",
      });
    }
    ElMessage.error(detail);
  } finally {
    approvingMessageId.value = null;
  }
}

// After each exchange, store a concise summary in the project's LlamaIndex so
// future conversations can retrieve past findings. Best-effort; never blocks chat.
async function saveConversationMemory(
  thread: ConversationThread,
  prompt: string,
  answer: string,
) {
  const projectId = projectIdForTarget(thread.targetId, thread);
  if (!projectId || !prompt?.trim() || !answer?.trim()) return;
  try {
    await endpoints.saveMemory({
      projectId,
      targetId: thread.targetId,
      conversationId: thread.id,
      prompt: prompt.trim(),
      answer: answer.trim(),
    });
  } catch {
    /* memory is best-effort */
  }
}

async function sendPrompt() {
  const text = prompt.value.trim();
  if (!text || sending.value) return;
  if (text.length > 4000) {
    ElMessage.warning("本轮请求请控制在 4000 字以内");
    return;
  }
  let target = selectedTarget.value;
  if (!target) {
    ElMessage.warning(
      enabledTargets.value.length
        ? "请先选择授权目标"
        : "请先登记并启用一个授权目标",
    );
    return;
  }

  const editing = editingMessage.value;
  if (editing && selectedThread.value?.id !== editing.threadId) {
    ElMessage.warning("请回到原对话继续编辑，或取消本次编辑");
    return;
  }
  const references = cloneMessageDraft(editing?.references || activeDraft.value?.refs);
  const mode = editing?.mode || activeDraft.value?.mode;
  const quote = cloneMessageDraft(quotedMessage.value);
  let thread = selectedThread.value;
  let assistantMessage: ConversationMessage | undefined;
  // Lock before creating a branch or awaiting navigation so double submits cannot fork twice.
  sending.value = true;
  try {
    const auditScope = await auditScopeForMessage(references, target.id,
      projectIdForTarget(target.id, thread));
    if (auditScope) {
      target = auditScope.target;
      selectedTargetId.value = target.id;
      // Server sessions bind their target permanently. Repair old failed audit chats in a new session.
      if (!thread || thread.targetId !== target.id || thread.projectId !== auditScope.projectId)
        thread = conversations.createThread(target.id, target.name, text, auditScope.projectId,
          editing ? { threadId: editing.threadId, messageId: editing.messageId } : undefined);
    }
    if (editing && (!auditScope || thread?.id === editing.threadId)) {
      try { thread = conversations.forkBeforeMessage(editing.threadId, editing.messageId, text); }
      catch (error) {
        ElMessage.error(error instanceof Error ? error.message : "未能创建分支，原对话仍保留");
        return;
      }
    } else if (!thread) {
      thread = conversations.createThread(target.id, target.name, text, projectIdForTarget(target.id));
    }
    if (thread) activeSendingThreadIds.value.add(thread.id);
    const turn = conversations.appendTurn(thread.id, {
      role: "user", content: text, status: "completed", taskIds: [], steps: [],
      references, copilotMode: mode, executionIntent: "AUTO",
      quote: quote ? { messageId: quote.id, role: quote.role, content: quote.content.slice(0, 4000), createdAt: quote.createdAt } : undefined,
    }, {
      role: "assistant", content: "我正在理解你的要求，核对目标范围与已有证据。",
      status: "running", taskIds: [], steps: [], executionIntent: "AUTO",
    });
    if (!turn) return;
    const userMessage = turn.userMessage;
    assistantMessage = turn.assistantMessage;
    const projectId = projectIdForTarget(thread.targetId, thread);
    editingMessage.value = undefined;
    activeDraft.value = undefined;
    clearQuotedMessage();
    prompt.value = "";
    if (selectedThread.value?.id !== thread.id)
      await router.replace({ path: "/", query: { conversation: thread.id } });
    void scrollToBottom();
    await dispatchConversationMessage(thread, userMessage, assistantMessage, projectId);
  } catch (error: any) {
    const message = error instanceof ConversationStorageError ? error.message : readableConversationError(error);
    if (thread && assistantMessage) {
      // 绑定到 const 局部变量：thread/assistantMessage 是外层 let，TS 无法把收窄结果
      // 带进下面的箭头函数闭包（TS18048）。此处显式固定，既满足类型检查，
      // 也避免闭包内再次读取可变变量。
      const activeThread = thread;
      const activeAssistantMessage = assistantMessage;
      // A task-list refresh can fail after a valid terminal answer was saved.
      // Preserve that answer, but never promote an initial or progress placeholder.
      const existing = conversations.items
        .find((item) => item.id === activeThread.id)
        ?.messages.find((item) => item.id === activeAssistantMessage.id);
      const streamed = String(existing?.content || "").trim();
      const alreadyAnswered =
        Boolean(streamed) &&
        existing?.modelStreamStatus === "completed" &&
        (existing.status === "completed" || existing.taskIds.length > 0);
      if (alreadyAnswered) {
        // 已有回答：保留回答正文，仅把状态标为已完成，避免"重试回复"按钮误现。
        conversations.updateMessage(activeThread.id, activeAssistantMessage.id, {
          content: streamed,
          status: "completed",
          modelStreamStatus: "completed",
        });
      } else {
        conversations.updateMessage(activeThread.id, activeAssistantMessage.id, {
          content: message,
          status: "failed",
          modelStreamStatus: "failed",
        });
      }
    } else ElMessage.error(message);
  } finally {
    if (thread) activeSendingThreadIds.value.delete(thread.id);
    sending.value = false;
    void scrollToBottom();
  }
}

async function retryConversationMessage(message: ConversationMessage) {
  let thread = selectedThread.value;
  if (
    !thread ||
    sending.value ||
    message.role !== "assistant" ||
    // 失败的回答允许重试；已完成的回答允许"重新生成"。其余状态（发送中、
    // 排队、等待审批等）不提供入口，避免与进行中的流程互相干扰。
    !["failed", "completed"].includes(message.status) ||
    retryingMessageIds.value.has(message.id)
  )
    return;
  let userMessage = thread.messages.find(
    (item) => item.id === message.replyToId,
  );
  if (!userMessage) {
    ElMessage.error("找不到这次失败请求对应的用户消息，无法重试");
    return;
  }

  const answerRetry = message.taskIds.length > 0;
  const retryMessageId = message.id;
  retryingMessageIds.value = new Set(retryingMessageIds.value).add(message.id);
  if (thread) activeSendingThreadIds.value.add(thread.id);
  sending.value = true;
  try {
    if (!answerRetry) {
      const scope = await auditScopeForMessage(messageReferences(userMessage), thread.targetId,
        projectIdForTarget(thread.targetId, thread));
      if (scope && (thread.targetId !== scope.target.id || thread.projectId !== scope.projectId)) {
        thread = conversations.createThread(scope.target.id, scope.target.name, userMessage.content, scope.projectId,
          { threadId: thread.id, messageId: userMessage.id });
        const turn = conversations.appendTurn(thread.id, {
          role: "user", content: userMessage.content, status: "completed", taskIds: [], steps: [],
          references: cloneMessageDraft(messageReferences(userMessage)), copilotMode: userMessage.copilotMode,
          quote: cloneMessageDraft(userMessage.quote),
          executionIntent: userMessage.executionIntent, executionRequested: userMessage.executionRequested,
        }, {
          role: "assistant", content: "正在重新核查审计记录。", status: "planning", taskIds: [], steps: [],
          executionIntent: userMessage.executionIntent,
        })!;
        userMessage = turn.userMessage;
        message = turn.assistantMessage;
        selectedTargetId.value = scope.target.id;
        await router.replace({ path: "/", query: { conversation: thread.id } });
      }
    }
    if (answerRetry) {
      conversations.updateMessage(thread.id, message.id, {
        content: "正在根据已关联任务重新生成回复。",
        status: "answering",
      });
      const requestPrompt = buildContextPrompt(thread, userMessage.id);
      const { data } = await endpoints.answerAi({
        projectId: projectIdForTarget(thread.targetId, thread),
        targetId: thread.targetId,
        prompt: requestPrompt,
        taskIds: message.taskIds,
      });
      const answer = requireAiAnswer(data.answer, data.summary);
      conversations.updateMessage(thread.id, message.id, {
        content: answer,
        status: "completed",
        modelStreamStatus: "completed",
        provider: data.provider,
        taskIds: data.taskIds || message.taskIds,
        citations: data.citations || message.citations,
      });
    } else {
      conversations.updateMessage(thread.id, message.id, {
        content: "正在重新理解你的要求，并根据授权范围生成执行计划。",
        status: "planning",
        taskIds: [],
        steps: [],
        thinking: [],
        agentEvents: [],
        progressStartedAt: new Date().toISOString(),
        citations: [],
        planningStage: "status",
        planningStatus: "正在核对授权范围",
      });
      await dispatchConversationMessage(thread, userMessage, message);
    }
    ElMessage.success("重试成功");
  } catch (error: any) {
    if (error instanceof ConversationStorageError) {
      ElMessage.error(error.message);
      return;
    }
    const errorMessage = readableConversationError(error);
    conversations.updateMessage(thread.id, message.id, {
      content: errorMessage,
      status: "failed",
      modelStreamStatus: "failed",
    });
  } finally {
    const next = new Set(retryingMessageIds.value);
    next.delete(retryMessageId);
    retryingMessageIds.value = next;
    if (thread) activeSendingThreadIds.value.delete(thread.id);
    sending.value = false;
    void scrollToBottom();
  }
}

function handlePromptKeydown(event: KeyboardEvent) {
  if (event.isComposing || event.keyCode === 229) return;
  if (event.key === "Escape" && editingMessage.value && !event.isComposing) {
    event.preventDefault();
    cancelMessageEdit();
    return;
  }
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    void sendPrompt();
  }
}

async function requestFinalAnswer(
  thread: ConversationThread,
  message: ConversationMessage,
) {
  const key = `${thread.id}:${message.id}`;
  if (answeringMessages.has(key)) return;
  answeringMessages.add(key);
  conversations.updateMessage(thread.id, message.id, { status: "answering", modelStreamStatus: "running", progressFinishedAt: undefined });
  try {
    const userMessage = thread.messages.find(
      (item) => item.id === message.replyToId,
    );
    const requestPrompt = userMessage
      ? buildContextPrompt(thread, userMessage.id)
      : thread.title;
    const { data } = await endpoints.answerAi({
      projectId: projectIdForTarget(thread.targetId, thread),
      targetId: thread.targetId,
      prompt: requestPrompt,
      taskIds: message.taskIds,
    });
    const answer = requireAiAnswer(data.answer, data.summary);
    conversations.updateMessage(thread.id, message.id, { status: "completed", modelStreamStatus: "completed", progressFinishedAt: new Date().toISOString() });
    conversations.appendMessage(thread.id, {
      role: "assistant",
      content: answer,
      status: "completed",
      provider: data.provider,
      taskIds: data.taskIds || message.taskIds,
      steps: [],
      citations: data.citations,
      replyToId: message.replyToId,
    }, { keepInMemoryOnFailure: true });
  } catch (error: any) {
    conversations.updateMessage(thread.id, message.id, { status: "completed", modelStreamStatus: "failed", progressFinishedAt: new Date().toISOString() });
    const summaryError = readableAiConversationError(
      error,
      "暂时无法生成汇总回答。你可以继续追问，或前往“安全发现”查看详细结果。",
    );
    conversations.appendMessage(thread.id, {
      role: "assistant",
      content: `任务已经结束，但生成检测结论时出现问题：${summaryError}`,
      status: "failed",
      taskIds: message.taskIds,
      steps: [],
      replyToId: message.replyToId,
    }, { keepInMemoryOnFailure: true });
  } finally {
    answeringMessages.delete(key);
    void scrollToBottom();
  }
}

function reconcileTaskMessages() {
  for (const thread of conversations.items) {
    for (const message of thread.messages) {
      if (message.role !== "assistant" || !["running", "answering"].includes(message.status))
        continue;
      // 无关联任务的一轮（例如模型只产出了待确认的计划、尚未派发任务）：
      // 这一轮没有可汇总的任务，POST /api/ai/answers 明确要求 taskIds 非空，
      // 因此不能走 requestFinalAnswer。模型正文已经在终态事件里到达并写入 content，
      // 这里只需就地收尾，避免界面永久停留在「尚未收到阶段反馈」。
      if (!message.taskIds.length) {
        if (message.modelStreamStatus !== "completed") continue;
        conversations.updateMessage(thread.id, message.id, {
          status: "completed",
          progressFinishedAt:
            message.progressFinishedAt || new Date().toISOString(),
        });
        continue;
      }
      const related = relatedTasks(message);
      if (
        related.length === message.taskIds.length &&
        related.every((item) => TERMINAL_STATUSES.has(item.status))
      ) {
        void requestFinalAnswer(thread, message);
      }
    }
  }
}

function applyTaskEvent(event: TaskProgressEvent) {
  if (!Number(event.taskId)) return;
  const task = tasks.value.find((item) => item.id === Number(event.taskId));
  if (!task) {
    void loadTasks();
    return;
  }
  Object.assign(task, {
    status: event.status || task.status,
    progress: event.progress ?? task.progress,
    progressDeterminate: event.progressDeterminate ?? task.progressDeterminate,
    progressCompleted: event.progressCompleted ?? task.progressCompleted,
    progressTotal: event.progressTotal ?? task.progressTotal,
    progressMessage: event.progressMessage || task.progressMessage,
    errorMessage: event.errorMessage || task.errorMessage,
    startedAt: event.startedAt || task.startedAt,
    finishedAt: event.finishedAt || task.finishedAt,
  });
  if (event.logLine) {
    const timestamp = formatDateTime(
      event.emittedAt || new Date().toISOString(),
    );
    task.executionLog = `${task.executionLog ? `${task.executionLog}\n` : ""}${timestamp}  ${event.logLine}`;
  }
  reconcileTaskMessages();
  if (event.status && TERMINAL_STATUSES.has(event.status))
    void loadDashboardStats();
}

async function loadTasks() {
  const result = await safeGet<ProjectTaskRecord[]>(endpoints.tasks, []);
  tasks.value = Array.isArray(result.data)
    ? result.data.map((task) => ({
        id: task.id,
        targetId: task.targetId,
        toolCode: task.toolCode,
        status: task.status,
        progress: task.progress ?? (task.status === "SUCCESS" ? 100 : 0),
        progressDeterminate: task.progressDeterminate,
        progressCompleted: task.progressCompleted,
        progressTotal: task.progressTotal,
        progressMessage: task.progressMessage,
        executionLog: task.executionLog,
        errorMessage: task.errorMessage,
        startedAt: task.startedAt,
        finishedAt: task.finishedAt,
        createdAt: task.createdAt,
      }))
    : [];
  taskbarProgress.syncTasks(tasks.value);
  conversations.setTaskStates(
    tasks.value.map((task) => ({
      id: task.id,
      toolCode: task.toolCode,
      status: task.status,
      progressMessage: task.progressMessage,
      errorMessage: task.errorMessage,
      startedAt: task.startedAt,
      finishedAt: task.finishedAt,
      createdAt: task.createdAt,
    })),
  );
  if (!result.offline) reconcileTaskMessages();
}

async function loadProjectScopes() {
  const projectResult = await safeGet<AssessmentProject[]>(
    endpoints.projects,
    [],
  );
  const activeProjects = (
    Array.isArray(projectResult.data) ? projectResult.data : []
  ).filter((project) => project.status === "ACTIVE");
  const memberships = await Promise.all(
    activeProjects.map(async (project) => ({
      projectId: project.id,
      result: await safeGet<ProjectTarget[]>(
        () => endpoints.projectTargets(project.id),
        [],
      ),
    })),
  );
  const mapping: Record<number, number> = {};
  for (const membership of memberships) {
    for (const item of membership.result.data || [])
      if (!mapping[item.targetId])
        mapping[item.targetId] = membership.projectId;
  }
  projectByTarget.value = mapping;
}

async function refreshStatus() {
  await Promise.all([engine.check(), loadTasks()]);
}

async function load() {
  loading.value = true;
  const [targetResult] = await Promise.all([
    safeGet<Target[]>(endpoints.targets, []),
    loadTasks(),
    loadProjectScopes(),
  ]);
  targets.value = Array.isArray(targetResult.data) ? targetResult.data : [];
  const threadTarget = selectedThread.value?.targetId;
  const savedTarget = Number(
    localStorage.getItem("security_toolbox_dashboard_target"),
  );
  const preferred =
    enabledTargets.value.find((item) => item.id === threadTarget) ||
    enabledTargets.value.find((item) => item.id === savedTarget) ||
    enabledTargets.value[0];
  selectedTargetId.value = preferred?.id;
  const copilotDraft = copilot.consume();
  if (copilotDraft) {
    activeDraft.value = copilotDraft;
    if (
      copilotDraft.targetId &&
      enabledTargets.value.some((item) => item.id === copilotDraft.targetId)
    ) {
      selectedTargetId.value = copilotDraft.targetId;
    }
    if (!prompt.value) prompt.value = copilotDraft.prompt.slice(0, 4000);
    try {
      const scope = await auditScopeForMessage(copilotDraft.refs, selectedTargetId.value,
        selectedTargetId.value ? projectIdForTarget(selectedTargetId.value) : undefined);
      if (scope) selectedTargetId.value = scope.target.id;
    } catch (error) {
      selectedTargetId.value = undefined;
      ElMessage.warning(readableConversationError(error));
    }
  }
  const draft =
    typeof route.query.draft === "string" ? route.query.draft.trim() : "";
  if (draft && selectedThread.value && !prompt.value) {
    prompt.value = draft.slice(0, 1000);
    await router.replace({
      path: "/",
      query: { conversation: selectedThread.value.id },
    });
  }
  loading.value = false;
  void scrollToBottom();
  focusComposer();
}

function acknowledgeThreadCompletion(thread: ConversationThread | undefined) {
  const lastAssistant = [...(thread?.messages || [])]
    .reverse()
    .find((message) => message.role === "assistant");
  if (!thread || !lastAssistant || lastAssistant.status !== "completed" || lastAssistant.completionSeen) return;
  conversations.updateMessage(thread.id, lastAssistant.id, { completionSeen: true });
}

function startNewConversation() {
  acknowledgeThreadCompletion(selectedThread.value);
  editingMessage.value = undefined;
  prompt.value = "";
  activeDraft.value = undefined;
  clearQuotedMessage();
  void router.replace("/").then(() => focusComposer());
}

async function removeCurrentConversation() {
  const thread = selectedThread.value;
  if (!thread) return;
  try {
    await ElMessageBox.confirm(
      "删除这段本机对话记录？已经创建的检测任务不会被删除。",
      "删除对话",
      {
        confirmButtonText: "删除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  try {
    await endpoints.clearAgentSession(thread.id);
    conversations.remove(thread.id);
    await router.replace("/");
    ElMessage.success("对话已删除");
  } catch (error) {
    ElMessage.error(readableAiConversationError(error, "删除对话失败，请稍后重试"));
  }
}

async function stopContinuation() {
  const thread = selectedThread.value;
  if (!thread) return;
  try {
    const result = await endpoints.stopAgentContinuation(thread.id);
    const cancelled = result?.data?.cancelled ?? 0;
    // Already-dispatched work is untouched, so never imply the whole run was cancelled.
    ElMessage.success(
      cancelled > 0
        ? `已停止自动续接，取消了 ${cancelled} 项尚未执行的续接`
        : "当前没有待执行的自动续接",
    );
  } catch (error) {
    ElMessage.error(readableAiConversationError(error, "停止自动续接失败，请稍后重试"));
  }
}

async function clearConversations() {  if (!conversations.items.length) return;
  try {
    await ElMessageBox.confirm(
      "将清空本机保存的全部对话，已经创建的检测任务不会被删除。",
      "清空全部对话",
      {
        confirmButtonText: "全部删除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  try {
    await Promise.all(
      conversations.items.map((thread) =>
        endpoints.clearAgentSession(thread.id),
      ),
    );
    conversations.clear();
    await router.replace("/");
    ElMessage.success("全部对话已清空");
  } catch (error) {
    ElMessage.error(readableAiConversationError(error, "清空对话失败，请稍后重试"));
  }
}

watch(selectedThread, (thread) => {
  if (thread) {
    acknowledgeThreadCompletion(thread);
    for (const msg of thread.messages) {
      if (msg.role === "assistant" && typedMessageContent.value[msg.id] === undefined) {
        typedMessageContent.value[msg.id] = displayedMessageContent(msg);
      }
    }
  }
  if (editingMessage.value && thread?.id !== editingMessage.value.threadId) cancelMessageEdit();
  clearQuotedMessage();
  if (
    thread &&
    enabledTargets.value.some((item) => item.id === thread.targetId)
  )
    selectedTargetId.value = thread.targetId;
  void scrollToBottom();
  focusComposer();
});

watch(selectedTargetId, (value) => {
  if (value)
    localStorage.setItem("security_toolbox_dashboard_target", String(value));
});

watch(
  () => selectedThread.value?.messages.map((m) => `${m.id}:${m.content.length}:${m.status}`).join(","),
  () => {
    startTypewriterLoop();
    void scrollToBottom();
  },
  { immediate: true },
);

const dashboardStats = ref<{
  targets: number;
  running: number;
  findings: number;
  critical: number;
}>();
async function loadDashboardStats() {
  const { data } = await safeGet(endpoints.dashboard, {
    targets: 0,
    running: 0,
    findings: 0,
    critical: 0,
  });
  dashboardStats.value = data as {
    targets: number;
    running: number;
    findings: number;
    critical: number;
  };
}
// Switching conversations must re-read that thread's pending state, otherwise the
// card would show the previous thread's waiting tasks until the next poll tick.
watch(() => selectedThread.value?.id, () => { void refreshAwaitingStatus(); });

onMounted(() => {
  for (const thread of conversations.items) {
    for (const msg of thread.messages) {
      historicalMessageIds.add(msg.id);
    }
  }
  stopTaskFeed = connectTaskEventFeed(applyTaskEvent);
  pollTimer = setInterval(() => void loadTasks(), 10_000);
  // Keep the "what are we waiting for" description fresh. Runs at the same low
  // rate as the task poll; the thread query above limits it to the visible thread.
  awaitingPollTimer = setInterval(() => void refreshAwaitingStatus(), 10_000);
  void refreshAwaitingStatus();
  focusComposer();
  void load();
  void loadDashboardStats();
  document.addEventListener("pointerdown", handleDocumentPointerDown, true);
  document.addEventListener("keydown", handleDocumentKeydown);
});
onBeforeUnmount(() => {
  if (pollTimer) clearInterval(pollTimer);
  if (awaitingPollTimer) clearInterval(awaitingPollTimer);
  if (typewriterInterval) clearInterval(typewriterInterval);
  if (turnHighlightTimer) clearTimeout(turnHighlightTimer);
  stopTaskFeed?.();
  document.removeEventListener("pointerdown", handleDocumentPointerDown, true);
  document.removeEventListener("keydown", handleDocumentKeydown);
});
</script>

<template>
  <div class="chat-page" :class="{ 'has-thread': isConversation }">
    <header class="chat-header">
      <div>
        <strong>{{ displayConversationTitle(selectedThread) || "安全助手" }}</strong>
        <span
          v-if="selectedThread"
          :title="targetHoverText(selectedThread.targetName)"
          >{{ displayKnownTestName(selectedThread.targetName) }} · 连续对话
          <span
            v-if="currentThreadStatus"
            class="dashboard-thread-status"
            :class="`status--${currentThreadStatus.type}`"
          >
            <span v-if="currentThreadStatus.type === 'running'" class="status-dot-pulse" />
            {{ currentThreadStatus.label }}
          </span>
        </span>
        <span v-else
          ><i :class="{ offline, checking: engine.status === 'checking' }" />{{
            engine.status === "checking"
              ? "正在检查本地引擎"
              : offline
                ? "本地引擎暂不可用"
                : "本地引擎已就绪"
          }}</span
        >
      </div>
      <div class="chat-header-actions">
        <el-tooltip
          content="刷新引擎与任务状态"
          placement="bottom"
          :show-after="350"
          ><button
            class="header-icon-button"
            type="button"
            aria-label="刷新引擎与任务状态"
            :disabled="loading"
            @click="refreshStatus"
          >
            <el-icon :class="{ rotating: loading }"
              ><Refresh
            /></el-icon></button
        ></el-tooltip>
        <el-tooltip
          v-if="selectedThread"
          content="停止本会话的自动续接（已完成的任务不受影响）"
          placement="bottom"
          :show-after="350"
          ><button
            class="header-icon-button"
            type="button"
            aria-label="停止自动续接"
            @click="stopContinuation"
          >
            <el-icon><VideoPause /></el-icon></button
        ></el-tooltip>
        <button type="button" @click="startNewConversation">
          <el-icon><Plus /></el-icon>新对话
        </button>        <button
          v-if="selectedThread"
          type="button"
          class="danger"
          @click="removeCurrentConversation"
        >
          <el-icon><Delete /></el-icon>删除
        </button>
        <button
          v-else-if="conversations.items.length"
          type="button"
          class="danger"
          @click="clearConversations"
        >
          清空对话
        </button>
      </div>
    </header>

    <div v-if="conversations.persistenceError" class="conversation-storage-notice" role="alert">
      <p>{{ conversations.persistenceError.message }}</p>
      <button v-if="conversations.hasUnsavedChanges" type="button" @click="conversations.retryPersist()">重试保存</button>
    </div>

    <section v-if="!selectedThread" class="chat-welcome">
      <div class="welcome-mark" aria-hidden="true">
        <el-icon><ChatDotRound /></el-icon>
      </div>
      <h1>告诉我你想检查什么</h1>
      <p>
        我会先理解要求，再自动派发授权范围内的任务；执行结束后，会在同一段对话里回复检测结论。
      </p>

      <div
        v-if="dashboardStats"
        class="welcome-stats"
        role="group"
        aria-label="工作区实时概览"
      >
        <button
          type="button"
          class="welcome-stat welcome-stat--link"
          title="点击查看授权目标管理"
          @click="router.push('/targets')"
        >
          <strong>{{ dashboardStats.targets }}</strong
          ><small>授权目标</small>
        </button>
        <button
          type="button"
          class="welcome-stat welcome-stat--link"
          title="点击查看检测任务与实时进度"
          @click="router.push('/tasks')"
        >
          <strong>{{ dashboardStats.running }}</strong
          ><small>进行中任务</small>
        </button>
        <button
          type="button"
          class="welcome-stat welcome-stat--link"
          title="点击查看安全发现全部发现项"
          @click="router.push('/findings')"
        >
          <strong>{{ dashboardStats.findings }}</strong
          ><small>累计发现</small>
        </button>
        <button
          type="button"
          class="welcome-stat welcome-stat--link"
          :class="{ warn: dashboardStats.critical > 0 }"
          title="点击查看高危漏洞发现项"
          @click="router.push({ path: '/findings', query: { severity: 'HIGH' } })"
        >
          <strong>{{ dashboardStats.critical }}</strong
          ><small>高危发现</small>
        </button>
      </div>

      <div class="welcome-composer">
        <div v-if="composerReferences.length" class="copilot-draft-refs">
          <span
            v-for="reference in composerReferences"
            :key="`${reference.type}-${reference.id || reference.title || reference.label}`"
            >{{ displayKnownTestName(reference.title || reference.label) || copilotReferenceTypeLabel(reference.type) }}</span
          >
        </div>
        <textarea
          ref="composerInputRef"
          v-model="prompt"
          rows="4"
          :disabled="sending"
          placeholder="例如：检查目标的开放端口；如需先看方案，可以说“先给方案，不执行”"
          @keydown="handlePromptKeydown"
        />
        <MarkdownComposerPreview :content="prompt" />
        <div class="composer-footer">
          <div class="target-picker">
            <span>授权目标</span>
            <el-select
              v-if="enabledTargets.length"
              v-model="selectedTargetId"
              size="small"
              :disabled="sending || loading"
              placeholder="选择目标"
              popper-class="target-picker-popper"
              :title="targetHoverText(selectedTarget?.name, selectedTarget?.targetValue)"
            >
              <el-option
                v-for="target in enabledTargets"
                :key="target.id"
                :value="target.id"
                :label="displayKnownTestName(target.name)"
              >
                <div
                  class="target-option"
                  :title="targetHoverText(target.name, target.targetValue)"
                >
                  <span>{{ displayKnownTestName(target.name) }}</span
                  ><small>{{ target.targetValue }}</small>
                </div>
              </el-option>
            </el-select>
            <button
              v-else
              type="button"
              class="create-target"
              @click="router.push('/targets')"
            >
              <el-icon><Plus /></el-icon>新增授权目标
            </button>
          </div>
          <span class="composer-shortcut">Enter 发送，Shift + Enter 换行</span>
          <el-tooltip content="发送" placement="top" :show-after="350"
            ><button
              type="button"
              class="send-button"
              aria-label="发送"
              :disabled="sending || !prompt.trim() || !selectedTargetId"
              @click="sendPrompt"
            >
              <el-icon :class="{ rotating: sending }"
                ><Refresh v-if="sending" /><Promotion v-else
              /></el-icon></button
          ></el-tooltip>
        </div>
      </div>

      <div class="quick-actions">
        <button
          v-for="action in quickActions"
          :key="action.path"
          type="button"
          @click="router.push(action.path)"
        >
          <el-icon><component :is="action.icon" /></el-icon>
          <span
            ><strong>{{ action.label }}</strong
            ><small>{{ action.description }}</small></span
          >
        </button>
      </div>

    </section>

    <template v-else>
      <div class="chat-conversation-body">
        <section ref="messagesElement" class="chat-messages" @scroll.passive="updateActiveTurn">
          <div class="messages-inner">
            <article
              v-for="message in selectedThread.messages"
              :key="message.id"
              :data-message-id="message.id"
              class="chat-message"
              :class="[message.role, { 'is-turn-jump-highlight': highlightedTurnId === message.id }]"
            >
            <ConversationAvatar class="message-avatar" :role="message.role" />
            <div class="message-column">
              <div class="message-meta">
                <strong>{{
                  message.role === "assistant" ? "安全助手" : "你"
                }}</strong
                ><span>{{ formatTime(message.createdAt) }}</span>
                <span v-if="message.role === 'assistant' && ['completed', 'failed'].includes(message.status)" class="message-answer-source">{{ aiAnswerSource(message.provider, message.status === 'failed') }}</span>
              </div>
              <div v-if="message.quote" class="message-quote">
                <strong
                  >引用
                  {{
                    message.quote.role === "assistant" ? "安全助手" : "你"
                  }}</strong
                >
                <span>{{ quotePreview(message.quote.content) }}</span>
              </div>
              <div
                class="message-response"
                :class="{ 'is-failed': message.role === 'assistant' && message.status === 'failed' }"
              >
                <div
                  v-if="message.status === 'failed' && message.role === 'assistant'"
                  class="failed-response-card"
                >
                  <AiProgressPanel
                    :message="message"
                    :tasks="relatedTasks(message)"
                    :hide-attention="true"
                    :status-outside="isStatusOutsideAnswerCard(message)"
                    :awaiting="awaitingStatusForThread(selectedThread.id)"
                    @open-tasks="router.push('/tasks')"
                  >
                    <AiFailureNotice :message="message" />
                  </AiProgressPanel>
                </div>
                <AiProgressPanel
                  v-else-if="message.role === 'assistant'"
                  :message="message"
                  :tasks="relatedTasks(message)"
                  :status-outside="isStatusOutsideAnswerCard(message)"
                  :status-in-plan="hasDispatchNotice(message)"
                  :awaiting="awaitingStatusForThread(selectedThread.id)"
                  @open-tasks="router.push('/tasks')"
                >
                  <div
                    v-if="displayedContentForMessage(message)"
                    class="message-bubble markdown-body"
                  >
                    <div v-html="renderMarkdown(displayedContentForMessage(message), { localizeToolCodes: true })" />
                  </div>
                </AiProgressPanel>
                <div
                  v-else-if="message.role === 'user'"
                  class="message-bubble markdown-body"
                  v-html="renderMarkdown(message.content)"
                />
              <div
                v-if="
                  message.reference && isTrafficReference(message.reference)
                "
                class="traffic-reference-card"
              >
                <header>
                  <span
                    ><el-icon><Connection /></el-icon>流量会话 #{{
                      message.reference.packetId
                    }}</span
                  >
                  <code>{{ message.reference.method }}</code>
                </header>
                <strong>{{ message.reference.url }}</strong>
                <div class="traffic-reference-meta">
                  <span v-if="message.reference.statusCode"
                    >HTTP {{ message.reference.statusCode }}</span
                  >
                  <span v-if="message.reference.contentType">{{
                    message.reference.contentType
                  }}</span>
                  <span v-if="message.reference.durationMs"
                    >{{ message.reference.durationMs }} ms</span
                  >
                </div>
                <details>
                  <summary>查看引用报文</summary>
                  <div class="traffic-reference-packets">
                    <article>
                      <h4>请求头</h4>
                      <FluentCodeBlock class="reference-output" :content="formatReferenceValue(message.reference.requestHeaders)" aria-label="引用报文请求头" :min-rows="3" :max-rows="8" wrap />
                    </article>
                    <article>
                      <h4>请求体</h4>
                      <FluentCodeBlock class="reference-output" :content="formatReferenceValue(message.reference.requestBody)" aria-label="引用报文请求体" :min-rows="3" :max-rows="8" wrap />
                    </article>
                    <article>
                      <h4>响应头</h4>
                      <FluentCodeBlock class="reference-output" :content="formatReferenceValue(message.reference.responseHeaders)" aria-label="引用报文响应头" :min-rows="3" :max-rows="8" wrap />
                    </article>
                    <article>
                      <h4>响应体</h4>
                      <FluentCodeBlock class="reference-output" :content="formatReferenceValue(message.reference.responseBody)" aria-label="引用报文响应体" :min-rows="3" :max-rows="8" wrap />
                    </article>
                  </div>
                </details>
              </div>
              <div
                v-for="reference in genericReferences(message)"
                :key="`${message.id}-${reference.type}-${reference.id || reference.title || reference.label}`"
                class="copilot-reference-card"
              >
                <header>
                  <span>{{
                    displayKnownTestName(reference.title || reference.label) || copilotReferenceTypeLabel(reference.type)
                  }}</span
                  ><code>{{ copilotReferenceTypeLabel(reference.type) }}</code>
                </header>
                <strong v-if="reference.subtitle">{{
                  reference.subtitle
                }}</strong>
                <p v-if="reference.summary">{{ reference.summary }}</p>
                <details
                  v-if="reference.data && Object.keys(reference.data).length"
                >
                  <summary>查看引用详情</summary>
                  <FluentCodeBlock class="reference-output" :content="JSON.stringify(reference.data, null, 2)" aria-label="引用详情原始数据" :min-rows="4" :max-rows="10" wrap />
                </details>
              </div>
              <div
                v-if="
                  message.role === 'assistant' && agentCitations(message).length
                "
                class="agent-citation-bubbles"
                aria-label="参考资料"
              >
                <el-tooltip
                  v-for="(citation, citationIndex) in agentCitations(message)"
                  :key="
                    citation.id ||
                    citation.url ||
                    `${message.id}-citation-${citationIndex}`
                  "
                  :content="
                    citationBubbleHint(citation) ||
                    citationBubbleLabel(citation, citationIndex)
                  "
                  placement="top"
                  :show-after="250"
                >
                  <a
                    v-if="safeCitationUrl(citation)"
                    class="agent-citation-bubble"
                    :href="safeCitationUrl(citation)"
                    target="_blank"
                    rel="noopener noreferrer"
                    >{{ citationBubbleLabel(citation, citationIndex) }}</a
                  >
                  <span v-else class="agent-citation-bubble">{{
                    citationBubbleLabel(citation, citationIndex)
                  }}</span>
                </el-tooltip>
              </div>
              <details
                v-if="
                  message.role === 'assistant' &&
                  message.steps.length
                "
                class="execution-plan-card"
                :class="{ 'is-awaiting-approval': isAwaitingAiApproval(message), 'has-dispatch-notice': hasDispatchNotice(message) }"
                :open="isAwaitingAiApproval(message) || isAwaitingAiDispatch(message) || isAiDispatchRejected(message)"
              >
                <!-- Fluent 2 card: the disclosure row is the card's only header.
                     Everything below it is one section, never a nested banner. -->
                <summary class="execution-plan-disclosure">
                  <span class="execution-plan-disclosure-text">
                    <FluentIcon name="chevron-right" class="execution-plan-chevron" aria-hidden="true" />
                    <span>执行计划</span>
                    <span class="execution-plan-count">{{ message.steps.length }} 项</span>
                  </span>
                  <span class="execution-plan-state" :class="taskState(message).className">{{ hasDispatchNotice(message) ? isAiDispatchRejected(message) ? '未派发' : '待确认' : taskState(message).label }}</span>
                </summary>

                <!-- One decision surface for the approval gate. It states the
                     state once, lists the plan, and carries the actions, so no
                     separate banner repeats the header or the progress line. -->
                <div
                  v-if="
                    message.steps.length &&
                    !message.taskIds.length &&
                    (message.approvalStatus === 'REQUIRED' || message.approvalStatus === 'PENDING')
                  "
                  class="plan-approval"
                >
                  <div class="plan-approval-head">
                    <FluentIcon name="warning" class="plan-approval-icon" aria-hidden="true" />
                    <div class="plan-approval-copy">
                      <strong>等待管理员确认后执行</strong>
                      <p>已生成 {{ message.steps.length }} 步计划，确认后才会创建检测任务。</p>
                    </div>
                  </div>
                  <div class="plan-approval-actions">
                    <el-button
                      size="default"
                      :disabled="sending || approvingMessageId !== null"
                      @click="reopenApproval(message)"
                      >查看方案详情</el-button
                    >
                    <el-button
                      type="success"
                      size="default"
                      :loading="approvingMessageId === message.id"
                      :disabled="sending || approvingMessageId !== null"
                      @click="handleAgentApprovalDecision(message, 'APPROVED')"
                    >
                      <el-icon><CircleCheck /></el-icon>
                      确认并执行
                    </el-button>
                    <el-button
                      type="danger"
                      plain
                      size="default"
                      :disabled="sending || approvingMessageId !== null"
                      @click="handleAgentApprovalDecision(message, 'REJECTED')"
                    >
                      驳回方案
                    </el-button>
                  </div>
                </div>

                <AiDispatchNotice
                  v-if="hasDispatchNotice(message)"
                  :message="message"
                  :disabled="sending || approvingMessageId !== null"
                  :loading="approvingMessageId === message.id"
                  @open-tasks="router.push('/tasks')"
                  @resume="handleAgentApprovalDecision(message, 'APPROVED')"
                  @adjust-plan="adjustDispatchPlan(message)"
                />

                <ol v-if="message.steps.length" class="execution-plan-list">
                  <li
                    v-for="(step, index) in message.steps"
                    :key="`${message.id}-${step.taskId || step.toolCode}-${index}`"
                    :class="planStepState(message, index).state"
                  >
                    <!-- Fluent list-row: a leading 20px state icon, then the
                         title + supporting copy, then the trailing status. -->
                    <span class="plan-step-icon" aria-hidden="true">
                      <FluentIcon
                        v-if="planStepState(message, index).state === 'success'"
                        name="checkmark-circle"
                      />
                      <FluentIcon
                        v-else-if="planStepState(message, index).state === 'failed'"
                        name="dismiss"
                      />
                      <FluentIcon v-else-if="planStepState(message, index).state === 'running'" name="clock" />
                      <span v-else class="plan-step-index">{{ index + 1 }}</span>
                    </span>
                    <div>
                      <strong>{{ displayedStepTitle(step) }}</strong
                      ><small v-if="displayedStepReason(step)">{{ displayedStepReason(step) }}</small
                      ><el-progress
                        v-if="planStepState(message, index).state === 'running'"
                        :percentage="planStepState(message, index).progress"
                        :stroke-width="3"
                        :show-text="false"
                        :indeterminate="
                          planStepState(message, index).indeterminate
                        "
                        :duration="1.2"
                      />
                    </div>
                    <span v-if="!hasDispatchNotice(message)" class="plan-step-status">{{
                      planStepState(message, index).label
                    }}</span>
                  </li>
                </ol>
                <footer v-if="message.taskIds.length" class="execution-plan-footer">
                  <span>{{ planTaskSummary(message) }}</span>
                  <button type="button" class="execution-plan-link" @click="router.push('/tasks')">
                    查看任务
                  </button>
                </footer>
                <details
                  v-if="taskLogs(message)"
                  class="plan-runtime-details"
                >
                  <summary>查看详细执行日志</summary>
                  <FluentCodeBlock class="runtime-output" :content="taskLogs(message)" aria-label="AI 任务详细执行日志" :min-rows="3" :max-rows="8" wrap live />
                </details>
              </details>
              </div>
              <AiStatusStamp
                v-if="isStatusOutsideAnswerCard(message)"
                class="message-status"
                :message="message"
                :tasks="relatedTasks(message)"
                :awaiting="awaitingStatusForThread(selectedThread.id)"
              />
              <div class="message-actions" role="toolbar" aria-label="消息操作">
                <el-tooltip content="引用消息" placement="top" :show-after="350">
                  <button type="button" class="message-action" aria-label="引用消息" :disabled="sending" @click="quoteMessage(message)">
                    <span class="message-quote-icon" :style="messageQuoteStyle" aria-hidden="true" />
                  </button>
                </el-tooltip>
                <el-dropdown trigger="click" placement="bottom-start" :disabled="!message.content" @command="copyMessage(message, $event)">
                  <button type="button" class="message-action" :class="{ 'is-copied': copiedMessageId === message.id }" :title="copiedMessageId === message.id ? '已复制，可选择格式再次复制' : '选择复制格式'" aria-label="选择复制格式" :disabled="!message.content">
                    <el-icon aria-hidden="true"><CircleCheck v-if="copiedMessageId === message.id" /><CopyDocument v-else /></el-icon>
                  </button>
                  <template #dropdown>
                    <el-dropdown-menu>
                      <el-dropdown-item command="markdown">复制 Markdown</el-dropdown-item>
                      <el-dropdown-item command="plain">复制无格式文本</el-dropdown-item>
                    </el-dropdown-menu>
                  </template>
                </el-dropdown>
                <template v-if="message.role === 'assistant' && ['failed', 'completed'].includes(message.status)">
                  <el-tooltip :content="message.taskIds.length ? '重新生成回复' : message.status === 'failed' ? '重试回复' : '重新生成回复'" placement="top" :show-after="350">
                    <button type="button" class="message-action" :aria-label="message.taskIds.length ? '重新生成回复' : message.status === 'failed' ? '重试回复' : '重新生成回复'" :disabled="sending || retryingMessageIds.has(message.id)" @click="retryConversationMessage(message)">
                      <FluentIcon name="arrow-clockwise" aria-hidden="true" />
                    </button>
                  </el-tooltip>
                  <el-tooltip v-if="message.status === 'failed'" content="配置诊断" placement="top" :show-after="350">
                    <button type="button" class="message-action" aria-label="配置诊断" :disabled="sending || retryingMessageIds.has(message.id)" @click="openAiDiagnostics">
                      <FluentIcon name="settings" aria-hidden="true" />
                    </button>
                  </el-tooltip>
                </template>
                <el-tooltip v-if="message.role === 'user'" content="编辑消息" placement="top" :show-after="350">
                  <button type="button" class="message-action" aria-label="编辑消息" :disabled="sending" @click="editMessage(message)">
                    <el-icon aria-hidden="true"><EditPen /></el-icon>
                  </button>
                </el-tooltip>
              </div>
            </div>
          </article>
          <div v-if="!selectedThread.messages.length" class="thread-empty">
            开始描述任务，我会在这里持续回复。
          </div>
        </div>
      </section>

      <!-- 对话轮次快速导航条（DSH 风格右侧小横条）
           整个导航条只用一个受控 tooltip 实例：卡片内容跟着 hoveredTurn 切换，
           相邻横条的鼠标划过不可能产生两张卡片并存（每个横条各挂一个实例时，
           前一个实例的隐藏与后一个实例的显示是两个互不相干的计时器）。 -->
      <nav
        v-if="userTurns.length > 1"
        class="turn-rail"
        aria-label="对话轮次快速导航"
        @mouseleave="clearTurnTooltip"
      >
        <div class="turn-rail-track">
          <button
            v-for="turn in userTurns"
            :key="turn.id"
            type="button"
            class="turn-rail-mark"
            :class="{
              'is-active': activeTurnId === turn.id,
              'is-target': highlightedTurnId === turn.id,
            }"
            :aria-label="`跳转到第 ${turn.turn} 轮提问: ${turn.preview}`"
            :aria-describedby="hoveredTurn?.id === turn.id ? 'turn-rail-tooltip' : undefined"
            @mouseenter="showTurnTooltip($event, turn)"
            @focus="showTurnTooltip($event, turn)"
            @blur="clearTurnTooltip"
            @click="jumpToTurn(turn.id)"
          >
            <span class="turn-rail-bar" />
          </button>
        </div>
        <!-- virtual-triggering 模式下默认插槽不会渲染，锚点由 turnTooltipAnchor
             直接指向被悬停的横条按钮，卡片就贴在真实触发元素上。 -->
        <el-tooltip
          :visible="turnTooltipVisible"
          placement="left"
          :show-after="0"
          :hide-after="0"
          :enterable="false"
          :offset="10"
          popper-class="turn-rail-tooltip"
          virtual-triggering
          :virtual-ref="turnTooltipAnchor ?? undefined"
        >
          <template #content>
            <div v-if="hoveredTurn" class="turn-tooltip-content">
              <div class="turn-tooltip-header">
                <strong>第 {{ hoveredTurn.turn }} 轮提问</strong>
                <span v-if="hoveredTurn.timeText">{{ hoveredTurn.timeText }}</span>
              </div>
              <div class="turn-tooltip-body">{{ hoveredTurn.preview }}</div>
              <div class="turn-tooltip-tip">点击快速跳转</div>
            </div>
          </template>
        </el-tooltip>
      </nav>
    </div>

    <footer class="chat-composer-wrap">
        <div class="thread-target">
          <span>当前授权目标</span
          ><strong
            :title="targetHoverText(selectedThread.targetName)"
            >{{ displayKnownTestName(selectedThread.targetName) }}</strong
          ><small>如需更换目标，请新建对话</small>
        </div>
        <div class="thread-composer">
          <div v-if="editingMessage" class="composer-edit-notice" role="status">
            <el-icon aria-hidden="true"><EditPen /></el-icon>
            <span><strong>编辑消息</strong><span class="composer-edit-help">发送后新建分支，原对话及后续消息保留。</span></span>
            <el-tooltip content="取消编辑（Esc）" placement="top" :show-after="350"><button type="button" :disabled="sending" aria-label="取消编辑" @click="cancelMessageEdit"><el-icon aria-hidden="true"><Dismiss /></el-icon></button></el-tooltip>
          </div>
          <div v-if="quotedMessage" class="composer-quote">
            <span
              ><strong
                >引用
                {{
                  quotedMessage.role === "assistant" ? "安全助手" : "你"
                }}</strong
              >{{ quotePreview(quotedMessage.content) }}</span
            >
            <el-tooltip content="取消引用" placement="top" :show-after="350"
              ><button
                type="button"
                aria-label="取消引用"
                @click="clearQuotedMessage"
              >
                <el-icon><Dismiss /></el-icon></button
            ></el-tooltip>
          </div>
          <div v-if="composerReferences.length" class="copilot-draft-refs">
            <span
              v-for="reference in composerReferences"
              :key="`${reference.type}-${reference.id || reference.title || reference.label}`"
              >{{ displayKnownTestName(reference.title || reference.label) || copilotReferenceTypeLabel(reference.type) }}</span
            >
          </div>
          <textarea
            ref="composerInputRef"
            v-model="prompt"
            rows="2"
            :disabled="sending"
            placeholder="继续提问或说明下一步；只需方案时，请说“先给方案，不执行”"
            @keydown="handlePromptKeydown"
          />
          <MarkdownComposerPreview :content="prompt" />
          <div class="thread-composer-footer">
            <span class="composer-shortcut">Enter 发送，Shift + Enter 换行</span>
            <el-tooltip :content="editingMessage ? '发送编辑并新建分支' : '发送'" placement="top" :show-after="350"
              ><button
                type="button"
                class="send-button"
                :aria-label="editingMessage ? '发送编辑并新建分支' : '发送'"
                :disabled="sending || !prompt.trim()"
                @click="sendPrompt"
              >
                <el-icon :class="{ rotating: sending }"
                  ><Refresh v-if="sending" /><Promotion v-else
                /></el-icon></button
            ></el-tooltip>
          </div>
        </div>
        <span class="composer-hint"
          >仅调用白名单工具，并严格遵守该目标的授权范围</span
        >

        <!-- 会话性能与用量统计底栏（DSH 同款设计） -->
        <!-- trigger="manual" + 胶囊 click 切换：三张卡片共用 openStatsCard，保证互斥
             展开，卡片向上弹出盖住相邻胶囊时也不会两张同时保留。 -->
        <div v-if="sessionStats" class="composer-stats-bar" aria-label="会话性能与用量统计" @pointerdown="handleStatsBarPointerDown">
          <!-- 1. 轮次、步数与输出速度 -->
          <el-popover
            :visible="statsCardVisible('session')"
            placement="top"
            :width="260"
            trigger="manual"
            popper-class="stats-pill-popover"
          >
            <template #reference>
              <button
                type="button"
                class="stats-pill"
                :aria-pressed="statsCardVisible('session') ? 'true' : 'false'"
                :aria-label="`${sessionStats.turns} 轮 ${sessionStats.steps} 步${sessionStats.tps > 0 ? ` · ${sessionStats.tps} tok/s` : ''}`"
                @click="toggleStatsCardOnPillClick('session')"
              >
                <span class="pill-icon pill-icon--gauge" :style="gaugeIconStyle" aria-hidden="true" />
                <span>{{ sessionStats.turns }} 轮 {{ sessionStats.steps }} 步</span>
                <template v-if="sessionStats.tps > 0">
                  <span class="pill-sep" aria-hidden="true">·</span>
                  <span>{{ sessionStats.tps }} tok/s</span>
                </template>
              </button>
            </template>
            <div class="stats-popover-content">
              <div class="stats-popover-title">
                <div class="stats-popover-title-left">
                  <span class="pill-icon pill-icon--gauge" :style="gaugeIconStyle" aria-hidden="true" />
                  <strong>会话统计</strong>
                </div>
              </div>
              <div class="stats-popover-divider" />
              <dl class="stats-popover-details">
                <dt>对话轮数</dt>
                <dd>{{ sessionStats.turns }} 轮</dd>
                <dt>工作步骤</dt>
                <dd>{{ sessionStats.steps }} 步</dd>
                <dt v-if="sessionStats.llmMs > 0">模型用时</dt>
                <dd v-if="sessionStats.llmMs > 0">{{ formatDurationCompact(sessionStats.llmMs) }}</dd>
                <dt v-if="sessionStats.toolMs > 0">工具用时</dt>
                <dd v-if="sessionStats.toolMs > 0">{{ formatDurationCompact(sessionStats.toolMs) }}</dd>
                <dt v-if="sessionStats.tps > 0">输出速度（TPS）</dt>
                <dd v-if="sessionStats.tps > 0">{{ sessionStats.tps }} tok/s</dd>
              </dl>
            </div>
          </el-popover>

          <!-- 2. Token 用量与缓存命中率 -->
          <el-popover
            v-if="sessionStats.totalTokens > 0"
            :visible="statsCardVisible('tokens')"
            placement="top"
            :width="260"
            trigger="manual"
            popper-class="stats-pill-popover"
          >
            <template #reference>
              <button
                type="button"
                class="stats-pill"
                :aria-pressed="statsCardVisible('tokens') ? 'true' : 'false'"
                :aria-label="`Token 用量: ${formatTokensCompact(sessionStats.totalTokens)}`"
                @click="toggleStatsCardOnPillClick('tokens')"
              >
                <span class="pill-icon pill-icon--database" :style="databaseIconStyle" aria-hidden="true" />
                <span>{{ formatTokensCompact(sessionStats.totalTokens) }}</span>
                <template v-if="sessionStats.cacheHitRate !== null">
                  <span class="pill-sep" aria-hidden="true">·</span>
                  <span>缓存命中 {{ sessionStats.cacheHitRate }}%</span>
                </template>
              </button>
            </template>
            <div class="stats-popover-content">
              <div class="stats-popover-title">
                <div class="stats-popover-title-left">
                  <span class="pill-icon pill-icon--database" :style="databaseIconStyle" aria-hidden="true" />
                  <strong>Token 用量</strong>
                </div>
                <span class="stats-popover-title-val">{{ formatTokensExact(sessionStats.totalTokens) }}</span>
              </div>
              <div class="stats-popover-divider" />
              <dl class="stats-popover-details">
                <template v-if="sessionStats.cacheHitRate !== null">
                  <dt>缓存命中率</dt>
                  <dd>{{ sessionStats.cacheHitRate }}%</dd>
                </template>
                <dt>未缓存输入</dt>
                <dd>{{ formatTokensExact(sessionStats.uncachedInputTokens) }}</dd>
                <dt>缓存读取</dt>
                <dd>{{ formatTokensExact(sessionStats.cachedInputTokens) }}</dd>
                <dt v-if="sessionStats.cacheWriteTokens > 0">缓存写入</dt>
                <dd v-if="sessionStats.cacheWriteTokens > 0">{{ formatTokensExact(sessionStats.cacheWriteTokens) }}</dd>
                <dt>模型输出</dt>
                <dd>{{ formatTokensExact(sessionStats.outputTokens) }}</dd>
              </dl>
            </div>
          </el-popover>

          <!-- 3. 上下文窗口占用率 (Context Meter Ring) -->
          <el-popover
            v-if="sessionStats.contextWindowTokens > 0 || sessionStats.contextPercent > 0"
            :visible="statsCardVisible('context')"
            placement="top"
            :width="260"
            trigger="manual"
            popper-class="stats-pill-popover"
          >
            <template #reference>
              <button
                type="button"
                class="stats-pill"
                :aria-pressed="statsCardVisible('context') ? 'true' : 'false'"
                :aria-label="`上下文占用: ${sessionStats.contextPercent}%`"
                @click="toggleStatsCardOnPillClick('context')"
              >
                <svg class="context-ring" viewBox="0 0 14 14" width="14" height="14" aria-hidden="true">
                  <circle
                    class="context-ring-bg"
                    cx="7"
                    cy="7"
                    r="5.5"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.8"
                    opacity="0.25"
                  />
                  <circle
                    class="context-ring-meter"
                    cx="7"
                    cy="7"
                    r="5.5"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.8"
                    stroke-linecap="round"
                    :stroke-dasharray="2 * Math.PI * 5.5"
                    :stroke-dashoffset="(2 * Math.PI * 5.5) * (1 - sessionStats.contextPercent / 100)"
                    transform="rotate(-90 7 7)"
                  />
                </svg>
                <span>{{ sessionStats.contextPercent }}%</span>
              </button>
            </template>
            <div class="stats-popover-content">
              <div class="stats-popover-title">
                <div class="stats-popover-title-left">
                  <svg class="context-ring" viewBox="0 0 14 14" width="14" height="14" aria-hidden="true">
                    <circle cx="7" cy="7" r="5.5" fill="none" stroke="currentColor" stroke-width="1.8" opacity="0.25" />
                    <circle
                      cx="7"
                      cy="7"
                      r="5.5"
                      fill="none"
                      stroke="currentColor"
                      stroke-width="1.8"
                      stroke-linecap="round"
                      :stroke-dasharray="2 * Math.PI * 5.5"
                      :stroke-dashoffset="(2 * Math.PI * 5.5) * (1 - sessionStats.contextPercent / 100)"
                      transform="rotate(-90 7 7)"
                    />
                  </svg>
                  <strong>上下文窗口占用</strong>
                </div>
                <span class="stats-popover-title-val">{{ sessionStats.contextPercent }}%</span>
              </div>
              <div class="stats-popover-divider" />
              <dl class="stats-popover-details">
                <dt>已占用 Tokens</dt>
                <dd>{{ formatTokensExact(sessionStats.contextWindowUsed) }}</dd>
                <dt>窗口容量上限</dt>
                <dd>{{ formatTokensExact(sessionStats.contextWindowTokens) }}</dd>
                <dt>当前负载</dt>
                <dd>{{ sessionStats.contextPercent }}%</dd>
              </dl>
            </div>
          </el-popover>
        </div>
      </footer>
    </template>
    <AiApprovalDialog v-model:visible="approvalDialogVisible" :message="approvalDialogMessage" :target-name="displayKnownTestName(approvalTarget?.name || selectedThread?.targetName)" :target-value="approvalTarget?.targetValue || `目标 #${selectedThread?.targetId || ''}`" :allowed-ports="approvalTarget?.allowedPorts || ''" :busy="approvingMessageId !== null" @decide="decideDialogApproval" />
  </div>
</template>

<style scoped>
.conversation-storage-notice {
  flex: none;
  margin: 8px 18px;
  padding: 10px 12px;
  border: 1px solid var(--el-color-danger-light-5);
  border-radius: 8px;
  background: var(--el-color-danger-light-9);
  color: var(--el-color-danger);
}
.conversation-storage-notice p { margin: 0; }
.conversation-storage-notice button { margin-top: 8px; }
.chat-page {
  display: flex;
  height: 100%;
  min-height: 0;
  flex: 1 1 0%;
  overflow: hidden;
  flex-direction: column;
  border: 1px solid var(--app-border);
  border-radius: 12px;
  background: transparent;
  box-shadow: var(--app-shadow);
}
.chat-header {
  display: flex;
  min-height: 64px;
  flex: none;
  align-items: center;
  justify-content: space-between;
  padding: 10px 18px;
  border-bottom: 1px solid var(--app-border);
  background: var(--app-surface-soft);
  backdrop-filter: blur(18px) saturate(130%);
}
.chat-header > div:first-child {
  display: flex;
  min-width: 0;
  flex-direction: column;
}
.chat-header strong {
  overflow: hidden;
  color: var(--app-text);
  font-size: 14px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.chat-header span {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 4px;
  color: var(--app-muted);
  font-size: 10px;
}
.chat-header span i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #35a06a;
}
.chat-header span i.offline {
  background: #bd8136;
}
.dashboard-thread-status {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 1px 7px;
  border-radius: 10px;
  font-size: 10px;
  font-weight: 500;
  line-height: 14px;
  margin-left: 6px;
  vertical-align: middle;
}
.dashboard-thread-status.status--running {
  background: #e0f2fe;
  color: #0369a1;
  border: 1px solid #bae6fd;
}
.dashboard-thread-status.status--completed {
  background: #ecfdf5;
  color: #047857;
  border: 1px solid #a7f3d0;
}
.dashboard-thread-status.status--failed {
  background: #fef2f2;
  color: #b91c1c;
  border: 1px solid #fecaca;
}
.status-dot-pulse {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: #0284c7;
  animation: tag-pulse 1.4s ease-in-out infinite;
}
@keyframes tag-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.3; transform: scale(0.7); }
}
.chat-header-actions {
  display: flex;
  align-items: center;
  gap: 5px;
}
.chat-header-actions button {
  display: flex;
  height: 30px;
  align-items: center;
  gap: 5px;
  padding: 0 9px;
  border: 1px solid transparent;
  border-radius: 7px;
  background: transparent;
  color: var(--app-muted);
  font-size: 11px;
  cursor: pointer;
}
.chat-header-actions button:hover:not(:disabled) {
  border-color: var(--app-border);
  background: var(--app-surface-soft);
}
.chat-header-actions button.danger:hover:not(:disabled),
.chat-header-actions button.danger:focus-visible:not(:disabled) {
  border-color: var(--fluent-danger-bg);
  background: color-mix(in srgb, var(--fluent-danger-bg) 10%, var(--app-surface-strong));
  color: light-dark(var(--fluent-danger-hover-bg), #ffd2cc);
}
.chat-welcome {
  display: flex;
  min-height: 0;
  flex: 1;
  overflow: auto;
  flex-direction: column;
  align-items: center;
  padding: clamp(44px, 7vh, 86px) 20px 36px;
  text-align: center;
}
.welcome-mark {
  display: grid;
  width: 48px;
  height: 48px;
  place-items: center;
  border-radius: 14px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font-size: 23px;
}
.chat-welcome h1 {
  margin: 18px 0 8px;
  color: var(--app-text);
  font-size: clamp(27px, 2.2vw, 36px);
  font-weight: 620;
  letter-spacing: 0;
}
.chat-welcome > p {
  max-width: 620px;
  margin: 0;
  color: var(--app-muted);
  font-size: 13px;
  line-height: 1.7;
}
.welcome-composer {
  width: min(760px, 100%);
  margin-top: 27px;
  overflow: hidden;
  border: 1px solid var(--app-border);
  border-radius: 15px;
  background: var(--app-surface-strong);
  text-align: left;
  box-shadow: 0 9px 30px var(--app-shadow);
}
.welcome-composer:focus-within,
.thread-composer:focus-within {
  border-color: var(--app-accent);
  box-shadow: 0 0 0 3px var(--app-accent-soft);
}
.welcome-composer textarea,
.thread-composer textarea {
  display: block;
  width: 100%;
  resize: none;
  border: 0;
  outline: 0;
  background: transparent;
  color: var(--app-text);
  font: inherit;
  font-size: 14px;
  line-height: 1.65;
}
.welcome-composer textarea {
  min-height: 110px;
  padding: 18px 19px 8px;
}
.welcome-composer textarea::placeholder,
.thread-composer textarea::placeholder {
  color: var(--app-muted);
}
.composer-footer {
  display: grid;
  grid-template-columns: minmax(0, 1fr) max-content 36px;
  align-items: center;
  gap: 12px;
  padding: 8px 18px 11px;
}
.composer-footer .target-picker {
  width: 100%;
  max-width: 290px;
  min-width: 0;
}
.target-picker {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  gap: 8px;
}
.target-picker > span,
.composer-shortcut {
  color: var(--app-muted);
  font-size: 10px;
}
.target-picker small {
  float: right;
  margin-left: 10px;
  color: var(--app-muted);
}
.composer-shortcut {
  min-width: max-content;
  justify-self: end;
  white-space: nowrap;
  text-align: right;
}
.send-button,
.thread-composer > button {
  display: grid;
  width: 36px;
  height: 36px;
  place-items: center;
  border: 0;
  border-radius: 9px;
  background: var(--app-accent);
  color: var(--app-surface-strong);
  font-size: 17px;
  cursor: pointer;
}
.send-button:disabled,
.thread-composer > button:disabled {
  background: var(--app-border);
  cursor: default;
}
.create-target {
  height: 28px;
  padding: 0 10px;
  border: 1px solid var(--app-border);
  border-radius: 7px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font-size: 11px;
  cursor: pointer;
}
.quick-actions {
  display: grid;
  width: min(760px, 100%);
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin-top: 14px;
}
.quick-actions button {
  display: grid;
  min-width: 0;
  grid-template-columns: 27px minmax(0, 1fr);
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  border: 1px solid var(--app-border);
  border-radius: 9px;
  background: var(--app-surface-soft);
  color: var(--app-muted);
  text-align: left;
  cursor: pointer;
}
.quick-actions button:hover {
  border-color: var(--app-border);
  background: var(--app-surface-strong);
}
.quick-actions button span {
  display: flex;
  min-width: 0;
  flex-direction: column;
}
.quick-actions strong {
  color: var(--app-text);
  font-size: 11px;
}
.quick-actions small {
  overflow: hidden;
  margin-top: 2px;
  color: var(--app-muted);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.chat-messages {
  min-height: 0;
  flex: 1;
  overflow: auto;
  background: transparent;
  scroll-behavior: smooth;
}
.messages-inner {
  width: min(820px, 100%);
  min-height: 100%;
  margin: 0 auto;
  padding: 30px 22px 34px;
}
.chat-message {
  display: grid;
  grid-template-columns: 34px minmax(0, 1fr);
  align-items: start;
  gap: 11px;
  margin-bottom: 26px;
}
.chat-message.user {
  grid-template-columns: minmax(0, 1fr) 34px;
}
.chat-message.user .message-avatar {
  grid-column: 2;
  grid-row: 1;
}
.chat-message.user .message-column {
  grid-column: 1;
  grid-row: 1;
  align-items: flex-end;
}
.message-column {
  display: flex;
  min-width: 0;
  flex-direction: column;
  align-items: flex-start;
}
.message-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin: 0 3px 6px;
}
.message-meta strong {
  color: var(--app-text);
  font-size: 10px;
}
.message-meta span {
  color: var(--app-muted);
  font-size: 9px;
}
.message-bubble {
  max-width: min(680px, 92%);
  padding: 11px 14px;
  border: 1px solid var(--app-border);
  border-radius: 4px 13px 13px;
  background: var(--app-surface-strong);
  color: var(--app-text);
  font-size: 13px;
  line-height: 1.75;
  white-space: pre-wrap;
  word-break: break-word;
  box-shadow: 0 1px 2px var(--app-shadow);
}
.user .message-bubble {
  border-color: var(--app-border);
  border-radius: 13px 4px 13px 13px;
  background: var(--app-accent-soft);
}
.message-steps {
  display: flex;
  max-width: 680px;
  flex-wrap: wrap;
  gap: 5px;
  margin-top: 8px;
}
.message-steps span {
  padding: 4px 8px;
  border: 1px solid var(--app-border);
  border-radius: 6px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font-size: 9px;
}
.task-progress-card {
  width: min(520px, 90%);
  margin-top: 9px;
  padding: 9px 11px;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-soft);
}
.task-progress-card > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 7px;
}
.task-progress-card span {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--app-muted);
  font-size: 9px;
}
.task-progress-card i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #2d91a0;
  box-shadow: 0 0 0 3px var(--app-accent-soft);
}
.task-progress-card.failed i {
  background: #c85a5a;
  box-shadow: none;
}
.task-progress-card.success i {
  background: #39a36d;
  box-shadow: none;
}
.task-progress-card.pending i {
  background: #c18b3b;
  box-shadow: none;
}
.task-progress-card button {
  border: 0;
  background: transparent;
  color: var(--app-accent);
  font-size: 9px;
  cursor: pointer;
}
.thread-empty {
  display: grid;
  min-height: 300px;
  place-items: center;
  color: var(--app-muted);
  font-size: 12px;
}
.chat-composer-wrap {
  width: min(850px, 100%);
  flex: none;
  margin: 0 auto;
  padding: 8px 22px 5px;
  background: transparent;
}
.thread-target {
  display: flex;
  align-items: center;
  gap: 7px;
  margin-bottom: 7px;
  padding: 0 3px;
}
.thread-target span,
.thread-target small {
  color: var(--app-muted);
  font-size: 9px;
}
.thread-target strong {
  color: var(--app-text);
  font-size: 10px;
}
.thread-target small {
  margin-left: auto;
}
.thread-composer {
  display: flex;
  flex-direction: column;
  padding: 10px 12px 8px 14px;
  border: 1px solid var(--app-border);
  border-radius: 12px;
  background: var(--app-surface-strong);
  box-shadow: 0 4px 16px var(--app-shadow);
}
.thread-composer-footer {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 4px;
}
.thread-composer-footer .composer-shortcut {
  margin-left: auto;
  color: var(--app-muted);
  font-size: 11px;
}
.thread-composer-footer .send-button {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  flex-shrink: 0;
}
.thread-composer textarea {
  max-height: 130px;
  min-height: 48px;
  padding: 4px 0;
}
.composer-hint {
  display: block;
  /* 与 .composer-stats-bar 的 padding-top 配平：提示语在输入框与统计栏之间
     视觉等距（各约 9px，含行高半行距）。改这里要同步改 stats 的 padding-top。 */
  margin-top: 7px;
  color: var(--app-muted);
  font-size: 9px;
  text-align: center;
}
.rotating {
  animation: spin 0.8s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
@media (max-width: 760px) {
  .chat-page {
    min-height: 560px;
  }
  .chat-header {
    align-items: flex-start;
  }
  .chat-header-actions button {
    padding: 0 6px;
  }
  .chat-header-actions button:not(:first-child) span {
    display: none;
  }
  .composer-footer {
    grid-template-columns: 1fr 36px;
  }
  .composer-footer .target-picker {
    grid-column: 1 / -1;
  }
  .composer-shortcut {
    display: none;
  }
  .quick-actions {
    grid-template-columns: 1fr;
  }
  .messages-inner {
    padding: 22px 12px;
  }
  .chat-message {
    grid-template-columns: 29px minmax(0, 1fr);
    gap: 8px;
  }
  .chat-message.user {
    grid-template-columns: minmax(0, 1fr) 29px;
  }
  .message-bubble {
    max-width: 96%;
  }
  .chat-composer-wrap {
    padding: 9px 11px 7px;
  }
  .thread-target small {
    display: none;
  }
}
/* =================================================================
   Execution plan card — Fluent 2 Card anatomy
   One disclosure row is the card header; below it a single content
   section. A pending approval is a decision surface inside that same
   section, never a second stacked banner with its own heading.
   ================================================================= */
.execution-plan-card {
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
  margin-top: 10px;
  padding: 0;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card, 8px);
  background: var(--app-surface-strong);
  color: var(--app-text);
  box-shadow: 0 1px 2px color-mix(in srgb, CanvasText 4%, transparent);
}
.execution-plan-card > summary {
  list-style: none;
}
.execution-plan-card > summary::-webkit-details-marker {
  display: none;
}
/* The disclosure keeps the card's 44px header row. Its divider is only drawn
   when the content below it is not already separated by the approval
   surface, so the two never render a double rule. */
.execution-plan-disclosure {
  display: flex;
  min-height: 44px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 14px;
  border-radius: inherit;
  color: var(--app-text-muted);
  cursor: pointer;
}
.execution-plan-card[open]:not(.is-awaiting-approval) > .execution-plan-disclosure {
  border-bottom: 1px solid var(--app-border);
}
.execution-plan-disclosure:hover {
  background: var(--app-surface-soft);
}
.execution-plan-disclosure:focus-visible {
  outline: 2px solid var(--app-accent);
  outline-offset: -2px;
}
.execution-plan-disclosure-text {
  display: inline-flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
  font-size: var(--fluent-body1-size, 14px);
  font-weight: var(--fluent-weight-semibold, 600);
  line-height: 20px;
}
.execution-plan-chevron {
  width: 16px;
  height: 16px;
  flex: none;
  color: var(--app-muted);
  transition: transform var(--fluent-fast, 150ms);
}
.execution-plan-card[open] .execution-plan-chevron {
  transform: rotate(90deg);
}
.execution-plan-count {
  white-space: nowrap;
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
  font-weight: var(--fluent-weight-regular, 400);
}
.execution-plan-state {
  flex: 0 1 auto;
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
  line-height: 16px;
  text-align: right;
  overflow-wrap: anywhere;
}
.execution-plan-state.waiting {
  color: var(--fluent-warning-bg, #8a4b08);
}
.execution-plan-state.failed {
  color: var(--fluent-danger-bg, #b42318);
}
/* Approval decision surface: icon + copy on the left, actions on the
   right, stacked only when the card gets narrow. */
.plan-approval {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px 16px;
  padding: 12px 14px;
  background: color-mix(
    in srgb,
    var(--fluent-warning-bg, #8a4b08) 6%,
    var(--app-surface-soft)
  );
  border-bottom: 1px solid var(--app-border);
}
.plan-approval-head {
  display: flex;
  min-width: 0;
  flex: 1 1 260px;
  align-items: flex-start;
  gap: 10px;
}
.plan-approval-icon {
  width: 20px;
  height: 20px;
  flex: none;
  margin-top: 1px;
  color: var(--fluent-warning-bg, #8a4b08);
}
.plan-approval-copy {
  min-width: 0;
}
.plan-approval-copy strong {
  display: block;
  color: var(--app-text);
  font-size: var(--fluent-body1-size, 14px);
  font-weight: var(--fluent-weight-semibold, 600);
  line-height: 20px;
}
.plan-approval-copy p {
  margin: 2px 0 0;
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
  line-height: 16px;
}
.plan-approval-actions {
  display: flex;
  flex: 0 1 auto;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.plan-approval-actions :deep(.el-button) {
  margin: 0;
  min-height: 32px;
}
.execution-plan-list {
  display: grid;
  /* `minmax(0, 1fr)` (not the implicit `auto` track): an auto track is sized to
     the longest unbreakable word, so one long progress message (e.g.
     `DIR_SCAN dictionary=… bases=[http://…]`) widened the whole card and squeezed
     the title column down to a single character per line. */
  grid-template-columns: minmax(0, 1fr);
  gap: 0;
  margin: 0;
  padding: 0;
  list-style: none;
}
.execution-plan-list li {
  display: grid;
  grid-template-columns: 20px minmax(0, 1fr) auto;
  align-items: start;
  gap: 10px;
  padding: 10px 14px;
  border-top: 1px solid var(--app-border);
}
.execution-plan-list li:first-child {
  border-top: 0;
}
/* Pending steps read as an ordered list; only terminal states get an icon. */
.plan-step-icon {
  display: grid;
  width: 20px;
  height: 20px;
  place-items: center;
  margin-top: 1px;
  border-radius: 50%;
  background: var(--app-surface-soft);
  color: var(--app-muted);
}
.plan-step-icon .fluent-system-icon {
  width: 16px;
  height: 16px;
}
.plan-step-index {
  font-size: 11px;
  font-style: normal;
  font-weight: 600;
  line-height: 1;
  font-variant-numeric: tabular-nums;
}
.execution-plan-list li > div {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 3px;
}
.execution-plan-list li strong {
  display: block;
  color: var(--app-text);
  font-size: var(--fluent-body1-size, 14px);
  font-weight: var(--fluent-weight-medium, 500);
  line-height: 20px;
  white-space: normal;
  overflow-wrap: anywhere;
}
.has-dispatch-notice .execution-plan-list li { grid-template-columns: 20px minmax(0, 1fr); align-items: center; }
.has-dispatch-notice .execution-plan-state { padding: 3px 8px; border: 1px solid var(--app-border); border-radius: 4px; color: var(--app-text-muted); background: var(--app-surface-soft); }
.execution-plan-list li small {
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
  line-height: 16px;
  overflow-wrap: anywhere;
}
.plan-step-status {
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
  line-height: 16px;
  white-space: nowrap;
}
.execution-plan-list li.running .plan-step-icon {
  background: var(--app-accent-soft);
  color: var(--app-accent);
  animation: planPulse 1.4s ease-in-out infinite;
}
.execution-plan-list li.running .plan-step-status {
  color: var(--app-accent);
}
.execution-plan-list li.success .plan-step-icon {
  background: color-mix(in srgb, var(--fluent-success-bg, #107c41) 14%, transparent);
  color: var(--fluent-success-bg, #107c41);
}
.execution-plan-list li.success .plan-step-status {
  color: var(--fluent-success-bg, #107c41);
}
.execution-plan-list li.failed .plan-step-icon {
  background: color-mix(in srgb, var(--fluent-danger-bg, #b42318) 14%, transparent);
  color: var(--fluent-danger-bg, #b42318);
}
.execution-plan-list li.failed .plan-step-status {
  color: var(--fluent-danger-bg, #b42318);
}
.execution-plan-list .el-progress {
  margin-top: 4px;
}
/* Footer carries the task summary and the only navigation action. */
.execution-plan-footer {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px 12px;
  padding: 10px 14px;
  border-top: 1px solid var(--app-border);
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
  line-height: 16px;
}
.execution-plan-footer span {
  min-width: 0;
  overflow-wrap: anywhere;
}
.execution-plan-link {
  flex: none;
  min-height: 32px;
  padding: 0 10px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control, 4px);
  background: var(--app-surface-strong);
  color: var(--app-text);
  font: inherit;
  font-weight: var(--fluent-weight-medium, 500);
  cursor: pointer;
}
.execution-plan-link:hover {
  background: var(--app-surface-soft);
  border-color: var(--app-accent);
  color: var(--app-accent);
}
.execution-plan-link:focus-visible {
  outline: 2px solid var(--app-accent);
  outline-offset: 1px;
}
.plan-runtime-details {
  margin: 0;
  border-top: 1px solid var(--app-border);
}
.plan-runtime-details summary {
  min-height: 36px;
  display: flex;
  align-items: center;
  padding: 0 14px;
  color: var(--app-accent);
  font-size: var(--fluent-caption1-size, 12px);
  cursor: pointer;
}
.plan-runtime-details > :not(summary) {
  margin: 0 14px 10px;
}
@keyframes planPulse {
  50% {
    box-shadow: 0 0 0 4px var(--app-accent-soft);
  }
}

.welcome-composer textarea,
.thread-composer textarea {
  font-size: 15px;
}
.message-meta strong {
  font-size: 12px;
}
.message-meta span {
  font-size: 11px;
}
.message-bubble {
  max-width: min(720px, 94%);
  padding: 13px 16px;
  font-size: 15px;
  line-height: 1.75;
}
.message-steps span {
  font-size: 11px;
}
.task-progress-card span,
.task-progress-card button {
  font-size: 11px;
}
.thread-target span,
.thread-target small,
.composer-hint {
  font-size: 10px;
}
.thread-target strong {
  font-size: 12px;
}
.traffic-reference-card {
  width: min(720px, 94%);
  margin-top: 9px;
  overflow: hidden;
  border: 1px solid var(--app-border);
  border-radius: 10px;
  background: var(--app-surface-soft);
  color: var(--app-text);
}
.user .traffic-reference-card {
  align-self: flex-end;
}
.traffic-reference-card > header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 9px 12px;
  border-bottom: 1px solid var(--app-border);
}
.traffic-reference-card > header > span {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--app-accent);
  font-size: 10px;
  font-weight: 650;
}
.traffic-reference-card > header code {
  padding: 3px 6px;
  border-radius: 5px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font:
    700 10px ui-monospace,
    Consolas,
    monospace;
}
.traffic-reference-card > strong {
  display: block;
  overflow: hidden;
  padding: 11px 12px 4px;
  color: var(--app-text);
  font:
    12px ui-monospace,
    Consolas,
    monospace;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.traffic-reference-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  padding: 4px 12px 10px;
}
.traffic-reference-meta span {
  padding: 2px 6px;
  border-radius: 5px;
  background: var(--app-surface-soft);
  color: var(--app-muted);
  font-size: 9px;
}
.traffic-reference-card details {
  border-top: 1px solid var(--app-border);
}
.traffic-reference-card summary {
  padding: 8px 12px;
  color: var(--app-accent);
  font-size: 10px;
  cursor: pointer;
}
.traffic-reference-packets {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  padding: 0 10px 10px;
}
.traffic-reference-packets article {
  min-width: 0;
  overflow: hidden;
  border: 1px solid var(--app-border);
  border-radius: 7px;
  background: var(--app-surface-strong);
}
.traffic-reference-packets h4 {
  margin: 0;
  padding: 7px 9px;
  border-bottom: 1px solid var(--app-border);
  color: var(--app-muted);
  font-size: 9px;
}
.reference-output {
  padding: 9px;
  box-sizing: border-box;
}
@media (max-width: 760px) {
  .traffic-reference-packets {
    grid-template-columns: 1fr;
  }
}
.runtime-output {
  margin-top: 10px;
}
.agent-event-details {
  margin-top: 6px;
  border-top: 1px solid var(--app-border);
}
.agent-event-details > summary {
  padding-top: 9px;
  color: var(--app-accent);
  font-size: 10px;
  cursor: pointer;
}
.agent-event-list {
  display: grid;
  gap: 0;
  margin: 8px 0 0;
  padding: 0;
  list-style: none;
}
.agent-event-list li {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: start;
  gap: 8px;
  padding: 7px 0;
  border-top: 1px solid var(--app-border);
}
.agent-event-list li > span {
  min-width: 52px;
  padding: 2px 6px;
  border-radius: 5px;
  background: var(--app-surface-strong);
  color: var(--app-text);
  font-size: 9px;
  font-weight: 650;
  text-align: center;
}
.agent-event-list li > div {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 3px;
}
.agent-event-list li strong {
  overflow: hidden;
  color: var(--app-text);
  font-size: 10px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.agent-event-list li small {
  color: var(--app-muted);
  font-size: 9px;
  line-height: 1.45;
}
.agent-event-list li code {
  overflow: auto;
  max-height: 74px;
  padding: 5px 7px;
  border-radius: 5px;
  background: #111827;
  color: #e5edf7;
  font:
    9px/1.45 ui-monospace,
    Consolas,
    monospace;
  white-space: pre-wrap;
  word-break: break-word;
}
.agent-node-run-id,
.agent-node-snapshot {
  overflow-wrap: anywhere;
  font-family: Consolas, "Courier New", monospace;
}
.agent-event-list li.running > span {
  background: var(--app-accent-soft);
  color: var(--app-accent);
}
.agent-event-list li.success > span {
  background: #e3f4ea;
  color: #216c4c;
}
.agent-event-list li.failed > span {
  background: #fbe8e8;
  color: #9f3030;
}
.agent-event-list li.approval > span {
  background: #fff2d8;
  color: #875b10;
}
.message-usage {
  display: flex;
  width: fit-content;
  max-width: 94%;
  flex-wrap: wrap;
  gap: 5px 10px;
  margin-top: 8px;
  color: var(--app-muted);
  font-size: 10px;
}
.message-usage-source {
  color: var(--app-accent);
}
.agent-citation-bubbles {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  width: min(720px, 94%);
  margin-top: 8px;
}
.agent-citation-bubble {
  display: inline-flex;
  max-width: 180px;
  align-items: center;
  min-height: 24px;
  padding: 2px 10px;
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--app-border) 88%, transparent);
  border-radius: 999px;
  background: color-mix(in srgb, var(--app-surface-soft) 88%, transparent);
  color: var(--app-muted);
  font-size: 10px;
  font-weight: 600;
  line-height: 1.3;
  text-decoration: none;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: default;
}
.agent-citation-bubble:hover {
  border-color: color-mix(in srgb, var(--app-accent) 35%, var(--app-border));
  color: var(--app-accent);
  background: color-mix(
    in srgb,
    var(--app-accent-soft, #e8f1ff) 70%,
    var(--app-surface-soft)
  );
}
a.agent-citation-bubble {
  cursor: pointer;
}
.message-actions {
  display: flex;
  margin-top: 7px;
}
.message-actions button {
  display: flex;
  align-items: center;
  gap: 5px;
  padding: 5px 9px;
  border: 1px solid var(--app-border);
  border-radius: 7px;
  background: var(--app-surface-soft);
  color: var(--app-accent);
  font-size: 11px;
  cursor: pointer;
}
.message-actions button:disabled {
  color: var(--app-muted);
  cursor: default;
}
.message-quote {
  display: flex;
  width: min(660px, 90%);
  flex-direction: column;
  gap: 3px;
  margin-bottom: 6px;
  padding: 7px 10px;
  border-left: 3px solid var(--app-accent);
  border-radius: 0 6px 6px 0;
  background: var(--app-surface-soft);
}
.message-quote strong {
  color: var(--app-accent);
  font-size: 10px;
}
.message-quote span {
  overflow: hidden;
  color: var(--app-muted);
  font-size: 10px;
  line-height: 1.45;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.user .message-quote {
  align-self: flex-end;
}
.composer-quote {
  display: flex;
  grid-column: 1/-1;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 7px 9px;
  border-bottom: 1px solid var(--app-border);
  color: var(--app-muted);
  font-size: 10px;
}
.composer-quote span {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 2px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.composer-quote strong {
  color: var(--app-accent);
}
.composer-quote button {
  width: 24px;
  height: 24px;
  flex: none;
  border: 0;
  border-radius: 5px;
  background: transparent;
  color: var(--app-muted);
  font-size: 17px;
  cursor: pointer;
}
.composer-quote button:hover {
  background: var(--app-surface-soft);
  color: var(--app-text);
}
.markdown-body {
  white-space: normal;
}
.markdown-body :deep(> :first-child) {
  margin-top: 0;
}
.markdown-body :deep(> :last-child) {
  margin-bottom: 0;
}
.markdown-body :deep(p) {
  margin: 0 0 10px;
}
.markdown-body :deep(h1),
.markdown-body :deep(h2),
.markdown-body :deep(h3),
.markdown-body :deep(h4) {
  margin: 16px 0 8px;
  color: var(--app-text);
  line-height: 1.35;
}
.markdown-body :deep(h1) {
  font-size: 20px;
}
.markdown-body :deep(h2) {
  padding-bottom: 5px;
  border-bottom: 1px solid var(--app-border);
  font-size: 17px;
}
.markdown-body :deep(h3) {
  font-size: 15px;
}
.markdown-body :deep(h4) {
  font-size: 14px;
}
.markdown-body :deep(ul),
.markdown-body :deep(ol) {
  margin: 7px 0 11px;
  padding-left: 22px;
}
.markdown-body :deep(li) {
  margin: 3px 0;
}
.markdown-body :deep(a) {
  color: var(--app-accent);
  text-decoration: none;
}
.markdown-body :deep(a:hover) {
  text-decoration: underline;
}
.markdown-body :deep(code) {
  padding: 2px 5px;
  border-radius: 4px;
  background: var(--app-surface-soft);
  font:
    12px ui-monospace,
    Consolas,
    monospace;
}
.markdown-body :deep(pre) {
  max-width: 100%;
  overflow: auto;
  margin: 10px 0;
  padding: 11px 12px;
  border: 1px solid var(--app-border);
  border-radius: 7px;
  background: var(--app-surface-soft);
  color: var(--app-text);
  white-space: pre;
}
.markdown-body :deep(pre code) {
  padding: 0;
  background: transparent;
  color: inherit;
}
.markdown-body :deep(blockquote) {
  margin: 10px 0;
  padding: 7px 12px;
  border-left: 3px solid var(--app-accent);
  background: var(--app-accent-soft);
  color: var(--app-muted);
}
.markdown-body :deep(table) {
  display: block;
  max-width: 100%;
  overflow: auto;
  overflow-wrap: normal;
  word-break: normal;
  margin: 10px 0;
  border-collapse: collapse;
}
.markdown-body :deep(th),
.markdown-body :deep(td) {
  padding: 6px 9px;
  border: 1px solid var(--app-border);
  text-align: left;
}
.markdown-body :deep(th) {
  background: var(--app-surface-soft);
}
.markdown-body :deep(hr) {
  margin: 14px 0;
  border: 0;
  border-top: 1px solid var(--app-border);
}
.markdown-body :deep(img) {
  max-width: 100%;
  height: auto;
  border-radius: 6px;
}
.copilot-draft-refs {
  display: flex;
  grid-column: 1/-1;
  flex-wrap: wrap;
  gap: 6px;
  padding: 8px 12px 0;
}
.copilot-draft-refs span {
  max-width: 240px;
  overflow: hidden;
  padding: 4px 8px;
  border-radius: 6px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.copilot-reference-card {
  width: min(720px, 94%);
  margin-top: 9px;
  overflow: hidden;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-soft);
}
.user .copilot-reference-card {
  align-self: flex-end;
}
.copilot-reference-card header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 9px 12px;
  border-bottom: 1px solid var(--app-border);
}
.copilot-reference-card header span {
  color: var(--app-accent);
  font-size: 11px;
  font-weight: 650;
}
.copilot-reference-card header code {
  color: var(--app-muted);
  font-size: 9px;
}
.copilot-reference-card > strong,
.copilot-reference-card > p {
  display: block;
  margin: 0;
  padding: 9px 12px 0;
  color: var(--app-text);
  font-size: 11px;
}
.copilot-reference-card > p {
  padding-bottom: 10px;
  color: var(--app-muted);
  line-height: 1.55;
}
.copilot-reference-card details {
  border-top: 1px solid var(--app-border);
}
.copilot-reference-card summary {
  padding: 8px 12px;
  color: var(--app-accent);
  font-size: 10px;
  cursor: pointer;
}
.desktop-v2-native-frame .chat-page {
  border: 0;
  border-radius: 0;
  box-shadow: none;
}
.desktop-v2-native-frame .chat-page .chat-header {
  min-height: 48px;
  padding: 7px 16px;
}
.desktop-v2-native-frame .chat-page .chat-header span {
  margin-top: 2px;
}
.desktop-v2-native-frame .chat-page .chat-header-actions button {
  min-width: 32px;
  height: 32px;
  padding: 0 10px;
}
.welcome-mark {
  background: var(--app-accent-soft);
  color: var(--app-accent);
}
.chat-header span i {
  background: var(--app-accent);
  box-shadow: 0 0 0 3px var(--app-accent-soft);
}
.chat-header span i.checking {
  background: #bd8136;
  box-shadow: 0 0 0 3px color-mix(in srgb, #bd8136 18%, transparent);
}
.chat-header span i.offline {
  background: #b34f4f;
  box-shadow: none;
}
.target-option {
  display: flex;
  flex: 1 1 0%;
  width: 100%;
  min-width: 0;
  flex-direction: column;
  gap: 3px;
  line-height: 1.25;
}
.target-option span {
  display: block;
  max-width: 100%;
  overflow: hidden;
  color: var(--app-text);
  font-size: 12px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.target-option small {
  display: block;
  max-width: 100%;
  overflow: hidden;
  margin: 0;
  color: var(--app-muted);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
:global(.target-picker-popper .el-select-dropdown__item) {
  display: flex;
  height: auto;
  min-height: 48px;
  max-width: 100%;
  box-sizing: border-box;
  align-items: center;
  padding-top: 7px;
  padding-bottom: 7px;
}

/* Fluent WinUI 3 visual language */
.chat-page {
  font-family:
    "Segoe UI Variable Text", "Segoe UI Variable", "Segoe UI", sans-serif;
  border-radius: 12px;
  box-shadow: 0 1px 2px color-mix(in srgb, CanvasText 7%, transparent);
}
.chat-header {
  min-height: 56px;
  padding: 8px 16px;
  background: color-mix(in srgb, var(--app-surface-soft) 88%, transparent);
  backdrop-filter: blur(20px) saturate(125%);
}
.chat-header strong {
  font-size: 14px;
  font-weight: 600;
  letter-spacing: 0;
}
.chat-header span {
  font-size: 11px;
}
.chat-header-actions button,
.create-target {
  min-width: 32px;
  height: 32px;
  padding: 0 10px;
  border-color: transparent;
  border-radius: 8px;
  background: transparent;
  color: var(--app-text);
  font:
    600 12px/1 "Segoe UI Variable Text",
    "Segoe UI",
    sans-serif;
  transition:
    background-color 100ms ease,
    border-color 100ms ease,
    transform 60ms ease;
}
.chat-header-actions button:hover:not(:disabled),
.create-target:hover {
  border-color: var(--app-border);
  background: var(--app-surface-soft);
}
.chat-header-actions button:active:not(:disabled),
.create-target:active,
.quick-actions button:active {
  transform: scale(0.98);
  background: color-mix(in srgb, var(--app-surface-soft) 82%, CanvasText 4%);
}
.chat-header-actions button:focus-visible,
.create-target:focus-visible,
.quick-actions button:focus-visible,
.send-button:focus-visible,
.thread-composer > button:focus-visible {
  outline: 2px solid var(--app-accent);
  outline-offset: 2px;
}
.welcome-stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  width: min(760px, 100%);
  margin-top: 22px;
}
.welcome-stat {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: 14px 10px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface-soft);
}
.welcome-stat--link {
  cursor: pointer;
  font-family: inherit;
  text-align: center;
  outline: none;
  transition: all var(--fluent-fast, 150ms ease);
}
.welcome-stat--link:hover {
  background: var(--app-surface-hover, rgba(0, 120, 212, 0.04));
  border-color: var(--fluent-primary, #0078d4);
  transform: translateY(-2px);
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.07);
}
.welcome-stat--link:active {
  transform: translateY(0);
}
.welcome-stat strong {
  color: var(--app-text);
  font-size: 24px;
  font-weight: var(--fluent-weight-semibold);
  letter-spacing: 0;
}
.welcome-stat small {
  color: var(--app-muted);
  font-size: var(--type-caption);
}
.welcome-stat.warn {
  --welcome-stat-warning: #c8503f;
}
.welcome-stat--link.warn:hover {
  border-color: var(--welcome-stat-warning);
  background: color-mix(in srgb, var(--welcome-stat-warning) 10%, var(--app-surface-soft));
  box-shadow: 0 4px 14px rgba(200, 80, 63, 0.12);
}
.welcome-stat--link:focus-visible {
  outline: 2px solid var(--app-accent);
  outline-offset: 2px;
}
.welcome-stat.warn strong {
  color: var(--welcome-stat-warning);
}
@media (max-width: 760px) {
  .welcome-stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
.chat-welcome {
  padding: clamp(48px, 7vh, 88px) 24px 40px;
}
.welcome-mark {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  font-size: 22px;
}
.chat-welcome h1 {
  margin: 20px 0 8px;
  font-size: clamp(28px, 2.2vw, 36px);
  font-weight: 650;
  letter-spacing: 0;
}
.chat-welcome > p {
  font-size: 14px;
  line-height: 1.6;
}
.welcome-composer {
  margin-top: 28px;
  border-color: var(--app-border);
  border-radius: 12px;
  background: var(--app-surface-strong);
  box-shadow:
    0 2px 4px color-mix(in srgb, CanvasText 6%, transparent),
    0 8px 24px color-mix(in srgb, CanvasText 5%, transparent);
  transition:
    border-color 120ms ease,
    box-shadow 120ms ease;
}
.welcome-composer:focus-within,
.thread-composer:focus-within {
  border-color: var(--app-accent);
  box-shadow:
    inset 0 -2px var(--app-accent),
    0 2px 8px color-mix(in srgb, CanvasText 7%, transparent);
}
.welcome-composer textarea,
.thread-composer textarea {
  font-family: "Segoe UI Variable Text", "Segoe UI", sans-serif;
  font-size: 14px;
  line-height: 1.55;
}
.welcome-composer textarea {
  min-height: 112px;
  padding: 18px 20px 8px;
}
.composer-footer {
  grid-template-columns: minmax(0, 1fr) max-content 36px;
  padding: 8px 18px 10px;
}
.target-picker > span,
.composer-shortcut {
  font-size: 11px;
}
.send-button,
.thread-composer > button {
  width: 36px;
  height: 36px;
  border-radius: 8px;
  background: var(--app-accent);
  color: HighlightText;
  transition:
    filter 100ms ease,
    transform 60ms ease;
}
.send-button:hover:not(:disabled),
.thread-composer > button:hover:not(:disabled) {
  filter: brightness(1.08);
}
.send-button:active:not(:disabled),
.thread-composer > button:active:not(:disabled) {
  transform: scale(0.96);
  filter: brightness(0.94);
}
.send-button:disabled,
.thread-composer > button:disabled {
  background: var(--app-surface-soft);
  color: var(--app-muted);
  opacity: 0.72;
}
.quick-actions {
  gap: 10px;
  margin-top: 14px;
}
.quick-actions button {
  min-height: 68px;
  grid-template-columns: 28px minmax(0, 1fr);
  gap: 10px;
  padding: 12px 14px;
  border-radius: 8px;
  background: var(--app-surface-soft);
  box-shadow: 0 1px 2px color-mix(in srgb, CanvasText 5%, transparent);
  transition:
    background-color 100ms ease,
    border-color 100ms ease,
    transform 60ms ease;
}
.quick-actions button:hover {
  border-color: color-mix(in srgb, var(--app-border) 72%, CanvasText 12%);
  background: var(--app-surface-strong);
}
.quick-actions strong {
  font-size: 12px;
  font-weight: 600;
}
.quick-actions small {
  margin-top: 3px;
  font-size: 10px;
}
.messages-inner {
  padding: 32px 24px 36px;
}
.message-meta {
  margin-bottom: 7px;
}
.message-meta strong {
  font-size: 12px;
  font-weight: 600;
}
.message-meta span {
  font-size: 11px;
}
.message-bubble {
  padding: 12px 15px;
  border-radius: 4px 12px 12px;
  background: var(--app-surface-strong);
  font-size: 14px;
  line-height: 1.7;
  box-shadow: 0 1px 2px color-mix(in srgb, CanvasText 6%, transparent);
}
.user .message-bubble {
  border-radius: 12px 4px 12px 12px;
  background: var(--app-accent-soft);
}
.message-steps span {
  padding: 5px 9px;
  border-radius: 8px;
  font-size: 11px;
}
.task-progress-card {
  border-radius: 8px;
  background: var(--app-surface-soft);
  box-shadow: 0 1px 2px color-mix(in srgb, CanvasText 4%, transparent);
}
.task-progress-card {
  padding: 10px 12px;
}
.task-progress-card span,
.task-progress-card button {
  font-size: 11px;
}
.traffic-reference-card {
  border-radius: 8px;
  box-shadow: 0 1px 2px color-mix(in srgb, CanvasText 4%, transparent);
}
.traffic-reference-packets article {
  border-radius: 8px;
}
.chat-composer-wrap {
  padding: 8px 22px 5px;
}
.thread-composer {
  border-radius: 12px;
  background: var(--app-surface-strong);
  box-shadow: 0 2px 8px color-mix(in srgb, CanvasText 7%, transparent);
  transition:
    border-color 120ms ease,
    box-shadow 120ms ease;
}
.thread-target span,
.thread-target small,
.composer-hint {
  font-size: 10px;
}
.thread-target strong {
  font-size: 12px;
  font-weight: 600;
}
:global(.target-picker-popper) {
  width: min(360px, calc(100vw - 32px)) !important;
  max-width: min(360px, calc(100vw - 32px)) !important;
  font-family: "Segoe UI Variable Text", "Segoe UI", sans-serif;
}
:global(.target-picker-popper .el-select-dropdown) {
  max-width: 100% !important;
}
:global(.target-picker-popper .el-select-dropdown__item) {
  /* Menu rows stay square and edge-to-edge, matching every other select. */
  border-radius: 0;
  padding-left: 10px;
  padding-right: 10px;
}
:global(.target-picker-popper .el-select-dropdown__item.is-hovering) {
  background: var(--app-surface-soft);
}

.agent-event-details[open] > summary,
.plan-runtime-details[open] > summary {
  font-weight: 700;
}
/* Dashboard layout guardrails
 *
 * The welcome area is a column flex container.  Its composer contains a
 * textarea and a footer, so allowing the item to shrink makes the browser
 * collapse it to a thin strip in shorter windows. Keep the input as a
 * non-shrinking, content-sized surface; the parent can still scroll when the
 * window is shorter than the complete welcome screen.
 */
.chat-welcome .welcome-composer {
  flex: 0 0 auto;
  min-height: 170px;
}

.chat-welcome .welcome-composer:not(:has(.composer-preview--expanded)) textarea {
  box-sizing: border-box;
  height: 112px;
  min-height: 112px;
}

/* Keep labels readable in both light/dark and Windows high-contrast themes. */
.chat-welcome .quick-actions button,
.chat-welcome .create-target,
.chat-header-actions button,
.execution-plan-link {
  color: var(--app-text);
}

.chat-welcome .quick-actions button strong {
  color: var(--app-text);
}

.chat-welcome .send-button,
.chat-composer-wrap .thread-composer > button {
  color: var(--system-accent-foreground, #fff);
}

.chat-welcome .send-button:disabled,
.chat-composer-wrap .thread-composer > button:disabled {
  color: var(--app-muted);
}

/* Keep commands and live execution details comfortably readable without
   changing the conversation structure or adding another surface layer. */
.chat-header-actions {
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 10px;
}

.message-actions {
  gap: 8px;
}

.message-actions button {
  display: inline-flex;
  min-height: 32px;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 0 10px;
}

.message-actions {
  display: flex;
  align-items: center;
  min-height: 32px;
  margin-top: 6px;
  gap: 4px;
  opacity: 0;
  pointer-events: none;
  transition: opacity 120ms ease;
}
.chat-message.assistant .message-actions {
  justify-content: flex-start;
}
.chat-message.user .message-actions {
  justify-content: flex-end;
}
.chat-message:hover .message-actions,
.chat-message:focus-within .message-actions {
  opacity: 1;
  pointer-events: auto;
}
.message-actions .message-action {
  display: inline-flex;
  width: 32px;
  height: 32px;
  min-height: 32px;
  align-items: center;
  justify-content: center;
  padding: 0;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--app-muted);
  font-size: 16px;
}
.message-actions .message-action:hover:not(:disabled),
.message-actions .message-action:focus-visible {
  background: var(--app-surface-soft);
  color: var(--app-text);
}
.message-actions .message-action:focus-visible {
  outline: 2px solid var(--app-accent);
  outline-offset: 2px;
}
.message-actions .message-action.is-copied { color: var(--app-accent); }
.message-quote-icon {
  width: 18px;
  height: 18px;
  background: currentColor;
  mask-position: center;
  mask-size: contain;
  mask-repeat: no-repeat;
}
.message-response { display: contents; }
.chat-message.assistant .message-response {
  display: block;
  width: min(100%, 720px);
  box-sizing: border-box;
  min-width: 0;
  padding: 12px 16px;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-strong);
  box-shadow: 0 1px 2px rgb(0 0 0 / 4%);
}
/* Every assistant state shares the outer chat bubble. Keep the prose inside
   that bubble unboxed, including under the native desktop surface rules. */
.chat-message.assistant .message-response .message-bubble {
  width: 100%;
  max-width: 100%;
  box-sizing: border-box;
  margin: 0;
  padding: 0;
  border: 0;
  border-radius: 0 !important;
  background: transparent !important;
  box-shadow: none;
}
.failed-response-card {
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
}
.failed-response-card :deep(.progress-header) { flex-wrap: wrap; }
.failed-response-card :deep(.progress-heading) { flex-basis: 160px; }
/* The finished-answer status stamp and the action bar belong to the message
   chrome: they sit outside the answer card, aligned with its outer edge, so the
   card holds only the answer. The card's own bottom padding separates the stamp
   from the prose, so the panel's trailing margin is not needed. */
.message-status {
  width: min(100%, 720px);
  box-sizing: border-box;
  margin: 0;
}
.chat-message.assistant .message-response:has(+ .message-status) :deep(.ai-progress-panel) { margin-bottom: 0; }
.composer-edit-notice {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 32px;
  padding: 0 4px;
  color: var(--app-text-muted);
  font-size: 12px;
  line-height: 18px;
}
.composer-edit-notice > .el-icon { flex: none; font-size: 16px; }
.composer-edit-notice > span { flex: 1; min-width: 0; }
.composer-edit-notice strong { margin-right: 8px; color: var(--app-text); font-weight: 500; }
.composer-edit-help { overflow-wrap: anywhere; }
.composer-edit-notice button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: none;
  width: 32px;
  height: 32px;
  padding: 0;
  border: 0;
  border-radius: 4px;
  background: transparent;
  color: var(--app-text-muted);
  font-size: 16px;
  cursor: pointer;
}
.composer-edit-notice button:hover:not(:disabled) { background: var(--app-surface-soft); color: var(--app-text); }
.composer-edit-notice button:disabled { opacity: .45; cursor: not-allowed; }
.composer-edit-notice button:focus-visible { outline: 2px solid var(--app-accent); outline-offset: 2px; }
@media (hover: none), (pointer: coarse), (max-width: 640px) {
  .message-actions { opacity: 1; pointer-events: auto; min-height: 40px; }
  .message-actions .message-action { width: 40px; height: 40px; }
}
@media (prefers-reduced-motion: reduce) { .message-actions { transition: none; } }

/* Keep commands and live execution details comfortably readable without
   changing the conversation structure or adding another surface layer. */
.execution-plan-card {
  margin-top: 14px;
}

.execution-plan-disclosure {
  min-height: 44px;
  padding: 8px 16px;
}

.execution-plan-list li {
  gap: 12px;
  padding: 12px 16px;
}

.execution-plan-list li > div {
  gap: 4px;
}

.plan-approval {
  padding: 14px 16px;
  gap: 14px 20px;
}

.plan-approval-actions {
  gap: 10px;
}

.execution-plan-footer {
  padding: 12px 16px;
}

.agent-event-details {
  margin-top: 10px;
}

.agent-event-details > summary,
.traffic-reference-card summary,
.copilot-reference-card summary {
  display: flex;
  min-height: 32px;
  align-items: center;
  padding-top: 8px;
  padding-bottom: 2px;
  font-size: 11px;
  line-height: 1.45;
}

.agent-event-list {
  margin-top: 10px;
}

.agent-event-list li {
  gap: 10px;
  padding: 10px 0;
}

.agent-event-list li > span {
  display: inline-flex;
  min-width: 58px;
  min-height: 24px;
  align-items: center;
  justify-content: center;
  padding: 3px 8px;
  font-size: 10px;
}

.agent-event-list li > div {
  gap: 4px;
}

.agent-event-list li strong {
  font-size: 11px;
  line-height: 1.45;
}

.agent-event-list li small {
  font-size: 10px;
  line-height: 1.5;
}

.agent-event-list li code {
  max-height: 100px;
  padding: 8px 9px;
  font-size: 10px;
  line-height: 1.55;
}

.composer-quote button {
  width: 32px;
  height: 32px;
}

.quick-actions {
  gap: 12px;
  margin-top: 18px;
}

.quick-actions button {
  min-height: 76px;
  gap: 12px;
  padding: 14px 16px;
}

@media (max-width: 760px) {
  .chat-header-actions {
    gap: 8px;
  }

  .execution-plan-list li {
    grid-template-columns: 20px minmax(0, 1fr);
  }

  .execution-plan-list li .plan-step-status,
  .agent-event-list li > small {
    grid-column: 2;
    padding-top: 0;
  }

  .agent-event-list li {
    grid-template-columns: auto minmax(0, 1fr);
  }
}

/* Icon-only controls use an explicit square box so the SVG optical centre and
   the hover/focus surface stay aligned at every Windows DPI scale. */
.chat-header-actions .header-icon-button,
.desktop-v2-native-frame
  .chat-page
  .chat-header-actions
  .header-icon-button {
  display: inline-grid;
  box-sizing: border-box;
  width: 36px;
  min-width: 36px;
  height: 36px;
  flex: 0 0 36px;
  padding: 0;
  place-items: center;
  line-height: 0;
}
.chat-header-actions .header-icon-button .el-icon {
  display: grid;
  width: 18px;
  height: 18px;
  place-items: center;
  font-size: 16px;
  line-height: 0;
}
.chat-header-actions .header-icon-button :deep(.fluent-system-icon),
.desktop-v2-native-frame
  .chat-page
  .chat-header-actions
  .header-icon-button
  :deep(.fluent-system-icon) {
  display: block;
  width: 16px;
  height: 16px;
  margin: 0;
  font-size: 16px;
  vertical-align: 0;
}
.chat-welcome .welcome-mark {
  display: inline-grid;
  box-sizing: border-box;
  width: 48px;
  min-width: 48px;
  max-width: 48px;
  height: 48px;
  min-height: 48px;
  max-height: 48px;
  flex: 0 0 48px;
  padding: 0;
  place-items: center;
  overflow: hidden;
  border: 1px solid color-mix(in srgb, var(--app-accent) 28%, var(--app-border));
  border-radius: 12px;
  background: var(--app-accent-soft);
}
.chat-welcome .welcome-mark .el-icon {
  display: grid;
  width: 24px;
  height: 24px;
  place-items: center;
  font-size: 24px;
  line-height: 1;
}
.execution-plan-card :deep(.el-progress-bar__inner) {
  transition: width 0.18s linear;
}

.welcome-composer {
  background: color-mix(in srgb, var(--app-surface-strong) 84%, transparent);
}

@media (max-width: 760px) {
  .composer-footer {
    grid-template-columns: minmax(0, 1fr) 36px;
  }

  .composer-footer .target-picker {
    grid-column: 1 / -1;
  }

  .composer-footer > .el-switch {
    grid-column: 1;
    justify-self: start;
  }

  .composer-shortcut {
    display: none;
  }

  .composer-footer .send-button {
    grid-column: 2;
  }
}
/* Keep the plan in the message flow; approval plans open by default. The
   disclosure is the card header, so it keeps the card's own 44px row height
   instead of collapsing into a bare text link. */
.execution-plan-card {
  width: 100%;
  margin-top: 4px;
}
.execution-plan-disclosure:focus-visible {
  outline: 2px solid var(--app-text);
  outline-offset: -2px;
}

/* 对话轮次导航条（DSH 风格右侧小横条快速跳转） */
.chat-conversation-body {
  position: relative;
  min-height: 0;
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.chat-message {
  scroll-margin-top: 18px;
}

.chat-message.is-turn-jump-highlight {
  animation: turnMessageHighlight 1.8s cubic-bezier(0.2, 0.8, 0.2, 1);
  border-radius: 10px;
}

@keyframes turnMessageHighlight {
  0% {
    background-color: color-mix(in srgb, var(--app-accent, #3b82f6) 24%, transparent);
    box-shadow: 0 0 0 6px color-mix(in srgb, var(--app-accent, #3b82f6) 24%, transparent);
  }
  60% {
    background-color: color-mix(in srgb, var(--app-accent, #3b82f6) 12%, transparent);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--app-accent, #3b82f6) 12%, transparent);
  }
  100% {
    background-color: transparent;
    box-shadow: none;
  }
}

.turn-rail {
  position: absolute;
  right: 14px;
  top: 50%;
  transform: translateY(-50%);
  z-index: 15;
  pointer-events: auto;
  user-select: none;
}

.turn-rail-track {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 5px;
  padding: 8px 4px;
  max-height: min(440px, calc(100vh - 280px));
  overflow-y: auto;
  overscroll-behavior: contain;
  scrollbar-width: none;
}
.turn-rail-track::-webkit-scrollbar {
  display: none;
}

.turn-rail-mark {
  all: unset;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  width: 28px;
  height: 12px;
  cursor: pointer;
  padding: 0;
  border-radius: 4px;
}

.turn-rail-bar {
  display: block;
  width: 14px;
  height: 2.5px;
  border-radius: 2px;
  background: var(--app-border, #cbd5e1);
  opacity: 0.65;
  transform-origin: right center;
  transition: width 0.16s cubic-bezier(0.2, 0, 0, 1),
              height 0.16s ease,
              background-color 0.16s ease,
              opacity 0.16s ease,
              box-shadow 0.16s ease;
}

.turn-rail-mark:hover .turn-rail-bar {
  width: 22px;
  height: 3px;
  background: var(--app-accent, #3b82f6);
  opacity: 0.95;
}

.turn-rail-mark.is-active .turn-rail-bar {
  width: 24px;
  height: 3px;
  background: var(--app-accent, #0066cc);
  opacity: 1;
  box-shadow: 0 0 6px color-mix(in srgb, var(--app-accent, #0066cc) 40%, transparent);
}

.turn-rail-mark.is-target .turn-rail-bar {
  width: 26px;
  height: 3.5px;
  background: var(--app-accent, #0066cc);
  opacity: 1;
  animation: turnBarPulse 1.2s ease-in-out infinite;
}

@keyframes turnBarPulse {
  0%, 100% { transform: scaleY(1); opacity: 0.85; }
  50% { transform: scaleY(1.3); opacity: 1; }
}

.turn-tooltip-content {
  max-width: 250px;
  line-height: 1.4;
}

.turn-tooltip-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
  margin-bottom: 4px;
}

.turn-tooltip-header strong {
  font-size: 12px;
  font-weight: 600;
  color: var(--app-text, #111827);
}

.turn-tooltip-header span {
  font-size: 10px;
  color: var(--app-muted, #6b7280);
}

.turn-tooltip-body {
  font-size: 11px;
  color: var(--app-text-secondary, #4b5563);
  word-break: break-word;
  white-space: pre-wrap;
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
  text-overflow: ellipsis;
}

.turn-tooltip-tip {
  margin-top: 6px;
  font-size: 10px;
  color: var(--app-accent, #3b82f6);
  opacity: 0.85;
}

:global(.turn-rail-tooltip) {
  padding: 8px 12px !important;
  border-radius: 8px !important;
  background: var(--app-surface, #ffffff) !important;
  color: var(--app-text, #111827) !important;
  border: 1px solid var(--app-border, #e5e7eb) !important;
  box-shadow: var(--app-shadow, 0 4px 16px rgba(0, 0, 0, 0.12)) !important;
  max-width: 280px !important;
}

:global(.turn-rail-tooltip .el-popper__arrow::before) {
  background: var(--app-surface, #ffffff) !important;
  border-color: var(--app-border, #e5e7eb) !important;
}

@media (max-width: 768px) {
  .turn-rail {
    display: none;
  }
}

/* DSH 同款底部性能与用量统计栏 */
/* 上下等间距：本栏与上方提示语、下方卡片底边的视觉间距必须相等。
     上方间距 = 提示语下方行高半行距 + 本栏 padding-top；
     下方间距 = 本栏 padding-bottom + .chat-composer-wrap 的 padding-bottom。
   改任何一个都要重新配平另外两个（含 .composer-hint 的 margin-top）。
   当前配平值（headless Edge 实测）：
     提示语上方 9px = 7（margin-top）+ 2（提示语行高半行距）
     提示语下方 8.5px = 2（提示语行高半行距）+ 6（padding-top）+ 0.5（pill 行高余量）
     栏底 10.5px = 4 + 5 + 0.5（pill 行高余量） */
.composer-stats-bar {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 16px;
  padding: 6px 0 4px;
  user-select: none;
}

.stats-pill {
  all: unset;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--app-muted, #6b7280);
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 6px;
  transition: color 0.14s ease, background-color 0.14s ease;
  line-height: 1;
}

.stats-pill:hover {
  color: var(--app-text, #111827);
  background-color: var(--app-surface-soft, rgba(0, 0, 0, 0.04));
}

.pill-icon {
  display: inline-block;
  width: 14px;
  height: 14px;
  background-color: currentColor;
  mask-size: contain;
  mask-repeat: no-repeat;
  mask-position: center;
  -webkit-mask-size: contain;
  -webkit-mask-repeat: no-repeat;
  -webkit-mask-position: center;
  flex-shrink: 0;
}

.pill-sep {
  opacity: 0.45;
  margin: 0 1px;
}

.context-ring {
  flex-shrink: 0;
  color: var(--app-muted, #6b7280);
  transition: color 0.14s ease;
}

.stats-pill:hover .context-ring {
  color: var(--app-text, #111827);
}

.context-ring-meter {
  transition: stroke-dashoffset 0.3s ease;
  color: var(--app-accent, #3b82f6);
}

/* 状态统计弹窗样式 */
:global(.stats-pill-popover) {
  padding: 12px 14px !important;
  border-radius: 10px !important;
  background: var(--app-surface, #ffffff) !important;
  border: 1px solid var(--app-border, #e5e7eb) !important;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.12) !important;
}

.stats-popover-content {
  font-size: 12px;
  color: var(--app-text, #111827);
  line-height: 1.5;
}

.stats-popover-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 8px;
}

.stats-popover-title-left {
  display: flex;
  align-items: center;
  gap: 6px;
}

.stats-popover-title strong {
  font-size: 13px;
  font-weight: 600;
}

.stats-popover-title-val {
  font-size: 12px;
  font-weight: 600;
  color: var(--app-accent, #3b82f6);
}

.stats-popover-divider {
  height: 1px;
  background: var(--app-border, #e5e7eb);
  margin-bottom: 8px;
}

.stats-popover-details {
  display: grid;
  grid-template-columns: auto auto;
  justify-content: space-between;
  row-gap: 5px;
  column-gap: 16px;
  margin: 0;
  padding: 0;
}

.stats-popover-details dt {
  color: var(--app-muted, #6b7280);
  font-size: 11px;
}

.stats-popover-details dd {
  margin: 0;
  text-align: right;
  font-weight: 500;
  font-size: 11px;
  color: var(--app-text, #111827);
}

@media (max-width: 640px) {
  .composer-stats-bar {
    gap: 8px;
    flex-wrap: wrap;
  }
  .stats-pill {
    font-size: 11px;
    padding: 3px 6px;
  }
}
</style>
