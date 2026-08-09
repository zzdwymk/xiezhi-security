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
  ArrowRight,
  ChatDotRound,
  CircleCheck,
  Connection,
  Delete,
  Dismiss,
  DocumentChecked,
  FolderOpened,
  List,
  Plus,
  Promotion,
  Refresh,
  Tickets,
  Warning,
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
  type ProjectTarget,
  type ProjectTaskRecord,
  type Target,
  type TaskProgressEvent,
} from "../api";
import {
  useConversationStore,
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
import { toErrorMessage } from "../utils/errorMessage";
import type { CopilotDraft, CopilotReference } from "../types/copilot";
import { renderMarkdown } from "../utils/markdown";
import {
  taskProgressIndeterminate,
  taskProgressPercentage,
} from "../utils/taskProgress";

interface TaskRow {
  id: number;
  targetId: number;
  toolCode: string;
  status: string;
  progress: number;
  progressDeterminate?: boolean;
  progressCompleted?: number;
  progressTotal?: number;
  progressMessage?: string;
  executionLog?: string;
  createdAt: string;
}

const TERMINAL_STATUSES = new Set([
  "SUCCESS",
  "FAILED",
  "TIMEOUT",
  "REJECTED",
  "CANCELLED",
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
const quotedMessage = ref<ConversationMessage>();
const loading = ref(false);
const sending = ref(false);
const messagesElement = ref<HTMLElement>();
const answeringMessages = new Set<string>();
const retryingMessageIds = ref(new Set<string>());
const activeDraft = ref<CopilotDraft>();
let pollTimer: ReturnType<typeof setInterval> | undefined;
let stopTaskFeed: (() => void) | undefined;

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

// Keep the existing welcome composition, but make the implemented workspaces
// discoverable without requiring users to infer routes from the sidebar.
const capabilityCards = [
  {
    label: "评估项目",
    description: "授权范围、目标、任务和项目报告",
    path: "/projects",
    icon: FolderOpened,
    tone: "teal",
  },
  {
    label: "授权目标",
    description: "登记目标与允许端口范围",
    path: "/targets",
    icon: Aim,
    tone: "blue",
  },
  {
    label: "探测与信息收集",
    description: "指纹、WAF、域名与网络证据",
    path: "/recon",
    icon: Connection,
    tone: "violet",
  },
  {
    label: "红队工作流",
    description: "手动连线并编排并行评估阶段",
    path: "/workflow",
    icon: Promotion,
    tone: "indigo",
  },
  {
    label: "任务控制中心",
    description: "实时进度、命令日志、取消与重试",
    path: "/tasks",
    icon: List,
    tone: "amber",
  },
  {
    label: "漏洞复测与扫描 Diff",
    description: "复测发现并比较两次扫描",
    path: "/findings",
    icon: Warning,
    tone: "red",
  },
  {
    label: "项目报告",
    description: "导出项目级 PDF 总结报告",
    path: "/projects",
    icon: DocumentChecked,
    tone: "green",
  },
  {
    label: "审批与审计",
    description: "查看授权守卫与操作审计记录",
    path: "/audits",
    icon: Tickets,
    tone: "slate",
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

function displayAgentValue(value: unknown, limit = 1600) {
  if (value === undefined || value === null) return "";
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}

function agentEventLabel(event: ConversationAgentEvent) {
  const publicLabels: Record<string, string> = {
    ROUTING: "路由中",
    RETRIEVING: "检索中",
    GROUNDED: "已形成依据",
    WAITING_APPROVAL: "等待审批",
    EXECUTING: "执行中",
    REVIEWED: "已复核",
    FAILED: "失败",
  };
  if (event.publicNodeStatus)
    return publicLabels[event.publicNodeStatus] || event.publicNodeStatus;
  if (event.type === "approval") {
    const status = String(
      event.approvalStatus || event.status || "",
    ).toUpperCase();
    if (status.includes("CONFIRMED")) return "已确认执行";
    if (status === "NOT_REQUIRED") return "无需审批";
    return "等待确认";
  }
  const labels: Record<string, string> = {
    route: "意图路由",
    evidence: "项目证据",
    rewrite: "查询改写",
    plan: "计划",
    step: "步骤",
    tool_call: "工具调用",
    tool_result: "工具结果",
    state: "状态",
    guard: "授权校验",
    review: "结果复核",
    retry: "重试",
    citation: "引用",
    done: "完成",
    error: "错误",
  };
  return labels[event.type] || event.type;
}

function agentEventClass(event: ConversationAgentEvent) {
  if (event.publicNodeStatus === "FAILED") return "failed";
  if (event.publicNodeStatus === "WAITING_APPROVAL") return "approval";
  if (event.publicNodeStatus === "REVIEWED") return "success";
  if (
    ["ROUTING", "RETRIEVING", "EXECUTING"].includes(
      event.publicNodeStatus || "",
    )
  )
    return "running";
  if (
    event.type === "error" ||
    event.status === "failed" ||
    event.status === "rejected"
  )
    return "failed";
  if (
    event.type === "approval" ||
    event.status === "awaiting_approval" ||
    event.approvalStatus === "PENDING"
  )
    return "approval";
  if (
    event.type === "done" ||
    event.status === "success" ||
    event.status === "completed"
  )
    return "success";
  if (
    event.type === "tool_call" ||
    event.type === "retry" ||
    event.status === "running"
  )
    return "running";
  return "pending";
}

function taskState(message: ConversationMessage) {
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
      label: "已回答",
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
    ["FAILED", "TIMEOUT", "REJECTED", "CANCELLED"].includes(item.status),
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
    const progress = Math.max(0, Math.min(100, Number(step?.progress) || 0));
    if (["success", "completed", "done"].includes(status))
      return {
        state: "success" as PlanStepVisualState,
        label: "已完成",
        progress: 100,
        indeterminate: false,
      };
    if (
      ["failed", "error", "rejected", "cancelled", "timeout"].includes(status)
    )
      return {
        state: "failed" as PlanStepVisualState,
        label: status === "timeout" ? "已超时" : "失败",
        progress,
        indeterminate: false,
      };
    if (["running", "executing", "in_progress"].includes(status))
      return {
        state: "running" as PlanStepVisualState,
        label: progress ? `执行中 ${progress}%` : "执行中",
        progress,
        indeterminate: progress <= 0,
      };
    if (
      ["awaiting_approval", "approval_required", "pending_approval"].includes(
        status,
      )
    )
      return {
        state: "pending" as PlanStepVisualState,
        label: "等待审批",
        progress,
        indeterminate: false,
      };
    return {
      state: "pending" as PlanStepVisualState,
      label: taskId ? "等待状态" : "等待执行",
      progress,
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
      label: task.progressDeterminate
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

function planProgress(message: ConversationMessage) {
  if (!message.steps.length) return 0;
  return Math.round(
    message.steps.reduce(
      (sum, _, index) => sum + planStepState(message, index).progress,
      0,
    ) / message.steps.length,
  );
}

function planProgressIndeterminate(message: ConversationMessage) {
  if (!message.steps.length) return false;
  return message.steps.some((_, index) => {
    const state = planStepState(message, index);
    return state.state === "running" && state.indeterminate;
  });
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
  const content = `${quote}${message.content}`;
  return context ? `${content}\n\n${context}` : content;
}

function quoteMessage(message: ConversationMessage) {
  quotedMessage.value = message;
  focusComposer();
}

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

function visibleAgentEvents(message: ConversationMessage) {
  const collapsed: ConversationAgentEvent[] = [];
  for (const event of (message.agentEvents || []).filter(isEssentialAgentEvent)) {
    const previous = collapsed[collapsed.length - 1];
    if (
      previous &&
      previous.outerNodeId === event.outerNodeId &&
      previous.nodeRunId === event.nodeRunId &&
      previous.publicNodeStatus === event.publicNodeStatus
    ) {
      collapsed[collapsed.length - 1] = event;
    } else {
      collapsed.push(event);
    }
  }
  return collapsed.slice(-8);
}

/** The public UI treats LedgerAgent as one black-box node. Internal graph steps are never shown. */
function isEssentialAgentEvent(event: ConversationAgentEvent) {
  return Boolean(event.publicNodeStatus);
}

function publicNodeDetail(event: ConversationAgentEvent) {
  const details = [
    event.actionCount !== undefined ? `${event.actionCount} 个动作` : "",
    event.evidenceCount !== undefined ? `${event.evidenceCount} 条证据引用` : "",
    event.taskIds?.length ? `任务 ${event.taskIds.join(", ")}` : "",
    event.terminationReason ? `终止原因：${event.terminationReason}` : "",
    event.recoverable !== undefined
      ? event.recoverable
        ? "可恢复"
        : "不可恢复"
      : event.publicNodeStatus === "FAILED"
        ? "恢复资格待服务端确认"
        : "",
  ].filter(Boolean);
  return details.join(" · ") || "状态已由安全 Harness 校验";
}

function genericReferencePrompt(reference: CopilotReference) {
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
  const latest = entries[entries.length - 1];
  const history = entries.slice(0, -1).join("\n").slice(-12000);
  return `这是同一授权目标下的连续对话，请结合上下文理解用户当前要求。\n${history}${history ? "\n" : ""}${latest}`;
}

async function scrollToBottom() {
  await nextTick();
  const element = messagesElement.value;
  if (element) element.scrollTop = element.scrollHeight;
}

function eventStepIndex(message: ConversationMessage, event: AgentStreamEvent) {
  if (event.workflowNodeId) {
    const byWorkflowNode = message.steps.findIndex(
      (step) => step.workflowNodeId === String(event.workflowNodeId),
    );
    if (byWorkflowNode >= 0) return byWorkflowNode;
  }
  if (event.stepIndex !== undefined && Number.isFinite(Number(event.stepIndex)))
    return Number(event.stepIndex);
  if (event.stepId) {
    const byId = message.steps.findIndex(
      (step) =>
        step.id === String(event.stepId) ||
        step.toolCallId === String(event.stepId),
    );
    if (byId >= 0) return byId;
  }
  if (event.toolCallId) {
    const byCall = message.steps.findIndex(
      (step) => step.toolCallId === String(event.toolCallId),
    );
    if (byCall >= 0) return byCall;
  }
  if (event.toolCode) {
    const byTool = message.steps.findIndex(
      (step) => step.toolCode === String(event.toolCode),
    );
    if (byTool >= 0) return byTool;
  }
  if (event.taskId) {
    const byTask = message.steps.findIndex(
      (step) => step.taskId === Number(event.taskId),
    );
    if (byTask >= 0) return byTask;
    const callOrdinal = (message.agentEvents || []).filter(
      (item) => item.type === "tool_call",
    ).length;
    if (callOrdinal < message.steps.length) return callOrdinal;
  }
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

function applyAgentEvent(
  threadId: string,
  messageId: string,
  incoming: AiDispatchStreamEvent,
) {
  const event = normalizeAgentEvent(incoming) as AgentStreamEvent | undefined;
  if (!event) return;
  const thread = conversations.items.find((item) => item.id === threadId);
  const message = thread?.messages.find((item) => item.id === messageId);
  if (!message) return;

  const events = [...(message.agentEvents || [])];
  const eventRecord: ConversationAgentEvent = {
    id: event.id ? String(event.id) : `${Date.now()}-${events.length}`,
    type: event.type,
    stage: event.stage ? String(event.stage) : undefined,
    status: event.status ? String(event.status) : undefined,
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
  };
  const last = events[events.length - 1];
  const duplicate =
    last &&
    last.type === eventRecord.type &&
    last.publicNodeStatus === eventRecord.publicNodeStatus &&
    last.stepId === eventRecord.stepId &&
    last.toolCallId === eventRecord.toolCallId &&
    last.summary === eventRecord.summary &&
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
    steps = rawSteps.map((step, index) => normalizedStep(step, index));
  }
  const index = eventStepIndex({ ...message, steps }, event);
  const stepStatus =
    event.type === "tool_call"
      ? "running"
      : event.type === "tool_result"
        ? event.status === "failed" || event.error
          ? "failed"
          : "success"
        : event.type === "approval"
          ? "awaiting_approval"
          : event.type === "retry"
            ? "running"
            : event.status;
  const hasStepIdentity = Boolean(
    event.stepId ||
    event.toolCode ||
    event.toolName ||
    event.toolCallId ||
    event.taskId,
  );
  if (
    index !== undefined ||
    ["step", "tool_call", "tool_result", "retry"].includes(event.type) ||
    (event.type === "approval" && hasStepIdentity)
  ) {
    const targetIndex = index !== undefined ? index : steps.length;
    if (!steps[targetIndex])
      steps[targetIndex] = normalizedStep(
        event as unknown as Record<string, unknown>,
        targetIndex,
      );
    const current = steps[targetIndex];
    steps[targetIndex] = {
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
    };
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
    event.summary ||
    event.message ||
    (event.type === "tool_call"
      ? `正在调用 ${event.toolName || event.toolCode || "安全工具"}`
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
    retry: "正在准备重新验证",
    completed: "红队评估流程已完成",
  };
  const hasPlanSteps =
    (Array.isArray(event.steps) && event.steps.length > 0) ||
    Boolean(
      event.plan &&
      Array.isArray(event.plan.steps) &&
      event.plan.steps.length > 0,
    );
  const status =
    event.type === "error"
      ? "failed"
      : event.type === "done" && !message.taskIds.length
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
  if (event.type === "error")
    content = toErrorMessage(
      event.message || event.summary,
      "智能体执行失败。",
    ).slice(0, 2000);
  else if (event.type === "done" && event.answer)
    content = String(event.answer);
  else if (progressSummary && ["planning", "running"].includes(status))
    content = stageLabel[stage] || "智能体正在执行并校验任务。";
  conversations.updateMessage(threadId, messageId, {
    status: status as ConversationMessage["status"],
    content,
    agentEvents: events.slice(-100),
    citations: citations.slice(-30),
    steps,
    planningStage:
      event.stage || String(event.node || "") || message.planningStage,
    planningStatus:
      event.type === "plan" && steps.length
        ? `已生成 ${steps.length} 步执行计划`
        : stageLabel[stage] ||
          String(progressSummary || message.planningStatus || ""),
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
    : toErrorMessage(error, "智能体无法派发任务，请检查目标授权范围和后端配置。");
}

async function dispatchConversationMessage(
  thread: ConversationThread,
  userMessage: ConversationMessage,
  assistantMessage: ConversationMessage,
) {
  const requestPrompt = buildContextPrompt(thread, userMessage.id);
  const refs = messageReferences(userMessage);
  const projectId = projectIdForTarget(thread.targetId, thread);
  const workflow = await latestWorkflowIdentity(projectId);
  const data = await dispatchAiStreaming(
    {
      projectId,
      targetId: thread.targetId,
      sessionId: thread.id,
      turnId: userMessage.id,
      ...workflow,
      prompt: requestPrompt,
      execute: true,
      mode: userMessage.copilotMode,
      refs,
    },
    (event) => recordThinkingProgress(thread.id, assistantMessage.id, event),
  );
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
  conversations.updateMessage(thread.id, assistantMessage.id, {
    content:
      data.answer?.trim() ||
      (data.taskCount
        ? `${planSummary || "执行 Plan 已创建。"}\n\n已按授权范围派发 ${data.taskCount} 个任务。我会持续查看执行进度，完成后直接在这里回复检测结论。`
        : planSummary ||
          streamedMessage?.content ||
          "智能体已完成本次处理。"),
    status: data.taskIds.length ? "running" : "completed",
    provider: data.plan.provider,
    taskIds: data.taskIds,
    steps: finalSteps.length ? finalSteps : streamedMessage?.steps || [],
    citations: finalCitations.slice(-30),
    planningStage: "completed",
    planningStatus: data.taskIds.length
      ? "Plan 已创建，正在执行任务"
      : "智能体已完成处理",
  });
  void saveConversationMemory(
    thread,
    userMessage.content,
    data.answer?.trim() || planSummary || streamedMessage?.content || "",
  );
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
  const target = selectedTarget.value;
  if (!target) {
    ElMessage.warning(
      enabledTargets.value.length
        ? "请先选择授权目标"
        : "请先登记并启用一个授权目标",
    );
    return;
  }

  let thread = selectedThread.value;
  if (!thread) {
    thread = conversations.createThread(
      target.id,
      target.name,
      text,
      projectIdForTarget(target.id),
    );
    await router.replace({ path: "/", query: { conversation: thread.id } });
  }

  const userMessage = conversations.appendMessage(thread.id, {
    role: "user",
    content: text,
    status: "completed",
    taskIds: [],
    steps: [],
    references: activeDraft.value?.refs,
    copilotMode: activeDraft.value?.mode,
    quote: quotedMessage.value
      ? {
          messageId: quotedMessage.value.id,
          role: quotedMessage.value.role,
          content: quotedMessage.value.content.slice(0, 4000),
          createdAt: quotedMessage.value.createdAt,
        }
      : undefined,
  });
  if (!userMessage) return;
  clearQuotedMessage();
  const assistantMessage = conversations.appendMessage(thread.id, {
    role: "assistant",
    content:
      "我正在理解你的要求。明确需要执行检测时，我会先生成真实计划；普通问题会直接回答。",
    status: "running",
    taskIds: [],
    steps: [],
    replyToId: userMessage.id,
  });
  if (!assistantMessage) return;

  prompt.value = "";
  sending.value = true;
  void scrollToBottom();
  try {
    await dispatchConversationMessage(thread, userMessage, assistantMessage);
  } catch (error: any) {
    const message = readableConversationError(error);
    conversations.updateMessage(thread.id, assistantMessage.id, {
      content: message,
      status: "failed",
    });
    ElMessage.error(message);
  } finally {
    activeDraft.value = undefined;
    sending.value = false;
    void scrollToBottom();
  }
}

async function retryConversationMessage(message: ConversationMessage) {
  const thread = selectedThread.value;
  if (
    !thread ||
    message.role !== "assistant" ||
    message.status !== "failed" ||
    retryingMessageIds.value.has(message.id)
  )
    return;
  const userMessage = thread.messages.find(
    (item) => item.id === message.replyToId,
  );
  if (!userMessage) {
    ElMessage.error("找不到这次失败请求对应的用户消息，无法重试");
    return;
  }

  const answerRetry = message.taskIds.length > 0;
  retryingMessageIds.value = new Set(retryingMessageIds.value).add(message.id);
  sending.value = true;
  try {
    if (answerRetry) {
      conversations.updateMessage(thread.id, message.id, {
        content: "任务已经结束，正在重新生成检测结论。",
        status: "answering",
      });
      const requestPrompt = buildContextPrompt(thread, userMessage.id);
      const { data } = await endpoints.answerAi({
        projectId: projectIdForTarget(thread.targetId, thread),
        targetId: thread.targetId,
        prompt: requestPrompt,
        taskIds: message.taskIds,
      });      conversations.updateMessage(thread.id, message.id, {
        content: data.answer || data.summary || "任务已经执行完成。",
        status: "completed",
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
        citations: [],
        planningStage: "status",
        planningStatus: "正在核对授权范围",
      });
      await dispatchConversationMessage(thread, userMessage, message);
    }
    ElMessage.success("重试成功");
  } catch (error: any) {
    const errorMessage = readableConversationError(error);
    conversations.updateMessage(thread.id, message.id, {
      content: errorMessage,
      status: "failed",
    });
    ElMessage.error(errorMessage);
  } finally {
    const next = new Set(retryingMessageIds.value);
    next.delete(message.id);
    retryingMessageIds.value = next;
    sending.value = false;
    void scrollToBottom();
  }
}

function handlePromptKeydown(event: KeyboardEvent) {
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
  conversations.updateMessage(thread.id, message.id, { status: "answering" });
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
    });    conversations.updateMessage(thread.id, message.id, { status: "completed" });
    conversations.appendMessage(thread.id, {
      role: "assistant",
      content: data.answer || data.summary || "任务已经执行完成。",
      status: "completed",
      provider: data.provider,
      taskIds: data.taskIds || message.taskIds,
      steps: [],
      citations: data.citations,
      replyToId: message.replyToId,
    });
  } catch (error: any) {
    conversations.updateMessage(thread.id, message.id, { status: "completed" });
    const summaryError = toErrorMessage(
      error,
      "暂时无法生成汇总回答。你可以继续追问，或前往“结果中心”查看详细结果。",
    );
    conversations.appendMessage(thread.id, {
      role: "assistant",
      content: `任务已经结束，但生成检测结论时出现问题：${summaryError}`,
      status: "failed",
      taskIds: message.taskIds,
      steps: [],
      replyToId: message.replyToId,
    });
  } finally {
    answeringMessages.delete(key);
    void scrollToBottom();
  }
}

function reconcileTaskMessages() {
  for (const thread of conversations.items) {
    for (const message of thread.messages) {
      if (
        message.role !== "assistant" ||
        !["running", "answering"].includes(message.status) ||
        !message.taskIds.length
      )
        continue;
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
        createdAt: task.createdAt,
      }))
    : [];
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

function startNewConversation() {
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
    conversations.remove(thread.id);
    await router.replace("/");
  } catch {
    // User cancelled.
  }
}

async function clearConversations() {
  if (!conversations.items.length) return;
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
    conversations.clear();
    await router.replace("/");
  } catch {
    // User cancelled.
  }
}

watch(selectedThread, (thread) => {
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
  () => selectedThread.value?.messages.length,
  () => void scrollToBottom(),
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
onMounted(() => {
  stopTaskFeed = connectTaskEventFeed(applyTaskEvent);
  pollTimer = setInterval(() => void loadTasks(), 10_000);
  focusComposer();
  void load();
  void loadDashboardStats();
});
onBeforeUnmount(() => {
  if (pollTimer) clearInterval(pollTimer);
  stopTaskFeed?.();
});
</script>

<template>
  <div class="chat-page" :class="{ 'has-thread': isConversation }">
    <header class="chat-header">
      <div>
        <strong>{{ selectedThread?.title || "安全助手" }}</strong>
        <span v-if="selectedThread"
          >{{ selectedThread.targetName }} · 连续对话</span
        >
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
        <button type="button" @click="startNewConversation">
          <el-icon><Plus /></el-icon>新对话
        </button>
        <button
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
        <div class="welcome-stat">
          <strong>{{ dashboardStats.targets }}</strong
          ><small>授权目标</small>
        </div>
        <div class="welcome-stat">
          <strong>{{ dashboardStats.running }}</strong
          ><small>进行中任务</small>
        </div>
        <div class="welcome-stat">
          <strong>{{ dashboardStats.findings }}</strong
          ><small>累计发现</small>
        </div>
        <div
          class="welcome-stat"
          :class="{ warn: dashboardStats.critical > 0 }"
        >
          <strong>{{ dashboardStats.critical }}</strong
          ><small>高危发现</small>
        </div>
      </div>

      <div class="welcome-composer">
        <div v-if="activeDraft?.refs.length" class="copilot-draft-refs">
          <span
            v-for="reference in activeDraft.refs"
            :key="`${reference.type}-${reference.id || reference.title || reference.label}`"
            >{{ reference.title || reference.label || reference.type }}</span
          >
        </div>
        <textarea
          ref="composerInputRef"
          v-model="prompt"
          rows="4"
          :disabled="sending"
          placeholder="例如：帮我检查这个目标的全部开放端口，并告诉我哪些服务需要重点关注"
          @keydown="handlePromptKeydown"
        />
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
            >
              <el-option
                v-for="target in enabledTargets"
                :key="target.id"
                :value="target.id"
                :label="target.name"
              >
                <div class="target-option">
                  <span>{{ target.name }}</span
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
          <span>Enter 发送，Shift + Enter 换行</span>
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

      <section
        class="capability-center"
        aria-labelledby="capability-center-title"
      >
        <header class="capability-center-head">
          <div>
            <span class="capability-eyebrow">红队评估闭环</span>
            <h2 id="capability-center-title">
              从授权范围到复测报告，闭环管理安全评估
            </h2>
          </div>
          <p>
            阶段进度、证据与审计上下文贯穿整个项目，所有验证都以授权范围为前提。
          </p>
        </header>

        <div
          class="agent-architecture red-team-loop"
          aria-label="红队安全评估闭环阶段"
        >
          <div class="architecture-node phase-start">
            <span>1</span><strong>启动 / 范围</strong
            ><small>确认授权目标、边界、审批与时间窗口</small>
          </div>
          <i aria-hidden="true"
            ><el-icon><ArrowRight /></el-icon
          ></i>
          <div class="architecture-node phase-recon">
            <span>2</span><strong>侦察</strong
            ><small>收集域名、指纹、WAF 与公开信息</small>
          </div>
          <i aria-hidden="true"
            ><el-icon><ArrowRight /></el-icon
          ></i>
          <div class="architecture-node phase-assets">
            <span>3</span><strong>资产发现</strong
            ><small>枚举子域、端口、服务与关联资产</small>
          </div>
          <i aria-hidden="true"
            ><el-icon><ArrowRight /></el-icon
          ></i>
          <div class="architecture-node phase-validate">
            <span>4</span><strong>漏洞验证</strong
            ><small>按授权范围验证漏洞与证据</small>
          </div>
          <i aria-hidden="true"
            ><el-icon><ArrowRight /></el-icon
          ></i>
          <div class="architecture-node phase-impact">
            <span>5</span><strong>影响评估</strong
            ><small>评估可达性、影响面与业务风险</small>
          </div>
          <i aria-hidden="true"
            ><el-icon><ArrowRight /></el-icon
          ></i>
          <div class="architecture-node phase-retest">
            <span>6</span><strong>复测</strong
            ><small>复核修复状态并比较扫描 Diff</small>
          </div>
          <i aria-hidden="true"
            ><el-icon><ArrowRight /></el-icon
          ></i>
          <div class="architecture-node phase-report">
            <span>7</span><strong>报告 / 结束</strong
            ><small>汇总审计记录、结论与项目报告</small>
          </div>
        </div>

        <div class="capability-grid">
          <button
            v-for="card in capabilityCards"
            :key="card.label"
            type="button"
            class="capability-card"
            :class="`tone-${card.tone}`"
            @click="router.push(card.path)"
          >
            <span class="capability-icon"
              ><el-icon><component :is="card.icon" /></el-icon
            ></span>
            <span class="capability-copy"
              ><strong>{{ card.label }}</strong
              ><small>{{ card.description }}</small></span
            >
            <span class="capability-arrow" aria-hidden="true"
              ><el-icon><ArrowRight /></el-icon
            ></span>
          </button>
        </div>
      </section>
    </section>

    <template v-else>
      <section ref="messagesElement" class="chat-messages">
        <div class="messages-inner">
          <article
            v-for="message in selectedThread.messages"
            :key="message.id"
            class="chat-message"
            :class="message.role"
          >
            <div class="message-avatar">
              {{ message.role === "assistant" ? "助" : "你" }}
            </div>
            <div class="message-column">
              <div class="message-meta">
                <strong>{{
                  message.role === "assistant" ? "安全助手" : "你"
                }}</strong
                ><span>{{ formatTime(message.createdAt) }}</span>
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
                v-if="message.role === 'assistant'"
                class="message-bubble markdown-body"
                v-html="renderMarkdown(message.content)"
              />
              <div v-else class="message-bubble">{{ message.content }}</div>
              <div class="message-actions">
                <button
                  type="button"
                  :disabled="sending"
                  @click="quoteMessage(message)"
                >
                  引用
                </button>
                <button
                  v-if="
                    message.role === 'assistant' && message.status === 'failed'
                  "
                  type="button"
                  :disabled="sending || retryingMessageIds.has(message.id)"
                  @click="retryConversationMessage(message)"
                >
                  <el-icon
                    :class="{ rotating: retryingMessageIds.has(message.id) }"
                    ><Refresh
                  /></el-icon>
                  {{ retryingMessageIds.has(message.id) ? "重试中" : "重试" }}
                </button>
              </div>
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
                      <h4>Request Headers</h4>
                      <pre>{{
                        formatReferenceValue(message.reference.requestHeaders)
                      }}</pre>
                    </article>
                    <article>
                      <h4>Request Body</h4>
                      <pre>{{
                        formatReferenceValue(message.reference.requestBody)
                      }}</pre>
                    </article>
                    <article>
                      <h4>Response Headers</h4>
                      <pre>{{
                        formatReferenceValue(message.reference.responseHeaders)
                      }}</pre>
                    </article>
                    <article>
                      <h4>Response Body</h4>
                      <pre>{{
                        formatReferenceValue(message.reference.responseBody)
                      }}</pre>
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
                    reference.title || reference.label || reference.type
                  }}</span
                  ><code>{{ reference.type }}</code>
                </header>
                <strong v-if="reference.subtitle">{{
                  reference.subtitle
                }}</strong>
                <p v-if="reference.summary">{{ reference.summary }}</p>
                <details
                  v-if="reference.data && Object.keys(reference.data).length"
                >
                  <summary>查看引用详情</summary>
                  <pre>{{ JSON.stringify(reference.data, null, 2) }}</pre>
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
              <section
                v-if="
                  message.role === 'assistant' &&
                  (message.steps.length || visibleAgentEvents(message).length)
                "
                class="execution-plan-card"
              >
                <header v-if="message.steps.length">
                  <div>
                    <strong>执行计划清单</strong
                    ><span
                      >{{ message.steps.length }} 步 ·
                      {{ taskState(message).label }}</span
                    >
                  </div>
                  <button
                    v-if="message.taskIds.length"
                    type="button"
                    @click="router.push('/tasks')"
                  >
                    查看任务
                  </button>
                </header>
                <el-progress
                  v-if="message.steps.length"
                  :percentage="planProgress(message)"
                  :stroke-width="6"
                  :show-text="false"
                  :indeterminate="planProgressIndeterminate(message)"
                  :duration="1.2"
                />
                <ol v-if="message.steps.length" class="execution-plan-list">
                  <li
                    v-for="(step, index) in message.steps"
                    :key="`${message.id}-${step.taskId || step.toolCode}-${index}`"
                    :class="planStepState(message, index).state"
                  >
                    <i
                      ><el-icon
                        v-if="planStepState(message, index).state === 'success'"
                        ><CircleCheck /></el-icon
                      ><template v-else>{{ index + 1 }}</template></i
                    >
                    <div>
                      <strong>{{ step.title }}</strong
                      ><small>{{ step.reason || step.toolCode }}</small
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
                    <span>{{ planStepState(message, index).label }}</span>
                  </li>
                </ol>
                <details
                  v-if="visibleAgentEvents(message).length"
                  class="agent-event-details"
                  open
                >
                  <summary>LedgerAgent 公开节点状态（实时）</summary>
                  <ol class="agent-event-list">
                    <li
                      v-for="(event, eventIndex) in visibleAgentEvents(message)"
                      :key="
                        event.id || `${message.id}-agent-event-${eventIndex}`
                      "
                      :class="agentEventClass(event)"
                    >
                      <span>{{ agentEventLabel(event) }}</span>
                      <div>
                        <strong>
                          LedgerAgent
                          <template v-if="event.outerNodeId">
                            · {{ event.outerNodeId }}
                          </template>
                        </strong>
                        <small>{{ publicNodeDetail(event) }}</small>
                        <small v-if="event.nodeRunId" class="agent-node-run-id">
                          nodeRunId: {{ event.nodeRunId }}
                        </small>
                        <small
                          v-if="event.workflowRevision && event.workflowDigest"
                          class="agent-node-snapshot"
                        >
                          Workflow r{{ event.workflowRevision }} ·
                          {{ event.workflowDigest }}
                        </small>
                      </div>
                      <small v-if="event.ledgerSequence">
                        Ledger #{{ event.ledgerSequence }}
                      </small>
                    </li>
                  </ol>
                </details>
                <details
                  v-if="taskLogs(message)"
                  class="plan-runtime-details"
                  open
                >
                  <summary>实时命令与执行日志</summary>
                  <pre class="task-runtime-log">{{ taskLogs(message) }}</pre>
                </details>
              </section>
            </div>
          </article>
          <div v-if="!selectedThread.messages.length" class="thread-empty">
            开始描述任务，我会在这里持续回复。
          </div>
        </div>
      </section>

      <footer class="chat-composer-wrap">
        <div class="thread-target">
          <span>当前授权目标</span
          ><strong>{{ selectedThread.targetName }}</strong
          ><small>如需更换目标，请新建对话</small>
        </div>
        <div class="thread-composer">
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
          <div v-if="activeDraft?.refs.length" class="copilot-draft-refs">
            <span
              v-for="reference in activeDraft.refs"
              :key="`${reference.type}-${reference.id || reference.title || reference.label}`"
              >{{ reference.title || reference.label || reference.type }}</span
            >
          </div>
          <textarea
            ref="composerInputRef"
            v-model="prompt"
            rows="2"
            :disabled="sending"
            placeholder="继续提问，或告诉我下一步要执行什么"
            @keydown="handlePromptKeydown"
          />
          <el-tooltip content="发送" placement="top" :show-after="350"
            ><button
              type="button"
              aria-label="发送"
              :disabled="sending || !prompt.trim()"
              @click="sendPrompt"
            >
              <el-icon :class="{ rotating: sending }"
                ><Refresh v-if="sending" /><Promotion v-else
              /></el-icon></button
          ></el-tooltip>
        </div>
        <span class="composer-hint"
          >仅调用白名单工具，并严格遵守该目标的授权范围</span
        >
      </footer>
    </template>
  </div>
</template>

<style scoped>
.chat-page {
  display: flex;
  height: 100%;
  min-height: 620px;
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
.chat-header-actions button:hover {
  border-color: var(--app-border);
  background: var(--app-surface-soft);
}
.chat-header-actions button.danger:hover {
  border-color: #efd2d2;
  background: color-mix(in srgb, #b74e4e 10%, transparent);
  color: #b74e4e;
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
  grid-template-columns: minmax(210px, 280px) minmax(0, 1fr) 36px;
  align-items: center;
  gap: 12px;
  padding: 8px 10px 11px 18px;
}
.target-picker {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  gap: 8px;
}
.target-picker > span,
.composer-footer > span {
  color: var(--app-muted);
  font-size: 10px;
}
.target-picker small {
  float: right;
  margin-left: 10px;
  color: var(--app-muted);
}
.composer-footer > span {
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
  background: var(--app-surface-soft);
  color: var(--app-accent);
}
.chat-message.user .message-column {
  grid-column: 1;
  grid-row: 1;
  align-items: flex-end;
}
.message-avatar {
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border-radius: 9px;
  background: var(--app-accent);
  color: var(--app-surface-strong);
  font-size: 10px;
  font-weight: 700;
}
.message-column {
  display: flex;
  min-width: 0;
  flex-direction: column;
  align-items: flex-start;
}
.message-meta {
  display: flex;
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
  padding: 10px 22px 14px;
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
  display: grid;
  grid-template-columns: minmax(0, 1fr) 38px;
  align-items: end;
  gap: 8px;
  padding: 8px 8px 8px 14px;
  border: 1px solid var(--app-border);
  border-radius: 13px;
  background: var(--app-surface-strong);
  box-shadow: 0 4px 16px var(--app-shadow);
}
.thread-composer textarea {
  max-height: 130px;
  min-height: 48px;
  padding: 4px 0;
}
.composer-hint {
  display: block;
  margin-top: 6px;
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
  .composer-footer > span {
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
  .message-avatar {
    width: 28px;
    height: 28px;
  }
  .message-bubble {
    max-width: 96%;
  }
  .chat-composer-wrap {
    padding: 9px 11px 12px;
  }
  .thread-target small {
    display: none;
  }
}
.execution-plan-card {
  width: min(660px, 94%);
  margin-top: 10px;
  padding: 12px 14px;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-soft);
  color: var(--app-text);
  box-shadow: 0 1px 2px color-mix(in srgb, CanvasText 4%, transparent);
}
.execution-plan-card > header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}
.execution-plan-card > header > div {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 3px;
}
.execution-plan-card > header strong {
  font-size: 13px;
}
.execution-plan-card > header span {
  overflow: hidden;
  color: var(--app-muted);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.execution-plan-card > header button {
  border: 0;
  background: transparent;
  color: var(--app-accent);
  font-size: 10px;
  cursor: pointer;
}
.execution-plan-list {
  display: grid;
  gap: 0;
  margin: 11px 0 0;
  padding: 0;
  list-style: none;
}
.execution-plan-list li {
  display: grid;
  grid-template-columns: 25px minmax(0, 1fr) auto;
  align-items: start;
  gap: 9px;
  padding: 10px 2px;
  border-top: 1px solid var(--app-border);
}
.execution-plan-list li > i {
  display: grid;
  width: 21px;
  height: 21px;
  place-items: center;
  border-radius: 50%;
  background: var(--app-surface-strong);
  color: var(--app-muted);
  font-size: 10px;
  font-style: normal;
  font-weight: 700;
}
.execution-plan-list li > div {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 3px;
}
.execution-plan-list li strong {
  font-size: 11px;
}
.execution-plan-list li small {
  overflow: hidden;
  color: var(--app-muted);
  font-size: 9px;
  line-height: 1.45;
  text-overflow: ellipsis;
}
.execution-plan-list li > span {
  padding-top: 3px;
  color: var(--app-muted);
  font-size: 9px;
  white-space: nowrap;
}
.execution-plan-list li.running > i {
  background: var(--app-accent-soft);
  color: var(--app-accent);
  animation: planPulse 1.4s ease-in-out infinite;
}
.execution-plan-list li.running > span {
  color: var(--app-accent);
}
.execution-plan-list li.success > i {
  background: #e3f4ea;
  color: #27815a;
}
.execution-plan-list li.success > span {
  color: #27815a;
}
.execution-plan-list li.failed > i {
  background: #fbe8e8;
  color: #b94040;
}
.execution-plan-list li.failed > span {
  color: #b94040;
}
.execution-plan-list .el-progress {
  margin-top: 4px;
}
.plan-runtime-details {
  margin-top: 4px;
  border-top: 1px solid var(--app-border);
}
.plan-runtime-details summary {
  padding-top: 9px;
  color: var(--app-accent);
  font-size: 10px;
  cursor: pointer;
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
.traffic-reference-packets pre {
  max-height: 180px;
  overflow: auto;
  margin: 0;
  padding: 9px;
  color: var(--app-text);
  font:
    10px/1.55 ui-monospace,
    Consolas,
    monospace;
  white-space: pre-wrap;
  word-break: break-all;
}
@media (max-width: 760px) {
  .traffic-reference-packets {
    grid-template-columns: 1fr;
  }
}
.task-runtime-log {
  max-height: 180px;
  overflow: auto;
  margin: 9px 0 0;
  padding: 8px;
  border: 1px solid var(--app-border);
  border-radius: 6px;
  background: var(--app-surface-soft);
  color: var(--app-accent);
  font:
    10px/1.55 ui-monospace,
    Consolas,
    monospace;
  white-space: pre-wrap;
  word-break: break-word;
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
  background: #111827;
  color: #e5edf7;
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
.copilot-reference-card pre {
  max-height: 220px;
  overflow: auto;
  margin: 0;
  padding: 10px 12px;
  color: var(--app-text);
  font:
    10px/1.55 ui-monospace,
    Consolas,
    monospace;
  white-space: pre-wrap;
  word-break: break-all;
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
  min-width: 0;
  flex-direction: column;
  gap: 3px;
  line-height: 1.25;
}
.target-option span {
  overflow: hidden;
  color: var(--app-text);
  font-size: 12px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.target-option small {
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
.chat-header-actions button:hover,
.create-target:hover {
  border-color: var(--app-border);
  background: var(--app-surface-soft);
}
.chat-header-actions button:active,
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
.welcome-stat.warn strong {
  color: #c8503f;
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
  grid-template-columns: minmax(220px, 290px) minmax(0, 1fr) 36px;
  padding: 8px 10px 10px 18px;
}
.target-picker > span,
.composer-footer > span {
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
.message-avatar {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  font-size: 11px;
  font-weight: 650;
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
.task-runtime-log {
  border-radius: 8px;
}
.chat-composer-wrap {
  padding: 10px 22px 16px;
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
  font-family: "Segoe UI Variable Text", "Segoe UI", sans-serif;
}
:global(.target-picker-popper .el-select-dropdown__item) {
  border-radius: 8px;
  margin: 2px 6px;
  padding-left: 10px;
  padding-right: 10px;
}
:global(.target-picker-popper .el-select-dropdown__item.is-hovering) {
  background: var(--app-surface-soft);
}

/* Fluent 2 capability surface: keep the welcome composition intact while
   making the already-available workspaces visible at a glance. */
.capability-center {
  width: min(980px, 100%);
  margin-top: 24px;
  padding: 18px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface);
  box-shadow: var(--fluent-card-shadow);
  text-align: left;
}
.capability-center-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 18px;
  margin-bottom: 14px;
}
.capability-eyebrow {
  display: block;
  margin-bottom: 4px;
  color: var(--app-accent);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0;
}
.capability-center h2 {
  margin: 0;
  color: var(--app-text);
  font-size: 16px;
  font-weight: 650;
  letter-spacing: 0;
}
.capability-center-head p {
  max-width: 330px;
  margin: 0;
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.5;
  text-align: right;
}
.agent-architecture {
  display: grid;
  grid-template-columns:
    minmax(0, 1fr) auto minmax(0, 1.2fr) auto minmax(0, 1fr)
    auto minmax(0, 1fr);
  align-items: center;
  gap: 8px;
  margin-bottom: 16px;
  padding: 10px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-soft);
}
.architecture-node {
  display: grid;
  min-width: 0;
  grid-template-columns: 24px minmax(0, 1fr);
  align-items: center;
  column-gap: 8px;
  padding: 8px 9px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-strong);
}
.architecture-node > span {
  display: grid;
  width: 22px;
  height: 22px;
  place-items: center;
  border-radius: 50%;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font-size: 10px;
  font-weight: 700;
}
.architecture-node strong,
.architecture-node small {
  grid-column: 2;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.architecture-node strong {
  color: var(--app-text);
  font-size: 11px;
  font-weight: 700;
}
.architecture-node small {
  margin-top: 2px;
  color: var(--app-muted);
  font-size: 9px;
}
.architecture-node.phase-start {
  border-color: color-mix(in srgb, var(--app-accent) 42%, var(--app-border));
  background: var(--app-accent-soft);
}
.architecture-node.phase-start > span {
  background: var(--app-accent);
  color: var(--system-accent-foreground, #fff);
}
.agent-architecture > i {
  color: var(--app-accent);
  font-size: 16px;
  font-style: normal;
  text-align: center;
}
.capability-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}
.capability-card {
  display: grid;
  min-width: 0;
  grid-template-columns: 30px minmax(0, 1fr) 14px;
  align-items: center;
  gap: 8px;
  padding: 10px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-strong);
  color: var(--app-text);
  text-align: left;
  cursor: pointer;
  transition:
    background-color var(--fluent-fast),
    border-color var(--fluent-fast),
    transform var(--fluent-fast),
    box-shadow var(--fluent-fast);
}
.capability-card:hover {
  border-color: color-mix(in srgb, var(--app-accent) 44%, var(--app-border));
  background: var(--app-surface-soft);
  box-shadow: var(--fluent-shadow-2);
  transform: translateY(-1px);
}
.capability-card:focus-visible {
  outline: 2px solid var(--app-accent);
  outline-offset: 2px;
}
.capability-icon {
  display: grid;
  width: 30px;
  height: 30px;
  place-items: center;
  border-radius: var(--fluent-radius-control);
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font-size: 16px;
}
.capability-copy {
  display: flex;
  min-width: 0;
  flex-direction: column;
}
.capability-copy strong {
  overflow: hidden;
  color: var(--app-text);
  font-size: 11px;
  font-weight: 700;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.capability-copy small {
  display: -webkit-box;
  overflow: hidden;
  margin-top: 3px;
  color: var(--app-muted);
  font-size: 9px;
  line-height: 1.35;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}
.capability-arrow {
  color: var(--app-accent);
  font-size: 15px;
  font-weight: 600;
  text-align: center;
}
.capability-card.tone-blue .capability-icon {
  background: color-mix(in srgb, #3178c6 14%, var(--app-surface));
  color: #2767ae;
}
.capability-card.tone-violet .capability-icon {
  background: color-mix(in srgb, #7b61c9 14%, var(--app-surface));
  color: #654bb0;
}
.capability-card.tone-indigo .capability-icon {
  background: color-mix(in srgb, #526bb4 14%, var(--app-surface));
  color: #405b9f;
}
.capability-card.tone-amber .capability-icon {
  background: color-mix(in srgb, #c88c2d 16%, var(--app-surface));
  color: #986719;
}
.capability-card.tone-red .capability-icon {
  background: color-mix(in srgb, #c75757 14%, var(--app-surface));
  color: #a43f3f;
}
.capability-card.tone-green .capability-icon {
  background: color-mix(in srgb, #3b9b70 14%, var(--app-surface));
  color: #277b57;
}
.capability-card.tone-slate .capability-icon {
  background: color-mix(in srgb, #607384 14%, var(--app-surface));
  color: #4b5d6d;
}
.agent-event-details[open] > summary,
.plan-runtime-details[open] > summary {
  font-weight: 700;
}
@media (max-width: 980px) {
  .capability-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .agent-architecture {
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 6px;
  }
  .agent-architecture > i {
    display: none;
  }
  .architecture-node {
    grid-template-columns: 22px minmax(0, 1fr);
    padding: 7px;
  }
}
@media (max-width: 760px) {
  .capability-center {
    padding: 13px;
  }
  .capability-center-head {
    display: block;
  }
  .capability-center-head p {
    max-width: none;
    margin-top: 6px;
    text-align: left;
  }
  .capability-grid {
    grid-template-columns: 1fr;
  }
  .agent-architecture {
    grid-template-columns: 1fr 1fr;
  }
  .architecture-node small {
    font-size: 8px;
  }
}

/* Seven-stage red-team assessment loop. The wide layout keeps the flow on a
 * single line; narrower windows switch to a readable phase grid. */
.red-team-loop {
  display: flex;
  align-items: stretch;
  gap: 6px;
}

.red-team-loop .architecture-node {
  flex: 1 1 0;
  align-content: center;
  align-items: start;
  padding: 8px;
}

.red-team-loop .architecture-node small {
  display: -webkit-box;
  min-height: 2.7em;
  overflow: hidden;
  white-space: normal;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.red-team-loop > i {
  flex: 0 0 auto;
  align-self: center;
}

.red-team-loop .phase-validate > span {
  background: color-mix(in srgb, #c75757 15%, var(--app-surface));
  color: light-dark(#993c3c, #ffb7b7);
}

.red-team-loop .phase-impact > span {
  background: color-mix(in srgb, #c88c2d 17%, var(--app-surface));
  color: light-dark(#875b12, #ffd48a);
}

.red-team-loop .phase-retest > span,
.red-team-loop .phase-report > span {
  background: color-mix(in srgb, #3b9b70 15%, var(--app-surface));
  color: light-dark(#236e4f, #9ee3c4);
}

@media (max-width: 1180px) {
  .red-team-loop {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 8px;
  }

  .red-team-loop > i {
    display: none;
  }
}

@media (max-width: 760px) {
  .red-team-loop {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 520px) {
  .red-team-loop {
    grid-template-columns: 1fr;
  }
}

/* Dashboard layout guardrails
 *
 * The welcome area is a column flex container.  Its composer contains a
 * textarea and a footer, so allowing the item to shrink makes the browser
 * collapse it to a thin strip when the capability center is also visible.
 * Keep the input as a non-shrinking, content-sized surface; the parent can
 * still scroll when the window is shorter than the complete welcome screen.
 */
.chat-welcome .welcome-composer {
  flex: 0 0 auto;
  min-height: 170px;
}

.chat-welcome .welcome-composer textarea {
  box-sizing: border-box;
  height: 112px;
  min-height: 112px;
}

/* Flatten the capability section so it does not read as a card inside a
 * second card. Individual capability actions remain distinct, keyboard
 * focusable surfaces while the architecture row is visually open.
 */
.chat-welcome .capability-center {
  border: 0;
  background: transparent;
  box-shadow: none;
  padding-right: 0;
  padding-left: 0;
}

.chat-welcome .agent-architecture {
  border: 0;
  background: transparent;
  padding-right: 0;
  padding-left: 0;
}

/* Keep labels readable in both light/dark and Windows high-contrast themes. */
.chat-welcome .quick-actions button,
.chat-welcome .capability-card,
.chat-welcome .create-target,
.chat-header-actions button,
.message-actions button,
.execution-plan-card > header button {
  color: var(--app-text);
}

.chat-welcome .quick-actions button strong,
.chat-welcome .capability-card strong {
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

.message-actions button,
.execution-plan-card > header button {
  display: inline-flex;
  min-height: 32px;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 0 10px;
}

.execution-plan-card {
  margin-top: 14px;
  padding: 16px 18px;
}

.execution-plan-card > header {
  gap: 16px;
  margin-bottom: 12px;
}

.execution-plan-card > header span {
  font-size: 11px;
  line-height: 1.45;
}

.execution-plan-card > header button {
  border-radius: var(--fluent-radius-control);
  font-size: 11px;
  font-weight: 600;
}

.execution-plan-card > header button:hover {
  background: var(--app-accent-soft);
}

.execution-plan-list {
  margin-top: 14px;
}

.execution-plan-list li {
  grid-template-columns: 28px minmax(0, 1fr) auto;
  gap: 12px;
  padding: 12px 2px;
}

.execution-plan-list li > i {
  width: 24px;
  height: 24px;
  font-size: 11px;
}

.execution-plan-list li > div {
  gap: 4px;
}

.execution-plan-list li strong {
  font-size: 12px;
  line-height: 1.4;
}

.execution-plan-list li small,
.execution-plan-list li > span {
  font-size: 11px;
  line-height: 1.5;
}

.agent-event-details {
  margin-top: 10px;
}

.agent-event-details > summary,
.plan-runtime-details > summary,
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

.task-runtime-log {
  margin-top: 10px;
  padding: 10px;
  font-size: 11px;
  line-height: 1.6;
}

.composer-quote button {
  width: 32px;
  height: 32px;
}

/* The capability section is already flattened into the page. Increase its
   rhythm and let the seven stages wrap before their labels become cramped. */
.quick-actions {
  gap: 12px;
  margin-top: 18px;
}

.quick-actions button {
  min-height: 76px;
  gap: 12px;
  padding: 14px 16px;
}

.chat-welcome .capability-center {
  margin-top: 30px;
}

.capability-center-head {
  align-items: flex-start;
  gap: 24px;
  margin-bottom: 20px;
}

.capability-center h2 {
  font-size: 18px;
  line-height: 1.4;
}

.capability-center-head p {
  font-size: 12px;
  line-height: 1.6;
}

.chat-welcome .red-team-loop {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 22px;
  padding: 0 0 4px;
}

.red-team-loop > i {
  display: none;
}

.red-team-loop .architecture-node {
  min-height: 88px;
  grid-template-columns: 28px minmax(0, 1fr);
  align-content: center;
  column-gap: 10px;
  padding: 12px;
}

.red-team-loop .architecture-node > span {
  width: 26px;
  height: 26px;
  font-size: 11px;
}

.red-team-loop .architecture-node strong {
  font-size: 12px;
  line-height: 1.4;
}

.red-team-loop .architecture-node small {
  margin-top: 4px;
  font-size: 10px;
  line-height: 1.45;
}

.capability-grid {
  gap: 12px;
}

.capability-card {
  min-height: 78px;
  grid-template-columns: 36px minmax(0, 1fr) 18px;
  gap: 10px;
  padding: 14px;
}

.capability-icon {
  width: 36px;
  height: 36px;
  font-size: 18px;
}

.capability-copy strong {
  font-size: 12px;
  line-height: 1.4;
}

.capability-copy small {
  margin-top: 4px;
  font-size: 10px;
  line-height: 1.45;
}

@media (max-width: 980px) {
  .capability-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 760px) {
  .chat-header-actions {
    gap: 8px;
  }

  .execution-plan-card {
    width: 100%;
    padding: 14px;
  }

  .execution-plan-list li {
    grid-template-columns: 28px minmax(0, 1fr);
  }

  .execution-plan-list li > span,
  .agent-event-list li > small {
    grid-column: 2;
    padding-top: 0;
  }

  .agent-event-list li {
    grid-template-columns: auto minmax(0, 1fr);
  }

  .capability-center-head {
    display: block;
  }

  .chat-welcome .red-team-loop {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .capability-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 520px) {
  .chat-welcome .red-team-loop {
    grid-template-columns: 1fr;
  }
}

/* Icon-only controls use an explicit square box so the SVG optical centre and
   the hover/focus surface stay aligned at every Windows DPI scale. */
.chat-header-actions .header-icon-button {
  display: inline-grid;
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
  line-height: 1;
}
.chat-header-actions .header-icon-button :deep(svg) {
  display: block;
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
</style>
