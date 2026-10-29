import { defineStore } from "pinia";
import { computed, ref } from "vue";
import { endpoints } from "../api";
import type { JudgeVerdictDocument } from "../api";
import type { CopilotReference } from "../types/copilot";
import type { CopilotMode } from "../types/copilot";
import { isPublicAiProgressEvent, publicAiProgressText, publicProgressProvenance } from "../utils/aiPresentation";
import { normalizeAiExecutionDecision, type AiExecutionDecision, type AiExecutionIntent } from "../utils/aiIntent";

export interface ConversationStep {
  id?: string;
  workflowNodeId?: string;
  nodeRunId?: string;
  group?: number;
  dependsOnNodeIds?: string[];
  toolCode: string;
  parameters?: Record<string, unknown>;
  risk?: string;
  title: string;
  reason?: string;
  taskId?: number;
  status?:
    | "pending"
    | "running"
    | "success"
    | "failed"
    | "awaiting_approval"
    | string;
  progress?: number;
  command?: string;
  toolCallId?: string;
  output?: string;
  error?: string;
  attempt?: number;
  maxAttempts?: number;
  requiresApproval?: boolean;
}

export interface ConversationThinkingStep {
  stage: string;
  summary: string;
  createdAt: string;
}

/** Safe, server-authored events emitted by the agent graph.  The client never
 * renders hidden model reasoning; only these bounded summaries are persisted. */
export type ConversationAgentEventType =
  | "route"
  | "evidence"
  | "rewrite"
  | "plan"
  | "step"
  | "tool_call"
  | "tool_result"
  | "approval"
  | "retry"
  | "citation"
  | "done"
  | "error"
  | string;

export interface ConversationCitation {
  id?: string;
  title?: string;
  source?: string;
  url?: string;
  /** Evidence text is never persisted by the UI; only its bounded length is retained. */
  summaryLength?: number;
  locator?: string;
}

export type PublicAgentNodeStatus =
  | "ROUTING"
  | "RETRIEVING"
  | "GROUNDED"
  | "WAITING_APPROVAL"
  | "EXECUTING"
  | "REVIEWED"
  | "FAILED";

export interface ModelUsageSnapshot {
  available: boolean;
  source: "PROVIDER" | "ESTIMATED" | "MIXED" | "UNAVAILABLE";
  model: string;
  modelCalls: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  cachedInputTokens: number;
  cacheHitRatePermille: number | null;
  contextWindowTokens: number;
  contextWindowUsedTokens: number;
  contextWindowUsagePermille: number;
  peakInputTokens: number;
  providerReportedCalls: number;
  estimatedCalls: number;
  cacheReportedCalls: number;
  cacheWriteTokens: number;
  reasoningTokens: number;
  estimatedInputTokens: number;
  lastInputTokens: number;
  contextWindowSource: "MODEL" | "CONFIGURED" | "DEFAULT";
  estimator: string;
}

export interface ConversationAgentEvent {
  id?: string;
  type: ConversationAgentEventType;
  stage?: string;
  status?: string;
  summary?: string;
  message?: string;
  stepId?: string;
  stepIndex?: number;
  toolCode?: string;
  toolName?: string;
  toolCallId?: string;
  taskId?: number;
  command?: string;
  input?: unknown;
  output?: unknown;
  attempt?: number;
  maxAttempts?: number;
  approvalId?: string;
  approvalStatus?: string;
  executionDecision?: AiExecutionDecision;
  citation?: ConversationCitation;
  contractVersion?: number;
  runId?: string;
  workflowId?: string;
  workflowRevision?: number;
  workflowDigest?: string;
  workflowNodeId?: string;
  outerNodeId?: string;
  nodeRunId?: string;
  publicNodeStatus?: PublicAgentNodeStatus;
  innerStep?: string;
  ledgerSequence?: number;
  ledgerEntryDigest?: string;
  ledgerDigest?: string;
  terminationReason?: string;
  evidenceCount?: number;
  source?: string;
  assessmentSource?: string;
  modelDecision?: string;
  evidenceDecision?: string;
  reasonCodes?: string[];
  guardReason?: string;
  actionCount?: number;
  taskIds?: number[];
  recoverable?: boolean;
  recorded?: boolean;
  eventTiming?: string;
  createdAt?: string;
  modelUsage?: ModelUsageSnapshot;
}

export type ConversationMessageRole = "user" | "assistant";
export type ConversationMessageStatus =
  | "sending"
  | "planning"
  | "running"
  | "answering"
  | "completed"
  | "failed";

export interface TrafficConversationReference {
  type: "traffic-session";
  packetId: string;
  sessionId?: string;
  targetId?: number;
  method: string;
  url: string;
  host?: string;
  port?: number;
  path?: string;
  statusCode?: number;
  contentType?: string;
  durationMs?: number;
  riskLevel?: string;
  createdAt?: string;
  requestHeaders?: string;
  responseHeaders?: string;
  requestBody?: string;
  responseBody?: string;
}

export type ConversationReference =
  | TrafficConversationReference
  | CopilotReference;

export interface ConversationMessage {
  id: string;
  role: ConversationMessageRole;
  content: string;
  status: ConversationMessageStatus;
  provider?: string;
  taskIds: number[];
  steps: ConversationStep[];
  thinking?: ConversationThinkingStep[];
  agentEvents?: ConversationAgentEvent[];
  modelUsage?: ModelUsageSnapshot;
  citations?: ConversationCitation[];
  planningStage?: string;
  planningStatus?: string;
  progressStartedAt?: string;
  progressFinishedAt?: string;
  modelStreamStatus?: "running" | "completed" | "failed" | "interrupted";
  /** True after the user has opened this thread's latest completed turn. */
  completionSeen?: boolean;
  reference?: ConversationReference;
  references?: ConversationReference[];
  copilotMode?: CopilotMode;
  executionRequested?: boolean;
  executionIntent?: AiExecutionIntent;
  executionDecision?: AiExecutionDecision;
  approvalId?: number | string;
  approvalStatus?: string;
  /** Semantic-judge verdict document attached to this approval, when available. */
  judge?: JudgeVerdictDocument | null;
  replyToId?: string;
  /** Execution request state is separate from the model answer and approval decision. */
  approvalDispatchStatus?: "dispatching" | "rejected" | "unknown" | "dispatched";
  approvalDispatchError?: string;
  approvalDispatchUpdatedAt?: string;
  quote?: {
    messageId: string;
    role: ConversationMessageRole;
    content: string;
    createdAt: string;
  };
  createdAt: string;
  updatedAt: string;
}

export interface ConversationThread {
  id: string;
  branchSource?: { threadId: string; messageId: string };
  title: string;
  projectId?: number;
  targetId: number;
  targetName: string;
  targetIds?: number[];
  scopeMode?: "SINGLE" | "PROJECT_ALL" | "PROJECT_SUBSET";
  messages: ConversationMessage[];
  createdAt: string;
  updatedAt: string;
}

interface LegacyConversationRecord {
  id: string;
  prompt: string;
  targetId: number;
  targetName: string;
  summary: string;
  provider: string;
  taskIds: number[];
  steps: ConversationStep[];
  createdAt: string;
}

const STORAGE_KEY = "security_toolbox_ai_conversations_v2";
const LEGACY_STORAGE_KEY = "security_toolbox_ai_conversations_v1";
const MAX_STORAGE_CHARS = 4_500_000;
const MAX_CONVERSATIONS = 100;

export class ConversationStorageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConversationStorageError";
  }
}

type NewConversationMessage = Omit<ConversationMessage, "id" | "createdAt" | "updatedAt">;

function createId() {
  return (
    globalThis.crypto?.randomUUID?.() ||
    `${Date.now()}-${Math.random().toString(16).slice(2)}`
  );
}

function titleFromPrompt(prompt: string) {
  const title = prompt.replace(/\s+/g, " ").trim();
  return title.length > 28 ? `${title.slice(0, 28)}…` : title || "新对话";
}

function migrateLegacy(
  items: LegacyConversationRecord[],
): ConversationThread[] {
  return items.map((item) => {
    const createdAt = item.createdAt || new Date().toISOString();
    const userId = createId();
    return {
      id: item.id || createId(),
      title: titleFromPrompt(item.prompt),
      targetId: item.targetId,
      targetName: item.targetName,
      createdAt,
      updatedAt: createdAt,
      messages: [
        {
          id: userId,
          role: "user",
          content: item.prompt,
          status: "completed",
          taskIds: [],
          steps: [],
          createdAt,
          updatedAt: createdAt,
        },
        {
          id: createId(),
          role: "assistant",
          content: item.summary,
          status: item.taskIds?.length ? "running" : "completed",
          provider: item.provider,
          taskIds: item.taskIds || [],
          steps: item.steps || [],
          replyToId: userId,
          createdAt,
          updatedAt: createdAt,
        },
      ],
    };
  });
}

function loadConversations(): ConversationThread[] {
  try {
    const currentRaw = localStorage.getItem(STORAGE_KEY);
    if (currentRaw !== null) {
      const current = JSON.parse(currentRaw);
      return Array.isArray(current)
        ? normalizeConversations(current as ConversationThread[])
        : [];
    }
    const legacy = JSON.parse(localStorage.getItem(LEGACY_STORAGE_KEY) || "[]");
    return Array.isArray(legacy)
      ? normalizeConversations(migrateLegacy(legacy as LegacyConversationRecord[]))
      : [];
  } catch {
    return [];
  }
}

function finiteNumber(value: unknown) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : undefined;
}

function sanitizeStoredModelUsage(value: ModelUsageSnapshot | undefined): ModelUsageSnapshot | undefined {
  if (!value || typeof value !== "object" || typeof value.available !== "boolean") return undefined;
  const bounded = (number: unknown, max = 4_000_000_000) =>
    typeof number === "number" && Number.isInteger(number) && number >= 0 && number <= max ? number : undefined;
  const source = ["PROVIDER", "ESTIMATED", "MIXED", "UNAVAILABLE"].includes(value.source) ? value.source : undefined;
  const calls = bounded(value.modelCalls, 10_000);
  const input = bounded(value.inputTokens);
  const output = bounded(value.outputTokens);
  const total = bounded(value.totalTokens);
  const cached = bounded(value.cachedInputTokens);
  const contextTokens = bounded(value.contextWindowTokens);
  const contextUsed = bounded(value.contextWindowUsedTokens);
  const contextRate = bounded(value.contextWindowUsagePermille, 1000);
  const peak = bounded(value.peakInputTokens);
  const cacheRate = value.cacheHitRatePermille === null ? null : bounded(value.cacheHitRatePermille, 1000);
  const providerCalls = bounded(value.providerReportedCalls, 10_000);
  const estimatedCalls = bounded(value.estimatedCalls, 10_000);
  const cacheCalls = bounded(value.cacheReportedCalls, 10_000);
  const cacheWrites = bounded(value.cacheWriteTokens);
  const reasoning = bounded(value.reasoningTokens);
  const estimatedInput = bounded(value.estimatedInputTokens);
  const lastInput = bounded(value.lastInputTokens);
  const contextSource = ["MODEL", "CONFIGURED", "DEFAULT"].includes(value.contextWindowSource)
    ? value.contextWindowSource as ModelUsageSnapshot["contextWindowSource"] : undefined;
  if (!source || calls === undefined || input === undefined || output === undefined || total === undefined
    || cached === undefined || contextTokens === undefined || contextUsed === undefined
    || contextRate === undefined || peak === undefined || cacheRate === undefined
    || providerCalls === undefined || estimatedCalls === undefined || cacheCalls === undefined
    || cacheWrites === undefined || reasoning === undefined || estimatedInput === undefined || lastInput === undefined
    || !contextSource || typeof value.estimator !== "string" || value.estimator.length > 32
    || typeof value.model !== "string" || value.model.length > 120) return undefined;
  return {
    available: value.available, source, model: value.model, modelCalls: calls,
    inputTokens: input, outputTokens: output, totalTokens: total, cachedInputTokens: cached,
    cacheHitRatePermille: cacheRate, contextWindowTokens: contextTokens, contextWindowUsedTokens: contextUsed,
    contextWindowUsagePermille: contextRate, peakInputTokens: peak,
    providerReportedCalls: providerCalls, estimatedCalls, cacheReportedCalls: cacheCalls,
    cacheWriteTokens: cacheWrites, reasoningTokens: reasoning, estimatedInputTokens: estimatedInput,
    lastInputTokens: lastInput, contextWindowSource: contextSource, estimator: value.estimator,
  };
}

function sanitizeStoredCitation(value: ConversationCitation & { snippet?: unknown }) {
  return {
    id: value.id,
    title: value.title,
    source: value.source,
    url: value.url,
    locator: value.locator,
    summaryLength:
      finiteNumber(value.summaryLength) ??
      (typeof value.snippet === "string" ? value.snippet.length : 0),
  } satisfies ConversationCitation;
}

function sanitizeStoredAgentEvent(event: ConversationAgentEvent) {
  return {
    ...publicProgressProvenance({ ...event }),
    id: event.id,
    type: event.type,
    stage: event.stage,
    summary: isPublicAiProgressEvent(event) ? publicAiProgressText(event.summary || event.message) || undefined : undefined,
    status: event.status,
    stepId: event.stepId,
    stepIndex: finiteNumber(event.stepIndex),
    toolCode: event.toolCode,
    toolName: event.toolName,
    toolCallId: event.toolCallId,
    taskId: finiteNumber(event.taskId),
    attempt: finiteNumber(event.attempt),
    maxAttempts: finiteNumber(event.maxAttempts),
    approvalId: event.approvalId,
    approvalStatus: event.approvalStatus,
    executionDecision: normalizeAiExecutionDecision(event.executionDecision),
    citation: event.citation
      ? sanitizeStoredCitation(event.citation)
      : undefined,
    contractVersion: finiteNumber(event.contractVersion),
    runId: event.runId,
    workflowId: event.workflowId,
    workflowRevision: finiteNumber(event.workflowRevision),
    workflowDigest: event.workflowDigest,
    workflowNodeId: event.workflowNodeId,
    outerNodeId: event.outerNodeId,
    nodeRunId: event.nodeRunId,
    publicNodeStatus: event.publicNodeStatus,
    innerStep: event.innerStep,
    ledgerSequence: finiteNumber(event.ledgerSequence),
    ledgerEntryDigest: event.ledgerEntryDigest,
    ledgerDigest: event.ledgerDigest,
    terminationReason: event.terminationReason,
    evidenceCount: finiteNumber(event.evidenceCount),
    actionCount: finiteNumber(event.actionCount),
    taskIds: Array.isArray(event.taskIds)
      ? event.taskIds.map(Number).filter((id) => Number.isFinite(id) && id > 0)
      : undefined,
    recoverable: event.recoverable,
    recorded: event.recorded,
    eventTiming: event.eventTiming,
    createdAt: event.createdAt,
    modelUsage: sanitizeStoredModelUsage(event.modelUsage),
  } satisfies ConversationAgentEvent;
}

export function normalizeConversations(
  items: ConversationThread[],
): ConversationThread[] {
  return items.map((thread) => ({
    ...thread,
    messages: (thread.messages || []).map((message) => ({
      ...message,
      // A saved browser stream cannot still be connected after a reload.
      // Keep task states independent; their server records may still be running.
      modelStreamStatus: message.modelStreamStatus === "running"
        || (!message.modelStreamStatus && ["sending", "planning", "running", "answering"].includes(message.status))
        ? "interrupted" : message.modelStreamStatus,
      executionIntent: message.executionIntent === "AUTO" ? "AUTO" : undefined,
      executionDecision: normalizeAiExecutionDecision(message.executionDecision),
      approvalDispatchStatus: ["dispatching", "rejected", "unknown", "dispatched"].includes(message.approvalDispatchStatus || "")
        ? message.approvalDispatchStatus === "dispatching" ? "unknown" : message.approvalDispatchStatus : undefined,
      approvalDispatchError: typeof message.approvalDispatchError === "string" ? message.approvalDispatchError : undefined,
      approvalDispatchUpdatedAt: typeof message.approvalDispatchUpdatedAt === "string" ? message.approvalDispatchUpdatedAt : undefined,
      taskIds: Array.isArray(message.taskIds) ? message.taskIds : [],
      modelUsage: sanitizeStoredModelUsage(message.modelUsage),
      steps: Array.isArray(message.steps) ? message.steps : [],
      agentEvents: Array.isArray(message.agentEvents)
        ? message.agentEvents.filter(isPublicAiProgressEvent).map(sanitizeStoredAgentEvent)
        : [],
      citations: Array.isArray(message.citations)
        ? message.citations.map(sanitizeStoredCitation)
        : [],
    })),
  }));
}

export const useConversationStore = defineStore("conversations", () => {
  const items = ref<ConversationThread[]>(loadConversations());
  const recent = computed(() => items.value.slice(0, 8));
  // 共享的任务状态快照：任务轮询由 Dashboard 负责，写回这里；
  // 侧边栏悬浮会话状态（App.vue）据此读取，避免两侧使用不一致的任务状态。
  const taskStates = ref<Record<number, {
    id: number;
    toolCode: string;
    status: string;
    progressMessage?: string;
    errorMessage?: string;
    startedAt?: string;
    finishedAt?: string;
    createdAt: string;
  }>>({});
  function setTaskStates(list: Array<{
    id: number;
    toolCode: string;
    status: string;
    progressMessage?: string;
    errorMessage?: string;
    startedAt?: string;
    finishedAt?: string;
    createdAt: string;
  }>) {
    const next: Record<number, (typeof taskStates.value)[number]> = {};
    for (const task of list) next[task.id] = task;
    taskStates.value = next;
  }
  const persistenceError = ref<{
    message: string;
    operation: string;
    reason: string;
    at: string;
  }>();
  const hasUnsavedChanges = ref(false);

  function persistCandidates(candidates: ConversationThread[], operation: string, keepInMemory = false) {
    try {
      let trimmed = candidates;
      let serialized = JSON.stringify(trimmed);
      // 若超出存储容量或会话数量过多，自动归档截断最久未活跃的旧会话（保留最新会话），防止硬溢出
      if (serialized.length > MAX_STORAGE_CHARS || trimmed.length > MAX_CONVERSATIONS) {
        while (trimmed.length > 5 && (serialized.length > MAX_STORAGE_CHARS || trimmed.length > MAX_CONVERSATIONS)) {
          trimmed = trimmed.slice(0, -1);
          serialized = JSON.stringify(trimmed);
        }
      }
      if (serialized.length > MAX_STORAGE_CHARS)
        throw new Error(`本机对话达到保存大小限制（${serialized.length} / ${MAX_STORAGE_CHARS} 字符）`);
      localStorage.setItem(STORAGE_KEY, serialized);
      // 同步更新 items 避免内存状态与存储状态分裂
      if (trimmed.length !== candidates.length) {
        items.value = trimmed;
      }
      // 异步持久化到后端数据库
      if (trimmed.length > 0) {
        const active = trimmed[0];
        void endpoints.saveConversation(active.id, active).catch(() => {});
      }
      persistenceError.value = undefined;
      hasUnsavedChanges.value = false;
      return true;
    } catch (error) {
      if (keepInMemory) hasUnsavedChanges.value = true;
      const reason = error instanceof Error ? error.message : String(error);
      persistenceError.value = {
        operation, reason, at: new Date().toISOString(),
        message: `${operation}未保存：${reason}。已有持久记录未删除。${keepInMemory
          ? "本轮更新仍保留在当前窗口，请在关闭前重试保存。"
          : "本次改动未提交，请保留输入后重试。"}`,
      };
      return false;
    }
  }

  function requirePersistence(candidates: ConversationThread[], operation: string) {
    if (!persistCandidates(candidates, operation))
      throw new ConversationStorageError(persistenceError.value!.message);
  }

  function retryPersist() {
    return persistCandidates(items.value, "重试保存对话", true);
  }

  function createThread(
    targetId: number,
    targetName: string,
    firstPrompt: string,
    projectId?: number,
    branchSource?: ConversationThread["branchSource"],
    scopeOptions?: {
      targetIds?: number[];
      scopeMode?: "SINGLE" | "PROJECT_ALL" | "PROJECT_SUBSET";
    },
  ) {
    const now = new Date().toISOString();
    const thread: ConversationThread = {
      id: createId(),
      title: titleFromPrompt(firstPrompt),
      projectId,
      branchSource,
      targetId,
      targetName,
      targetIds: scopeOptions?.targetIds,
      scopeMode: scopeOptions?.scopeMode || "SINGLE",
      messages: [],
      createdAt: now,
      updatedAt: now,
    };
    const candidates = [thread, ...items.value];
    requirePersistence(candidates, "创建对话");
    items.value = candidates;
    return thread;
  }

  /** Editing creates context-only history; old execution and approval state stays in its source. */
  function forkBeforeMessage(threadId: string, messageId: string, firstPrompt: string) {
    const source = items.value.find(thread => thread.id === threadId);
    const index = source?.messages.findIndex(message => message.id === messageId && message.role === "user") ?? -1;
    if (!source || index < 0) throw new Error("找不到要编辑的用户消息，原对话未改变");
    const now = new Date().toISOString();
    const prefix = source.messages.slice(0, index);
    const ids = new Map(prefix.map(message => [message.id, createId()]));
    const clone = <T>(value: T): T => value === undefined ? value : JSON.parse(JSON.stringify(value));
    const branch: ConversationThread = {
      id: createId(), title: titleFromPrompt(firstPrompt), projectId: source.projectId,
      targetId: source.targetId, targetName: source.targetName,
      branchSource: { threadId, messageId }, createdAt: now, updatedAt: now,
      messages: prefix.map(message => ({
        id: ids.get(message.id)!, role: message.role, content: message.content,
        status: "completed", taskIds: [], steps: [],
        reference: clone(message.reference), references: clone(message.references),
        copilotMode: message.copilotMode,
        replyToId: message.replyToId ? ids.get(message.replyToId) : undefined,
        quote: message.quote ? { ...clone(message.quote), messageId: ids.get(message.quote.messageId) || message.quote.messageId } : undefined,
        createdAt: message.createdAt, updatedAt: now,
      })),
    };
    const candidates = [branch, ...items.value];
    requirePersistence(candidates, "创建对话分支");
    items.value = candidates;
    return branch;
  }

  function newMessage(message: NewConversationMessage): ConversationMessage {
    const now = new Date().toISOString();
    return { ...message, id: createId(), createdAt: now, updatedAt: now };
  }

  function appendPrepared(thread: ConversationThread, created: ConversationMessage[], keepInMemory = false) {
    const updatedAt = created[created.length - 1]!.updatedAt;
    const others = items.value.filter(item => item.id !== thread.id);
    const candidate = { ...thread, messages: [...thread.messages, ...created], updatedAt };
    if (!persistCandidates([candidate, ...others], "保存对话消息", keepInMemory) && !keepInMemory)
      throw new ConversationStorageError(persistenceError.value!.message);
    // Keep captured thread references valid for buildContextPrompt and active stream callbacks.
    thread.messages.push(...created);
    thread.updatedAt = updatedAt;
    items.value = [thread, ...others];
  }

  function appendMessage(threadId: string, message: NewConversationMessage, options: { keepInMemoryOnFailure?: boolean } = {}) {
    const thread = items.value.find(item => item.id === threadId);
    if (!thread) return undefined;
    const created = newMessage(message);
    appendPrepared(thread, [created], options.keepInMemoryOnFailure);
    return created;
  }

  function appendTurn(threadId: string, user: NewConversationMessage, assistant: NewConversationMessage) {
    const thread = items.value.find(item => item.id === threadId);
    if (!thread) return undefined;
    const userMessage = newMessage(user);
    const assistantMessage = newMessage({ ...assistant, replyToId: userMessage.id });
    // One durable commit avoids saving a user message without its assistant placeholder.
    appendPrepared(thread, [userMessage, assistantMessage]);
    return { userMessage, assistantMessage };
  }

  function updateMessage(
    threadId: string,
    messageId: string,
    patch: Partial<Omit<ConversationMessage, "id" | "role" | "createdAt">>,
  ) {
    const thread = items.value.find((item) => item.id === threadId);
    const message = thread?.messages.find((item) => item.id === messageId);
    if (!thread || !message) return undefined;
    Object.assign(message, patch, { updatedAt: new Date().toISOString() });
    thread.updatedAt = message.updatedAt;
    // Persistence failures must not throw into an already successful AI stream callback.
    persistCandidates(items.value, "保存对话更新", true);
    return message;
  }

  function updateThreadTarget(
    threadId: string,
    targetId: number,
    targetName: string,
  ) {
    const thread = items.value.find((item) => item.id === threadId);
    if (!thread || thread.messages.length) return;
    thread.targetId = targetId;
    thread.targetName = targetName;
    thread.updatedAt = new Date().toISOString();
    persistCandidates(items.value, "保存对话目标", true);
  }

  function remove(id: string) {
    const candidates = items.value.filter((item) => item.id !== id);
    requirePersistence(candidates, "删除本机对话");
    items.value = candidates;
    void endpoints.deleteConversation(id).catch(() => {});
  }

  function clear() {
    requirePersistence([], "清空本机对话");
    items.value = [];
    void endpoints.clearAllConversations().catch(() => {});
  }

  async function fetchFromDatabase() {
    try {
      const { data } = await endpoints.listConversations();
      if (Array.isArray(data) && data.length > 0) {
        const remoteThreads = normalizeConversations(data as ConversationThread[]);
        const map = new Map<string, ConversationThread>();
        for (const t of remoteThreads) map.set(t.id, t);
        for (const t of items.value) {
          const remote = map.get(t.id);
          if (!remote || new Date(t.updatedAt).getTime() >= new Date(remote.updatedAt).getTime()) {
            map.set(t.id, t);
          }
        }
        const merged = Array.from(map.values()).sort(
          (a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime(),
        );
        items.value = merged;
      }
    } catch {}
  }

  function taskIds(thread: ConversationThread) {
    return [...new Set(thread.messages.flatMap((message) => message.taskIds))];
  }

  return {
    items,
    recent,
    taskStates,
    setTaskStates,
    persistenceError,
    hasUnsavedChanges,
    retryPersist,
    createThread,
    forkBeforeMessage,
    appendMessage,
    appendTurn,
    updateMessage,
    updateThreadTarget,
    remove,
    clear,
    fetchFromDatabase,
    taskIds,
  };
});
