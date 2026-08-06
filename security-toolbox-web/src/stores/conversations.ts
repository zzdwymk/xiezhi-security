import { defineStore } from "pinia";
import { computed, ref } from "vue";
import type { CopilotReference } from "../types/copilot";
import type { CopilotMode } from "../types/copilot";

export interface ConversationStep {
  id?: string;
  toolCode: string;
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
  snippet?: string;
  locator?: string;
  metadata?: Record<string, unknown>;
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
  citation?: ConversationCitation;
  createdAt?: string;
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
  citations?: ConversationCitation[];
  planningStage?: string;
  planningStatus?: string;
  reference?: ConversationReference;
  references?: ConversationReference[];
  copilotMode?: CopilotMode;
  replyToId?: string;
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
  title: string;
  projectId?: number;
  targetId: number;
  targetName: string;
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
const MAX_CONVERSATIONS = 30;
const MAX_STORAGE_CHARS = 3_500_000;

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
      ? migrateLegacy(legacy as LegacyConversationRecord[])
      : [];
  } catch {
    return [];
  }
}

function normalizeConversations(
  items: ConversationThread[],
): ConversationThread[] {
  return items.map((thread) => ({
    ...thread,
    messages: (thread.messages || []).map((message) => ({
      ...message,
      taskIds: Array.isArray(message.taskIds) ? message.taskIds : [],
      steps: Array.isArray(message.steps) ? message.steps : [],
      agentEvents: Array.isArray(message.agentEvents)
        ? message.agentEvents
        : [],
      citations: Array.isArray(message.citations) ? message.citations : [],
    })),
  }));
}

export const useConversationStore = defineStore("conversations", () => {
  const items = ref<ConversationThread[]>(loadConversations());
  const recent = computed(() => items.value.slice(0, 8));

  function persist() {
    let serialized = JSON.stringify(items.value);
    while (serialized.length > MAX_STORAGE_CHARS && items.value.length > 1) {
      items.value = items.value.slice(0, -1);
      serialized = JSON.stringify(items.value);
    }
    try {
      localStorage.setItem(STORAGE_KEY, serialized);
    } catch {
      while (items.value.length > 1) {
        items.value = items.value.slice(0, -1);
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(items.value));
          return;
        } catch {
          // Continue evicting the oldest local conversation.
        }
      }
    }
  }

  function createThread(
    targetId: number,
    targetName: string,
    firstPrompt: string,
    projectId?: number,
  ) {
    const now = new Date().toISOString();
    const thread: ConversationThread = {
      id: createId(),
      title: titleFromPrompt(firstPrompt),
      projectId,
      targetId,
      targetName,
      messages: [],
      createdAt: now,
      updatedAt: now,
    };
    items.value = [thread, ...items.value].slice(0, MAX_CONVERSATIONS);
    persist();
    return thread;
  }

  function appendMessage(
    threadId: string,
    message: Omit<ConversationMessage, "id" | "createdAt" | "updatedAt">,
  ) {
    const thread = items.value.find((item) => item.id === threadId);
    if (!thread) return undefined;
    const now = new Date().toISOString();
    const created: ConversationMessage = {
      ...message,
      id: createId(),
      createdAt: now,
      updatedAt: now,
    };
    thread.messages.push(created);
    thread.updatedAt = now;
    items.value = [
      thread,
      ...items.value.filter((item) => item.id !== threadId),
    ];
    persist();
    return created;
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
    persist();
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
    persist();
  }

  function remove(id: string) {
    items.value = items.value.filter((item) => item.id !== id);
    persist();
  }

  function clear() {
    items.value = [];
    persist();
  }

  function taskIds(thread: ConversationThread) {
    return [...new Set(thread.messages.flatMap((message) => message.taskIds))];
  }

  return {
    items,
    recent,
    createThread,
    appendMessage,
    updateMessage,
    updateThreadTarget,
    remove,
    clear,
    taskIds,
  };
});
