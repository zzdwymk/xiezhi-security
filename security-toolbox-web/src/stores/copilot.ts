import { defineStore } from "pinia";
import { computed, ref } from "vue";
import type {
  CopilotDraft,
  CopilotMode,
  CopilotReference,
} from "../types/copilot";

const STORAGE_KEY = "security_toolbox_copilot_draft_v1";
const DEFAULT_TTL_MS = 15 * 60_000;

function readDraft(): CopilotDraft | undefined {
  try {
    const parsed = JSON.parse(
      sessionStorage.getItem(STORAGE_KEY) || "null",
    ) as CopilotDraft | null;
    if (!parsed || parsed.expiresAt <= Date.now()) {
      sessionStorage.removeItem(STORAGE_KEY);
      return undefined;
    }
    return { ...parsed, refs: Array.isArray(parsed.refs) ? parsed.refs : [] };
  } catch {
    sessionStorage.removeItem(STORAGE_KEY);
    return undefined;
  }
}

export const useCopilotStore = defineStore("copilot", () => {
  const draft = ref<CopilotDraft | undefined>(readDraft());
  const hasDraft = computed(() =>
    Boolean(draft.value && draft.value.expiresAt > Date.now()),
  );

  function prepare(input: {
    targetId?: number;
    prompt?: string;
    mode?: CopilotMode;
    refs?: CopilotReference[];
    ttlMs?: number;
  }) {
    const createdAt = Date.now();
    draft.value = {
      id:
        globalThis.crypto?.randomUUID?.() ||
        `${createdAt}-${Math.random().toString(16).slice(2)}`,
      targetId: input.targetId,
      prompt: input.prompt?.trim() || "",
      mode: input.mode || "ask",
      refs: input.refs || [],
      createdAt,
      expiresAt: createdAt + Math.max(30_000, input.ttlMs || DEFAULT_TTL_MS),
    };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(draft.value));
    return draft.value;
  }

  function open(input: {
    targetId?: number;
    prompt?: string;
    mode?: CopilotMode;
    entity?: CopilotReference;
    refs?: CopilotReference[];
    ttlMs?: number;
  }) {
    const refs = [...(input.refs || [])];
    if (input.entity) refs.unshift(input.entity);
    return prepare({
      ...input,
      targetId: input.targetId ?? input.entity?.targetId,
      refs,
    });
  }

  function consume() {
    const value = readDraft();
    draft.value = undefined;
    sessionStorage.removeItem(STORAGE_KEY);
    return value;
  }

  function clear() {
    draft.value = undefined;
    sessionStorage.removeItem(STORAGE_KEY);
  }

  return { draft, hasDraft, prepare, open, consume, clear };
});
