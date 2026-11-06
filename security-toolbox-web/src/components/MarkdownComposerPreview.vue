<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, useId } from "vue";
import { renderMarkdown } from "../utils/markdown";
import FluentIcon from "./FluentIcon.vue";

/**
 * Markdown preview for the composer draft, shown in a collapsible rail that
 * slides in to the right of the textarea.
 *
 * The rail is a plain flex sibling of the editor inside the composer column:
 * it never wraps, re-parents or re-sizes the textarea, so the input area keeps
 * its own rules (one fixed step of height). Narrow composers hide the trigger,
 * because there is no room for a useful rail next to the text.
 */
const props = defineProps<{ content: string; open?: boolean }>();
const emit = defineEmits<{ "update:open": [value: boolean] }>();
const regionId = useId();
const toggleRef = ref<HTMLButtonElement | null>(null);

const hasContent = computed(() => props.content.trim().length > 0);
const expanded = computed(() => props.open === true && hasContent.value);
// Keep the editable source and the outgoing message untouched. Preview uses
// exactly the same safe, unlocalized rendering as a sent user message.
const html = computed(() => renderMarkdown(props.content));

const toggleLabel = computed(() =>
  !hasContent.value
    ? "暂无输入内容，预览不可用"
    : expanded.value
      ? "收起预览栏"
      : "在右侧预览 Markdown 渲染效果",
);

function setOpen(value: boolean) {
  if (props.open !== value) emit("update:open", value);
}

/** The editor is the only textarea in this composer; keep the caret there. */
function editor() {
  return toggleRef.value?.closest(".thread-composer, .welcome-composer")?.querySelector("textarea") ?? null;
}

async function close() {
  setOpen(false);
}

function handleKeydown(event: KeyboardEvent) {
  if (event.key !== "Escape" || !expanded.value) return;
  const composer = toggleRef.value?.closest(".thread-composer, .welcome-composer");
  const target = event.target;
  // Only for the composer the user is working in, never for a dialog elsewhere.
  if (!composer || !(target instanceof Node) || !composer.contains(target)) return;
  event.preventDefault();
  event.stopPropagation();
  void close().then(() => editor()?.focus({ preventScroll: true }));
}

onMounted(() => window.addEventListener("keydown", handleKeydown, true));
onBeforeUnmount(() => window.removeEventListener("keydown", handleKeydown, true));
</script>

<template>
  <button
    ref="toggleRef"
    type="button"
    class="composer-preview-toggle"
    :class="{ 'is-active': expanded }"
    :disabled="!hasContent"
    :aria-expanded="expanded ? 'true' : 'false'"
    :aria-controls="regionId"
    :aria-label="toggleLabel"
    :title="toggleLabel"
    @click="setOpen(!expanded)"
  >
    <FluentIcon name="eye" aria-hidden="true" /><span>预览</span>
  </button>
  <aside
    v-show="expanded"
    :id="regionId"
    class="composer-preview-rail"
    :class="{ 'rail-open': expanded }"
    role="complementary"
    aria-label="Markdown 渲染预览"
  >
    <header class="composer-preview-head">
      <span>实时预览</span>
      <button type="button" class="composer-preview-close" aria-label="收起预览栏" title="收起预览栏" @click="setOpen(false)">
        <FluentIcon name="chevron-right" aria-hidden="true" />
      </button>
    </header>
    <div class="composer-preview-body markdown-body" tabindex="0" aria-label="Markdown 渲染预览，可滚动查看" v-html="html" />
  </aside>
</template>

<style scoped>
/* Trigger matches the footer's other text controls and stays content-sized. */
.composer-preview-toggle {
  display: inline-flex;
  width: fit-content;
  min-height: 26px;
  flex: none;
  align-items: center;
  gap: 6px;
  padding: 0 8px;
  border: 1px solid transparent;
  border-radius: 6px;
  background: transparent;
  color: var(--app-text-muted);
  font: inherit;
  font-size: 11px;
  white-space: nowrap;
  cursor: pointer;
  transition: background-color 100ms ease, border-color 100ms ease, color 100ms ease, opacity 100ms ease;
}
.composer-preview-toggle .fluent-system-icon { width: 14px; height: 14px; flex: none; }
.composer-preview-toggle:hover:not(:disabled) { border-color: var(--app-border); background: var(--app-surface-soft); color: var(--app-text); }
.composer-preview-toggle.is-active { border-color: var(--app-accent); color: var(--app-accent); }
.composer-preview-toggle:disabled { opacity: 0.5; cursor: default; }
.composer-preview-toggle:focus-visible,
.composer-preview-close:focus-visible,
.composer-preview-body:focus-visible { outline: 2px solid var(--app-accent); outline-offset: 2px; }

/* The rail is a fixed-width column beside the editor, never a layout driver. */
.composer-preview-rail {
  display: flex;
  width: 300px;
  min-width: 300px;
  max-height: 220px;
  flex: none;
  flex-direction: column;
  overflow: hidden;
  align-self: stretch;
  border: 1px solid var(--app-border);
  border-radius: 10px;
  background: var(--app-surface-soft);
  color: var(--app-text);
}
.composer-preview-head {
  display: flex;
  flex: none;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 4px 6px 4px 10px;
  border-bottom: 1px solid var(--app-border);
  color: var(--app-text-muted);
  font-size: 11px;
}
.composer-preview-close {
  display: inline-grid;
  width: 24px;
  height: 24px;
  flex: none;
  place-items: center;
  padding: 0;
  border: 0;
  border-radius: 5px;
  background: transparent;
  color: var(--app-text-muted);
  cursor: pointer;
}
.composer-preview-close:hover { background: var(--app-surface-strong); color: var(--app-text); }
.composer-preview-close .fluent-system-icon { width: 14px; height: 14px; }
.composer-preview-body {
  min-height: 0;
  flex: 1 1 auto;
  overflow: auto;
  overflow-wrap: anywhere;
  padding: 10px 12px;
  font-size: 13px;
  line-height: 1.65;
  color: var(--app-text);
}
.composer-preview-body :deep(> :first-child) { margin-top: 0; }
.composer-preview-body :deep(> :last-child) { margin-bottom: 0; }
.composer-preview-body :deep(table) { display: block; max-width: 100%; overflow-x: auto; }
.composer-preview-body :deep(pre) { max-width: 100%; overflow-x: auto; }
</style>
