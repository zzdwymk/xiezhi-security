<script setup lang="ts">
import { ref, computed, nextTick, onMounted, onBeforeUnmount, watch } from "vue";
import { ElMessage } from "element-plus";
import FluentIcon from "./FluentIcon.vue";

const props = withDefaults(
  defineProps<{
    title?: string;
    content?: string;
    emptyText?: string;
    icon?: string;
    monospace?: boolean;
    wrap?: boolean;
    /** Height floor, in text lines. */
    minRows?: number;
    /** Height ceiling in text lines. With `wrap`, a longer text scrolls inside
     *  this budget instead of being clipped at the last row. */
    maxRows?: number;
    copyable?: boolean;
    live?: boolean;
    ariaLabel?: string;
    textareaRef?: (el: HTMLTextAreaElement | null) => void;
  }>(),
  {
    title: "",
    content: "",
    emptyText: "",
    icon: "document",
    monospace: true,
    wrap: false,
    minRows: 6,
    maxRows: 12,
    copyable: false,
    live: false,
    ariaLabel: "",
    textareaRef: undefined,
  },
);

const inputEl = ref();
function syncTextarea() {
  const inner = inputEl.value as
    | { textarea?: HTMLTextAreaElement }
    | undefined;
  textareaEl.value = inner?.textarea ?? null;
  props.textareaRef?.(inner?.textarea ?? null);
}
onMounted(() => {
  syncTextarea();
  void measureRows();
});

// el-input's `autosize` sizes the textarea to its content and *clips* whatever
// exceeds maxRows. A readonly textarea reports no layout overflow, so those rows
// vanished silently: a log with one wrapped nmap command (17 rows) showed 8 and
// lost the rest, which reads on screen as "cut off on the right".
//
// A wrapping block is therefore measured instead of capped: `measureRows()` asks
// the browser for the real content height (CJK + monospace metrics cannot be
// derived in CSS arithmetic) and `autosize` gets exactly the row count that keeps
// the box at `max-rows`, so the box stops growing there and scrolls the remainder
// (see the `.is-wrap` rules). Shorter content keeps its natural height. Unwrapped
// blocks keep Element Plus' sizing: their lines scroll sideways, so capping can
// never hide text.
const textareaEl = ref<HTMLTextAreaElement | null>(null);
const measuredRows = ref(0);

function measureRows() {
  const el = textareaEl.value;
  if (!el) return;
  const style = getComputedStyle(el);
  const lineHeight = Number.parseFloat(style.lineHeight);
  if (!lineHeight) return;
  const verticalPadding =
    Number.parseFloat(style.paddingTop) + Number.parseFloat(style.paddingBottom);
  const rows = Math.ceil((el.scrollHeight - verticalPadding) / lineHeight);
  if (Number.isFinite(rows) && rows > 0) measuredRows.value = rows;
}

const autosize = computed(() => {
  if (!props.wrap) return { minRows: props.minRows, maxRows: props.maxRows };
  const rows = measuredRows.value || props.maxRows;
  if (rows <= props.maxRows) return { minRows: props.minRows, maxRows: rows };
  // Past the ceiling: hold the reading height so the shared scroll rules apply.
  return { minRows: props.maxRows, maxRows: props.maxRows };
});

watch(
  () => [props.content, props.wrap, props.maxRows],
  async () => {
    await nextTick();
    // Re-measure once the DOM has the new content, cheaply (readonly value).
    measureRows();
  },
);

const copied = ref(false);
let copiedTimer: ReturnType<typeof setTimeout> | null = null;

onBeforeUnmount(() => {
  if (copiedTimer) clearTimeout(copiedTimer);
  props.textareaRef?.(null);
});

async function copy() {
  if (!props.content) return;
  try {
    await navigator.clipboard.writeText(props.content);
    copied.value = true;
    if (copiedTimer) clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => {
      copied.value = false;
    }, 1800);
    ElMessage.success(`已复制${props.title || "内容"}`);
  } catch {
    ElMessage.error("复制失败，请手动复制");
  }
}
</script>

<template>
  <div class="fluent-code-block">
    <div v-if="title || (copyable && content)" class="fluent-code-header">
      <span v-if="title" class="fluent-code-title">
        <FluentIcon :name="icon" />
        <span>{{ title }}</span>
      </span>
      <el-tooltip
        :content="copied ? `已复制${title || '内容'}` : `复制${title || '内容'}`"
        placement="top"
        :show-after="200"
      >
        <button
          v-if="copyable && content"
          type="button"
          class="fluent-subtle-btn"
          :class="{ 'is-copied': copied }"
          :aria-label="`复制${title || '内容'}`"
          @click="copy"
        >
          <FluentIcon :name="copied ? 'checkmark' : 'copy'" />
          <span>{{ copied ? '已复制' : '复制' }}</span>
        </button>
      </el-tooltip>
    </div>
    <slot>
      <el-input
        ref="inputEl"
        class="fluent-code-textarea"
        :class="{ 'is-mono': monospace, 'is-wrap': wrap }"
        :model-value="content"
        type="textarea"
        :autosize="autosize"
        readonly
        :placeholder="emptyText"
        :role="live ? 'log' : undefined"
        :aria-live="live ? 'polite' : undefined"
        :aria-label="ariaLabel || undefined"
      />
    </slot>
  </div>
</template>

<style scoped>
/* The wrapper is the only width reference this block has. `100%` resolved against
   the containing block's *content* box, but Dashboard pads that block on both sides
   (`.plan-runtime-details > :not(summary) { margin: 0 14px }`), so the box came out
   14px wider than the card's inner area and hung past its right edge — which reads
   on screen as "cut off on the right". `border-box` keeps the width and the wrapper's
   own padding on the same box model, and `auto` lets the block fill the padded box. */
.fluent-code-block {
  display: flex;
  box-sizing: border-box;
  width: auto;
  max-width: 100%;
  min-width: 0;
  flex-direction: column;
  gap: 6px;
}
.fluent-code-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 0 2px;
  font-size: var(--type-micro, 11px);
}
.fluent-code-title {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--app-muted, #64748b);
  font-weight: var(--fluent-weight-medium, 500);
}
.fluent-subtle-btn {
  display: inline-flex;
  min-height: 24px;
  align-items: center;
  gap: 4px;
  margin-left: auto;
  padding: 3px 8px;
  border: none;
  border-radius: var(--fluent-radius-control);
  background: transparent;
  color: var(--app-muted, #64748b);
  font-size: var(--type-caption, 12px);
  cursor: pointer;
  transition: all var(--fluent-fast);
}
.fluent-subtle-btn:hover {
  background: var(--app-surface-soft, #f1f5f9);
}
.fluent-subtle-btn:active {
  transform: scale(0.96);
}
.fluent-subtle-btn.is-copied {
  color: #107c41 !important;
  background: #dff6dd !important;
  font-weight: var(--fluent-weight-medium, 500);
}
:root[data-system-theme="dark"] .fluent-subtle-btn.is-copied,
html.dark .fluent-subtle-btn.is-copied,
[data-theme="dark"] .fluent-subtle-btn.is-copied {
  color: #4ade80 !important;
  background: rgba(34, 197, 94, 0.18) !important;
}
.fluent-code-textarea :deep(.el-textarea__inner) {
  white-space: pre;
  border: 0 !important;
  border-radius: var(--fluent-radius-control, 4px) !important;
  background: var(--app-surface-strong, #ffffff) !important;
  box-shadow: 0 0 0 1px var(--app-border, #e2e8f0) inset !important;
  color: var(--app-text, #1e293b);
  transition: box-shadow 150ms ease;
}
/* Element Plus sizes the box from the measured rows; all that remains here is to
   make the overflow reachable — a readonly textarea never reports it otherwise.
   The scrollbar is reserved in the gutter so no text ever sits underneath it. */
.fluent-code-block :deep(.fluent-code-textarea.is-wrap .el-textarea__inner) {
  overflow-y: auto;
  scrollbar-gutter: stable;
}
.fluent-code-textarea.is-mono :deep(.el-textarea__inner) {
  font-family: var(--font-mono, "Cascadia Code", "Consolas", monospace);
  font-size: 11.5px;
  line-height: 1.55;
}
/* Wrapped surfaces always lay lines out at the mono metrics the row budget above
   is expressed in, so the budget cannot drift from the rendered line height. */
.fluent-code-block :deep(.fluent-code-textarea.is-wrap .el-textarea__inner) {
  font-size: 11.5px;
  line-height: 1.55;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.fluent-code-textarea :deep(.el-textarea__inner:hover) {
  box-shadow: 0 0 0 1px var(--app-border-strong, #cbd5e1) inset !important;
}
.fluent-code-textarea :deep(.el-textarea__inner:focus),
.fluent-code-textarea :deep(.el-textarea__inner:focus-within) {
  outline: none !important;
  box-shadow:
    inset 0 0 0 1px var(--app-border, #cbd5e1),
    inset 0 -2px 0 0 var(--app-accent, #0078d4) !important;
}
</style>
