<script setup lang="ts">
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
    minRows?: number;
    maxRows?: number;
    copyable?: boolean;
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
    copyable: true,
  },
);

async function copy() {
  if (!props.content) return;
  try {
    await navigator.clipboard.writeText(props.content);
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
      <button
        v-if="copyable && content"
        type="button"
        class="fluent-subtle-btn"
        :title="`复制${title || '内容'}`"
        @click="copy"
      >
        <FluentIcon name="copy" />
        <span>复制</span>
      </button>
    </div>
    <slot>
      <el-input
        class="fluent-code-textarea"
        :class="{ 'is-mono': monospace, 'is-wrap': wrap }"
        :model-value="content"
        type="textarea"
        :autosize="{ minRows, maxRows }"
        readonly
        :placeholder="emptyText"
      />
    </slot>
  </div>
</template>

<style scoped>
.fluent-code-block {
  display: flex;
  width: 100%;
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
  font-size: 11px;
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
  align-items: center;
  gap: 4px;
  margin-left: auto;
  padding: 2px 7px;
  border: none;
  border-radius: 3px;
  background: transparent;
  color: var(--app-muted, #64748b);
  font-size: 11px;
  cursor: pointer;
  transition: all 120ms ease;
}
.fluent-subtle-btn:hover {
  background: var(--app-surface-soft, #f1f5f9);
  color: var(--app-accent, #0078d4);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
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
.fluent-code-textarea.is-mono :deep(.el-textarea__inner) {
  font-family: var(--font-mono, "Cascadia Code", "Consolas", monospace);
  font-size: 11.5px;
  line-height: 1.55;
}
.fluent-code-textarea.is-wrap :deep(.el-textarea__inner) {
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
