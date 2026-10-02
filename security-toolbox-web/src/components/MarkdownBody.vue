<script setup lang="ts">
import { computed } from "vue";
import { renderMarkdown } from "../utils/markdown";

const props = defineProps<{ content: string }>();
const html = computed(() => renderMarkdown(props.content));
</script>

<template>
  <div class="markdown-body" v-html="html" />
</template>

<style scoped>
.markdown-body {
  min-width: 0;
  max-width: 100%;
  color: var(--app-text);
  font-size: var(--fontSizeBase300, 14px);
  line-height: var(--lineHeightBase300, 20px);
  white-space: normal;
  overflow-wrap: anywhere;
}
.markdown-body :deep(p) { margin: 0 0 10px; }
.markdown-body :deep(h1), .markdown-body :deep(h2),
.markdown-body :deep(h3), .markdown-body :deep(h4),
.markdown-body :deep(h5), .markdown-body :deep(h6) {
  margin: 16px 0 8px;
  line-height: 1.4;
  font-weight: 600;
}
.markdown-body :deep(h1) { font-size: var(--fontSizeBase500, 20px); }
.markdown-body :deep(h2) { font-size: var(--fontSizeBase400, 16px); }
.markdown-body :deep(h3), .markdown-body :deep(h4),
.markdown-body :deep(h5), .markdown-body :deep(h6) { font-size: inherit; }
.markdown-body :deep(ul), .markdown-body :deep(ol) { margin: 8px 0; padding-left: 24px; }
.markdown-body :deep(li) { margin: 3px 0; }
.markdown-body :deep(a) { color: var(--app-accent); text-decoration: underline; }
.markdown-body :deep(code) {
  padding: 2px 4px;
  border-radius: 4px;
  background: var(--app-surface-soft);
  font: 0.9em ui-monospace, Consolas, monospace;
}
.markdown-body :deep(pre) {
  box-sizing: border-box;
  max-width: 100%;
  overflow-x: auto;
  margin: 10px 0;
  padding: 12px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control, 6px);
  background: var(--app-surface-soft);
  white-space: pre;
  overflow-wrap: normal;
}
.markdown-body :deep(pre code) { padding: 0; background: transparent; color: inherit; }
.markdown-body :deep(blockquote) {
  margin: 10px 0;
  padding: 8px 12px;
  border-left: 3px solid var(--app-accent);
  background: var(--app-accent-soft);
}
.markdown-body :deep(table) {
  display: block;
  max-width: 100%;
  overflow-x: auto;
  margin: 10px 0;
  border-collapse: collapse;
}
.markdown-body :deep(th), .markdown-body :deep(td) {
  padding: 6px 9px;
  border: 1px solid var(--app-border);
  text-align: left;
}
.markdown-body :deep(th) { background: var(--app-surface-soft); }
.markdown-body :deep(hr) { margin: 14px 0; border: 0; border-top: 1px solid var(--app-border); }
.markdown-body :deep(> :first-child) { margin-top: 0; }
.markdown-body :deep(> :last-child) { margin-bottom: 0; }
</style>
