<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import type { ConversationMessage } from "../stores/conversations";
import type { AiAwaitingStatus, AiProgressTask } from "../utils/aiProgress";
import { AI_STATUS_LABELS, aiStatusIcon, buildAiStatusSummary } from "../utils/aiStatus";
import { aiElapsedLabel } from "../utils/aiPresentation";
import FluentIcon from "./FluentIcon.vue";

// The finished-answer status stamp. It carries the same reading and the same
// typography as the in-card progress header, but lives with the message chrome
// so the answer surface holds only the answer.
const props = defineProps<{ message: ConversationMessage; tasks: AiProgressTask[]; awaiting?: AiAwaitingStatus }>();
const now = ref(Date.now());
const summary = computed(() => buildAiStatusSummary(props.message, props.tasks, now.value, props.awaiting));
let timer: ReturnType<typeof setInterval> | undefined;
watch(() => summary.value.spinning, spinning => {
  if (timer) clearInterval(timer);
  timer = undefined; now.value = Date.now();
  if (spinning) timer = setInterval(() => { now.value = Date.now(); }, 1000);
}, { immediate: true });
onBeforeUnmount(() => { if (timer) clearInterval(timer); });
</script>

<template>
  <header class="progress-header" :class="[summary.tone, { 'is-completed': summary.completed }]">
    <span v-if="summary.spinning" class="progress-spinner" role="progressbar" :aria-labelledby="`${message.id}-progress-title`" />
    <FluentIcon v-else :name="aiStatusIcon(summary.tone)" :label="AI_STATUS_LABELS[summary.tone]" class="progress-status-icon" />
    <div class="progress-heading" role="status" aria-live="polite" aria-atomic="true"><strong :id="`${message.id}-progress-title`">{{ summary.title }}</strong></div>
    <span v-if="summary.progress.elapsed !== undefined" class="progress-elapsed" title="从本轮请求开始计时，不代表模型思考耗时">{{ summary.progress.elapsed < 1000 ? '不足 1 秒' : aiElapsedLabel(summary.progress.elapsed) }}</span>
  </header>
</template>

<style scoped>
/* Keep these declarations in step with the AiProgressPanel header: the stamp
   replaces that header for a finished answer and must not shift the layout. */
.progress-header {
  --colorNeutralForeground1: var(--app-text, CanvasText);
  --colorNeutralForeground2: var(--app-text-muted, GrayText);
  --colorNeutralStroke2: var(--app-border, GrayText);
  --colorBrandStroke1: var(--app-accent, #0f6cbd);
  --colorStatusSuccessForeground1: light-dark(#0e700e, #54b054);
  --colorStatusDangerForeground2: light-dark(#6e0811, #eeacb2);
  --colorStatusWarningForeground1: light-dark(#bc4b09, #faa06b);
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 44px;
  color: var(--colorNeutralForeground2);
  font-family: var(--fluent-font, "Segoe UI", sans-serif);
  font-size: 14px;
  line-height: 20px;
}
.progress-header.is-completed { min-height: 28px; gap: 6px; }
.progress-heading { flex: 1; min-width: 0; color: var(--colorNeutralForeground1); }
.progress-header.is-completed > .progress-heading { flex: 0 1 auto; color: var(--colorNeutralForeground2); }
.progress-heading strong { font-size: 16px; line-height: 22px; font-weight: 600; overflow-wrap: anywhere; }
.progress-header.is-completed .progress-heading strong { font-size: 13px; line-height: 18px; font-weight: 400; }
.progress-status-icon, .progress-spinner { flex: 0 0 16px; width: 16px; height: 16px; color: var(--colorBrandStroke1); }
.progress-header.is-completed > .progress-status-icon { width: 14px; height: 14px; flex-basis: 14px; }
.progress-header.failed .progress-status-icon { color: var(--colorStatusDangerForeground2); }
.progress-header.success .progress-status-icon { color: var(--colorStatusSuccessForeground1); }
.progress-header.warning .progress-status-icon { color: var(--colorStatusWarningForeground1); }
.progress-spinner {
  box-sizing: border-box;
  border: 2px solid var(--colorNeutralStroke2);
  border-top-color: var(--colorBrandStroke1);
  border-radius: 50%;
  animation: fluent-status-stamp-spin 1s linear infinite;
}
.progress-elapsed { font-size: 12px; line-height: 18px; font-variant-numeric: tabular-nums; white-space: nowrap; }
:root[data-system-theme="light"] .progress-header { color-scheme: light; }
:root[data-system-theme="dark"] .progress-header { color-scheme: dark; }
@keyframes fluent-status-stamp-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .progress-spinner { animation: none; } }
@media (forced-colors: active) {
  .progress-header { --colorNeutralForeground1: CanvasText; --colorNeutralForeground2: CanvasText; --colorNeutralStroke2: ButtonBorder; --colorBrandStroke1: Highlight; --colorStatusSuccessForeground1: CanvasText; --colorStatusDangerForeground2: CanvasText; --colorStatusWarningForeground1: CanvasText; }
  .progress-spinner { forced-color-adjust: none; border-color: GrayText; border-top-color: Highlight; }
  .fluent-system-icon { forced-color-adjust: none; background-color: CanvasText; }
}
</style>
