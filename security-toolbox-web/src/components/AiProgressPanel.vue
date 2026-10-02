<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import type { ConversationMessage } from "../stores/conversations";
import { buildAiProgress, aiTaskElapsed, isRecordedAiEvent, type AiProgressTask, type ProgressTone } from "../utils/aiProgress";
import { aiElapsedLabel, aiToolLabel, publicAiProgressText } from "../utils/aiPresentation";
import FluentIcon from "./FluentIcon.vue";
const props = defineProps<{ message: ConversationMessage; tasks: AiProgressTask[] }>();
const emit = defineEmits<{ (event: "open-tasks"): void }>();
const now = ref(Date.now());
const expanded = ref(false);
const progress = computed(() => buildAiProgress(props.message, props.tasks, now.value));
const needsClarification = computed(() => props.message.executionDecision === "CLARIFY"
  && !progress.value.active && !progress.value.interrupted && !progress.value.failed && !progress.value.waitingApproval
  && progress.value.tone !== "warning" && !props.message.taskIds.length);
const displayTone = computed(() => needsClarification.value ? "warning" : progress.value.tone);
const spinning = computed(() => displayTone.value === "active" && (progress.value.elapsed ?? 0) >= 1000);
const title = computed(() => needsClarification.value ? "等待补充信息" : progress.value.currentTitle);
const taskLabels: Record<string, string> = { SUCCESS: "成功", FAILED: "失败", TIMEOUT: "超时", REJECTED: "已拒绝", CANCELLED: "已取消", SKIPPED: "已跳过", BLOCKED: "等待前置任务", PENDING: "排队中", RUNNING: "执行中" };
const taskTones: Record<string, ProgressTone> = { SUCCESS: "success", FAILED: "failed", TIMEOUT: "failed", REJECTED: "warning", CANCELLED: "warning", SKIPPED: "neutral", BLOCKED: "neutral", PENDING: "neutral", RUNNING: "active" };
const stateLabels: Record<ProgressTone, string> = { active: "进行中", success: "成功", failed: "失败", warning: "需要关注", neutral: "阶段反馈" };
const intentLabels = { EXECUTE: "执行检测", PLAN_ONLY: "规划与分析", CLARIFY: "需要补充信息" };
const attention = computed(() => {
  const p = progress.value;
  if (needsClarification.value) return "请补充回答中列出的信息，再继续。";
  if (p.interrupted || p.failed || p.waitingApproval) return p.currentDetail;
  if (p.tone === "warning") {
    const unsuccessful = p.related.find(task => ["FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "SKIPPED"].includes(task.status));
    return unsuccessful
      ? `${aiToolLabel(unsuccessful.toolCode)}：${publicAiProgressText(unsuccessful.errorMessage || unsuccessful.progressMessage) || taskLabels[unsuccessful.status]}。请在任务中心查看详情后决定下一步。`
      : p.currentDetail;
  }
  return p.unresolvedTasks ? p.currentDetail : "";
});
const activity = computed(() => progress.value.active && !attention.value ? progress.value.currentDetail : "");
let timer: ReturnType<typeof setInterval> | undefined;
watch(() => progress.value.active, active => {
  if (timer) clearInterval(timer);
  timer = undefined; now.value = Date.now();
  if (active) timer = setInterval(() => { now.value = Date.now(); }, 1000);
}, { immediate: true });
watch(() => props.message.id, () => { expanded.value = false; });
onBeforeUnmount(() => { if (timer) clearInterval(timer); });
function taskDuration(task: AiProgressTask) {
  const elapsed = aiTaskElapsed(task, now.value);
  return elapsed === undefined ? "" : elapsed < 1000 ? "不足 1 秒" : aiElapsedLabel(elapsed);
}
function stateIcon(tone: ProgressTone | string) {
  return tone === "success" ? "checkmark-circle" : tone === "failed" ? "dismiss" : tone === "warning" ? "warning" : tone === "neutral" ? "info" : "clock";
}
function receivedAt(at: number) {
  const elapsed = Math.max(0, at - progress.value.startedAt);
  return elapsed < 1000 ? "不足 1 秒" : aiElapsedLabel(elapsed);
}
</script>

<template>
  <section class="ai-progress-panel" :class="[displayTone, { 'is-expanded': expanded }]" aria-label="AI 处理进展">
    <header class="progress-header">
      <span v-if="spinning" class="progress-spinner" role="progressbar" :aria-labelledby="`${message.id}-progress-title`" />
      <FluentIcon v-else :name="stateIcon(displayTone)" class="progress-status-icon" />
      <div class="progress-heading" role="status" aria-live="polite" aria-atomic="true"><strong :id="`${message.id}-progress-title`">{{ title }}</strong></div>
      <span v-if="progress.elapsed !== undefined" class="progress-elapsed" title="从本轮请求开始计时，不代表模型思考耗时">{{ progress.elapsed < 1000 ? '不足 1 秒' : aiElapsedLabel(progress.elapsed) }}</span>
      <button class="progress-toggle" type="button" :aria-label="expanded ? '收起详细过程' : '查看详细过程'" :aria-expanded="expanded" :aria-controls="`${message.id}-progress-timeline`" @click="expanded = !expanded">
        <span>过程</span><FluentIcon :name="expanded ? 'chevron-up' : 'chevron-down'" />
      </button>
    </header>
    <p v-if="attention" class="progress-attention">{{ attention }}</p>
    <p v-else-if="activity" class="progress-activity" :title="activity">{{ activity }}</p>
    <!-- Only server task records are calls. Internal graph phases never create rows. -->
    <div v-if="progress.related.length" class="progress-tool-stream" aria-label="检测工具调用">
      <details v-for="task in progress.related" :key="task.id" class="progress-tool-call" :class="taskTones[task.status] || 'neutral'">
        <summary>
          <span v-if="task.status === 'RUNNING'" class="progress-spinner task-spinner" aria-hidden="true" />
          <FluentIcon v-else :name="stateIcon(taskTones[task.status] || 'neutral')" />
          <span class="tool-name">{{ aiToolLabel(task.toolCode) }}</span>
          <span class="tool-state">{{ taskLabels[task.status] || '等待状态' }}</span>
          <FluentIcon name="chevron-down" class="tool-chevron" />
        </summary>
        <div class="tool-detail">
          <p v-if="task.errorMessage || task.progressMessage">{{ publicAiProgressText(task.errorMessage || task.progressMessage) }}</p>
          <span v-if="taskDuration(task)" class="tool-duration">{{ taskDuration(task) }}</span>
          <button type="button" class="task-link" @click="emit('open-tasks')">查看任务</button>
        </div>
      </details>
    </div>
    <div v-show="expanded" :id="`${message.id}-progress-timeline`" class="progress-timeline-wrap">
      <ul v-if="message.executionDecision || progress.evidenceCount !== undefined || message.steps.length || message.taskIds.length" class="progress-facts" aria-label="本轮摘要">
        <li v-if="message.executionDecision">已识别：{{ intentLabels[message.executionDecision] }}</li>
        <li v-if="progress.evidenceCount !== undefined">{{ progress.evidenceCount }} 条证据引用</li>
        <li v-if="message.steps.length">{{ message.steps.length }} 项计划</li>
        <li v-if="message.taskIds.length">任务已结束 {{ progress.completeTasks }}/{{ message.taskIds.length }}</li>
      </ul>
      <p v-if="progress.showQuietHint" class="progress-waiting">{{ aiElapsedLabel(progress.quietFor) }} 内没有新的阶段反馈，仍在等待模型或工具返回。</p>
      <aside v-if="progress.decision" class="progress-decision"><strong>判断与下一步</strong><p>{{ progress.decision }}</p></aside>
      <ol v-if="progress.summaryEntries.length" class="progress-milestones" aria-label="关键阶段">
        <li v-for="entry in progress.summaryEntries" :key="entry.key" :class="entry.tone"><FluentIcon :name="stateIcon(entry.tone)" :label="stateLabels[entry.tone]" /><span>{{ entry.title }}</span></li>
      </ol>
      <ol v-if="progress.entries.length" class="progress-timeline" tabindex="0" aria-label="已保存的公开阶段记录，可滚动查看">
        <li v-for="entry in progress.entries" :key="entry.key" :class="entry.tone">
          <FluentIcon :name="stateIcon(entry.tone)" :label="stateLabels[entry.tone]" />
          <div><strong>{{ entry.title }}{{ isRecordedAiEvent(entry.event) ? ' · 补发记录' : '' }}</strong><p>{{ entry.detail }}</p></div><time v-if="entry.at !== undefined && Number.isFinite(progress.startedAt) && entry.at >= progress.startedAt" :datetime="entry.event.createdAt">{{ isRecordedAiEvent(entry.event) ? "收到于 " : "" }}+{{ receivedAt(entry.at) }}</time>
        </li>
      </ol>
      <p v-else class="progress-empty">{{ progress.active ? "等待首条阶段反馈。" : "本轮未保存阶段记录。" }}</p>
      <p class="progress-note">仅展示收到的公开事件；流程记录数量不等于模型调用或实际检测次数。补发记录在处理后收到，时间表示收到反馈的时刻，不代表阶段发生时间或耗时。</p>
    </div>
  </section>
</template>

<style scoped>
/* A lightweight part of the assistant message, using Fluent 2 typography,
   state foregrounds and focus. It is not a separate status card. */
.ai-progress-panel {
  --colorNeutralBackground1: var(--app-surface-strong, Canvas);
  --colorNeutralForeground1: var(--app-text, CanvasText);
  --colorNeutralForeground2: var(--app-text-muted, GrayText);
  --colorNeutralStroke2: var(--app-border, GrayText);
  --colorBrandStroke1: var(--app-accent, #0f6cbd);
  --colorStatusSuccessForeground1: light-dark(#0e700e, #54b054);
  --colorStatusDangerForeground2: light-dark(#6e0811, #eeacb2);
  --colorStatusWarningForeground1: light-dark(#bc4b09, #faa06b);
  --fontSizeBase200: 12px; --lineHeightBase200: 16px;
  --fontSizeBase300: 14px; --lineHeightBase300: 20px;
  width: 100%; min-width: 0; box-sizing: border-box; margin: 4px 0;
  border: 0; border-radius: 0; background: transparent; box-shadow: none;
  color: var(--colorNeutralForeground2); font-family: var(--fluent-font, "Segoe UI", sans-serif);
  font-size: var(--fontSizeBase300); line-height: var(--lineHeightBase300);
}
.progress-header { display: flex; align-items: center; gap: 8px; min-height: 44px; }
.progress-heading { flex: 1; min-width: 0; color: var(--colorNeutralForeground1); }
.progress-heading strong { font-size: var(--fontSizeBase300); line-height: var(--lineHeightBase300); font-weight: 400; overflow-wrap: anywhere; }
.progress-status-icon, .progress-spinner { flex: 0 0 16px; width: 16px; height: 16px; color: var(--colorBrandStroke1); }
.progress-spinner { box-sizing: border-box; border: 2px solid var(--colorNeutralStroke2); border-top-color: var(--colorBrandStroke1); border-radius: 50%; animation: fluent-progress-spin 1s linear infinite; }
.failed > .progress-header > .progress-status-icon, .failed.progress-tool-call .tool-state { color: var(--colorStatusDangerForeground2); }
.success > .progress-header > .progress-status-icon, .success.progress-tool-call > summary > .fluent-system-icon:first-child { color: var(--colorStatusSuccessForeground1); }
.warning > .progress-header > .progress-status-icon, .warning.progress-tool-call .tool-state { color: var(--colorStatusWarningForeground1); }
.progress-elapsed, .tool-duration, .progress-timeline time { font-size: var(--fontSizeBase200); line-height: var(--lineHeightBase200); font-variant-numeric: tabular-nums; white-space: nowrap; }
.progress-toggle, .task-link { display: inline-flex; align-items: center; justify-content: center; gap: 4px; flex: none; min-height: 44px; padding: 0 4px; border: 0; border-radius: 4px; background: transparent; color: var(--colorNeutralForeground2); font: inherit; cursor: pointer; }
.progress-toggle:hover, .task-link:hover, .progress-tool-call > summary:hover { background: var(--app-surface-soft, transparent); color: var(--colorNeutralForeground1); }
.progress-toggle:focus-visible, .task-link:focus-visible, .progress-tool-call > summary:focus-visible, .progress-timeline:focus-visible { outline: 2px solid var(--colorNeutralForeground1); outline-offset: -2px; }
.progress-toggle > .fluent-system-icon { width: 16px; height: 16px; }
.progress-activity, .progress-attention { margin: 0 0 8px 24px; overflow-wrap: anywhere; }
.progress-activity { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.progress-attention { color: var(--colorNeutralForeground1); }
.progress-tool-stream { display: grid; grid-template-columns: minmax(0, 1fr); gap: 0; margin: 0 0 4px 24px; }
.progress-tool-call { min-width: 0; border: 0; background: transparent; }
.progress-tool-call > summary { display: flex; align-items: center; gap: 8px; min-height: 36px; padding: 0 4px; border-radius: 4px; cursor: pointer; list-style: none; }
.progress-tool-call > summary::-webkit-details-marker { display: none; }
.progress-tool-call > summary > .fluent-system-icon { width: 16px; height: 16px; flex: 0 0 16px; }
.tool-name { min-width: 0; overflow-wrap: anywhere; color: var(--colorNeutralForeground1); }
.tool-state { margin-left: auto; flex-shrink: 0; }
.tool-chevron { transition: transform 120ms linear; }
.progress-tool-call[open] .tool-chevron { transform: rotate(180deg); }
.tool-detail { margin: 0 0 8px 28px; }
.tool-detail p { margin: 0; overflow-wrap: anywhere; }
.tool-duration { margin-right: 8px; }
.task-link { color: var(--colorNeutralForeground1); text-decoration: underline; }
.progress-timeline-wrap { margin: 4px 0 8px 8px; padding: 0 0 0 16px; border-left: 1px solid var(--colorNeutralStroke2); }
.progress-facts { display: flex; flex-wrap: wrap; gap: 4px 16px; padding: 0; margin: 0 0 12px; list-style: none; }
.progress-waiting, .progress-note, .progress-empty { margin: 8px 0; overflow-wrap: anywhere; }
.progress-decision { margin: 0 0 12px; }
.progress-decision strong, .progress-timeline strong { color: var(--colorNeutralForeground1); font-size: var(--fontSizeBase300); line-height: var(--lineHeightBase300); font-weight: 400; }
.progress-decision p, .progress-timeline p { margin: 4px 0 0; overflow-wrap: anywhere; }
.progress-milestones { list-style: none; display: grid; gap: 4px; padding: 0; margin: 0 0 12px; }
.progress-milestones li { display: flex; align-items: center; gap: 8px; min-width: 0; }
.progress-milestones li > span { min-width: 0; overflow-wrap: anywhere; }
.progress-milestones .fluent-system-icon, .progress-timeline .fluent-system-icon { width: 16px; height: 16px; flex: 0 0 16px; }
.progress-timeline { padding: 4px; margin: 0; list-style: none; max-height: 320px; overflow-y: auto; }
.progress-timeline li { display: grid; grid-template-columns: 16px minmax(0, 1fr) auto; gap: 8px; padding: 8px 0; }
.progress-timeline .fluent-system-icon { margin-top: 2px; }
.progress-timeline .failed .fluent-system-icon, .progress-milestones .failed { color: var(--colorStatusDangerForeground2); }
.progress-timeline .warning .fluent-system-icon, .progress-milestones .warning { color: var(--colorStatusWarningForeground1); }
.progress-timeline .success .fluent-system-icon { color: var(--colorStatusSuccessForeground1); }
@keyframes fluent-progress-spin { to { transform: rotate(360deg); } }
:root[data-system-theme="light"] .ai-progress-panel { color-scheme: light; }
:root[data-system-theme="dark"] .ai-progress-panel { color-scheme: dark; }
@media (prefers-reduced-motion: reduce) { .progress-spinner { animation: none; } .tool-chevron { transition: none; } }
@media (forced-colors: active) {
  .ai-progress-panel { --colorNeutralForeground1: CanvasText; --colorNeutralForeground2: CanvasText; --colorNeutralStroke2: ButtonBorder; --colorBrandStroke1: Highlight; --colorStatusSuccessForeground1: CanvasText; --colorStatusDangerForeground2: CanvasText; --colorStatusWarningForeground1: CanvasText; }
  .progress-spinner { forced-color-adjust: none; border-color: GrayText; border-top-color: Highlight; }
  .fluent-system-icon { forced-color-adjust: none; background-color: CanvasText; }
  .progress-toggle:focus-visible, .task-link:focus-visible, .progress-tool-call > summary:focus-visible, .progress-timeline:focus-visible { outline-color: Highlight; }
}
@media (max-width: 600px) {
  .progress-timeline li { grid-template-columns: 16px minmax(0, 1fr); }
  .progress-timeline time { grid-column: 2; }
}
</style>
