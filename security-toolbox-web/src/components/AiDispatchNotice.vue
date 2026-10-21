<script setup lang="ts">
import { computed } from "vue";
import type { ConversationMessage } from "../stores/conversations";
import { aiDispatchQuotaFailure, isAiDispatchRejected } from "../utils/aiApproval";
import { publicAiProgressText } from "../utils/aiPresentation";
import FluentIcon from "./FluentIcon.vue";

const props = defineProps<{ message: ConversationMessage; disabled?: boolean; loading?: boolean }>();
const emit = defineEmits<{ (event: "resume"): void; (event: "open-tasks"): void; (event: "adjust-plan"): void }>();
const quota = computed(() => aiDispatchQuotaFailure(props.message.approvalDispatchError));
const rejected = computed(() => isAiDispatchRejected(props.message));
const dispatching = computed(() => props.loading && !rejected.value && props.message.approvalDispatchStatus === "dispatching");
const title = computed(() => quota.value?.oversized ? "方案步骤超出任务额度"
  : quota.value ? "任务额度不足，暂未执行"
  : rejected.value ? "执行校验未通过"
  : dispatching.value ? "正在确认任务派发结果" : "派发结果尚未确认");
const detail = computed(() => quota.value?.legacy
  ? "服务器在创建任务前拒绝了请求。可能是已有任务占用，也可能是整份方案超过额度。"
  : publicAiProgressText(props.message.approvalDispatchError)
    || (rejected.value ? "执行请求未通过校验，本次未创建检测任务。"
      : "尚未收到完整派发回执，请先核对任务记录，避免把未知结果当作执行失败。"));
const hint = computed(() => quota.value?.oversized
  ? "原方案和批准记录已保留。仅等待不会解除超限，请拆分方案并重新确认。"
  : quota.value?.legacy ? "若没有未结束的任务仍被拒绝，请调整方案；不要反复恢复同一份超额计划。"
  : quota.value ? "本次未创建任务。已有任务结束后，可重新校验并执行原方案。"
  : rejected.value ? "原方案和批准记录已保留，请核对当前授权后再重新校验。"
  : "恢复时仅核验并执行已批准的原方案，不会重新生成方案或重复派发已关联任务。");
const actionLabel = computed(() => quota.value?.oversized ? "调整方案"
  : quota.value ? "重试原计划" : rejected.value ? "重新校验原方案" : "恢复原计划执行");
</script>

<template>
  <section class="ai-dispatch-notice" :class="{ 'is-rejected': rejected, 'is-dispatching': dispatching }" aria-label="执行状态与后续操作">
    <div class="dispatch-notice-body" role="status" aria-live="polite" aria-atomic="true">
      <FluentIcon :name="dispatching ? 'clock' : 'warning'" class="dispatch-notice-icon" aria-hidden="true" />
      <div class="dispatch-notice-copy">
        <strong>{{ title }}</strong>
        <p>{{ detail }}</p>
        <p class="dispatch-notice-hint">{{ hint }}</p>
      </div>
    </div>
    <div class="dispatch-notice-actions">
      <button type="button" class="dispatch-action" :disabled="disabled" @click="emit('open-tasks')">查看检测任务</button>
      <button v-if="quota?.legacy" type="button" class="dispatch-action" :disabled="disabled" @click="emit('adjust-plan')">调整方案</button>
      <button type="button" class="dispatch-action is-primary" :disabled="disabled || loading || dispatching" :aria-busy="loading || dispatching" @click="quota?.oversized ? emit('adjust-plan') : emit('resume')">
        <FluentIcon v-if="loading || dispatching" name="clock" aria-hidden="true" />
        {{ loading ? '正在校验…' : dispatching ? '正在确认…' : actionLabel }}
      </button>
    </div>
  </section>
</template>

<style scoped>
.ai-dispatch-notice {
  --dispatch-warning: light-dark(#8a4b08, #faa06b);
  min-width: 0;
  padding: 16px;
  border-bottom: 1px solid var(--app-border);
  background: color-mix(in srgb, var(--dispatch-warning) 5%, var(--app-surface-strong));
  color: var(--app-text);
  font-family: var(--fluent-font);
  font-size: 14px;
  line-height: 20px;
}
.dispatch-notice-body { display: flex; align-items: flex-start; gap: 10px; min-width: 0; }
.dispatch-notice-icon { width: 18px; height: 18px; flex: 0 0 18px; margin-top: 2px; color: var(--dispatch-warning); }
.dispatch-notice-copy { min-width: 0; }
.dispatch-notice-copy strong { display: block; font-size: 14px; font-weight: 600; line-height: 22px; }
.dispatch-notice-copy p { margin: 4px 0 0; overflow-wrap: anywhere; }
.dispatch-notice-copy .dispatch-notice-hint { margin-top: 6px; color: var(--app-text-muted); font-size: 12px; line-height: 18px; }
.dispatch-notice-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 14px 0 0 28px; }
.dispatch-action { display: inline-flex; align-items: center; justify-content: center; gap: 6px; box-sizing: border-box; min-height: 34px; max-width: 100%; padding: 6px 12px; border: 1px solid var(--app-border); border-radius: var(--fluent-radius-control, 4px); background: var(--app-surface-strong); color: var(--app-text); font: inherit; font-size: 13px; line-height: 20px; cursor: pointer; }
.dispatch-action:not(.is-primary):hover:not(:disabled) { background: var(--app-surface-soft); border-color: var(--app-accent); }
.dispatch-action:not(.is-primary):active:not(:disabled) { background: var(--fluent-subtle-pressed-bg, var(--app-surface-soft)); border-color: var(--app-accent); }
.dispatch-action.is-primary { border-color: var(--fluent-action-bg, var(--app-accent)); background: var(--fluent-action-bg, var(--app-accent)); color: var(--fluent-action-fg, var(--system-accent-foreground, white)); }
.dispatch-action.is-primary:hover:not(:disabled) { border-color: var(--fluent-action-bg-hover, var(--app-accent-dark)); background: var(--fluent-action-bg-hover, var(--app-accent-dark)); color: var(--fluent-action-fg, var(--system-accent-foreground, white)); }
.dispatch-action.is-primary:active:not(:disabled) { border-color: var(--fluent-action-bg-pressed, var(--fluent-action-bg-hover, var(--app-accent-dark))); background: var(--fluent-action-bg-pressed, var(--fluent-action-bg-hover, var(--app-accent-dark))); color: var(--fluent-action-fg, var(--system-accent-foreground, white)); }
.dispatch-action:focus-visible { outline: 2px solid var(--app-accent); outline-offset: 2px; }
.dispatch-action:disabled { border-color: var(--fluent-disabled-border, var(--app-border)); background: var(--fluent-disabled-bg, var(--app-surface-soft)); color: var(--fluent-disabled-fg, var(--app-muted)); cursor: not-allowed; }
.dispatch-action .fluent-system-icon { width: 16px; height: 16px; flex: none; }
@media (max-width: 480px) {
  .ai-dispatch-notice { padding: 12px; }
  .dispatch-notice-actions { margin-left: 0; }
  .dispatch-action { flex: 1 1 auto; min-height: 40px; }
}
@media (forced-colors: active) {
  .dispatch-notice-icon { color: CanvasText; }
  .dispatch-action { border-color: ButtonText; background: ButtonFace; color: ButtonText; }
  .dispatch-action.is-primary:not(:disabled) { border-color: Highlight; background: Highlight; color: HighlightText; }
  .dispatch-action.is-primary:hover:not(:disabled), .dispatch-action.is-primary:active:not(:disabled) { border-color: Highlight; background: Highlight; color: HighlightText; }
  .dispatch-action:disabled { border-color: GrayText; background: ButtonFace; color: GrayText; }
  .dispatch-action:focus-visible { outline-color: Highlight; }
}
</style>
