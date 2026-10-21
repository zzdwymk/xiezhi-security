<script setup lang="ts">
import { computed } from "vue";
import type { ConversationMessage } from "../stores/conversations";
import { aiProgressFailureText } from "../utils/aiPresentation";
import FluentIcon from "./FluentIcon.vue";

const props = defineProps<{ message: ConversationMessage }>();
const hasTasks = computed(() => props.message.taskIds.length > 0);
const detail = computed(() => aiProgressFailureText(props.message.content, hasTasks.value, 4000)
  || "服务未返回可显示的错误说明，请打开配置诊断检查连接。");
const summary = computed(() => {
  const explanation = detail.value.split(/\s*(?:变化|参数差异|变更明细)[：:]/, 1)[0]?.trim() || detail.value;
  return explanation.length > 180 ? explanation.slice(0, 180) + "…" : explanation;
});
</script>

<template>
  <!-- Keep the readable explanation in the shared response surface and the
       technical payload behind a disclosure. Recovery stays in the toolbar. -->
  <section class="ai-failure-notice" aria-label="回复失败说明">
    <p class="failure-summary">{{ summary }}</p>
    <details class="failure-details">
      <summary><FluentIcon name="chevron-right" />错误详情</summary>
      <p>{{ detail }}</p>
    </details>
  </section>
</template>

<style scoped>
.ai-failure-notice { min-width: 0; box-sizing: border-box; margin: 0; padding: 0; color: var(--app-text); font-size: 14px; line-height: 1.7; }
.failure-summary { margin: 0 0 8px; overflow-wrap: anywhere; }
.failure-details summary { display: inline-flex; align-items: center; justify-content: center; gap: 6px; box-sizing: border-box; min-height: 32px; border-radius: 4px; font: inherit; cursor: pointer; }
.failure-details summary:hover { background: var(--app-surface-soft); }
.failure-details .fluent-system-icon { width: 16px; height: 16px; }
.failure-details { min-width: 0; margin: 0; }
.failure-details summary { justify-content: flex-start; padding: 4px 0; border: 0; background: transparent; color: var(--app-text-muted); font-size: 13px; line-height: 20px; list-style: none; }
.failure-details summary::-webkit-details-marker { display: none; }
.failure-details[open] summary .fluent-system-icon { transform: rotate(90deg); }
.failure-details > p { box-sizing: border-box; max-height: 240px; margin: 8px 0 0; overflow: auto; overflow-wrap: anywhere; white-space: pre-wrap; overscroll-behavior: contain; }
.failure-details summary:focus-visible { outline: 2px solid var(--app-accent); outline-offset: 2px; }
@media (pointer: coarse), (max-width: 640px) { .failure-details summary { min-height: 40px; } }
</style>
