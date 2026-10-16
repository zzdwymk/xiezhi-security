<script setup lang="ts">
import { computed } from "vue";
import type { ConversationMessage } from "../stores/conversations";
import { aiToolLabel } from "../utils/aiPresentation";
import { approvalParameterRows } from "../utils/aiApproval";
import FluentIcon from "./FluentIcon.vue";

const props = defineProps<{
  visible: boolean;
  message?: ConversationMessage;
  targetName: string;
  targetValue: string;
  allowedPorts: string;
  busy: boolean;
}>();

defineEmits<{
  (event: "update:visible", value: boolean): void;
  (event: "decide", decision: "APPROVED" | "REJECTED"): void;
}>();

const hasCautionStep = computed(() =>
  props.message?.steps.some(
    (step) => step.requiresApproval || step.risk === "CAUTION",
  ),
);
</script>

<template>
  <el-dialog
    :model-value="visible"
    title="确认 AI 行动方案"
    class="app-dialog ai-approval-modal"
    style="--app-dialog-width: 600px"
    align-center
    append-to-body
    :close-on-click-modal="false"
    :close-on-press-escape="!busy"
    :show-close="!busy"
    @update:model-value="$emit('update:visible', $event)"
  >
    <section
      v-if="message"
      class="ai-approval-dialog"
      :data-approval-id="message.approvalId"
    >
      <!-- 1. 方案摘要与授权目标元数据卡片 (Fluent Card) -->
      <section class="approval-overview-card" aria-label="授权目标与范围">
        <header class="approval-overview-head">
          <div class="approval-id-wrap">
            <span class="approval-id-badge">方案 #{{ message.approvalId }}</span>
            <span class="approval-scope-label">仅本次执行</span>
          </div>
          <span
            class="approval-risk-tag"
            :class="hasCautionStep ? 'is-caution' : 'is-normal'"
          >
            <FluentIcon
              :name="hasCautionStep ? 'warning' : 'shield'"
              aria-hidden="true"
            />
            <span>{{ hasCautionStep ? "需人工确认" : "受控检测" }}</span>
          </span>
        </header>

        <dl class="approval-meta-grid">
          <div class="approval-meta-item is-target">
            <dt>授权目标</dt>
            <dd>
              <strong class="approval-target-name">{{ targetName }}</strong>
              <code class="approval-target-addr">{{ targetValue }}</code>
            </dd>
          </div>
          <div class="approval-meta-item">
            <dt>授权端口</dt>
            <dd>
              <span class="approval-port-badge">{{
                allowedPorts || "以登记的授权范围为准"
              }}</span>
            </dd>
          </div>
        </dl>
      </section>

      <!-- 2. 执行步骤清单 (Fluent List / Sub-cards) -->
      <section class="approval-steps-section" aria-label="执行动作清单">
        <h3 class="approval-steps-title">
          <span>拟执行计划</span>
          <span class="approval-steps-count">{{ message.steps.length }} 步</span>
        </h3>

        <ol class="approval-step-list">
          <li
            v-for="(step, index) in message.steps"
            :key="step.id || index"
            class="approval-step-card"
          >
            <header class="approval-step-head">
              <span class="approval-step-number" aria-hidden="true">{{ index + 1 }}</span>
              <strong class="approval-step-name">{{ aiToolLabel(step.toolCode) }}</strong>
              <span
                class="approval-step-risk"
                :class="
                  step.requiresApproval || step.risk === 'CAUTION'
                    ? 'is-caution'
                    : 'is-controlled'
                "
              >
                <FluentIcon
                  :name="
                    step.requiresApproval || step.risk === 'CAUTION'
                      ? 'warning'
                      : 'shield'
                  "
                  aria-hidden="true"
                />
                <span>{{
                  step.requiresApproval || step.risk === "CAUTION"
                    ? "需人工确认"
                    : "受控操作"
                }}</span>
              </span>
            </header>

            <div class="approval-step-body">
              <dl
                v-if="Object.keys(step.parameters || {}).length"
                class="approval-parameters"
              >
                <div
                  v-for="row in approvalParameterRows(step.parameters)"
                  :key="row.label"
                  class="approval-param-row"
                >
                  <dt>{{ row.label }}</dt>
                  <dd><code>{{ row.value }}</code></dd>
                </div>
              </dl>
              <div v-else class="approval-defaults-hint">
                <FluentIcon name="info" aria-hidden="true" />
                <span>{{
                  step.toolCode === "nuclei_scan"
                    ? "默认安全模板（未提供参数覆盖）"
                    : "未提供参数覆盖，使用该节点已保存的配置"
                }}；本轮仍受登记范围约束。</span>
              </div>
            </div>
          </li>
        </ol>
      </section>

      <!-- 3. 安全策略提示 (Fluent InfoBar) -->
      <div class="approval-policy-infobar" role="note">
        <FluentIcon name="info" class="approval-policy-icon" aria-hidden="true" />
        <p class="approval-policy-text">
          允许后将执行以上计划。关闭窗口会继续等待，不会创建检测任务。
        </p>
      </div>
    </section>

    <template #footer>
      <div class="app-dialog__footer-row">
        <el-button :disabled="busy" @click="$emit('update:visible', false)">
          关闭，继续等待
        </el-button>
        <el-button
          type="danger"
          plain
          :disabled="busy"
          @click="$emit('decide', 'REJECTED')"
        >
          <FluentIcon name="dismiss" aria-hidden="true" />
          <span>拒绝执行</span>
        </el-button>
        <el-button
          type="primary"
          :loading="busy"
          :disabled="busy"
          @click="$emit('decide', 'APPROVED')"
        >
          <FluentIcon v-if="!busy" name="checkmark" aria-hidden="true" />
          <span>允许执行</span>
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>

<style scoped>
.ai-approval-dialog {
  display: flex;
  flex-direction: column;
  gap: 14px;
  font-family: var(--fluent-font);
  font-size: var(--fluent-body1-size, 14px);
  line-height: var(--fluent-body1-line, 20px);
  color: var(--app-text);
}

/* 1. 方案摘要卡片 */
.approval-overview-card {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 12px 14px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card, 8px);
  background: var(--app-surface-soft);
}

.approval-overview-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.approval-id-wrap {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.approval-id-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control, 4px);
  background: var(--app-surface-strong);
  color: var(--app-text);
  font-size: var(--fluent-caption1-size, 12px);
  font-weight: var(--fluent-weight-semibold, 600);
  line-height: 1.4;
}

.approval-scope-label {
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
}

.approval-risk-tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: var(--fluent-radius-circular, 999px);
  font-size: var(--fluent-caption1-size, 12px);
  font-weight: var(--fluent-weight-medium, 500);
  line-height: 1.4;
}

.approval-risk-tag .fluent-system-icon {
  width: 14px;
  height: 14px;
}

.approval-risk-tag.is-caution {
  border: 1px solid color-mix(in srgb, var(--fluent-warning-bg, #8a4b08) 28%, transparent);
  background: color-mix(in srgb, var(--fluent-warning-bg, #8a4b08) 10%, var(--app-surface-strong));
  color: var(--fluent-warning-bg, #8a4b08);
}

.approval-risk-tag.is-normal {
  border: 1px solid color-mix(in srgb, var(--app-accent) 24%, var(--app-border));
  background: var(--app-accent-soft);
  color: var(--app-accent);
}

.approval-meta-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 10px 16px;
  margin: 0;
  padding: 0;
}

.approval-meta-item {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.approval-meta-item dt {
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
  line-height: 16px;
}

.approval-meta-item dd {
  margin: 0;
  color: var(--app-text);
  font-size: var(--fluent-body1-size, 14px);
  line-height: 20px;
  overflow-wrap: anywhere;
}

.approval-target-name {
  display: block;
  font-weight: var(--fluent-weight-semibold, 600);
}

.approval-target-addr {
  display: block;
  margin-top: 2px;
  color: var(--app-muted);
  font-family: var(--font-mono, monospace);
  font-size: var(--fluent-caption1-size, 12px);
}

.approval-port-badge {
  display: inline-block;
  padding: 2px 8px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control, 4px);
  background: var(--app-surface-strong);
  color: var(--app-text);
  font-family: var(--font-mono, monospace);
  font-size: var(--fluent-caption1-size, 12px);
  white-space: nowrap;
}

/* 2. 执行步骤部分 */
.approval-steps-section {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.approval-steps-title {
  display: flex;
  align-items: baseline;
  gap: 8px;
  margin: 0;
  color: var(--app-text);
  font-size: var(--fluent-body1-size, 14px);
  font-weight: var(--fluent-weight-semibold, 600);
}

.approval-steps-count {
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
  font-weight: var(--fluent-weight-regular, 400);
}

.approval-step-list {
  display: grid;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.approval-step-card {
  overflow: hidden;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card, 8px);
  background: var(--app-surface-strong);
}

.approval-step-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 12px;
  border-bottom: 1px solid var(--app-border);
  background: var(--app-surface-soft);
}

.approval-step-number {
  display: grid;
  place-items: center;
  width: 22px;
  height: 22px;
  flex: none;
  border-radius: 50%;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font-size: 11px;
  font-weight: 600;
  line-height: 1;
}

.approval-step-name {
  flex: 1;
  min-width: 0;
  color: var(--app-text);
  font-size: var(--fluent-body1-size, 14px);
  font-weight: var(--fluent-weight-semibold, 600);
  line-height: 20px;
  overflow-wrap: anywhere;
}

.approval-step-risk {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: var(--fluent-radius-circular, 999px);
  font-size: var(--fluent-caption1-size, 12px);
  font-weight: var(--fluent-weight-medium, 500);
  white-space: nowrap;
}

.approval-step-risk .fluent-system-icon {
  width: 14px;
  height: 14px;
}

.approval-step-risk.is-caution {
  border: 1px solid color-mix(in srgb, var(--fluent-warning-bg, #8a4b08) 28%, transparent);
  background: color-mix(in srgb, var(--fluent-warning-bg, #8a4b08) 10%, transparent);
  color: var(--fluent-warning-bg, #8a4b08);
}

.approval-step-risk.is-controlled {
  border: 1px solid var(--app-border);
  background: var(--app-surface-soft);
  color: var(--app-muted);
}

.approval-step-body {
  padding: 10px 12px;
  font-size: var(--fluent-caption1-size, 12px);
  line-height: 18px;
}

.approval-parameters {
  display: grid;
  gap: 6px;
  margin: 0;
  padding: 0;
}

.approval-param-row {
  display: grid;
  grid-template-columns: 88px minmax(0, 1fr);
  align-items: baseline;
  gap: 8px 12px;
  padding: 4px 0;
  border-top: 1px solid color-mix(in srgb, var(--app-border) 60%, transparent);
}

.approval-param-row:first-child {
  border-top: 0;
  padding-top: 0;
}

.approval-param-row:last-child {
  padding-bottom: 0;
}

.approval-param-row dt {
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
}

.approval-param-row dd {
  margin: 0;
  overflow-wrap: anywhere;
}

.approval-param-row dd code {
  padding: 2px 6px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control, 4px);
  background: var(--app-surface-soft);
  color: var(--app-text);
  font-family: var(--font-mono, monospace);
  font-size: var(--fluent-caption1-size, 12px);
  word-break: break-all;
}

.approval-defaults-hint {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
  line-height: 18px;
}

.approval-defaults-hint .fluent-system-icon {
  width: 16px;
  height: 16px;
  flex: none;
  margin-top: 1px;
  color: var(--app-muted);
}

/* 3. 安全策略提示栏 (Fluent InfoBar) */
.approval-policy-infobar {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 14px;
  border: 1px solid color-mix(in srgb, var(--app-accent) 18%, var(--app-border));
  border-radius: var(--fluent-radius-control, 4px);
  background: color-mix(in srgb, var(--app-accent) 6%, var(--app-surface-soft));
}

.approval-policy-icon {
  width: 16px;
  height: 16px;
  flex: none;
  margin-top: 2px;
  color: var(--app-accent);
}

.approval-policy-text {
  margin: 0;
  color: var(--app-text);
  font-size: var(--fluent-caption1-size, 12px);
  line-height: 18px;
}

/* 4. 底部按钮 Fluent 样式微调 */
.app-dialog__footer-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
}

.app-dialog__footer-row .el-button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin: 0;
  min-height: 32px;
}

.app-dialog__footer-row .el-button .fluent-system-icon {
  width: 14px;
  height: 14px;
}

@media (max-width: 520px) {
  .approval-meta-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>

