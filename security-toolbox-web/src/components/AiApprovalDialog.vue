<script setup lang="ts">
import type { ConversationMessage } from "../stores/conversations";
import { aiToolLabel } from "../utils/aiPresentation";
import { approvalParameterRows } from "../utils/aiApproval";
defineProps<{ visible: boolean; message?: ConversationMessage; targetName: string; targetValue: string; allowedPorts: string; busy: boolean }>();
defineEmits<{ (event: "update:visible", value: boolean): void; (event: "decide", decision: "APPROVED" | "REJECTED"): void }>();
</script>

<template>
  <el-dialog :model-value="visible" title="确认本次检测" class="app-dialog ai-approval-modal" style="--app-dialog-width: 560px" align-center append-to-body :close-on-click-modal="false" :close-on-press-escape="!busy" :show-close="!busy" @update:model-value="$emit('update:visible', $event)">
    <section v-if="message" class="ai-approval-dialog" :data-approval-id="message.approvalId">
      <p class="approval-id">审批单 #{{ message.approvalId }} · 仅本次执行</p>
      <dl class="approval-target"><dt>授权目标</dt><dd>{{ targetName }} · {{ targetValue }}</dd><dt>授权端口</dt><dd>{{ allowedPorts || '以登记的授权范围为准' }}</dd></dl>
      <ol class="approval-tools">
        <li v-for="(step, index) in message.steps" :key="step.id || index">
          <strong>{{ aiToolLabel(step.toolCode) }}</strong>
          <span class="approval-risk">{{ step.requiresApproval || step.risk === 'CAUTION' ? '需人工确认' : '受控操作' }}</span>
          <dl v-if="Object.keys(step.parameters || {}).length" class="approval-parameters"><template v-for="row in approvalParameterRows(step.parameters)" :key="row.label"><dt>{{ row.label }}</dt><dd>{{ row.value }}</dd></template></dl>
          <p v-else class="approval-defaults">{{ step.toolCode === 'nuclei_scan' ? '默认安全模板（未提供参数覆盖）' : '未提供参数覆盖，使用该节点已保存的配置' }}；本轮仍受登记范围约束。</p>
        </li>
      </ol>
      <p class="approval-note">批准后将执行以上计划。关闭窗口会继续等待，不会创建检测任务。</p>
    </section>
    <template #footer>
      <div class="approval-buttons"><el-button :disabled="busy" @click="$emit('update:visible', false)">关闭，继续等待</el-button><el-button :disabled="busy" @click="$emit('decide', 'REJECTED')">拒绝</el-button><el-button type="primary" :loading="busy" :disabled="busy" @click="$emit('decide', 'APPROVED')">批准本次执行</el-button></div>
    </template>
  </el-dialog>
</template>

<style scoped>
.ai-approval-dialog { font-size: 14px; line-height: 20px; color: var(--app-text); }
.approval-id,.approval-defaults,.approval-note { color: var(--app-muted); }
.approval-target,.approval-parameters { display: grid; grid-template-columns: 88px minmax(0,1fr); gap: 8px 12px; }
dt { color: var(--app-muted); } dd { margin: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
.approval-tools { margin: 16px 0; padding-left: 24px; } .approval-tools li { margin: 12px 0; }
.approval-risk { margin-left: 8px; color: var(--app-muted); } .approval-buttons { display: flex; justify-content: flex-end; flex-wrap: wrap; gap: 8px; }
.approval-buttons :deep(.el-button) { margin: 0; min-height: 40px; }
</style>
