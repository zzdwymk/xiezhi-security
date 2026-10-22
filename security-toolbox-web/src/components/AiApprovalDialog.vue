<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { ConversationMessage } from "../stores/conversations";
import type { JudgeVerdictDocument } from "../api";
import { aiToolLabel } from "../utils/aiPresentation";
import FluentIcon from "./FluentIcon.vue";

const props = defineProps<{
  visible: boolean;
  message?: ConversationMessage;
  targetName: string;
  targetValue: string;
  allowedPorts: string;
  busy: boolean;
}>();

const emit = defineEmits<{
  (event: "update:visible", value: boolean): void;
  (event: "decide", decision: "APPROVED" | "REJECTED", overrides?: Array<Record<string, any>>): void;
}>();

const hasCautionStep = computed(() =>
  props.message?.steps.some(
    (step) => step.requiresApproval || step.risk === "CAUTION",
  ),
);

const judge = computed<JudgeVerdictDocument | null>(() => props.message?.judge ?? null);

const judgeSeverity = computed<"critical" | "warning" | "clear">(() => {
  const doc = judge.value;
  if (!doc) return "clear";
  if (doc.degraded || doc.worstRisk === "CRITICAL") return "critical";
  if (doc.requiresHumanReview) return "warning";
  return "clear";
});

const judgeTitle = computed(() => {
  const doc = judge.value;
  if (!doc) return "";
  if (doc.degraded) {
    const rawHeadline = doc.headline || "无法判定";
    const cleanHeadline = rawHeadline.startsWith("判官熔断")
      ? rawHeadline.replace(/^判官熔断[（(]?/, "").replace(/[)）]?$/, "")
      : rawHeadline;
    return `安全审查预警（判官熔断）· ${cleanHeadline || "未能自动识别行为模式"}`;
  }
  if (doc.requiresHumanReview) return `行为透视识别 · 疑似 ${doc.headline || "需人工审核的动作"}`;
  return "安全审查通过 · 判官未发现需要拦截的行为";
});

const judgeSeverityIcon = computed(() => {
  if (judgeSeverity.value === "critical") return "dismiss";
  if (judgeSeverity.value === "warning") return "warning";
  return "checkmark-circle";
});

const judgePrimaryStep = computed(() => {
  const steps = judge.value?.steps;
  if (steps && steps.length > 0) return steps[0];
  return null;
});

function judgeRiskTagType(risk: string): "success" | "warning" | "danger" | "info" {
  if (risk === "SAFE") return "success";
  if (risk === "CAUTION") return "warning";
  if (risk === "HIGH" || risk === "CRITICAL") return "danger";
  return "info";
}

function judgeBehaviourLabel(behaviour?: string): string {
  const b = String(behaviour || "").trim();
  if (!b || b === "判官熔断（无法判定）" || b === "无法判定") {
    return "需人工确认";
  }
  return b;
}

// ------------------------------------------------------------------ 可交互参数编辑与选项元数据
const editableParameters = ref<Array<Record<string, any>>>([]);

watch(
  () => props.message?.steps,
  (steps) => {
    if (steps && Array.isArray(steps)) {
      editableParameters.value = steps.map((s) => ({ ...(s.parameters || {}) }));
    } else {
      editableParameters.value = [];
    }
  },
  { immediate: true, deep: true },
);

const DICTIONARY_OPTIONS = [
  { value: "dirb-common", label: "内置常用字典 (dirb-common · 4429条)" },
  { value: "dirb-small", label: "精简高频字典 (dirb-small · 928条)" },
  { value: "dirb-big", label: "大字典 (dirb-big · 20226条)" },
  { value: "dirb-best1050", label: "Top 1050 字典 (dirb-best1050)" },
  { value: "dirbuster-2.3-small", label: "DirBuster 深度字典 (81522条)" },
  { value: "custom", label: "用户自定义字典" },
];

const TECHNIQUE_OPTIONS = [
  { value: "BEUT", label: "全技术综合检测 (布尔/报错/联合/时间)" },
  { value: "B", label: "布尔盲注 (Boolean-based blind)" },
  { value: "E", label: "报错注入 (Error-based)" },
  { value: "U", label: "联合查询注入 (Union query)" },
  { value: "T", label: "时间盲注 (Time-based blind)" },
];

const LEVEL_OPTIONS = [
  { value: 1, label: "1 级 (标准 GET/POST 参数)" },
  { value: 2, label: "2 级 (包含 Cookie 注入)" },
  { value: 3, label: "3 级 (包含 User-Agent 注入)" },
  { value: 4, label: "4 级 (包含 Referer 注入)" },
  { value: 5, label: "5 级 (包含 Host 头深度探测)" },
];

const NMAP_MODE_OPTIONS = [
  { value: "quick", label: "快速扫描（仅端口存活，-sT）" },
  { value: "regular", label: "常规扫描（-sT -v 详细输出）" },
  { value: "intense", label: "深入扫描（-sT -T4 -A -v 服务/系统/脚本）" },
  { value: "intense_udp", label: "深入扫描 + UDP（-sU -T4 -A -v）" },
  { value: "intense_all_tcp", label: "深入扫描 + 全 TCP 端口（-p- -T4 -A -v）" },
  { value: "intense_no_ping", label: "深入扫描 + 不检测存活（-T4 -A -v -Pn）" },
  { value: "ping", label: "Ping 主机发现（-sn -PE -PS443 -PA80）" },
  { value: "quick_plus", label: "快速扫描+（-sV -T4 -O --version-light 版本/系统）" },
  { value: "quick_trace", label: "快速路由追踪（-sn --traceroute）" },
  { value: "slow_comprehensive", label: "慢速全面扫描（-sU -T4 -A -v -p- 默认脚本）" },
  { value: "service", label: "服务识别（-sV -O --version-light 兼容旧值）" },
];

const MODE_OPTIONS = [
  { value: "passive", label: "被动扫描（只观察流量，不主动发包）" },
  { value: "active", label: "主动扫描（主动发送探测请求）" },
];

const VULN_MODE_OPTIONS = [
  { value: "SAFE", label: "安全（默认，仅基础探测）" },
  { value: "FINGERPRINT", label: "指纹（识别目标指纹）" },
  { value: "FULL", label: "完整（含爆破/弱口令，谨慎使用）" },
];

const CHECK_OPTIONS = [
  { value: "cookies", label: "Cookie 安全属性（Secure/HttpOnly/SameSite）" },
  { value: "cors", label: "CORS 跨域策略（跨域读写放开风险）" },
  { value: "methods", label: "危险 HTTP 方法（PUT/DELETE/TRACE 等）" },
  { value: "disclosure", label: "技术栈信息泄露（Server/X-Powered-By 等响应头）" },
];

// 工具码 -> 下拉型参数枚举，避免把半截枚举映射到错误工具上
const ENUM_OPTIONS_BY_TOOL: Record<string, Record<string, { value: any; label: string }[]>> = {
  nmap_service_scan: { mode: NMAP_MODE_OPTIONS },
  zap_fuzz: { mode: MODE_OPTIONS },
  fscan_scan: { vulnMode: VULN_MODE_OPTIONS },
  http_security_check: { check: CHECK_OPTIONS },
};

function enumOptions(toolCode: string | undefined, key: string) {
  return ENUM_OPTIONS_BY_TOOL[String(toolCode || "")]?.[key];
}

// 与后端 NmapServiceScanTool.buildCommand 对齐的“实际执行命令”预览（仅展示，非真正下发）。
const NMAP_MODE_FLAGS: Record<string, string> = {
  quick: "",
  regular: "-v",
  intense: "-T4 -A -v",
  intense_udp: "-sU -T4 -A -v",
  intense_all_tcp: "-T4 -A -v -p-",
  intense_no_ping: "-T4 -A -v -Pn",
  ping: "-sn -PE -PS443 -PA80",
  quick_plus: "-sV -T4 -O --version-light",
  quick_trace: "-sn --traceroute",
  slow_comprehensive: "-sU -T4 -A -v -p- --script default",
  service: "-sV -T4 -O --version-light",
};
const NMAP_NO_PORT_MODES = new Set(["ping", "quick_trace"]);

function nmapCommandPreview(parameters: Record<string, any>): string {
  const mode = String(parameters?.mode || "quick");
  const ports = String(parameters?.ports || "1-65535").trim();
  const parts = ["nmap", "-sT", "-n"];
  const flags = NMAP_MODE_FLAGS[mode] ?? "";
  if (flags) parts.push(flags);
  if (!NMAP_NO_PORT_MODES.has(mode)) parts.push(ports === "1-65535" ? "-p-" : `-p ${ports}`);
  parts.push("--stats-every 1s", "-oX -", "<目标>");
  return parts.join(" ");
}

const RISK_OPTIONS = [
  { value: 1, label: "1 级 (默认无害测试，不破坏数据)" },
  { value: 2, label: "2 级 (包含重负载时间盲注)" },
  { value: 3, label: "3 级 (高风险，可能触发更新或堆叠查询)" },
];

const PARAM_LABELS: Record<string, string> = {
  concurrency: "并发请求数",
  workers: "并发工作线程",
  depth: "探测深度",
  dictionary: "枚举字典",
  ports: "扫描端口",
  path: "请求路径",
  level: "检测级别",
  risk: "风险级别",
  technique: "检测技术",
  timeout: "超时时间 (秒)",
  extensions: "匹配扩展名",
  vulnMode: "扫描模式",
  mode: "识别模式",
  check: "检查项目",
};

function onApprove() {
  const overrides = editableParameters.value.map((p) => ({ ...p }));
  emit("decide", "APPROVED", overrides);
}
</script>

<template>
  <el-dialog
    :model-value="visible"
    title="确认 AI 行动方案"
    class="app-dialog ai-approval-modal"
    style="--app-dialog-width: 640px"
    align-center
    append-to-body
    :close-on-click-modal="false"
    :close-on-press-escape="!busy"
    :show-close="!busy"
    @update:model-value="$emit('update:visible', $event)"
  >
    <template #header>
      <div class="approval-dialog-header">
        <div class="approval-header-title-row">
          <FluentIcon name="shield" class="approval-header-icon" aria-hidden="true" />
          <h2 class="approval-header-title">检测操作授权审批</h2>
          <span class="approval-header-subtag">AI 建议行动方案</span>
        </div>
        <p class="approval-header-desc">
          AI 智能体基于当前分析建议执行以下探测动作，须由管理员审核具体动作与核对参数后授权执行。
        </p>
      </div>
    </template>

    <section
      v-if="message"
      class="ai-approval-dialog"
      :data-approval-id="message.approvalId"
    >
      <!-- 1. 方案摘要与授权目标元数据卡片 (Fluent 2 Card) -->
      <section class="approval-overview-card" aria-label="授权目标与范围">
        <header class="approval-overview-head">
          <div class="approval-id-wrap">
            <span class="approval-id-badge">待审方案 #{{ message.approvalId }}</span>
            <span class="approval-scope-label">单次授权有效</span>
          </div>
          <span
            class="approval-risk-tag"
            :class="hasCautionStep ? 'is-caution' : 'is-normal'"
          >
            <FluentIcon
              :name="hasCautionStep ? 'warning' : 'shield'"
              aria-hidden="true"
            />
            <span>{{ hasCautionStep ? "需人工审核" : "受控常规操作" }}</span>
          </span>
        </header>

        <dl class="approval-meta-grid">
          <div class="approval-meta-item is-target">
            <dt>申请执行目标</dt>
            <dd>
              <strong class="approval-target-name">{{ targetName }}</strong>
              <code class="approval-target-addr">{{ targetValue }}</code>
            </dd>
          </div>
          <div class="approval-meta-item">
            <dt>允许端口范围</dt>
            <dd>
              <span class="approval-port-badge">{{
                allowedPorts || "以登记的授权范围为准"
              }}</span>
            </dd>
          </div>
        </dl>
      </section>

      <!-- 2. 系统安全风险初审横幅 (Fluent 2 InfoBar，无内嵌多层杂乱方框) -->
      <section
        v-if="judge"
        class="approval-judge-banner"
        :class="`approval-judge-banner--${judgeSeverity}`"
        aria-label="系统安全风险初审"
      >
        <header class="approval-judge-head">
          <div class="approval-judge-icon-wrap" :class="`is-${judgeSeverity}`">
            <FluentIcon :name="judgeSeverityIcon" aria-hidden="true" />
          </div>
          <strong class="approval-judge-title">{{ judgeTitle }}</strong>
          <el-tag size="small" :type="judgeRiskTagType(judge.worstRisk)">
            最高风险 {{ judge.worstRisk }}
          </el-tag>
          <el-tag v-if="judge.degraded" size="small" type="danger" effect="dark">
            熔断拦截
          </el-tag>
        </header>

        <p v-if="judge.degraded" class="approval-judge-note">
          语义判官未能给出可信判定（{{ judge.degradedReason || "原因未知" }}）。
          按 Fail-Closed 原则，系统已按最坏情况标记为高风险，请人工逐项核对下方具体参数后再决定。
        </p>

        <!-- 纯净通透的行为解读，彻底移除内嵌杂乱嵌套灰框 -->
        <div v-if="judgePrimaryStep" class="approval-judge-narrative">
          <p class="approval-judge-summary-lead">
            {{ judgePrimaryStep.summary }}
          </p>
          <div class="approval-judge-meta-row">
            <el-tag size="small" :type="judgeRiskTagType(judgePrimaryStep.risk)" effect="plain">
              {{ judgeBehaviourLabel(judgePrimaryStep.behaviour) }}
            </el-tag>
            <span class="approval-judge-tool-lead">{{ aiToolLabel(judgePrimaryStep.toolCode) }}</span>
            <span class="approval-judge-conf-badge">
              置信度 {{ Math.round((judgePrimaryStep.confidence || 0) * 100) }}%
            </span>
          </div>
        </div>

        <p v-else-if="judge.degraded" class="approval-judge-note">
          本次没有可用的逐项判定结果，全部步骤均需人工判断。
        </p>
      </section>

      <!-- 3. 拟执行检测方案清单 (Fluent 2 List，参数支持管理员直接交互调整) -->
      <section class="approval-steps-section" aria-label="拟执行检测方案清单">
        <h3 class="approval-steps-title">
          <span>待授权检测方案</span>
          <span class="approval-steps-count">拟执行计划 {{ message.steps.length }} 步</span>
          <span class="approval-steps-tip">（参数支持管理员直接微调）</span>
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
              <!-- 交互式参数编辑表单：支持用户在审批时直接选择/微调参数 -->
              <dl
                v-if="editableParameters[index] && Object.keys(editableParameters[index]).length"
                class="approval-parameters"
              >
                <div
                  v-for="(val, key) in editableParameters[index]"
                  :key="key"
                  class="approval-param-row"
                >
                  <dt class="approval-param-label">{{ PARAM_LABELS[key] || key }}</dt>
                  <dd class="approval-param-control-cell">
                    <!-- 0. 工具原生枚举下拉：Nmap 识别模式 / 扫描模式 / HTTP 检查项等 -->
                    <el-select
                      v-if="enumOptions(step.toolCode, key)"
                      v-model="editableParameters[index][key]"
                      size="small"
                      class="param-interactive-control"
                      :disabled="busy"
                    >
                      <el-option
                        v-for="opt in enumOptions(step.toolCode, key)"
                        :key="opt.value"
                        :label="opt.label"
                        :value="opt.value"
                      />
                    </el-select>

                    <!-- 1. 字典选择型参数 -->
                    <el-select
                      v-if="key === 'dictionary'"
                      v-model="editableParameters[index][key]"
                      size="small"
                      class="param-interactive-control"
                      :disabled="busy"
                    >
                      <el-option
                        v-for="opt in DICTIONARY_OPTIONS"
                        :key="opt.value"
                        :label="opt.label"
                        :value="opt.value"
                      />
                    </el-select>

                    <!-- 2. 探测深度步进器 (1~3层) -->
                    <el-input-number
                      v-else-if="key === 'depth'"
                      v-model="editableParameters[index][key]"
                      :min="1"
                      :max="3"
                      size="small"
                      controls-position="right"
                      class="param-interactive-number"
                      :disabled="busy"
                    />

                    <!-- 3. 并发请求数步进器 (1~50) -->
                    <el-input-number
                      v-else-if="key === 'concurrency' || key === 'workers'"
                      v-model="editableParameters[index][key]"
                      :min="1"
                      :max="50"
                      :step="5"
                      size="small"
                      controls-position="right"
                      class="param-interactive-number"
                      :disabled="busy"
                    />

                    <!-- 4. 检测技术下拉选择 -->
                    <el-select
                      v-else-if="key === 'technique'"
                      v-model="editableParameters[index][key]"
                      size="small"
                      class="param-interactive-control"
                      :disabled="busy"
                    >
                      <el-option
                        v-for="opt in TECHNIQUE_OPTIONS"
                        :key="opt.value"
                        :label="opt.label"
                        :value="opt.value"
                      />
                    </el-select>

                    <!-- 5. 检测级别下拉选择 -->
                    <el-select
                      v-else-if="key === 'level'"
                      v-model="editableParameters[index][key]"
                      size="small"
                      class="param-interactive-control"
                      :disabled="busy"
                    >
                      <el-option
                        v-for="opt in LEVEL_OPTIONS"
                        :key="opt.value"
                        :label="opt.label"
                        :value="opt.value"
                      />
                    </el-select>

                    <!-- 6. 风险级别下拉选择 -->
                    <el-select
                      v-else-if="key === 'risk'"
                      v-model="editableParameters[index][key]"
                      size="small"
                      class="param-interactive-control"
                      :disabled="busy"
                    >
                      <el-option
                        v-for="opt in RISK_OPTIONS"
                        :key="opt.value"
                        :label="opt.label"
                        :value="opt.value"
                      />
                    </el-select>

                    <!-- 7. 布尔开关 -->
                    <el-switch
                      v-else-if="typeof val === 'boolean'"
                      v-model="editableParameters[index][key]"
                      size="small"
                      :disabled="busy"
                    />

                    <!-- 8. 其他数字输入 -->
                    <el-input-number
                      v-else-if="typeof val === 'number'"
                      v-model="editableParameters[index][key]"
                      size="small"
                      controls-position="right"
                      class="param-interactive-number"
                      :disabled="busy"
                    />

                    <!-- 9. 通用文本输入 (端口、路径等) -->
                    <el-input
                      v-else
                      v-model="editableParameters[index][key]"
                      size="small"
                      class="param-interactive-input"
                      :disabled="busy"
                    />
                  </dd>
                </div>
              </dl>

              <div
                v-if="
                  step.toolCode === 'nmap_service_scan' &&
                  editableParameters[index] &&
                  Object.keys(editableParameters[index]).length
                "
                class="approval-command-preview"
              >
                <span class="approval-command-preview-label">本轮将执行命令</span>
                <code class="approval-command-preview-code">{{
                  nmapCommandPreview(editableParameters[index])
                }}</code>
              </div>

              <div v-else-if="!editableParameters[index] || !Object.keys(editableParameters[index]).length" class="approval-defaults-hint">
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

      <!-- 4. 安全策略提示 (Fluent InfoBar) -->
      <div class="approval-policy-infobar" role="note">
        <FluentIcon name="info" class="approval-policy-icon" aria-hidden="true" />
        <p class="approval-policy-text">
          授权后系统将严格按照上述目标范围与核对参数派发任务；拒绝将终止本次方案。允许后将执行以上计划。
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
          拒绝执行
        </el-button>
        <el-button
          type="primary"
          :loading="busy"
          :disabled="busy"
          @click="onApprove"
        >
          允许执行
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>

<style scoped>
.approval-dialog-header {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.approval-header-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.approval-header-icon {
  width: 20px;
  height: 20px;
  color: var(--app-accent, #0f6cbd);
  flex: none;
}

.approval-header-title {
  margin: 0;
  font-family: var(--fluent-font, system-ui, sans-serif);
  font-size: 18px;
  font-weight: 600;
  color: var(--app-text);
  line-height: 24px;
}

.approval-header-subtag {
  display: inline-flex;
  align-items: center;
  padding: 1px 8px;
  border-radius: 4px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font-size: 11px;
  font-weight: 500;
}

.approval-header-desc {
  margin: 2px 0 0;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.5;
}

.ai-approval-dialog {
  display: flex;
  flex-direction: column;
  gap: 14px;
  font-family: var(--fluent-font, system-ui, -apple-system, sans-serif);
  font-size: var(--fluent-body1-size, 14px);
  line-height: var(--fluent-body1-line, 20px);
  color: var(--app-text);
}

/* 1. 方案摘要卡片 (Fluent 2 Card) */
.approval-overview-card {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 12px 14px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card, 8px);
  background: var(--app-surface-soft);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}

.approval-overview-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding-bottom: 8px;
  border-bottom: 1px solid color-mix(in srgb, var(--app-border) 60%, transparent);
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
  font-size: 12px;
  font-weight: 600;
  line-height: 1.4;
}

.approval-scope-label {
  color: var(--app-muted);
  font-size: 12px;
}

.approval-risk-tag {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 2px 10px;
  border-radius: var(--fluent-radius-circular, 999px);
  font-size: 12px;
  font-weight: 500;
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
  gap: 10px 20px;
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
  font-size: 12px;
  line-height: 16px;
}

.approval-meta-item dd {
  margin: 0;
  color: var(--app-text);
  font-size: 14px;
  line-height: 20px;
  overflow-wrap: anywhere;
}

.approval-target-name {
  display: block;
  font-weight: 600;
}

.approval-target-addr {
  display: inline-block;
  margin-top: 2px;
  padding: 2px 6px;
  border-radius: 4px;
  background: var(--app-surface);
  border: 1px solid color-mix(in srgb, var(--app-border) 60%, transparent);
  color: var(--app-text);
  font-family: var(--font-mono, monospace);
  font-size: 12px;
}

.approval-port-badge {
  display: inline-block;
  padding: 2px 8px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control, 4px);
  background: var(--app-surface-strong);
  color: var(--app-text);
  font-family: var(--font-mono, monospace);
  font-size: 12px;
  white-space: nowrap;
}

/* 2. 智能安全风险初审横幅 (Fluent 2 InfoBar 规范：四边等宽 1px 描边 + 柔和底色 + 状态图标) */
.approval-judge-banner {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px 16px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card, 8px);
  background: var(--app-surface-soft);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
  transition: border-color var(--fluent-fast, 120ms) ease, background-color var(--fluent-fast, 120ms) ease;
}

.approval-judge-banner--critical {
  border-color: color-mix(in srgb, var(--fluent-error-bg, #a4262c) 35%, var(--app-border));
  background: color-mix(in srgb, var(--fluent-error-bg, #a4262c) 6%, var(--app-surface));
}

.approval-judge-banner--warning {
  border-color: color-mix(in srgb, var(--fluent-warning-bg, #8a4b08) 35%, var(--app-border));
  background: color-mix(in srgb, var(--fluent-warning-bg, #8a4b08) 6%, var(--app-surface));
}

.approval-judge-banner--clear {
  border-color: color-mix(in srgb, #107c41 35%, var(--app-border));
  background: color-mix(in srgb, #107c41 6%, var(--app-surface));
}

.approval-judge-head {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.approval-judge-icon-wrap {
  display: grid;
  place-items: center;
  width: 20px;
  height: 20px;
  flex: none;
}

.approval-judge-icon-wrap .fluent-system-icon {
  width: 18px;
  height: 18px;
}

.approval-judge-icon-wrap.is-critical {
  color: var(--fluent-error-bg, #a4262c);
}

.approval-judge-icon-wrap.is-warning {
  color: var(--fluent-warning-bg, #8a4b08);
}

.approval-judge-icon-wrap.is-clear {
  color: #107c41;
}

.approval-judge-title {
  flex: 1;
  min-width: 140px;
  color: var(--app-text);
  font-size: 14px;
  font-weight: 600;
  overflow-wrap: anywhere;
}

.approval-judge-note {
  margin: 0;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 18px;
  overflow-wrap: anywhere;
}

/* 纯净通透的行为解读 */
.approval-judge-narrative {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin: 0;
  padding: 0;
}

.approval-judge-summary-lead {
  margin: 0;
  color: var(--app-text);
  font-size: 13px;
  line-height: 1.5;
}

.approval-judge-meta-row {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  font-size: 12px;
}

.approval-judge-tool-lead {
  font-weight: 600;
  color: var(--app-text);
}

.approval-judge-conf-badge {
  color: var(--app-muted);
  font-variant-numeric: tabular-nums;
  font-size: 12px;
}

/* 3. 执行动作清单 (Fluent 2 List) */
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
  font-size: 14px;
  font-weight: 600;
}

.approval-steps-count {
  color: var(--app-muted);
  font-size: 12px;
  font-weight: 400;
}

.approval-steps-tip {
  color: var(--app-accent, #0f6cbd);
  font-size: 12px;
  font-weight: 400;
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
  background: var(--app-surface);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
}

.approval-step-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  border-bottom: 1px solid color-mix(in srgb, var(--app-border) 60%, transparent);
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
  font-size: 12px;
  font-weight: 600;
  line-height: 1;
}

.approval-step-name {
  flex: 1;
  min-width: 0;
  color: var(--app-text);
  font-size: 14px;
  font-weight: 600;
  line-height: 20px;
  overflow-wrap: anywhere;
}

.approval-step-risk {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: var(--fluent-radius-circular, 999px);
  font-size: 12px;
  font-weight: 500;
  line-height: 1.4;
}

.approval-step-risk .fluent-system-icon {
  width: 14px;
  height: 14px;
}

.approval-step-risk.is-caution {
  background: color-mix(in srgb, var(--fluent-warning-bg, #8a4b08) 12%, transparent);
  color: var(--fluent-warning-bg, #8a4b08);
}

.approval-step-risk.is-controlled {
  background: color-mix(in srgb, var(--app-accent) 12%, transparent);
  color: var(--app-accent);
}

.approval-step-body {
  padding: 10px 14px;
}

.approval-parameters {
  display: grid;
  gap: 10px;
  margin: 0;
  padding: 0;
}

.approval-param-row {
  display: grid;
  grid-template-columns: 105px 1fr;
  align-items: center;
  gap: 12px;
  font-size: 13px;
}

.approval-param-label {
  color: var(--app-muted);
  font-weight: 500;
  font-size: 13px;
}

.approval-param-control-cell {
  margin: 0;
}

.param-interactive-control {
  width: 100%;
  max-width: 320px;
}

.param-interactive-number {
  width: 100%;
  max-width: 320px;
}

.param-interactive-input {
  width: 100%;
  max-width: 340px;
}

.approval-command-preview {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin-top: 10px;
  padding: 8px 10px;
  border: 1px solid color-mix(in srgb, var(--app-border) 70%, transparent);
  border-radius: var(--fluent-radius-control, 4px);
  background: var(--app-surface-soft);
}

.approval-command-preview-label {
  color: var(--app-muted);
  font-size: 11px;
  font-weight: 500;
}

.approval-command-preview-code {
  font-family: var(--font-mono, monospace);
  font-size: 12px;
  line-height: 1.5;
  color: var(--app-text);
  overflow-wrap: anywhere;
  white-space: pre-wrap;
}

.approval-defaults-hint {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--app-muted);
  font-size: 13px;
}

.approval-defaults-hint .fluent-system-icon {
  width: 16px;
  height: 16px;
  flex: none;
}

/* 4. 底部安全策略提示 (Fluent InfoBar) */
.approval-policy-infobar {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 14px;
  border: 1px solid color-mix(in srgb, var(--app-accent) 25%, var(--app-border));
  border-radius: var(--fluent-radius-card, 8px);
  background: var(--app-accent-soft);
  color: var(--app-text);
  font-size: 12px;
  line-height: 1.5;
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
  flex: 1;
}

.app-dialog__footer-row {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 10px;
}
</style>
