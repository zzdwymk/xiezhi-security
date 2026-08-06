<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Aim,
  MagicStick,
  Refresh,
  Search,
  VideoPlay,
} from "../components/fluentIcons";
import {
  DetectionRule,
  endpoints,
  Target,
  VulnerabilityCatalogStats,
  VulnerabilityDefinition,
} from "../api";
import { useCopilotStore } from "../stores/copilot";
import { toErrorMessage } from "../utils/errorMessage";

const copilot = useCopilotStore();
const router = useRouter();

const vulnerabilities = ref<VulnerabilityDefinition[]>([]);
const route = useRoute();
const rules = ref<DetectionRule[]>([]);
const targets = ref<Target[]>([]);
const selected = ref<VulnerabilityDefinition>();
const query = ref("");
const severityFilter = ref("");
const sourceFilter = ref("");
const yearFilter = ref("");
const safetyFilter = ref("");
const knownExploitedOnly = ref(false);
const page = ref(0);
// Keep the catalog deliberately compact: exactly ten entries per page.
const pageSize = 10;
const total = ref(0);
const stats = ref<VulnerabilityCatalogStats>();
const targetId = ref<number>();
const selectedRuleCodes = ref<string[]>([]);
const portSelections = ref<string[]>([]);
const loading = ref(false);
const scanning = ref(false);
const syncingCatalog = ref(false);
const projectIdByTarget = ref<Record<number, number>>({});

const enabledTargets = computed(() =>
  targets.value.filter((item) => item.enabled),
);
const selectedRules = computed(() =>
  rules.value.filter((item) => selectedRuleCodes.value.includes(item.ruleCode)),
);
const includesPortScan = computed(() =>
  selectedRules.value.some((item) =>
    ["tcp_ports", "nmap_service_scan"].includes(item.toolCode),
  ),
);
const includesNucleiScan = computed(() =>
  selectedRules.value.some((item) => item.toolCode === "nuclei_scan"),
);
const selectedTarget = computed(() =>
  targets.value.find((item) => item.id === targetId.value),
);
const isFullPortTarget = computed(
  () => selectedTarget.value?.allowedPorts?.replace(/\s/g, "") === "1-65535",
);
const compatibleRules = computed(() =>
  rules.value.filter((rule) => isRuleCompatible(rule, selectedTarget.value)),
);

const commonPorts = [
  { value: "21", label: "21 · FTP" },
  { value: "22", label: "22 · SSH" },
  { value: "23", label: "23 · Telnet" },
  { value: "25", label: "25 · SMTP" },
  { value: "53", label: "53 · DNS" },
  { value: "80", label: "80 · HTTP" },
  { value: "110", label: "110 · POP3" },
  { value: "139", label: "139 · NetBIOS" },
  { value: "443", label: "443 · HTTPS" },
  { value: "445", label: "445 · SMB" },
  { value: "1433", label: "1433 · SQL Server" },
  { value: "3306", label: "3306 · MySQL" },
  { value: "3389", label: "3389 · RDP" },
  { value: "5432", label: "5432 · PostgreSQL" },
  { value: "6379", label: "6379 · Redis" },
  { value: "8080", label: "8080 · HTTP Alt" },
  { value: "9200", label: "9200 · Elasticsearch" },
  { value: "27017", label: "27017 · MongoDB" },
];

function normalizePortToken(value: string) {
  return value.trim().replace(/[\u2013\u2014~]/g, "-");
}

function normalizedPorts() {
  const tokens = portSelections.value
    .flatMap((value) => value.replace(/[，；;\s]+/g, ",").split(","))
    .map(normalizePortToken)
    .filter(Boolean);
  if (!tokens.length) throw new Error("请至少选择或填写一个扫描端口");
  for (const token of tokens) {
    const match = token.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
    if (!match) throw new Error(`端口“${token}”格式不正确`);
    const start = Number(match[1]);
    const end = Number(match[2] || match[1]);
    if (start < 1 || end > 65535 || start > end)
      throw new Error(`端口“${token}”不在有效范围内`);
  }
  return [...new Set(tokens)].join(",");
}

function severityType(severity: string) {
  if (severity === "CRITICAL" || severity === "HIGH") return "danger";
  if (severity === "MEDIUM") return "warning";
  if (severity === "LOW") return "info";
  return "success";
}

function isRuleCompatible(rule: DetectionRule, target?: Target) {
  if (!target || rule.targetType.toUpperCase() === "ANY") return true;
  const type = rule.targetType.toUpperCase();
  const value = target.targetValue.toLowerCase();
  if (type === "HTTPS") return value.startsWith("https://");
  if (type === "WEB") {
    return (
      value.startsWith("http://") ||
      value.startsWith("https://") ||
      target.targetType.toUpperCase() === "URL"
    );
  }
  return type === target.targetType.toUpperCase();
}

function compatibilityHint(rule: DetectionRule) {
  if (isFullPortTarget.value && rule.toolCode === "tcp_ports")
    return "全端口不能使用逐端口 TCP 探测，请改用 Nmap";
  if (!selectedTarget.value || isRuleCompatible(rule, selectedTarget.value))
    return "";
  if (rule.targetType.toUpperCase() === "HTTPS")
    return "当前目标不是 HTTPS 地址";
  if (rule.targetType.toUpperCase() === "WEB") return "当前目标不是 Web 地址";
  return `仅适用于 ${rule.targetType} 目标`;
}

// Monotonic generation token: each load() call bumps this so stale responses (e.g.
// from the 5s sync poll racing a user page click) are discarded instead of
// overwriting newer results or fighting each other.
let loadGen = 0;

async function load() {
  loading.value = true;
  const gen = ++loadGen;
  try {
    const [
      vulnerabilityResponse,
      statsResponse,
      ruleResponse,
      targetResponse,
      projectResponse,
    ] = await Promise.all([
      endpoints.vulnerabilities({
        page: page.value,
        size: pageSize,
        query: query.value,
        severity: severityFilter.value || undefined,
        source: sourceFilter.value || undefined,
        year: yearFilter.value || undefined,
        knownExploited: knownExploitedOnly.value || undefined,
        scanSafety: safetyFilter.value || undefined,
      }),
      endpoints.vulnerabilityStats(),
      endpoints.detectionRules(),
      endpoints.targets(),
      endpoints.projects(),
    ]);
    if (gen !== loadGen) return;
    const content = vulnerabilityResponse.data.content || [];
    total.value = Number(vulnerabilityResponse.data.totalElements || 0);
    const maxPage = Math.max(0, Math.ceil(total.value / pageSize) - 1);
    if (total.value > 0 && page.value > maxPage) {
      page.value = maxPage;
      const retry = await endpoints.vulnerabilities({
        page: page.value,
        size: pageSize,
        query: query.value,
        severity: severityFilter.value || undefined,
        source: sourceFilter.value || undefined,
        year: yearFilter.value || undefined,
        knownExploited: knownExploitedOnly.value || undefined,
        scanSafety: safetyFilter.value || undefined,
      });
      if (gen !== loadGen) return;
      vulnerabilities.value = (retry.data.content || []).slice(0, pageSize);
      total.value = Number(retry.data.totalElements || 0);
    } else {
      vulnerabilities.value = content.slice(0, pageSize);
      // If content is empty but total > 0 the catalog shrank mid-flight (e.g. during
      // a Nuclei sync). Show the empty page rather than recursively reloading — the
      // sync poll or next navigation will refresh the list shortly.
    }
    stats.value = statsResponse.data;
    rules.value = ruleResponse.data;
    targets.value = targetResponse.data;
    const activeProjects = projectResponse.data.filter(
      (item) => item.status === "ACTIVE",
    );
    const memberships = await Promise.all(
      activeProjects.map(async (item) => ({
        projectId: item.id,
        links: (await endpoints.projectTargets(item.id)).data,
      })),
    );
    const mapping: Record<number, number> = {};
    for (const membership of memberships)
      for (const link of membership.links)
        if (!mapping[link.targetId])
          mapping[link.targetId] = membership.projectId;
    projectIdByTarget.value = mapping;
    const requestedTarget = Number(route.query.target);
    if (
      !targetId.value &&
      Number.isFinite(requestedTarget) &&
      targets.value.some((item) => item.id === requestedTarget && item.enabled)
    ) {
      targetId.value = requestedTarget;
    }
    if (
      !selected.value ||
      !vulnerabilities.value.some((item) => item.id === selected.value?.id)
    ) {
      selected.value = vulnerabilities.value[0];
    }
    if (!selectedRuleCodes.value.length)
      selectedRuleCodes.value = rules.value
        .filter((item) => item.toolCode !== "nuclei_scan")
        .map((item) => item.ruleCode);
  } catch (error) {
    if (gen === loadGen) ElMessage.error(describeCatalogLoadError(error));
  } finally {
    if (gen === loadGen) loading.value = false;
  }
}

// Surfaces the concrete failure instead of a single opaque message so a stopped or
// still-starting backend can be told apart from an actual server-side error.
function describeCatalogLoadError(error: unknown): string {
  const base = "无法加载漏洞库";
  const err = error as {
    code?: string;
    message?: string;
    response?: { status?: number };
    config?: { url?: string };
  };
  const endpoint = err?.config?.url ? `（接口 ${err.config.url}）` : "";
  const status = err?.response?.status;
  if (status) {
    if (status === 401 || status === 403)
      return `${base}：登录状态已失效，请重新登录${endpoint}`;
    if (status >= 500) return `${base}：本地服务返回 ${status} 错误${endpoint}`;
    return `${base}：请求失败（HTTP ${status}）${endpoint}`;
  }
  if (err?.code === "ECONNABORTED")
    return `${base}：本地服务响应超时，请确认后端已启动${endpoint}`;
  if (err?.code === "ERR_NETWORK" || !err?.response) {
    return `${base}：无法连接本地服务，请确认桌面后端正在运行${endpoint}`;
  }
  return `${base}，请检查本地引擎${endpoint}`;
}

function searchCatalog() {
  page.value = 0;
  void load();
}

function changePage(value: number) {
  const next = Math.max(1, Math.floor(Number(value) || 1));
  const maxPageNumber = Math.max(1, Math.ceil(total.value / pageSize) || 1);
  const clamped = Math.min(next, maxPageNumber);
  page.value = clamped - 1;
  void load();
}

function references(value?: string) {
  return (value || "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function verificationLabel(item: VulnerabilityDefinition) {
  if (item.verificationStatus === "OFFICIAL_RELEASE_DIGEST_PRESENT")
    return "官方固定版本 · 含签名摘要";
  if (item.sourceType === "BUILTIN") return "獬豸内置复核";
  if (item.templateSigned) return "本地模板 · 含签名摘要";
  return "来源待复核";
}

function askCopilot(item: VulnerabilityDefinition) {
  copilot.prepare({
    targetId: targetId.value,
    refs: [
      {
        type: "vulnerability",
        id: item.id,
        targetId: targetId.value,
        title: item.sourceExternalId || item.vulnerabilityCode || item.name,
      },
    ],
    mode: targetId.value ? "plan" : "ask",
    prompt: targetId.value
      ? "结合当前授权目标评估该漏洞的相关性，生成非破坏性的验证计划，并明确停止条件和修复优先级。"
      : "解释该漏洞的影响、常见受影响条件、检测思路和修复优先级，不执行任何检测。",
  });
  void router.push("/");
}

function syncErrorText(error: unknown) {
  return toErrorMessage(error, "漏洞库同步失败");
}

async function syncOfficialCatalog() {
  try {
    await ElMessageBox.confirm(
      "将从 ProjectDiscovery 官方稳定 Release 更新 Nuclei 与模板，校验 SHA-256 后导入漏洞元数据，并使用 CISA KEV 标记已知在野利用漏洞。不会自动执行导入的 PoC。",
      "更新真实漏洞库",
      {
        confirmButtonText: "更新并同步",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    syncingCatalog.value = true;
    if (window.toolboxDesktop?.installDependency) {
      await window.toolboxDesktop.installDependency("nuclei");
    }
    // Only poll backend sync state after local dependency install succeeds.
    startSyncStatusPoll();
    const { data } = await endpoints.syncNucleiCatalog();
    ElMessage.success(
      `同步完成：发现 ${data.discovered} 个真实模板，新增 ${data.imported}，更新 ${data.updated}`,
    );
    page.value = 0;
    await load();
  } catch (error: any) {
    if (error !== "cancel" && error !== "close") {
      ElMessage.error(syncErrorText(error));
    }
  } finally {
    syncingCatalog.value = false;
  }
}

async function startScan() {
  if (!targetId.value) return ElMessage.warning("请先选择一个已授权目标");
  if (!selectedRuleCodes.value.length)
    return ElMessage.warning("请至少选择一条检测规则");
  const target = targets.value.find((item) => item.id === targetId.value);
  if (
    isFullPortTarget.value &&
    selectedRules.value.some((rule) => rule.toolCode === "tcp_ports")
  ) {
    return ElMessage.warning(
      "全端口扫描不能使用 TCP 逐端口探测，请选择 Nmap 服务扫描",
    );
  }
  let ports: string | undefined;
  if (includesPortScan.value) {
    try {
      ports = normalizedPorts();
    } catch (error) {
      return ElMessage.warning(toErrorMessage(error, "扫描端口设置无效"));
    }
  }
  try {
    await ElMessageBox.confirm(
      includesNucleiScan.value
        ? `将对“${target?.name || targetId.value}”执行 ${selectedRuleCodes.value.length} 条检测规则，其中包含 Nuclei 通用漏洞模板扫描，可能发送较多请求并耗时较长。所有请求仍受授权范围和端口白名单限制。`
        : `将对“${target?.name || targetId.value}”执行 ${selectedRuleCodes.value.length} 条低风险检测规则。所有请求仍受授权范围和端口白名单限制。`,
      "确认主动检测",
      {
        confirmButtonText: "开始检测",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    scanning.value = true;
    const projectId = projectIdByTarget.value[targetId.value];
    if (!projectId)
      return ElMessage.warning("该目标尚未加入有效的安全评估项目");
    const { data } = await endpoints.startActiveScan({
      projectId,
      targetId: targetId.value,
      ruleCodes: selectedRuleCodes.value,
      ports,
    });
    ElMessage.success(`已创建 ${data.taskCount} 个检测任务`);
  } catch (error: any) {
    if (error !== "cancel" && error !== "close") {
      ElMessage.error(toErrorMessage(error, "主动检测启动失败"));
    }
  } finally {
    scanning.value = false;
  }
}

watch(targetId, () => {
  portSelections.value = selectedTarget.value?.allowedPorts
    ? selectedTarget.value.allowedPorts
        .split(",")
        .map(normalizePortToken)
        .filter(Boolean)
    : [];
  selectedRuleCodes.value = isFullPortTarget.value
    ? compatibleRules.value
        .filter((rule) => !["tcp_ports", "nuclei_scan"].includes(rule.toolCode))
        .map((rule) => rule.ruleCode)
    : compatibleRules.value
        .filter((rule) => rule.toolCode !== "nuclei_scan")
        .map((rule) => rule.ruleCode);
});

let syncStatusPoll: number | undefined;
function startSyncStatusPoll() {
  if (syncStatusPoll) return;
  // The catalog sync runs on the backend; leaving this page must not lose track of it.
  // Poll the backend `syncing` flag so returning to the page keeps showing progress and
  // completion is detected without a manual refresh, instead of the local loading state
  // silently disappearing on unmount.
  syncStatusPoll = window.setInterval(async () => {
    await load();
    if (!stats.value?.syncing && !syncingCatalog.value) {
      window.clearInterval(syncStatusPoll);
      syncStatusPoll = undefined;
    }
  }, 5000);
}
onMounted(async () => {
  await load();
  if (stats.value?.syncing) startSyncStatusPoll();
});
onUnmounted(() => {
  if (syncStatusPoll) window.clearInterval(syncStatusPoll);
});
</script>

<template>
  <div class="vuln-workbench" v-loading="loading">
    <aside class="vuln-catalog-pane">
      <header class="pane-title">
        <div>
          <b>漏洞知识库</b
          ><small>{{
            stats
              ? `${stats.total} 条 · ${stats.nuclei} 个 Nuclei 模板 · ${stats.knownExploited} 个 KEV`
              : `${total} 条`
          }}</small>
        </div>
        <el-button
          link
          type="primary"
          :icon="Refresh"
          :loading="syncingCatalog || stats?.syncing"
          @click="syncOfficialCatalog"
          >同步</el-button
        >
      </header>
      <div class="catalog-search">
        <el-input
          v-model="query"
          size="small"
          clearable
          class="catalog-query"
          placeholder="搜索 CVE、模板 ID、名称、标签"
          @keyup.enter="searchCatalog"
          @clear="searchCatalog"
        >
          <template #prefix
            ><el-icon><Search /></el-icon
          ></template>
        </el-input>
        <div class="catalog-filters">
          <el-select
            v-model="severityFilter"
            size="small"
            clearable
            placeholder="严重度"
            @change="searchCatalog"
          >
            <el-option
              v-for="value in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']"
              :key="value"
              :label="value"
              :value="value"
            />
          </el-select>
          <el-select
            v-model="sourceFilter"
            size="small"
            clearable
            placeholder="来源"
            @change="searchCatalog"
          >
            <el-option label="獬豸内置" value="BUILTIN" />
            <el-option label="Nuclei 模板" value="NUCLEI" />
          </el-select>
          <el-input
            v-model="yearFilter"
            size="small"
            clearable
            maxlength="4"
            placeholder="CVE 年份"
            @keyup.enter="searchCatalog"
            @clear="searchCatalog"
          />
          <el-select
            v-model="safetyFilter"
            size="small"
            clearable
            placeholder="执行分级"
            @change="searchCatalog"
          >
            <el-option label="默认安全" value="SAFE" />
            <el-option label="需人工审查" value="REVIEW_REQUIRED" />
            <el-option label="默认禁止" value="BLOCKED" />
          </el-select>
        </div>
        <el-checkbox
          v-model="knownExploitedOnly"
          size="small"
          class="catalog-kev"
          @change="searchCatalog"
        >
          仅 CISA 已知在野利用（KEV）
        </el-checkbox>
      </div>
      <div class="catalog-list">
        <button
          v-for="item in vulnerabilities"
          :key="item.id"
          type="button"
          :class="{ active: selected?.id === item.id }"
          @click="selected = item"
        >
          <span
            ><el-tag size="small" :type="severityType(item.severity)">{{
              item.severity
            }}</el-tag
            ><i>{{ item.sourceExternalId || item.vulnerabilityCode }}</i></span
          >
          <b>{{ item.name }}</b>
          <small
            >{{ item.category
            }}<template v-if="item.knownExploited"> · CISA KEV</template
            ><template v-if="item.scanSafety">
              · {{ item.scanSafety }}</template
            ></small
          >
        </button>
      </div>
      <footer class="catalog-pagination">
        <el-pagination
          small
          background
          layout="prev, pager, next, jumper"
          :page-size="pageSize"
          :total="total"
          :current-page="page + 1"
          :pager-count="5"
          @current-change="changePage"
        />
      </footer>
    </aside>

    <main class="vuln-detail-pane">
      <template v-if="selected">
        <header class="detail-header">
          <div class="detail-heading">
            <span>{{
              selected.sourceExternalId || selected.vulnerabilityCode
            }}</span>
            <h2>{{ selected.name }}</h2>
            <el-button
              class="detail-ai-action"
              type="primary"
              :icon="MagicStick"
              @click="askCopilot(selected)"
              >AI 研判</el-button
            >
          </div>
          <div class="detail-badges">
            <el-tag v-if="selected.knownExploited" type="danger"
              >CISA KEV</el-tag
            ><el-tag :type="severityType(selected.severity)">{{
              selected.severity
            }}</el-tag>
          </div>
        </header>
        <div class="source-facts">
              <span><b>来源</b>{{ selected.sourceName || "獬豸" }}</span>
          <span><b>版本</b>{{ selected.sourceVersion || "内置" }}</span>
          <span><b>真实性</b>{{ verificationLabel(selected) }}</span>
          <span><b>执行分级</b>{{ selected.scanSafety || "SAFE" }}</span>
          <span v-if="selected.cveIds"><b>CVE</b>{{ selected.cveIds }}</span>
          <span v-if="selected.cweIds"><b>CWE</b>{{ selected.cweIds }}</span>
          <span v-if="selected.cvssScore != null"
            ><b>CVSS</b>{{ selected.cvssScore }}</span
          >
          <span v-if="selected.epssScore != null"
            ><b>EPSS</b>{{ selected.epssScore }}</span
          >
          <span v-if="selected.protocols"
            ><b>协议</b>{{ selected.protocols }}</span
          >
          <span v-if="selected.templateSha256"
            ><b>SHA-256</b><code>{{ selected.templateSha256 }}</code></span
          >
        </div>
        <div class="detail-tabs">
          <section>
            <h3>风险说明</h3>
            <p>{{ selected.description }}</p>
          </section>
          <section>
            <h3>检测方式</h3>
            <p>{{ selected.detectionGuidance }}</p>
          </section>
          <section>
            <h3>修复建议</h3>
            <p>{{ selected.remediation }}</p>
          </section>
          <section v-if="selected.tags || selected.authors">
            <h3>模板元数据</h3>
            <p v-if="selected.authors">作者：{{ selected.authors }}</p>
            <p v-if="selected.tags">标签：{{ selected.tags }}</p>
            <p v-if="selected.templateRelativePath">
              路径：{{ selected.templateRelativePath }}
            </p>
          </section>
          <section
            v-if="
              references(selected.referenceUrls).length || selected.sourceUrl
            "
          >
            <h3>真实来源与公开 PoC</h3>
            <p class="reference-links">
              <a
                v-if="selected.sourceUrl"
                :href="selected.sourceUrl"
                target="_blank"
                rel="noreferrer"
                >查看固定版本官方模板</a
              ><a
                v-for="url in references(selected.referenceUrls)"
                :key="url"
                :href="url"
                target="_blank"
                rel="noreferrer"
                >{{ url }}</a
              >
            </p>
          </section>
        </div>
      </template>
    </main>

    <aside class="scan-launcher-pane">
      <header class="pane-title">
        <div><b>主动检测</b><small>安全规则编排器</small></div>
        <el-icon><Aim /></el-icon>
      </header>
      <div class="scan-form">
        <label>授权目标</label>
        <el-select
          v-model="targetId"
          size="small"
          placeholder="选择目标"
          style="width: 100%"
        >
          <el-option
            v-for="target in enabledTargets"
            :key="target.id"
            :label="target.name"
            :value="target.id"
          >
            <span>{{ target.name }}</span
            ><small class="target-value">{{ target.targetValue }}</small>
          </el-option>
        </el-select>
        <label>检测规则</label>
        <el-checkbox-group v-model="selectedRuleCodes" class="rule-list">
          <el-checkbox
            v-for="rule in rules"
            :key="rule.ruleCode"
            :value="rule.ruleCode"
            :disabled="
              (Boolean(selectedTarget) &&
                !isRuleCompatible(rule, selectedTarget)) ||
              (isFullPortTarget && rule.toolCode === 'tcp_ports')
            "
          >
            <span>
              <b>{{ rule.name }}</b>
              <small>{{
                compatibilityHint(rule) ||
                `${rule.ruleCode} · ${rule.targetType} · ${rule.riskLevel}`
              }}</small>
            </span>
          </el-checkbox>
        </el-checkbox-group>
        <template v-if="includesPortScan">
          <label>扫描端口</label>
          <el-alert
            v-if="isFullPortTarget"
            title="全端口扫描将使用 Nmap 检测 1-65535，可能需要较长时间，请保持应用运行。"
            type="warning"
            :closable="false"
            show-icon
            class="full-port-alert"
          />
          <el-select
            v-model="portSelections"
            :disabled="isFullPortTarget"
            multiple
            filterable
            allow-create
            default-first-option
            collapse-tags
            :max-collapse-tags="4"
            placeholder="多选常用端口，或输入 8000-8010"
            style="width: 100%"
          >
            <el-option
              v-for="port in commonPorts"
              :key="port.value"
              :label="port.label"
              :value="port.value"
            />
          </el-select>
          <p class="port-help">
            可多选，也可输入端口或范围；多个自定义端口可用逗号分隔。当前授权：{{
              selectedTarget?.allowedPorts || "未选择目标"
            }}
          </p>
        </template>
      </div>
      <div class="scan-summary">
        <span>{{ selectedRules.length }} 条规则</span
        ><span>{{
          includesNucleiScan ? "通用漏洞模板扫描" : "低风险探测"
        }}</span
        ><span>人工确认</span>
      </div>
      <el-button
        type="primary"
        class="scan-button"
        :icon="VideoPlay"
        :loading="scanning"
        @click="startScan"
        >开始主动检测</el-button
      >
    </aside>
  </div>
</template>

<style scoped>
.vuln-workbench {
  display: grid;
  height: 100%;
  min-height: 560px;
  grid-template-columns: minmax(230px, 26%) minmax(320px, 1fr) minmax(
      300px,
      34%
    );
  overflow: hidden;
  border: 1px solid #d9dee6;
  border-radius: 6px;
  background: #fff;
}
.vuln-catalog-pane,
.scan-launcher-pane {
  display: flex;
  min-width: 0;
  min-height: 0;
  flex-direction: column;
  background: #f8fafc;
}
.vuln-catalog-pane {
  border-right: 1px solid #e1e5eb;
}
.scan-launcher-pane {
  border-left: 1px solid #e1e5eb;
}
.pane-title {
  display: flex;
  height: 52px;
  flex: none;
  align-items: center;
  justify-content: space-between;
  padding: 0 14px;
  border-bottom: 1px solid #e1e5eb;
  background: #f3f5f8;
}
.pane-title div {
  display: flex;
  flex-direction: column;
}
.pane-title b {
  color: #273142;
  font-size: 13px;
}
.pane-title small {
  margin-top: 3px;
  color: #8a94a3;
  font-size: 10px;
}
.catalog-search {
  padding: 10px;
  border-bottom: 1px solid #e5e9ef;
}
.catalog-search {
  flex: none;
}
.catalog-list {
  flex: 1 1 auto;
  min-height: 0;
  overflow: auto;
}
.catalog-list button {
  display: flex;
  width: 100%;
  flex-direction: column;
  gap: 6px;
  padding: 12px 13px;
  border: 0;
  border-bottom: 1px solid #edf0f4;
  background: transparent;
  text-align: left;
  cursor: pointer;
}
.catalog-list button:hover {
  background: #f1f5f9;
}
.catalog-list button.active {
  box-shadow: inset 3px 0 #2563eb;
  background: #eaf1fd;
}
.catalog-list button > span {
  display: flex;
  align-items: center;
  gap: 7px;
}
.catalog-list i {
  color: #8b95a3;
  font-size: 10px;
  font-style: normal;
}
.catalog-list b {
  color: #334155;
  font-size: 12px;
}
.catalog-list small {
  color: #94a3b8;
  font-size: 10px;
}
.vuln-detail-pane {
  min-width: 0;
  min-height: 0;
  overflow: auto;
  padding: 24px;
}
.detail-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  padding-bottom: 20px;
  border-bottom: 1px solid #e5e7eb;
}
.detail-header span {
  color: #2563eb;
  font:
    11px Consolas,
    monospace;
}
.detail-header h2 {
  margin: 7px 0 0;
  color: #1f2937;
  font-size: 20px;
}
.detail-tabs {
  display: grid;
  gap: 16px;
  margin-top: 20px;
}
.detail-tabs section {
  padding: 17px;
  border: 1px solid #e5e7eb;
  border-radius: 5px;
  background: #fafbfc;
}
.detail-tabs h3 {
  margin: 0 0 9px;
  color: #334155;
  font-size: 12px;
}
.detail-tabs p {
  margin: 0;
  color: #64748b;
  font-size: 12px;
  line-height: 1.75;
}
.scan-form {
  min-height: 0;
  flex: 1;
  overflow: auto;
  padding: 14px;
}
.scan-form > label {
  display: block;
  margin: 2px 0 8px;
  color: #64748b;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0;
}
.scan-form > label:not(:first-child) {
  margin-top: 18px;
}
.target-value {
  float: right;
  margin-left: 14px;
  color: #94a3b8;
}
.rule-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.rule-list :deep(.el-checkbox) {
  height: auto;
  margin: 0;
  padding: 9px;
  border: 1px solid #e4e8ee;
  border-radius: 4px;
  background: #fff;
  align-items: flex-start;
}
.rule-list :deep(.el-checkbox__label) > span {
  display: flex;
  flex-direction: column;
}
.rule-list b {
  color: #374151;
  font-size: 11px;
}
.rule-list small {
  margin-top: 3px;
  color: #94a3b8;
  font-size: 9px;
}
.port-help {
  margin: 7px 1px 0;
  color: #9299a3;
  font-size: 9px;
  line-height: 1.55;
  word-break: break-all;
}
.scan-summary {
  display: flex;
  justify-content: space-between;
  padding: 9px 14px;
  border-top: 1px solid #e1e5eb;
  color: #7b8491;
  font-size: 9px;
}
.scan-button {
  margin: 0 14px 14px;
}
@media (max-width: 1150px) {
  .vuln-workbench {
    height: auto;
    min-height: 0;
    grid-template-columns: minmax(220px, 30%) minmax(360px, 1fr);
    grid-template-rows: minmax(560px, calc(100vh - 130px)) auto;
    overflow: visible;
  }
  .scan-launcher-pane {
    position: static;
    grid-column: 1/-1;
    width: auto;
    height: auto;
    max-height: none;
    border-top: 1px solid #e1e5eb;
    border-left: 0;
    box-shadow: none;
  }
  .scan-form {
    overflow: visible;
  }
}
</style>
<style scoped>
.full-port-alert {
  margin-bottom: 8px;
}
.vuln-workbench {
  border-color: var(--app-border);
  background: transparent;
  color: var(--app-text);
}
.vuln-catalog-pane,
.scan-launcher-pane {
  background: var(--app-surface-soft);
}
.vuln-catalog-pane,
.scan-launcher-pane,
.pane-title,
.catalog-search,
.catalog-list button,
.detail-header,
.scan-summary {
  border-color: var(--app-border);
}
.pane-title {
  background: var(--app-surface);
}
.pane-title b,
.catalog-list b,
.detail-header h2,
.detail-tabs h3,
.rule-list b {
  color: var(--app-text);
}
.pane-title small,
.catalog-list i,
.catalog-list small,
.detail-tabs p,
.scan-form > label,
.target-value,
.rule-list small,
.port-help,
.scan-summary {
  color: var(--app-muted);
}
.catalog-list button:hover {
  background: var(--app-surface-soft);
}
.catalog-list button.active {
  background: var(--app-accent-soft-strong);
  box-shadow: inset 3px 0 var(--app-accent);
}
.detail-header span {
  color: var(--app-accent);
}
.detail-tabs section,
.rule-list :deep(.el-checkbox) {
  border-color: var(--app-border);
  background: var(--app-surface);
}

/* Fluent WinUI 3 */
.vuln-workbench {
  font-family: inherit;
  border-radius: 8px;
  box-shadow: 0 1px 2px color-mix(in srgb, var(--app-text) 5%, transparent);
}
.pane-title {
  height: 48px;
}
.catalog-search :deep(.el-input__wrapper),
.scan-form :deep(.el-select__wrapper) {
  min-height: 32px;
  border-radius: 4px;
}
.catalog-list button {
  min-height: 64px;
  gap: 5px;
  transition: background-color 0.12s ease;
}
.catalog-list button.active {
  box-shadow: inset 3px 0 var(--app-accent);
}
.detail-tabs section {
  border-radius: 6px;
  box-shadow: 0 1px 2px color-mix(in srgb, var(--app-text) 4%, transparent);
}
.rule-list :deep(.el-checkbox) {
  min-height: 44px;
  border-radius: 4px;
  transition:
    background-color 0.12s ease,
    border-color 0.12s ease;
}
.rule-list :deep(.el-checkbox:hover) {
  background: var(--app-surface-soft);
}
.rule-list :deep(.el-checkbox.is-checked) {
  border-color: color-mix(in srgb, var(--app-accent) 46%, var(--app-border));
  background: var(--app-accent-soft);
}
.scan-button {
  min-height: 32px;
  border-radius: 4px;
}
</style>
<style scoped>
.catalog-filters {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 8px;
  margin: 0;
}
.catalog-search :deep(.el-checkbox__label) {
  font-size: 11px;
}
.catalog-list i {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.catalog-pagination {
  display: flex;
  flex: none;
  justify-content: center;
  padding: 8px 4px;
  border-top: 1px solid var(--app-border);
}
.detail-badges {
  display: flex;
  gap: 6px;
}
.source-facts {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  margin-top: 16px;
  padding: 15px;
  border: 1px solid var(--app-border);
  border-radius: 6px;
  background: var(--app-surface);
}
.source-facts span {
  min-width: 0;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.45;
  word-break: break-all;
}
.source-facts b {
  display: block;
  margin-bottom: 4px;
  color: var(--app-text);
  font-size: 11px;
}
.source-facts code {
  font-size: 11px;
}
.reference-links {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.reference-links a {
  color: var(--app-accent);
  overflow-wrap: anywhere;
}
.pane-title :deep(.el-button) {
  font-size: 10px;
}
.detail-heading {
  min-width: 0;
  flex: 1;
  padding-right: 16px;
}
.detail-ai-action {
  height: 32px !important;
  margin-top: 14px !important;
  padding: 0 13px !important;
  border: 1px solid var(--app-accent) !important;
  border-radius: var(--fluent-radius-control) !important;
  background: var(--app-accent) !important;
  color: var(--system-accent-foreground, #fff) !important;
  font-size: 12px !important;
  font-weight: 650 !important;
  box-shadow: var(--fluent-shadow-2) !important;
}
.detail-ai-action:hover,
.detail-ai-action:focus {
  border-color: var(--app-accent-dark) !important;
  background: var(--app-accent-dark) !important;
  color: var(--system-accent-foreground, #fff) !important;
}
.detail-ai-action :deep(.el-icon),
.detail-ai-action :deep(span) {
  color: #fff !important;
}
.detail-ai-action :deep(.el-icon) {
  font-size: 14px !important;
}
.detail-badges {
  flex: none;
  align-items: flex-start;
  padding-top: 1px;
}
@media (max-width: 900px) {
  .detail-header {
    flex-direction: column;
    gap: 12px;
  }
  .detail-heading {
    padding-right: 0;
  }
  .detail-badges {
    order: -1;
  }
  .detail-ai-action {
    height: 32px !important;
    margin-top: 11px !important;
    padding: 0 10px !important;
    font-size: 12px !important;
  }
}

/* The workbench itself is the page surface. Keep the three functional panes
   and their dividers, but remove the redundant outer card inside the desktop
   workspace. */
.vuln-workbench {
  display: grid !important;
  grid-template-columns: minmax(240px, 26%) minmax(320px, 1fr) minmax(
      300px,
      34%
    ) !important;
  border: 0;
  border-radius: 0;
  box-shadow: none;
  height: 100%;
  min-height: 0;
  overflow: hidden;
}
.vuln-catalog-pane,
.scan-launcher-pane {
  display: flex;
  min-width: 0;
  min-height: 0;
  flex-direction: column;
}
.vuln-detail-pane {
  min-width: 0;
  min-height: 0;
  overflow: auto;
}
.vuln-catalog-pane,
.vuln-detail-pane,
.scan-launcher-pane {
  min-height: 0;
}
.catalog-filters {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 8px;
  margin: 0;
}
.catalog-filters :deep(.el-select),
.catalog-filters :deep(.el-input) {
  width: 100%;
  min-width: 0;
}
.catalog-pagination {
  flex: none;
}

/* Catalog filters should stay a compact 2x2 grid inside the left pane.
   Global fluent rules currently force .catalog-filters into a wrapping flex
   row, which makes every control stack full-width and look sparse. */
.catalog-search {
  display: flex;
  flex: none;
  flex-direction: column;
  gap: 10px;
  padding: 12px;
}
.catalog-query {
  width: 100%;
}
.catalog-filters {
  display: grid !important;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) !important;
  gap: 8px !important;
  margin: 0 !important;
  align-items: stretch !important;
  flex-wrap: nowrap !important;
}
.catalog-filters :deep(.el-select),
.catalog-filters :deep(.el-input),
.catalog-filters :deep(.el-select__wrapper),
.catalog-filters :deep(.el-input__wrapper) {
  width: 100%;
  min-width: 0;
}
.catalog-kev {
  margin: 0 !important;
  height: auto !important;
  align-items: flex-start;
  white-space: normal;
}
.catalog-kev :deep(.el-checkbox__label) {
  white-space: normal;
  line-height: 1.45;
  padding-left: 8px;
}
.catalog-search :deep(.el-checkbox__label),
.pane-title small,
.catalog-list i,
.catalog-list small {
  font-size: 11px;
  line-height: 1.45;
}
.catalog-pagination {
  padding: 10px 4px;
}
.catalog-pagination :deep(.el-pagination) {
  flex-wrap: wrap;
  justify-content: center;
  row-gap: 6px;
}
.catalog-pagination :deep(.el-pagination__jump) {
  margin-left: 8px;
  font-size: 12px;
}
.catalog-pagination :deep(.el-pagination__editor.el-input) {
  width: 52px;
}
.pane-title :deep(.el-button) {
  font-size: 12px;
}
.scan-form > label {
  margin-bottom: 9px;
  font-size: 11px;
}
.rule-list {
  gap: 8px;
}
.rule-list :deep(.el-checkbox) {
  min-height: 48px;
  padding: 11px;
}
.rule-list b {
  font-size: 12px;
}
.rule-list small,
.port-help {
  font-size: 11px;
  line-height: 1.5;
}
.scan-summary {
  gap: 10px;
  padding: 11px 14px;
  font-size: 11px;
}
@media (max-width: 1150px) {
  .vuln-workbench {
    height: auto;
    grid-template-columns: minmax(220px, 30%) minmax(0, 1fr) !important;
    grid-template-rows: minmax(560px, calc(100vh - 130px)) auto;
    overflow: visible;
  }
  .scan-launcher-pane {
    position: static;
    grid-column: 1/-1;
    width: auto;
    height: auto;
    max-height: none;
    border-left: 0;
    box-shadow: none;
  }
  .scan-form {
    overflow: visible;
  }
}
</style>
