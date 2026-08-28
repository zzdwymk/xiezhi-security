<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  endpoints,
  connectTaskEventFeed,
  type AuditLogRecord,
  type AssessmentProject,
  type DiscoveryResult,
  type FingerprintCatalogInfo,
  type IcpBatchResult,
  type MemoryDoc,
  type ProjectApproval,
  type ProjectFindingRecord,
  type ProjectReportSummary,
  type ProjectTaskRecord,
  type ProjectSummary,
  type ProjectTarget,
  type ReconMode,
  type ReconResult,
  type SafePocRecommendation,
  type ScanDiff,
  type SecurityAction,
  type SecurityActionCategory,
  type Target,
  type TaskProgressEvent,
  type WorkflowRunDetail,
  type WorkflowSpecV2,
} from "../api";
import { formatDateTime, formatExecutionLog } from "../utils/dateTime";
import {
  formatAuditAction,
  formatAuditDetail,
  formatAuditResource,
  formatAuditResult,
  formatApprovalAction,
  auditResultTagType,
} from "../utils/auditFormat";
import {
  taskProgressIndeterminate,
  taskProgressPercentage,
  taskProgressStatus,
  taskProgressText,
} from "../utils/taskProgress";
import { useAuthStore } from "../stores/auth";
import { useCopilotStore } from "../stores/copilot";
import AppPagination from "../components/AppPagination.vue";
import {
  ArrowDown,
  MagicStick,
  Refresh,
  UploadFilled,
} from "../components/fluentIcons";
import { useClientPagination } from "../composables/useClientPagination";
import { toErrorMessage } from "../utils/errorMessage";
import {
  downloadBlob,
  downloadText,
  EmptyDownloadError,
} from "../utils/download";
import { COMMON_PORT_OPTIONS, normalizeAllowedPorts } from "../utils/ports";
import { parseBatchTargets } from "../utils/targetParser";

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const copilot = useCopilotStore();
const id = Number(route.params.id);
const project = ref<AssessmentProject>();
const summary = ref<ProjectSummary>();
const reportSummary = ref<ProjectReportSummary>();
const links = ref<ProjectTarget[]>([]);
const targets = ref<Target[]>([]);
const PROJECT_TABS = new Set([
  "overview",
  "targets",
  "discovery",
  "recon",
  "tasks",
  "findings",
  "security-actions",
  "audits",
  "report",
  "memory",
]);

function requestedProjectTab(value: unknown) {
  const name = Array.isArray(value) ? value[0] : value;
  return typeof name === "string" && PROJECT_TABS.has(name) ? name : "overview";
}

const tab = ref(requestedProjectTab(route.query.tab));
const loading = ref(false);
const selected = ref<number>();
const discoveryTarget = ref<number>();
const discoveryRows = ref<DiscoveryResult[]>([]);
const {
  page: discoveryPage,
  pageSize: discoveryPageSize,
  pagedItems: pagedDiscoveryRows,
} = useClientPagination(discoveryRows);
const probing = ref(false);
const fingerprintCatalog = ref<FingerprintCatalogInfo>();
const fingerprintCatalogExpanded = ref(false);
const fingerprintCatalogLoading = ref(false);
const fingerprintCatalogReloading = ref(false);
const fingerprintCatalogUpdating = ref(false);
const fingerprintCatalogFileInput = ref<HTMLInputElement>();
const fingerprintCatalogUpdateFile = ref<{ name: string; size: number }>();
const fingerprintCatalogUpdateState = ref<
  "idle" | "updating" | "success" | "error" | "cancelled"
>("idle");
const fingerprintCatalogUpdateError = ref("");
const fingerprintCatalogUpdateResult = ref<FingerprintCatalogInfo>();
const pocRecommendationVisible = ref(false);
const pocRecommendationLoading = ref(false);
const pocRecommendationTarget = ref<DiscoveryResult>();
const pocRecommendationIds = ref<string[]>([]);
const pocRecommendations = ref<SafePocRecommendation[]>([]);
const {
  page: pocPage,
  pageSize: pocPageSize,
  pagedItems: pagedPocRecommendations,
} = useClientPagination(pocRecommendations);
const reconTarget = ref<number>();
const reconMode = ref<ReconMode>("PASSIVE");
const includeSameSubnet = ref(false);
const includeHttp = ref(true);
const includeTls = ref(true);
const enumerateSubdomains = ref(true);
const subdomainDictionary = ref(
  "www,api,admin,dev,test,staging,mail,vpn,portal,cdn",
);
const reconRows = ref<ReconResult[]>([]);
const collectingRecon = ref(false);
const reconFilter = ref("");
const icpLoading = ref(false);
const icpRows = ref<IcpBatchResult[]>([]);
const {
  page: icpPage,
  pageSize: icpPageSize,
  pagedItems: pagedIcpRows,
} = useClientPagination(icpRows);

watch(
  () => route.query.tab,
  (value) => {
    const requested = requestedProjectTab(value);
    if (requested !== tab.value) tab.value = requested;
  },
);

function handleTabChange(name: string | number) {
  const nextTab = requestedProjectTab(String(name));
  if (nextTab === "memory") loadMemories();
  if (route.query.tab === nextTab) return;
  router.replace({
    query: {
      ...route.query,
      tab: nextTab === "overview" ? undefined : nextTab,
    },
  });
}

// Project-scoped execution, finding, approval and audit views.  These are kept
// separate from the global pages so the project detail screen always shows the
// records that belong to this authorization boundary.
const projectTasks = ref<ProjectTaskRecord[]>([]);
const projectFindings = ref<ProjectFindingRecord[]>([]);
const projectApprovals = ref<ProjectApproval[]>([]);
const {
  page: approvalPage,
  pageSize: approvalPageSize,
  pagedItems: pagedProjectApprovals,
} = useClientPagination(projectApprovals);
const projectAudits = ref<AuditLogRecord[]>([]);
const projectDataLoading = ref(false);
const {
  page: taskPage,
  pageSize: taskPageSize,
  pagedItems: pagedProjectTasks,
} = useClientPagination(projectTasks);
const {
  page: findingPage,
  pageSize: findingPageSize,
  pagedItems: pagedProjectFindings,
} = useClientPagination(projectFindings);
const auditPage = ref(1);
const auditPageSize = ref(20);
const projectAuditTotal = ref(0);
const taskDetail = ref<ProjectTaskRecord>();
const taskDetailVisible = ref(false);
const taskDetailLoading = ref(false);
const taskRetrying = ref<number>();
const taskCancelling = ref<number>();
const findingDetail = ref<ProjectFindingRecord>();
const findingDetailVisible = ref(false);
const findingRetesting = ref<number>();
const diffVisible = ref(false);
const diffLoading = ref(false);
const diff = ref<ScanDiff>();
const diffItems = computed(() => diff.value?.items || []);
const {
  page: diffPage,
  pageSize: diffPageSize,
  pagedItems: pagedDiffItems,
} = useClientPagination(diffItems);
const diffBaselineTaskId = ref<number>();
const diffCurrentTaskId = ref<number>();
const approvalDialog = ref(false);
const approvalSaving = ref(false);
const approvalForm = ref({
  action: "SCAN",
  comment: "",
  authorizationSnapshotHash: "",
});
const approvalDecision = ref<number>();
const auditLoading = ref(false);
const reportTargetId = ref<number | "ALL">("ALL");
const projectReportHtmlLoading = ref(false);
const projectReportPdfLoading = ref(false);
const targetReportHtmlLoading = ref(false);
const targetReportPdfLoading = ref(false);
const reportSummaryLoading = ref(false);
const reportPreviewVisible = ref(false);
const reportPreviewTitle = ref("");
const reportPreviewHtml = ref("");
const workflowRunning = ref(false);
const workflowLog = ref<string[]>([]);
const workflowProgress = ref(0);
const workflowIndeterminate = ref(false);
const workflowStatus = ref("待执行");
const workflowTaskIds = ref<number[]>([]);
const workflowRunId = ref<number>();
const workflowStopping = ref(false);
let workflowPollGeneration = 0;
let stopTaskFeed: (() => void) | undefined;

interface SecurityActionPreset {
  category: SecurityActionCategory;
  label: string;
  title: string;
  riskLevel: "MEDIUM" | "HIGH";
  description: string;
  executionPlan: string;
  rollbackPlan: string;
}

const SECURITY_ACTION_PRESETS: readonly SecurityActionPreset[] = [
  {
    category: "VULNERABILITY_VALIDATION",
    label: "非破坏性漏洞验证",
    title: "非破坏性漏洞验证",
    riskLevel: "MEDIUM",
    description: "针对已记录漏洞执行一次受控复现，确认可达性与影响边界。",
    executionPlan:
      "仅调用服务端受控漏洞验证流程，对选定漏洞执行单次非破坏性复现并记录最小必要证据；不写入或删除业务数据。",
    rollbackPlan:
      "停止受控验证流程，清理本次验证生成的临时会话与标记，并复核目标服务状态。",
  },
  {
    category: "CONTROLLED_EXPLOITATION",
    label: "受控利用价值验证",
    title: "受控利用价值验证",
    riskLevel: "HIGH",
    description: "在明确停止条件下验证漏洞实际影响，不扩大目标范围。",
    executionPlan:
      "仅使用服务端登记的受控验证能力，在单一授权目标内验证最小影响路径；达到证据要求或停止条件后立即结束。",
    rollbackPlan:
      "终止受控验证流程，清除临时验证状态，确认业务数据、配置和服务可用性未发生改变。",
  },
  {
    category: "PRIVILEGE_VALIDATION",
    label: "权限边界验证",
    title: "权限边界验证",
    riskLevel: "HIGH",
    description: "验证现有身份或漏洞能否越过既定权限边界，不读取敏感凭据。",
    executionPlan:
      "通过服务端受控检查验证授权目标上的权限边界，仅记录权限级别与访问结果摘要，不导出凭据或敏感数据。",
    rollbackPlan:
      "撤销本次验证产生的临时授权上下文，结束相关会话，并复核原有权限边界。",
  },
  {
    category: "INTERNAL_ASSESSMENT",
    label: "授权内网边界评估",
    title: "授权内网边界评估",
    riskLevel: "HIGH",
    description: "只在项目已显式纳入的目标上验证内部暴露面，禁止横向移动。",
    executionPlan:
      "仅对当前项目内已登记目标执行服务端受控边界检查，不探测未登记地址，不进行横向移动。",
    rollbackPlan:
      "停止边界检查并关闭临时会话，确认未对项目外地址产生后续请求。",
  },
  {
    category: "PERSISTENCE_VALIDATION",
    label: "持久化风险模拟验证",
    title: "持久化风险模拟验证",
    riskLevel: "HIGH",
    description: "仅模拟评估持久化条件，不植入后门、不建立真实维持机制。",
    executionPlan:
      "仅调用服务端登记的模拟检查评估持久化前置条件，不创建账号、计划任务、启动项或远程控制通道。",
    rollbackPlan:
      "结束模拟检查，清理所有临时验证标记，并复核系统启动项、账号与服务状态未发生改变。",
  },
];

function newSecurityActionForm() {
  const start = new Date(Date.now() + 5 * 60_000);
  start.setSeconds(0, 0);
  const end = new Date(start.getTime() + 60 * 60_000);
  return {
    targetId: undefined as number | undefined,
    findingId: undefined as number | undefined,
    category: "VULNERABILITY_VALIDATION" as SecurityActionCategory,
    purpose: "",
    windowStart: start as Date | null,
    windowEnd: end as Date | null,
    acknowledged: false,
  };
}

const securityActions = ref<SecurityAction[]>([]);
const {
  page: securityActionPage,
  pageSize: securityActionPageSize,
  pagedItems: pagedSecurityActions,
} = useClientPagination(securityActions);
const securityActionLoading = ref(false);
const securityActionDialog = ref(false);
const securityActionSaving = ref(false);
const securityActionMutating = ref<number>();
const securityActionForm = ref(newSecurityActionForm());
const securityActionDetail = ref<SecurityAction>();
const securityActionDetailVisible = ref(false);
const securityActionOperationDialog = ref(false);
const securityActionOperation = ref<"COMPLETE" | "ROLLBACK">("COMPLETE");
const securityActionOperationTarget = ref<SecurityAction>();
const securityActionOperationSaving = ref(false);
const securityActionOperationForm = ref({ evidence: "", reason: "" });

const linkedIds = computed(() => new Set(links.value.map((x) => x.targetId)));
const available = computed(() =>
  targets.value.filter((t) => !linkedIds.value.has(t.id)),
);
const linkedTargets = computed(() =>
  targets.value.filter((t) => linkedIds.value.has(t.id)),
);
const {
  page: linkedTargetPage,
  pageSize: linkedTargetPageSize,
  pagedItems: pagedLinkedTargets,
} = useClientPagination(linkedTargets);
const successfulTasks = computed(() =>
  projectTasks.value.filter((task) => task.status === "SUCCESS"),
);
const pendingTasks = computed(() =>
  projectTasks.value.filter((task) =>
    ["PENDING", "QUEUED", "RUNNING"].includes(task.status),
  ),
);
const reportSeverityRows = computed(() =>
  Object.entries(reportSummary.value?.severityCounts || {}).map(
    ([severity, count]) => ({ severity, count }),
  ),
);
const reportVulnerabilityCount = computed(
  () =>
    (reportSummary.value?.findings || []).filter(findingIsVulnerability).length,
);
const reportInformationalCount = computed(
  () =>
    (reportSummary.value?.findings || []).length -
    reportVulnerabilityCount.value,
);
const recentStatusFilter = ref("");
const recentToolFilter = ref("");
const projectToolOptions = computed(() => [
  ...new Set(projectTasks.value.map((task) => task.toolCode).filter(Boolean)),
]);
const filteredRecentTasks = computed(() =>
  projectTasks.value
    .filter(
      (task) =>
        !recentStatusFilter.value || task.status === recentStatusFilter.value,
    )
    .filter(
      (task) =>
        !recentToolFilter.value || task.toolCode === recentToolFilter.value,
    )
    .slice(-8)
    .reverse(),
);

function auditSnapshotLabel(row: AuditLogRecord) {
  if (row.authorizationSnapshotHash) return row.authorizationSnapshotHash;
  if (row.action === "AI_AGENT_TURN" && !row.relatedTaskId) {
    return "不适用（未生成任务）";
  }
  return "未记录";
}
const reportTarget = computed(() =>
  reportTargetId.value === "ALL"
    ? undefined
    : linkedTargets.value.find((target) => target.id === reportTargetId.value),
);
const selectedSecurityActionPreset = computed(
  () =>
    SECURITY_ACTION_PRESETS.find(
      (item) => item.category === securityActionForm.value.category,
    ) || SECURITY_ACTION_PRESETS[0],
);
const securityActionFindings = computed(() =>
  projectFindings.value.filter(
    (item) =>
      !securityActionForm.value.targetId ||
      item.targetId === securityActionForm.value.targetId,
  ),
);
const canManageSecurityActions = computed(() => auth.user?.role === "ADMIN");
const canUpdateFingerprintCatalog = computed(() => auth.user?.role === "ADMIN");
const pendingSecurityActionCount = computed(
  () =>
    securityActions.value.filter((item) => item.status === "PENDING_APPROVAL")
      .length,
);
const runningSecurityActionCount = computed(
  () =>
    securityActions.value.filter((item) => item.status === "RUNNING").length,
);
const projectAuthorizationGuard = computed(() => {
  if (!project.value) return { active: false, text: "项目授权信息尚未加载" };
  if (project.value.status !== "ACTIVE")
    return {
      active: false,
      text: `项目当前为「${projectStatusLabel(project.value.status)}」，必须切换为「进行中」后才能申请或启动安全行动`,
    };
  const now = Date.now();
  const start = Date.parse(project.value.authorizationValidFrom);
  const end = Date.parse(project.value.authorizationExpiresAt);
  if (!Number.isFinite(start) || !Number.isFinite(end))
    return { active: false, text: "项目授权有效期无效，请先修正授权信息" };
  if (now < start)
    return {
      active: false,
      text: `项目授权尚未生效，将于 ${formatDateTime(project.value.authorizationValidFrom)} 生效`,
    };
  if (now > end)
    return {
      active: false,
      text: `项目授权已于 ${formatDateTime(project.value.authorizationExpiresAt)} 失效`,
    };
  return {
    active: true,
    text: `授权守卫已通过，有效期至 ${formatDateTime(project.value.authorizationExpiresAt)}`,
  };
});

watch(
  linkedTargets,
  (items) => {
    if (
      reportTargetId.value !== "ALL" &&
      !items.some((item) => item.id === reportTargetId.value)
    )
      reportTargetId.value = "ALL";
  },
  { immediate: true },
);

watch(taskDetailVisible, (visible) => {
  if (!visible) taskDetailLoading.value = false;
});

function errorMessage(error: unknown, fallback: string) {
  return toErrorMessage(error, fallback);
}

function displayTaskError(message?: string) {
  return message
    ? toErrorMessage(message, "任务执行失败，请查看执行日志")
    : "无";
}

function projectStatusLabel(status?: string) {
  const labels: Record<string, string> = {
    ACTIVE: "进行中",
    DRAFT: "草稿",
    PAUSED: "已暂停",
    COMPLETED: "已完成",
    ARCHIVED: "已归档",
  };
  return (status && labels[status]) || status || "未知";
}

function projectStatusType(
  status?: string,
): "success" | "warning" | "info" | "primary" | "danger" | "" {
  const types: Record<
    string,
    "success" | "warning" | "info" | "primary" | "danger"
  > = {
    ACTIVE: "success",
    DRAFT: "info",
    PAUSED: "warning",
    COMPLETED: "primary",
    ARCHIVED: "info",
  };
  return (status && types[status]) || "info";
}

function taskStatusType(status: string) {
  if (status === "SUCCESS") return "success";
  if (["FAILED", "TIMEOUT", "REJECTED", "CANCELLED"].includes(status))
    return "danger";
  if (status === "RUNNING") return "warning";
  return "info";
}

function taskStatusLabel(status?: string) {
  const labels: Record<string, string> = {
    PENDING: "待执行",
    QUEUED: "排队中",
    BLOCKED: "等待前置",
    RUNNING: "执行中",
    SUCCESS: "成功",
    FAILED: "失败",
    TIMEOUT: "超时",
    CANCELLED: "已取消",
    REJECTED: "已拒绝",
    SKIPPED: "已跳过",
    PREPARING: "准备中",
    STOPPING: "停止中",
    STOPPED: "已停止",
    PARTIAL_FAILED: "部分失败",
  };
  return (status && labels[status]) || status || "未知";
}

function approvalStatusLabel(status?: string) {
  const labels: Record<string, string> = {
    PENDING: "待审批",
    APPROVED: "已通过",
    REJECTED: "已拒绝",
  };
  return (status && labels[status]) || status || "未知";
}

function findingStatusLabel(status?: string) {
  const labels: Record<string, string> = {
    OPEN: "待确认",
    CONFIRMED: "已确认",
    FALSE_POSITIVE: "误报",
    FIXED: "已修复",
  };
  return (status && labels[status]) || status || "未知";
}

function findingSeverityType(severity: string) {
  if (severity === "CRITICAL" || severity === "HIGH") return "danger";
  if (severity === "MEDIUM") return "warning";
  if (severity === "LOW") return "primary";
  return "info";
}

function approvalStatusType(status: string) {
  if (status === "APPROVED") return "success";
  if (status === "REJECTED") return "danger";
  return "warning";
}

function securityActionStatusType(status: string) {
  if (status === "COMPLETED") return "success";
  if (["REJECTED", "FAILED"].includes(status)) return "danger";
  if (["PENDING_APPROVAL", "APPROVED", "RUNNING"].includes(status))
    return "warning";
  return "info";
}

function securityActionStatusLabel(status: string) {
  return (
    (
      {
        PENDING_APPROVAL: "待审批",
        APPROVED: "已批准",
        REJECTED: "已拒绝",
        RUNNING: "执行中",
        COMPLETED: "已完成",
        FAILED: "执行失败",
        ROLLED_BACK: "已回滚",
      } as Record<string, string>
    )[status] || status
  );
}

function securityActionCategoryLabel(category: string) {
  return (
    SECURITY_ACTION_PRESETS.find((item) => item.category === category)?.label ||
    category
  );
}

function securityActionRiskType(level: string) {
  if (["HIGH", "CRITICAL"].includes(level)) return "danger";
  if (level === "MEDIUM") return "warning";
  return "info";
}

function securityActionWindowState(action: SecurityAction) {
  const now = Date.now();
  const start = Date.parse(action.windowStart);
  const end = Date.parse(action.windowEnd);
  if (now < start) return { allowed: false, label: "等待时间窗" };
  if (now > end) return { allowed: false, label: "时间窗已结束" };
  return { allowed: true, label: "时间窗内" };
}

function taskTargetName(targetId?: number) {
  return (
    linkedTargets.value.find((target) => target.id === targetId)?.name ||
    `目标 #${targetId || "-"}`
  );
}

function openProjectCopilot(
  kind: "overview" | "recon" | "findings" = "overview",
) {
  const target = linkedTargets.value.find((item) => item.enabled);
  if (!target) {
    ElMessage.warning(
      "请先在项目中加入并启用一个授权目标，再让 AI 参与项目分析",
    );
    return;
  }
  const prompt =
    kind === "recon"
      ? `请结合安全评估项目 #${id} 当前已保存的信息收集、探测服务、网站指纹和 WAF 证据，整理资产清单、可信度、未知项和下一步低风险验证建议。不要把开放端口或公开资产直接判定为漏洞。`
      : kind === "findings"
        ? `请汇总安全评估项目 #${id} 当前漏洞与复测记录，按风险和证据完整性排序，指出需要人工复核的误报边界、扫描 Diff 关注点和整改优先级；只分析已有结果，不要重复发起扫描。`
        : `请介绍安全评估项目 #${id} 的授权范围、目标、检测任务、漏洞/复测、审批审计和项目报告状态，并给出当前最合适的下一步。只基于项目已有资料，不要创建检测任务。`;
  copilot.open({ targetId: target.id, mode: "analyze", prompt });
  void router.push("/");
}

function taskLogText(task?: ProjectTaskRecord) {
  return formatExecutionLog(task?.executionLog) || "等待任务开始执行…";
}

function mergeProjectTask(task: ProjectTaskRecord) {
  const index = projectTasks.value.findIndex((item) => item.id === task.id);
  if (index >= 0)
    projectTasks.value.splice(index, 1, {
      ...projectTasks.value[index],
      ...task,
    });
  else if (task.projectId === id) projectTasks.value.unshift(task);
  if (reportSummary.value)
    reportSummary.value = {
      ...reportSummary.value,
      vulnerabilityDiscovery: projectTasks.value,
    };
}

const ASSET_OBSERVATION_TOOLS = new Set(["tcp_ports", "nmap_service_scan"]);
// Mirror of the server-side FindingClassification: an open port (INFO, no vulnerabilityCode,
// from tcp_ports/nmap) is attack-surface information, not a vulnerability, so it must not be
// counted under 漏洞发现.
function findingIsVulnerability(finding: {
  severity?: string;
  sourceTool?: string;
  vulnerabilityCode?: string | null;
}) {
  if (finding.vulnerabilityCode && String(finding.vulnerabilityCode).trim())
    return true;
  if (
    finding.sourceTool &&
    ASSET_OBSERVATION_TOOLS.has(String(finding.sourceTool).toLowerCase())
  )
    return false;
  return (
    String(finding.severity || "")
      .trim()
      .toUpperCase() !== "INFO"
  );
}

function applyReportSummary(data: ProjectReportSummary) {
  reportSummary.value = data;
  projectTasks.value = Array.isArray(data.vulnerabilityDiscovery)
    ? data.vulnerabilityDiscovery
    : [];
  projectFindings.value = Array.isArray(data.findings) ? data.findings : [];
  projectApprovals.value = Array.isArray(data.approvals) ? data.approvals : [];
  if (data.project) project.value = data.project;
  const retested = Number(
    data.verification?.retestedFindings ??
      projectFindings.value.filter((item) =>
        ["VERIFIED", "FIXED", "REOPENED"].includes(item.status),
      ).length,
  );
  const audits = Number(
    data.approvalAndAudit?.totalApprovals ?? projectApprovals.value.length,
  );
  const vulnerabilityCount = projectFindings.value.filter(
    findingIsVulnerability,
  ).length;
  summary.value = {
    project: data.project || project.value!,
    targetCount: Array.isArray(data.targets)
      ? data.targets.length
      : links.value.length,
    taskCount: projectTasks.value.length,
    vulnerabilityCount,
    informationalCount: projectFindings.value.length - vulnerabilityCount,
    retestCount: retested,
    auditCount: audits,
  };
}

async function loadProjectReportSummary(showError = false) {
  reportSummaryLoading.value = true;
  try {
    const { data } = await endpoints.projectReportSummary(id);
    applyReportSummary(data);
  } catch (error: any) {
    if (showError) ElMessage.error(errorMessage(error, "项目报告摘要加载失败"));
  } finally {
    reportSummaryLoading.value = false;
  }
}

async function loadProjectTasks() {
  projectDataLoading.value = true;
  try {
    const { data } = await endpoints.tasks();
    const all = Array.isArray(data) ? data : [];
    const knownIds = new Set(projectTasks.value.map((task) => task.id));
    const filtered = all.filter(
      (task) => task.projectId === id || knownIds.has(task.id),
    );
    if (filtered.length || !projectTasks.value.length)
      projectTasks.value = filtered;
    if (reportSummary.value)
      reportSummary.value = {
        ...reportSummary.value,
        vulnerabilityDiscovery: projectTasks.value,
      };
  } catch (error: any) {
    // The report summary remains the authoritative fallback when the live list
    // endpoint is temporarily unavailable.
    if (!projectTasks.value.length)
      ElMessage.error(errorMessage(error, "项目任务加载失败"));
  } finally {
    projectDataLoading.value = false;
  }
}

async function loadProjectApprovals() {
  try {
    projectApprovals.value = (await endpoints.projectApprovals(id)).data || [];
    if (reportSummary.value)
      reportSummary.value = {
        ...reportSummary.value,
        approvals: projectApprovals.value,
      };
  } catch (error: any) {
    if (!projectApprovals.value.length)
      ElMessage.error(errorMessage(error, "审批记录加载失败"));
  }
}

function mergeSecurityAction(action: SecurityAction) {
  const index = securityActions.value.findIndex(
    (item) => item.id === action.id,
  );
  if (index >= 0) securityActions.value.splice(index, 1, action);
  else securityActions.value.unshift(action);
}

async function loadSecurityActions(showError = false) {
  securityActionLoading.value = true;
  try {
    securityActions.value = (await endpoints.securityActions(id)).data || [];
  } catch (error: any) {
    if (showError || !securityActions.value.length)
      ElMessage.error(errorMessage(error, "安全行动记录加载失败"));
  } finally {
    securityActionLoading.value = false;
  }
}

function openSecurityActionDialog() {
  if (!canManageSecurityActions.value)
    return ElMessage.warning("只有管理员可以申请高风险安全行动");
  if (!projectAuthorizationGuard.value.active)
    return ElMessage.warning(projectAuthorizationGuard.value.text);
  if (!linkedTargets.value.length)
    return ElMessage.warning("项目尚未添加授权目标");
  const form = newSecurityActionForm();
  form.targetId = linkedTargets.value[0]?.id;
  securityActionForm.value = form;
  securityActionDialog.value = true;
}

async function createSecurityAction() {
  const form = securityActionForm.value;
  const preset = selectedSecurityActionPreset.value;
  if (!canManageSecurityActions.value)
    return ElMessage.warning("只有管理员可以申请高风险安全行动");
  if (!projectAuthorizationGuard.value.active)
    return ElMessage.warning(projectAuthorizationGuard.value.text);
  if (!form.targetId || !linkedIds.value.has(form.targetId))
    return ElMessage.warning("请选择当前项目内的授权目标");
  if (!form.purpose.trim()) return ElMessage.warning("请填写本次验证目的");
  if (!form.windowStart || !form.windowEnd)
    return ElMessage.warning("请选择完整的执行时间窗");
  const windowStart = form.windowStart.getTime();
  const windowEnd = form.windowEnd.getTime();
  if (windowEnd <= windowStart)
    return ElMessage.warning("结束时间必须晚于开始时间");
  if (windowEnd - windowStart > 8 * 60 * 60_000)
    return ElMessage.warning("单次执行时间窗不得超过 8 小时");
  const authorizationStart = Date.parse(
    project.value?.authorizationValidFrom || "",
  );
  const authorizationEnd = Date.parse(
    project.value?.authorizationExpiresAt || "",
  );
  if (windowStart < authorizationStart || windowEnd > authorizationEnd)
    return ElMessage.warning("执行时间窗必须完全位于项目授权有效期内");
  if (!form.acknowledged)
    return ElMessage.warning("请确认已理解授权边界和停止条件");

  securityActionSaving.value = true;
  try {
    const { data } = await endpoints.createSecurityAction(id, {
      targetId: form.targetId,
      findingId: form.findingId,
      category: preset.category,
      title: preset.title,
      purpose: form.purpose.trim(),
      riskLevel: preset.riskLevel,
      nonDestructive: true,
      lateralMovement: false,
      executionPlan: preset.executionPlan,
      rollbackPlan: preset.rollbackPlan,
      windowStart: form.windowStart.toISOString(),
      windowEnd: form.windowEnd.toISOString(),
    });
    mergeSecurityAction(data);
    securityActionDialog.value = false;
    ElMessage.success(`安全行动 #${data.id} 已提交审批申请`);
    await loadProjectAudits();
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "安全行动申请失败"));
  } finally {
    securityActionSaving.value = false;
  }
}

async function decideSecurityAction(
  row: SecurityAction,
  decision: "APPROVED" | "REJECTED",
) {
  if (!canManageSecurityActions.value)
    return ElMessage.warning("只有管理员可以审批安全行动");
  let result: { value?: string };
  try {
    result = (await ElMessageBox.prompt(
      decision === "APPROVED"
        ? "批准后仍需等待执行时间窗，并在开始时再次校验项目授权。单管理员模式需要管理员再次确认，多账号模式下申请人与审批人必须不同。"
        : "拒绝后该行动不能启动，请填写拒绝依据。",
      decision === "APPROVED" ? "批准高风险安全行动" : "拒绝高风险安全行动",
      {
        type: decision === "APPROVED" ? "warning" : "error",
        confirmButtonText: decision === "APPROVED" ? "确认批准" : "确认拒绝",
        cancelButtonText: "取消",
        inputPlaceholder:
          decision === "APPROVED" ? "审批备注（可选）" : "拒绝原因（必填）",
        inputValidator: (value) =>
          decision === "APPROVED" ||
          Boolean(value?.trim()) ||
          "拒绝时必须填写原因",
      },
    )) as { value?: string };
  } catch {
    return;
  }

  securityActionMutating.value = row.id;
  try {
    const { data } = await endpoints.decideSecurityAction(id, row.id, {
      decision,
      comment: result.value?.trim(),
    });
    mergeSecurityAction(data);
    ElMessage.success(
      decision === "APPROVED" ? "安全行动已批准" : "安全行动已拒绝",
    );
    await loadProjectAudits();
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "审批操作失败"));
  } finally {
    securityActionMutating.value = undefined;
  }
}

async function startSecurityAction(row: SecurityAction) {
  if (!canManageSecurityActions.value)
    return ElMessage.warning("只有管理员可以开始安全行动");
  if (!projectAuthorizationGuard.value.active)
    return ElMessage.warning(projectAuthorizationGuard.value.text);
  const windowState = securityActionWindowState(row);
  if (!windowState.allowed) return ElMessage.warning(windowState.label);
  try {
    await ElMessageBox.confirm(
      `即将开始「${row.title}」。系统只登记并约束服务端白名单安全行动，不会执行任意命令；请严格按照已批准计划和停止条件操作。`,
      "开始高风险安全行动",
      {
        type: "warning",
        confirmButtonText: "确认开始",
        cancelButtonText: "取消",
      },
    );
  } catch {
    return;
  }

  securityActionMutating.value = row.id;
  try {
    mergeSecurityAction((await endpoints.startSecurityAction(id, row.id)).data);
    ElMessage.success("安全行动已进入执行中状态");
    await loadProjectAudits();
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "安全行动启动失败"));
  } finally {
    securityActionMutating.value = undefined;
  }
}

function openSecurityActionOperation(
  row: SecurityAction,
  operation: "COMPLETE" | "ROLLBACK",
) {
  securityActionOperation.value = operation;
  securityActionOperationTarget.value = row;
  securityActionOperationForm.value = { evidence: "", reason: "" };
  securityActionOperationDialog.value = true;
}

async function submitSecurityActionOperation() {
  const row = securityActionOperationTarget.value;
  const form = securityActionOperationForm.value;
  if (!row) return;
  if (!form.evidence.trim())
    return ElMessage.warning("请填写可审计的结果证据摘要");
  if (securityActionOperation.value === "ROLLBACK" && !form.reason.trim())
    return ElMessage.warning("请填写回滚原因");
  securityActionOperationSaving.value = true;
  try {
    const result =
      securityActionOperation.value === "COMPLETE"
        ? await endpoints.completeSecurityAction(id, row.id, {
            evidence: form.evidence.trim(),
            terminationReason: form.reason.trim() || undefined,
          })
        : await endpoints.rollbackSecurityAction(id, row.id, {
            evidence: form.evidence.trim(),
            reason: form.reason.trim(),
          });
    mergeSecurityAction(result.data);
    securityActionOperationDialog.value = false;
    ElMessage.success(
      securityActionOperation.value === "COMPLETE"
        ? "安全行动已完成并留存证据"
        : "安全行动已回滚并留存证据",
    );
    await loadProjectAudits();
  } catch (error: any) {
    ElMessage.error(
      errorMessage(
        error,
        securityActionOperation.value === "COMPLETE"
          ? "完成登记失败"
          : "回滚登记失败",
      ),
    );
  } finally {
    securityActionOperationSaving.value = false;
  }
}

async function loadProjectAudits() {
  auditLoading.value = true;
  try {
    const { data } = await endpoints.audits(
      auditPage.value - 1,
      auditPageSize.value,
      id,
    );
    const nextTotal = Number(data?.totalElements || 0);
    const lastPage = Math.max(1, Math.ceil(nextTotal / auditPageSize.value));
    if (nextTotal > 0 && auditPage.value > lastPage) {
      auditPage.value = lastPage;
      await loadProjectAudits();
      return;
    }
    projectAudits.value = data?.content || [];
    projectAuditTotal.value = nextTotal;
  } catch {
    projectAudits.value = [];
    projectAuditTotal.value = 0;
  } finally {
    auditLoading.value = false;
  }
}

async function refreshProjectData() {
  await Promise.all([
    loadProjectReportSummary(),
    loadProjectTasks(),
    loadProjectApprovals(),
    loadSecurityActions(),
  ]);
  await loadProjectAudits();
}

function appendTaskLog(task: ProjectTaskRecord, line: string) {
  if (!line) return;
  const current = task.executionLog || "";
  task.executionLog = current ? `${current}\n${line}` : line;
}

let summaryRefreshTimer: ReturnType<typeof setTimeout> | undefined;
let overviewPollTimer: number | undefined;
// Aggregates (overview el-descriptions + report cards) are not part of the per-task SSE patch,
// so refresh them (debounced) whenever a task reaches a terminal state instead of forcing the
// user to click 刷新摘要.
function scheduleSummaryRefresh() {
  clearTimeout(summaryRefreshTimer);
  summaryRefreshTimer = setTimeout(() => {
    void loadProjectReportSummary();
  }, 1500);
}

function applyProjectTaskEvent(event: TaskProgressEvent) {
  if (!Number(event.taskId)) return;
  if (Number(event.projectId) > 0 && Number(event.projectId) !== id) return;
  const current = projectTasks.value.find(
    (task) => task.id === Number(event.taskId),
  );
  if (!current) {
    if (Number(event.projectId) === id) void loadProjectTasks();
    return;
  }
  const patch: Partial<ProjectTaskRecord> = {
    status: event.status || current.status,
    progress: event.progress ?? current.progress,
    progressDeterminate:
      event.progressDeterminate ?? current.progressDeterminate,
    progressCompleted: event.progressCompleted ?? current.progressCompleted,
    progressTotal: event.progressTotal ?? current.progressTotal,
    progressMessage: event.progressMessage || current.progressMessage,
    progressUpdatedAt: event.progressUpdatedAt || current.progressUpdatedAt,
    errorMessage: event.errorMessage || current.errorMessage,
    terminationReason: event.terminationReason || current.terminationReason,
    timeoutAt: event.timeoutAt || current.timeoutAt,
    startedAt: event.startedAt || current.startedAt,
    finishedAt: event.finishedAt || current.finishedAt,
  };
  const updated = { ...current, ...patch };
  if (event.logLine)
    appendTaskLog(
      updated,
      `${formatDateTime(event.emittedAt || new Date().toISOString())}  ${event.logLine}`,
    );
  mergeProjectTask(updated);
  if (
    ["SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED"].includes(
      updated.status,
    )
  )
    scheduleSummaryRefresh();
  if (taskDetail.value?.id === updated.id) {
    Object.assign(taskDetail.value, patch);
    if (event.logLine)
      appendTaskLog(
        taskDetail.value,
        `${formatDateTime(event.emittedAt || new Date().toISOString())}  ${event.logLine}`,
      );
    if (
      ["SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED"].includes(
        updated.status,
      )
    )
      taskDetailLoading.value = false;
  }
}

function showTaskDetail(row: ProjectTaskRecord) {
  taskDetail.value = { ...row };
  taskDetailVisible.value = true;
  taskDetailLoading.value = ["PENDING", "QUEUED", "RUNNING"].includes(
    row.status,
  );
}

async function retryProjectTask(row: ProjectTaskRecord) {
  if (taskRetrying.value) return;
  taskRetrying.value = row.id;
  try {
    const { data } = await endpoints.retryTask(row.id);
    if (data) mergeProjectTask(data);
    ElMessage.success(`已创建重试任务 #${data?.id || "—"}`);
    await loadProjectTasks();
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "任务重试失败"));
  } finally {
    taskRetrying.value = undefined;
  }
}

async function cancelProjectTask(row: ProjectTaskRecord) {
  if (taskCancelling.value) return;
  taskCancelling.value = row.id;
  try {
    const { data } = await endpoints.cancelTask(row.id);
    if (data) mergeProjectTask(data);
    ElMessage.success(`已请求取消任务 #${row.id}`);
    await loadProjectTasks();
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "任务取消失败"));
  } finally {
    taskCancelling.value = undefined;
  }
}

function openDiffDialog() {
  diff.value = undefined;
  const completed = successfulTasks.value;
  diffBaselineTaskId.value =
    completed.length > 1
      ? completed[completed.length - 2].id
      : completed[0]?.id;
  diffCurrentTaskId.value = completed[completed.length - 1]?.id;
  diffVisible.value = true;
}

async function loadDiff() {
  const baseline = Number(diffBaselineTaskId.value);
  const current = Number(diffCurrentTaskId.value);
  if (
    !Number.isSafeInteger(baseline) ||
    !Number.isSafeInteger(current) ||
    baseline <= 0 ||
    current <= 0 ||
    baseline === current
  ) {
    ElMessage.warning("请选择两个不同的成功任务作为基线和当前版本");
    return;
  }
  diffLoading.value = true;
  try {
    diff.value = (await endpoints.scanDiff(baseline, current)).data;
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "扫描 Diff 获取失败"));
  } finally {
    diffLoading.value = false;
  }
}

async function retestProjectFinding(row: ProjectFindingRecord) {
  findingRetesting.value = row.id;
  try {
    const { data } = await endpoints.retestFinding(row.id);
    ElMessage.success(
      `已创建漏洞复测任务 #${data?.retestTaskId || data?.id || "—"}`,
    );
    await loadProjectReportSummary();
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "创建复测任务失败"));
  } finally {
    findingRetesting.value = undefined;
  }
}

async function updateProjectFindingStatus(
  row: ProjectFindingRecord,
  status: string,
) {
  try {
    const { data } = await endpoints.updateFindingStatus(row.id, status);
    Object.assign(row, data);
    if (reportSummary.value)
      reportSummary.value = {
        ...reportSummary.value,
        findings: projectFindings.value,
      };
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "漏洞状态更新失败"));
  }
}

function openApprovalDialog() {
  const hash =
    projectTasks.value.find((task) => task.authorizationSnapshotHash)
      ?.authorizationSnapshotHash || "";
  approvalForm.value = {
    action: "SCAN",
    comment: "",
    authorizationSnapshotHash: hash,
  };
  approvalDialog.value = true;
}

async function requestApproval() {
  if (!approvalForm.value.action.trim())
    return ElMessage.warning("请选择审批动作");
  approvalSaving.value = true;
  try {
    const { data } = await endpoints.requestProjectApproval(
      id,
      approvalForm.value,
    );
    if (data) projectApprovals.value = [data, ...projectApprovals.value];
    approvalDialog.value = false;
    ElMessage.success("审批申请已提交");
    await loadProjectAudits();
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "审批申请提交失败"));
  } finally {
    approvalSaving.value = false;
  }
}

async function decideApproval(
  row: ProjectApproval,
  status: "APPROVED" | "REJECTED",
) {
  approvalDecision.value = row.id;
  try {
    const { data } = await endpoints.decideProjectApproval(id, row.id, {
      status,
    });
    Object.assign(row, data);
    ElMessage.success(status === "APPROVED" ? "审批已通过" : "审批已拒绝");
    await loadProjectAudits();
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "审批决定提交失败"));
  } finally {
    approvalDecision.value = undefined;
  }
}

async function downloadProjectSummaryPdf() {
  projectReportPdfLoading.value = true;
  try {
    const blob = (await endpoints.downloadProjectReportPdf(id)).data;
    downloadBlob(blob, `project-${id}-security-report.pdf`);
  } catch (error: any) {
    ElMessage.error(
      error instanceof EmptyDownloadError
        ? error.message
        : errorMessage(error, "项目总结 PDF 下载失败"),
    );
  } finally {
    projectReportPdfLoading.value = false;
  }
}

const REPORT_PREVIEW_CSP = [
  "default-src 'none'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "connect-src 'none'",
  "script-src 'none'",
  "style-src 'unsafe-inline'",
  "img-src data:",
  "font-src data:",
  "media-src 'none'",
  "worker-src 'none'",
  "form-action 'none'",
].join("; ");

const REPORT_PREVIEW_BLOCKED_ELEMENTS = [
  "script",
  "iframe",
  "frame",
  "frameset",
  "object",
  "embed",
  "applet",
  "portal",
  "form",
  "input",
  "button",
  "textarea",
  "select",
  "option",
  "link",
  "base",
  "meta",
  "audio",
  "video",
  "source",
  "track",
].join(",");

const REPORT_PREVIEW_BLOCKED_ATTRIBUTES = new Set([
  "srcdoc",
  "srcset",
  "action",
  "formaction",
  "manifest",
  "poster",
  "background",
  "target",
  "download",
  "ping",
  "nonce",
  "integrity",
  "crossorigin",
]);

/**
 * Treat generated report HTML as untrusted even though it originates from the
 * local backend. The returned document is rendered only inside an opaque-origin
 * sandboxed iframe; this pass also removes active content and all network URLs.
 */
function buildSandboxedReportHtml(source: string): string {
  if (!source?.trim()) throw new Error("报告内容为空，无法预览");
  const reportDocument = new DOMParser().parseFromString(source, "text/html");

  reportDocument
    .querySelectorAll(REPORT_PREVIEW_BLOCKED_ELEMENTS)
    .forEach((node) => node.remove());
  reportDocument.querySelectorAll<Element>("*").forEach((element) => {
    for (const attribute of Array.from(element.attributes)) {
      const name = attribute.name.toLowerCase();
      const value = attribute.value.trim();
      if (
        name.startsWith("on") ||
        REPORT_PREVIEW_BLOCKED_ATTRIBUTES.has(name)
      ) {
        element.removeAttribute(attribute.name);
        continue;
      }
      if (name === "href" || name === "xlink:href") {
        if (!value.startsWith("#")) element.removeAttribute(attribute.name);
        continue;
      }
      if (name === "src") {
        const isEmbeddedRasterImage =
          element.tagName.toLowerCase() === "img" &&
          /^data:image\/(?:png|jpe?g|gif|webp);base64,/i.test(value);
        if (!isEmbeddedRasterImage) element.removeAttribute(attribute.name);
      }
    }
  });

  const charset = reportDocument.createElement("meta");
  charset.setAttribute("charset", "utf-8");
  const csp = reportDocument.createElement("meta");
  csp.httpEquiv = "Content-Security-Policy";
  csp.content = REPORT_PREVIEW_CSP;
  const referrer = reportDocument.createElement("meta");
  referrer.name = "referrer";
  referrer.content = "no-referrer";
  reportDocument.head.prepend(charset, csp, referrer);
  reportDocument.documentElement.lang =
    reportDocument.documentElement.lang || "zh-CN";
  return `<!doctype html>\n${reportDocument.documentElement.outerHTML}`;
}

function showReportPreview(source: string, title: string) {
  reportPreviewHtml.value = buildSandboxedReportHtml(source);
  reportPreviewTitle.value = title;
  reportPreviewVisible.value = true;
}

function resetReportPreview() {
  reportPreviewHtml.value = "";
  reportPreviewTitle.value = "";
}

async function openProjectSummaryHtml() {
  projectReportHtmlLoading.value = true;
  try {
    const html = (await endpoints.downloadProjectReportHtml(id)).data;
    showReportPreview(
      html,
      `${project.value?.name || `项目 #${id}`} · HTML 报告`,
    );
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "项目总结 HTML 打开失败"));
  } finally {
    projectReportHtmlLoading.value = false;
  }
}

async function downloadTargetPdfReport() {
  const target = reportTarget.value;
  if (!target)
    return ElMessage.warning("项目尚未添加授权目标，无法生成单目标报告");
  targetReportPdfLoading.value = true;
  try {
    const blob = (await endpoints.downloadTargetReportPdf(target.id)).data;
    downloadBlob(blob, `target-${target.id}-security-report.pdf`);
  } catch (error: any) {
    ElMessage.error(
      error instanceof EmptyDownloadError
        ? error.message
        : errorMessage(error, "目标 PDF 下载失败"),
    );
  } finally {
    targetReportPdfLoading.value = false;
  }
}

async function openTargetHtmlReport() {
  const target = reportTarget.value;
  if (!target)
    return ElMessage.warning("项目尚未添加授权目标，无法生成单目标报告");
  targetReportHtmlLoading.value = true;
  try {
    const html = (await endpoints.downloadTargetReportHtml(target.id)).data;
    showReportPreview(html, `${target.name} · 单目标 HTML 报告`);
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "目标 HTML 打开失败"));
  } finally {
    targetReportHtmlLoading.value = false;
  }
}

const STATUS_OPTIONS = [
  { value: "DRAFT", label: "草稿" },
  { value: "ACTIVE", label: "进行中" },
  { value: "PAUSED", label: "暂停" },
  { value: "COMPLETED", label: "已完成" },
  { value: "ARCHIVED", label: "已归档" },
];
async function changeStatus(status: string) {
  try {
    const { data } = await endpoints.updateProjectStatus(id, status);
    project.value = data;
    if (summary.value) summary.value = { ...summary.value, project: data };
    ElMessage.success(
      "项目状态已更新为「" +
        (STATUS_OPTIONS.find((s) => s.value === status)?.label || status) +
        "」",
    );
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "状态更新失败"));
  }
}

interface EditableBatchTargetItem {
  id: string;
  name: string;
  targetValue: string;
  targetType: "ip" | "domain" | "url";
  useCustomPort: boolean;
  selectedPorts: string[];
  fullPortAccess: boolean;
}

const targetDialog = ref(false);
const targetSaving = ref(false);
const targetMode = ref<"single" | "batch">("single");
const targetForm = ref({
  name: "",
  targetValue: "",
  targetType: "domain",
  authorizationNote: "",
});
const targetSelectedPorts = ref<string[]>(["80", "443"]);
const targetFullPortAccess = ref(false);

const targetBatchForm = reactive({
  rawText: "",
  authorizationNote: "",
  fullPortAccess: false,
  selectedPorts: ["80", "443"],
});
const targetBatchParseResult = computed(() =>
  parseBatchTargets(targetBatchForm.rawText),
);
const editableTargetBatchItems = ref<EditableBatchTargetItem[]>([]);

watch(
  () => targetBatchForm.rawText,
  (newText) => {
    const res = parseBatchTargets(newText);
    editableTargetBatchItems.value = res.items.map((item) => {
      let itemPorts: string[] = [];
      if (item.customPorts) {
        itemPorts = item.customPorts
          .split(/[,;\s]+/)
          .map((s) => s.trim())
          .filter(Boolean);
      }
      return {
        id: item.id || `${item.targetType}-${item.targetValue}`,
        name: item.name,
        targetValue: item.targetValue,
        targetType: item.targetType,
        useCustomPort: Boolean(item.customPorts || item.isFullPort),
        selectedPorts: itemPorts.length
          ? itemPorts
          : [...targetBatchForm.selectedPorts],
        fullPortAccess: Boolean(item.isFullPort),
      };
    });
  },
  { immediate: true },
);

function enableTargetItemCustomPort(row: EditableBatchTargetItem) {
  row.useCustomPort = true;
  if (!row.selectedPorts?.length && !row.fullPortAccess) {
    row.selectedPorts = [...targetBatchForm.selectedPorts];
    row.fullPortAccess = targetBatchForm.fullPortAccess;
  }
}

function resetTargetItemToInherit(row: EditableBatchTargetItem) {
  row.useCustomPort = false;
  row.selectedPorts = [...targetBatchForm.selectedPorts];
  row.fullPortAccess = false;
}

function removeTargetBatchItem(id: string) {
  editableTargetBatchItems.value = editableTargetBatchItems.value.filter(
    (it) => it.id !== id,
  );
}

function openTargetCreate() {
  targetMode.value = "single";
  targetForm.value = {
    name: "",
    targetValue: "",
    targetType: "domain",
    authorizationNote: project.value?.authorizationStatement || "",
  };
  targetSelectedPorts.value = ["80", "443"];
  targetFullPortAccess.value = false;

  targetBatchForm.rawText = "";
  targetBatchForm.authorizationNote =
    project.value?.authorizationStatement || "";
  targetBatchForm.fullPortAccess = false;
  targetBatchForm.selectedPorts = ["80", "443"];

  targetDialog.value = true;
}

async function createTargetInProject() {
  const f = targetForm.value;
  if (!f.name.trim() || !f.targetValue.trim() || !f.authorizationNote.trim()) {
    ElMessage.warning("请填写名称、地址和授权记录");
    return;
  }
  let allowedPorts: string;
  try {
    allowedPorts = normalizeAllowedPorts(
      targetSelectedPorts.value,
      "",
      targetFullPortAccess.value,
    );
  } catch (error: any) {
    ElMessage.warning(error?.message || "端口格式不正确");
    return;
  }
  targetSaving.value = true;
  try {
    await endpoints.createTarget({
      name: f.name.trim(),
      targetValue: f.targetValue.trim(),
      targetType: f.targetType,
      allowedPorts,
      authorizationNote: f.authorizationNote.trim(),
      enabled: true,
      projectId: id,
    });
    ElMessage.success("授权目标已创建并加入项目");
    targetDialog.value = false;
    await load();
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "创建目标失败"));
  } finally {
    targetSaving.value = false;
  }
}

async function batchCreateTargetsInProject() {
  const items = editableTargetBatchItems.value;
  if (!items.length) {
    ElMessage.warning("未解析出任何有效的主机、域名或 URL 目标");
    return;
  }
  if (!targetBatchForm.authorizationNote.trim()) {
    ElMessage.warning("请填写统一授权记录说明");
    return;
  }

  let defaultAllowedPorts: string;
  try {
    defaultAllowedPorts = normalizeAllowedPorts(
      targetBatchForm.selectedPorts,
      "",
      targetBatchForm.fullPortAccess,
    );
  } catch (error: any) {
    ElMessage.warning(error?.message || "端口格式不正确");
    return;
  }

  targetSaving.value = true;
  let successCount = 0;
  let failedCount = 0;
  try {
    for (const item of items) {
      try {
        let allowedPorts: string;
        if (targetBatchForm.fullPortAccess) {
          allowedPorts = "1-65535";
        } else if (item.useCustomPort) {
          if (item.fullPortAccess) {
            allowedPorts = "1-65535";
          } else {
            allowedPorts = normalizeAllowedPorts(
              item.selectedPorts || [],
              "",
              false,
            );
          }
        } else {
          allowedPorts = defaultAllowedPorts;
        }

        await endpoints.createTarget({
          name: item.name,
          targetValue: item.targetValue,
          targetType: item.targetType,
          allowedPorts,
          authorizationNote: targetBatchForm.authorizationNote.trim(),
          enabled: true,
          projectId: id,
        });
        successCount++;
      } catch {
        failedCount++;
      }
    }

    if (failedCount === 0) {
      ElMessage.success(`已成功批量录入 ${successCount} 个目标并加入项目`);
    } else if (successCount > 0) {
      ElMessage.warning(`批量录入完成：成功 ${successCount} 个，失败 ${failedCount} 个`);
    } else {
      throw new Error("所有批量目标保存均失败");
    }

    targetDialog.value = false;
    await load();
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "批量创建目标失败"));
  } finally {
    targetSaving.value = false;
  }
}
async function removeTargetFromProject(targetId: number) {
  try {
    await endpoints.removeProjectTarget(id, targetId);
    ElMessage.success("已移出项目");
    await load();
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "移出失败"));
  }
}

const memoryRows = ref<MemoryDoc[]>([]);
const {
  page: memoryPage,
  pageSize: memoryPageSize,
  pagedItems: pagedMemoryRows,
} = useClientPagination(memoryRows);
const memoryLoading = ref(false);
async function loadMemories() {
  memoryLoading.value = true;
  try {
    memoryRows.value = (await endpoints.listMemories(id)).data || [];
  } catch {
    memoryRows.value = [];
  } finally {
    memoryLoading.value = false;
  }
}
function memorySourceLabel(source?: string) {
  const labels: Record<string, string> = {
    conversation: '对话',
  };
  return source ? labels[source] || source : '-';
}
async function deleteMemory(docId: string) {
  try {
    await ElMessageBox.confirm(
      "删除这条对话记忆？删除后 AI 将无法再检索到它。",
      "确认删除",
      { type: "warning" },
    );
    await endpoints.deleteMemory(id, docId);
    ElMessage.success("已删除对话记忆");
    await loadMemories();
  } catch (error) {
    if (error !== "cancel" && error !== "close") ElMessage.error("删除失败");
  }
}

async function clearMemories() {
  if (!memoryRows.value.length)
    return ElMessage.info("当前没有可清空的 AI 记忆");
  try {
    await ElMessageBox.confirm(
      `将清空本项目全部 ${memoryRows.value.length} 条 AI 对话记忆。清空后 AI 无法再检索这些摘要，且不可恢复。`,
      "清空 AI 记忆",
      {
        type: "warning",
        confirmButtonText: "全部清空",
        cancelButtonText: "取消",
      },
    );
    memoryLoading.value = true;
    const { data } = await endpoints.clearMemories(id);
    ElMessage.success(
      `已清空 ${data?.deleted ?? memoryRows.value.length} 条 AI 记忆`,
    );
    await loadMemories();
  } catch (error) {
    if (error !== "cancel" && error !== "close") ElMessage.error("清空失败");
  } finally {
    memoryLoading.value = false;
  }
}

function openReportMetric(targetTab: string, query?: Record<string, string>) {
  tab.value = targetTab;
  if (targetTab === "tasks") void loadProjectTasks();
  if (targetTab === "findings") void load();
  if (targetTab === "audits") {
    void loadProjectApprovals();
    void loadProjectAudits();
  }
  const nextQuery = {
    ...route.query,
    tab: targetTab === "overview" ? undefined : targetTab,
    ...(query || {}),
  };
  void router.replace({ path: route.path, query: nextQuery });
}

async function loadDiscovery() {
  try {
    discoveryRows.value = (
      await endpoints.projectDiscoveryResults(id, discoveryTarget.value)
    ).data;
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "探测结果加载失败"));
  }
}

/**
 * Probe results keep the matcher output in an evidence JSON blob.  Keep the
 * parsing tolerant because older records may have stored the same payload as
 * an object (or may not contain matcher output at all).
 */
function parseDiscoveryJson(value: unknown): unknown {
  if (typeof value !== "string" || !value.trim()) return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function discoveryFingerprintMatches(
  row: DiscoveryResult,
): Array<Record<string, unknown>> {
  const evidence = parseDiscoveryJson(row.evidence);
  const candidates: unknown[] = [];
  if (evidence && typeof evidence === "object" && !Array.isArray(evidence)) {
    const record = evidence as Record<string, unknown>;
    candidates.push(record.fingerprints, record.matches);
  }
  candidates.push((row as Record<string, unknown>).fingerprints);
  const direct = parseDiscoveryJson(row.fingerprint);
  if (direct && typeof direct === "object" && !Array.isArray(direct)) {
    const record = direct as Record<string, unknown>;
    candidates.push(record.fingerprints, record.matches);
  } else candidates.push(direct);
  for (const candidate of candidates) {
    const parsed = parseDiscoveryJson(candidate);
    if (!Array.isArray(parsed)) continue;
    const matches = parsed.filter((item): item is Record<string, unknown> =>
      Boolean(item && typeof item === "object" && !Array.isArray(item)),
    );
    if (matches.length) return matches;
  }
  return [];
}

function discoveryFingerprintIds(row: DiscoveryResult): string[] {
  return [
    ...new Set(
      discoveryFingerprintMatches(row)
        .map((item) => item.id ?? item.ruleId ?? item.fingerprintId)
        .filter(
          (value): value is string =>
            typeof value === "string" && value.trim().length > 0,
        )
        .map((value) => value.trim()),
    ),
  ];
}

function discoveryFingerprintNames(row: DiscoveryResult): string[] {
  const matches = discoveryFingerprintMatches(row);
  return [
    ...new Set(
      matches
        .map((item) => item.name)
        .filter(
          (value): value is string =>
            typeof value === "string" && value.trim().length > 0,
        )
        .map((value) => value.trim()),
    ),
  ];
}

function discoveryRowKey(row: DiscoveryResult) {
  return `${row.id ?? row.targetId}-${row.detectedAt ?? row.createdAt ?? row.url ?? ""}`;
}

async function openPocRecommendations(row: DiscoveryResult) {
  pocRecommendationTarget.value = row;
  pocRecommendationIds.value = discoveryFingerprintIds(row);
  pocRecommendations.value = [];
  pocRecommendationVisible.value = true;
  if (!pocRecommendationIds.value.length) return;
  pocRecommendationLoading.value = true;
  try {
    const { data } = await endpoints.pocRecommendations(
      pocRecommendationIds.value,
    );
    pocRecommendations.value = Array.isArray(data) ? data : [];
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "安全检测建议加载失败"));
  } finally {
    pocRecommendationLoading.value = false;
  }
}

function pocVerificationLabel(status?: string) {
  const labels: Record<string, string> = {
    OFFICIAL_RELEASE_DIGEST_PRESENT: "官方固定版本 · 含签名",
    OFFICIAL_RELEASE_UNSIGNED: "官方固定版本 · 未签名",
    OFFICIAL_REPOSITORY_SNAPSHOT: "官方仓库快照",
    LOCAL_DIGEST_PRESENT: "本地模板 · 含签名",
    LOCAL_UNVERIFIED: "本地模板 · 待复核",
    BUILTIN_REVIEWED: "内置复核",
    VERIFIED: "已复核签名",
    UNVERIFIED: "待复核",
  };
  return (status && labels[status]) || status || "待复核";
}

function diffChangeLabel(type?: string) {
  const labels: Record<string, string> = {
    ADDED: "新增",
    RESOLVED: "已修复",
    PERSISTENT: "持续存在",
    SEVERITY_CHANGED: "等级变化",
  };
  return (type && labels[type]) || type || "未知";
}

function diffChangeTagType(type?: string): "success" | "danger" | "warning" | "info" {
  const map: Record<string, "success" | "danger" | "warning" | "info"> = {
    ADDED: "danger",
    RESOLVED: "success",
    PERSISTENT: "info",
    SEVERITY_CHANGED: "warning",
  };
  return (type && map[type]) || "info";
}

function openAuthorizedDetection() {
  const targetId = pocRecommendationTarget.value?.targetId;
  if (!targetId) return;
  pocRecommendationVisible.value = false;
  void router.push({
    path: "/vulnerabilities",
    query: { target: String(targetId) },
  });
}

async function loadFingerprintCatalog() {
  fingerprintCatalogLoading.value = true;
  try {
    fingerprintCatalog.value = (await endpoints.fingerprintCatalog()).data;
  } catch {
    fingerprintCatalog.value = undefined;
  } finally {
    fingerprintCatalogLoading.value = false;
  }
}

async function reloadFingerprintCatalog() {
  fingerprintCatalogReloading.value = true;
  try {
    fingerprintCatalog.value = (
      await endpoints.reloadFingerprintCatalog()
    ).data;
    ElMessage.success(
      `指纹规则已重载：${fingerprintCatalog.value.ruleCount} 条`,
    );
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "指纹规则重载失败"));
  } finally {
    fingerprintCatalogReloading.value = false;
  }
}

const FINGERPRINT_CATALOG_MAX_BYTES = 2 * 1024 * 1024;

function fingerprintCatalogSourceLabel(
  source?: FingerprintCatalogInfo["source"],
) {
  const labels: Record<string, string> = {
    BUILTIN: "内置规则",
    MANAGED: "本机更新",
    EXTERNAL: "外部配置",
  };
  return source ? labels[source] || source : "当前来源";
}

function fingerprintCatalogFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(bytes < 1024 * 100 ? 1 : 0)} KB`;
}

function openFingerprintCatalogFilePicker() {
  if (!canUpdateFingerprintCatalog.value) {
    ElMessage.warning("仅管理员可以更新指纹库");
    return;
  }
  if (fingerprintCatalogUpdating.value) return;
  fingerprintCatalogFileInput.value?.click();
}

function setFingerprintCatalogUpdateError(message: string) {
  fingerprintCatalogUpdateState.value = "error";
  fingerprintCatalogUpdateError.value = message;
  fingerprintCatalogUpdateResult.value = undefined;
  ElMessage.error(message);
}

async function updateFingerprintCatalogFromFile(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  input.value = "";
  if (!file) return;

  fingerprintCatalogUpdateFile.value = { name: file.name, size: file.size };
  fingerprintCatalogUpdateState.value = "idle";
  fingerprintCatalogUpdateError.value = "";
  fingerprintCatalogUpdateResult.value = undefined;

  const isJsonFile =
    /\.json$/i.test(file.name) ||
    ["application/json", "text/json"].includes(file.type.toLowerCase());
  if (!isJsonFile) {
    setFingerprintCatalogUpdateError("请选择扩展名为 .json 的指纹规则文件");
    return;
  }
  if (!file.size) {
    setFingerprintCatalogUpdateError("指纹规则文件不能为空");
    return;
  }
  if (file.size > FINGERPRINT_CATALOG_MAX_BYTES) {
    setFingerprintCatalogUpdateError("指纹规则文件不能超过 2 MB");
    return;
  }

  let catalogBytes: ArrayBuffer;
  try {
    catalogBytes = await file.arrayBuffer();
    const catalogJson = new TextDecoder("utf-8", { fatal: true })
      .decode(catalogBytes)
      .replace(/^\uFEFF/, "");
    const document = JSON.parse(catalogJson);
    if (!document || typeof document !== "object" || Array.isArray(document)) {
      throw new Error("JSON 根节点必须是对象");
    }
  } catch {
    setFingerprintCatalogUpdateError("文件不是有效的 JSON 指纹规则库");
    return;
  }

  const confirmed = await ElMessageBox.confirm(
    `将使用“${file.name}”更新服务器管理的指纹库。服务端会完整校验内容，校验失败时保留当前版本。`,
    "更新指纹库",
    {
      type: "warning",
      confirmButtonText: "上传并更新",
      cancelButtonText: "取消",
    },
  ).catch(() => false);
  if (confirmed !== "confirm") {
    fingerprintCatalogUpdateState.value = "cancelled";
    return;
  }

  fingerprintCatalogUpdating.value = true;
  fingerprintCatalogUpdateState.value = "updating";
  try {
    const updated = (await endpoints.updateFingerprintCatalog(catalogBytes))
      .data;
    let refreshed = updated;
    try {
      refreshed = (await endpoints.fingerprintCatalog()).data;
    } catch {
      // The update response already contains the committed catalog metadata.
    }
    fingerprintCatalog.value = refreshed;
    fingerprintCatalogUpdateResult.value = refreshed;
    fingerprintCatalogUpdateState.value = "success";
    ElMessage.success(
      `指纹库已更新至 v${refreshed.version}，共 ${refreshed.ruleCount} 条规则`,
    );
  } catch (error: any) {
    setFingerprintCatalogUpdateError(
      errorMessage(error, "指纹库更新失败，当前版本未更改"),
    );
  } finally {
    fingerprintCatalogUpdating.value = false;
  }
}

async function loadRecon() {
  try {
    reconRows.value = (
      await endpoints.projectReconResults(id, reconTarget.value)
    ).data;
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "信息收集结果加载失败"));
  }
}

async function load() {
  loading.value = true;
  try {
    const [p, s, l, t] = await Promise.all([
      endpoints.project(id),
      endpoints.projectSummary(id),
      endpoints.projectTargets(id),
      endpoints.targets(),
    ]);
    project.value = p.data;
    summary.value = s.data;
    links.value = l.data;
    targets.value = t.data;
    reportTargetId.value = reportTargetId.value || l.data[0]?.targetId;
    await Promise.all([
      loadDiscovery(),
      loadRecon(),
      loadFingerprintCatalog(),
      loadProjectReportSummary(),
    ]);
    // Approval records have a dedicated endpoint and are refreshed separately
    // from the larger report summary so decisions appear immediately.
    await Promise.all([
      loadProjectApprovals(),
      loadSecurityActions(),
      loadProjectAudits(),
      loadProjectWorkflowRun(),
    ]);
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "项目加载失败"));
  } finally {
    loading.value = false;
  }
}

async function add() {
  if (!selected.value) return;
  await endpoints.addProjectTarget(id, selected.value);
  selected.value = undefined;
  await load();
  ElMessage.success("目标已加入项目");
}

type LinkedStepOptions = {
  notify?: boolean;
  rethrow?: boolean;
  confirmActive?: boolean;
};

async function probe(options: LinkedStepOptions = {}): Promise<boolean> {
  const { notify = true, rethrow = false } = options;
  if (!discoveryTarget.value) {
    if (notify) ElMessage.warning("请选择授权目标");
    return false;
  }
  probing.value = true;
  try {
    const result = await endpoints.probeProjectTarget(
      id,
      discoveryTarget.value,
    );
    discoveryRows.value = [result.data, ...discoveryRows.value];
    const evidence = parseDiscoveryJson(result.data.evidence);
    const unavailable = Boolean(
      evidence &&
      typeof evidence === "object" &&
      !Array.isArray(evidence) &&
      String(
        (evidence as Record<string, unknown>).status || "",
      ).toUpperCase() === "UNAVAILABLE",
    );
    if (notify) {
      if (unavailable)
        ElMessage.warning(
          "目标当前未响应，失败原因已记录，其他工作流步骤仍可继续",
        );
      else ElMessage.success("探测完成");
    }
    return !unavailable;
  } catch (error: any) {
    if (notify) ElMessage.error(errorMessage(error, "探测失败"));
    if (rethrow) throw error;
    return false;
  } finally {
    probing.value = false;
  }
}

async function collectRecon(options: LinkedStepOptions = {}): Promise<boolean> {
  const { notify = true, rethrow = false, confirmActive = true } = options;
  if (!reconTarget.value) {
    if (notify) ElMessage.warning("请选择项目内授权目标");
    return false;
  }
  if (reconMode.value === "ACTIVE" && confirmActive) {
    try {
      await ElMessageBox.confirm(
        "主动收集会向授权目标发送 DNS、HTTP/TLS 和受限主机探测请求。请确认授权范围仍然有效。",
        "确认主动信息收集",
        {
          type: "warning",
          confirmButtonText: "确认执行",
          cancelButtonText: "取消",
        },
      );
    } catch {
      return false;
    }
  }
  collectingRecon.value = true;
  try {
    const result = await endpoints.collectProjectRecon(id, {
      targetId: reconTarget.value,
      mode: reconMode.value,
      includeSameSubnet:
        reconMode.value === "ACTIVE" && includeSameSubnet.value,
      activeNetworkProbe:
        reconMode.value === "ACTIVE" && includeSameSubnet.value,
      includeHttp: includeHttp.value,
      includeTls: includeTls.value,
      enumerateSubdomains: enumerateSubdomains.value,
      subdomainWords: enumerateSubdomains.value
        ? subdomainDictionary.value
            .split(/[，,;；\s]+/)
            .map((item) => item.trim())
            .filter(Boolean)
            .slice(0, 50)
        : [],
    });
    reconRows.value = [result.data, ...reconRows.value];
    const unavailableSources = parseValue(result.data.sourceEvidence).filter(
      (item) =>
        item &&
        typeof item === "object" &&
        String((item as Record<string, unknown>).status || "").toUpperCase() ===
          "UNAVAILABLE",
    );
    if (notify && unavailableSources.length) {
      ElMessage.warning(
        `信息收集已完成，${unavailableSources.length} 个来源暂不可用；其余结果已保存`,
      );
    } else if (notify) {
      ElMessage.success("信息收集完成");
    }
    return unavailableSources.length === 0;
  } catch (error: any) {
    if (notify) ElMessage.error(errorMessage(error, "信息收集失败"));
    if (rethrow) throw error;
    return false;
  } finally {
    collectingRecon.value = false;
  }
}

async function queryIcpBatch() {
  const targetIds = linkedTargets.value.map((target) => target.id);
  if (!targetIds.length) return ElMessage.warning("项目尚未添加授权目标");
  icpLoading.value = true;
  try {
    icpRows.value = (await endpoints.projectIcpBatch(id, targetIds)).data || [];
    const availableCount = icpRows.value.filter(
      (item) => item.status === "AVAILABLE",
    ).length;
    const requiresConfiguration = icpRows.value.some(
      (item) => item.status === "CONFIG_REQUIRED",
    );
    if (requiresConfiguration)
      ElMessage.warning(
        "尚未配置 ICP 备案数据源；请设置 HTTPS 的 ICP_API_URL 后重启本地服务",
      );
    else if (availableCount)
      ElMessage.success(
        `ICP备案查询完成：${availableCount}/${icpRows.value.length} 个目标返回数据`,
      );
    else
      ElMessage.warning(
        "ICP备案数据源暂未返回可用结果，请查看表格中的具体原因",
      );
  } catch (error: any) {
    ElMessage.error(errorMessage(error, "ICP备案批量查询失败"));
  } finally {
    icpLoading.value = false;
  }
}

function icpStatusLabel(status: string) {
  if (status === "AVAILABLE") return "已返回";
  if (status === "CONFIG_REQUIRED") return "需要配置";
  return "不可用";
}

function icpStatusType(status: string) {
  if (status === "AVAILABLE") return "success";
  if (status === "CONFIG_REQUIRED") return "warning";
  return "danger";
}

function parseValue(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null || value === "") return [];
  if (typeof value !== "string") return [value];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return [value];
  }
}

function reconGroups(row: ReconResult) {
  return [
    {
      label: "域名",
      data: values(row, "domains", "domainNames", "rootDomain"),
    },
    { label: "子域名", data: values(row, "subdomains", "subDomains") },
    { label: "DNS 记录", data: values(row, "dnsRecords", "dnsRecords") },
    {
      label: "IP/归属地",
      data: values(
        row,
        "ipAddresses",
        "ips",
        "addresses",
        "ipInformation",
        "geolocationInformation",
      ),
    },
    {
      label: "服务器/网络",
      data: values(
        row,
        "servers",
        "serverInfo",
        "httpInformation",
        "networkInformation",
      ),
    },
    {
      label: "TLS 证书",
      data: values(row, "certificates", "tlsCertificates", "tlsInformation"),
    },
  ];
}

const filteredReconRows = computed(() => {
  const q = reconFilter.value.trim().toLowerCase();
  if (!q) return reconRows.value;
  return reconRows.value.filter((row) =>
    JSON.stringify(row).toLowerCase().includes(q),
  );
});
const {
  page: reconPage,
  pageSize: reconPageSize,
  pagedItems: pagedReconRows,
  resetPage: resetReconPage,
} = useClientPagination(filteredReconRows);
watch(reconFilter, resetReconPage);

function exportRecon(format: "json" | "csv" | "html" = "json") {
  const rows = filteredReconRows.value;
  if (!rows.length) return ElMessage.warning("暂无可导出的结果");
  let content = "";
  let type = "";
  let ext = format;
  if (format === "json") {
    content = JSON.stringify(rows, null, 2);
    type = "application/json;charset=utf-8";
  }
  if (format === "csv") {
    const keys = [
      "id",
      "targetId",
      "rootDomain",
      "subdomains",
      "dnsRecords",
      "ipInformation",
      "httpInformation",
      "networkInformation",
      "collectedAt",
    ];
    const esc = (v: unknown) =>
      `"${String(typeof v === "string" ? v : JSON.stringify(v ?? "")).replace(/"/g, '""')}"`;
    content = [
      keys.join(","),
      ...rows.map((r) => keys.map((k) => esc((r as any)[k])).join(",")),
    ].join("\n");
    type = "text/csv;charset=utf-8";
  }
  if (format === "html") {
    content = `<html><meta charset="utf-8"><body><h1>项目 ${id} 信息收集</h1><pre>${JSON.stringify(rows, null, 2).replace(/</g, "&lt;")}</pre></body></html>`;
    type = "text/html;charset=utf-8";
  }
  try {
    downloadText(content, `project-${id}-recon.${ext}`, type);
  } catch (error) {
    ElMessage.error(
      error instanceof EmptyDownloadError ? error.message : "导出失败",
    );
  }
}

const PROJECT_WORKFLOW_TERMINALS = new Set([
  "COMPLETED",
  "PARTIAL_FAILED",
  "STOPPED",
  "FAILED",
]);

function projectWorkflowStatusLabel(status: string) {
  const labels: Record<string, string> = {
    PREPARING: "准备中",
    RUNNING: "执行中",
    STOPPING: "停止中",
    COMPLETED: "工作流完成",
    PARTIAL_FAILED: "部分任务失败",
    STOPPED: "已停止",
    FAILED: "执行失败",
  };
  return labels[status] || status;
}

function projectWorkflowTaskStatus(status: string) {
  const labels: Record<string, string> = {
    PENDING: "排队中",
    BLOCKED: "等待前置节点",
    RUNNING: "执行中",
    SUCCESS: "成功",
    FAILED: "失败",
    TIMEOUT: "超时",
    REJECTED: "被拒绝",
    CANCELLED: "已取消",
    SKIPPED: "已跳过",
  };
  return labels[status] || status;
}

function workflowTaskSummary(task: ProjectTaskRecord) {
  if (task.resultJson) {
    try {
      const result = JSON.parse(task.resultJson);
      if (typeof result?.summary === "string") return result.summary;
    } catch {
      /* Fall back to persisted progress or error text. */
    }
  }
  return task.errorMessage || task.progressMessage || "";
}

function applyProjectWorkflowRun(detail: WorkflowRunDetail) {
  workflowRunId.value = detail.run.id;
  workflowProgress.value = Math.max(0, Math.min(100, detail.run.progress || 0));
  workflowStatus.value = projectWorkflowStatusLabel(detail.run.status);
  workflowTaskIds.value = detail.tasks.map((task) => task.id);
  workflowLog.value = [
    `[运行 #${detail.run.id}] ${detail.run.message || workflowStatus.value}`,
    ...detail.tasks.map((task) => {
      const summary = workflowTaskSummary(task);
      return `[#${task.id}] ${task.toolCode} · ${projectWorkflowTaskStatus(task.status)}${summary ? ` · ${summary}` : ""}`;
    }),
  ];
  workflowIndeterminate.value =
    !PROJECT_WORKFLOW_TERMINALS.has(detail.run.status) &&
    detail.tasks.some(
      (task) =>
        ["PENDING", "BLOCKED", "RUNNING"].includes(task.status) &&
        !task.progressDeterminate,
    );
  workflowRunning.value = !PROJECT_WORKFLOW_TERMINALS.has(detail.run.status);
}

async function pollProjectWorkflowRun(runId: number) {
  const generation = ++workflowPollGeneration;
  while (generation === workflowPollGeneration) {
    try {
      const { data } = await endpoints.workflowRun(runId);
      if (generation !== workflowPollGeneration) return;
      applyProjectWorkflowRun(data);
      if (PROJECT_WORKFLOW_TERMINALS.has(data.run.status)) {
        await refreshProjectData();
        return;
      }
    } catch {
      if (generation !== workflowPollGeneration) return;
      workflowStatus.value = "运行状态读取失败，正在重试";
    }
    await new Promise((resolve) => window.setTimeout(resolve, 750));
  }
}

async function loadProjectWorkflowRun() {
  workflowPollGeneration += 1;
  try {
    const { data } = await endpoints.workflowRuns(id);
    const run =
      (data || []).find(
        (item) => !PROJECT_WORKFLOW_TERMINALS.has(item.status),
      ) || data?.[0];
    if (!run) return;
    const detail = (await endpoints.workflowRun(run.id)).data;
    applyProjectWorkflowRun(detail);
    if (!PROJECT_WORKFLOW_TERMINALS.has(detail.run.status)) {
      void pollProjectWorkflowRun(detail.run.id);
    }
  } catch (error) {
    ElMessage.warning(errorMessage(error, "工作流运行状态加载失败"));
  }
}

async function runWorkflow() {
  const target =
    reconTarget.value || discoveryTarget.value || linkedTargets.value[0]?.id;
  if (!target) return ElMessage.warning("请先选择项目内授权目标");

  let spec: WorkflowSpecV2 | undefined;
  try {
    const result = await endpoints.getWorkflowSpec(id);
    spec = result.data;
  } catch (error: any) {
    return ElMessage.error(errorMessage(error, "读取工作流配置失败"));
  }

  const steps = spec?.steps || [];
  if (!steps.length) {
    return ElMessage.warning(
      "当前项目尚未保存红队工作流，请先前往“红队工作流”页面编排并保存",
    );
  }

  try {
    await ElMessageBox.confirm(
      `将按已保存工作流执行 ${steps.length} 个步骤。高风险步骤会逐次确认，仅限当前项目授权目标。`,
      "启动项目联动工作流",
      { type: "warning" },
    );
  } catch {
    return;
  }

  try {
    if (!spec.workflowId || !spec.revision || !spec.specDigest) {
      throw new Error("工作流快照缺少版本标识，请重新保存工作流");
    }
    const identity = {
      projectId: id,
      targetId: target,
      workflowId: spec.workflowId,
      workflowRevision: spec.revision,
      workflowDigest: spec.specDigest,
    };
    const { data: preflight } = await endpoints.preflightWorkflowRun(identity);
    const skippedNodeIds = preflight.issues.map((issue) => issue.nodeId);
    if (preflight.issues.length) {
      const issueText = preflight.issues
        .map((issue) => `${issue.label}：${issue.reason}`)
        .join("；");
      const skipConfirmed = await ElMessageBox.confirm(
        `${issueText}。是否明确跳过这些节点并继续？依赖它们的后继步骤也会跳过。`,
        "工作流预检发现不可用节点",
        {
          type: "warning",
          confirmButtonText: "跳过并继续",
          cancelButtonText: "取消执行",
        },
      ).catch(() => false);
      if (skipConfirmed !== "confirm") return;
    }

    const approvedNodeIds: string[] = [];
    for (const step of steps) {
      const nodeId = step.nodeId || step.tool;
      if (
        step.requiresApproval &&
        step.tool !== "retrieve_project_context" &&
        !skippedNodeIds.includes(nodeId)
      ) {
        const approved = await ElMessageBox.confirm(
          `步骤“${step.label || step.tool}”风险级别为 ${step.risk || "CAUTION"}，确认对当前授权目标执行？`,
          "确认高风险步骤",
          { type: "warning", confirmButtonText: "确认执行" },
        ).catch(() => false);
        if (approved !== "confirm") return;
        approvedNodeIds.push(nodeId);
      }
    }

    reconTarget.value = target;
    discoveryTarget.value = target;
    workflowRunId.value = undefined;
    workflowRunning.value = true;
    workflowProgress.value = 0;
    workflowIndeterminate.value = true;
    workflowStatus.value = "准备执行";
    workflowLog.value = [
      `[工作流] 已预检版本 ${spec.revision}，正在创建后端运行`,
    ];
    workflowTaskIds.value = [];
    const { data: detail } = await endpoints.startWorkflowRun({
      ...identity,
      approvedNodeIds,
      skippedNodeIds,
    });
    applyProjectWorkflowRun(detail);
    await pollProjectWorkflowRun(detail.run.id);
  } catch (error: any) {
    workflowStatus.value = "执行失败";
    workflowLog.value.push(`[工作流] 错误：${errorMessage(error, "执行失败")}`);
    ElMessage.error(errorMessage(error, "联动工作流失败"));
  } finally {
    if (!workflowRunId.value) {
      workflowRunning.value = false;
      workflowIndeterminate.value = false;
    }
  }
}

async function stopProjectWorkflow() {
  const runId = workflowRunId.value;
  if (!runId || !workflowRunning.value || workflowStopping.value) return;
  workflowStopping.value = true;
  workflowStatus.value = "正在停止";
  try {
    const { data } = await endpoints.stopWorkflowRun(runId);
    applyProjectWorkflowRun(data);
    if (PROJECT_WORKFLOW_TERMINALS.has(data.run.status)) {
      workflowPollGeneration += 1;
    }
  } catch (error) {
    ElMessage.error(errorMessage(error, "停止工作流失败"));
  } finally {
    workflowStopping.value = false;
  }
}

function values(row: ReconResult, ...keys: string[]): unknown[] {
  for (const key of keys) {
    const value = row[key];
    const parsed = parseValue(value);
    if (parsed.length) return parsed;
  }
  return [];
}

function itemText(value: unknown) {
  if (typeof value === "string" || typeof value === "number")
    return String(value);
  return JSON.stringify(value, null, 2);
}

async function report() {
  await downloadProjectSummaryPdf();
}

onMounted(() => {
  stopTaskFeed = connectTaskEventFeed(applyProjectTaskEvent);
  void load();
  overviewPollTimer = window.setInterval(() => {
    if (tab.value === "overview" || tab.value === "report")
      void loadProjectReportSummary();
  }, 15_000);
});
onUnmounted(() => {
  workflowPollGeneration += 1;
  stopTaskFeed?.();
  clearTimeout(summaryRefreshTimer);
  if (overviewPollTimer) window.clearInterval(overviewPollTimer);
});
</script>

<template>
  <section class="panel project-detail-page" v-loading="loading">
    <div class="section-head">
      <div>
        <h3>{{ project?.name || "评估项目" }}</h3>
        <p>{{ project?.description || project?.authorizationStatement }}</p>
      </div>
      <div
        class="detail-head-actions"
        style="display: flex; align-items: center; gap: 10px"
      >
        <el-select
          :model-value="project?.status"
          placeholder="项目状态"
          style="width: 168px"
          @change="changeStatus"
        >
          <el-option
            v-for="s in STATUS_OPTIONS"
            :key="s.value"
            :label="s.label"
            :value="s.value"
          />
        </el-select>
        <el-button type="primary" plain @click="openProjectCopilot()"
          ><el-icon><MagicStick /></el-icon>AI 项目分析</el-button
        >
        <el-button :loading="projectReportPdfLoading" @click="report"
          >项目总结 PDF</el-button
        >
      </div>
    </div>
    <el-tabs v-model="tab" class="project-tabs" @tab-change="handleTabChange">
      <el-tab-pane label="概览" name="overview">
        <el-descriptions v-if="summary" :column="3" border>
          <el-descriptions-item label="状态">
            <el-tag
              size="small"
              :type="projectStatusType(summary.project.status)"
              effect="light"
            >
              {{ projectStatusLabel(summary.project.status) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="目标">{{
            summary.targetCount
          }}</el-descriptions-item>
          <el-descriptions-item label="检测任务">{{
            summary.taskCount
          }}</el-descriptions-item>
          <el-descriptions-item label="漏洞发现">{{
            summary.vulnerabilityCount
          }}</el-descriptions-item>
          <el-descriptions-item label="风险点">{{
            summary.informationalCount
          }}</el-descriptions-item>
          <el-descriptions-item label="复测记录">{{
            summary.retestCount
          }}</el-descriptions-item>
          <el-descriptions-item label="审批/审计">{{
            summary.auditCount
          }}</el-descriptions-item>
        </el-descriptions>
      </el-tab-pane>
      <el-tab-pane label="授权目标" name="targets">
        <div class="toolbar">
          <el-select
            v-model="selected"
            placeholder="选择已有目标加入项目"
            clearable
            filterable
          >
            <el-option
              v-for="t in available"
              :key="t.id"
              :label="`${t.name} · ${t.targetValue}`"
              :value="t.id"
            />
          </el-select>
          <el-button type="primary" @click="add">加入项目</el-button>
          <el-button @click="openTargetCreate">新建授权目标</el-button>
        </div>
        <el-empty
          v-if="!linkedTargets.length"
          description="项目暂无授权目标，先新建或加入一个目标"
        />
        <el-table v-else :data="pagedLinkedTargets" stripe>
          <el-table-column prop="name" label="名称" min-width="140" />
          <el-table-column prop="targetValue" label="地址" min-width="180" />
          <el-table-column prop="targetType" label="类型" width="90" />
          <el-table-column
            prop="allowedPorts"
            label="授权端口"
            min-width="140"
          />
          <el-table-column label="操作" width="110"
            ><template #default="s"
              ><el-button
                link
                type="danger"
                @click="removeTargetFromProject(s.row.id)"
                >移出项目</el-button
              ></template
            ></el-table-column
          >
        </el-table>
        <AppPagination
          v-model:page="linkedTargetPage"
          v-model:page-size="linkedTargetPageSize"
          class="project-table-pagination"
          :total="linkedTargets.length"
        />
        <el-dialog
          v-model="targetDialog"
          title="在本项目下新建授权目标"
          class="app-dialog app-dialog--md"
          align-center
          destroy-on-close
        >
          <div class="target-mode-nav">
            <el-segmented
              v-model="targetMode"
              class="target-mode-segmented"
              :options="[
                { label: '单目标录入', value: 'single' },
                { label: '批量导入 / 网段 (CIDR)', value: 'batch' },
              ]"
            />
          </div>

          <!-- 单目标录入 -->
          <el-form v-if="targetMode === 'single'" label-position="top" class="project-target-create-form">
            <div class="project-form-row">
              <el-form-item label="名称" required
                ><el-input v-model="targetForm.name" placeholder="用于内部识别"
              /></el-form-item>
              <el-form-item label="类型"
                ><el-select v-model="targetForm.targetType"
                  ><el-option label="域名" value="domain" /><el-option
                    label="IP 地址"
                    value="ip" /><el-option
                    label="URL"
                    value="url" /></el-select
              ></el-form-item>
            </div>
            <el-form-item label="地址" required
              ><el-input
                v-model="targetForm.targetValue"
                placeholder="example.com 或 192.0.2.10"
            /></el-form-item>
            <el-form-item label="端口授权模式"
              ><div class="port-picker">
                <div class="full-port-option">
                  <div>
                    <b>整机全端口模式（1-65535）</b>
                    <small>将整台主机的所有端口作为目标，开放全暴露面深度探测（使用 Nmap）。</small>
                  </div>
                  <el-switch v-model="targetFullPortAccess" />
                </div>
                <div v-if="!targetFullPortAccess" class="custom-port-section">
                  <span class="custom-port-label">允许测试的指定服务端口：</span>
                  <el-select
                    v-model="targetSelectedPorts"
                    multiple
                    filterable
                    allow-create
                    collapse-tags
                    collapse-tags-tooltip
                    default-first-option
                    placeholder="选择常用端口或手动输入，如 8000, 8080-8090"
                  >
                    <el-option
                      v-for="port in COMMON_PORT_OPTIONS"
                      :key="port.value"
                      :label="port.label"
                      :value="port.value"
                    />
                  </el-select>
                </div>
                <p class="port-hint">
                  {{
                    targetFullPortAccess
                      ? "已开启整机全端口模式，将保存为 1-65535；适用于靶场或整机全面黑盒评估。"
                      : "已开启指定端口模式，超出此端口集合的请求将在执行前被平台授权守卫拦截保护。"
                  }}
                </p>
              </div></el-form-item
            >
            <el-form-item label="授权记录" required
              ><el-input
                v-model="targetForm.authorizationNote"
                type="textarea"
                :rows="2"
                placeholder="填写授权来源、允许范围和有效期"
            /></el-form-item>
          </el-form>

          <!-- 批量导入与网段模式 -->
          <el-form v-else label-position="top" class="project-target-create-form">
            <el-form-item label="批量目标与网段输入" required>
              <el-input
                v-model="targetBatchForm.rawText"
                type="textarea"
                :rows="5"
                placeholder="支持按行粘贴多个目标或网段，例如：&#10;192.168.1.10&#10;192.168.1.20-192.168.1.30&#10;10.0.0.0/28&#10;app.example.com&#10;https://target.com:8443"
              />
            </el-form-item>

            <div class="batch-preview-card" v-if="targetBatchForm.rawText.trim()">
              <div class="batch-preview-head">
                <div>
                  <span class="preview-title">解析结果与单机端口定制</span>
                  <small class="preview-sub">支持单独修改每台主机的专属端口，未单独指定的将继承下方统一设置</small>
                </div>
                <span class="preview-badge">共 {{ editableTargetBatchItems.length }} 个主机目标</span>
              </div>
              <div class="batch-preview-stats">
                <span>IP 主机：<b>{{ targetBatchParseResult.stats.ipCount }}</b></span>
                <span>域名：<b>{{ targetBatchParseResult.stats.domainCount }}</b></span>
                <span>URL 站点：<b>{{ targetBatchParseResult.stats.urlCount }}</b></span>
                <span v-if="targetBatchParseResult.stats.customPortCount">已定制端口：<b>{{ targetBatchParseResult.stats.customPortCount }}</b> 台</span>
              </div>
              <div v-if="targetBatchParseResult.errors.length" class="batch-preview-errors">
                <span v-for="err in targetBatchParseResult.errors.slice(0, 3)" :key="err">⚠️ {{ err }}</span>
              </div>

              <el-table
                v-if="editableTargetBatchItems.length"
                :data="editableTargetBatchItems"
                size="small"
                class="batch-preview-table"
                max-height="240"
              >
                <el-table-column label="目标地址" min-width="160">
                  <template #default="{ row }">
                    <div class="preview-target-cell">
                      <span class="preview-target-val" :title="row.targetValue">{{ row.targetValue }}</span>
                      <el-tag size="small" :type="row.targetType === 'ip' ? 'info' : row.targetType === 'domain' ? 'primary' : 'success'" effect="plain">
                        {{ row.targetType === 'ip' ? 'IP' : row.targetType === 'domain' ? '域名' : 'URL' }}
                      </el-tag>
                    </div>
                  </template>
                </el-table-column>

                <el-table-column label="端口模式 / 允许端口" min-width="280">
                  <template #default="{ row }">
                    <div v-if="targetBatchForm.fullPortAccess" class="preview-inherit-row">
                      <el-tag size="small" type="warning" effect="plain">整机全端口（继承统一 1-65535）</el-tag>
                      <small class="inherit-disabled-hint">已统一开启全端口</small>
                    </div>
                    <div v-else-if="!row.useCustomPort" class="preview-inherit-row">
                      <span class="inherit-text">
                        继承统一（{{ targetBatchForm.selectedPorts.join(',') || '未配置' }}）
                      </span>
                      <el-button link type="primary" size="small" @click="enableTargetItemCustomPort(row)">
                        单独指定
                      </el-button>
                    </div>
                    <div v-else class="preview-custom-row">
                      <template v-if="row.fullPortAccess">
                        <el-tag size="small" type="warning" effect="plain">单机全端口</el-tag>
                        <el-button link size="small" @click="row.fullPortAccess = false">改端口</el-button>
                      </template>
                      <template v-else>
                        <el-select
                          v-model="row.selectedPorts"
                          multiple
                          filterable
                          allow-create
                          collapse-tags
                          collapse-tags-tooltip
                          default-first-option
                          size="small"
                          placeholder="选择或输入端口"
                          style="min-width: 150px; max-width: 220px;"
                        >
                          <el-option
                            v-for="port in COMMON_PORT_OPTIONS"
                            :key="port.value"
                            :label="port.label"
                            :value="port.value"
                          />
                        </el-select>
                        <el-button link type="warning" size="small" @click="row.fullPortAccess = true">全端口</el-button>
                      </template>
                      <el-button link type="info" size="small" @click="resetTargetItemToInherit(row)">恢复继承</el-button>
                    </div>
                  </template>
                </el-table-column>

                <el-table-column label="操作" width="56" align="center">
                  <template #default="{ row }">
                    <el-button link type="danger" size="small" @click="removeTargetBatchItem(row.id)">✕</el-button>
                  </template>
                </el-table-column>
              </el-table>
            </div>

            <el-form-item label="统一授权记录" required>
              <el-input
                v-model="targetBatchForm.authorizationNote"
                type="textarea"
                :rows="2"
                placeholder="填写统一授权依据、审批单号或测试协议"
              />
            </el-form-item>

            <el-form-item label="统一端口授权模式" class="port-form-item">
              <div class="port-picker">
                <div class="full-port-option">
                  <div>
                    <b>整机全端口模式（1-65535）</b>
                    <small>所有批量主机均开启全端口模式，开放全部 65535 端口深度探测。</small>
                  </div>
                  <el-switch v-model="targetBatchForm.fullPortAccess" />
                </div>
                <div v-if="!targetBatchForm.fullPortAccess" class="custom-port-section">
                  <span class="custom-port-label">所有目标统一允许的服务端口：</span>
                  <el-select
                    v-model="targetBatchForm.selectedPorts"
                    multiple
                    filterable
                    allow-create
                    collapse-tags
                    collapse-tags-tooltip
                    default-first-option
                    placeholder="选择常用端口或手动输入，如 8000, 8080-8090"
                  >
                    <el-option
                      v-for="port in COMMON_PORT_OPTIONS"
                      :key="port.value"
                      :label="port.label"
                      :value="port.value"
                    />
                  </el-select>
                </div>
              </div>
            </el-form-item>
          </el-form>

          <template #footer>
            <el-button @click="targetDialog = false">取消</el-button>
            <el-button
              v-if="targetMode === 'single'"
              type="primary"
              :loading="targetSaving"
              @click="createTargetInProject"
            >
              创建并加入
            </el-button>
            <el-button
              v-else
              type="primary"
              :loading="targetSaving"
              :disabled="!targetBatchParseResult.stats.total"
              @click="batchCreateTargetsInProject"
            >
              批量加入 {{ targetBatchParseResult.stats.total ? `(${targetBatchParseResult.stats.total} 个)` : '' }}
            </el-button>
          </template>
        </el-dialog>
      </el-tab-pane>
      <el-tab-pane label="探测服务" name="discovery">
        <div class="toolbar">
          <el-select
            v-model="discoveryTarget"
            placeholder="选择授权目标"
            clearable
            @change="loadDiscovery"
          >
            <el-option
              v-for="t in linkedTargets"
              :key="t.id"
              :label="`${t.name} · ${t.targetValue}`"
              :value="t.id"
            />
          </el-select>
          <el-button type="primary" :loading="probing" @click="probe()"
            >开始指纹/WAF识别</el-button
          >
          <el-button @click="loadDiscovery">刷新</el-button>
        </div>
        <section
          class="fingerprint-catalog-panel"
          :class="{ collapsed: !fingerprintCatalogExpanded }"
        >
          <header class="fingerprint-catalog-heading">
            <button
              type="button"
              class="fingerprint-catalog-toggle"
              :aria-expanded="fingerprintCatalogExpanded"
              aria-controls="project-fingerprint-catalog-body"
              :aria-label="
                fingerprintCatalogExpanded ? '收起指纹规则库' : '展开指纹规则库'
              "
              @click="fingerprintCatalogExpanded = !fingerprintCatalogExpanded"
            >
              <el-icon class="fingerprint-catalog-chevron">
                <ArrowDown />
              </el-icon>
              <span class="fingerprint-catalog-heading-copy">
                <strong>指纹规则库</strong>
                <span v-if="fingerprintCatalog">
                  v{{ fingerprintCatalog.version }} ·
                  {{ fingerprintCatalog.ruleCount }} 条规则
                </span>
                <span v-else-if="fingerprintCatalogLoading"
                  >正在读取规则信息</span
                >
                <span v-else>暂时无法读取指纹规则信息</span>
              </span>
            </button>
            <el-tag
              v-if="fingerprintCatalog"
              class="fingerprint-catalog-source-tag"
              size="small"
              effect="plain"
              >{{
                fingerprintCatalogSourceLabel(fingerprintCatalog.source)
              }}</el-tag
            >
          </header>
          <div
            id="project-fingerprint-catalog-body"
            class="fluent-collapsible fingerprint-catalog-collapse"
            :class="{ 'is-collapsed': !fingerprintCatalogExpanded }"
            :aria-hidden="!fingerprintCatalogExpanded"
            :inert="!fingerprintCatalogExpanded"
          >
            <div class="fluent-collapsible-inner">
              <div class="fingerprint-catalog-details">
                <div class="fingerprint-catalog-content">
                  <div
                    v-if="fingerprintCatalog"
                    class="fingerprint-catalog-meta"
                  >
                    <div>
                      <small>当前版本</small>
                      <strong>v{{ fingerprintCatalog.version }}</strong>
                    </div>
                    <div>
                      <small>规则数量</small>
                      <strong>{{ fingerprintCatalog.ruleCount }} 条</strong>
                    </div>
                    <div class="fingerprint-catalog-sha">
                      <small>SHA-256</small>
                      <code>{{ fingerprintCatalog.sha256 }}</code>
                    </div>
                  </div>
                  <el-skeleton
                    v-else-if="fingerprintCatalogLoading"
                    :rows="1"
                    animated
                  />
                  <span v-else class="muted-text"
                    >暂时无法读取指纹规则信息</span
                  >
                </div>
                <div
                  v-if="canUpdateFingerprintCatalog"
                  class="fingerprint-catalog-actions"
                >
                  <input
                    ref="fingerprintCatalogFileInput"
                    class="fingerprint-catalog-file-input"
                    type="file"
                    accept=".json,application/json"
                    @change="updateFingerprintCatalogFromFile"
                  />
                  <el-button
                    size="small"
                    :loading="fingerprintCatalogReloading"
                    :disabled="
                      fingerprintCatalogLoading || fingerprintCatalogUpdating
                    "
                    @click="reloadFingerprintCatalog"
                  >
                    <el-icon><Refresh /></el-icon>
                    重新读取
                  </el-button>
                  <el-button
                    type="primary"
                    plain
                    size="small"
                    :loading="fingerprintCatalogUpdating"
                    :disabled="
                      fingerprintCatalogLoading || fingerprintCatalogReloading
                    "
                    @click="openFingerprintCatalogFilePicker"
                  >
                    <el-icon><UploadFilled /></el-icon>
                    {{ fingerprintCatalogUpdating ? "正在更新" : "更新指纹库" }}
                  </el-button>
                </div>
                <div
                  v-if="fingerprintCatalogUpdateFile"
                  class="fingerprint-catalog-update"
                  :class="`is-${fingerprintCatalogUpdateState}`"
                >
                  <div class="fingerprint-catalog-update-file">
                    <small>本地 JSON 文件</small>
                    <strong :title="fingerprintCatalogUpdateFile.name">{{
                      fingerprintCatalogUpdateFile.name
                    }}</strong>
                    <span>{{
                      fingerprintCatalogFileSize(
                        fingerprintCatalogUpdateFile.size,
                      )
                    }}</span>
                  </div>
                  <div
                    class="fingerprint-catalog-update-result"
                    role="status"
                    aria-live="polite"
                  >
                    <template
                      v-if="fingerprintCatalogUpdateState === 'updating'"
                    >
                      <el-tag size="small" type="info">更新中</el-tag>
                      <span
                        >正在上传并由服务器校验，校验完成前继续使用当前版本。</span
                      >
                    </template>
                    <template
                      v-else-if="
                        fingerprintCatalogUpdateState === 'success' &&
                        fingerprintCatalogUpdateResult
                      "
                    >
                      <el-tag size="small" type="success">更新成功</el-tag>
                      <span
                        >v{{ fingerprintCatalogUpdateResult.version }} ·
                        {{
                          fingerprintCatalogUpdateResult.ruleCount
                        }}
                        条规则</span
                      >
                      <code
                        >SHA-256
                        {{ fingerprintCatalogUpdateResult.sha256 }}</code
                      >
                    </template>
                    <template
                      v-else-if="fingerprintCatalogUpdateState === 'error'"
                    >
                      <el-tag size="small" type="danger">更新失败</el-tag>
                      <span>{{ fingerprintCatalogUpdateError }}</span>
                    </template>
                    <template
                      v-else-if="fingerprintCatalogUpdateState === 'cancelled'"
                    >
                      <el-tag size="small" type="info">已取消</el-tag>
                      <span>当前指纹规则未更改。</span>
                    </template>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
        <el-empty v-if="!discoveryRows.length" description="暂无探测结果" />
        <el-table v-else :data="pagedDiscoveryRows" stripe>
          <el-table-column label="目标" min-width="170"
            ><template #default="s">{{
              s.row.targetValue || s.row.url || taskTargetName(s.row.targetId)
            }}</template></el-table-column
          >
          <el-table-column label="网站指纹" min-width="220"
            ><template #default="s">
              <div class="fingerprint-cell">
                <div
                  v-if="discoveryFingerprintNames(s.row).length"
                  class="fingerprint-tags"
                >
                  <el-tag
                    v-for="name in discoveryFingerprintNames(s.row)"
                    :key="name"
                    size="small"
                    effect="plain"
                    >{{ name }}</el-tag
                  >
                </div>
                <span v-else>{{
                  s.row.technologies ||
                  s.row.framework ||
                  s.row.server ||
                  "未识别"
                }}</span>
              </div>
            </template></el-table-column
          >
          <el-table-column label="WAF" width="140"
            ><template #default="s">{{
              typeof s.row.waf === "string"
                ? s.row.waf
                : s.row.wafName || "未识别"
            }}</template></el-table-column
          >
          <el-table-column label="证据" width="120"
            ><template #default="s"
              ><el-popover trigger="click" width="420"
                ><template #reference
                  ><el-button link type="primary">查看证据</el-button></template
                >
                <pre class="json-view">{{
                  JSON.stringify(
                    parseDiscoveryJson(s.row.evidence) || [],
                    null,
                    2,
                  )
                }}</pre>
              </el-popover></template
            ></el-table-column
          >
          <el-table-column label="安全检测建议" width="150"
            ><template #default="s">
              <el-button
                link
                type="primary"
                :disabled="!discoveryFingerprintIds(s.row).length"
                :loading="
                  pocRecommendationLoading &&
                  pocRecommendationTarget &&
                  discoveryRowKey(pocRecommendationTarget) ===
                    discoveryRowKey(s.row)
                "
                @click="openPocRecommendations(s.row)"
                >查看 SAFE PoC</el-button
              >
            </template></el-table-column
          >
        </el-table>
        <AppPagination
          v-model:page="discoveryPage"
          v-model:page-size="discoveryPageSize"
          class="project-table-pagination"
          :total="discoveryRows.length"
        />
        <el-dialog
          v-model="pocRecommendationVisible"
          title="指纹关联的安全检测建议"
          class="app-dialog app-dialog--wide"
          align-center
          destroy-on-close
        >
          <div class="poc-recommendation-context">
            <div>
              <small>授权目标</small
              ><strong>{{
                pocRecommendationTarget
                  ? pocRecommendationTarget.targetValue ||
                    pocRecommendationTarget.url ||
                    taskTargetName(pocRecommendationTarget.targetId)
                  : "—"
              }}</strong>
            </div>
            <div>
              <small>匹配指纹 ID</small>
              <div class="fingerprint-tags">
                <el-tag
                  v-for="fingerprintId in pocRecommendationIds"
                  :key="fingerprintId"
                  size="small"
                  effect="plain"
                  >{{ fingerprintId }}</el-tag
                ><span v-if="!pocRecommendationIds.length" class="muted-text"
                  >未提取到可关联的指纹 ID</span
                >
              </div>
            </div>
          </div>
          <el-alert
            class="poc-safety-alert"
            title="服务端仅返回启用、可追溯且 scanSafety=SAFE 的官方或已复核模板；这里不会自动执行 PoC。需要检测时，请进入授权漏洞检测页人工确认。"
            type="info"
            :closable="false"
            show-icon
          />
          <el-skeleton v-if="pocRecommendationLoading" :rows="4" animated />
          <el-alert
            v-else-if="!pocRecommendationIds.length"
            title="该探测记录没有可用于关联推荐的指纹 ID。可先刷新指纹规则并重新探测。"
            type="warning"
            :closable="false"
            show-icon
          />
          <el-empty
            v-else-if="!pocRecommendations.length"
            description="没有匹配的 SAFE 模板建议"
          />
          <el-table
            v-else
            :data="pagedPocRecommendations"
            stripe
            size="small"
            max-height="440"
            class="poc-recommendation-table"
          >
            <el-table-column label="等级" width="95"
              ><template #default="s"
                ><el-tag
                  size="small"
                  :type="findingSeverityType(s.row.severity)"
                  >{{ s.row.severity }}</el-tag
                ></template
              ></el-table-column
            >
            <el-table-column
              prop="name"
              label="检测规则 / PoC"
              min-width="240"
              show-overflow-tooltip
            />
            <el-table-column
              label="模板 ID"
              min-width="180"
              show-overflow-tooltip
              ><template #default="s"
                ><code>{{
                  s.row.templateId || s.row.vulnerabilityCode
                }}</code></template
              ></el-table-column
            >
            <el-table-column label="真实性" width="140"
              ><template #default="s">{{
                pocVerificationLabel(s.row.verificationStatus)
              }}</template></el-table-column
            >
            <el-table-column
              label="模板摘要"
              min-width="220"
              show-overflow-tooltip
              ><template #default="s"
                ><code>{{ s.row.sha256 || "未提供" }}</code></template
              ></el-table-column
            >
          </el-table>
          <AppPagination
            v-model:page="pocPage"
            v-model:page-size="pocPageSize"
            class="project-table-pagination"
            :total="pocRecommendations.length"
          />
          <template #footer
            ><el-button @click="pocRecommendationVisible = false"
              >关闭</el-button
            ><el-button
              type="primary"
              :disabled="!pocRecommendationTarget"
              @click="openAuthorizedDetection"
              >进入授权漏洞检测</el-button
            ></template
          >
        </el-dialog>
      </el-tab-pane>
      <el-tab-pane label="信息收集" name="recon">
        <el-alert
          class="recon-alert"
          type="info"
          :closable="false"
          show-icon
          title="默认使用被动收集；主动收集只允许在项目授权目标和端口范围内执行。"
        />
        <div class="recon-controls">
          <div class="recon-controls-row recon-controls-row--primary">
            <el-select
              v-model="reconTarget"
              placeholder="选择项目内授权目标"
              clearable
              @change="loadRecon"
            >
              <el-option
                v-for="t in linkedTargets"
                :key="t.id"
                :label="`${t.name} · ${t.targetValue}`"
                :value="t.id"
              />
            </el-select>
            <el-radio-group v-model="reconMode">
              <el-radio-button value="PASSIVE">被动收集</el-radio-button>
              <el-radio-button value="ACTIVE">主动收集</el-radio-button>
            </el-radio-group>
          </div>
          <div class="recon-controls-row recon-controls-row--options">
            <el-checkbox v-model="includeHttp">HTTP 信息</el-checkbox>
            <el-checkbox v-model="includeTls">TLS/证书</el-checkbox>
            <el-checkbox v-model="enumerateSubdomains"
              >字典枚举子域名</el-checkbox
            >
            <el-checkbox
              v-model="includeSameSubnet"
              :disabled="reconMode !== 'ACTIVE'"
              >受限同网段发现</el-checkbox
            >
            <el-input
              v-if="enumerateSubdomains"
              v-model="subdomainDictionary"
              class="subdomain-dictionary"
              placeholder="子域名字典：www,api,dev"
            />
          </div>
          <div class="recon-controls-row recon-controls-row--actions">
            <el-button
              type="primary"
              :loading="collectingRecon"
              @click="collectRecon()"
              >开始收集</el-button
            >
            <el-button @click="loadRecon">刷新</el-button>
            <el-button :loading="icpLoading" @click="queryIcpBatch"
              >ICP备案批量查询</el-button
            >
            <el-input
              v-model="reconFilter"
              clearable
              placeholder="过滤域名/IP/证据"
              class="recon-filter-input"
            />
            <el-dropdown
              :disabled="!filteredReconRows.length"
              @command="(f: 'json' | 'csv' | 'html') => exportRecon(f)"
            >
              <el-button>导出结果</el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="json">JSON</el-dropdown-item>
                  <el-dropdown-item command="csv">CSV</el-dropdown-item>
                  <el-dropdown-item command="html">HTML</el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
            <el-button
              type="success"
              :loading="workflowRunning"
              :disabled="workflowRunning"
              @click="runWorkflow"
              >一键联动工作流</el-button
            >
            <el-button
              v-if="workflowRunning"
              type="danger"
              :loading="workflowStopping"
              @click="stopProjectWorkflow"
              >停止工作流</el-button
            >
            <el-button type="primary" plain @click="openProjectCopilot('recon')"
              ><el-icon><MagicStick /></el-icon>AI 解读结果</el-button
            >
          </div>
        </div>
        <el-table
          v-if="icpRows.length"
          :data="pagedIcpRows"
          size="small"
          stripe
          class="icp-table"
          ><el-table-column label="目标" min-width="180"
            ><template #default="scope">{{
              taskTargetName(scope.row.targetId) || scope.row.domain
            }}</template></el-table-column
          ><el-table-column
            prop="domain"
            label="域名"
            min-width="180"
          /><el-table-column label="状态" width="120"
            ><template #default="scope"
              ><el-tag size="small" :type="icpStatusType(scope.row.status)">{{
                icpStatusLabel(scope.row.status)
              }}</el-tag></template
            ></el-table-column
          ><el-table-column
            prop="reason"
            label="说明"
            min-width="320"
            show-overflow-tooltip
          /><el-table-column label="备案数据" min-width="260"
            ><template #default="scope">
              <pre class="json-view">{{
                JSON.stringify(scope.row.data || {}, null, 2)
              }}</pre>
            </template></el-table-column
          ></el-table
        >
        <AppPagination
          v-model:page="icpPage"
          v-model:page-size="icpPageSize"
          class="project-table-pagination"
          :total="icpRows.length"
        />
        <div v-if="workflowRunning || workflowLog.length" class="workflow-box">
          <div class="workflow-head">
            <strong>项目任务流：按已保存红队工作流执行</strong
            ><span
              >{{ workflowRunId ? `运行 #${workflowRunId} · ` : ""
              }}{{ workflowStatus }}</span
            >
          </div>
          <el-progress
            :percentage="Math.round(workflowProgress)"
            :status="
              ['执行失败', '部分任务失败'].includes(workflowStatus)
                ? 'exception'
                : undefined
            "
            :indeterminate="workflowIndeterminate"
            :duration="1.2"
          />
          <pre class="workflow-log">{{ workflowLog.join("\n") }}</pre>
        </div>
        <p class="mode-hint">
          {{
            reconMode === "PASSIVE"
              ? "通过公开 DNS、证书透明度及已有项目证据聚合信息，不主动扫描目标。"
              : "执行受控 DNS、HTTP/TLS 探测；同网段发现必须显式开启且仍受项目授权范围约束。"
          }}
        </p>
        <el-empty
          v-if="!filteredReconRows.length"
          :description="
            reconRows.length ? '没有匹配的结果' : '暂无信息收集记录'
          "
        />
        <el-collapse v-else class="recon-results">
          <el-collapse-item
            v-for="(row, index) in pagedReconRows"
            :key="row.id || index"
            :name="row.id || index"
          >
            <template #title>
              <div class="result-title">
                <strong>{{
                  row.targetValue || `目标 #${row.targetId}`
                }}</strong>
                <el-tag
                  :type="row.mode === 'ACTIVE' ? 'warning' : 'success'"
                  size="small"
                  >{{ row.mode === "ACTIVE" ? "主动" : "被动" }}</el-tag
                >
                <span>{{
                  formatDateTime(
                    row.completedAt || row.createdAt || row.startedAt,
                  )
                }}</span>
              </div>
            </template>
            <div class="recon-grid">
              <article
                v-for="group in reconGroups(row)"
                :key="group.label"
                class="recon-card"
              >
                <header>
                  <span>{{ group.label }}</span
                  ><el-tag size="small" effect="plain">{{
                    group.data.length
                  }}</el-tag>
                </header>
                <div v-if="group.data.length" class="card-list">
                  <pre
                    v-for="(item, itemIndex) in group.data"
                    :key="itemIndex"
                    >{{ itemText(item) }}</pre>
                </div>
                <span v-else class="empty-text">未收集到</span>
              </article>
            </div>
            <div class="evidence-block">
              <h4>来源与证据</h4>
              <pre class="json-view evidence-json">{{
                JSON.stringify(
                  parseValue(row.evidence || row.sourceEvidence),
                  null,
                  2,
                )
              }}</pre>
            </div>
          </el-collapse-item>
        </el-collapse>
        <AppPagination
          v-model:page="reconPage"
          v-model:page-size="reconPageSize"
          class="project-table-pagination"
          :total="filteredReconRows.length"
        />
      </el-tab-pane>
      <el-tab-pane label="检测任务" name="tasks">
        <div class="project-tab-toolbar">
          <span
            >本项目共 {{ projectTasks.length }} 个任务，{{
              pendingTasks.length
            }}
            个仍在排队或执行。</span
          >
          <el-button
            size="small"
            :loading="projectDataLoading"
            @click="loadProjectTasks"
            >刷新任务</el-button
          >
        </div>
        <el-alert
          title="任务在创建时会保存授权目标、端口、授权声明、工具版本及规则/模板哈希快照。"
          type="info"
          :closable="false"
          show-icon
        />
        <el-empty
          v-if="!projectTasks.length"
          description="本项目暂无检测任务"
        />
        <el-table
          v-else
          :data="pagedProjectTasks"
          stripe
          size="small"
          class="project-table"
        >
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column prop="toolCode" label="工具" min-width="140" />
          <el-table-column label="目标" min-width="150"
            ><template #default="scope">{{
              taskTargetName(scope.row.targetId)
            }}</template></el-table-column
          >
          <el-table-column label="状态" width="110"
            ><template #default="scope"
              ><el-tag size="small" :type="taskStatusType(scope.row.status)">{{
                taskStatusLabel(scope.row.status)
              }}</el-tag></template
            ></el-table-column
          >
          <el-table-column label="进度" min-width="220"
            ><template #default="scope"
              ><div class="live-task-progress">
                <el-progress
                  :percentage="taskProgressPercentage(scope.row)"
                  :stroke-width="7"
                  :status="taskProgressStatus(scope.row)"
                  :indeterminate="taskProgressIndeterminate(scope.row)"
                  :duration="1.2"
                  :show-text="false"
                /><span>{{ taskProgressText(scope.row) }}</span>
              </div></template
            ></el-table-column
          >
          <el-table-column label="创建时间" min-width="170"
            ><template #default="scope">{{
              formatDateTime(scope.row.createdAt)
            }}</template></el-table-column
          >
          <el-table-column label="操作" width="280">
            <template #default="scope">
              <el-button link type="primary" @click="showTaskDetail(scope.row)"
                >实时日志</el-button
              >
              <el-button
                v-if="
                  ['PENDING', 'QUEUED', 'RUNNING'].includes(scope.row.status)
                "
                link
                type="danger"
                :loading="taskCancelling === scope.row.id"
                @click="cancelProjectTask(scope.row)"
                >取消</el-button
              >
              <el-button
                v-if="
                  ['FAILED', 'TIMEOUT', 'REJECTED', 'CANCELLED'].includes(
                    scope.row.status,
                  )
                "
                link
                type="warning"
                :loading="taskRetrying === scope.row.id"
                @click="retryProjectTask(scope.row)"
                >重试</el-button
              >
              <el-button link @click="router.push('/tasks')"
                >任务中心</el-button
              >
            </template>
          </el-table-column>
        </el-table>
        <AppPagination
          v-model:page="taskPage"
          v-model:page-size="taskPageSize"
          class="project-table-pagination"
          :total="projectTasks.length"
        />
      </el-tab-pane>
      <el-tab-pane label="漏洞与复测" name="findings">
        <div class="project-tab-toolbar">
          <span
            >项目漏洞 {{ projectFindings.length }} 条 · 已复测
            {{ summary?.retestCount || 0 }} 条</span
          >
          <div class="toolbar-inline">
            <el-button size="small" @click="loadProjectReportSummary(true)"
              >刷新漏洞</el-button
            ><el-button
              size="small"
              type="warning"
              plain
              @click="openDiffDialog"
              >扫描 Diff</el-button
            ><el-button
              size="small"
              type="primary"
              plain
              @click="openProjectCopilot('findings')"
              ><el-icon><MagicStick /></el-icon>AI 汇总</el-button
            >
          </div>
        </div>
        <el-empty
          v-if="!projectFindings.length"
          description="本项目暂无漏洞发现"
        />
        <el-table
          v-else
          :data="pagedProjectFindings"
          stripe
          size="small"
          class="project-table"
        >
          <el-table-column prop="id" label="ID" width="70" />
          <el-table-column
            prop="title"
            label="漏洞"
            min-width="240"
            show-overflow-tooltip
          />
          <el-table-column label="等级" width="100"
            ><template #default="scope"
              ><el-tag
                size="small"
                :type="findingSeverityType(scope.row.severity)"
                >{{ scope.row.severity }}</el-tag
              ></template
            ></el-table-column
          >
          <el-table-column prop="sourceTool" label="来源" width="120" />
          <el-table-column label="状态" width="150"
            ><template #default="scope"
              ><el-select
                size="small"
                :model-value="scope.row.status"
                @change="updateProjectFindingStatus(scope.row, $event)"
                ><el-option label="待确认" value="OPEN" /><el-option
                  label="已确认"
                  value="CONFIRMED" /><el-option
                  label="误报"
                  value="FALSE_POSITIVE" /><el-option
                  label="已修复"
                  value="FIXED" /></el-select></template
          ></el-table-column>
          <el-table-column label="发现时间" min-width="170"
            ><template #default="scope">{{
              formatDateTime(scope.row.createdAt)
            }}</template></el-table-column
          >
          <el-table-column label="操作" width="180"
            ><template #default="scope"
              ><el-button
                link
                type="primary"
                @click="
                  findingDetail = scope.row;
                  findingDetailVisible = true;
                "
                >详情</el-button
              ><el-button
                link
                type="warning"
                :loading="findingRetesting === scope.row.id"
                @click="retestProjectFinding(scope.row)"
                >复测</el-button
              ></template
            ></el-table-column
          >
        </el-table>
        <AppPagination
          v-model:page="findingPage"
          v-model:page-size="findingPageSize"
          class="project-table-pagination"
          :total="projectFindings.length"
        />
      </el-tab-pane>
      <el-tab-pane label="安全行动" name="security-actions">
        <div class="project-tab-toolbar">
          <span
            >共 {{ securityActions.length }} 项 · 待审批
            {{ pendingSecurityActionCount }} 项 · 执行中
            {{ runningSecurityActionCount }} 项</span
          >
          <div class="toolbar-inline">
            <el-button
              size="small"
              :loading="securityActionLoading"
              @click="loadSecurityActions(true)"
              >刷新状态</el-button
            >
            <el-button
              class="security-action-request-button"
              size="small"
              type="danger"
              :disabled="
                !canManageSecurityActions || !projectAuthorizationGuard.active
              "
              @click="openSecurityActionDialog"
              >申请高风险行动</el-button
            >
          </div>
        </div>
        <div class="security-action-guard-grid">
          <el-alert
            :title="projectAuthorizationGuard.text"
            :type="projectAuthorizationGuard.active ? 'success' : 'error'"
            :closable="false"
            show-icon
          />
          <el-alert
            title="受控边界：仅允许服务端白名单动作、非破坏性验证、最长 8 小时时间窗；禁止横向移动和任意命令。"
            type="warning"
            :closable="false"
            show-icon
          />
          <el-alert
            v-if="!canManageSecurityActions"
            title="当前账号可查看审批状态，但只有管理员可以申请、审批、开始、完成或回滚安全行动。"
            type="info"
            :closable="false"
            show-icon
          />
        </div>
        <el-empty
          v-if="!securityActionLoading && !securityActions.length"
          description="暂无高风险安全行动；单管理员模式需要二次确认，多账号模式需要不同账号审批后才能开始"
        />
        <el-table
          v-else
          v-loading="securityActionLoading"
          :data="pagedSecurityActions"
          stripe
          size="small"
          class="project-table security-action-table"
        >
          <el-table-column prop="id" label="ID" width="65" />
          <el-table-column
            label="安全行动"
            min-width="220"
            show-overflow-tooltip
          >
            <template #default="scope"
              ><strong>{{ scope.row.title }}</strong
              ><small>{{
                securityActionCategoryLabel(scope.row.category)
              }}</small></template
            >
          </el-table-column>
          <el-table-column label="授权目标" min-width="150"
            ><template #default="scope">{{
              taskTargetName(scope.row.targetId)
            }}</template></el-table-column
          >
          <el-table-column label="风险" width="90"
            ><template #default="scope"
              ><el-tag
                size="small"
                :type="securityActionRiskType(scope.row.riskLevel)"
                >{{ scope.row.riskLevel }}</el-tag
              ></template
            ></el-table-column
          >
          <el-table-column label="审批/执行状态" width="135"
            ><template #default="scope"
              ><el-tag
                size="small"
                :type="securityActionStatusType(scope.row.status)"
                >{{ securityActionStatusLabel(scope.row.status) }}</el-tag
              ></template
            ></el-table-column
          >
          <el-table-column label="批准时间窗" min-width="220">
            <template #default="scope"
              ><span class="security-action-window"
                >{{ formatDateTime(scope.row.windowStart) }}<br />至
                {{ formatDateTime(scope.row.windowEnd) }}</span
              ></template
            >
          </el-table-column>
          <el-table-column label="申请/审批" min-width="150"
            ><template #default="scope"
              ><span class="security-action-actors"
                >申请：{{ scope.row.requestedBy }}<br />审批：{{
                  scope.row.approvedBy || "待定"
                }}</span
              ></template
            ></el-table-column
          >
          <el-table-column label="操作" width="310" fixed="right">
            <template #default="scope">
              <el-button
                link
                type="primary"
                @click="
                  securityActionDetail = scope.row;
                  securityActionDetailVisible = true;
                "
                >详情</el-button
              >
              <template
                v-if="
                  canManageSecurityActions &&
                  scope.row.status === 'PENDING_APPROVAL'
                "
              >
                <el-button
                  link
                  type="success"
                  :loading="securityActionMutating === scope.row.id"
                  @click="decideSecurityAction(scope.row, 'APPROVED')"
                  >批准</el-button
                >
                <el-button
                  link
                  type="danger"
                  :loading="securityActionMutating === scope.row.id"
                  @click="decideSecurityAction(scope.row, 'REJECTED')"
                  >拒绝</el-button
                >
              </template>
              <el-button
                v-if="
                  canManageSecurityActions && scope.row.status === 'APPROVED'
                "
                link
                type="warning"
                :disabled="
                  !projectAuthorizationGuard.active ||
                  !securityActionWindowState(scope.row).allowed
                "
                :loading="securityActionMutating === scope.row.id"
                @click="startSecurityAction(scope.row)"
                >开始</el-button
              >
              <template
                v-if="
                  canManageSecurityActions && scope.row.status === 'RUNNING'
                "
              >
                <el-button
                  link
                  type="success"
                  @click="openSecurityActionOperation(scope.row, 'COMPLETE')"
                  >完成</el-button
                >
                <el-button
                  link
                  type="danger"
                  @click="openSecurityActionOperation(scope.row, 'ROLLBACK')"
                  >回滚</el-button
                >
              </template>
              <el-button
                v-else-if="
                  canManageSecurityActions &&
                  ['COMPLETED', 'FAILED'].includes(scope.row.status)
                "
                link
                type="danger"
                @click="openSecurityActionOperation(scope.row, 'ROLLBACK')"
                >回滚</el-button
              >
            </template>
          </el-table-column>
        </el-table>
        <AppPagination
          v-model:page="securityActionPage"
          v-model:page-size="securityActionPageSize"
          class="project-table-pagination"
          :total="securityActions.length"
        />
      </el-tab-pane>
      <el-tab-pane label="审批与审计" name="audits">
        <div class="project-tab-toolbar">
          <span
            >授权声明：{{ project?.authorizationStatement || "未填写" }}</span
          >
          <div class="toolbar-inline">
            <el-button size="small" @click="refreshProjectData"
              >刷新记录</el-button
            ><el-button size="small" type="primary" @click="openApprovalDialog"
              >申请审批</el-button
            >
          </div>
        </div>
        <el-alert
          v-if="project?.authorizationExpiresAt"
          :title="`授权有效期：${formatDateTime(project.authorizationValidFrom)} 至 ${formatDateTime(project.authorizationExpiresAt)}`"
          type="warning"
          :closable="false"
          show-icon
        />
        <h4 class="project-subtitle">
          审批记录（{{ projectApprovals.length }}）
        </h4>
        <el-empty v-if="!projectApprovals.length" description="暂无审批记录" />
        <el-table
          v-else
          :data="pagedProjectApprovals"
          stripe
          size="small"
          class="project-table"
        >
          <el-table-column prop="id" label="ID" width="65" /><el-table-column
            label="动作"
            width="120"
            ><template #default="scope">{{
              formatApprovalAction(scope.row.action)
            }}</template></el-table-column
          ><el-table-column label="状态" width="110"
            ><template #default="scope"
              ><el-tag
                size="small"
                :type="approvalStatusType(scope.row.status)"
                >{{ approvalStatusLabel(scope.row.status) }}</el-tag
              ></template
            ></el-table-column
          ><el-table-column
            prop="requestedBy"
            label="申请人"
            width="120"
          /><el-table-column
            prop="approvedBy"
            label="决定人"
            width="120"
          /><el-table-column
            prop="comment"
            label="备注"
            min-width="180"
            show-overflow-tooltip
          /><el-table-column
            prop="authorizationSnapshotHash"
            label="授权快照哈希"
            min-width="180"
            show-overflow-tooltip
          /><el-table-column label="申请时间" min-width="170"
            ><template #default="scope">{{
              formatDateTime(scope.row.createdAt)
            }}</template></el-table-column
          ><el-table-column label="操作" width="170"
            ><template #default="scope"
              ><template v-if="scope.row.status === 'PENDING'"
                ><el-button
                  link
                  type="success"
                  :loading="approvalDecision === scope.row.id"
                  @click="decideApproval(scope.row, 'APPROVED')"
                  >通过</el-button
                ><el-button
                  link
                  type="danger"
                  :loading="approvalDecision === scope.row.id"
                  @click="decideApproval(scope.row, 'REJECTED')"
                  >拒绝</el-button
                ></template
              ><span v-else class="muted-text">已决定</span></template
            ></el-table-column
          >
        </el-table>
        <AppPagination
          v-model:page="approvalPage"
          v-model:page-size="approvalPageSize"
          class="project-table-pagination"
          :total="projectApprovals.length"
        />
        <h4 class="project-subtitle">操作审计（{{ projectAuditTotal }}）</h4>
        <el-empty
          v-if="auditLoading || !projectAudits.length"
          :description="
            auditLoading ? '正在加载审计记录…' : '暂无匹配的项目审计记录'
          "
        />
        <el-table
          v-else
          :data="projectAudits"
          stripe
          size="small"
          class="project-table"
          ><el-table-column
            prop="action"
            label="操作"
            min-width="160"
            show-overflow-tooltip
          >
            <template #default="scope">
              <strong>{{ formatAuditAction(scope.row.action) }}</strong>
            </template>
          </el-table-column
          ><el-table-column
            prop="resourceType"
            label="资源"
            width="120"
          >
            <template #default="scope">
              {{ formatAuditResource(scope.row.resourceType) }}
            </template>
          </el-table-column
          ><el-table-column
            prop="result"
            label="结果"
            width="100"
          >
            <template #default="scope">
              <el-tag size="small" :type="auditResultTagType(scope.row.result)" effect="light">
                {{ formatAuditResult(scope.row.result) }}
              </el-tag>
            </template>
          </el-table-column
          ><el-table-column
            prop="operator"
            label="操作人"
            width="120"
          /><el-table-column label="授权快照哈希" min-width="180">
            <template #default="scope">
              <span
                :class="{
                  'muted-text': !scope.row.authorizationSnapshotHash,
                }"
                :title="auditSnapshotLabel(scope.row)"
              >
                {{ auditSnapshotLabel(scope.row) }}
              </span>
            </template>
          </el-table-column>
          <el-table-column
            label="详情"
            min-width="220"
            show-overflow-tooltip
            ><template #default="scope">{{
              formatAuditDetail(scope.row.detail)
            }}</template></el-table-column
          ><el-table-column label="时间" min-width="170"
            ><template #default="scope">{{
              formatDateTime(scope.row.createdAt)
            }}</template></el-table-column
          ></el-table
        >
        <AppPagination
          v-model:page="auditPage"
          v-model:page-size="auditPageSize"
          class="project-table-pagination"
          :total="projectAuditTotal"
          @current-change="loadProjectAudits"
          @size-change="
            auditPage = 1;
            loadProjectAudits();
          "
        />
      </el-tab-pane>
      <el-tab-pane label="AI 记忆" name="memory">
        <div class="project-tab-toolbar">
          <span
            >这些项目级对话摘要会被安全保存并按需查找，用于后续连续分析。</span
          >
          <div class="toolbar-inline">
            <el-button
              size="small"
              :loading="memoryLoading"
              @click="loadMemories"
              >刷新记忆</el-button
            >
            <el-button
              size="small"
              type="danger"
              plain
              :disabled="memoryLoading || !memoryRows.length"
              @click="clearMemories"
              >清空记忆</el-button
            >
          </div>
        </div>
        <el-empty
          v-if="!memoryLoading && !memoryRows.length"
          description="暂无项目级 AI 记忆"
        />
        <el-table
          v-else
          :data="pagedMemoryRows"
          stripe
          size="small"
          class="project-table"
          ><el-table-column
            prop="title"
            label="摘要"
            min-width="260"
            show-overflow-tooltip
          /><el-table-column label="来源" width="160"
            ><template #default="scope">{{
              memorySourceLabel(scope.row.source)
            }}</template></el-table-column
          ><el-table-column
            prop="chars"
            label="字符数"
            width="90"
          /><el-table-column label="创建时间" min-width="170"
            ><template #default="scope">{{
              formatDateTime(scope.row.createdAt)
            }}</template></el-table-column
          ><el-table-column label="操作" width="100"
            ><template #default="scope"
              ><el-button link type="danger" @click="deleteMemory(scope.row.id)"
                >删除</el-button
              ></template
            ></el-table-column
          ></el-table
        >
        <AppPagination
          v-model:page="memoryPage"
          v-model:page-size="memoryPageSize"
          class="project-table-pagination"
          :total="memoryRows.length"
        />
      </el-tab-pane>
      <el-tab-pane label="项目报告" name="report">
        <div class="project-tab-toolbar report-toolbar">
          <span
            >项目总结报告聚合本项目全部授权目标、任务、漏洞、复测、探测、审批和审计数据。</span
          >
          <div class="toolbar-inline">
            <el-button size="small" @click="loadProjectReportSummary(true)"
              >刷新摘要</el-button
            >
            <el-button
              size="small"
              :loading="projectReportHtmlLoading"
              @click="openProjectSummaryHtml"
              >项目 HTML</el-button
            >
            <el-button
              size="small"
              type="primary"
              :loading="projectReportPdfLoading"
              @click="downloadProjectSummaryPdf"
              >项目 PDF</el-button
            >
          </div>
        </div>
        <div class="target-report-toolbar">
          <div>
            <strong>单目标附录</strong>
            <span
              >默认查看全部目标；选择单个目标后可导出该目标的任务与漏洞附录。</span
            >
          </div>
          <div class="toolbar-inline">
            <el-select
              v-model="reportTargetId"
              size="small"
              aria-label="报告目标范围"
              style="width: 260px"
            >
              <el-option label="全部目标" value="ALL" />
              <el-option
                v-for="target in linkedTargets"
                :key="target.id"
                :label="`${target.name} · ${target.targetValue}`"
                :value="target.id"
              />
            </el-select>
            <el-button
              size="small"
              :disabled="!reportTarget"
              :loading="targetReportHtmlLoading"
              @click="openTargetHtmlReport"
              >目标 HTML</el-button
            >
            <el-button
              size="small"
              :disabled="!reportTarget"
              :loading="targetReportPdfLoading"
              @click="downloadTargetPdfReport"
              >目标 PDF</el-button
            >
          </div>
        </div>
        <el-skeleton
          v-if="reportSummaryLoading && !reportSummary"
          :rows="5"
          animated
        />
        <template v-else-if="reportSummary">
          <div class="report-cards" aria-label="项目报告指标">
            <button
              type="button"
              class="report-card report-card--link"
              @click="openReportMetric('tasks')"
            >
              <strong>{{ reportSummary.vulnerabilityDiscovery.length }}</strong>
              <span>任务总数</span>
            </button>
            <button
              type="button"
              class="report-card report-card--link"
              @click="openReportMetric('findings')"
            >
              <strong>{{ reportVulnerabilityCount }}</strong>
              <span>漏洞发现</span>
            </button>
            <button
              type="button"
              class="report-card report-card--link"
              @click="openReportMetric('findings')"
            >
              <strong>{{ reportInformationalCount }}</strong>
              <span>风险点</span>
            </button>
            <button
              type="button"
              class="report-card report-card--link"
              @click="openReportMetric('findings')"
            >
              <strong>{{
                reportSummary.verification?.retestedFindings || 0
              }}</strong>
              <span>已复测</span>
            </button>
            <button
              type="button"
              class="report-card report-card--link"
              @click="openReportMetric('audits')"
            >
              <strong>{{
                reportSummary.approvalAndAudit?.totalApprovals ||
                reportSummary.approvals.length
              }}</strong>
              <span>审批/审计</span>
            </button>
          </div>
          <div class="report-severity" aria-label="漏洞等级分布">
            <button
              v-for="item in reportSeverityRows"
              :key="item.severity"
              type="button"
              class="report-severity-chip report-severity--link"
              @click="openReportMetric('findings', { severity: item.severity })"
            >
              <el-tag size="small" :type="findingSeverityType(item.severity)">{{
                item.severity
              }}</el-tag>
              <b>{{ item.count }}</b>
            </button>
          </div>
          <el-alert
            v-if="reportSummary.controlledPostExploitation"
            class="report-safety-alert"
            type="info"
            :closable="false"
            show-icon
            :title="reportSummary.controlledPostExploitation.safetyBoundary"
          />
          <div class="report-recent-head">
            <h4 class="project-subtitle">最近任务</h4>
            <div class="toolbar-inline">
              <el-select
                v-model="recentToolFilter"
                size="small"
                clearable
                placeholder="全部工具"
                style="width: 150px"
                ><el-option
                  v-for="code in projectToolOptions"
                  :key="code"
                  :label="code"
                  :value="code" /></el-select
              ><el-select
                v-model="recentStatusFilter"
                size="small"
                clearable
                placeholder="全部状态"
                style="width: 130px"
                ><el-option
                  v-for="s in [
                    'PENDING',
                    'RUNNING',
                    'SUCCESS',
                    'FAILED',
                    'TIMEOUT',
                    'CANCELLED',
                    'REJECTED',
                  ]"
                  :key="s"
                  :label="s"
                  :value="s"
              /></el-select>
            </div>
          </div>
          <el-table
            :data="filteredRecentTasks"
            size="small"
            stripe
            class="project-table"
            style="cursor: pointer"
            @row-click="showTaskDetail"
            ><el-table-column prop="id" label="ID" width="65" /><el-table-column
              prop="toolCode"
              label="工具"
              min-width="140"
            /><el-table-column
              prop="status"
              label="状态"
              width="110"
            /><el-table-column label="创建时间" min-width="170"
              ><template #default="scope">{{
                formatDateTime(scope.row.createdAt)
              }}</template></el-table-column
            ><el-table-column label="快照" min-width="220"
              ><template #default="scope"
                ><span class="snapshot-summary"
                  >{{ scope.row.toolVersionSnapshot || "工具版本未记录" }} ·
                  {{
                    scope.row.ruleVersionSnapshot ? "规则已固化" : "无规则哈希"
                  }}</span
                ></template
              ></el-table-column
            ></el-table
          >
        </template>
        <el-empty v-else description="暂无项目报告摘要" />
      </el-tab-pane>
    </el-tabs>

    <el-dialog
      v-model="reportPreviewVisible"
      :title="reportPreviewTitle"
      class="app-dialog app-dialog--xl report-preview-dialog"
      align-center
      destroy-on-close
      @closed="resetReportPreview"
    >
      <div class="report-preview-shell">
        <el-alert
          title="只读沙箱预览：脚本、表单、弹窗、外链和网络资源均已禁用。"
          type="info"
          :closable="false"
          show-icon
        />
        <iframe
          v-if="reportPreviewHtml"
          class="report-preview-frame"
          :title="`${reportPreviewTitle}只读预览`"
          :srcdoc="reportPreviewHtml"
          sandbox=""
          referrerpolicy="no-referrer"
        />
      </div>
      <template #footer
        ><el-button @click="reportPreviewVisible = false"
          >关闭预览</el-button
        ></template
      >
    </el-dialog>

    <el-dialog
      v-model="taskDetailVisible"
      title="项目任务实时日志"
      class="app-dialog app-dialog--lg"
      align-center
      destroy-on-close
    >
      <el-descriptions v-if="taskDetail" :column="2" border>
        <el-descriptions-item label="任务 ID">{{
          taskDetail.id
        }}</el-descriptions-item
        ><el-descriptions-item label="工具">{{
          taskDetail.toolCode
        }}</el-descriptions-item>
        <el-descriptions-item label="目标">{{
          taskTargetName(taskDetail.targetId)
        }}</el-descriptions-item
        ><el-descriptions-item label="状态"
          ><el-tag size="small" :type="taskStatusType(taskDetail.status)">{{
            taskStatusLabel(taskDetail.status)
          }}</el-tag></el-descriptions-item
        >
        <el-descriptions-item label="进度"
          ><div class="live-task-progress">
            <el-progress
              :percentage="taskProgressPercentage(taskDetail)"
              :stroke-width="7"
              :status="taskProgressStatus(taskDetail)"
              :indeterminate="taskProgressIndeterminate(taskDetail)"
              :duration="1.2"
              :show-text="false"
            /><span>{{ taskProgressText(taskDetail) }}</span>
          </div></el-descriptions-item
        ><el-descriptions-item label="终止原因">{{
          taskDetail.terminationReason || "未终止"
        }}</el-descriptions-item>
        <el-descriptions-item label="失败原因" :span="2">{{
          displayTaskError(taskDetail.errorMessage)
        }}</el-descriptions-item>
        <el-descriptions-item label="允许端口快照">{{
          taskDetail.allowedPortsSnapshot || "未记录"
        }}</el-descriptions-item
        ><el-descriptions-item label="快照时间">{{
          formatDateTime(taskDetail.snapshotCapturedAt)
        }}</el-descriptions-item>
        <el-descriptions-item label="授权声明快照" :span="2">{{
          taskDetail.authorizationStatementSnapshot || "未记录"
        }}</el-descriptions-item>
        <el-descriptions-item label="授权快照哈希" :span="2"
          ><code class="snapshot-hash">{{
            taskDetail.authorizationSnapshotHash || "未记录"
          }}</code></el-descriptions-item
        >
        <el-descriptions-item label="工具版本" :span="2">{{
          taskDetail.toolVersionSnapshot || "未记录"
        }}</el-descriptions-item>
        <el-descriptions-item label="规则/模板哈希" :span="2"
          ><code class="snapshot-hash"
            >规则：{{ taskDetail.ruleVersionSnapshot || "不适用"
            }}<br />Nuclei：{{
              taskDetail.nucleiTemplateHashSnapshot || "不适用"
            }}</code
          ></el-descriptions-item
        >
        <el-descriptions-item label="实时执行日志" :span="2">
          <pre class="project-live-log">{{ taskLogText(taskDetail) }}</pre>
        </el-descriptions-item>
      </el-descriptions>
      <el-alert
        v-if="taskDetailLoading"
        title="正在订阅任务 SSE 进度；关闭窗口不会取消任务。"
        type="info"
        :closable="false"
        show-icon
      />
      <template #footer>
        <el-button @click="taskDetailVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="findingDetailVisible"
      title="项目漏洞详情"
      class="app-dialog app-dialog--lg"
      align-center
      destroy-on-close
    >
      <el-descriptions v-if="findingDetail" :column="1" border
        ><el-descriptions-item label="名称">{{
          findingDetail.title
        }}</el-descriptions-item
        ><el-descriptions-item label="等级/状态"
          ><el-tag
            size="small"
            :type="findingSeverityType(findingDetail.severity)"
            >{{ findingDetail.severity }}</el-tag
          >
          <el-tag size="small">{{
            findingStatusLabel(findingDetail.status)
          }}</el-tag></el-descriptions-item
        ><el-descriptions-item label="说明">{{
          findingDetail.description || "未提供"
        }}</el-descriptions-item
        ><el-descriptions-item label="证据">
          <pre class="project-json-block">{{
            findingDetail.evidence || "未提供"
          }}</pre></el-descriptions-item
        ><el-descriptions-item label="修复建议">{{
          findingDetail.remediation || "未提供"
        }}</el-descriptions-item></el-descriptions
      >
      <template #footer>
        <el-button @click="findingDetailVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="diffVisible"
      title="项目扫描 Diff"
      class="app-dialog app-dialog--wide"
      align-center
      destroy-on-close
    >
      <el-form inline label-position="top" class="diff-form"
        ><el-form-item label="基线成功任务"
          ><el-select
            v-model="diffBaselineTaskId"
            placeholder="选择基线"
            filterable
            ><el-option
              v-for="task in successfulTasks"
              :key="`base-${task.id}`"
              :label="`#${task.id} · ${task.toolCode} · ${formatDateTime(task.createdAt)}`"
              :value="task.id" /></el-select></el-form-item
        ><el-form-item label="当前成功任务"
          ><el-select
            v-model="diffCurrentTaskId"
            placeholder="选择当前"
            filterable
            ><el-option
              v-for="task in successfulTasks"
              :key="`current-${task.id}`"
              :label="`#${task.id} · ${task.toolCode} · ${formatDateTime(task.createdAt)}`"
              :value="task.id" /></el-select></el-form-item
        ><el-form-item class="diff-compare-item"
          ><el-button type="primary" :loading="diffLoading" @click="loadDiff"
            >比较</el-button
          ></el-form-item
        ></el-form
      >
      <template v-if="diff">
        <el-alert
          :title="`新增 ${diff.summary.added} · 持续 ${diff.summary.persistent} · 已修复 ${diff.summary.resolved} · 等级变化 ${diff.summary.severityChanged}`"
          type="info"
          :closable="false"
          show-icon
        />
        <el-table
          :data="pagedDiffItems"
          size="small"
          max-height="380"
          class="project-table"
        >
          <el-table-column label="变化" width="120">
            <template #default="scope">
              <el-tag
                size="small"
                :type="diffChangeTagType(scope.row.changeType)"
                effect="plain"
              >
                {{ diffChangeLabel(scope.row.changeType) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="title" label="漏洞" min-width="240" />
          <el-table-column label="等级" width="160">
            <template #default="scope">
              {{ scope.row.previousSeverity || "-" }} →
              {{ scope.row.currentSeverity || "-" }}
            </template>
          </el-table-column>
          <el-table-column prop="ruleCode" label="规则" min-width="150" />
        </el-table>
        <AppPagination
          v-model:page="diffPage"
          v-model:page-size="diffPageSize"
          class="project-table-pagination"
          :total="diffItems.length"
        />
      </template>
      <el-empty v-else description="选择两个成功任务后比较扫描变化" />
      <template #footer>
        <el-button @click="diffVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="approvalDialog"
      title="申请项目审批"
      class="app-dialog app-dialog--md"
      align-center
      destroy-on-close
    >
      <el-form label-position="top"
        ><el-form-item label="审批动作"
          ><el-select v-model="approvalForm.action" style="width: 100%"
            ><el-option label="主动扫描" value="SCAN" /><el-option
              label="漏洞复测"
              value="RETEST" /><el-option
              label="后续验证"
              value="POST_SCAN" /><el-option
              label="其他安全操作"
              value="OTHER" /></el-select></el-form-item
        ><el-form-item label="说明"
          ><el-input
            v-model="approvalForm.comment"
            type="textarea"
            :rows="3"
            placeholder="说明申请目的、范围和停止条件" /></el-form-item
        ><el-form-item label="授权快照哈希"
          ><el-input
            v-model="approvalForm.authorizationSnapshotHash"
            placeholder="可从任务快照自动带入"
          /><small class="field-hint"
            >审批记录会保留该哈希，便于审计时核对当时授权边界。</small
          ></el-form-item
        ></el-form
      >
      <template #footer
        ><el-button @click="approvalDialog = false">取消</el-button
        ><el-button
          type="primary"
          :loading="approvalSaving"
          @click="requestApproval"
          >提交申请</el-button
        ></template
      >
    </el-dialog>

    <el-dialog
      v-model="securityActionDialog"
      title="申请高风险安全行动"
      class="app-dialog app-dialog--wide"
      align-center
      destroy-on-close
    >
      <el-alert
        title="这是项目级受控行动申请，不是命令执行器。只能选择服务端已登记的安全行动类型；单管理员模式由管理员二次确认，多账号模式必须由不同账号审批。"
        type="warning"
        :closable="false"
        show-icon
        class="security-action-dialog-alert"
      />
      <el-form label-position="top" class="security-action-form">
        <div class="project-form-row">
          <el-form-item label="授权目标" required>
            <el-select
              v-model="securityActionForm.targetId"
              filterable
              style="width: 100%"
              placeholder="选择项目内目标"
            >
              <el-option
                v-for="target in linkedTargets"
                :key="target.id"
                :label="`${target.name} · ${target.targetValue}`"
                :value="target.id"
              />
            </el-select>
          </el-form-item>
          <el-form-item label="关联漏洞（可选）">
            <el-select
              v-model="securityActionForm.findingId"
              clearable
              filterable
              style="width: 100%"
              placeholder="仅显示该目标的项目漏洞"
            >
              <el-option
                v-for="finding in securityActionFindings"
                :key="finding.id"
                :label="`#${finding.id} · ${finding.title}`"
                :value="finding.id"
              />
            </el-select>
          </el-form-item>
        </div>
        <el-form-item label="安全行动类型" required>
          <el-select v-model="securityActionForm.category" style="width: 100%">
            <el-option
              v-for="preset in SECURITY_ACTION_PRESETS"
              :key="preset.category"
              :label="`${preset.label}（${preset.riskLevel}）`"
              :value="preset.category"
            />
          </el-select>
          <small class="field-hint">{{
            selectedSecurityActionPreset.description
          }}</small>
        </el-form-item>
        <el-form-item label="验证目的" required
          ><el-input
            v-model="securityActionForm.purpose"
            maxlength="1000"
            show-word-limit
            type="textarea"
            :rows="3"
            placeholder="说明目标、预期证据和明确停止条件；不要填写口令、令牌或私钥"
        /></el-form-item>
        <div class="security-action-plan-grid">
          <el-form-item label="风险等级"
            ><el-tag
              size="large"
              :type="
                securityActionRiskType(selectedSecurityActionPreset.riskLevel)
              "
              >{{ selectedSecurityActionPreset.riskLevel }}</el-tag
            ></el-form-item
          >
          <el-form-item label="安全属性"
            ><div class="security-action-flags">
              <el-tag type="success" effect="plain">非破坏性</el-tag
              ><el-tag type="success" effect="plain">禁止横向移动</el-tag>
            </div></el-form-item
          >
        </div>
        <el-form-item label="服务端执行计划（只读）"
          ><el-input
            :model-value="selectedSecurityActionPreset.executionPlan"
            type="textarea"
            :rows="3"
            readonly
        /></el-form-item>
        <el-form-item label="服务端回滚计划（只读）"
          ><el-input
            :model-value="selectedSecurityActionPreset.rollbackPlan"
            type="textarea"
            :rows="3"
            readonly
        /></el-form-item>
        <div class="project-form-row">
          <el-form-item label="批准开始时间" required
            ><el-date-picker
              v-model="securityActionForm.windowStart"
              type="datetime"
              style="width: 100%"
              placeholder="选择开始时间"
          /></el-form-item>
          <el-form-item label="批准结束时间" required
            ><el-date-picker
              v-model="securityActionForm.windowEnd"
              type="datetime"
              style="width: 100%"
              placeholder="选择结束时间"
          /></el-form-item>
        </div>
        <el-checkbox v-model="securityActionForm.acknowledged"
          >我确认目标属于本项目授权范围，执行时间窗在授权有效期内，并已阅读停止与回滚条件。</el-checkbox
        >
      </el-form>
      <template #footer
        ><el-button @click="securityActionDialog = false">取消</el-button
        ><el-button
          type="danger"
          :loading="securityActionSaving"
          :disabled="!projectAuthorizationGuard.active"
          @click="createSecurityAction"
          >提交审批申请</el-button
        ></template
      >
    </el-dialog>

    <el-dialog
      v-model="securityActionDetailVisible"
      title="安全行动详情与审批状态"
      class="app-dialog app-dialog--lg"
      align-center
      destroy-on-close
    >
      <el-descriptions v-if="securityActionDetail" :column="2" border>
        <el-descriptions-item label="行动 ID">{{
          securityActionDetail.id
        }}</el-descriptions-item>
        <el-descriptions-item label="状态"
          ><el-tag
            size="small"
            :type="securityActionStatusType(securityActionDetail.status)"
            >{{
              securityActionStatusLabel(securityActionDetail.status)
            }}</el-tag
          ></el-descriptions-item
        >
        <el-descriptions-item label="行动类型">{{
          securityActionCategoryLabel(securityActionDetail.category)
        }}</el-descriptions-item>
        <el-descriptions-item label="风险等级"
          ><el-tag
            size="small"
            :type="securityActionRiskType(securityActionDetail.riskLevel)"
            >{{ securityActionDetail.riskLevel }}</el-tag
          ></el-descriptions-item
        >
        <el-descriptions-item label="授权目标">{{
          taskTargetName(securityActionDetail.targetId)
        }}</el-descriptions-item>
        <el-descriptions-item label="关联漏洞">{{
          securityActionDetail.findingId
            ? `#${securityActionDetail.findingId}`
            : "无"
        }}</el-descriptions-item>
        <el-descriptions-item label="申请人">{{
          securityActionDetail.requestedBy
        }}</el-descriptions-item>
        <el-descriptions-item label="审批人">{{
          securityActionDetail.approvedBy || "待审批"
        }}</el-descriptions-item>
        <el-descriptions-item label="批准时间窗" :span="2"
          >{{ formatDateTime(securityActionDetail.windowStart) }} 至
          {{
            formatDateTime(securityActionDetail.windowEnd)
          }}</el-descriptions-item
        >
        <el-descriptions-item label="验证目的" :span="2">{{
          securityActionDetail.purpose
        }}</el-descriptions-item>
        <el-descriptions-item label="执行计划" :span="2">
          <pre class="security-action-plan-block">{{
            securityActionDetail.executionPlan
          }}</pre>
        </el-descriptions-item>
        <el-descriptions-item label="回滚计划" :span="2">
          <pre class="security-action-plan-block">{{
            securityActionDetail.rollbackPlan
          }}</pre>
        </el-descriptions-item>
        <el-descriptions-item label="终止原因" :span="2">{{
          securityActionDetail.terminationReason || "未记录"
        }}</el-descriptions-item>
        <el-descriptions-item label="执行证据" :span="2">
          <pre class="security-action-plan-block">{{
            securityActionDetail.evidence || "未记录"
          }}</pre>
        </el-descriptions-item>
        <el-descriptions-item label="回滚证据" :span="2">
          <pre class="security-action-plan-block">{{
            securityActionDetail.rollbackEvidence || "未记录"
          }}</pre>
        </el-descriptions-item>
      </el-descriptions>
      <template #footer>
        <el-button @click="securityActionDetailVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="securityActionOperationDialog"
      :title="
        securityActionOperation === 'COMPLETE'
          ? '登记安全行动完成'
          : '登记安全行动回滚'
      "
      class="app-dialog app-dialog--md"
      align-center
      destroy-on-close
    >
      <el-alert
        title="证据只填写可审计的摘要，不要保存明文凭据、令牌、私钥或用户 Hash；服务端会再次拦截敏感内容。"
        type="warning"
        :closable="false"
        show-icon
      />
      <el-form label-position="top" class="security-action-form">
        <el-form-item label="结果证据摘要" required
          ><el-input
            v-model="securityActionOperationForm.evidence"
            maxlength="4000"
            show-word-limit
            type="textarea"
            :rows="5"
            placeholder="例如：验证结果、时间、影响范围和复核结论"
        /></el-form-item>
        <el-form-item
          :label="
            securityActionOperation === 'COMPLETE'
              ? '终止原因（可选）'
              : '回滚原因（必填）'
          "
          ><el-input
            v-model="securityActionOperationForm.reason"
            maxlength="1000"
            show-word-limit
            type="textarea"
            :rows="3"
            placeholder="填写停止、失败或回滚的原因"
        /></el-form-item>
      </el-form>
      <template #footer
        ><el-button @click="securityActionOperationDialog = false"
          >取消</el-button
        ><el-button
          :type="securityActionOperation === 'COMPLETE' ? 'success' : 'danger'"
          :loading="securityActionOperationSaving"
          @click="submitSecurityActionOperation"
          >{{
            securityActionOperation === "COMPLETE" ? "确认完成" : "确认回滚"
          }}</el-button
        ></template
      >
    </el-dialog>
  </section>
</template>

<style scoped>
.project-form-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 14px;
}
.project-target-create-form :deep(.el-form-item) {
  margin-bottom: 16px;
}
.project-target-create-form :deep(.el-form-item__label) {
  padding-bottom: 6px;
  color: var(--app-text);
  font-size: 12px;
  font-weight: 600;
}
.project-target-create-form :deep(.el-input__wrapper),
.project-target-create-form :deep(.el-textarea__inner),
.project-target-create-form :deep(.el-select__wrapper) {
  border-radius: 5px;
}
.project-target-create-form :deep(.el-textarea__inner) {
  line-height: 1.55;
}
@media (max-width: 600px) {
  .port-picker {
    gap: 10px;
  }
}
.port-picker {
  display: grid;
  width: 100%;
  gap: 10px;
}
.port-picker :deep(.el-select) {
  width: 100%;
}
.full-port-option {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 10px 12px;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-soft);
}
.full-port-option div {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 4px;
}
.full-port-option b {
  color: var(--app-text);
  font-size: 13px;
}
.full-port-option small {
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.55;
}
.port-hint {
  margin: 0 2px;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.55;
}
@media (max-width: 600px) {
  .project-form-row {
    grid-template-columns: 1fr;
  }
}
.json-view {
  max-height: 180px;
  overflow: auto;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font:
    11px/1.45 Consolas,
    monospace;
}
.workflow-box {
  margin: 14px 0;
  padding: 14px;
  border: 1px solid var(--el-border-color);
  border-radius: 8px;
  background: var(--el-fill-color-light);
}
.workflow-head {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}
.workflow-head span {
  color: var(--el-color-primary);
}
.workflow-log {
  max-height: 240px;
  overflow: auto;
  margin: 10px 0 0;
  padding: 10px;
  border-radius: 6px;
  background: #111827;
  color: #d1fae5;
  white-space: pre-wrap;
  font:
    12px/1.5 Consolas,
    monospace;
}
.recon-alert {
  margin: 0 0 16px;
}
.recon-controls {
  display: flex;
  flex-direction: column;
  gap: 14px;
  margin: 0 0 6px;
  padding: 14px 16px;
  border: 1px solid var(--app-border, var(--el-border-color));
  border-radius: 10px;
  background: var(--app-surface-soft, var(--el-fill-color-blank));
}
.recon-controls-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px 14px;
}
.recon-controls-row--primary {
  padding-bottom: 2px;
}
.recon-controls-row--options {
  padding: 2px 0 4px;
  border-top: 1px dashed
    color-mix(
      in srgb,
      var(--app-border, var(--el-border-color)) 80%,
      transparent
    );
  border-bottom: 1px dashed
    color-mix(
      in srgb,
      var(--app-border, var(--el-border-color)) 80%,
      transparent
    );
}
.recon-controls-row--actions {
  padding-top: 2px;
}
.recon-controls .el-select {
  width: min(320px, 100%);
}
.recon-filter-input {
  width: min(240px, 100%);
}
.recon-controls :deep(.el-radio-group),
.recon-controls :deep(.el-checkbox),
.recon-controls :deep(.el-button) {
  margin: 0 !important;
}
.recon-controls :deep(.el-checkbox) {
  margin-right: 2px !important;
  height: auto;
}
.mode-hint {
  margin: 14px 0 18px;
  color: var(--el-text-color-secondary);
  font-size: 12px;
  line-height: 1.65;
}
.result-title {
  display: flex;
  align-items: center;
  gap: 10px;
}
.result-title span {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.recon-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 12px;
}
.recon-card {
  min-height: 120px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 8px;
  padding: 12px;
  background: var(--el-fill-color-blank);
}
.recon-card header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
  font-weight: 600;
}
.card-list {
  max-height: 220px;
  overflow: auto;
}
.card-list pre {
  margin: 0 0 6px;
  padding: 7px;
  border-radius: 5px;
  background: var(--el-fill-color-light);
  white-space: pre-wrap;
  word-break: break-word;
  font:
    12px/1.4 Consolas,
    monospace;
}
.empty-text {
  color: var(--el-text-color-placeholder);
  font-size: 12px;
}
.evidence-block {
  margin-top: 14px;
}
.evidence-block h4 {
  margin: 0 0 8px;
}
.evidence-json {
  padding: 10px;
  border-radius: 6px;
  background: var(--el-fill-color-light);
}
.project-tab-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  margin-bottom: 12px;
  color: var(--app-muted, var(--el-text-color-secondary));
  font-size: 12px;
}
.project-tab-toolbar > span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.toolbar-inline {
  display: flex;
  flex: none;
  align-items: center;
  gap: 8px;
}
.project-table {
  margin-top: 12px;
}
.project-subtitle {
  margin: 20px 0 8px;
  color: var(--app-text, var(--el-text-color-primary));
  font-size: 13px;
}
.muted-text,
.field-hint,
.snapshot-summary {
  color: var(--app-muted, var(--el-text-color-secondary));
  font-size: 11px;
}
.field-hint {
  display: block;
  margin-top: 6px;
  line-height: 1.5;
}
.project-live-log,
.project-json-block {
  max-height: 360px;
  overflow: auto;
  margin: 0;
  padding: 12px;
  border-radius: 6px;
  background: #111827;
  color: #d1fae5;
  white-space: pre-wrap;
  word-break: break-word;
  font:
    12px/1.55 Consolas,
    "Cascadia Mono",
    monospace;
}
.project-json-block {
  max-height: 280px;
}
.target-report-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin: 10px 0 14px;
  padding: 12px 14px;
  border: 1px solid var(--app-border, var(--el-border-color));
  border-radius: 10px;
  background: var(--app-surface-soft, var(--el-fill-color-light));
}
.target-report-toolbar > div:first-child {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 3px;
}
.target-report-toolbar strong {
  color: var(--app-text, var(--el-text-color-primary));
  font-size: 13px;
}
.target-report-toolbar span {
  color: var(--app-muted, var(--el-text-color-secondary));
  font-size: 11px;
  line-height: 1.5;
}
.report-cards {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin: 14px 0;
}
.report-cards > div {
  display: flex;
  min-height: 84px;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--app-border, var(--el-border-color));
  border-radius: 8px;
  background: var(--app-surface-soft, var(--el-fill-color-light));
}
.report-cards strong {
  color: var(--app-text, var(--el-text-color-primary));
  font-size: 26px;
}
.report-cards span {
  margin-top: 4px;
  color: var(--app-muted, var(--el-text-color-secondary));
  font-size: 11px;
}
.report-severity {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 14px;
}
.report-severity > span {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 8px;
  border: 1px solid var(--app-border, var(--el-border-color));
  border-radius: 6px;
  background: var(--app-surface, var(--el-bg-color));
}
.report-severity b {
  font-size: 12px;
}
.report-safety-alert {
  margin: 12px 0 18px;
}
.report-recent-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
}
.report-recent-head .project-subtitle {
  margin: 0;
}
.report-safety-alert + .report-recent-head {
  margin-top: 16px;
}
.diff-form {
  display: flex;
  align-items: flex-end;
  flex-wrap: wrap;
  gap: 16px;
}
.app-dialog .diff-form :deep(.el-form-item) {
  margin-right: 0;
  margin-bottom: 0;
}
.diff-form :deep(.el-select) {
  width: 290px;
}
.diff-compare-item {
  align-self: flex-end;
}
@media (max-width: 900px) {
  .project-tab-toolbar,
  .target-report-toolbar {
    align-items: flex-start;
    flex-direction: column;
  }
  .project-tab-toolbar > span {
    white-space: normal;
  }
  .toolbar-inline {
    width: 100%;
    flex-wrap: wrap;
  }
  .target-report-toolbar .toolbar-inline :deep(.el-select) {
    width: 100% !important;
  }
  .report-cards {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .diff-form {
    align-items: stretch;
    flex-direction: column;
  }
  .diff-form :deep(.el-select) {
    width: 100%;
  }
}
.report-preview-shell {
  display: flex;
  height: min(74vh, 820px);
  min-height: 460px;
  flex-direction: column;
  gap: 10px;
}
.report-preview-frame {
  width: 100%;
  min-height: 0;
  flex: 1;
  border: 1px solid var(--app-border, var(--el-border-color));
  border-radius: 10px;
  background: #fff;
}
@media (max-width: 760px) {
  .report-preview-shell {
    height: 72vh;
    min-height: 380px;
  }
}
.subdomain-dictionary {
  width: min(280px, 100%);
}
.icp-table {
  margin: 10px 0 14px;
}
@media (max-width: 760px) {
  .subdomain-dictionary {
    width: 100%;
  }
}
.fingerprint-catalog-panel {
  display: block;
  margin: 0 0 14px;
  overflow: hidden;
  border: 1px solid var(--app-border, var(--el-border-color));
  border-radius: 10px;
  background: var(--app-surface-soft, var(--el-fill-color-light));
}
.fingerprint-catalog-heading {
  display: flex;
  min-height: 52px;
  box-sizing: border-box;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 9px 14px;
}
.fingerprint-catalog-toggle {
  display: flex;
  min-width: 0;
  flex: 1 1 auto;
  align-items: center;
  gap: 9px;
  padding: 0;
  border: 0;
  outline: 0;
  background: transparent;
  color: inherit;
  cursor: pointer;
  font: inherit;
  text-align: left;
}
.fingerprint-catalog-toggle:focus-visible {
  border-radius: var(--fluent-radius-control, 4px);
  box-shadow: 0 0 0 2px var(--app-accent-soft);
}
.fingerprint-catalog-chevron {
  flex: 0 0 auto;
  color: var(--app-muted, var(--el-text-color-secondary));
  transition: transform var(--fluent-collapse-motion);
}
.fingerprint-catalog-panel.collapsed .fingerprint-catalog-chevron {
  transform: rotate(-90deg);
}
.fingerprint-catalog-heading-copy {
  display: flex;
  min-width: 0;
  flex-direction: column;
}
.fingerprint-catalog-heading-copy strong {
  overflow: hidden;
  color: var(--app-text, var(--el-text-color-primary));
  font-size: 13px;
  line-height: 1.4;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fingerprint-catalog-heading-copy > span {
  overflow: hidden;
  margin-top: 2px;
  color: var(--app-muted, var(--el-text-color-secondary));
  font-size: 11px;
  line-height: 1.4;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fingerprint-catalog-source-tag {
  display: inline-flex !important;
  flex: 0 0 auto;
  align-items: center;
  align-self: center;
  justify-content: center;
  margin: 0 !important;
  line-height: 1 !important;
}
.fingerprint-catalog-source-tag :deep(.el-tag__content) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin: 0;
  line-height: 1;
}
.fingerprint-catalog-details {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 14px 20px;
  padding: 12px 16px 14px;
  border-top: 1px solid var(--app-border, var(--el-border-color));
}
.fingerprint-catalog-content {
  min-width: 0;
}
.fingerprint-catalog-meta {
  display: grid;
  grid-template-columns: minmax(150px, 1fr) minmax(110px, 0.7fr);
  gap: 8px 18px;
}
.fingerprint-catalog-meta > div {
  min-width: 0;
}
.fingerprint-catalog-meta small,
.fingerprint-catalog-meta strong,
.fingerprint-catalog-meta code {
  display: block;
}
.fingerprint-catalog-meta small,
.fingerprint-catalog-update small {
  margin-bottom: 3px;
  color: var(--app-muted, var(--el-text-color-secondary));
  font-size: 10px;
}
.fingerprint-catalog-meta strong {
  overflow: hidden;
  color: var(--app-text, var(--el-text-color-primary));
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fingerprint-catalog-sha {
  grid-column: 1 / -1;
}
.fingerprint-catalog-meta code,
.fingerprint-catalog-update-result code {
  color: var(--app-muted, var(--el-text-color-secondary));
  font-size: 10px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}
.fingerprint-catalog-actions {
  display: flex;
  align-items: flex-start;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 8px;
}
.fingerprint-catalog-actions :deep(.el-button) {
  margin: 0 !important;
}
.fingerprint-catalog-file-input {
  display: none;
}
.fingerprint-catalog-update {
  display: grid;
  grid-column: 1 / -1;
  grid-template-columns: minmax(180px, 0.55fr) minmax(260px, 1.45fr);
  gap: 12px 20px;
  padding-top: 12px;
  border-top: 1px solid
    color-mix(
      in srgb,
      var(--app-border, var(--el-border-color)) 82%,
      transparent
    );
}
.fingerprint-catalog-update-file,
.fingerprint-catalog-update-result {
  min-width: 0;
}
.fingerprint-catalog-update-file small,
.fingerprint-catalog-update-file strong,
.fingerprint-catalog-update-file span {
  display: block;
}
.fingerprint-catalog-update-file strong {
  overflow: hidden;
  color: var(--app-text, var(--el-text-color-primary));
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fingerprint-catalog-update-file span {
  margin-top: 3px;
  color: var(--app-muted, var(--el-text-color-secondary));
  font-size: 10px;
}
.fingerprint-catalog-update-result {
  display: flex;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 6px 8px;
  color: var(--app-text, var(--el-text-color-primary));
  font-size: 11px;
  line-height: 1.5;
}
.fingerprint-catalog-update-result code {
  flex-basis: 100%;
}
.fingerprint-catalog-update.is-error .fingerprint-catalog-update-result span {
  color: var(--el-color-danger);
}
@media (max-width: 900px) {
  .fingerprint-catalog-details {
    grid-template-columns: 1fr;
  }
  .fingerprint-catalog-actions {
    justify-content: flex-start;
  }
}
@media (max-width: 600px) {
  .fingerprint-catalog-meta,
  .fingerprint-catalog-update {
    grid-template-columns: 1fr;
  }
  .fingerprint-catalog-sha {
    grid-column: auto;
  }
  .fingerprint-catalog-actions :deep(.el-button) {
    flex: 1 1 150px;
  }
}
.fingerprint-cell {
  min-width: 0;
  line-height: 1.5;
}
.fingerprint-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}
.poc-recommendation-context {
  display: grid;
  grid-template-columns: minmax(180px, 0.7fr) minmax(260px, 1.3fr);
  gap: 12px;
  margin-bottom: 12px;
  padding: 12px;
  border: 1px solid var(--app-border, var(--el-border-color));
  border-radius: 8px;
  background: var(--app-surface-soft, var(--el-fill-color-light));
}
.poc-recommendation-context > div {
  min-width: 0;
}
.poc-recommendation-context small {
  display: block;
  margin-bottom: 5px;
  color: var(--app-muted, var(--el-text-color-secondary));
  font-size: 11px;
}
.poc-recommendation-context strong {
  display: block;
  overflow: hidden;
  color: var(--app-text, var(--el-text-color-primary));
  text-overflow: ellipsis;
  white-space: nowrap;
}
.poc-safety-alert {
  margin-bottom: 12px;
}
.poc-recommendation-table code {
  font-size: 11px;
  word-break: break-all;
}
@media (max-width: 760px) {
  .poc-recommendation-context {
    grid-template-columns: 1fr;
  }
  .poc-recommendation-table :deep(.el-table__cell) {
    padding: 7px 0;
  }
}
.security-action-guard-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 8px;
  margin: 12px 0;
}
.security-action-table :deep(.el-table__cell) {
  vertical-align: top;
}
.security-action-table strong,
.security-action-table small {
  display: block;
}
.security-action-table small {
  margin-top: 4px;
  color: var(--app-muted, var(--el-text-color-secondary));
  font-size: 11px;
}
.security-action-window,
.security-action-actors {
  font-size: 11px;
  line-height: 1.55;
}
.security-action-flags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding-top: 4px;
}
.security-action-plan-grid {
  display: grid;
  grid-template-columns: 150px 1fr;
  gap: 12px;
}
.security-action-plan-block {
  max-height: 180px;
  overflow: auto;
  margin: 0;
  padding: 10px;
  border-radius: 6px;
  background: var(--app-surface-soft, var(--el-fill-color-light));
  color: var(--app-text, var(--el-text-color-primary));
  white-space: pre-wrap;
  word-break: break-word;
  font:
    12px/1.55 Consolas,
    "Cascadia Mono",
    monospace;
}
.security-action-dialog-alert {
  margin-bottom: 14px;
}
.security-action-form :deep(.el-form-item) {
  margin-bottom: 14px;
}
@media (max-width: 760px) {
  .security-action-plan-grid {
    grid-template-columns: 1fr;
  }
  .security-action-table :deep(.el-table__cell) {
    padding: 7px 0;
  }
}
.security-action-request-button:not(.is-disabled) {
  border-color: var(--fluent-danger-bg) !important;
  background: var(--fluent-danger-bg) !important;
  color: #fff !important;
}
.security-action-request-button:not(.is-disabled):hover,
.security-action-request-button:not(.is-disabled):focus {
  border-color: var(--fluent-danger-hover-bg) !important;
  background: var(--fluent-danger-hover-bg) !important;
  color: #fff !important;
}
.security-action-request-button.is-disabled {
  border-color: var(--fluent-disabled-border) !important;
  background: var(--fluent-disabled-bg) !important;
  color: var(--fluent-disabled-fg) !important;
}
.security-action-request-button :deep(span) {
  color: inherit !important;
}

/* Keep project workbenches readable through rhythm instead of nested surfaces. */
.project-detail-page {
  display: flex;
  flex-direction: column;
  min-height: 100% !important;
  height: 100% !important;
  overflow: hidden !important;
}
.project-tabs {
  display: flex;
  flex: 1;
  min-height: 0;
  flex-direction: column;
}
.project-tabs :deep(.el-tabs__header) {
  flex: none;
  margin-bottom: 12px;
}
.project-tabs :deep(.el-tabs__content) {
  flex: 1;
  min-height: 0;
  overflow: auto !important;
  scrollbar-gutter: stable;
}
.project-tabs :deep(.el-tab-pane) {
  min-height: 100%;
  padding: 8px 0 28px;
}
.project-tabs .toolbar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  margin: 0 0 20px;
}
.project-tabs .toolbar :deep(.el-select) {
  width: min(420px, 100%);
  flex: 0 1 420px;
}
.project-tabs .toolbar :deep(.el-button) {
  flex: none;
  margin: 0 !important;
}
.project-tabs :deep(.el-table th.el-table__cell) {
  height: 48px;
  padding: 0;
  font-size: 13px;
  font-weight: 600;
}
.project-tabs :deep(.el-table td.el-table__cell) {
  padding: 12px 0;
  font-size: 13px;
}
.project-tabs :deep(.el-table .cell) {
  padding-inline: 16px;
  line-height: 1.55;
}
.project-tabs .project-tab-toolbar {
  gap: 18px;
  margin-bottom: 18px;
  font-size: 13px;
}
.project-tabs .toolbar-inline {
  gap: 10px;
}
.project-tabs .project-table {
  margin-top: 18px;
}
.project-table-pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}
.project-tabs .project-subtitle {
  margin: 24px 0 12px;
  font-size: 14px;
}
.project-tabs .report-recent-head .project-subtitle {
  margin: 0;
}
.project-tabs .recon-alert {
  display: inline-flex;
  width: auto;
  max-width: 100%;
  margin: 0 0 16px !important;
}
.project-tabs .recon-controls {
  gap: 16px;
  margin-top: 4px;
  margin-bottom: 12px;
  padding: 16px 18px;
}
.project-tabs .recon-controls-row {
  gap: 14px 16px;
}
.project-tabs .mode-hint {
  margin: 16px 0 22px;
}
.project-tabs .recon-grid {
  gap: 16px;
}
.project-tabs .recon-results :deep(.el-collapse-item__header) {
  padding: 0 18px;
}
.project-tabs .recon-results :deep(.el-collapse-item__content) {
  padding: 18px;
}
.project-tabs .security-action-guard-grid {
  gap: 12px;
  margin: 18px 0 20px;
}
.target-mode-nav {
  margin-bottom: 18px;
}
.target-mode-segmented {
  width: 100%;
}
.target-mode-segmented :deep(.el-segmented) {
  width: 100%;
}
.target-mode-segmented :deep(.el-segmented__item) {
  min-height: 32px;
  font-weight: 600;
}
.target-mode-segmented :deep(.el-segmented__item-selected) {
  box-sizing: border-box;
  width: 50% !important;
  transform: translateX(0) translateZ(0) !important;
  transition: transform var(--fluent-duration-normal, 200ms)
    var(--fluent-curve-standard, ease);
}
.target-mode-segmented :deep(.el-segmented__group):has(
    .el-segmented__item.is-selected:last-child
  )
  .el-segmented__item-selected {
  transform: translateX(100%) translateZ(0) !important;
}
.batch-preview-card {
  margin: -4px 0 16px;
  padding: 12px 14px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-soft);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.batch-preview-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.preview-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--app-text);
}
.preview-badge {
  display: inline-grid;
  place-items: center;
  min-width: 20px;
  height: 20px;
  padding: 0 8px;
  border-radius: 999px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font-size: 11px;
  font-weight: 600;
}
.batch-preview-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  font-size: 12px;
  color: var(--app-muted);
}
.batch-preview-stats b {
  color: var(--app-text);
}
.batch-preview-errors {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding-top: 6px;
  border-top: 1px dashed var(--app-border);
  font-size: 11px;
  color: var(--el-color-warning);
}
.preview-sub {
  display: block;
  font-size: 11px;
  color: var(--app-muted);
  margin-top: 2px;
}
.batch-preview-table {
  margin-top: 4px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control);
  overflow: hidden;
}
.preview-target-cell {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}
.preview-target-val {
  font-family: var(--fluent-mono, monospace);
  font-size: 11px;
  color: var(--app-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.preview-inherit-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.inherit-text {
  font-size: 11px;
  color: var(--app-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.inherit-disabled-hint {
  font-size: 11px;
  color: var(--app-muted);
}
.preview-custom-row {
  display: flex;
  align-items: center;
  gap: 6px;
}
.custom-port-section {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-top: 6px;
}
.custom-port-label {
  font-size: 12px;
  color: var(--app-muted);
}

.live-task-progress {
  display: grid;
  grid-template-columns: minmax(86px, 1fr) minmax(70px, auto);
  align-items: center;
  gap: 8px;
  min-width: 0;
}
.live-task-progress > span {
  overflow: hidden;
  color: var(--app-text);
  font-size: 11px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.live-task-progress :deep(.el-progress) {
  min-width: 0;
}
.live-task-progress :deep(.el-progress-bar__inner) {
  transition: width 0.18s linear;
}

@media (max-width: 1100px) {
  .project-tabs .toolbar :deep(.el-select) {
    width: 100%;
    flex-basis: 100%;
  }
}

@media (max-width: 760px) {
  .project-tabs :deep(.el-tab-pane) {
    padding: 6px 0 22px;
  }
  .project-tabs .toolbar {
    align-items: stretch;
    gap: 10px;
    margin-bottom: 18px;
  }
  .project-tabs .toolbar :deep(.el-select) {
    width: 100%;
    flex-basis: 100%;
  }
  .project-tabs .toolbar :deep(.el-button) {
    flex: 1 1 140px;
  }
  .project-tabs :deep(.el-table td.el-table__cell) {
    padding: 10px 0;
  }
  .project-tabs .project-tab-toolbar {
    gap: 12px;
    margin-bottom: 16px;
  }
}

@media (max-width: 480px) {
  .project-tabs .toolbar :deep(.el-button) {
    flex-basis: 100%;
  }
}

.report-cards {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin: 4px 0 14px;
}
.report-card {
  display: flex;
  min-height: 92px;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 16px 12px;
  border: 1px solid var(--app-border, var(--el-border-color));
  border-radius: 12px;
  background: var(--app-surface, #fff);
  color: var(--app-text, inherit);
  box-shadow: none;
  font: inherit;
  text-align: center;
  cursor: pointer;
  transition:
    border-color 0.15s ease,
    background-color 0.15s ease,
    box-shadow 0.15s ease,
    transform 0.12s ease;
}
.report-card strong {
  color: var(--app-text, #1f2937);
  font-size: 28px;
  font-weight: 650;
  line-height: 1.1;
}
.report-card span {
  color: var(--app-muted, #6b7280);
  font-size: 12px;
  line-height: 1.35;
}
.report-card--link:hover,
.report-card--link:focus-visible {
  border-color: var(--app-accent);
  background: var(
    --app-accent-soft,
    color-mix(in srgb, var(--app-accent) 10%, #fff)
  );
  box-shadow: 0 0 0 1px color-mix(in srgb, var(--app-accent) 25%, transparent);
  outline: none;
  transform: translateY(-1px);
}
.report-card--link:active {
  transform: translateY(0);
}
.report-severity {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin: 0 0 16px;
}
.report-severity-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-height: 34px;
  padding: 4px 10px 4px 4px;
  border: 1px solid var(--app-border, var(--el-border-color));
  border-radius: 999px;
  background: var(--app-surface, #fff);
  color: inherit;
  font: inherit;
  cursor: pointer;
  transition:
    border-color 0.15s ease,
    background-color 0.15s ease,
    box-shadow 0.15s ease;
}
.report-severity-chip :deep(.el-tag) {
  height: 24px;
  padding: 0 10px;
  border-radius: 999px;
  line-height: 22px;
}
.report-severity-chip b {
  color: var(--app-text, #111827);
  font-size: 13px;
  font-weight: 650;
}
.report-severity--link:hover,
.report-severity--link:focus-visible {
  border-color: var(--app-accent);
  background: var(
    --app-accent-soft,
    color-mix(in srgb, var(--app-accent) 10%, #fff)
  );
  box-shadow: 0 0 0 1px color-mix(in srgb, var(--app-accent) 22%, transparent);
  outline: none;
}
@media (max-width: 1100px) {
  .report-cards {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media (max-width: 640px) {
  .report-cards {
    grid-template-columns: 1fr;
  }
}
</style>
