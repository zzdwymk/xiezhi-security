<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  endpoints,
  connectTaskEventFeed,
  safeGet,
  type AssessmentProject,
  type ProjectTarget,
  type ProjectTaskRecord,
  type ScanSchedule,
  type Target,
  type TaskProgressEvent,
  type TaskControlStatus,
  type VulnerabilityDefinition,
} from "../api";
import { InfoCircle, Search, View, MagicStick, Document } from "../components/fluentIcons";
import AppPagination from "../components/AppPagination.vue";
import FluentCodeBlock from "../components/FluentCodeBlock.vue";
import FluentJsonView from "../components/FluentJsonView.vue";
import OfflineState from "../components/OfflineState.vue";
import { useClientPagination } from "../composables/useClientPagination";
import { formatDateTime, formatExecutionLog } from "../utils/dateTime";
import { useCopilotStore } from "../stores/copilot";
import { toErrorMessage } from "../utils/errorMessage";
import { downloadBlob, EmptyDownloadError } from "../utils/download";
import { severityLabel } from "../utils/aiPresentation";
import {
  taskProgressIndeterminate,
  taskProgressPercentage,
  taskProgressStatus,
  taskProgressText,
} from "../utils/taskProgress";
import { taskbarProgress } from "../utils/taskbarProgress";

const copilot = useCopilotStore();
const router = useRouter();

interface TaskRow {
  id: number;
  projectId: number;
  targetId: number;
  toolCode: string;
  status: string;
  progress: number;
  progressDeterminate?: boolean;
  progressCompleted?: number;
  progressTotal?: number;
  progressMessage?: string;
  progressUpdatedAt?: string;
  requestJson?: string;
  resultJson?: string;
  executionLog?: string;
  targetSnapshotJson?: string;
  allowedPortsSnapshot?: string;
  authorizationStatementSnapshot?: string;
  authorizationValidFromSnapshot?: string;
  authorizationExpiresAtSnapshot?: string;
  toolVersionSnapshot?: string;
  ruleVersionSnapshot?: string;
  nucleiTemplateHashSnapshot?: string;
  snapshotCapturedAt?: string;
  errorMessage?: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  terminationReason?: string;
  timeoutAt?: string;
  queueEnteredAt?: string;
  queueStartedAt?: string;
}

const rows = ref<TaskRow[]>([]);
const notifiedTasks = new Set<number>();
let notifiedSeverities: Set<string> | null = null;
let notifiedTaskCompleteEnabled = true;
const statusFilter = ref<string>("");
const statusOptions = [
  { value: "PENDING", label: "待执行" },
  { value: "QUEUED", label: "排队中" },
  { value: "BLOCKED", label: "等待前置" },
  { value: "RUNNING", label: "执行中" },
  { value: "SUCCESS", label: "成功" },
  { value: "FAILED", label: "失败" },
  { value: "TIMEOUT", label: "超时" },
  { value: "CANCELLED", label: "已取消" },
  { value: "REJECTED", label: "已拒绝" },
  { value: "SKIPPED", label: "已跳过" },
  { value: "PREPARING", label: "准备中" },
  { value: "STOPPING", label: "停止中" },
  { value: "STOPPED", label: "已停止" },
  { value: "PARTIAL_FAILED", label: "部分失败" },
];
const toolFilter = ref<string>("");
const projectFilter = ref<number | "">("");
const targetFilter = ref<number | "">("");
const dateRange = ref<[Date, Date] | null>(null);
const idKeyword = ref<string>("");
const filterProjects = ref<AssessmentProject[]>([]);
const filterTargets = ref<Target[]>([]);
const filterTools = computed(() => {
  const set = new Set<string>();
  for (const tool of SCHEDULE_TOOL_OPTIONS) {
    set.add(tool.value);
  }
  rows.value.forEach((task) => {
    if (task.toolCode) set.add(task.toolCode);
  });
  return Array.from(set)
    .sort()
    .map((code) => ({
      value: code,
      label: scheduleToolLabel(code),
    }));
});
const filteredTasks = computed(() => {
  if (!statusFilter.value
      && !toolFilter.value
      && !projectFilter.value
      && !targetFilter.value
      && !dateRange.value
      && !idKeyword.value.trim()) {
    return rows.value;
  }
  return rows.value.filter((task) => {
    if (statusFilter.value && task.status !== statusFilter.value) return false;
    if (toolFilter.value && task.toolCode !== toolFilter.value) return false;
    if (
      projectFilter.value &&
      task.projectId !== Number(projectFilter.value)
    )
      return false;
    if (targetFilter.value && task.targetId !== Number(targetFilter.value))
      return false;
    if (idKeyword.value.trim()) {
      const keyword = idKeyword.value.trim().toLowerCase();
      if (
        !String(task.id).toLowerCase().includes(keyword) &&
        !String(task.toolCode).toLowerCase().includes(keyword)
      )
        return false;
    }
    if (dateRange.value) {
      const createdAt = new Date(task.createdAt);
      const start = dateRange.value[0].getTime();
      const end = dateRange.value[1].getTime() + 86_399_000;
      const created = createdAt.getTime();
      if (Number.isFinite(created) && (created < start || created > end))
        return false;
    }
    return true;
  });
});
const {
  page,
  pageSize,
  total,
  pagedItems: pagedRows,
} = useClientPagination(filteredTasks);
watch(
  [statusFilter, toolFilter, projectFilter, targetFilter, dateRange, idKeyword],
  () => {
    page.value = 1;
  },
);
const hasActiveFilter = computed(
  () =>
    Boolean(statusFilter.value) ||
    Boolean(toolFilter.value) ||
    Boolean(projectFilter.value) ||
    Boolean(targetFilter.value) ||
    Boolean(dateRange.value) ||
    Boolean(idKeyword.value.trim()),
);
function clearAllFilters() {
  statusFilter.value = "";
  toolFilter.value = "";
  projectFilter.value = "";
  targetFilter.value = "";
  dateRange.value = null;
  idKeyword.value = "";
}
const controlStatus = ref<TaskControlStatus>();
const offline = ref(false);
const detail = ref<TaskRow>();
const detailVisible = ref(false);
const downloading = ref<number>();
const retrying = ref<number>();
const cancelling = ref<number>();
const scheduleVisible = ref(false);
const scheduleSaving = ref(false);
const scheduleAction = ref("");
const scheduleContextLoading = ref(false);
const scheduleTargetsLoading = ref(false);
const schedules = ref<ScanSchedule[]>([]);
const {
  page: schedulePage,
  pageSize: schedulePageSize,
  pagedItems: pagedSchedules,
} = useClientPagination(schedules);
const scheduleProjects = ref<AssessmentProject[]>([]);
const scheduleTargets = ref<Target[]>([]);
const scheduleProjectLinks = ref<ProjectTarget[]>([]);
type ScheduleMode = "daily" | "weekly" | "monthly" | "interval";
type ScheduleIntervalUnit = "minutes" | "hours" | "days";
type ScheduleScannerSource = "NUCLEI" | "AFROG" | "XRAY";
const SCHEDULE_TOOL_OPTIONS = [
  { value: "tcp_ports", label: "TCP 端口探测" },
  { value: "http_headers", label: "HTTP 响应头" },
  { value: "tls_config", label: "TLS 配置" },
  { value: "nmap_service_scan", label: "Nmap 服务识别" },
  { value: "fscan_scan", label: "fscan 主机扫描" },
  { value: "http_security_check", label: "HTTP 常见安全检查" },
  { value: "nuclei_scan", label: "Nuclei 漏洞扫描" },
  { value: "afrog_scan", label: "Afrog PoC 扫描" },
  { value: "xray_scan", label: "Xray PoC 扫描" },
  { value: "zap_scan", label: "OWASP ZAP 主动扫描" },
  { value: "sqlmap_scan", label: "sqlmap SQL 注入检测" },
] as const;
const HTTP_SECURITY_CHECK_OPTIONS = [
  { value: "cookies", label: "Cookie 安全属性" },
  { value: "cors", label: "CORS 跨域策略" },
  { value: "methods", label: "危险 HTTP 方法" },
  { value: "disclosure", label: "技术栈信息泄露" },
] as const;
const scheduleForm = ref<{
  projectId: number | "";
  targetId: number | "";
  toolCode: string;
  httpCheck: string;
  pocCodes: string[];
  mode: ScheduleMode;
  runTime: string;
  weekday: number;
  monthDay: number;
  intervalValue: number;
  intervalUnit: ScheduleIntervalUnit;
}>({
  projectId: "",
  targetId: "",
  toolCode: "tcp_ports",
  httpCheck: "cookies",
  pocCodes: [],
  mode: "daily",
  runTime: "03:00",
  weekday: 1,
  monthDay: 1,
  intervalValue: 1,
  intervalUnit: "hours",
});
const activeScheduleProjects = computed(() =>
  scheduleProjects.value.filter((project) => project.status === "ACTIVE"),
);
const availableScheduleTargets = computed(() => {
  const linkedIds = new Set(
    scheduleProjectLinks.value.map((link) => link.targetId),
  );
  return scheduleTargets.value
    .filter((target) => linkedIds.has(target.id))
    .sort((left, right) =>
      targetDisplayName(left).localeCompare(targetDisplayName(right), "zh-CN"),
    );
});
const scheduleScannerSource = computed<ScheduleScannerSource | undefined>(() =>
  scannerSourceForScheduleTool(scheduleForm.value.toolCode),
);
const schedulePocOptions = ref<VulnerabilityDefinition[]>([]);
const schedulePocLoading = ref(false);
let timer: number | undefined;
let stopTaskFeed: (() => void) | undefined;
let scheduleTargetRequest = 0;
let schedulePocLoadGeneration = 0;
const logOutput = ref<HTMLElement>();
const setLogOutput = (el: HTMLTextAreaElement | null) => {
  logOutput.value = el ?? undefined;
};

async function loadNotificationPreferences() {
  const bridge = window.toolboxDesktop;
  if (!bridge?.getNotificationSettings) {
    notifiedSeverities = new Set(["CRITICAL", "HIGH", "MEDIUM"]);
    notifiedTaskCompleteEnabled = true;
    return;
  }
  try {
    const settings = await bridge.getNotificationSettings();
    notifiedSeverities = new Set(settings.severities);
    notifiedTaskCompleteEnabled = settings.taskCompleteNotifications !== false;
  } catch {
    notifiedSeverities = new Set(["CRITICAL", "HIGH", "MEDIUM"]);
    notifiedTaskCompleteEnabled = true;
  }
}

function collectResultSeverities(resultJson?: string): string[] {
  if (!resultJson) return [];
  try {
    const parsed: unknown = JSON.parse(resultJson);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return [];
    const result = parsed as Record<string, unknown>;
    const data =
      result.data && typeof result.data === "object" && !Array.isArray(result.data)
        ? (result.data as Record<string, unknown>)
        : undefined;
    const candidates = [
      result.matches,
      data?.matches,
      result.findings,
      data?.findings,
      data?.items,
      data?.results,
    ];
    const list = candidates.find((value) => Array.isArray(value)) as
      | Array<Record<string, unknown>>
      | undefined;
    if (!list) return [];
    return Array.from(
      new Set(
        list
          .map((item) => item && typeof item === "object" ? item : {})
          .map((entry) => {
            const severity =
              (entry as Record<string, unknown>).severity ??
              (entry as Record<string, unknown>).level;
            return typeof severity === "string"
              ? severity.trim().toUpperCase()
              : "";
          })
          .filter(Boolean),
      ),
    );
  } catch {
    return [];
  }
}

async function notifyTaskCompletion(row: TaskRow) {
  const bridge = window.toolboxDesktop;
  if (!bridge?.showTaskNotification) return;
  if (notifiedTasks.has(row.id)) return;
  const terminal = new Set([
    "SUCCESS",
    "FAILED",
    "TIMEOUT",
    "REJECTED",
    "CANCELLED",
  ]);
  if (!terminal.has(row.status)) return;
  notifiedTasks.add(row.id);
  if (!notifiedSeverities) await loadNotificationPreferences();

  if (row.status === "SUCCESS") {
    if (!notifiedTaskCompleteEnabled) return;
    const found = new Set(collectResultSeverities(row.resultJson));
    const selected = notifiedSeverities ?? new Set<string>();
    if (!(selected.size > 0 && [...selected].some((s) => found.has(s)))) {
      return;
    }
  }

  const success = row.status === "SUCCESS";
  const severityHint = success ? matchedSeverityHint(row) : "";
  void bridge.showTaskNotification({
    type: success ? "info" : "error",
    title: success
      ? severityHint
        ? `发现${severityHint}漏洞 · #${row.id}`
        : `任务 #${row.id} 已完成`
      : `任务 #${row.id} ${statusLabel(row.status)}`,
    body: success
      ? severityHint
        ? `任务发现 ${severityHint} 严重程度漏洞，已生成结果，可在「任务控制中心」查看。`
        : "任务已完成，可在「任务控制中心」查看结果详情。"
      : row.errorMessage ||
        `任务状态为 ${statusLabel(row.status)}，可在「任务控制中心」查看原因。`,
  });
}

function matchedSeverityHint(row: TaskRow): string {
  const found = collectResultSeverities(row.resultJson);
  const selected = notifiedSeverities ?? new Set<string>();
  const matched = found
    .filter((s) => selected.has(s))
    .sort((a, b) => severityRank(a) - severityRank(b));
  if (!matched.length) return "";
  const labels = Array.from(new Set(matched)).map((s) => severityLabel(s));
  return labels.join("/");
}

function applyTaskEvent(event: TaskProgressEvent) {
  if (!Number(event.taskId)) return;
  const row = rows.value.find((item) => item.id === Number(event.taskId));
  if (!row) {
    void load();
    return;
  }
  const terminal = new Set([
    "SUCCESS",
    "FAILED",
    "TIMEOUT",
    "REJECTED",
    "CANCELLED",
  ]);
  // Never resurrect a finished/cancelled task with a stale RUNNING progress frame.
  if (
    terminal.has(row.status) &&
    event.status &&
    !terminal.has(String(event.status))
  ) {
    if (event.logLine && detail.value?.id === row.id) {
      const timestamp = formatDateTime(
        event.emittedAt || new Date().toISOString(),
      );
      detail.value.executionLog = `${detail.value.executionLog ? `${detail.value.executionLog}\n` : ""}${timestamp}  ${event.logLine}`;
    }
    return;
  }
  const nextStatus = event.status || row.status;
  const patch = {
    status: nextStatus,
    progress:
      terminal.has(String(nextStatus)) && nextStatus !== "SUCCESS"
        ? (event.progress ?? row.progress)
        : (event.progress ?? row.progress),
    progressDeterminate: event.progressDeterminate ?? row.progressDeterminate,
    progressCompleted: event.progressCompleted ?? row.progressCompleted,
    progressTotal: event.progressTotal ?? row.progressTotal,
    progressMessage: event.progressMessage || row.progressMessage,
    progressUpdatedAt: event.progressUpdatedAt || row.progressUpdatedAt,
    errorMessage: event.errorMessage || row.errorMessage,
    startedAt: event.startedAt || row.startedAt,
    finishedAt: event.finishedAt || row.finishedAt,
  };
  Object.assign(row, patch);
  if (detail.value?.id === row.id) {
    Object.assign(detail.value, patch);
    if (event.logLine) {
      const timestamp = formatDateTime(
        event.emittedAt || new Date().toISOString(),
      );
      detail.value.executionLog = `${detail.value.executionLog ? `${detail.value.executionLog}\n` : ""}${timestamp}  ${event.logLine}`;
      void nextTick(() => {
        if (logOutput.value)
          logOutput.value.scrollTop = logOutput.value.scrollHeight;
      });
    }
  }
  taskbarProgress.syncTasks(rows.value);
  void notifyTaskCompletion(row);
}

async function load() {
  const result = await safeGet<ProjectTaskRecord[]>(endpoints.tasks, []);
  const terminal = new Set([
    "SUCCESS",
    "FAILED",
    "TIMEOUT",
    "REJECTED",
    "CANCELLED",
  ]);
  const previous = new Map<number, string>();
  for (const row of rows.value) previous.set(row.id, row.status);
  rows.value = Array.isArray(result.data)
    ? result.data.map((task) => ({
        ...task,
        progress: task.progress ?? (task.status === "SUCCESS" ? 100 : 0),
      }))
    : [];
  taskbarProgress.syncTasks(rows.value);
  const firstLoad = previous.size === 0;
  for (const row of rows.value) {
    if (terminal.has(row.status)) {
      if (firstLoad) {
        notifiedTasks.add(row.id);
      } else if (!terminal.has(previous.get(row.id) || "")) {
        void notifyTaskCompletion(row);
      }
    }
  }
  if (detail.value) {
    const refreshed = rows.value.find((row) => row.id === detail.value?.id);
    if (refreshed) {
      const previousLog = detail.value.executionLog;
      detail.value = refreshed;
      if (refreshed.executionLog !== previousLog) {
        await nextTick();
        if (logOutput.value)
          logOutput.value.scrollTop = logOutput.value.scrollHeight;
      }
    }
  }
  offline.value = result.offline;
  try {
    controlStatus.value = (await endpoints.taskControlStatus()).data;
  } catch {
    controlStatus.value = undefined;
  }
  try {
    schedules.value = (await endpoints.scanSchedules()).data;
  } catch {
    schedules.value = [];
  }
}

async function loadFilterContext() {
  try {
    const [projectResponse, targetResponse] = await Promise.all([
      endpoints.projects(),
      endpoints.targets(),
    ]);
    filterProjects.value = (projectResponse.data || []) as AssessmentProject[];
    filterTargets.value = (targetResponse.data || []) as Target[];
  } catch {
    filterProjects.value = [];
    filterTargets.value = [];
  }
}

function scannerSourceForScheduleTool(
  toolCode: string,
): ScheduleScannerSource | undefined {
  if (toolCode === "nuclei_scan") return "NUCLEI";
  if (toolCode === "afrog_scan") return "AFROG";
  if (toolCode === "xray_scan") return "XRAY";
  return undefined;
}

function schedulePocOptionLabel(item: VulnerabilityDefinition) {
  return `${item.sourceExternalId || item.vulnerabilityCode} · ${item.name}`;
}

function scheduleSeverityType(severity: string) {
  if (severity === "CRITICAL" || severity === "HIGH") return "danger";
  if (severity === "MEDIUM") return "warning";
  if (severity === "LOW") return "info";
  return "success";
}

function scheduleSafetyType(safety?: string) {
  if (safety === "BLOCKED") return "danger";
  if (safety === "REVIEW_REQUIRED") return "warning";
  return "success";
}

function scheduleSafetyLabel(safety?: string) {
  if (safety === "BLOCKED") return "高风险";
  if (safety === "REVIEW_REQUIRED") return "需审查";
  return "安全";
}

async function loadSchedulePocOptions(search = "") {
  const source = scheduleScannerSource.value;
  if (!source) return;
  const generation = ++schedulePocLoadGeneration;
  schedulePocLoading.value = true;
  try {
    const { data } = await endpoints.vulnerabilities({
      page: 0,
      size: 200,
      source,
      scanSafety: "SAFE",
      query: search.trim() || undefined,
    });
    if (
      generation !== schedulePocLoadGeneration ||
      source !== scheduleScannerSource.value
    )
      return;
    const selectedCodes = new Set(scheduleForm.value.pocCodes);
    const merged = new Map<string, VulnerabilityDefinition>();
    for (const item of schedulePocOptions.value) {
      if (selectedCodes.has(item.vulnerabilityCode))
        merged.set(item.vulnerabilityCode, item);
    }
    for (const item of data.content || []) {
      if (item.scanSafety === "SAFE") merged.set(item.vulnerabilityCode, item);
    }
    schedulePocOptions.value = [...merged.values()];
  } catch (error) {
    if (generation === schedulePocLoadGeneration)
      ElMessage.error(
        toErrorMessage(error, `无法加载 ${source} PoC`),
      );
  } finally {
    if (generation === schedulePocLoadGeneration)
      schedulePocLoading.value = false;
  }
}

// 定时任务 PoC 弹窗选择状态与操作
const schedulePocDialogVisible = ref(false);
const scheduleDialogSearch = ref("");
const scheduleDialogSeverity = ref("");
const scheduleDialogLoading = ref(false);
const scheduleDialogList = ref<VulnerabilityDefinition[]>([]);
const scheduleDialogTotal = ref(0);
const scheduleDialogPage = ref(0);
const scheduleDialogPageSize = 20;
const scheduleDialogSelected = ref<Set<string>>(new Set());
const scheduleDialogCachedDefs = new Map<string, VulnerabilityDefinition>();

let scheduleDialogSearchTimer: ReturnType<typeof setTimeout> | undefined;

function openSchedulePocDialog() {
  const source = scheduleScannerSource.value;
  if (!source) return;
  scheduleDialogSearch.value = "";
  scheduleDialogSeverity.value = "";
  scheduleDialogPage.value = 0;
  scheduleDialogSelected.value = new Set(scheduleForm.value.pocCodes);
  for (const item of schedulePocOptions.value) {
    scheduleDialogCachedDefs.set(item.vulnerabilityCode, item);
  }
  schedulePocDialogVisible.value = true;
  void loadScheduleDialogData();
}

async function loadScheduleDialogData() {
  const source = scheduleScannerSource.value;
  if (!source) return;
  scheduleDialogLoading.value = true;
  try {
    const { data } = await endpoints.vulnerabilities({
      page: scheduleDialogPage.value,
      size: scheduleDialogPageSize,
      source,
      scanSafety: "SAFE",
      query: scheduleDialogSearch.value.trim() || undefined,
      severity: scheduleDialogSeverity.value || undefined,
    });
    scheduleDialogList.value = data.content || [];
    scheduleDialogTotal.value = data.totalElements || 0;
    for (const item of scheduleDialogList.value) {
      scheduleDialogCachedDefs.set(item.vulnerabilityCode, item);
    }
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "加载 SAFE PoC 列表失败"));
  } finally {
    scheduleDialogLoading.value = false;
  }
}

function onScheduleDialogSearchInput() {
  clearTimeout(scheduleDialogSearchTimer);
  scheduleDialogSearchTimer = setTimeout(() => {
    scheduleDialogPage.value = 0;
    void loadScheduleDialogData();
  }, 300);
}

function handleScheduleDialogFilterChange() {
  scheduleDialogPage.value = 0;
  void loadScheduleDialogData();
}

function handleScheduleDialogPageChange(newPage: number) {
  scheduleDialogPage.value = Math.max(0, newPage - 1);
  void loadScheduleDialogData();
}

function toggleScheduleDialogCode(code: string) {
  if (scheduleDialogSelected.value.has(code)) {
    scheduleDialogSelected.value.delete(code);
  } else {
    if (scheduleDialogSelected.value.size >= 50) {
      ElMessage.warning("单个定时任务最多选择 50 个 PoC");
      return;
    }
    scheduleDialogSelected.value.add(code);
  }
  scheduleDialogSelected.value = new Set(scheduleDialogSelected.value);
}

function selectAllScheduleDialogCurrentPage() {
  for (const item of scheduleDialogList.value) {
    if (scheduleDialogSelected.value.size >= 50) {
      ElMessage.warning("已达到单个定时任务最多 50 个 PoC 限制");
      break;
    }
    scheduleDialogSelected.value.add(item.vulnerabilityCode);
  }
  scheduleDialogSelected.value = new Set(scheduleDialogSelected.value);
}

function deselectAllScheduleDialogCurrentPage() {
  for (const item of scheduleDialogList.value) {
    scheduleDialogSelected.value.delete(item.vulnerabilityCode);
  }
  scheduleDialogSelected.value = new Set(scheduleDialogSelected.value);
}

function applyScheduleDialogSelection() {
  scheduleForm.value.pocCodes = Array.from(scheduleDialogSelected.value);
  schedulePocDialogVisible.value = false;
  ElMessage.success(
    `已为定时任务选定 ${scheduleForm.value.pocCodes.length} 个 SAFE PoC`,
  );
}

function getSchedulePocName(code: string) {
  const item =
    scheduleDialogCachedDefs.get(code) ||
    schedulePocOptions.value.find((p) => p.vulnerabilityCode === code);
  return item ? item.sourceExternalId || item.name || code : code;
}

function removeSchedulePoc(code: string) {
  scheduleForm.value.pocCodes = scheduleForm.value.pocCodes.filter(
    (c) => c !== code,
  );
}

function onScheduleToolChange(toolCode: string) {
  schedulePocLoadGeneration += 1;
  schedulePocLoading.value = false;
  schedulePocOptions.value = [];
  scheduleForm.value.httpCheck = "cookies";
  scheduleForm.value.pocCodes = [];
}

function buildScheduleParameters(): Record<string, unknown> | undefined {
  if (scheduleForm.value.toolCode === "http_security_check") {
    const check = scheduleForm.value.httpCheck;
    if (!HTTP_SECURITY_CHECK_OPTIONS.some((item) => item.value === check)) {
      ElMessage.warning("请选择有效的 HTTP 检查类型");
      return undefined;
    }
    return { check };
  }

  const source = scheduleScannerSource.value;
  if (!source) return {};
  const pocCodes = [...new Set(scheduleForm.value.pocCodes.map((code) => code.trim()))]
    .filter(Boolean);
  if (!pocCodes.length) {
    ElMessage.warning(`请为 ${source} 至少选择一个 PoC`);
    return undefined;
  }
  if (pocCodes.length > 50) {
    ElMessage.warning("单个定时任务最多选择 50 个 PoC");
    return undefined;
  }
  return { pocCodes };
}

async function confirmScannerSchedule() {
  const source = scheduleScannerSource.value;
  if (!source) return true;
  const target = scheduleTargets.value.find(
    (item) => item.id === Number(scheduleForm.value.targetId),
  );
  const scope = `${scheduleForm.value.pocCodes.length} 个指定 SAFE PoC`;
  const risk =
    "无人值守任务不会执行需审查或高影响 PoC；系统会在每次派发和实际执行前复验项目授权、SAFE 分级及本地文件哈希。";
  const confirmed = await ElMessageBox.confirm(
    `将为“${target ? targetDisplayName(target) : `目标 #${scheduleForm.value.targetId}`}”创建 ${scheduleToolLabel(scheduleForm.value.toolCode)} 定时任务。\n\nPoC 范围：${scope}\n${risk}\n\n该检测会按所选时间规则重复执行，直到任务被停用或删除。`,
    "确认扫描器定时任务",
    {
      type: "warning",
      confirmButtonText: "创建定时任务",
      cancelButtonText: "取消",
    },
  ).catch(() => false);
  return confirmed === "confirm";
}

async function createSchedule() {
  const projectId = Number(scheduleForm.value.projectId);
  const targetId = Number(scheduleForm.value.targetId);
  if (!Number.isSafeInteger(projectId) || projectId <= 0)
    return ElMessage.warning("请选择安全评估项目");
  if (!Number.isSafeInteger(targetId) || targetId <= 0)
    return ElMessage.warning("请选择项目内授权目标");
  if (
    !scheduleProjectLinks.value.some(
      (link) => link.projectId === projectId && link.targetId === targetId,
    )
  )
    return ElMessage.warning("所选目标不属于当前项目，请重新选择");
  const parameters = buildScheduleParameters();
  if (!parameters) return;
  const [hourText, minuteText] = scheduleForm.value.runTime.split(":");
  const hour = Number(hourText);
  const minute = Number(minuteText);
  if (
    scheduleForm.value.mode !== "interval" &&
    (!Number.isInteger(hour) ||
      hour < 0 ||
      hour > 23 ||
      !Number.isInteger(minute) ||
      minute < 0 ||
      minute > 59)
  )
    return ElMessage.warning("请选择有效的执行时间");
  let cronExpression: string | undefined;
  let intervalSeconds: number | undefined;
  if (scheduleForm.value.mode === "interval") {
    const unitSeconds: Record<ScheduleIntervalUnit, number> = {
      minutes: 60,
      hours: 3600,
      days: 86400,
    };
    const value = Number(scheduleForm.value.intervalValue);
    intervalSeconds = value * unitSeconds[scheduleForm.value.intervalUnit];
    if (
      !Number.isFinite(value) ||
      !Number.isInteger(value) ||
      value < 1 ||
      intervalSeconds < 60
    )
      return ElMessage.warning("自定义间隔必须是至少 1 分钟");
  } else if (scheduleForm.value.mode === "daily") {
    cronExpression = `0 ${minute} ${hour} * * *`;
  } else if (scheduleForm.value.mode === "weekly") {
    cronExpression = `0 ${minute} ${hour} * * ${scheduleForm.value.weekday}`;
  } else {
    cronExpression = `0 ${minute} ${hour} ${scheduleForm.value.monthDay} * *`;
  }
  if (!(await confirmScannerSchedule())) return;
  scheduleSaving.value = true;
  try {
    await endpoints.createScanSchedule({
      projectId,
      targetId,
      toolCode: scheduleForm.value.toolCode,
      parameters,
      cronExpression,
      intervalSeconds,
      enabled: true,
    });
    scheduleVisible.value = false;
    await load();
    ElMessage.success("定时任务已创建");
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "定时任务创建失败"));
  } finally {
    scheduleSaving.value = false;
  }
}

function scheduleActionKey(action: string, id: number) {
  return `${action}:${id}`;
}

async function toggleSchedule(schedule: ScanSchedule) {
  const action = schedule.enabled ? "disable" : "enable";
  scheduleAction.value = scheduleActionKey(action, schedule.id);
  try {
    const response = schedule.enabled
      ? await endpoints.disableScanSchedule(schedule.id)
      : await endpoints.enableScanSchedule(schedule.id);
    const index = schedules.value.findIndex((item) => item.id === schedule.id);
    if (index >= 0) schedules.value[index] = response.data;
    ElMessage.success(schedule.enabled ? "定时任务已停用" : "定时任务已启用");
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "更新定时任务状态失败"));
  } finally {
    scheduleAction.value = "";
  }
}

async function deleteSchedule(schedule: ScanSchedule) {
  try {
    await ElMessageBox.confirm(
      `确定删除“${scheduleProjectName(schedule.projectId)} · ${scheduleTargetName(schedule.targetId)}”的定时任务吗？已执行的任务不会被删除。`,
      "删除定时任务",
      { type: "warning", confirmButtonText: "删除", cancelButtonText: "取消" },
    );
  } catch {
    return;
  }
  scheduleAction.value = scheduleActionKey("delete", schedule.id);
  try {
    await endpoints.deleteScanSchedule(schedule.id);
    schedules.value = schedules.value.filter((item) => item.id !== schedule.id);
    ElMessage.success("定时任务已删除");
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "删除定时任务失败"));
  } finally {
    scheduleAction.value = "";
  }
}

function targetDisplayName(target: Target) {
  const name = target.name?.trim();
  return name && name !== target.targetValue
    ? `${name} · ${target.targetValue}`
    : target.targetValue;
}

function targetWindowActive(target: Target) {
  const start = Date.parse((target.authorizationValidFrom || "") as string);
  const end = Date.parse((target.authorizationExpiresAt || "") as string);
  if (!Number.isFinite(start) || !Number.isFinite(end)) return false;
  const now = Date.now();
  return now >= start && now < end;
}

function scheduleProjectName(projectId?: number) {
  if (!projectId) return "未关联项目";
  return (
    scheduleProjects.value.find((project) => project.id === projectId)?.name ||
    `项目 #${projectId}`
  );
}

function scheduleTargetName(targetId: number) {
  const target = scheduleTargets.value.find((item) => item.id === targetId);
  return target ? targetDisplayName(target) : `目标 #${targetId}`;
}

function scheduleToolLabel(toolCode: string) {
  return (
    SCHEDULE_TOOL_OPTIONS.find((item) => item.value === toolCode)?.label ||
    toolCode
  );
}

function scheduleParameterSummary(schedule: ScanSchedule) {
  let parameters: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(schedule.parametersJson || "{}");
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed))
      parameters = parsed;
  } catch {
    return "参数记录不可读";
  }
  if (schedule.toolCode === "http_security_check") {
    const check = String(parameters.check || "");
    return (
      HTTP_SECURITY_CHECK_OPTIONS.find((item) => item.value === check)?.label ||
      "未指定检查类型"
    );
  }
  const source = scannerSourceForScheduleTool(schedule.toolCode);
  if (!source) return "";
  if (parameters.allPocs === true) return "动态全部 PoC（不再支持）";
  if (Array.isArray(parameters.pocCodes))
    return `指定 ${parameters.pocCodes.length} 个 SAFE PoC`;
  return "未选择 PoC";
}

function scheduleTime(value?: string) {
  return value ? formatDateTime(value) : "未执行";
}

function scheduleRule(schedule: ScanSchedule) {
  if (schedule.intervalSeconds) {
    const seconds = Number(schedule.intervalSeconds);
    if (seconds % 86400 === 0) return `每 ${seconds / 86400} 天`;
    if (seconds % 3600 === 0) return `每 ${seconds / 3600} 小时`;
    if (seconds % 60 === 0) return `每 ${seconds / 60} 分钟`;
    return `每 ${seconds} 秒`;
  }
  const parts = schedule.cronExpression?.trim().split(/\s+/) || [];
  if (parts.length === 6) {
    const [, minute, hour, dayOfMonth, month, dayOfWeek] = parts;
    const time = `${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
    if (dayOfMonth === "*" && month === "*" && dayOfWeek === "*")
      return `每天 ${time}`;
    if (dayOfMonth === "*" && month === "*" && dayOfWeek !== "*")
      return `每周${weekdayLabel(Number(dayOfWeek))} ${time}`;
    if (dayOfMonth !== "*" && month === "*" && dayOfWeek === "*")
      return `每月 ${dayOfMonth} 日 ${time}`;
  }
  return schedule.cronExpression ? "按已保存规则执行" : "未设置规则";
}

function weekdayLabel(value: number) {
  return (
    (
      {
        1: "一",
        2: "二",
        3: "三",
        4: "四",
        5: "五",
        6: "六",
        7: "日",
        0: "日",
      } as Record<number, string>
    )[value] || "日"
  );
}

async function loadScheduleProjectTargets(projectIdValue: number | "") {
  const requestId = ++scheduleTargetRequest;
  scheduleForm.value.targetId = "";
  scheduleProjectLinks.value = [];
  const projectId = Number(projectIdValue);
  if (!Number.isSafeInteger(projectId) || projectId <= 0) return;
  scheduleTargetsLoading.value = true;
  try {
    const response = await endpoints.projectTargets(projectId);
    if (requestId !== scheduleTargetRequest) return;
    scheduleProjectLinks.value = response.data;
    if (!response.data.length) ElMessage.warning("该项目尚未添加授权目标");
  } catch (error) {
    if (requestId !== scheduleTargetRequest) return;
    ElMessage.error(toErrorMessage(error, "无法加载项目授权目标"));
  } finally {
    if (requestId === scheduleTargetRequest)
      scheduleTargetsLoading.value = false;
  }
}

async function openScheduleDialog() {
  scheduleVisible.value = true;
  scheduleContextLoading.value = true;
  scheduleForm.value = {
    projectId: "",
    targetId: "",
    toolCode: "tcp_ports",
    httpCheck: "cookies",
    pocCodes: [],
    mode: "daily",
    runTime: "03:00",
    weekday: 1,
    monthDay: 1,
    intervalValue: 1,
    intervalUnit: "hours",
  };
  schedulePocLoadGeneration += 1;
  schedulePocLoading.value = false;
  schedulePocOptions.value = [];
  scheduleProjectLinks.value = [];
  try {
    const [projectResponse, targetResponse] = await Promise.all([
      endpoints.projects(),
      endpoints.targets(),
    ]);
    scheduleProjects.value = projectResponse.data;
    scheduleTargets.value = targetResponse.data;
    const firstProject = activeScheduleProjects.value[0];
    if (!firstProject) {
      ElMessage.warning("暂无“进行中”状态的安全评估项目，请先启用项目");
      return;
    }
    scheduleForm.value.projectId = firstProject.id;
    await loadScheduleProjectTargets(firstProject.id);
  } catch (error) {
    scheduleProjects.value = [];
    scheduleTargets.value = [];
    ElMessage.error(toErrorMessage(error, "无法加载评估项目和授权目标"));
  } finally {
    scheduleContextLoading.value = false;
  }
}

const detailResultView = ref<"friendly" | "raw">("friendly");
const detailRequestView = ref<"friendly" | "raw">("friendly");

const parsedDetailResult = computed<Record<string, unknown> | undefined>(() => {
  const raw = detail.value?.resultJson;
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
});

const parsedDetailRequest = computed<unknown>(() => {
  const raw = detail.value?.requestJson;
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
});

const prettyDetailRequestJson = computed(() => {
  const parsed = parsedDetailRequest.value;
  if (parsed === undefined) return detail.value?.requestJson || "";
  try {
    return JSON.stringify(parsed, null, 2);
  } catch {
    return detail.value?.requestJson || "";
  }
});

const detailResultSummary = computed(() => {
  const summary = parsedDetailResult.value?.summary;
  return typeof summary === "string" ? summary : "";
});

interface TaskResultMatch {
  severity?: string;
  name: string;
  cwe?: string;
  url?: string;
}

const detailResultMatches = computed<TaskResultMatch[]>(() => {
  const result = parsedDetailResult.value;
  if (!result) return [];
  const data = result.data as Record<string, unknown> | undefined;
  const candidates = [
    result.matches,
    data?.matches,
    result.findings,
    data?.findings,
    data?.items,
    data?.results,
  ];
  const list = candidates.find((value) => Array.isArray(value)) as
    | Array<Record<string, unknown>>
    | undefined;
  if (!list) return [];
  return list
    .map((item) => {
      const entry = item && typeof item === "object" ? item : {};
      return {
        severity:
          typeof entry.severity === "string" ? entry.severity : undefined,
        name:
          (typeof entry.name === "string" && entry.name) ||
          (typeof entry.title === "string" && entry.title) ||
          "未命名条目",
        cwe:
          (typeof entry.cwe === "string" && entry.cwe) ||
          (typeof entry.vulnerabilityCode === "string" &&
            entry.vulnerabilityCode) ||
          undefined,
        url: typeof entry.url === "string" ? entry.url : undefined,
      };
    })
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
});

const RESULT_STAT_LABELS: Readonly<Record<string, string>> = {
  matchCount: "命中总数",
  inScopeAlertCount: "授权范围内",
  passiveAlertCount: "被动发现",
  activeAlertCount: "主动发现",
  total: "总数",
  count: "数量",
  itemCount: "条目数量",
  openPortCount: "开放端口",
};

function collectResultStats(source: unknown) {
  if (!source || typeof source !== "object" || Array.isArray(source)) return [];
  return Object.entries(source as Record<string, unknown>)
    .filter(
      ([key, value]) =>
        key !== "summary" &&
        typeof value === "number" &&
        Number.isFinite(value),
    )
    .slice(0, 6)
    .map(([key, value]) => ({
      label: RESULT_STAT_LABELS[key] || key,
      value: value as number,
    }));
}

const detailResultStats = computed(() => {
  const result = parsedDetailResult.value;
  if (!result) return [];
  const dataStats = collectResultStats(result.data);
  return dataStats.length ? dataStats : collectResultStats(result);
});

const prettyDetailResultJson = computed(() => {
  const parsed = parsedDetailResult.value;
  if (!parsed) return detail.value?.resultJson || "尚无结果";
  try {
    return JSON.stringify(parsed, null, 2);
  } catch {
    return detail.value?.resultJson || "";
  }
});

const SEVERITY_RANK: Readonly<Record<string, number>> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function severityRank(severity?: string): number {
  const key = (severity || "").trim().toUpperCase();
  return SEVERITY_RANK[key] ?? 99;
}

function resultSeverityType(severity?: string) {
  switch ((severity || "").toLowerCase()) {
    case "critical":
    case "high":
      return "danger" as const;
    case "medium":
      return "warning" as const;
    default:
      return "info" as const;
  }
}

function showDetail(row: TaskRow) {
  detail.value = row;
  detailResultView.value = "friendly";
  detailRequestView.value = "friendly";
  detailVisible.value = true;
  void nextTick(() => {
    if (logOutput.value)
      logOutput.value.scrollTop = logOutput.value.scrollHeight;
  });
}

async function downloadReport(taskId: number) {
  downloading.value = taskId;
  try {
    const { data } = await endpoints.downloadReport(taskId);
    downloadBlob(data, `security-report-task-${taskId}.html`);
  } catch (error) {
    ElMessage.error(
      error instanceof EmptyDownloadError ? error.message : "报告下载失败",
    );
  } finally {
    downloading.value = undefined;
  }
}

async function retryTask(row: TaskRow) {
  if (retrying.value) return;
  retrying.value = row.id;
  try {
    const { data } = await endpoints.retryTask(row.id);
    ElMessage.success(`已创建重试任务 #${data.id}`);
    await load();
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "任务重试失败"));
  } finally {
    retrying.value = undefined;
  }
}

async function cancelTask(row: TaskRow) {
  if (cancelling.value) return;
  cancelling.value = row.id;
  try {
    // Optimistic UI: flip immediately so a lagging progress frame cannot keep RUNNING.
    row.status = "CANCELLED";
    row.progressMessage = "用户取消任务";
    row.errorMessage = "用户取消任务";
    if (detail.value?.id === row.id) {
      detail.value.status = "CANCELLED";
      detail.value.progressMessage = "用户取消任务";
      detail.value.errorMessage = "用户取消任务";
    }
    await endpoints.cancelTask(row.id);
    ElMessage.success(`任务 #${row.id} 已取消`);
    await load();
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "取消任务失败"));
    await load();
  } finally {
    cancelling.value = undefined;
  }
}

function displayTaskError(message?: string) {
  return message
    ? toErrorMessage(message, "任务执行失败，请查看执行日志")
    : "无";
}

function statusType(status: string) {
  if (status === "SUCCESS") return "success";
  if (["FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "PARTIAL_FAILED"].includes(status))
    return "danger";
  if (["RUNNING", "STOPPING", "PREPARING"].includes(status)) return "warning";
  return "info";
}

function statusLabel(status?: string) {
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

function askCopilot(row: TaskRow) {
  copilot.prepare({
    targetId: row.targetId,
    refs: [
      {
        type: "task",
        id: row.id,
        targetId: row.targetId,
        title: `任务 #${row.id} · ${row.toolCode}`,
      },
    ],
    mode: "analyze",
    prompt:
      row.status === "SUCCESS"
        ? "解读这个任务的执行结果、关键证据和风险优先级，并给出下一步安全验证建议。"
        : "诊断这个任务当前状态或失败原因，给出安全、可执行的排查与重试建议。",
  });
  void router.push("/");
}

onMounted(() => {
  load();
  void loadFilterContext();
  void loadNotificationPreferences();
  stopTaskFeed = connectTaskEventFeed(applyTaskEvent);
  timer = window.setInterval(load, 10_000);
});
onUnmounted(() => {
  if (timer) window.clearInterval(timer);
  stopTaskFeed?.();
});
</script>

<template>
  <section class="panel tasks-page workspace-list-page">
    <div class="section-head">
      <div>
        <h3>任务控制中心</h3>
        <p>任务状态、真实完成量和执行日志通过实时事件持续更新。</p>
      </div>
      <div class="section-head-actions">
        <el-button @click="load">刷新</el-button
        ><el-button class="schedule-trigger" @click="openScheduleDialog"
          >定时任务<span v-if="schedules.length" class="schedule-count">{{
            schedules.length
          }}</span></el-button
        >
      </div>
    </div>
    <div class="task-filter-bar" aria-label="任务筛选">
      <el-select
        v-model="statusFilter"
        class="task-filter-cell"
        clearable
        placeholder="全部状态"
        aria-label="按任务状态筛选"
      >
        <el-option
          v-for="option in statusOptions"
          :key="option.value"
          :value="option.value"
          :label="option.label"
        />
      </el-select>
      <el-select
        v-model="toolFilter"
        class="task-filter-cell"
        clearable
        placeholder="全部工具"
        aria-label="按工具筛选"
      >
        <el-option
          v-for="option in filterTools"
          :key="option.value"
          :value="option.value"
          :label="option.label"
        />
      </el-select>
      <el-select
        v-model="projectFilter"
        class="task-filter-cell"
        clearable
        filterable
        placeholder="全部项目"
        aria-label="按项目筛选"
      >
        <el-option
          v-for="project in filterProjects"
          :key="project.id"
          :value="project.id"
          :label="project.name"
        />
      </el-select>
      <el-select
        v-model="targetFilter"
        class="task-filter-cell"
        clearable
        filterable
        placeholder="全部目标"
        aria-label="按目标筛选"
      >
        <el-option
          v-for="target in filterTargets"
          :key="target.id"
          :value="target.id"
          :label="targetDisplayName(target)"
        />
      </el-select>
      <div class="task-filter-row">
        <el-date-picker
          v-model="dateRange"
          class="task-filter-cell task-filter-cell--date"
          type="daterange"
          range-separator="至"
          start-placeholder="开始日期"
          end-placeholder="结束日期"
          aria-label="按创建时间筛选"
        />
        <el-input
          v-model="idKeyword"
          class="task-filter-cell task-filter-cell--search"
          placeholder="搜任务 ID / 工具"
          clearable
          aria-label="按任务ID或工具搜索"
        />
        <el-button
          v-if="hasActiveFilter"
          class="task-filter-clear"
          link
          type="primary"
          @click="clearAllFilters"
          >清除筛选</el-button
        >
      </div>
    </div>
    <div
      v-if="controlStatus"
      class="task-control-summary"
      aria-label="任务资源配额"
    >
      <span
        ><small>当前运行</small
        ><strong
          >{{ controlStatus.runningTasks }} /
          {{ controlStatus.maxConcurrentTasks }}</strong
        ></span
      >
      <span
        ><small>等待队列</small
        ><strong
          >{{ controlStatus.pendingTasks }} /
          {{ controlStatus.queueCapacity }}</strong
        ></span
      >
      <span
        ><small>可用并发槽位</small
        ><strong>{{ controlStatus.availableConcurrentSlots }}</strong></span
      >
      <span
        ><small>单目标上限</small
        ><strong
          >{{ controlStatus.maxConcurrentTasksPerTarget }} 个</strong
        ></span
      >
    </div>
    <OfflineState
      v-if="offline || !rows.length"
      title="暂无任务"
      :description="
        offline ? '无法连接后端服务。' : '在检测计划中提交步骤后会创建任务。'
      "
    />
    <el-table v-else :data="pagedRows">
      <el-table-column prop="id" label="ID" width="55" />
      <el-table-column prop="toolCode" label="工具" min-width="110" show-overflow-tooltip />
      <el-table-column prop="targetId" label="目标" width="65" />
      <el-table-column label="状态" width="85"
        ><template #default="scope"
          ><el-tag size="small" :type="statusType(scope.row.status)">{{
            statusLabel(scope.row.status)
          }}</el-tag></template
        ></el-table-column
      >
      <el-table-column label="进度" min-width="140"
        ><template #default="scope"
          ><div class="live-task-progress">
            <el-progress
              :percentage="taskProgressPercentage(scope.row)"
              :stroke-width="8"
              :status="taskProgressStatus(scope.row)"
              :indeterminate="taskProgressIndeterminate(scope.row)"
              :duration="1.2"
              :show-text="false"
            /><span>{{ taskProgressText(scope.row) }}</span>
          </div></template
        ></el-table-column
      >
      <el-table-column label="创建时间" min-width="140"
        ><template #default="scope">{{
          formatDateTime(scope.row.createdAt)
        }}</template></el-table-column
      >
      <el-table-column label="操作" min-width="300"
        ><template #default="scope"
          ><div class="task-row-actions">
            <el-button
              class="task-action"
              size="small"
              :icon="View"
              @click="showDetail(scope.row)"
              >详情</el-button
            ><el-button
              class="task-action task-action--ai"
              size="small"
              :icon="MagicStick"
              @click="askCopilot(scope.row)"
              >AI 分析</el-button
            ><el-button
              v-if="['PENDING', 'RUNNING'].includes(scope.row.status)"
              class="task-action task-action--danger"
              size="small"
              :loading="cancelling === scope.row.id"
              @click="cancelTask(scope.row)"
              >取消</el-button
            ><el-button
              v-if="
                ['FAILED', 'TIMEOUT', 'REJECTED', 'CANCELLED'].includes(
                  scope.row.status,
                )
              "
              class="task-action task-action--danger"
              size="small"
              :loading="retrying === scope.row.id"
              :disabled="Boolean(retrying)"
              @click="retryTask(scope.row)"
              >重试</el-button
            ><el-button
              class="task-action"
              size="small"
              :icon="Document"
              :disabled="scope.row.status !== 'SUCCESS'"
              :loading="downloading === scope.row.id"
              @click="downloadReport(scope.row.id)"
              >报告</el-button
            >
          </div></template
        ></el-table-column
      >
    </el-table>
    <AppPagination
      v-model:page="page"
      v-model:page-size="pageSize"
      class="tasks-pagination"
      :total="total"
    />
  </section>

  <el-dialog
    v-model="scheduleVisible"
    title="定时任务管理"
    class="app-dialog app-dialog--wide"
    align-center
    destroy-on-close
  >
    <div class="schedule-dialog-intro">
      选择常见时间规则即可自动创建检测任务，无需填写
      Cron。所有任务都会保留所属项目、授权目标和审计上下文。
    </div>
    <el-form v-loading="scheduleContextLoading" label-position="top">
      <el-form-item label="安全评估项目">
        <el-select
          v-model="scheduleForm.projectId"
          aria-label="安全评估项目"
          placeholder="选择进行中项目"
          filterable
          :disabled="scheduleContextLoading"
          @change="loadScheduleProjectTargets"
        >
          <el-option
            v-for="project in activeScheduleProjects"
            :key="project.id"
            :label="project.name"
            :value="project.id"
          />
        </el-select>
      </el-form-item>
      <el-form-item label="项目授权目标">
        <el-select
          v-model="scheduleForm.targetId"
          aria-label="项目授权目标"
          placeholder="选择当前项目内的目标"
          filterable
          :loading="scheduleTargetsLoading"
          :disabled="!scheduleForm.projectId || scheduleTargetsLoading"
        >
          <el-option
            v-for="target in availableScheduleTargets"
            :key="target.id"
            :label="targetDisplayName(target)"
            :value="target.id"
            :disabled="!target.enabled || !targetWindowActive(target)"
          >
            <span>{{ targetDisplayName(target) }}</span
            ><span v-if="!target.enabled" class="disabled-target">已停用</span
            ><span v-else-if="!targetWindowActive(target)" class="disabled-target"
              >授权失效</span
            >
          </el-option>
        </el-select>
      </el-form-item>
      <el-form-item label="检测工具"
        ><el-select
          v-model="scheduleForm.toolCode"
          aria-label="检测工具"
          @change="onScheduleToolChange"
          ><el-option
            v-for="tool in SCHEDULE_TOOL_OPTIONS"
            :key="tool.value"
            :label="tool.label"
            :value="tool.value"
          /></el-select
      ></el-form-item>
      <section
        v-if="
          scheduleForm.toolCode === 'http_security_check' ||
          scheduleScannerSource
        "
        class="schedule-parameter-panel"
        aria-label="检测参数"
      >
        <el-form-item
          v-if="scheduleForm.toolCode === 'http_security_check'"
          label="检查类型"
        >
          <el-select v-model="scheduleForm.httpCheck" aria-label="HTTP 检查类型">
            <el-option
              v-for="check in HTTP_SECURITY_CHECK_OPTIONS"
              :key="check.value"
              :label="check.label"
              :value="check.value"
            />
          </el-select>
        </el-form-item>
        <template v-if="scheduleScannerSource">
          <el-form-item label="PoC 范围">
            <div class="schedule-poc-policy">
              <el-tag size="small" type="success">指定安全 PoC</el-tag>
              <p class="schedule-parameter-help">
                仅重复执行下方明确选择且标记为 SAFE 的 PoC，最多 50 个。
                分级或文件变化时任务会自动停用。
              </p>
            </div>
          </el-form-item>
          <el-form-item label="指定 PoC">
            <div class="schedule-poc-selector poc-picker-wrapper">
              <el-button
                v-if="!scheduleForm.pocCodes.length"
                type="primary"
                plain
                style="width: 100%"
                :icon="Search"
                @click="openSchedulePocDialog"
              >
                选择 PoC
              </el-button>
              <div v-else class="poc-selected-summary-bar">
                <span class="poc-selected-count-label">
                  已选 <b>{{ scheduleForm.pocCodes.length }}</b> / 50 个 SAFE PoC
                </span>
                <div class="poc-selected-actions">
                  <el-button
                    link
                    type="primary"
                    size="small"
                    @click="openSchedulePocDialog"
                  >
                    修改
                  </el-button>
                  <el-button
                    link
                    type="danger"
                    size="small"
                    @click="scheduleForm.pocCodes = []"
                  >
                    清空
                  </el-button>
                </div>
              </div>

              <!-- 已选 PoC 预览标签 -->
              <div
                v-if="scheduleForm.pocCodes.length"
                class="poc-selected-tags"
              >
                <el-tag
                  v-for="code in scheduleForm.pocCodes.slice(0, 4)"
                  :key="code"
                  size="small"
                  closable
                  type="success"
                  class="poc-tag-item"
                  @close="removeSchedulePoc(code)"
                >
                  {{ getSchedulePocName(code) }}
                </el-tag>
                <el-tag
                  v-if="scheduleForm.pocCodes.length > 4"
                  size="small"
                  type="info"
                  class="poc-tag-more"
                  @click="openSchedulePocDialog"
                >
                  +{{ scheduleForm.pocCodes.length - 4 }}...
                </el-tag>
              </div>
            </div>
          </el-form-item>
        </template>
      </section>
      <el-form-item label="执行方式">
        <el-radio-group
          v-model="scheduleForm.mode"
          class="schedule-mode-picker"
        >
          <el-radio-button label="daily">每天</el-radio-button>
          <el-radio-button label="weekly">每周</el-radio-button>
          <el-radio-button label="monthly">每月</el-radio-button>
          <el-radio-button label="interval">按间隔</el-radio-button>
        </el-radio-group>
      </el-form-item>
      <div v-if="scheduleForm.mode !== 'interval'" class="schedule-rule-row">
        <el-form-item v-if="scheduleForm.mode === 'weekly'" label="星期几">
          <el-select v-model="scheduleForm.weekday"
            ><el-option
              v-for="day in 7"
              :key="day"
              :label="`星期${weekdayLabel(day)}`"
              :value="day"
          /></el-select>
        </el-form-item>
        <el-form-item v-if="scheduleForm.mode === 'monthly'" label="每月几号">
          <el-select v-model="scheduleForm.monthDay" filterable
            ><el-option
              v-for="day in 28"
              :key="day"
              :label="`${day} 日`"
              :value="day"
          /></el-select>
        </el-form-item>
        <el-form-item label="执行时间">
          <el-time-picker
            v-model="scheduleForm.runTime"
            format="HH:mm"
            value-format="HH:mm"
            placeholder="选择执行时间"
            :clearable="false"
            :editable="false"
          />
        </el-form-item>
      </div>
      <div v-else class="schedule-rule-row interval-rule-row">
        <el-form-item label="每隔">
          <el-input-number
            v-model="scheduleForm.intervalValue"
            :min="1"
            :max="999"
            controls-position="right"
          />
        </el-form-item>
        <el-form-item label="时间单位">
          <el-select v-model="scheduleForm.intervalUnit"
            ><el-option label="分钟" value="minutes" /><el-option
              label="小时"
              value="hours" /><el-option label="天" value="days"
          /></el-select>
        </el-form-item>
      </div>
      <p class="schedule-rule-preview">
        将按“{{
          scheduleForm.mode === "interval"
            ? `每 ${scheduleForm.intervalValue} ${scheduleForm.intervalUnit === "minutes" ? "分钟" : scheduleForm.intervalUnit === "hours" ? "小时" : "天"}`
            : scheduleForm.mode === "daily"
              ? `每天 ${scheduleForm.runTime}`
              : scheduleForm.mode === "weekly"
                ? `每周${weekdayLabel(scheduleForm.weekday)} ${scheduleForm.runTime}`
                : `每月 ${scheduleForm.monthDay} 日 ${scheduleForm.runTime}`
        }}”自动执行。
      </p>
    </el-form>
    <el-divider v-if="schedules.length" content-position="left"
      >已配置的定时任务</el-divider
    >
    <template v-if="schedules.length">
      <el-table
        :data="pagedSchedules"
        size="small"
        max-height="260"
        class="schedule-table"
      >
        <el-table-column prop="id" label="ID" width="50" />
        <el-table-column label="项目 / 授权目标" min-width="130">
          <template #default="scope"
            ><div class="schedule-context">
              <el-tooltip
                :content="scheduleProjectName(scope.row.projectId)"
                placement="top"
                :show-after="250"
              >
                <strong>{{ scheduleProjectName(scope.row.projectId) }}</strong>
              </el-tooltip>
              <el-tooltip
                :content="scheduleTargetName(scope.row.targetId)"
                placement="top"
                :show-after="250"
              >
                <small>{{ scheduleTargetName(scope.row.targetId) }}</small>
              </el-tooltip>
            </div></template
          >
        </el-table-column>
        <el-table-column label="工具 / 参数" min-width="110">
          <template #default="scope"
            ><div class="schedule-tool-context">
              <el-tooltip
                :content="scheduleToolLabel(scope.row.toolCode)"
                placement="top"
                :show-after="250"
              >
                <strong>{{ scheduleToolLabel(scope.row.toolCode) }}</strong>
              </el-tooltip>
              <el-tooltip
                v-if="scheduleParameterSummary(scope.row)"
                :content="scheduleParameterSummary(scope.row)"
                placement="top"
                :show-after="250"
              >
                <small>{{ scheduleParameterSummary(scope.row) }}</small>
              </el-tooltip>
            </div></template></el-table-column
        >
        <el-table-column label="规则" min-width="90">
          <template #default="scope">{{
            scheduleRule(scope.row)
          }}</template></el-table-column
        >
        <el-table-column label="下次执行" min-width="115">
          <template #default="scope">{{
            scheduleTime(scope.row.nextRunAt)
          }}</template></el-table-column
        >
        <el-table-column label="状态 / 最近错误" min-width="120">
          <template #default="scope"
            ><div class="schedule-status-context">
              <el-tag
                size="small"
                :type="scope.row.enabled ? 'success' : 'info'"
                >{{ scope.row.enabled ? "已启用" : "已停用" }}</el-tag
              >
              <el-tooltip
                v-if="scope.row.lastError"
                :content="scope.row.lastError"
                placement="top"
                :show-after="250"
              >
                <small>{{ scope.row.lastError }}</small>
              </el-tooltip>
            </div></template
          ></el-table-column
        >
        <el-table-column label="操作" width="130">
          <template #default="scope">
            <el-button
              link
              type="primary"
              :loading="
                scheduleAction ===
                scheduleActionKey(
                  scope.row.enabled ? 'disable' : 'enable',
                  scope.row.id,
                )
              "
              @click="toggleSchedule(scope.row)"
              >{{ scope.row.enabled ? "停用" : "启用" }}</el-button
            >
            <el-button
              link
              type="danger"
              :loading="
                scheduleAction === scheduleActionKey('delete', scope.row.id)
              "
              @click="deleteSchedule(scope.row)"
              >删除</el-button
            >
          </template>
        </el-table-column>
      </el-table>
      <AppPagination
        v-model:page="schedulePage"
        v-model:page-size="schedulePageSize"
        class="tasks-pagination"
        :total="schedules.length"
      />
    </template>
    <el-empty
      v-else
      description="还没有定时任务，可在上方创建"
      :image-size="64"
    />
    <template #footer
      ><el-button @click="scheduleVisible = false">取消</el-button
      ><el-button
        type="primary"
        :loading="scheduleSaving"
        @click="createSchedule"
        >创建</el-button
      ></template
    >
  </el-dialog>

  <el-dialog
    v-model="detailVisible"
    title="任务详情"
    class="app-dialog app-dialog--lg"
    align-center
  >
    <el-descriptions v-if="detail" :column="2" border>
      <el-descriptions-item label="任务 ID">{{
        detail.id
      }}</el-descriptions-item
      ><el-descriptions-item label="目标 ID">{{
        detail.targetId
      }}</el-descriptions-item>
      <el-descriptions-item label="工具">{{
        detail.toolCode
      }}</el-descriptions-item
      ><el-descriptions-item label="状态">{{
        detail.status
      }}</el-descriptions-item>
      <el-descriptions-item label="实时进度" :span="2"
        ><div class="live-task-progress detail-progress">
          <el-progress
            :percentage="taskProgressPercentage(detail)"
            :stroke-width="8"
            :status="taskProgressStatus(detail)"
            :indeterminate="taskProgressIndeterminate(detail)"
            :duration="1.2"
            :show-text="false"
          /><span>{{ taskProgressText(detail) }}</span>
        </div></el-descriptions-item
      >
      <el-descriptions-item label="开始时间">{{
        detail.startedAt ? formatDateTime(detail.startedAt) : "未开始"
      }}</el-descriptions-item
      ><el-descriptions-item label="完成时间">{{
        detail.finishedAt ? formatDateTime(detail.finishedAt) : "未完成"
      }}</el-descriptions-item>
      <el-descriptions-item label="失败原因" :span="2">{{
        displayTaskError(detail.errorMessage)
      }}</el-descriptions-item>
      <el-descriptions-item label="执行结果" :span="2">
        <div class="task-result-panel">
          <div class="task-result-toolbar">
            <el-radio-group
              v-model="detailResultView"
              size="small"
              class="task-result-switch"
            >
              <el-radio-button value="friendly">直观视图</el-radio-button>
              <el-radio-button value="raw">原始数据</el-radio-button>
            </el-radio-group>
            <span v-if="detailResultMatches.length" class="task-result-count"
              >共 {{ detailResultMatches.length }} 条</span
            >
          </div>

          <p v-if="!detail.resultJson" class="task-result-empty">尚无结果</p>

          <template v-else-if="detailResultView === 'friendly'">
            <template v-if="parsedDetailResult">
              <p v-if="detailResultSummary" class="task-result-summary">
                <el-icon class="task-result-summary-icon"><InfoCircle /></el-icon>
                <span class="task-result-summary-text">{{
                  detailResultSummary
                }}</span>
              </p>
              <div v-if="detailResultStats.length" class="task-result-stats">
                <div
                  v-for="stat in detailResultStats"
                  :key="stat.label"
                  class="task-result-stat"
                >
                  <strong>{{ stat.value }}</strong
                  ><span>{{ stat.label }}</span>
                </div>
              </div>
              <div
                v-if="detailResultMatches.length"
                class="task-result-matches"
              >
                <div
                  v-for="(match, index) in detailResultMatches"
                  :key="index"
                  class="task-result-match"
                >
                  <el-tag
                    size="small"
                    effect="plain"
                    class="task-result-match-sev"
                    :type="resultSeverityType(match.severity)"
                    >{{ severityLabel(match.severity) }}</el-tag
                  >
                  <div class="task-result-match-body">
                    <strong>{{ match.name }}</strong>
                    <span v-if="match.cwe" class="task-result-match-cwe">{{
                      match.cwe
                    }}</span>
                    <a
                      v-if="match.url"
                      class="task-result-match-url"
                      :href="match.url"
                      target="_blank"
                      rel="noopener noreferrer"
                      >{{ match.url }}</a
                    >
                  </div>
                </div>
              </div>
              <p v-else class="task-result-empty">未产生可展示的结构化条目。</p>
            </template>
            <template v-else>
              <p class="task-result-empty">
                结果不是结构化数据，已展示原始内容。
              </p>
              <FluentCodeBlock
                title="原始数据"
                :content="prettyDetailResultJson"
                icon="document"
                :max-rows="16"
              />
            </template>
          </template>

          <FluentCodeBlock
            v-else
            title="原始数据"
            :content="prettyDetailResultJson"
            icon="document"
            :max-rows="16"
          />
        </div>
      </el-descriptions-item>
      <el-descriptions-item label="终止原因">{{
        detail.terminationReason || "未终止"
      }}</el-descriptions-item
      ><el-descriptions-item label="超时时间">{{
        detail.timeoutAt ? formatDateTime(detail.timeoutAt) : "无"
      }}</el-descriptions-item>
      <el-descriptions-item label="进入队列">{{
        detail.queueEnteredAt ? formatDateTime(detail.queueEnteredAt) : "未记录"
      }}</el-descriptions-item
      ><el-descriptions-item label="开始占用资源">{{
        detail.queueStartedAt ? formatDateTime(detail.queueStartedAt) : "未开始"
      }}</el-descriptions-item>
      <el-descriptions-item label="授权目标快照" :span="2">
        <FluentCodeBlock
          :content="detail.targetSnapshotJson"
          empty-text="未记录"
          wrap
        />
      </el-descriptions-item>
      <el-descriptions-item label="允许端口快照">{{
        detail.allowedPortsSnapshot || "未记录"
      }}</el-descriptions-item>
      <el-descriptions-item label="快照时间">{{
        detail.snapshotCapturedAt
          ? formatDateTime(detail.snapshotCapturedAt)
          : "未记录"
      }}</el-descriptions-item>
      <el-descriptions-item label="授权声明" :span="2">{{
        detail.authorizationStatementSnapshot || "未记录"
      }}</el-descriptions-item>
      <el-descriptions-item label="授权生效">{{
        detail.authorizationValidFromSnapshot
          ? formatDateTime(detail.authorizationValidFromSnapshot)
          : "立即生效"
      }}</el-descriptions-item>
      <el-descriptions-item label="授权到期">{{
        detail.authorizationExpiresAtSnapshot
          ? formatDateTime(detail.authorizationExpiresAtSnapshot)
          : "长期有效"
      }}</el-descriptions-item>
      <el-descriptions-item label="工具版本" :span="2"
        ><code>{{
          detail.toolVersionSnapshot || "未记录"
        }}</code></el-descriptions-item
      >
      <el-descriptions-item label="规则版本 SHA-256" :span="2"
        ><code class="snapshot-hash">{{
          detail.ruleVersionSnapshot || "不适用"
        }}</code></el-descriptions-item
      >
      <el-descriptions-item label="Nuclei 模板集合 SHA-256" :span="2"
        ><code class="snapshot-hash">{{
          detail.nucleiTemplateHashSnapshot || "不适用"
        }}</code></el-descriptions-item
      >
      <el-descriptions-item label="实时执行日志" :span="2">
        <FluentCodeBlock
          :content="formatExecutionLog(detail.executionLog)"
          empty-text="等待任务开始执行…"
          icon="clipboard-task"
          wrap
          :max-rows="18"
          live
          ariaLabel="实时执行日志"
          :textarea-ref="setLogOutput"
        />
      </el-descriptions-item>
      <el-descriptions-item label="请求参数" :span="2">
        <div class="task-result-panel">
          <div class="task-result-toolbar">
            <el-radio-group
              v-model="detailRequestView"
              size="small"
              class="task-result-switch"
            >
              <el-radio-button value="friendly">直观视图</el-radio-button>
              <el-radio-button value="raw">原始数据</el-radio-button>
            </el-radio-group>
          </div>

          <p v-if="!detail.requestJson" class="task-result-empty">无</p>

          <template
            v-else-if="
              detailRequestView === 'friendly' &&
              parsedDetailRequest !== undefined
            "
          >
            <div class="task-result-json-friendly">
              <FluentJsonView :value="parsedDetailRequest" />
            </div>
          </template>

          <template v-else>
            <FluentCodeBlock
              title="原始数据"
              :content="prettyDetailRequestJson"
              icon="settings"
              :max-rows="16"
            />
          </template>
        </div>
      </el-descriptions-item>
    </el-descriptions>
    <template #footer>
      <el-button @click="detailVisible = false">关闭</el-button>
    </template>
  </el-dialog>

  <!-- 定时任务指定 SAFE PoC 弹窗 -->
  <el-dialog
    v-model="schedulePocDialogVisible"
    :title="`选择 ${scheduleScannerSource} SAFE PoC`"
    class="app-dialog app-dialog--wide poc-picker-dialog"
    align-center
    destroy-on-close
    append-to-body
  >
    <div class="poc-picker-filters">
      <el-input
        v-model="scheduleDialogSearch"
        clearable
        placeholder="搜索 CVE 编号、名称或标签..."
        style="width: 280px"
        @input="onScheduleDialogSearchInput"
        @keyup.enter="handleScheduleDialogFilterChange"
        @clear="handleScheduleDialogFilterChange"
      >
        <template #prefix>
          <el-icon><Search /></el-icon>
        </template>
      </el-input>
      <el-select
        v-model="scheduleDialogSeverity"
        placeholder="严重度"
        clearable
        style="width: 130px"
        @change="handleScheduleDialogFilterChange"
      >
        <el-option label="全部严重度" value="" />
        <el-option label="严重" value="CRITICAL" />
        <el-option label="高危" value="HIGH" />
        <el-option label="中危" value="MEDIUM" />
        <el-option label="低危" value="LOW" />
        <el-option label="信息" value="INFO" />
      </el-select>
      <el-button
        type="primary"
        :icon="Search"
        @click="handleScheduleDialogFilterChange"
      >
        搜索
      </el-button>
    </div>

    <div class="poc-picker-table-wrapper" v-loading="scheduleDialogLoading">
      <el-table
        :data="scheduleDialogList"
        row-key="vulnerabilityCode"
        size="small"
        height="360"
        stripe
        @row-click="(row: VulnerabilityDefinition) => toggleScheduleDialogCode(row.vulnerabilityCode)"
      >
        <el-table-column width="45" align="center">
          <template #default="{ row }">
            <el-checkbox
              :model-value="scheduleDialogSelected.has(row.vulnerabilityCode)"
              @click.stop
              @change="toggleScheduleDialogCode(row.vulnerabilityCode)"
            />
          </template>
        </el-table-column>
        <el-table-column label="编号 / CVE" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="poc-dialog-code">{{ row.sourceExternalId || row.vulnerabilityCode }}</span>
          </template>
        </el-table-column>
        <el-table-column label="PoC / 漏洞名称" min-width="260" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="poc-dialog-name">{{ row.name }}</span>
          </template>
        </el-table-column>
        <el-table-column label="严重度" width="90" align="center">
          <template #default="{ row }">
            <el-tag size="small" :type="scheduleSeverityType(row.severity)">
              {{ severityLabel(row.severity) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="执行分级" width="95" align="center">
          <template #default="{ row }">
            <el-tag size="small" :type="scheduleSafetyType(row.scanSafety)">
              {{ scheduleSafetyLabel(row.scanSafety) }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="poc-picker-pagination">
      <el-pagination
        :current-page="scheduleDialogPage + 1"
        :page-size="scheduleDialogPageSize"
        :total="scheduleDialogTotal"
        layout="total, prev, pager, next"
        size="small"
        @current-change="handleScheduleDialogPageChange"
      />
    </div>

    <template #footer>
      <div class="app-dialog__footer-row">
        <span class="poc-dialog-count">
          已选 <b>{{ scheduleDialogSelected.size }}</b> / 50 个 SAFE PoC
        </span>
        <el-button size="small" text type="primary" @click="selectAllScheduleDialogCurrentPage">
          选中当页
        </el-button>
        <el-button size="small" text @click="deselectAllScheduleDialogCurrentPage">
          取消当页
        </el-button>
        <el-button size="small" text type="danger" @click="scheduleDialogSelected = new Set()">
          清空
        </el-button>
        <span class="app-dialog__footer-spacer" />
        <el-button @click="schedulePocDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="applyScheduleDialogSelection">
          保存选择 ({{ scheduleDialogSelected.size }})
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>

<style scoped>
.tasks-pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}
.tasks-page :deep(.el-table) {
  font-size: 14px;
}
.tasks-page :deep(.el-table th.el-table__cell) {
  font-size: 14px;
  font-weight: 600;
}
.tasks-page :deep(.el-table td.el-table__cell .cell) {
  font-size: 13px;
}
.tasks-page :deep(.el-tag) {
  font-size: 11px;
}
.tasks-page :deep(.el-button.is-link) {
  font-size: 13px;
}
.task-control-summary {
  display: flex;
  align-items: stretch;
  flex-wrap: wrap;
  margin: 0 0 14px;
  border-top: 1px solid var(--app-border);
  border-bottom: 1px solid var(--app-border);
  background: var(--app-surface-soft);
}
.task-control-summary > span {
  display: flex;
  min-width: 150px;
  flex: 1;
  flex-direction: column;
  gap: 3px;
  padding: 10px 14px;
  border-right: 1px solid var(--app-border);
}
.task-control-summary > span:last-child {
  border-right: 0;
}
.task-control-summary small {
  color: var(--app-muted);
  font-size: 11px;
}
.task-control-summary strong {
  color: var(--app-text);
  font-size: 15px;
  line-height: 1.25;
}
.task-filter-bar {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin: 14px 0 16px;
  padding: 12px 14px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card, 8px);
  background: var(--app-surface-soft);
}
.task-filter-bar .task-filter-cell {
  width: 100%;
  min-width: 0;
}
.task-filter-row {
  display: flex;
  grid-column: 1 / -1;
  align-items: center;
  gap: 10px;
}
.task-filter-row .task-filter-cell--date {
  flex: 0 0 300px;
}
.task-filter-row .task-filter-cell--search {
  flex: 1 1 220px;
}
.task-filter-clear {
  flex: none;
}
@media (max-width: 900px) {
  .task-filter-bar {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .task-filter-row {
    flex-wrap: wrap;
  }
  .task-filter-row .task-filter-cell--date,
  .task-filter-row .task-filter-cell--search {
    flex: 1 1 100%;
  }
}
.schedule-trigger {
  color: var(--app-text) !important;
  border-color: var(--app-border-strong) !important;
  background: var(--app-surface-strong) !important;
}
.schedule-trigger:hover {
  border-color: var(--app-accent) !important;
  background: var(--app-accent-soft) !important;
  color: var(--app-text) !important;
}
.live-task-progress {
  display: grid;
  grid-template-columns: minmax(90px, 1fr) minmax(72px, auto);
  align-items: center;
  gap: 9px;
  min-width: 0;
}
.live-task-progress > span {
  overflow: hidden;
  color: var(--app-text);
  font-size: 12px;
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
.detail-progress {
  width: 100%;
  grid-template-columns: minmax(160px, 1fr) minmax(110px, auto);
}
.schedule-count {
  display: inline-grid;
  min-width: 18px;
  height: 18px;
  margin-left: 6px;
  padding: 0 4px;
  place-items: center;
  border-radius: 999px;
  background: var(--app-accent-soft);
  color: var(--app-accent-dark);
  font-size: 11px;
  line-height: 18px;
}
.schedule-dialog-intro {
  margin: -4px 0 14px;
  padding: 10px 12px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-soft);
  color: var(--app-muted);
  font-size: 13px;
  line-height: 1.55;
}
.schedule-mode-picker {
  display: flex;
  flex-wrap: wrap;
}
.schedule-mode-picker :deep(.el-radio-button__inner) {
  min-width: 76px;
  color: var(--app-text);
  border-color: var(--app-border);
  background: var(--app-surface);
}
.schedule-mode-picker
  :deep(.el-radio-button__original-radio:checked + .el-radio-button__inner) {
  color: var(--system-accent-foreground);
  border-color: var(--app-accent);
  background: var(--app-accent);
  box-shadow: -1px 0 0 0 var(--app-accent);
}
.schedule-parameter-panel {
  margin: 0 0 18px;
  padding: 8px 0;
  border-top: 1px solid var(--app-border);
  border-bottom: 1px solid var(--app-border);
}
.schedule-parameter-panel :deep(.el-form-item:last-child) {
  margin-bottom: 12px;
}
.schedule-poc-policy {
  display: flex;
  width: 100%;
  align-items: flex-start;
  flex-direction: column;
}
.schedule-parameter-help {
  width: 100%;
  margin: 7px 1px 0;
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.55;
}
.schedule-poc-selector {
  width: 100%;
}
.poc-picker-wrapper {
  margin-top: 4px;
}
.poc-selected-summary-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 10px;
  background: var(--app-surface, #fff);
  border: 1px solid var(--app-border, #e2e8f0);
  border-radius: 4px;
}
.poc-selected-count-label {
  font-size: 12px;
  color: var(--app-text, #334155);
}
.poc-selected-count-label b {
  color: var(--app-accent, #0284c7);
}
.poc-selected-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
.poc-selected-tags {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 5px;
  margin-top: 6px;
}
.poc-tag-item {
  max-width: 140px;
  overflow: hidden;
  text-overflow: ellipsis;
  font-size: 11px;
}
.poc-tag-more {
  cursor: pointer;
  font-size: 11px;
}
.poc-picker-filters {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.poc-picker-filters :deep(.el-input),
.poc-picker-filters :deep(.el-select),
.poc-picker-filters :deep(.el-button),
.poc-picker-filters :deep(.el-input__wrapper),
.poc-picker-filters :deep(.el-select__wrapper) {
  height: 32px !important;
  min-height: 32px !important;
  box-sizing: border-box;
}
.poc-picker-filters :deep(.el-button) {
  display: inline-flex;
  align-items: center;
  line-height: 1;
  padding: 0 16px;
}
.poc-picker-table-wrapper {
  border: 1px solid var(--app-border, #e2e8f0);
  border-radius: 4px;
  overflow: hidden;
}
.poc-dialog-code {
  font-family: Consolas, monospace;
  font-weight: 600;
  font-size: 12px;
}
.poc-dialog-name {
  font-size: 12px;
}
.poc-picker-pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 10px;
}
.poc-dialog-count {
  font-size: 12px;
  color: var(--app-text, #334155);
}
.poc-dialog-count b {
  color: var(--app-accent, #0284c7);
}
:global(.schedule-poc-select-popper) {
  min-width: 380px !important;
  max-width: min(540px, calc(100vw - 32px)) !important;
}
:global(.schedule-poc-select-popper .el-select-dropdown__item) {
  position: relative !important;
  padding: 6px 38px 6px 14px !important;
}
:global(.schedule-poc-select-popper .el-select-dropdown__item.is-selected::after) {
  right: 14px !important;
}
.schedule-poc-option {
  display: flex;
  width: 100%;
  min-width: 0;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.schedule-poc-option > span:first-child {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.schedule-poc-option b {
  color: var(--app-text);
  font-size: 12px;
  font-weight: 600;
}
.schedule-poc-option small {
  margin-left: 7px;
  color: var(--app-muted);
  font-size: 11px;
}
.schedule-poc-option-tags {
  display: flex;
  flex: none;
  gap: 5px;
}
.schedule-poc-option-tags :deep(.el-tag) {
  height: 20px;
  font-size: 10px;
}
.schedule-poc-empty {
  padding: 10px 12px;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.55;
}
.schedule-rule-row {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  column-gap: 14px;
}
.schedule-rule-row :deep(.el-form-item) {
  min-width: 0;
  margin-bottom: 8px;
}
.schedule-rule-row :deep(.el-form-item:last-child) {
  margin-bottom: 8px;
}
.schedule-rule-row :deep(.el-time-editor),
.schedule-rule-row :deep(.el-input-number),
.schedule-rule-row :deep(.el-select) {
  width: 100%;
}
.interval-rule-row {
  grid-template-columns: minmax(120px, 160px) minmax(130px, 180px);
  justify-content: start;
}
.schedule-rule-preview {
  margin: 4px 0 18px;
  padding-top: 2px;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.5;
}
.schedule-table {
  margin-top: 4px;
}
.schedule-context {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 2px;
}
.schedule-context strong {
  overflow: hidden;
  color: var(--app-text);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.schedule-context small {
  overflow: hidden;
  color: var(--app-muted);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.schedule-tool-context {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 2px;
}
.schedule-tool-context strong {
  overflow: hidden;
  color: var(--app-text);
  font-size: 12px;
  font-weight: 500;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.schedule-tool-context small {
  overflow: hidden;
  color: var(--app-muted);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.schedule-status-context {
  display: flex;
  min-width: 0;
  align-items: flex-start;
  flex-direction: column;
  gap: 4px;
}
.schedule-status-context small {
  display: -webkit-box;
  overflow: hidden;
  color: var(--el-color-danger);
  font-size: 10px;
  line-height: 1.35;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}
.task-result-panel {
  display: flex;
  width: 100%;
  flex-direction: column;
  gap: 10px;
}
.task-result-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
}
.task-result-switch :deep(.el-radio-button__inner) {
  min-width: 78px;
  color: var(--app-text);
  border-color: var(--app-border);
  background: var(--app-surface);
}
.task-result-switch
  :deep(.el-radio-button__original-radio:checked + .el-radio-button__inner) {
  color: var(--system-accent-foreground);
  border-color: var(--app-accent);
  background: var(--app-accent);
  box-shadow: -1px 0 0 0 var(--app-accent);
}
.task-result-count {
  color: var(--app-muted);
  font-size: 12px;
}
.task-result-summary {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin: 0;
  padding: 10px 12px;
  border: 1px solid color-mix(in srgb, var(--app-accent) 24%, var(--app-border));
  border-radius: var(--fluent-radius-control);
  background: var(--app-accent-soft);
  color: var(--app-text);
  font-size: 13px;
  line-height: 1.6;
}
.task-result-summary-icon {
  flex: none;
  margin-top: 1px;
  color: var(--app-accent);
  font-size: 16px;
}
.task-result-summary-text {
  min-width: 0;
}
.task-result-json-friendly {
  max-height: 320px;
  overflow: auto;
  padding: 10px 12px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface-soft);
}
.task-result-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(96px, 1fr));
  gap: 8px;
}
.task-result-stat {
  display: flex;
  align-items: center;
  flex-direction: column;
  gap: 2px;
  padding: 8px 6px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface-soft);
}
.task-result-stat strong {
  color: var(--app-accent);
  font-size: 16px;
  line-height: 1.2;
}
.task-result-stat span {
  color: var(--app-muted);
  font-size: 11px;
}
.task-result-matches {
  display: flex;
  max-height: 280px;
  overflow: auto;
  flex-direction: column;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card);
}
.task-result-match {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 9px 12px;
  border-bottom: 1px solid var(--app-border);
}
.task-result-match:last-child {
  border-bottom: none;
}
.task-result-match-sev {
  flex: none;
}
.task-result-match-body {
  display: flex;
  min-width: 0;
  flex: 1 1 auto;
  flex-direction: column;
  gap: 2px;
}
.task-result-match-body strong {
  color: var(--app-text);
  font-size: 13px;
  font-weight: 600;
  line-height: 1.45;
}
.task-result-match-cwe {
  color: var(--app-muted);
  font-size: 11px;
}
.task-result-match-url {
  overflow: hidden;
  color: var(--app-accent);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.task-result-empty {
  margin: 0;
  padding: 12px;
  border: 1px dashed var(--app-border-strong, var(--app-border));
  border-radius: var(--fluent-radius-control);
  color: var(--app-muted);
  font-size: 12px;
  text-align: center;
}
.snapshot-hash {
  word-break: break-all;
}
/* Row actions mirror the Results Center (.finding-row-actions) so the same
   task/finding verbs read identically across the two tables. */
.task-row-actions {
  display: grid;
  width: 100%;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  align-items: center;
  gap: 6px;
  box-sizing: border-box;
}
.task-row-actions :deep(.el-button),
.task-row-actions :deep(.el-button + .el-button),
.task-row-actions :deep(.task-action) {
  width: 100% !important;
  height: 28px;
  margin: 0 !important;
  padding: 0 4px !important;
  box-sizing: border-box;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  border-color: var(--app-border-strong);
  background: var(--app-surface-strong);
  color: var(--app-text);
  font-size: 12px;
  font-weight: 600;
}
.task-row-actions :deep(.el-button > span) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 3px;
  white-space: nowrap;
}
.task-row-actions :deep(.task-action:hover),
.task-row-actions :deep(.task-action:focus-visible) {
  border-color: var(--app-accent);
  background: var(--app-accent-soft);
  color: var(--app-text);
}
.task-row-actions :deep(.task-action--ai) {
  border-color: var(--app-accent);
  background: var(--app-accent-soft);
  color: var(--app-text);
}
.task-row-actions :deep(.task-action--danger) {
  border-color: color-mix(in srgb, #b42318 58%, var(--app-border));
  color: light-dark(#8f1d17, #ffb4ab);
}
.task-row-actions :deep(.task-action--danger:hover),
.task-row-actions :deep(.task-action--danger:focus-visible) {
  border-color: #b42318;
  background: color-mix(in srgb, #b42318 12%, var(--app-surface-strong));
  color: light-dark(#7a1712, #ffd2cc);
}
.task-row-actions :deep(.el-button .el-icon) {
  font-size: 12px;
}
.disabled-target {
  float: right;
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
@media (max-width: 640px) {
  .schedule-rule-row {
    grid-template-columns: 1fr;
  }
  .schedule-mode-picker :deep(.el-radio-button__inner) {
    min-width: 0;
    padding: 9px 12px;
  }
}
</style>
