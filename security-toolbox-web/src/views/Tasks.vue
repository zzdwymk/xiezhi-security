<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from "vue";
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
import AppPagination from "../components/AppPagination.vue";
import OfflineState from "../components/OfflineState.vue";
import { useClientPagination } from "../composables/useClientPagination";
import { formatDateTime, formatExecutionLog } from "../utils/dateTime";
import { useCopilotStore } from "../stores/copilot";
import { toErrorMessage } from "../utils/errorMessage";
import {
  taskProgressIndeterminate,
  taskProgressPercentage,
  taskProgressStatus,
  taskProgressText,
} from "../utils/taskProgress";

const copilot = useCopilotStore();
const router = useRouter();

interface TaskRow {
  id: number;
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
const {
  page,
  pageSize,
  total,
  pagedItems: pagedRows,
} = useClientPagination(rows);
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
  { value: "http_security_check", label: "HTTP 常见安全检查" },
  { value: "nuclei_scan", label: "Nuclei 漏洞扫描" },
  { value: "afrog_scan", label: "Afrog PoC 扫描" },
  { value: "xray_scan", label: "Xray PoC 扫描" },
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
}

async function load() {
  const result = await safeGet<ProjectTaskRecord[]>(endpoints.tasks, []);
  rows.value = Array.isArray(result.data)
    ? result.data.map((task) => ({
        ...task,
        progress: task.progress ?? (task.status === "SUCCESS" ? 100 : 0),
      }))
    : [];
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
      ElMessage.warning("暂无 ACTIVE 状态的安全评估项目，请先启用项目");
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

function showDetail(row: TaskRow) {
  detail.value = row;
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
    const url = URL.createObjectURL(data);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `security-report-task-${taskId}.html`;
    anchor.click();
    URL.revokeObjectURL(url);
  } catch {
    ElMessage.error("报告下载失败");
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
  if (["FAILED", "TIMEOUT", "REJECTED", "CANCELLED"].includes(status))
    return "danger";
  if (status === "RUNNING") return "warning";
  return "info";
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
      <el-table-column prop="id" label="ID" width="70" />
      <el-table-column prop="toolCode" label="工具" min-width="130" />
      <el-table-column prop="targetId" label="目标" width="80" />
      <el-table-column label="状态" width="105"
        ><template #default="scope"
          ><el-tag size="small" :type="statusType(scope.row.status)">{{
            scope.row.status
          }}</el-tag></template
        ></el-table-column
      >
      <el-table-column label="进度" min-width="220"
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
      <el-table-column label="创建时间" min-width="180"
        ><template #default="scope">{{
          formatDateTime(scope.row.createdAt)
        }}</template></el-table-column
      >
      <el-table-column label="操作" width="325"
        ><template #default="scope"
          ><el-button link type="primary" @click="showDetail(scope.row)"
            >详情</el-button
          ><el-button link type="primary" @click="askCopilot(scope.row)"
            >AI 分析</el-button
          ><el-button
            v-if="['PENDING', 'RUNNING'].includes(scope.row.status)"
            link
            type="danger"
            :loading="cancelling === scope.row.id"
            @click="cancelTask(scope.row)"
            >取消</el-button
          ><el-button
            v-if="
              ['FAILED', 'TIMEOUT', 'REJECTED', 'CANCELLED'].includes(
                scope.row.status,
              )
            "
            link
            type="danger"
            :loading="retrying === scope.row.id"
            :disabled="Boolean(retrying)"
            @click="retryTask(scope.row)"
            >重试</el-button
          ><el-button
            link
            :disabled="scope.row.status !== 'SUCCESS'"
            :loading="downloading === scope.row.id"
            @click="downloadReport(scope.row.id)"
            >报告</el-button
          ></template
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
          placeholder="选择 ACTIVE 项目"
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
            :disabled="!target.enabled"
          >
            <span>{{ targetDisplayName(target) }}</span
            ><span v-if="!target.enabled" class="disabled-target">已停用</span>
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
            <el-select
              v-model="scheduleForm.pocCodes"
              class="schedule-poc-selector"
              aria-label="指定 PoC"
              multiple
              filterable
              remote
              reserve-keyword
              collapse-tags
              :max-collapse-tags="2"
              :multiple-limit="50"
              :loading="schedulePocLoading"
              :placeholder="`搜索并选择 ${scheduleScannerSource} PoC`"
              @remote-method="loadSchedulePocOptions"
              @visible-change="
                (visible: boolean) =>
                  visible && !schedulePocOptions.length && loadSchedulePocOptions()
              "
            >
              <el-option
                v-for="poc in schedulePocOptions"
                :key="poc.vulnerabilityCode"
                :label="schedulePocOptionLabel(poc)"
                :value="poc.vulnerabilityCode"
              >
                <span class="schedule-poc-option">
                  <span>
                    <b>{{ poc.name }}</b>
                    <small>{{
                      poc.sourceExternalId || poc.vulnerabilityCode
                    }}</small>
                  </span>
                  <span class="schedule-poc-option-tags">
                    <el-tag
                      size="small"
                      :type="scheduleSeverityType(poc.severity)"
                      >{{ poc.severity }}</el-tag
                    >
                    <el-tag
                      size="small"
                      :type="scheduleSafetyType(poc.scanSafety)"
                      >{{ poc.scanSafety || "SAFE" }}</el-tag
                    >
                  </span>
                </span>
              </el-option>
              <template #empty>
                <div class="schedule-poc-empty">
                  未检索到 SAFE PoC，请先在漏洞知识库同步并复核对应扫描器目录。
                </div>
              </template>
            </el-select>
            <p class="schedule-parameter-help">
              已选择 {{ scheduleForm.pocCodes.length }} / 50 个。
            </p>
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
        <el-table-column prop="id" label="ID" width="54" />
        <el-table-column label="项目 / 授权目标" min-width="220">
          <template #default="scope"
            ><div class="schedule-context">
              <strong>{{ scheduleProjectName(scope.row.projectId) }}</strong
              ><small>{{ scheduleTargetName(scope.row.targetId) }}</small>
            </div></template
          >
        </el-table-column>
        <el-table-column label="工具 / 参数" min-width="155"
          ><template #default="scope"
            ><div class="schedule-tool-context">
              <strong>{{ scheduleToolLabel(scope.row.toolCode) }}</strong>
              <small v-if="scheduleParameterSummary(scope.row)">{{
                scheduleParameterSummary(scope.row)
              }}</small>
            </div></template></el-table-column
        >
        <el-table-column label="规则" min-width="115"
          ><template #default="scope">{{
            scheduleRule(scope.row)
          }}</template></el-table-column
        >
        <el-table-column label="下次执行" min-width="145"
          ><template #default="scope">{{
            scheduleTime(scope.row.nextRunAt)
          }}</template></el-table-column
        >
        <el-table-column label="状态 / 最近错误" min-width="170"
          ><template #default="scope"
            ><div class="schedule-status-context">
              <el-tag
                size="small"
                :type="scope.row.enabled ? 'success' : 'info'"
                >{{ scope.row.enabled ? "已启用" : "已停用" }}</el-tag
              >
              <small v-if="scope.row.lastError" :title="scope.row.lastError">{{
                scope.row.lastError
              }}</small>
            </div></template
          ></el-table-column
        >
        <el-table-column label="操作" width="178" fixed="right">
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
        <pre class="task-output">{{
          detail.targetSnapshotJson || "未记录"
        }}</pre>
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
        <pre ref="logOutput" class="task-output task-live-log">{{
          formatExecutionLog(detail.executionLog) || "等待任务开始执行…"
        }}</pre>
      </el-descriptions-item>
      <el-descriptions-item label="请求参数" :span="2">
        <pre class="task-output">{{ detail.requestJson || "无" }}</pre>
      </el-descriptions-item>
      <el-descriptions-item label="执行结果" :span="2">
        <pre class="task-output">{{ detail.resultJson || "尚无结果" }}</pre>
      </el-descriptions-item>
    </el-descriptions>
    <template #footer>
      <el-button @click="detailVisible = false">关闭</el-button>
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
  padding: 14px 0 2px;
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
.task-output {
  max-height: 280px;
  margin: 0;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 12px;
}
.task-live-log {
  min-height: 180px;
  max-height: 360px;
  padding: 12px;
  border-radius: 4px;
  background: #111827;
  color: #d1fae5;
  font-family: Consolas, "Cascadia Mono", monospace;
  line-height: 1.55;
}
.snapshot-hash {
  word-break: break-all;
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
