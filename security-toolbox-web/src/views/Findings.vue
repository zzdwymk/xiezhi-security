<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useSelectionIndicator } from "../composables/useSelectionIndicator";
import { useRoute, useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Delete as DeleteIcon,
  MagicStick,
  Sort,
  VideoPlay,
  View,
} from "../components/fluentIcons";
import {
  endpoints,
  safeGet,
  type PostScanPath,
  type ProjectFindingRecord,
  type ProjectTaskRecord,
  type ScanDiff,
  type Target,
} from "../api";
import AppPagination from "../components/AppPagination.vue";
import TrafficScanRecords from "../components/TrafficScanRecords.vue";
import { useAuthStore } from "../stores/auth";
import OfflineState from "../components/OfflineState.vue";
import { useClientPagination } from "../composables/useClientPagination";
import { formatDateTime } from "../utils/dateTime";
import { toErrorMessage } from "../utils/errorMessage";
import { useCopilotStore } from "../stores/copilot";
import { actionRiskLabel, actionStepLabel, findingTitleLabel, aiProviderLabel, aiToolLabel, severityLabel } from "../utils/aiPresentation";
import MarkdownBody from "../components/MarkdownBody.vue";

function postScanStatusLabel(status?: string) {
  const map: Record<string, string> = {
    DRAFT: "待执行",
    DISPATCHED: "已下发",
    EXPIRED: "已过期",
  };
  return (status && map[status]) || "未知状态";
}

function riskLevelLabel(risk?: string) {
  return actionRiskLabel(risk);
}

function confidenceLabel(confidence?: string) {
  return ({ HIGH: "高", MEDIUM: "中", LOW: "低" } as Record<string, string>)[confidence || ""] || "未评估";
}

function phaseLabel(phase?: string) {
  const map: Record<string, string> = {
    RECONNAISSANCE: "侦察阶段",
    recon: "侦察阶段",
    MAPPING: "资产测绘",
    mapping: "资产测绘",
    VULNERABILITY_DISCOVERY: "漏洞发现",
    discovery: "漏洞发现",
    VALIDATION: "受控验证",
    validation: "受控验证",
    IMPACT_ASSESSMENT: "影响评估",
    impact: "影响评估",
    REMEDIATION: "修复核验",
    retest: "修复核验",
    REPORTING: "报告交付",
    report: "报告交付",
    "Web 基线": "网页安全基线",
    "Web 相邻风险": "网页关联风险",
  };
  if (!phase) return "未指定阶段";
  return map[phase] || (/[\u4e00-\u9fff]/.test(phase) ? phase : "未知阶段");
}

function diffChangeLabel(type?: string) {
  const labels: Record<string, string> = {
    ADDED: "新增",
    RESOLVED: "已修复",
    PERSISTENT: "持续存在",
    SEVERITY_CHANGED: "等级变化",
  };
  return (type && labels[type]) || "未知变化";
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
  };
  return (status && labels[status]) || "未知状态";
}

const copilot = useCopilotStore();
const router = useRouter();
const route = useRoute();
const auth = useAuthStore();
const canReadTraffic = computed(() => auth.user?.role === "ADMIN");
// 发现来源页签：项目发现（本页表格）与流量发现（TrafficScanRecords）。
const FINDING_SOURCES = [
  { name: "project", label: "项目发现" },
  { name: "traffic", label: "流量发现" },
] as const;
const recordSource = computed({
  get: () => canReadTraffic.value && route.query.source === "traffic" ? "traffic" : "project",
  set: (source: string) => { void router.replace({ query: {
    ...route.query, source: source === "traffic" ? "traffic" : undefined, scanId: undefined,
  } }); },
});

/* 来源页签的选中条（项目发现 / 流量发现）
   版式与「检测任务」页的来源页签完全一致：同一个 Element Plus 页签组件、
   同一套字号/字重/内边距/行高、同一条 1px 底部分割线，选中条也采用组件
   自带的 3px 主色下划线（.el-tabs__active-bar，宽度与位移由 Element Plus
   自己的 Fluent 过渡完成）。
   之前这里自绘了一条 2px 下划线并额外套了一层 44px 页签 + 16px 上边距 +
   内容区淡入淡出，视觉与动画节奏都与检测任务页对不上，现统一回组件默认。 */
const tabsWrap = ref<HTMLElement | null>(null);
useSelectionIndicator({
  container: tabsWrap,
  activeSelector: ".findings-source-tab.is-active",
  indicatorSelector: ".findings-source-indicator",
  dependencies: [recordSource, canReadTraffic],
  orientation: "horizontal",
  sizeRatio: 1,
  minSize: 0,
  thickness: 2,
  edgeInset: 1,
});


interface FindingRow {
  id: number;
  taskId: number;
  targetId: number;
  projectId?: number;
  title: string;
  severity: string;
  status: string;
  sourceTool: string;
  description: string;
  evidence: string;
  remediation: string;
  createdAt: string;
}

const rows = ref<FindingRow[]>([]);
const offline = ref(false);
const detail = ref<FindingRow>();
const detailVisible = ref(false);
const loading = ref(false);
const deleting = ref<number>();
const retesting = ref<number>();
const diffVisible = ref(false);
const diffLoading = ref(false);
const diff = ref<ScanDiff>();
const diffItems = computed(() => diff.value?.items || []);
const {
  page: diffPage,
  pageSize: diffPageSize,
  pagedItems: pagedDiffItems,
  resetPage: resetDiffPage,
} = useClientPagination(diffItems);
const diffForm = ref<{ baselineTaskId?: number; currentTaskId?: number }>({});
const taskOptions = ref<ProjectTaskRecord[]>([]);
const taskOptionsLoading = ref(false);
const clearing = ref(false);

async function loadTaskOptions() {
  taskOptionsLoading.value = true;
  const result = await safeGet(endpoints.tasks, [] as ProjectTaskRecord[]);
  taskOptions.value = result.data;
  taskOptionsLoading.value = false;
}

watch(diffVisible, (visible) => {
  if (visible) loadTaskOptions();
});
const postScanVisible = ref(false);
const postScanLoading = ref(false);
const postScanRefreshing = ref(false);
const postScanExecuting = ref(false);
const postScanPlan = ref<PostScanPath>();
const selectedPostScanSteps = ref<string[]>([]);
const page = ref(1);
// Keep the result center compact and predictable: ten findings per page.
const pageSize = ref(10);
const total = ref(0);
const targets = ref<Target[]>([]);

const searchQuery = ref(
  typeof route.query.q === "string" ? route.query.q.trim() : "",
);
const categoryFilter = ref<"" | "vulnerability" | "risk">(
  typeof route.query.category === "string" && ["vulnerability", "risk"].includes(route.query.category)
    ? (route.query.category as "vulnerability" | "risk")
    : "",
);
const targetFilter = ref<number | undefined>(
  route.query.targetId ? Number(route.query.targetId) : undefined,
);
const taskFilter = computed(() => {
  const value = Number(route.query.taskId);
  return Number.isSafeInteger(value) && value > 0 ? value : undefined;
});

function clearTaskFilter() {
  void router.replace({ query: { ...route.query, taskId: undefined } });
}

function showSourceTask(taskId: number) {
  void router.push({ path: "/tasks", query: { taskId: String(taskId) } });
}
const severityFilter = ref<string>(
  typeof route.query.severity === "string" ? route.query.severity : "",
);
const statusFilter = ref<string>(
  typeof route.query.status === "string" ? route.query.status : "",
);
const findingSort = ref("time-desc");
const FINDING_SORT_OPTIONS = [
  { label: "时间从新到旧", value: "time-desc" },
  { label: "时间从旧到新", value: "time-asc" },
  { label: "严重度从高到低", value: "sev-desc" },
  { label: "严重度从低到高", value: "sev-asc" },
  { label: "ID 从大到小", value: "id-desc" },
  { label: "ID 从小到大", value: "id-asc" },
  { label: "标题 A-Z", value: "title-asc" },
];

const hasActiveFilters = computed(() =>
  Boolean(
    searchQuery.value.trim() ||
      categoryFilter.value ||
      targetFilter.value !== undefined ||
      taskFilter.value !== undefined ||
      severityFilter.value ||
      statusFilter.value,
  ),
);

function resetFilters() {
  if (taskFilter.value !== undefined) clearTaskFilter();
  searchQuery.value = "";
  categoryFilter.value = "";
  targetFilter.value = undefined;
  severityFilter.value = "";
  statusFilter.value = "";
  page.value = 1;
  void load();
}

async function loadTargets() {
  const result = await safeGet<Target[]>(endpoints.targets, []);
  targets.value = result.data || [];
}

let searchTimer: ReturnType<typeof setTimeout> | undefined;
let loadSequence = 0;

interface FindingPage {
  content: ProjectFindingRecord[];
  totalElements: number;
}

async function load() {
  const sequence = ++loadSequence;
  loading.value = true;
  try {
    const result = await safeGet<FindingPage>(
      () =>
        endpoints.findings(
          page.value - 1,
          pageSize.value,
          searchQuery.value.trim(),
          targetFilter.value,
          severityFilter.value || undefined,
          statusFilter.value || undefined,
          categoryFilter.value || undefined,
          findingSort.value,
          taskFilter.value,
        ),
      { content: [], totalElements: 0 },
    );
    if (sequence !== loadSequence) return;
    const nextTotal = Number(result.data?.totalElements || 0);
    const lastPage = Math.max(1, Math.ceil(nextTotal / pageSize.value));
    if (!result.offline && nextTotal > 0 && page.value > lastPage) {
      page.value = lastPage;
      await load();
      return;
    }
    rows.value = Array.isArray(result.data?.content)
      ? result.data.content.map((item) => ({
          ...item,
          description: item.description ?? "",
          evidence: item.evidence ?? "",
          remediation: item.remediation ?? "",
        }))
      : [];
    total.value = nextTotal;
    offline.value = result.offline;
  } finally {
    if (sequence === loadSequence) loading.value = false;
  }
}

async function updateStatus(row: FindingRow, status: string) {
  try {
    const { data } = await endpoints.updateFindingStatus(row.id, status);
    Object.assign(row, data);
    ElMessage.success("状态已更新");
  } catch {
    ElMessage.error("状态更新失败");
  }
}

async function deleteFinding(row: FindingRow) {
  try {
    await ElMessageBox.confirm(
      `确定删除“${row.title}”吗？删除后无法恢复。`,
      "删除结果",
      {
        confirmButtonText: "删除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  deleting.value = row.id;
  try {
    await endpoints.deleteFinding(row.id);
    if (detail.value?.id === row.id) {
      detailVisible.value = false;
      detail.value = undefined;
    }
    if (rows.value.length === 1 && page.value > 1) page.value -= 1;
    await load();
    ElMessage.success("结果已删除");
  } catch {
    ElMessage.error("删除失败，请稍后重试");
  } finally {
    deleting.value = undefined;
  }
}

async function retestFinding(row: FindingRow) {
  retesting.value = row.id;
  try {
    const { data } = await endpoints.retestFinding(row.id);
    ElMessage.success(`已创建漏洞复测任务 #${data.retestTaskId}`);
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "创建复测任务失败"));
  } finally {
    retesting.value = undefined;
  }
}

async function loadDiff() {
  const baseline = Number(diffForm.value.baselineTaskId);
  const current = Number(diffForm.value.currentTaskId);
  if (
    !Number.isSafeInteger(baseline) ||
    !Number.isSafeInteger(current) ||
    baseline <= 0 ||
    current <= 0
  ) {
    ElMessage.warning("请输入两个有效的成功任务 ID");
    return;
  }

  diffLoading.value = true;
  try {
    diff.value = (await endpoints.scanDiff(baseline, current)).data;
    resetDiffPage();
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "扫描差异获取失败"));
  } finally {
    diffLoading.value = false;
  }
}

async function clearFindings() {
  if (!total.value) return;
  try {
    await ElMessageBox.confirm(
      `确定清空全部 ${total.value} 条结果吗？该操作无法恢复。`,
      "清空安全发现",
      {
        confirmButtonText: "全部清空",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  clearing.value = true;
  try {
    await endpoints.clearFindings();
    page.value = 1;
    rows.value = [];
    total.value = 0;
    detailVisible.value = false;
    detail.value = undefined;
    ElMessage.success("安全发现已清空");
  } catch {
    ElMessage.error("清空失败，请稍后重试");
  } finally {
    clearing.value = false;
  }
}

function severityType(severity: string) {
  if (severity === "CRITICAL" || severity === "HIGH") return "danger";
  if (severity === "MEDIUM") return "warning";
  if (severity === "LOW") return "primary";
  return "info";
}

function pathRiskType(risk: string) {
  if (risk === "CRITICAL" || risk === "HIGH" || risk === "BLOCKED")
    return "danger";
  if (risk === "MEDIUM" || risk === "CAUTION") return "warning";
  return "success";
}

function askCopilot(row: FindingRow) {
  copilot.prepare({
    targetId: row.targetId,
    refs: [
      { type: "finding", id: row.id, targetId: row.targetId, title: row.title },
    ],
    mode: "remediate",
    prompt:
      "复核这个风险发现的可信度与业务影响，给出证据核验清单、修复方案、回归验证步骤和优先级。",
  });
  void router.push("/");
}

async function generatePostScanPath(row: FindingRow) {
  if (!row.projectId) {
    ElMessage.error("该发现缺少项目信息，无法生成后续验证路径");
    return;
  }
  postScanVisible.value = true;
  postScanLoading.value = true;
  postScanPlan.value = undefined;
  selectedPostScanSteps.value = [];
  try {
    const { data } = await endpoints.createPostScanPath({
      projectId: row.projectId,
      targetId: row.targetId,
      findingIds: [row.id],
      objective:
        "根据当前扫描发现生成下一步授权渗透验证路径，并编排可自动执行的低风险步骤。",
    });
    postScanPlan.value = data;
    selectedPostScanSteps.value = data.steps
      .filter((step) => step.automated && step.riskLevel === "SAFE")
      .map((step) => step.id);
  } catch (error: any) {
    postScanVisible.value = false;
    ElMessage.error(toErrorMessage(error, "无法生成后续验证路径"));
  } finally {
    postScanLoading.value = false;
  }
}

async function refreshPostScanPath() {
  const id = postScanPlan.value?.id;
  if (!id || postScanRefreshing.value) return;
  postScanRefreshing.value = true;
  try {
    const { data } = await endpoints.postScanPath(id);
    if (postScanPlan.value?.id !== id) return;
    postScanPlan.value = data;
    selectedPostScanSteps.value = selectedPostScanSteps.value.filter((stepId) =>
      data.steps.some((step) => step.id === stepId && step.automated && step.riskLevel === "SAFE"),
    );
  } catch (error: unknown) {
    ElMessage.error(toErrorMessage(error, "无法读取已保存的验证路径"));
  } finally {
    postScanRefreshing.value = false;
  }
}

async function executePostScanPath() {
  const plan = postScanPlan.value;
  if (!plan || !selectedPostScanSteps.value.length)
    return ElMessage.warning("请至少选择一个安全自动化步骤");
  const selected = plan.steps.filter((step) =>
    selectedPostScanSteps.value.includes(step.id),
  );
  try {
    await ElMessageBox.confirm(
      `将对授权目标 #${plan.targetId} 自动执行 ${selected.length} 个低风险后续验证步骤：${selected.map((step) => actionStepLabel(step.toolCode, step.title)).join("、")}。服务端会再次校验漏洞归属、目标授权、端口范围和工具白名单。`,
      "确认自动执行后续验证",
      {
        confirmButtonText: "确认执行",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    postScanExecuting.value = true;
    const { data } = await endpoints.confirmPostScanPath(plan.id, {
      acknowledged: true,
      selectedStepIds: selectedPostScanSteps.value,
    });
    postScanPlan.value = data;
    ElMessage.success(
      `已创建 ${data.taskIds.length} 个后续验证任务，请在“检测任务”查看进度`,
    );
  } catch (error: any) {
    if (error !== "cancel" && error !== "close") {
      ElMessage.error(toErrorMessage(error, "后续验证执行失败"));
    }
  } finally {
    postScanExecuting.value = false;
  }
}

onMounted(() => {
  void loadTargets();
  const seedQ = route.query.q;
  if (typeof seedQ === "string" && seedQ) searchQuery.value = seedQ.trim();
  if (typeof route.query.severity === "string")
    severityFilter.value = route.query.severity.trim();
  if (
    typeof route.query.category === "string" &&
    ["vulnerability", "risk"].includes(route.query.category)
  )
    categoryFilter.value = route.query.category as "vulnerability" | "risk";
  if (route.query.targetId) targetFilter.value = Number(route.query.targetId);
  if (typeof route.query.status === "string")
    statusFilter.value = route.query.status.trim();
  load();
});

watch(
  () => [
    route.query.q,
    route.query.severity,
    route.query.category,
    route.query.targetId,
    route.query.status,
  ],
  ([q, sev, cat, tid, st]) => {
    if (typeof q === "string") searchQuery.value = q.trim();
    if (typeof sev === "string") severityFilter.value = sev.trim();
    if (typeof cat === "string" && ["vulnerability", "risk"].includes(cat))
      categoryFilter.value = cat as "vulnerability" | "risk";
    if (tid) targetFilter.value = Number(tid);
    if (typeof st === "string") statusFilter.value = st.trim();
  },
);

watch(
  [targetFilter, taskFilter, categoryFilter, severityFilter, statusFilter, findingSort],
  () => {
    page.value = 1;
    void load();
  },
);

watch(searchQuery, () => {
  page.value = 1;
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => void load(), 250);
});

onBeforeUnmount(() => {
  if (searchTimer) clearTimeout(searchTimer);
});
</script>

<template>
  <section class="panel findings-page workspace-list-page" v-loading="loading && recordSource === 'project'">
    <div class="section-head">
      <div>
        <h3>安全发现</h3>
        <p>统一管理全量授权目标的漏洞发现、安全基线风险与技术证据。</p>
      </div>
      <div v-if="recordSource === 'project'" class="finding-head-actions section-head-actions">
        <el-button @click="load">刷新</el-button>
        <el-button type="warning" plain @click="diffVisible = true"
          >扫描差异</el-button
        >
        <el-button
          type="danger"
          plain
          :disabled="!total"
          :loading="clearing"
          @click="clearFindings"
          >清空</el-button
        >
      </div>
    </div>

    <!-- 来源页签：与「检测任务」页同构——同一个 el-tabs、同样的页签样式、
         同样的 1px 底部分割线；指示条也交给组件自带的 3px 下划线。
         页签栏与内容之间不再留额外间距（组件 header 默认 margin-bottom 已清零）。 -->
    <el-tabs
      v-if="canReadTraffic"
      ref="tabsWrap"
      v-model="recordSource"
      class="findings-source-tabs"
      aria-label="发现来源"
    >
      <el-tab-pane
        v-for="item in FINDING_SOURCES"
        :key="item.name"
        :label="item.label"
        :name="item.name"
      />
    </el-tabs>
    <Transition name="findings-pane" mode="out-in">
      <div v-if="recordSource === 'traffic'" key="traffic" class="findings-source-pane">
        <!-- 流量发现与项目发现各自占满页签下方空间：两者共用一条页签栏，
             内容区贴近页签栏，不再让固定的筛选工具栏把“流量发现”的表格往下压。 -->
        <!-- 嵌入态：隐藏组件自带工具条、表格改用列表页的平面样式，
             让切页签前后表格顶边与列样式不跳动。 -->
        <TrafficScanRecords mode="findings" bare embedded />
      </div>
      <div v-else key="project" class="findings-source-pane">
    <!-- 多维组合检索与过滤栏：版式与「检测任务」页 .task-filter-bar 一致——
         五列网格，前四列是筛选下拉，第五列是「时间区间 / 排序 + 搜索」组合；
         10px 列间距、10px 12px 内边距、同样的描边/圆角/底色、同样 32px 高的控件。
         两页筛选栏因此等高、控件同宽同高、聚焦下划线同为 2px 主色。 -->
    <div class="findings-filter-toolbar" aria-label="安全发现筛选">
      <el-select
        v-model="categoryFilter"
        class="finding-filter-cell"
        clearable
        placeholder="全部类型"
        aria-label="按发现类型筛选"
      >
        <el-option label="全部类型" value="" />
        <el-option label="漏洞发现" value="vulnerability" />
        <el-option label="风险点" value="risk" />
      </el-select>
      <el-select
        v-model="targetFilter"
        class="finding-filter-cell"
        clearable
        filterable
        placeholder="全部目标"
        aria-label="按目标筛选"
      >
        <el-option
          v-for="t in targets"
          :key="t.id"
          :label="`${t.name || t.targetValue} (#${t.id})`"
          :value="t.id"
        />
      </el-select>
      <el-select
        v-model="severityFilter"
        class="finding-filter-cell"
        clearable
        placeholder="全部等级"
        aria-label="按风险等级筛选"
      >
        <el-option label="严重" value="CRITICAL" />
        <el-option label="高危" value="HIGH" />
        <el-option label="中危" value="MEDIUM" />
        <el-option label="低危" value="LOW" />
        <el-option label="提示" value="INFO" />
      </el-select>
      <el-select
        v-model="statusFilter"
        class="finding-filter-cell"
        clearable
        placeholder="全部状态"
        aria-label="按处置状态筛选"
      >
        <el-option label="待确认" value="OPEN" />
        <el-option label="已确认" value="CONFIRMED" />
        <el-option label="误报" value="FALSE_POSITIVE" />
        <el-option label="已修复" value="FIXED" />
      </el-select>
      <!-- 第五列：与「检测任务」的「开始日期 至 结束日期 + 搜任务」同构——
           发现没有独立的日期区间字段，这里把时间区间换成「排序方式」。
           「清除筛选」只在有条件时出现，与检测任务页一样挂在筛选行末尾的
           固定槽位里，收起时留出 62px，展开时筛选框自动让位，不会与控件重叠。 -->
      <div class="finding-filter-row">
        <el-select
          v-model="findingSort"
          class="finding-filter-cell finding-filter-cell--sort"
          :prefix-icon="Sort"
          aria-label="排序方式"
        >
          <el-option
            v-for="opt in FINDING_SORT_OPTIONS"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
        <el-input
          v-model="searchQuery"
          class="finding-filter-cell finding-filter-cell--search"
          placeholder="搜名称 / 等级 / 工具"
          clearable
          aria-label="按名称、等级、工具或规则搜索"
        />
        <!-- 「清除筛选」只在有条件时出现，但槽位常驻（与检测任务页
             .task-filter-clear 同款处理）：收起时留白，展开时搜索框让出宽度。 -->
        <span class="finding-filter-clear-slot">
          <el-button
            v-if="hasActiveFilters"
            class="finding-filter-clear"
            link
            type="primary"
            @click="resetFilters"
            >清除筛选</el-button
          >
        </span>
      </div>
      <!-- 来源任务筛选：仅由任务行「来源任务」跳转进来时出现。它是工具栏的
            最后一个网格项（第 6 列），与筛选行（第 5 列）各自占一格，
            两者永远不会叠在一起；窄屏时整行铺满。 -->
      <el-tag
        v-if="taskFilter !== undefined"
        closable
        class="finding-task-filter-tag"
        @close="clearTaskFilter"
      >
        来源任务 #{{ taskFilter }}
      </el-tag>
    </div>
    <!-- 空态放在表格内部（#empty）而不是顶替整张表格：表格骨架（表头列宽、
         边框、行分隔线）始终在位，空态只是表格的空行，页签切换不再整体跳动。 -->
    <el-table
      :data="rows"
      :empty-text="offline ? '无法连接后端服务。' : '任务产生的检查结果会显示在这里。'"
    >
      <template #empty>
        <OfflineState
          title="暂无风险记录"
          :description="
            offline ? '无法连接后端服务。' : '任务产生的检查结果会显示在这里。'
          "
        />
      </template>
      <el-table-column
        prop="title"
        label="名称"
        min-width="150"
        show-overflow-tooltip
      ><template #default="scope">{{ findingTitleLabel(scope.row.title, scope.row.sourceTool) }}</template></el-table-column>
      <el-table-column label="等级" width="75"
        ><template #default="scope"
          ><el-tag size="small" :type="severityType(scope.row.severity)">{{
            severityLabel(scope.row.severity)
          }}</el-tag></template
        ></el-table-column
      >
      <el-table-column label="工具" min-width="110" show-overflow-tooltip>
        <template #default="scope">
          {{ aiToolLabel(scope.row.sourceTool) }}
        </template>
      </el-table-column>
      <el-table-column prop="targetId" label="目标" width="65" />
      <el-table-column label="发现时间" min-width="140"
        ><template #default="scope">{{
          formatDateTime(scope.row.createdAt)
        }}</template></el-table-column
      >
      <el-table-column label="状态" width="115"
        ><template #default="scope"
          ><el-select
            size="small"
            :model-value="scope.row.status"
            @change="updateStatus(scope.row, $event)"
            ><el-option label="待确认" value="OPEN" /><el-option
              label="已确认"
              value="CONFIRMED" /><el-option
              label="误报"
              value="FALSE_POSITIVE" /><el-option
              label="已修复"
              value="FIXED" /></el-select></template
      ></el-table-column>
      <el-table-column label="操作" min-width="288">
        <template #default="scope">
          <div class="finding-row-actions">
            <el-button
              class="finding-action"
              size="small"
              :icon="View"
              @click="
                detail = scope.row;
                detailVisible = true;
              "
              >详情</el-button
            >
            <el-button
              class="finding-action finding-action--ai"
              size="small"
              :icon="MagicStick"
              @click="askCopilot(scope.row)"
              >AI 研判</el-button
            >
            <el-button
              class="finding-action"
              size="small"
              :icon="View"
              @click="showSourceTask(scope.row.taskId)"
              >来源任务</el-button
            >
            <el-button
              class="finding-action finding-action--ai"
              size="small"
              :icon="MagicStick"
              @click="generatePostScanPath(scope.row)"
              >后续路径</el-button
            >
            <el-button
              class="finding-action"
              size="small"
              :loading="retesting === scope.row.id"
              @click="retestFinding(scope.row)"
              >复测</el-button
            >
            <el-button
              class="finding-action finding-action--danger row-action row-action--danger"
              size="small"
              :icon="DeleteIcon"
              :loading="deleting === scope.row.id"
              @click="deleteFinding(scope.row)"
              >删除</el-button
            >
          </div>
        </template>
      </el-table-column>
    </el-table>
    <AppPagination
      v-model:page="page"
      v-model:page-size="pageSize"
      class="findings-pagination"
      :page-sizes="[10, 20, 50, 100]"
      :total="total"
      @current-change="load"
      @size-change="
        page = 1;
        load();
      "
    />
      </div>
    </Transition>
  </section>

  <el-dialog
    v-model="detailVisible"
    title="风险详情"
    class="app-dialog app-dialog--lg"
    align-center
  >
    <el-descriptions v-if="detail" :column="1" border>
      <el-descriptions-item label="名称">{{
        findingTitleLabel(detail.title, detail.sourceTool)
      }}</el-descriptions-item>
      <el-descriptions-item v-if="findingTitleLabel(detail.title, detail.sourceTool) !== detail.title" label="原始名称">{{ detail.title }}</el-descriptions-item>
      <el-descriptions-item label="说明">
        <MarkdownBody :content="detail.description || '未提供'" />
      </el-descriptions-item>
      <el-descriptions-item label="证据">
        <el-input
          :model-value="detail.evidence || '未提供'"
          type="textarea"
          :autosize="{ minRows: 1, maxRows: 12 }"
          resize="none"
          readonly
          class="finding-evidence"
        />
      </el-descriptions-item>
      <el-descriptions-item label="修复建议">
        <MarkdownBody :content="detail.remediation || '未提供'" />
      </el-descriptions-item>
    </el-descriptions>
    <template #footer
      ><el-button @click="detailVisible = false">关闭</el-button
      ><el-button
        v-if="detail"
        type="primary"
        :icon="MagicStick"
        @click="generatePostScanPath(detail)"
        >生成 AI 后续渗透路径</el-button
      ></template
    >
  </el-dialog>

  <el-dialog
    v-model="postScanVisible"
    title="AI 扫描后渗透验证路径"
    class="app-dialog app-dialog--xl"
    align-center
    destroy-on-close
  >
    <div v-loading="postScanLoading" class="post-scan-dialog">
      <template v-if="postScanPlan">
        <el-alert
          title="自动执行仅限授权目标内的低风险白名单验证。真实 PoC、命令执行、爆破、持久化和数据写入只展示人工审查思路。"
          type="warning"
          :closable="false"
          show-icon
        />
        <section class="post-scan-analysis">
          <div class="post-scan-meta">
            <el-tag size="small">{{ postScanPlan.provider === 'openai-compatible' ? '模型分析 · 规则规划' : aiProviderLabel(postScanPlan.provider) }}</el-tag
            ><el-tag size="small" type="info">{{
              postScanStatusLabel(postScanPlan.status)
            }}</el-tag>
          </div>
          <MarkdownBody class="post-scan-summary" :content="postScanPlan.analysis" />
        </section>
        <section class="post-scan-paths">
          <h4>建议验证路径</h4>
          <article v-for="path in postScanPlan.paths" :key="path.id">
            <header>
              <b>{{ path.title }}</b
              ><el-tag size="small" :type="pathRiskType(path.riskLevel)">{{
                riskLevelLabel(path.riskLevel)
              }}</el-tag
              ><el-tag size="small" type="info"
                >置信度 {{ confidenceLabel(path.confidence) }}</el-tag
              >
            </header>
            <MarkdownBody class="post-scan-prose" :content="path.goal" />
            <div v-if="path.prerequisites?.length" class="post-scan-field">
              <strong>前置条件</strong>
              <MarkdownBody :content="path.prerequisites.join('\n\n')" />
            </div>
            <div class="post-scan-field">
              <strong>证据</strong>
              <MarkdownBody :content="path.evidenceBasis || '源扫描结果'" />
            </div>
            <div class="path-limits">
              <div class="post-scan-field">
                <strong>限制</strong>
                <MarkdownBody :content="path.limitations.join('\n\n') || '未提供'" />
              </div>
              <div class="post-scan-field">
                <strong>停止条件</strong>
                <MarkdownBody :content="path.stopConditions.join('\n\n') || '未提供'" />
              </div>
            </div>
          </article>
        </section>
        <section class="post-scan-steps">
          <h4>下一步编排</h4>
          <el-alert
            v-if="!postScanPlan.steps.length"
            title="暂无可执行步骤"
            description="当前发现尚未匹配到支持的后续验证操作。上方分析仅供人工复核，尚未创建或执行任务。"
            type="info"
            :closable="false"
            show-icon
          />
          <el-checkbox-group v-else v-model="selectedPostScanSteps">
            <article
              v-for="step in postScanPlan.steps"
              :key="step.id"
              :class="{ manual: !step.automated }"
            >
              <el-checkbox
                :value="step.id"
                :disabled="
                  !step.automated ||
                  step.riskLevel !== 'SAFE' ||
                  postScanPlan.status === 'DISPATCHED'
                "
              >
                <div class="post-step-title">
                  <b>{{ actionStepLabel(step.toolCode, step.title) }}</b
                  ><span
                    ><el-tag
                      size="small"
                      :type="pathRiskType(step.riskLevel)"
                      >{{ riskLevelLabel(step.riskLevel) }}</el-tag
                    ><el-tag
                      size="small"
                      :type="step.automated ? 'success' : 'warning'"
                      >{{ step.automated ? "可自动执行" : "人工审查" }}</el-tag
                    ></span
                  >
                </div>
                <MarkdownBody class="post-scan-prose" :content="step.reason" />
                <div v-if="step.prerequisites?.length" class="post-scan-field">
                  <strong>执行前置条件</strong>
                  <MarkdownBody :content="step.prerequisites.join('\n\n')" />
                </div>
                <small
                  >{{ phaseLabel(step.phase) }} · {{
                    step.toolCode ? aiToolLabel(step.toolCode) : "无自动工具"
                  }}</small
                >
                <div class="post-scan-field">
                  <strong>预期证据</strong>
                  <MarkdownBody :content="step.expectedEvidence" />
                </div>
                <div v-if="step.impact" class="post-scan-field">
                  <strong>预期影响</strong>
                  <MarkdownBody :content="step.impact" />
                </div>
                <MarkdownBody v-if="step.blockedReason" class="blocked-reason" :content="step.blockedReason" />
              </el-checkbox>
            </article>
          </el-checkbox-group>
        </section>
        <el-result
          v-if="postScanPlan.status === 'DISPATCHED'"
          icon="success"
          title="后续验证任务已创建"
          :sub-title="`任务 ID：${postScanPlan.taskIds.join(', ')}`"
        />
      </template>
    </div>
    <template #footer
      ><el-button @click="postScanVisible = false">关闭</el-button
      ><el-button
        v-if="postScanPlan"
        :loading="postScanRefreshing"
        :disabled="postScanExecuting"
        @click="refreshPostScanPath"
        >刷新状态</el-button
      ><el-button
        v-if="postScanPlan?.status === 'DRAFT'"
        type="primary"
        :icon="VideoPlay"
        :loading="postScanExecuting"
        :disabled="!selectedPostScanSteps.length"
        @click="executePostScanPath"
        >自动执行安全步骤</el-button
      ></template
    >
  </el-dialog>

  <el-dialog
    v-model="diffVisible"
    title="扫描差异"
    class="app-dialog app-dialog--lg"
    align-center
  >
    <el-form label-position="top" inline class="diff-form">
      <el-form-item label="基线任务 ID">
        <el-select
          v-model="diffForm.baselineTaskId"
          :loading="taskOptionsLoading"
          filterable
          clearable
          placeholder="选择基线任务"
        >
          <el-option
            v-for="task in taskOptions"
            :key="task.id"
            :label="`#${task.id} · ${aiToolLabel(task.toolCode, task.toolCode)} · ${taskStatusLabel(task.status)}`"
            :value="task.id"
          />
        </el-select>
      </el-form-item>
      <el-form-item label="当前任务 ID">
        <el-select
          v-model="diffForm.currentTaskId"
          :loading="taskOptionsLoading"
          filterable
          clearable
          placeholder="选择当前任务"
        >
          <el-option
            v-for="task in taskOptions"
            :key="task.id"
            :label="`#${task.id} · ${aiToolLabel(task.toolCode, task.toolCode)} · ${taskStatusLabel(task.status)}`"
            :value="task.id"
          />
        </el-select>
      </el-form-item>
      <el-form-item class="diff-compare-item">
        <el-button type="primary" :loading="diffLoading" @click="loadDiff"
          >比较</el-button
        >
      </el-form-item>
    </el-form>
    <template v-if="diff">
      <el-alert
        :title="`新增 ${diff.summary.added} · 持续 ${diff.summary.persistent} · 已修复 ${diff.summary.resolved} · 等级变化 ${diff.summary.severityChanged}`"
        type="info"
        :closable="false"
      />
      <el-table :data="pagedDiffItems" size="small" max-height="360">
        <el-table-column label="变化" width="90">
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
        <el-table-column prop="title" label="漏洞" min-width="150" show-overflow-tooltip />
        <el-table-column label="等级" width="130"
          ><template #default="scope"
            >{{ (scope.row.previousSeverity && severityLabel(scope.row.previousSeverity)) || "-" }} →
            {{ (scope.row.currentSeverity && severityLabel(scope.row.currentSeverity)) || "-" }}</template
          ></el-table-column
        >
      </el-table>
      <AppPagination
        v-model:page="diffPage"
        v-model:page-size="diffPageSize"
        class="findings-pagination"
        :total="diffItems.length"
      />
    </template>
    <template #footer>
      <el-button @click="diffVisible = false">关闭</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.findings-page .section-head h3 {
  font-size: var(--type-section-title);
}
/* 来源页签（项目发现 / 流量发现）：与「检测任务」页 .task-source-tabs 同一套结构。
   Element Plus 页签组件的 header / nav-wrap / item / active-bar 尺寸规则全部来自
   全局样式（fluent-design-2.css 的 .el-tabs__item：32px 高、8px 左右内边距、
   14px 字号、500 字重、激活态只改颜色不加粗、选中条 3px 主色下划线），
   这里只做两件事：
   1）去掉页签内容区——两个 pane 都是空的，只作为页签数据源；
   2）压掉 header 的默认下边距，让筛选栏紧贴页签栏下方，与检测任务页一致。 */
.findings-source-tabs {
  flex: 0 0 auto;
  min-width: 0;
}
.findings-source-tabs :deep(.el-tabs__header) {
  margin: 0;
  border-bottom: 0;
}
.findings-source-tabs :deep(.el-tabs__nav-wrap)::after {
  display: none;
}
.findings-source-tabs :deep(.el-tabs__content) {
  display: none;
}
/* 页签栏自身的 1px 分隔线：与检测任务页使用同一个 --app-border 令牌。 */
.findings-source-tabs::after {
  content: "";
  display: block;
  height: 1px;
  background: var(--app-border);
}
/* 内容切换：与检测任务页一致保留淡入淡出过渡，但时长统一到 Fluent 标准档
   （150ms / --fluent-curve-standard），不再用 180ms+120ms 这种和别的页面
   对不上的组合；设置里关闭"界面动画"或系统开启"减少动态效果"时直接跳过。 */
/* 内容区（页签下方）：筛选栏、表格、分页三者的唯一间距来源。
   早先筛选栏自己 margin:0、表格也 margin:0，页面根的 --page-gap 又只作用于
   section 的直接子元素，于是筛选栏与表格贴成一片、表格被压得只剩表头。
   这里显式给出列向间距，并让表格/分页按内容占位，不再互相挤压。 */
.findings-source-pane {
  display: flex;
  min-width: 0;
  flex: 1 1 auto;
  flex-direction: column;
  gap: 14px;
}
/* 表格按内容高度撑开（空态也是完整的一行），不被 flex 压缩成一条表头。 */
.findings-source-pane > .el-table {
  flex: 0 0 auto;
  min-height: 220px;
}
.findings-source-pane > .findings-pagination {
  flex: 0 0 auto;
}
.findings-pane-enter-active,
.findings-pane-leave-active {
  transition:
    opacity var(--fluent-duration-fast, 150ms) var(--fluent-curve-standard, ease),
    transform var(--fluent-duration-fast, 150ms) var(--fluent-curve-standard, ease);
}
.findings-pane-enter-from {
  opacity: 0;
  transform: translateY(6px);
}
.findings-pane-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}
html[data-anim-decorative="off"] .findings-pane-enter-active,
html[data-anim-decorative="off"] .findings-pane-leave-active {
  transition: none !important;
}
@media (prefers-reduced-motion: reduce) {
  .findings-pane-enter-active,
  .findings-pane-leave-active {
    transition: none !important;
  }
  .findings-pane-enter-from,
  .findings-pane-leave-to {
    transform: none;
  }
}
/* 筛选栏：与「检测任务」页 .task-filter-bar 逐项对齐——
   同一套五列网格与各列比例、10px 列间距、10px 12px 内边距、
   1px 描边 + 8px 圆角 + surface-soft 底色、32px 高的控件。
   末尾额外留一列收尾槽位（第 6 列，按内容宽度）放「来源任务」标签，
   与筛选行同一行，不会把筛选栏撑高；「清除筛选」在筛选行内固定槽位。
   两页筛选栏因此等高、控件同宽同高，来回切换不会出现“跳一下”的观感。 */
.findings-filter-toolbar {
  display: grid;
  /* 六列网格：前四列筛选下拉，第五列是「排序 + 搜索 + 清除槽位」行，
     第六列放「来源任务」标签。两个收尾项各自占一格，互不重叠。 */
  grid-template-columns:
    minmax(112px, 1fr) minmax(112px, 1fr) minmax(120px, 1.15fr) minmax(120px, 1.15fr)
    minmax(300px, 1.85fr) auto;
  align-items: center;
  gap: 10px;
  margin: 0;
  padding: 10px 12px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card, 8px);
  background: var(--app-surface-soft);
}
.findings-filter-toolbar .finding-filter-cell {
  width: 100%;
  min-width: 0;
}
/* 第五列 = 排序下拉 + 搜索框 + 清除筛选槽位，三者共享可用宽度。
   宽度按 flex 分配而不是写死 basis：早期版本给排序下拉和清除槽位都写了不可压缩
   的固定宽度，搜索框成了唯一可收缩项，在 1280 下被压到 18px（placeholder 完全
   看不见）。现在排序下拉按内容宽（下限 150px，容纳“时间从新到旧”），搜索框拿
   剩余（下限 96px，保证 placeholder 可读），清除槽位固定 56px；
   空间不足时优先压缩排序下拉，输入框始终可用。 */
.finding-filter-row {
  display: flex;
  flex: 1 1 auto;
  grid-column: 5 / 6;
  min-width: 0;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}
/* 排序下拉：固定按内容宽，绝不增长、绝不压缩到 150px 以下。
   flex-basis 必须写 auto 而不是百分比——写成 44% 时它会按容器宽度增长，
   把同行的搜索框和清除按钮挤到下一行。 */
.finding-filter-row .finding-filter-cell--sort {
  flex: 0 0 auto;
  width: auto;
  min-width: 150px;
  max-width: 220px;
}
.finding-filter-row .finding-filter-cell--search {
  flex: 1 1 96px;
  min-width: 96px;
}
/* 「清除筛选」只在有条件时出现，但槽位常驻（与检测任务页 .task-filter-clear 同款
   处理）：收起时留白，展开时搜索框让出宽度，控件不会被文字压住。 */
.finding-filter-clear-slot {
  display: inline-flex;
  flex: 0 0 56px;
  align-items: center;
  justify-content: flex-end;
  min-width: 0;
}
.finding-filter-clear {
  flex: none;
  white-space: nowrap;
  font-size: 12px;
  padding: 0 4px;
}
/* 来源任务筛选：从任务行「来源任务」跳转进来时才出现。它是工具栏的最后一个
   网格项（第 6 列），与筛选行（第 5 列）各自占一格——早先它和第 5 列末端的
   「清除筛选」挤在同一条水平带上，窗口不够宽时直接叠在一起。 */
.finding-task-filter-tag.el-tag {
  --el-tag-bg-color: var(--app-accent-soft);
  --el-tag-border-color: color-mix(in srgb, var(--app-accent) 32%, transparent);
  --el-tag-text-color: var(--app-accent);
  display: inline-flex;
  flex: 0 0 auto;
  align-items: center;
  justify-content: center;
  height: 32px;
  margin: 0;
  padding: 0 6px 0 11px;
  border-radius: var(--fluent-radius-control);
  font-family: var(--fluent-font);
  font-size: 12px;
  font-weight: 600;
  line-height: 1;
  white-space: nowrap;
}
.finding-task-filter-tag.el-tag > span {
  display: inline-flex;
  align-items: center;
}
.finding-task-filter-tag.el-tag :deep(.el-tag__close) {
  margin-left: 6px;
  color: var(--app-accent);
  flex-shrink: 0;
}
.finding-task-filter-tag.el-tag :deep(.el-tag__close:hover) {
  background-color: var(--app-accent);
  color: var(--app-surface);
}
/* 仅在存在筛选条件时出现的「清除筛选」：固定在筛选行末尾槽位，字号 12px。 */

/* 中等宽度（<=1600px）：六列挤不下时，筛选行单独占满一行，
   排序下拉与搜索框在行内平分，来源任务标签跟在末尾——不会出现
   “第五列内部 wrap 成两行、和标签错位”的半吊子状态。 */
@media (max-width: 1600px) {
  .findings-filter-toolbar {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }
  .finding-filter-row {
    grid-column: 1 / -1;
    flex-wrap: nowrap;
  }
  .finding-filter-row .finding-filter-cell--sort {
    flex: 0 0 auto;
    max-width: 200px;
  }
  .finding-task-filter-tag.el-tag {
    grid-column: auto;
  }
}
@media (max-width: 1200px) {
  .findings-filter-toolbar {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .finding-filter-row {
    grid-column: 1 / -1;
    flex-wrap: wrap;
  }
  .finding-filter-row .finding-filter-cell--sort,
  .finding-filter-row .finding-filter-cell--search {
    flex: 1 1 100%;
    max-width: none;
  }
}
@media (max-width: 900px) {
  .findings-filter-toolbar {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .finding-filter-row {
    flex-wrap: wrap;
  }
  .finding-filter-row .finding-filter-cell--sort,
  .finding-filter-row .finding-filter-cell--search {
    flex: 1 1 100%;
  }
}
.diff-form {
  display: flex;
  align-items: flex-end;
  flex-wrap: wrap;
  gap: 14px;
  margin-bottom: 18px;
  padding: 16px;
  background: var(--app-surface-soft, rgba(0, 0, 0, 0.02));
  border: 1px solid var(--app-border, #e2e8f0);
  border-radius: var(--fluent-radius-card, 8px);
}
.app-dialog .diff-form :deep(.el-form-item) {
  margin-right: 0 !important;
  margin-bottom: 0 !important;
}
.diff-form :deep(.el-form-item__label) {
  font-weight: 600;
  margin-bottom: 6px;
  line-height: 1.4;
  color: var(--app-text);
}
.diff-form :deep(.el-select) {
  width: 270px;
}
.diff-compare-item {
  align-self: flex-end;
}
.diff-summary-alert {
  margin: 14px 0 16px 0;
  border-radius: var(--fluent-radius-card, 6px);
}
.findings-page .section-head p {
  font-size: var(--type-section-desc);
  line-height: 1.5;
}
.findings-page .section-head :deep(.el-button) {
  font-size: 12px;
}
.findings-page .finding-head-actions :deep(.el-input__inner) {
  font-size: 12px;
}
.findings-page :deep(.el-table) {
  font-size: 13px;
}
.findings-page :deep(.el-table th.el-table__cell) {
  font-size: 13px;
  font-weight: 600;
  height: 44px;
}
.findings-page :deep(.el-table td.el-table__cell .cell) {
  font-size: 13px;
}
.findings-page :deep(.el-table .cell) {
  line-height: 1.45;
}
.findings-page :deep(.el-tag) {
  font-size: 11px;
}
.findings-page :deep(.el-select),
.findings-page :deep(.el-button.is-link) {
  font-size: 12px;
}
.finding-row-actions {
  display: grid;
  width: 100%;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  align-items: center;
  gap: 6px;
  box-sizing: border-box;
}
/* AI actions opt out of the neutral row-button base: their accent text/border
   comes from `.finding-action--ai` in unified-theme.css. Without this the
   scoped `[data-v-…]` attribute pushes this rule to (0,4,0) and it silently
   repaints the AI buttons black — the same failure the shared `.row-actions`
   base had on the Tasks page. */
.finding-row-actions
  :deep(
    .el-button:not(.finding-action--ai),
    .el-button + .el-button:not(.finding-action--ai),
    .finding-action:not(.finding-action--ai)
  ) {
  width: 100% !important;
  height: 28px;
  margin: 0 !important;
  margin-left: 0 !important;
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
.finding-row-actions :deep(.el-button > span) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 3px;
  white-space: nowrap;
}
.finding-row-actions :deep(.finding-action:hover),
.finding-row-actions :deep(.finding-action:focus-visible) {
  border-color: var(--app-accent);
  background: var(--app-accent-soft);
  color: var(--app-text);
}
/* The AI state itself lives in unified-theme.css next to `.row-action--ai`, so
   the Findings, audit-log and task AI buttons cannot drift apart. Only the
   per-page hover surface stays here: Findings uses `--app-accent-soft` so the
   hover matches the row-action palette of the surrounding table. */
.finding-row-actions :deep(.finding-action--ai:hover),
.finding-row-actions :deep(.finding-action--ai:focus-visible) {
  border-color: var(--app-accent-dark);
  background: var(--app-accent-soft);
  color: var(--fluent-link-fg);
}
.finding-row-actions :deep(.el-button .el-icon) {
  font-size: 12px;
}
/* Fluent 2 只读文本框：完整展示证据内容，长文本自动换行 */
.finding-evidence :deep(.el-textarea__inner) {
  font-family: var(--font-mono, "Cascadia Code", "Consolas", monospace);
  font-size: 12px;
  line-height: 1.6;
  color: var(--app-text, #1e293b);
  background: light-dark(rgba(0, 0, 0, 0.03), rgba(255, 255, 255, 0.05)) !important;
  border: 0 !important;
  border-radius: var(--fluent-radius-control, 4px) !important;
  box-shadow: 0 0 0 1px light-dark(rgba(0, 0, 0, 0.08), rgba(255, 255, 255, 0.1)) inset !important;
  padding: 8px 10px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  word-break: break-word;
  resize: none;
  transition: box-shadow 150ms ease;
}
.finding-evidence :deep(.el-textarea__inner:hover) {
  box-shadow: 0 0 0 1px light-dark(rgba(0, 0, 0, 0.16), rgba(255, 255, 255, 0.18)) inset !important;
}
.finding-evidence :deep(.el-textarea__inner:focus) {
  outline: none !important;
  box-shadow:
    inset 0 0 0 1px var(--app-border-strong, #cbd5e1),
    inset 0 -2px 0 0 var(--app-accent, #0078d4) !important;
}
.finding-head-actions {
  display: flex;
  width: min(680px, 70%);
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}
.finding-head-actions :deep(.el-input) {
  min-width: 240px;
  flex: 1 1 280px;
}
.findings-pagination {
  display: flex;
  justify-content: flex-end;
  padding: 15px 16px 17px;
}
/* 空态行：给足高度，让「暂无风险记录」的空块在表格里占满一整块而不是
   被 flex 压成一条 40px 的窄行。 */
.findings-source-pane :deep(.el-table__empty-block) {
  min-height: 260px;
  padding: 24px 12px;
}
.findings-source-pane :deep(.el-table__empty-block .empty-state) {
  width: 100%;
  min-height: 0;
}
.findings-pagination :deep(.el-pagination) {
  justify-content: flex-end;
  font-size: 12px;
}
:deep(.el-descriptions) {
  font-size: 12px;
}
@media (max-width: 760px) {
  .finding-head-actions {
    width: 100%;
  }
  .finding-head-actions :deep(.el-input) {
    min-width: 100%;
  }
  .finding-head-actions :deep(.el-input__inner) {
    font-size: 12px;
  }
  .findings-pagination {
    padding: 13px 10px 15px;
  }
}
.post-scan-dialog {
  min-width: 0;
  min-height: 180px;
}
.post-scan-analysis {
  margin: 14px 0;
  padding: 14px;
  border: 1px solid var(--app-border);
  border-radius: 6px;
  background: var(--app-surface-soft);
}
.post-scan-meta {
  display: flex;
  gap: 6px;
}
.post-scan-summary {
  margin: 10px 0 0;
  color: var(--app-text);
  font-size: 13px;
  line-height: 1.75;
}
.post-scan-paths h4,
.post-scan-steps h4 {
  margin: 16px 0 9px;
  font-size: 13px;
  padding-left: 8px;
  border-left: 3px solid var(--el-color-primary);
  line-height: 1.3;
}
.post-scan-paths article,
.post-scan-steps article {
  margin-bottom: 8px;
  padding: 12px;
  border: 1px solid var(--app-border);
  border-radius: 6px;
  background: var(--app-surface);
}
.post-scan-paths header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 7px;
}
.post-scan-paths header b {
  margin-right: auto;
  font-size: 12px;
}
.post-scan-prose {
  margin: 7px 0;
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.6;
}
.post-scan-paths small,
.post-scan-steps small {
  display: block;
  color: var(--app-muted);
  font-size: 10px;
  line-height: 1.55;
}
.path-limits {
  display: grid;
  gap: 3px;
  margin-top: 7px;
  color: var(--app-muted);
  font-size: 10px;
}
.post-scan-field {
  display: grid;
  min-width: 0;
  gap: 3px;
  margin-top: 7px;
  color: var(--app-muted);
}
.post-scan-field > strong {
  font-size: 12px;
}
.post-scan-field > .markdown-body {
  color: inherit;
  font-size: 13px;
  line-height: 1.6;
}
.post-scan-steps article.manual {
  background: var(--app-surface-soft);
}
.post-scan-steps article {
  transition:
    border-color 0.2s ease,
    box-shadow 0.2s ease;
}
.post-scan-steps article:hover {
  border-color: var(--el-color-primary-light-5);
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.06);
}
.post-scan-steps :deep(.el-checkbox) {
  width: 100%;
  height: auto;
  align-items: flex-start;
}
.post-scan-steps :deep(.el-checkbox__input) {
  margin-top: 5px;
}
.post-scan-steps :deep(.el-checkbox__label) {
  width: calc(100% - 25px);
  white-space: normal;
}
.post-step-title {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  min-height: 24px;
  margin-bottom: 2px;
}
.post-step-title > b {
  color: var(--app-text);
  font-size: 13px;
  line-height: 24px;
}
.post-step-title > span {
  display: flex;
  flex: none;
  gap: 5px;
}
.post-step-title > span .el-tag {
  vertical-align: middle;
}
.post-step-title > span {
  line-height: 24px;
}
.blocked-reason {
  margin-top: 5px;
  color: var(--el-color-warning) !important;
}
.post-scan-paths article,
.post-scan-steps article {
  margin-bottom: 10px;
  padding: 14px;
}
.post-scan-prose {
  margin: 9px 0;
  font-size: 12px;
}
.post-scan-paths small,
.post-scan-steps small,
.path-limits {
  font-size: 11px;
}
</style>
