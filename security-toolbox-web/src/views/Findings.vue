<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Delete as DeleteIcon,
  Document,
  MagicStick,
  Search,
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
} from "../api";
import AppPagination from "../components/AppPagination.vue";
import OfflineState from "../components/OfflineState.vue";
import { useClientPagination } from "../composables/useClientPagination";
import { formatDateTime } from "../utils/dateTime";
import { toErrorMessage } from "../utils/errorMessage";
import { useCopilotStore } from "../stores/copilot";
import { downloadBlob, EmptyDownloadError } from "../utils/download";

const copilot = useCopilotStore();
const router = useRouter();
const route = useRoute();

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
const downloading = ref<number>();
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
const postScanExecuting = ref(false);
const postScanPlan = ref<PostScanPath>();
const selectedPostScanSteps = ref<string[]>([]);
const page = ref(1);
// Keep the result center compact and predictable: ten findings per page.
const pageSize = ref(10);
const total = ref(0);
const searchQuery = ref("");
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
    ElMessage.error(toErrorMessage(error, "扫描 Diff 获取失败"));
  } finally {
    diffLoading.value = false;
  }
}

async function clearFindings() {
  if (!total.value) return;
  try {
    await ElMessageBox.confirm(
      `确定清空全部 ${total.value} 条结果吗？该操作无法恢复。`,
      "清空结果中心",
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
    ElMessage.success("结果中心已清空");
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

async function executePostScanPath() {
  const plan = postScanPlan.value;
  if (!plan || !selectedPostScanSteps.value.length)
    return ElMessage.warning("请至少选择一个安全自动化步骤");
  const selected = plan.steps.filter((step) =>
    selectedPostScanSteps.value.includes(step.id),
  );
  try {
    await ElMessageBox.confirm(
      `将对授权目标 #${plan.targetId} 自动执行 ${selected.length} 个低风险后续验证步骤：${selected.map((step) => step.title).join("、")}。服务端会再次校验漏洞归属、目标授权、端口范围和工具白名单。`,
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
  const seed = route.query.q;
  if (typeof seed === "string" && seed) searchQuery.value = seed;
  load();
});
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
  <section class="panel findings-page workspace-list-page" v-loading="loading">
    <div class="section-head">
      <div>
        <h3>风险</h3>
        <p>查看证据并记录人工确认结果。</p>
      </div>
      <div class="finding-head-actions section-head-actions">
        <el-input
          v-model="searchQuery"
          :prefix-icon="Search"
          clearable
          placeholder="搜索名称、等级、工具、目标或状态"
        />
        <el-button @click="load">刷新</el-button>
        <el-button type="warning" plain @click="diffVisible = true"
          >扫描 Diff</el-button
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
    <OfflineState
      v-if="offline || !rows.length"
      title="暂无风险记录"
      :description="
        offline ? '无法连接后端服务。' : '任务产生的检查结果会显示在这里。'
      "
    />
    <el-table v-else :data="rows">
      <el-table-column
        prop="title"
        label="名称"
        min-width="230"
        show-overflow-tooltip
      />
      <el-table-column label="等级" width="100"
        ><template #default="scope"
          ><el-tag size="small" :type="severityType(scope.row.severity)">{{
            scope.row.severity
          }}</el-tag></template
        ></el-table-column
      >
      <el-table-column prop="sourceTool" label="工具" width="130" />
      <el-table-column prop="targetId" label="目标" width="75" />
      <el-table-column label="发现时间" min-width="180"
        ><template #default="scope">{{
          formatDateTime(scope.row.createdAt)
        }}</template></el-table-column
      >
      <el-table-column label="状态" width="155"
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
      <el-table-column label="操作" width="330">
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
              :icon="Document"
              :loading="downloading === scope.row.taskId"
              @click="downloadReport(scope.row.taskId)"
              >报告</el-button
            >
            <el-button
              class="finding-action"
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
              class="finding-action finding-action--danger"
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
  </section>

  <el-dialog
    v-model="detailVisible"
    title="风险详情"
    class="app-dialog app-dialog--lg"
    align-center
  >
    <el-descriptions v-if="detail" :column="1" border>
      <el-descriptions-item label="名称">{{
        detail.title
      }}</el-descriptions-item>
      <el-descriptions-item label="说明">{{
        detail.description || "未提供"
      }}</el-descriptions-item>
      <el-descriptions-item label="证据">
        <pre class="finding-evidence">{{ detail.evidence || "未提供" }}</pre>
      </el-descriptions-item>
      <el-descriptions-item label="修复建议">{{
        detail.remediation || "未提供"
      }}</el-descriptions-item>
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
          <div>
            <el-tag size="small">{{ postScanPlan.provider }}</el-tag
            ><el-tag size="small" type="info">{{ postScanPlan.status }}</el-tag>
          </div>
          <p>{{ postScanPlan.analysis }}</p>
        </section>
        <section class="post-scan-paths">
          <h4>建议验证路径</h4>
          <article v-for="path in postScanPlan.paths" :key="path.id">
            <header>
              <b>{{ path.title }}</b
              ><el-tag size="small" :type="pathRiskType(path.riskLevel)">{{
                path.riskLevel
              }}</el-tag
              ><el-tag size="small" type="info"
                >置信度 {{ path.confidence }}</el-tag
              >
            </header>
            <p>{{ path.goal }}</p>
            <small>证据：{{ path.evidenceBasis || "源扫描结果" }}</small>
            <div class="path-limits">
              <span>限制：{{ path.limitations.join("；") }}</span
              ><span>停止条件：{{ path.stopConditions.join("；") }}</span>
            </div>
          </article>
        </section>
        <section class="post-scan-steps">
          <h4>下一步编排</h4>
          <el-checkbox-group v-model="selectedPostScanSteps">
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
                  <b>{{ step.title }}</b
                  ><span
                    ><el-tag
                      size="small"
                      :type="pathRiskType(step.riskLevel)"
                      >{{ step.riskLevel }}</el-tag
                    ><el-tag
                      size="small"
                      :type="step.automated ? 'success' : 'warning'"
                      >{{ step.automated ? "可自动执行" : "人工审查" }}</el-tag
                    ></span
                  >
                </div>
                <p>{{ step.reason }}</p>
                <small
                  >{{ step.phase }} · {{ step.toolCode || "无自动工具" }} ·
                  预期证据：{{ step.expectedEvidence }}</small
                >
                <small v-if="step.blockedReason" class="blocked-reason">{{
                  step.blockedReason
                }}</small>
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
    title="扫描 Diff"
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
            :label="`#${task.id} · ${task.toolCode} · ${task.status}`"
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
            :label="`#${task.id} · ${task.toolCode} · ${task.status}`"
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
        <el-table-column prop="changeType" label="变化" width="120" />
        <el-table-column prop="title" label="漏洞" min-width="220" />
        <el-table-column label="等级" width="140"
          ><template #default="scope"
            >{{ scope.row.previousSeverity || "-" }} →
            {{ scope.row.currentSeverity || "-" }}</template
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
.diff-compare-item {
  align-self: flex-end;
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
  font-size: 14px;
}
.findings-page :deep(.el-table th.el-table__cell) {
  font-size: 14px;
  font-weight: 600;
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
  white-space: normal;
}
.finding-row-actions :deep(.finding-action) {
  width: 100%;
  height: 32px;
  margin: 0;
  padding: 0 8px;
  border-color: var(--app-border-strong);
  background: var(--app-surface-strong);
  color: var(--app-text);
  font-size: 12px;
  font-weight: 600;
}
.finding-row-actions :deep(.finding-action:hover),
.finding-row-actions :deep(.finding-action:focus-visible) {
  border-color: var(--app-accent);
  background: var(--app-accent-soft);
  color: var(--app-text);
}
.finding-row-actions :deep(.finding-action--ai) {
  border-color: var(--app-accent);
  background: var(--app-accent-soft);
  color: var(--app-text);
}
.finding-row-actions :deep(.finding-action--danger) {
  border-color: color-mix(in srgb, #b42318 58%, var(--app-border));
  color: light-dark(#8f1d17, #ffb4ab);
}
.finding-row-actions :deep(.finding-action--danger:hover),
.finding-row-actions :deep(.finding-action--danger:focus-visible) {
  border-color: #b42318;
  background: color-mix(in srgb, #b42318 12%, var(--app-surface-strong));
  color: light-dark(#7a1712, #ffd2cc);
}
.finding-row-actions :deep(.el-button .el-icon) {
  font-size: 12px;
}
.finding-evidence {
  max-height: 300px;
  margin: 0;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 12px;
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
  min-height: 180px;
}
.post-scan-analysis {
  margin: 14px 0;
  padding: 14px;
  border: 1px solid var(--app-border);
  border-radius: 6px;
  background: var(--app-surface-soft);
}
.post-scan-analysis > div {
  display: flex;
  gap: 6px;
}
.post-scan-analysis p {
  margin: 10px 0 0;
  color: var(--app-text);
  font-size: 13px;
  line-height: 1.75;
  white-space: pre-wrap;
}
.post-scan-paths h4,
.post-scan-steps h4 {
  margin: 16px 0 9px;
  font-size: 13px;
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
  align-items: center;
  gap: 7px;
}
.post-scan-paths header b {
  margin-right: auto;
  font-size: 12px;
}
.post-scan-paths p,
.post-scan-steps p {
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
.post-scan-steps article.manual {
  background: var(--app-surface-soft);
}
.post-scan-steps :deep(.el-checkbox) {
  width: 100%;
  height: auto;
  align-items: flex-start;
}
.post-scan-steps :deep(.el-checkbox__label) {
  width: calc(100% - 25px);
  white-space: normal;
}
.post-step-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.post-step-title > b {
  color: var(--app-text);
  font-size: 12px;
}
.post-step-title > span {
  display: flex;
  flex: none;
  gap: 5px;
}
.blocked-reason {
  margin-top: 5px;
  color: var(--app-warning) !important;
}
.post-scan-paths article,
.post-scan-steps article {
  margin-bottom: 10px;
  padding: 14px;
}
.post-scan-paths p,
.post-scan-steps p {
  margin: 9px 0;
  font-size: 12px;
}
.post-scan-paths small,
.post-scan-steps small,
.path-limits {
  font-size: 11px;
}
</style>
