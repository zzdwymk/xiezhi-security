<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api, type TargetedScanHit, type TargetedScanProbe } from "../api";
import { useAuthStore } from "../stores/auth";
import { formatDateTime } from "../utils/dateTime";
import { severityLabel } from "../utils/aiPresentation";
import { targetedScanPresentation } from "../utils/targetedScanPresentation";
import { toErrorMessage } from "../utils/errorMessage";
import { InfoCircle, Refresh } from "./fluentIcons";
import AppPagination from "./AppPagination.vue";
import OfflineState from "./OfflineState.vue";

interface ScanRecord {
  id: number; engine: string; packetId: number; targetId: number;
  host: string; url?: string; hitCount: number; status: string;
  message?: string; createdAt?: string;
}
interface FuzzPacketResult {
  url?: string; status?: string; message?: string; completedRequests?: number;
  results?: Array<{ payload: string; statusCode?: number; reason?: string; durationMs?: number }>;
}
interface ScanDetail {
  entry: ScanRecord;
  result?: {
    status?: string; message?: string; engine?: string;
    hits?: TargetedScanHit[]; probes?: TargetedScanProbe[];
    results?: Record<string, FuzzPacketResult>;
  } | null;
}

const props = withDefaults(
  defineProps<{
    mode?: "tasks" | "findings";
    /**
     * 嵌入到已自带来源页签与动作按钮的页面时使用：
     * 隐藏内部工具条（说明 + 引擎筛选 + 刷新），由宿主统一提供，
     * 避免同一屏出现两行几乎相同的筛选条。
     */
    bare?: boolean;
    /**
     * 作为「安全发现 / 检测任务」这类列表页页签内容时使用：
     * 表格改成与同页主表格同一套 Fluent 平面样式（无外框、表头 48px、
     * 行高与单元格内边距一致），并且顶部不再留额外间距，
     * 让页签切换前后表格位置与观感保持一致。
     */
    embedded?: boolean;
  }>(),
  { mode: "tasks", bare: false, embedded: false },
);
const isFindings = computed(() => props.mode === "findings");
const engines = computed(() => isFindings.value ? ['ZAP', 'XRAY', 'SQLMAP'] : ['ZAP', 'XRAY', 'SQLMAP', 'FUZZ']);
const auth = useAuthStore();
const route = useRoute();
const router = useRouter();
const canRead = computed(() => auth.user?.role === "ADMIN");
const rows = ref<ScanRecord[]>([]);
const page = ref(1);
const pageSize = ref(10);
const total = ref(0);
/** 由宿主 v-model 传入的引擎筛选；嵌入模式下工具条由宿主渲染。 */
const engine = defineModel<string>("engine", { default: "" });
const loading = ref(false);
const error = ref("");
const detail = ref<ScanDetail>();
const detailVisible = ref(false);
const detailLoading = ref(false);
const detailError = ref("");
const statusLabels: Record<string, string> = {
  RUNNING: "执行中", COMPLETED: "已完成", FAILED: "失败", TIMEOUT: "超时", CANCELLED: "已取消",
};
const statusLabel = (status?: string) => statusLabels[status || ""] || "状态待核实";
const tagType = (status: string) => status === "COMPLETED" ? "success" : status === "RUNNING" ? "primary" : status === "FAILED" ? "danger" : "warning";
const notice = computed(() => targetedScanPresentation({ ...detail.value?.entry, ...detail.value?.result }));
const detailAlertType = computed(() => {
  const entry = detail.value?.entry;
  if (entry?.status === "RUNNING") return "info";
  if (entry?.status === "FAILED") return "error";
  if (entry?.status === "COMPLETED" && !entry.hitCount && !detail.value?.result?.hits?.length) return "success";
  return "warning";
});
const busy = computed(() => rows.value.some(row => row.status === "RUNNING") ||
  (detailVisible.value && detail.value?.entry.status === "RUNNING"));
let alive = true;
let listVersion = 0;
let detailVersion = 0;
let refreshTimer: ReturnType<typeof setTimeout> | undefined;

async function load(quiet = false) {
  if (!canRead.value || !alive) return;
  const version = ++listVersion;
  if (!quiet) loading.value = true;
  try {
    const { data } = await api.get<{ content: ScanRecord[]; totalElements: number }>("/traffic/scans", {
      params: { page: page.value - 1, size: pageSize.value, engine: engine.value || undefined, findingsOnly: isFindings.value || undefined },
    });
    if (!alive || !canRead.value || version !== listVersion) return;
    rows.value = Array.isArray(data.content) ? data.content : [];
    total.value = Number(data.totalElements || 0);
    error.value = "";
  } catch (err) {
    if (alive && version === listVersion) error.value = toErrorMessage(err, "无法加载流量检测记录");
  } finally {
    if (version === listVersion) loading.value = false;
  }
}

async function loadDetail(id: number, quiet = false) {
  if (!canRead.value || !alive) return;
  const version = ++detailVersion;
  if (!quiet) {
    detail.value = undefined;
    detailLoading.value = true;
    detailVisible.value = true;
  }
  detailError.value = "";
  try {
    const { data } = await api.get<ScanDetail>(`/traffic/scans/${id}`);
    if (alive && canRead.value && version === detailVersion) detail.value = data;
  } catch (err) {
    if (alive && version === detailVersion) detailError.value = toErrorMessage(err, "无法加载流量检测详情");
  } finally {
    if (version === detailVersion) detailLoading.value = false;
  }
}

function openDetail(id: number) {
  if (String(route.query.scanId) === String(id)) void loadDetail(id);
  else void router.replace({ query: { ...route.query, source: "traffic", scanId: String(id) } });
}
function openRelated(id: number) {
  void router.push({ path: isFindings.value ? '/tasks' : '/findings', query: { source: 'traffic', scanId: String(id) } });
}
function closeDetail() {
  ++detailVersion;
  detailLoading.value = false;
  if (route.query.scanId) void router.replace({ query: { ...route.query, scanId: undefined } });
}
async function refresh() {
  await load();
  if (detailVisible.value && detail.value) await loadDetail(detail.value.entry.id, true);
}
defineExpose({ refresh, loading });
function scheduleRefresh() {
  if (refreshTimer) clearTimeout(refreshTimer);
  if (!alive || !canRead.value || !busy.value) return;
  refreshTimer = setTimeout(async () => {
    await load(true);
    if (detailVisible.value && detail.value?.entry.status === "RUNNING") {
      await loadDetail(detail.value.entry.id, true);
    }
    scheduleRefresh();
  }, 3000);
}
watch(busy, scheduleRefresh);
watch([page, pageSize, engine], () => { void load(); });
watch(engine, () => { page.value = 1; });
watch(canRead, allowed => {
  if (allowed) void load();
  else {
    ++listVersion; ++detailVersion;
    rows.value = []; detail.value = undefined; detailVisible.value = false;
    if (refreshTimer) clearTimeout(refreshTimer);
  }
}, { immediate: true });
watch(() => [route.query.scanId, canRead.value], () => {
  const id = Number(route.query.scanId);
  if (canRead.value && Number.isSafeInteger(id) && id > 0) void loadDetail(id);
}, { immediate: true });
onBeforeUnmount(() => {
  alive = false; ++listVersion; ++detailVersion;
  if (refreshTimer) clearTimeout(refreshTimer);
});
</script>

<template>
  <div
    v-if="canRead"
    class="traffic-scan-records"
    :class="{ 'is-bare': bare, 'is-embedded': embedded }"
  >
    <div v-if="!bare" class="traffic-record-toolbar">
      <div class="traffic-record-toolbar-desc">
        <el-icon class="traffic-desc-icon"><InfoCircle /></el-icon>
        <p>{{ isFindings ? '按来源检测查看已保存的告警、风险证据和修复建议。模糊测试响应异常不作为漏洞发现。' : '跟踪流量定向检测与模糊测试的执行状态，查看探针和请求执行证据。' }}</p>
      </div>
      <div class="traffic-record-toolbar-actions">
        <el-select v-model="engine" clearable placeholder="全部引擎" aria-label="流量检测引擎" style="width: 140px">
          <el-option v-for="item in engines" :key="item" :label="item === 'FUZZ' ? '模糊测试' : item" :value="item" />
        </el-select>
        <el-button :loading="loading" :icon="Refresh" @click="refresh">刷新记录</el-button>
      </div>
    </div>
    <el-alert v-if="error" class="traffic-record-error" :title="error" type="error" :closable="false" show-icon />
    <el-table
      v-loading="loading"
      :data="rows"
      row-key="id"
      class="traffic-records-table"
      :empty-text="isFindings ? '暂无包含告警的流量检测' : '暂无流量检测记录'"
      stripe
    >
      <el-table-column prop="id" :label="isFindings ? '来源记录' : '记录 ID'" width="95" align="center">
        <template #default="{ row }">
          <span class="record-id">#{{ row.id }}</span>
        </template>
      </el-table-column>
      <el-table-column label="引擎" width="115" align="center">
        <template #default="{ row }">
          <el-tag
            size="small"
            :type="row.engine === 'FUZZ' ? 'warning' : 'info'"
            effect="light"
            class="engine-tag"
          >
            {{ row.engine === 'FUZZ' ? '模糊测试' : row.engine }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column v-if="!isFindings" label="状态" width="115" align="center">
        <template #default="{ row }">
          <el-tag size="small" :type="tagType(row.status)" effect="light" class="status-tag">
            {{ statusLabel(row.status) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="目标 URL" min-width="260" show-overflow-tooltip>
        <template #default="{ row }">
          <span class="target-url-cell">{{ row.url || row.host }}</span>
        </template>
      </el-table-column>
      <el-table-column prop="hitCount" :label="isFindings ? '告警数' : '命中数'" width="95" align="center">
        <template #default="{ row }">
          <div class="hit-count-wrap">
            <el-tag
              v-if="row.hitCount > 0"
              size="small"
              type="danger"
              effect="light"
              round
              class="hit-badge"
            >
              {{ row.hitCount }}
            </el-tag>
            <span v-else class="hit-zero">0</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column v-if="!isFindings" label="开始时间" width="180" align="center">
        <template #default="{ row }">
          <span class="time-cell">{{ formatDateTime(row.createdAt) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="190" align="center">
        <template #default="{ row }">
          <div class="table-actions">
            <el-button link type="primary" size="small" @click="openDetail(row.id)">
              {{ isFindings ? '查看发现' : '执行详情' }}
            </el-button>
            <el-button
              v-if="isFindings || (row.hitCount > 0 && row.engine !== 'FUZZ')"
              link
              size="small"
              @click="openRelated(row.id)"
            >
              {{ isFindings ? '来源记录' : '查看发现' }}
            </el-button>
          </div>
        </template>
      </el-table-column>

      <template #empty>
        <div class="traffic-empty-container">
          <OfflineState
            size="compact"
            :icon="isFindings ? 'warning' : 'globe-search'"
            :title="isFindings ? '暂无包含告警的流量检测' : '暂无流量检测记录'"
            :description="
              isFindings
                ? '当流量定向检测或模糊测试命中安全告警后，将在此聚合展示'
                : '通过流量定向检测或模糊测试下发任务后，执行状态与请求证据将在此展示'
            "
          />
        </div>
      </template>
    </el-table>
    <p v-if="busy" class="traffic-record-muted">执行中的记录每 3 秒自动更新。</p>
    <AppPagination v-model:page="page" v-model:page-size="pageSize" :total="total" :page-sizes="[10, 20, 50]" @size-change="page = 1" />

    <el-dialog v-model="detailVisible" :title="isFindings ? '流量安全发现' : '流量检测执行详情'" class="app-dialog app-dialog--wide traffic-record-dialog" align-center destroy-on-close @closed="closeDetail">
      <div v-loading="detailLoading" style="min-height: 100px">
        <el-alert v-if="detailError" :title="detailError" type="error" :closable="false" show-icon />
        <template v-if="detail">
          <el-descriptions v-if="!isFindings" :column="2" border>
            <el-descriptions-item label="记录 ID">{{ detail.entry.id }}</el-descriptions-item>
            <el-descriptions-item label="引擎">{{ detail.entry.engine }}</el-descriptions-item>
            <el-descriptions-item label="状态">{{ statusLabel(detail.entry.status) }}</el-descriptions-item>
            <el-descriptions-item label="命中数">{{ detail.entry.hitCount }}</el-descriptions-item>
            <el-descriptions-item label="目标 URL" :span="2">{{ detail.entry.url || detail.entry.host }}</el-descriptions-item>
            <el-descriptions-item label="开始时间" :span="2">{{ formatDateTime(detail.entry.createdAt) }}</el-descriptions-item>
          </el-descriptions>
          <p v-else>来源记录 #{{ detail.entry.id }} · {{ detail.entry.engine }} · {{ detail.entry.url || detail.entry.host }}</p>
          <el-alert v-if="!isFindings" :title="notice.title || statusLabel(detail.entry.status)" :type="detailAlertType" :closable="false" show-icon />
          <p v-if="!isFindings && notice.guidance">{{ notice.guidance }}</p>
          <details v-if="!isFindings && notice.detail"><summary>技术详情</summary><pre>{{ notice.detail }}</pre></details>
          <p v-if="!detail.result" class="traffic-record-muted">{{ detail.entry.status === 'RUNNING' ? '检测进行中，结果会在完成后自动更新。' : '这条历史记录仅保存了执行摘要，没有完整结果快照。' }}</p>
          <template v-else>
            <p v-if="isFindings && detail.entry.status !== 'COMPLETED' && detail.result.hits?.length">以下是目前已保存的告警，本次检测未完整完成。</p>
            <article v-for="(hit, index) in isFindings ? detail.result.hits || [] : []" :key="index" class="traffic-record-hit">
              <h4>{{ hit.title }} <el-tag>{{ severityLabel(hit.severity) }}</el-tag></h4>
              <p>{{ hit.description }}</p>
              <p v-if="hit.parameter">参数：{{ hit.parameter }}</p>
              <pre v-if="hit.evidence">{{ hit.evidence }}</pre>
              <p v-if="hit.solution">修复建议：{{ hit.solution }}</p>
            </article>
            <p v-if="detail.entry.status === 'COMPLETED' && !detail.result.hits?.length && !detail.entry.hitCount && detail.entry.engine !== 'FUZZ'">本次检查未命中告警；结论仅适用于本次检查范围。</p>
            <p v-if="isFindings && !detail.result.hits?.length && detail.entry.hitCount > 0 && detail.entry.engine !== 'FUZZ'">此记录仅保存了告警数量，没有可展示的告警详情。</p>
            <p v-if="isFindings && detail.entry.engine === 'FUZZ'">模糊测试记录的是请求响应差异，不能直接确认为漏洞；请在来源记录查看执行证据。</p>
            <el-table v-if="!isFindings && detail.result.probes?.length" :data="detail.result.probes" border max-height="320">
              <el-table-column prop="name" label="探针" min-width="150" />
              <el-table-column prop="target" label="目标" min-width="180" show-overflow-tooltip />
              <el-table-column prop="payload" label="测试输入" min-width="150" show-overflow-tooltip />
              <el-table-column label="结果" width="120"><template #default="{ row }">{{ row.triggered ? '命中' : row.statusCode >= 100 ? '未命中' : '响应未确认' }}</template></el-table-column>
              <el-table-column prop="statusCode" label="HTTP 状态" width="110" />
              <el-table-column prop="note" label="说明" min-width="150" show-overflow-tooltip />
              <el-table-column prop="responseSnippet" label="响应证据" min-width="180" show-overflow-tooltip />
            </el-table>
            <article v-for="(packet, packetId) in isFindings ? {} : detail.result.results || {}" :key="packetId" class="traffic-record-hit">
              <h4>报文 #{{ packetId }} · {{ statusLabel(packet.status) }}</h4>
              <p>{{ packet.url }} · 已完成 {{ packet.completedRequests ?? packet.results?.length ?? 0 }} 次请求</p>
              <p v-if="packet.message">{{ packet.message }}</p>
              <el-table :data="packet.results || []" border max-height="320">
                <el-table-column prop="payload" label="测试输入" min-width="180" show-overflow-tooltip />
                <el-table-column prop="statusCode" label="HTTP 状态" width="110" />
                <el-table-column prop="reason" label="结果说明" min-width="180" show-overflow-tooltip />
                <el-table-column prop="durationMs" label="耗时 (ms)" width="115" />
              </el-table>
            </article>
          </template>
        </template>
      </div>
      <template #footer><el-button v-if="detail && (isFindings || (detail.entry.hitCount > 0 && detail.entry.engine !== 'FUZZ'))" type="primary" @click="openRelated(detail.entry.id)">{{ isFindings ? '来源记录' : '查看发现' }}</el-button><el-button @click="detailVisible = false">关闭</el-button></template>
    </el-dialog>
  </div>
</template>

<style scoped>
.traffic-record-toolbar {
  display: flex;
  gap: 16px;
  align-items: center;
  justify-content: space-between;
  margin: 20px 0 16px;
  padding: 12px 16px;
  background: var(--app-surface-soft, rgba(0, 0, 0, 0.02));
  border: 1px solid var(--app-border, #e2e8f0);
  border-radius: var(--fluent-radius-card, 8px);
  flex-wrap: wrap;
}
.traffic-record-toolbar-desc {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 1;
  min-width: 240px;
}
.traffic-desc-icon {
  font-size: 16px;
  color: var(--app-accent, #0078d4);
  flex-shrink: 0;
}
.traffic-record-toolbar-desc p {
  margin: 0;
  font-size: 13px;
  line-height: 1.5;
  color: var(--app-muted, #64748b);
}
.traffic-record-toolbar-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}
.traffic-record-muted {
  color: var(--app-muted);
  margin: 14px 0;
  font-size: 12.5px;
}
.traffic-record-error {
  margin: 4px 0 10px;
}
.traffic-records-table {
  width: 100%;
  border-radius: var(--fluent-radius-card, 8px);
  overflow: hidden;
  border: 1px solid var(--app-border, #e2e8f0);
  background: var(--app-surface, #ffffff);
}
.traffic-records-table :deep(th.el-table__cell) {
  background-color: var(--app-surface-soft, #f8fafc) !important;
  color: var(--app-text, #1e293b);
  font-size: 13px !important;
  font-weight: 600;
  height: 44px;
  padding: 0;
  border-bottom: 1px solid var(--app-border, #e2e8f0) !important;
}
.traffic-records-table :deep(th.el-table__cell .cell) {
  padding: 0 14px;
  font-weight: 600;
  color: var(--app-text, #334155);
}
.traffic-records-table :deep(td.el-table__cell) {
  padding: 10px 0;
  font-size: 13px;
  color: var(--app-text, #334155);
  border-bottom: 1px solid color-mix(in srgb, var(--app-border, #e2e8f0) 80%, transparent);
}
.traffic-records-table :deep(td.el-table__cell .cell) {
  padding: 0 14px;
  line-height: 1.5;
}
.traffic-records-table :deep(.el-table__row:hover > td.el-table__cell) {
  background-color: var(--app-surface-soft, rgba(0, 0, 0, 0.025)) !important;
}
.record-id {
  font-family: var(--font-mono, Consolas, Monaco, monospace);
  font-size: 12.5px;
  font-weight: 600;
  color: var(--app-muted, #64748b);
}
.engine-tag,
.status-tag {
  font-weight: 500;
  font-size: 12px;
}
.target-url-cell {
  font-family: var(--font-mono, Consolas, Monaco, monospace);
  font-size: 12.5px;
  color: var(--app-text, #1e293b);
  word-break: break-all;
}
.hit-count-wrap {
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.hit-badge {
  font-weight: 600;
  font-size: 12px;
  padding: 0 8px;
}
.hit-zero {
  color: var(--app-muted, #94a3b8);
  font-size: 13px;
}
.time-cell {
  font-size: 12.5px;
  color: var(--app-muted, #64748b);
  white-space: nowrap;
}
.table-actions {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
}
.traffic-empty-container {
  padding: 8px 0 4px;
  display: flex;
  justify-content: center;
}
/* 空态说明按单行展示：flex 子项默认收缩到内容宽度，窄容器里会把一句话折成两行。
   给足宽度让说明一行放下，过长时才自然换行。 */
.traffic-empty-container :deep(.empty-state) {
  max-width: min(100%, 620px);
}
.traffic-empty-container :deep(.empty-state p) {
  max-width: none;
}
.traffic-record-dialog :deep(.el-table) {
  font-size: 13px;
  border-radius: var(--fluent-radius-card, 6px);
  overflow: hidden;
}
.traffic-record-dialog :deep(.el-table th.el-table__cell) {
  background-color: var(--app-surface-soft, #f8fafc) !important;
  color: var(--app-text, #334155);
  font-size: 13px !important;
  font-weight: 600;
  height: 40px;
}
.traffic-record-dialog :deep(.el-table td.el-table__cell) {
  font-size: 12.5px;
  padding: 8px 0;
}
.traffic-record-hit {
  padding: 14px 0;
  border-bottom: 1px solid var(--app-border);
}
.traffic-record-hit h4 {
  display: flex;
  gap: 10px;
  align-items: center;
  margin: 0 0 12px;
}
.traffic-record-dialog .el-alert {
  margin: 16px 0;
}
pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 300px;
  overflow: auto;
}
.traffic-scan-records > :last-child {
  margin-top: 16px;
}

/* 空态作为表格的空行填充：与同页「项目发现」表格一致——空块给足高度
   （min-height 覆盖 Element Plus 默认的 60px），内容在整行宽度里居中，
   不再出现「表头下面只吊着一条扁空行」的观感。 */
.traffic-scan-records.is-embedded .traffic-records-table :deep(.el-table__empty-block) {
  min-height: 260px;
}
.traffic-scan-records.is-embedded .traffic-records-table :deep(.el-table__empty-text) {
  width: 100%;
  line-height: 1;
}
.traffic-scan-records.is-embedded .traffic-empty-container {
  display: flex;
  width: 100%;
  /* 与「项目发现」的空态同高：那边 empty-state 实测 220px。 */
  min-height: 220px;
  align-items: center;
  justify-content: center;
  padding: 0;
}
.traffic-scan-records.is-embedded .traffic-empty-container :deep(.empty-state) {
  width: 100%;
  max-width: min(100%, 620px);
  /* 与项目发现的空态同一套尺寸：空块已经在 .el-table__empty-block 里给了
     260px，这里不再叠加紧凑态的 120px 下限，让内容自然居中原有的高度。 */
  min-height: 0;
  padding: 0;
}

/* 嵌入列表页页签时：与同页主表格（.workspace-list-page > .el-table）逐项对齐。
   项目发现表在 workspace-list-page 规则下是：表头 44px、单元格 0 8px、
   `.cell` 12px 横向留白、无外框无圆角。这里原先写的是表头 48px，
   两页页签来回切时表头高度会跳一下，现统一到 44px。 */
.traffic-scan-records.is-embedded {
  display: flex;
  min-width: 0;
  flex: 1 1 auto;
  flex-direction: column;
  /* 与「项目发现」的表格顶边对齐：那边表格上方是筛选栏，页签栏到表格隔着
     筛选栏 + gap；流量发现没有筛选栏，这里补同样的上沿留白，
     两个页签来回切换时表格不会上下跳。 */
  padding-top: 14px;
}
.traffic-scan-records.is-embedded .traffic-records-table {
  flex: 0 0 auto;
  width: 100%;
  /* 与「项目发现」表格同一下限：空态时也保持一整块，不被 flex 压成一条表头。
     有数据时由行内容自然撑开；只有 1-2 行时仍保留 220px，两页页签切换不跳。 */
  min-height: 220px;
  overflow: hidden;
  border: 0;
  border-radius: 0;
  background: transparent;
  --el-table-bg-color: var(--app-surface);
  --el-table-tr-bg-color: var(--app-surface);
  --el-table-header-bg-color: var(--app-surface-soft);
  --el-table-border-color: var(--app-border);
  --el-table-row-hover-bg-color: var(--fluent3-table-hover-bg);
}
.traffic-scan-records.is-embedded .traffic-records-table :deep(.el-table__inner-wrapper) {
  border-radius: 0;
}
.traffic-scan-records.is-embedded .traffic-records-table :deep(th.el-table__cell),
.traffic-scan-records.is-embedded .traffic-records-table :deep(td.el-table__cell) {
  padding: 0;
}
.traffic-scan-records.is-embedded .traffic-records-table :deep(th.el-table__cell) {
  height: 44px;
  background: var(--app-surface-soft) !important;
  color: color-mix(in srgb, var(--app-text) 86%, transparent);
  font-size: 13px !important;
  font-weight: 600;
  border-bottom-color: var(--app-border) !important;
}
.traffic-scan-records.is-embedded .traffic-records-table :deep(td.el-table__cell) {
  /* 与「项目发现」同一套行高：那边 td 是 padding:12px 0（行高约 87px）。
     早先这里把 td padding 归零，行塌到 25px，两页表格密度明显不一致。 */
  padding: 12px 0;
  border-bottom-color: var(--app-border);
  font-size: 13px;
}
/* 单元格横向留白与同页主表格一致（Element Plus 默认 12px）：组件自身的
   14px 只保留在独立使用的场景，嵌入态不再让两页表格文字左起点错位。 */
.traffic-scan-records.is-embedded .traffic-records-table :deep(.cell) {
  padding: 0 12px;
  line-height: 1.45;
}
.traffic-scan-records.is-embedded .traffic-records-table :deep(.el-table__row:hover > td.el-table__cell) {
  background: var(--app-accent-soft) !important;
}
/* 分页在嵌入态与同页其他列表共用同一条右对齐页脚。 */
.traffic-scan-records.is-embedded > :last-child {
  display: flex;
  flex: 0 0 auto;
  justify-content: flex-end;
  margin-top: 12px;
  padding: 16px 0 0;
  border-top: var(--fluent-stroke-thin) solid var(--app-border);
}
</style>
