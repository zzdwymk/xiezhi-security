<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { MagicStick } from "../components/fluentIcons";
import { endpoints, safeGet, type PageResponse } from "../api";
import AppPagination from "../components/AppPagination.vue";
import OfflineState from "../components/OfflineState.vue";
import { formatDateTime } from "../utils/dateTime";
import {
  formatAuditAction,
  formatAuditResource,
  formatAuditResult,
  auditResultTagType,
} from "../utils/auditFormat";
import { useCopilotStore } from "../stores/copilot";

const props = defineProps<{ kind: "tasks" | "findings" | "audits" }>();
const router = useRouter();
const copilot = useCopilotStore();
const rows = ref<any[]>([]);
const offline = ref(false);
// Pagination state only applies to the audits listing.
const page = ref(1);
const pageSize = ref(20);
const total = ref(0);
const config = computed(
  () =>
    ({
      tasks: {
        title: "任务",
        empty: "暂无任务",
        cols: [
          ["toolCode", "工具"],
          ["targetId", "目标"],
          ["status", "状态"],
          ["createdAt", "创建时间"],
        ],
      },
      findings: {
        title: "风险",
        empty: "暂无风险记录",
        cols: [
          ["title", "名称"],
          ["severity", "等级"],
          ["sourceTool", "工具"],
          ["targetId", "目标"],
          ["createdAt", "发现时间"],
        ],
      },
      audits: {
        title: "审计日志",
        empty: "暂无审计记录",
        cols: [
          ["action", "操作"],
          ["resourceType", "资源"],
          ["result", "结果"],
          ["createdAt", "时间"],
        ],
      },
    })[props.kind],
);

async function load() {
  if (props.kind === "audits") {
    const result = await safeGet<PageResponse<any>>(
      () => endpoints.audits(page.value - 1, pageSize.value),
      {
        content: [],
        totalElements: 0,
        totalPages: 0,
        number: 0,
        size: pageSize.value,
      },
    );
    const data = result.data;
    const nextTotal = Number(data?.totalElements || 0);
    const lastPage = Math.max(1, Math.ceil(nextTotal / pageSize.value));
    if (!result.offline && nextTotal > 0 && page.value > lastPage) {
      page.value = lastPage;
      await load();
      return;
    }
    rows.value = Array.isArray(data?.content) ? data.content : [];
    total.value = nextTotal;
    offline.value = result.offline;
  } else {
    const result = await safeGet<any[]>((endpoints as any)[props.kind], []);
    rows.value = Array.isArray(result.data) ? result.data : [];
    offline.value = result.offline;
  }
}

function analyzeAudit(row: any) {
  const resourceType = String(row.resourceType || "").toUpperCase();
  const resourceId = Number(row.resourceId);
  const scopedTargetId =
    resourceType === "TARGET" && resourceId > 0 ? resourceId : undefined;
  const scopedProjectId =
    resourceType === "PROJECT" && resourceId > 0 ? resourceId : undefined;
  copilot.open({
    mode: "analyze",
    targetId: scopedTargetId,
    prompt:
      "请结合这条审计日志判断操作是否符合预期，并给出需要进一步核查的方向。",
    entity: {
      type: "audit",
      id: row.id,
      title: `审计记录 #${row.id}`,
      summary:
        "系统将重新读取并校验这条记录，不会发送页面中的原始详情。",
      source: "audits",
      targetId: scopedTargetId,
      data: {
        auditId: row.id,
        ...(scopedProjectId ? { projectId: scopedProjectId } : {}),
      },
    },
  });
  void router.push("/");
}

function canAnalyzeAudit(row: any) {
  const resourceType = String(row.resourceType || "").toUpperCase();
  const resourceId = Number(row.resourceId);
  return (
    Number.isSafeInteger(resourceId) &&
    resourceId > 0 &&
    (resourceType === "TARGET" || resourceType === "PROJECT")
  );
}

onMounted(load);
watch(() => props.kind, load);
</script>

<template>
  <section class="panel data-page workspace-list-page">
    <div class="section-head">
      <div>
        <h3>{{ config.title }}</h3>
        <p>共 {{ kind === "audits" ? total : rows.length }} 条记录。</p>
      </div>
      <el-button @click="load">刷新</el-button>
    </div>
    <OfflineState
      v-if="offline || !rows.length"
      :title="config.empty"
      :description="offline ? '无法连接后端服务。' : '当前没有可显示的记录。'"
    />
    <el-table v-else :data="rows">
      <template v-if="kind === 'audits'">
        <el-table-column prop="action" label="操作" min-width="160" show-overflow-tooltip>
          <template #default="scope">
            <strong>{{ formatAuditAction(scope.row.action) }}</strong>
          </template>
        </el-table-column>
        <el-table-column prop="resourceType" label="资源类型" width="130">
          <template #default="scope">
            {{ formatAuditResource(scope.row.resourceType) }}
          </template>
        </el-table-column>
        <el-table-column prop="result" label="结果" width="110">
          <template #default="scope">
            <el-tag size="small" :type="auditResultTagType(scope.row.result)" effect="light">
              {{ formatAuditResult(scope.row.result) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="operator" label="操作人" width="120" show-overflow-tooltip />
        <el-table-column prop="detail" label="详情" min-width="200" show-overflow-tooltip />
        <el-table-column prop="createdAt" label="时间" min-width="170">
          <template #default="scope">
            {{ formatDateTime(scope.row.createdAt) }}
          </template>
        </el-table-column>
      </template>
      <template v-else>
        <el-table-column
          v-for="column in config.cols"
          :key="column[0]"
          :prop="column[0]"
          :label="column[1]"
          min-width="140"
          show-overflow-tooltip
        >
          <template #default="scope">{{
            column[0] === "createdAt"
              ? formatDateTime(scope.row[column[0]])
              : scope.row[column[0]]
          }}</template>
        </el-table-column>
      </template>
      <el-table-column v-if="kind === 'audits'" label="操作" width="120">
        <template #default="scope">
          <el-button
            v-if="canAnalyzeAudit(scope.row)"
            link
            type="primary"
            :icon="MagicStick"
            @click="analyzeAudit(scope.row)"
            >AI 核查</el-button
          >
        </template>
      </el-table-column>
    </el-table>
    <AppPagination
      v-if="kind === 'audits'"
      v-model:page="page"
      v-model:page-size="pageSize"
      class="audits-pagination"
      :page-sizes="[20, 50, 100, 200]"
      :total="total"
      @current-change="load"
      @size-change="
        page = 1;
        load();
      "
    />
  </section>
</template>

<style scoped>
.data-page :deep(.el-table) {
  font-size: 14px;
}
.data-page :deep(.el-table th.el-table__cell) {
  font-size: 14px;
  font-weight: 600;
}
.data-page :deep(.el-table td.el-table__cell .cell) {
  font-size: 13px;
}
.data-page :deep(.el-table .cell) {
  line-height: 1.45;
}
.audits-pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}
</style>
