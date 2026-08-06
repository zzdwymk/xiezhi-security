<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { endpoints, safeGet, type AssessmentProject } from "../api";
import AppPagination from "../components/AppPagination.vue";
import { useClientPagination } from "../composables/useClientPagination";
import { formatDateTime } from "../utils/dateTime";

const router = useRouter();
const rows = ref<AssessmentProject[]>([]);
const loading = ref(false);
const offline = ref(false);
const keyword = ref("");

const filteredRows = computed(() => {
  const query = keyword.value.trim().toLowerCase();
  if (!query) return rows.value;
  return rows.value.filter((project) =>
    [
      project.name,
      project.owner,
      project.description,
      project.authorizationStatement,
    ].some((value) =>
      String(value || "")
        .toLowerCase()
        .includes(query),
    ),
  );
});
const {
  page,
  pageSize,
  total,
  pagedItems: pagedRows,
  resetPage,
} = useClientPagination(filteredRows);
watch(keyword, resetPage);

async function load() {
  loading.value = true;
  try {
    const result = await safeGet(endpoints.projects, [] as AssessmentProject[]);
    rows.value = result.data;
    offline.value = result.offline;
  } finally {
    loading.value = false;
  }
}

function openRecon(projectId: number) {
  router.push({ path: `/projects/${projectId}`, query: { tab: "recon" } });
}

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    ACTIVE: "进行中",
    DRAFT: "草稿",
    PAUSED: "已暂停",
    COMPLETED: "已完成",
    ARCHIVED: "已归档",
  };
  return labels[status] || status || "未知";
}

function statusType(status: string) {
  if (status === "ACTIVE") return "success";
  if (status === "PAUSED") return "warning";
  if (status === "COMPLETED" || status === "ARCHIVED") return "info";
  return undefined;
}

onMounted(load);
</script>

<template>
  <section class="panel workspace-list-page recon-hub-page">
    <div class="section-head">
      <div>
        <h3>信息收集</h3>
        <p>
          先选择安全评估项目，再在项目授权范围内收集域名、子域名、DNS、IP、HTTP、TLS、备案和网络证据。
        </p>
      </div>
      <div class="section-head-actions">
        <el-button @click="load">刷新</el-button>
        <el-button type="primary" @click="router.push('/projects')"
          >项目管理</el-button
        >
      </div>
    </div>

    <el-alert
      class="recon-scope-note"
      type="info"
      :closable="false"
      show-icon
      title="信息收集按项目组织"
      description="被动收集默认不扫描目标；主动收集、子域名枚举和同网段发现均受项目授权目标、允许端口与有效期约束。"
    />

    <div class="recon-toolbar">
      <el-input
        v-model="keyword"
        clearable
        placeholder="搜索项目、负责人或授权说明"
      />
      <span>选择项目后将直接打开"信息收集"工作区</span>
    </div>

    <el-empty
      v-if="!loading && !filteredRows.length"
      :description="
        offline
          ? '本地服务暂不可用，无法读取评估项目'
          : rows.length
            ? '没有匹配的项目'
            : '暂无评估项目，请先创建项目并加入授权目标'
      "
    >
      <el-button
        v-if="!offline && !rows.length"
        type="primary"
        @click="router.push('/projects')"
        >创建评估项目</el-button
      >
    </el-empty>

    <el-table v-else v-loading="loading" :data="pagedRows" stripe>
      <el-table-column
        prop="name"
        label="评估项目"
        min-width="220"
        show-overflow-tooltip
      />
      <el-table-column prop="owner" label="负责人" width="140">
        <template #default="scope">{{ scope.row.owner || "未填写" }}</template>
      </el-table-column>
      <el-table-column label="状态" width="110">
        <template #default="scope">
          <el-tag :type="statusType(scope.row.status)" effect="light">{{
            statusLabel(scope.row.status)
          }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="授权有效期" min-width="300">
        <template #default="scope">
          {{ formatDateTime(scope.row.authorizationValidFrom) }} 至
          {{ formatDateTime(scope.row.authorizationExpiresAt) }}
        </template>
      </el-table-column>
      <el-table-column label="操作" width="150" align="right">
        <template #default="scope">
          <el-button type="primary" @click="openRecon(scope.row.id)"
            >进入信息收集</el-button
          >
        </template>
      </el-table-column>
    </el-table>
    <AppPagination
      v-model:page="page"
      v-model:page-size="pageSize"
      class="recon-pagination"
      :total="total"
    />
  </section>
</template>

<style scoped>
.recon-scope-note {
  margin-bottom: 20px;
}

.recon-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 20px;
}

.recon-toolbar .el-input {
  width: min(420px, 100%);
}

.recon-toolbar span {
  color: var(--app-text-muted);
  font-size: 13px;
}

.recon-pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}

@media (max-width: 720px) {
  .recon-toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .recon-toolbar .el-input {
    width: 100%;
  }
}
</style>
