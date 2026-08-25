<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import { endpoints, safeGet, type AssessmentProject } from "../api";
import AppPagination from "../components/AppPagination.vue";
import OfflineState from "../components/OfflineState.vue";
import { useClientPagination } from "../composables/useClientPagination";
import { formatDateTime } from "../utils/dateTime";
import { toErrorMessage } from "../utils/errorMessage";

const router = useRouter();
const rows = ref<AssessmentProject[]>([]);
const loading = ref(false);
const offline = ref(false);
const visible = ref(false);
const saving = ref(false);
const editVisible = ref(false);
const editSaving = ref(false);
const editingId = ref<number>();
const originalEditProject = ref<AssessmentProject>();
const projectStatusOptions = [
  { label: "草稿", value: "DRAFT" },
  { label: "进行中", value: "ACTIVE" },
  { label: "已暂停", value: "PAUSED" },
  { label: "已完成", value: "COMPLETED" },
  { label: "已归档", value: "ARCHIVED" },
];

function projectStatusLabel(status?: string) {
  const map: Record<string, string> = {
    ACTIVE: "进行中",
    DRAFT: "草稿",
    PAUSED: "已暂停",
    COMPLETED: "已完成",
    ARCHIVED: "已归档",
  };
  return (status && map[status]) || status || "未知";
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
const editForm = ref({
  name: "",
  description: "",
  authorizationStatement: "",
  authorizationValidFrom: "",
  authorizationExpiresAt: "",
  owner: "",
  status: "DRAFT",
});
const {
  page,
  pageSize,
  total,
  pagedItems: pagedRows,
} = useClientPagination(rows);
const form = ref({
  name: "",
  description: "",
  authorizationStatement: "",
  authorizationValidFrom: "",
  authorizationExpiresAt: "",
  owner: "",
});

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

async function create() {
  saving.value = true;
  try {
    await endpoints.createProject(form.value);
    visible.value = false;
    form.value = {
      name: "",
      description: "",
      authorizationStatement: "",
      authorizationValidFrom: "",
      authorizationExpiresAt: "",
      owner: "",
    };
    await load();
    ElMessage.success("项目已创建");
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "创建失败"));
  } finally {
    saving.value = false;
  }
}

function openEdit(row: AssessmentProject) {
  editingId.value = row.id;
  originalEditProject.value = { ...row };
  editForm.value = {
    name: row.name || "",
    description: row.description || "",
    authorizationStatement: row.authorizationStatement || "",
    authorizationValidFrom: row.authorizationValidFrom || "",
    authorizationExpiresAt: row.authorizationExpiresAt || "",
    owner: row.owner || "",
    status: row.status || "DRAFT",
  };
  editVisible.value = true;
}

function sameInstant(left?: string, right?: string) {
  if (!left && !right) return true;
  if (!left || !right) return false;
  const leftTime = Date.parse(left);
  const rightTime = Date.parse(right);
  return Number.isFinite(leftTime) && Number.isFinite(rightTime)
    ? leftTime === rightTime
    : left === right;
}

function projectAuthorizationChanged() {
  const original = originalEditProject.value;
  if (!original) return false;
  return (
    editForm.value.authorizationStatement !== original.authorizationStatement ||
    !sameInstant(
      editForm.value.authorizationValidFrom,
      original.authorizationValidFrom,
    ) ||
    !sameInstant(
      editForm.value.authorizationExpiresAt,
      original.authorizationExpiresAt,
    ) ||
    editForm.value.status !== original.status
  );
}

async function saveEdit() {
  if (!editingId.value) return;
  let updatingStatus = false;
  try {
    if (projectAuthorizationChanged()) {
      await ElMessageBox.confirm(
        "授权声明、授权时间窗或项目状态已经变化。保存后会影响该项目可执行的检测范围，请确认变更仍有明确授权。",
        "确认授权范围变更",
        {
          confirmButtonText: "确认并保存",
          cancelButtonText: "取消",
          type: "warning",
        },
      );
    }
    editSaving.value = true;
    const { status, ...projectFields } = editForm.value;
    await endpoints.updateProject(editingId.value, {
      ...projectFields,
      authorizationValidFrom: editForm.value.authorizationValidFrom
        ? new Date(editForm.value.authorizationValidFrom).toISOString()
        : undefined,
      authorizationExpiresAt: editForm.value.authorizationExpiresAt
        ? new Date(editForm.value.authorizationExpiresAt).toISOString()
        : undefined,
    });
    if (status !== originalEditProject.value?.status) {
      updatingStatus = true;
      await endpoints.updateProjectStatus(editingId.value, status);
    }
    editVisible.value = false;
    await load();
    ElMessage.success("项目已更新");
  } catch (error) {
    if (error === "cancel" || error === "close") return;
    if (updatingStatus) await load();
    ElMessage.error(
      toErrorMessage(
        error,
        updatingStatus ? "项目资料已保存，但状态更新失败" : "更新失败",
      ),
    );
  } finally {
    editSaving.value = false;
  }
}

onMounted(load);
</script>

<template>
  <section class="panel workspace-list-page projects-page">
    <div class="section-head">
      <div>
        <h3>安全评估项目</h3>
        <p>以项目统一管理授权范围、目标、检测任务、漏洞和审计记录。</p>
      </div>
      <div class="section-head-actions">
        <el-button type="primary" @click="visible = true"
          >新建评估项目</el-button
        >
      </div>
    </div>

    <OfflineState
      v-if="!loading && (offline || !rows.length)"
      title="暂无评估项目"
      :description="
        offline
          ? '无法连接后端服务。'
          : '创建项目后，可统一管理授权目标、检测任务和审计记录。'
      "
    />
    <el-table v-else v-loading="loading" :data="pagedRows">
      <el-table-column prop="name" label="项目名称" />
      <el-table-column prop="owner" label="负责人" width="130" />
      <el-table-column label="状态" width="130">
        <template #default="scope">
          <el-tag
            size="small"
            :type="projectStatusType(scope.row.status)"
            effect="light"
          >
            {{ projectStatusLabel(scope.row.status) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="授权有效期" min-width="230">
        <template #default="scope">
          {{ formatDateTime(scope.row.authorizationValidFrom) }} 至
          {{ formatDateTime(scope.row.authorizationExpiresAt) }}
        </template>
      </el-table-column>
      <el-table-column label="操作" width="180">
        <template #default="scope">
          <el-button
            link
            type="primary"
            @click="router.push(`/projects/${scope.row.id}`)"
          >
            进入项目
          </el-button>
          <el-button
            link
            type="primary"
            @click="openEdit(scope.row)"
          >
            编辑
          </el-button>
        </template>
      </el-table-column>
    </el-table>
    <AppPagination
      v-model:page="page"
      v-model:page-size="pageSize"
      class="projects-pagination"
      :total="total"
    />
  </section>

  <el-dialog
    v-model="visible"
    title="新建安全评估项目"
    class="app-dialog app-dialog--md project-dialog"
    align-center
    destroy-on-close
  >
    <el-form label-position="top" class="project-form">
      <div class="project-form-row">
        <el-form-item label="项目名称">
          <el-input
            v-model="form.name"
            placeholder="例如：2026 年度 Web 安全评估"
          />
        </el-form-item>
        <el-form-item label="负责人">
          <el-input v-model="form.owner" placeholder="负责人姓名或账号" />
        </el-form-item>
      </div>

      <el-form-item label="授权声明">
        <el-input
          v-model="form.authorizationStatement"
          type="textarea"
          :rows="3"
          placeholder="填写授权来源、测试范围和限制"
        />
      </el-form-item>

      <div class="project-form-row">
        <el-form-item label="授权开始">
          <el-date-picker
            v-model="form.authorizationValidFrom"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            format="YYYY-MM-DD HH:mm"
            placeholder="选择开始时间"
            :editable="false"
          />
        </el-form-item>
        <el-form-item label="授权结束">
          <el-date-picker
            v-model="form.authorizationExpiresAt"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            format="YYYY-MM-DD HH:mm"
            placeholder="选择结束时间"
            :editable="false"
          />
        </el-form-item>
      </div>

      <el-form-item label="项目说明">
        <el-input
          v-model="form.description"
          type="textarea"
          :rows="3"
          placeholder="补充项目目标、交付物和注意事项"
        />
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="visible = false">取消</el-button>
      <el-button type="primary" :loading="saving" @click="create"
        >创建项目</el-button
      >
    </template>
  </el-dialog>

  <el-dialog
    v-model="editVisible"
    title="编辑评估项目"
    class="app-dialog app-dialog--md project-dialog"
    align-center
    destroy-on-close
  >
    <el-form label-position="top" class="project-form">
      <div class="project-form-row">
        <el-form-item label="项目名称">
          <el-input
            v-model="editForm.name"
            placeholder="例如：2026 年度 Web 安全评估"
          />
        </el-form-item>
        <el-form-item label="负责人">
          <el-input v-model="editForm.owner" placeholder="负责人姓名或账号" />
        </el-form-item>
      </div>

      <el-form-item label="项目状态">
        <el-select v-model="editForm.status" style="width: 100%">
          <el-option
            v-for="option in projectStatusOptions"
            :key="option.value"
            :label="option.label"
            :value="option.value"
          />
        </el-select>
      </el-form-item>

      <el-form-item label="授权声明">
        <el-input
          v-model="editForm.authorizationStatement"
          type="textarea"
          :rows="3"
          placeholder="填写授权来源、测试范围和限制"
        />
      </el-form-item>

      <div class="project-form-row">
        <el-form-item label="授权开始">
          <el-date-picker
            v-model="editForm.authorizationValidFrom"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            format="YYYY-MM-DD HH:mm"
            placeholder="选择开始时间"
            :editable="false"
          />
        </el-form-item>
        <el-form-item label="授权结束">
          <el-date-picker
            v-model="editForm.authorizationExpiresAt"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            format="YYYY-MM-DD HH:mm"
            placeholder="选择结束时间"
            :editable="false"
          />
        </el-form-item>
      </div>

      <el-form-item label="项目说明">
        <el-input
          v-model="editForm.description"
          type="textarea"
          :rows="3"
          placeholder="补充项目目标、交付物和注意事项"
        />
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="editVisible = false">取消</el-button>
      <el-button
        type="primary"
        :loading="editSaving"
        :disabled="
          !editForm.name ||
          !editForm.authorizationStatement ||
          !editForm.authorizationValidFrom ||
          !editForm.authorizationExpiresAt ||
          !editForm.owner
        "
        @click="saveEdit"
        >保存修改</el-button
      >
    </template>
  </el-dialog>
</template>

<style scoped>
.projects-pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}
.project-form {
  padding: 2px 2px 0;
}

.project-form-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 14px;
}

.project-form :deep(.el-form-item) {
  margin-bottom: 16px;
}

.project-form :deep(.el-form-item__label) {
  padding-bottom: 6px;
  color: var(--app-text);
  font-size: 12px;
  font-weight: 600;
}

.project-form :deep(.el-input__wrapper),
.project-form :deep(.el-textarea__inner),
.project-form :deep(.el-date-editor) {
  border-radius: 5px;
}

.project-form :deep(.el-date-editor) {
  width: 100%;
}

.project-form :deep(.el-textarea__inner) {
  line-height: 1.55;
}

@media (max-width: 600px) {
  .project-form-row {
    grid-template-columns: 1fr;
  }
}
</style>
