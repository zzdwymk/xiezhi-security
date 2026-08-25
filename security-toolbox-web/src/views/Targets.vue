<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import { MagicStick } from "../components/fluentIcons";
import {
  endpoints,
  safeGet,
  type Target,
  type AssessmentProject,
  type ProjectTarget,
} from "../api";
import AppPagination from "../components/AppPagination.vue";
import OfflineState from "../components/OfflineState.vue";
import { useClientPagination } from "../composables/useClientPagination";
import { useCopilotStore } from "../stores/copilot";
import { formatDateTime } from "../utils/dateTime";
import { toErrorMessage } from "../utils/errorMessage";
import { downloadBlob, EmptyDownloadError } from "../utils/download";
import {
  COMMON_PORT_OPTIONS,
  normalizeAllowedPorts,
  validateDomainTarget,
} from "../utils/ports";

const copilot = useCopilotStore();
const router = useRouter();

const rows = ref<Target[]>([]);
const projects = ref<AssessmentProject[]>([]);
const projectIdsByTarget = ref<Record<number, number[]>>({});
const editingProjects = ref<AssessmentProject[]>([]);
const offline = ref(false);
const dialog = ref(false);
const saving = ref(false);
const saveError = ref("");
const reporting = ref<number>();
const editDialog = ref(false);
const editSaving = ref(false);
const editingTargetId = ref<number>();
const originalEditTarget = ref<Target>();
const editForm = reactive({
  name: "",
  targetValue: "",
  targetType: "domain",
  authorizationNote: "",
  allowedPorts: "80,443",
  enabled: true,
  authorizationValidFrom: "",
  authorizationExpiresAt: "",
});
const editSelectedPorts = ref<string[]>(["80", "443"]);
const editFullPortAccess = ref(false);
const {
  page,
  pageSize,
  total,
  pagedItems: pagedRows,
} = useClientPagination(rows);
const form = reactive({
  projectId: undefined as number | undefined,
  name: "",
  targetValue: "",
  targetType: "domain",
  authorizationNote: "",
  allowedPorts: "80,443",
  enabled: true,
  authorizationValidFrom: "",
  authorizationExpiresAt: "",
});
const selectedPorts = ref<string[]>(["80", "443"]);
const fullPortAccess = ref(false);

function normalizeDatePickerValue(value?: string) {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "";
  return parsed.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function applyProjectAuthorizationDefaults(projectId?: number) {
  const selectedProject = projects.value.find(
    (project) => project.id === projectId,
  );
  form.authorizationValidFrom = normalizeDatePickerValue(
    selectedProject?.authorizationValidFrom,
  );
  form.authorizationExpiresAt = normalizeDatePickerValue(
    selectedProject?.authorizationExpiresAt,
  );
}

function projectStatusLabel(status?: string) {
  const labels: Record<string, string> = {
    ACTIVE: '进行中',
    ARCHIVED: '已归档',
  };
  return status ? labels[status] || status : '';
}

function projectsForTarget(row: Target) {
  if (row.projectId) {
    const directProject = projects.value.find(
      (project) => project.id === row.projectId,
    );
    if (directProject) return [directProject];
  }
  const projectIds = new Set<number>();
  for (const projectId of projectIdsByTarget.value[row.id] || []) {
    projectIds.add(projectId);
  }
  return [...projectIds]
    .map((projectId) =>
      projects.value.find((project) => project.id === projectId),
    )
    .filter((project): project is AssessmentProject => Boolean(project));
}

function preferredProjectForTarget(row: Target) {
  const linkedProjects = projectsForTarget(row);
  return (
    linkedProjects.find((project) => project.status === "ACTIVE") ||
    linkedProjects[0]
  );
}

function targetAuthorizationWindow(row: Target) {
  const project = preferredProjectForTarget(row);
  const validFrom =
    row.authorizationValidFrom || project?.authorizationValidFrom || "";
  const expiresAt =
    row.authorizationExpiresAt || project?.authorizationExpiresAt || "";
  const usesTargetWindow = Boolean(
    row.authorizationValidFrom || row.authorizationExpiresAt,
  );
  return {
    validFrom,
    expiresAt,
    project,
    sourceLabel: usesTargetWindow
      ? row.authorizationValidFrom && row.authorizationExpiresAt
        ? "目标级"
        : "目标 / 项目"
      : project
        ? ""
        : "未设置",
  };
}

function compactDateTime(value?: string) {
  const formatted = formatDateTime(value);
  return formatted ? formatted.slice(0, 16) : "未设置";
}

function targetAuthorizationTitle(row: Target) {
  const window = targetAuthorizationWindow(row);
  const linkedProjects = projectsForTarget(row);
  const source = window.project
    ? `${window.sourceLabel} · ${window.project.name}`
    : window.sourceLabel;
  const otherProjects = linkedProjects
    .filter((project) => project.id !== window.project?.id)
    .map(
      (project) =>
        `${project.name}：${compactDateTime(project.authorizationValidFrom)} 至 ${compactDateTime(project.authorizationExpiresAt)}`,
    );
  return [
    `${source}：${compactDateTime(window.validFrom)} 至 ${compactDateTime(window.expiresAt)}`,
    ...otherProjects,
  ].join("\n");
}

function inheritedTimePlaceholder(boundary: "start" | "end") {
  const project =
    editingProjects.value.find((item) => item.status === "ACTIVE") ||
    editingProjects.value[0];
  const value =
    boundary === "start"
      ? project?.authorizationValidFrom
      : project?.authorizationExpiresAt;
  return value
    ? `项目：${compactDateTime(value)}`
    : boundary === "start"
      ? "选择开始时间"
      : "选择结束时间";
}

async function load() {
  const [targetResult, projectResult] = await Promise.all([
    safeGet(endpoints.targets, [] as Target[]),
    safeGet(endpoints.projects, [] as AssessmentProject[]),
  ]);
  rows.value = targetResult.data;
  projects.value = projectResult.data;
  const linkResults = await Promise.all(
    projects.value.map(async (project) => ({
      projectId: project.id,
      result: await safeGet(
        () => endpoints.projectTargets(project.id),
        [] as ProjectTarget[],
      ),
    })),
  );
  const linkedProjectIds: Record<number, number[]> = {};
  for (const { projectId, result } of linkResults) {
    for (const link of result.data) {
      const targetProjectIds = linkedProjectIds[link.targetId] || [];
      if (!targetProjectIds.includes(projectId))
        targetProjectIds.push(projectId);
      linkedProjectIds[link.targetId] = targetProjectIds;
    }
  }
  projectIdsByTarget.value = linkedProjectIds;
  offline.value = targetResult.offline;
}

function openCreate() {
  if (!projects.value.length) {
    ElMessageBox.confirm(
      "尚未创建安全评估项目。授权目标必须归属于一个评估项目，请先创建项目后再登记目标。",
      "需要先创建评估项目",
      {
        confirmButtonText: "去创建项目",
        cancelButtonText: "取消",
        type: "warning",
      },
    )
      .then(() => router.push("/projects"))
      .catch(() => {});
    return;
  }
  const active =
    projects.value.find((p) => p.status === "ACTIVE") || projects.value[0];
  Object.assign(form, {
    projectId: active?.id,
    name: "",
    targetValue: "",
    targetType: "domain",
    authorizationNote: "",
    allowedPorts: "80,443",
    enabled: true,
    authorizationValidFrom: normalizeDatePickerValue(
      active?.authorizationValidFrom,
    ),
    authorizationExpiresAt: normalizeDatePickerValue(
      active?.authorizationExpiresAt,
    ),
  });
  selectedPorts.value = ["80", "443"];
  fullPortAccess.value = false;
  saveError.value = "";
  dialog.value = true;
}

async function create() {
  saveError.value = "";
  if (!form.projectId) {
    saveError.value = "请选择该目标归属的评估项目";
    ElMessage.error(saveError.value);
    return;
  }
  try {
    validateDomainTarget(form.targetValue, form.targetType);
    form.allowedPorts = normalizeAllowedPorts(
      selectedPorts.value,
      "",
      fullPortAccess.value,
    );
    saving.value = true;
    await endpoints.createTarget({
      ...form,
      authorizationValidFrom: form.authorizationValidFrom
        ? new Date(form.authorizationValidFrom).toISOString()
        : undefined,
      authorizationExpiresAt: form.authorizationExpiresAt
        ? new Date(form.authorizationExpiresAt).toISOString()
        : undefined,
    });
    ElMessage.success("目标已保存");
    dialog.value = false;
    await load();
  } catch (error) {
    saveError.value = toErrorMessage(
      error,
      "保存失败，请检查服务状态和填写内容",
    );
    ElMessage.error(saveError.value);
  } finally {
    saving.value = false;
  }
}

async function remove(row: Target) {
  try {
    await ElMessageBox.confirm(`删除目标“${row.name}”？`, "确认删除", {
      type: "warning",
    });
    await endpoints.deleteTarget(row.id);
    ElMessage.success("目标已删除");
    await load();
  } catch (error) {
    if (error !== "cancel" && error !== "close") ElMessage.error("删除失败");
  }
}

function openEditTarget(row: Target) {
  editingTargetId.value = row.id;
  originalEditTarget.value = { ...row };
  editingProjects.value = projectsForTarget(row);
  editForm.name = row.name || "";
  editForm.targetValue = row.targetValue || "";
  editForm.targetType = (row.targetType || "domain").toLowerCase();
  editForm.authorizationNote = row.authorizationNote || "";
  editForm.allowedPorts = row.allowedPorts || "80,443";
  editForm.enabled = row.enabled !== false;
  editForm.authorizationValidFrom = normalizeDatePickerValue(
    row.authorizationValidFrom,
  );
  editForm.authorizationExpiresAt = normalizeDatePickerValue(
    row.authorizationExpiresAt,
  );
  const ports = (row.allowedPorts || "")
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  editSelectedPorts.value = ports;
  editFullPortAccess.value = (row.allowedPorts || "") === "1-65535";
  editDialog.value = true;
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

function targetAuthorizationChanged(ports: string) {
  const original = originalEditTarget.value;
  if (!original) return false;
  return (
    editForm.targetValue.trim() !== original.targetValue.trim() ||
    editForm.targetType.toLowerCase() !== original.targetType.toLowerCase() ||
    editForm.authorizationNote !== original.authorizationNote ||
    ports !== original.allowedPorts ||
    editForm.enabled !== original.enabled ||
    !sameInstant(
      editForm.authorizationValidFrom,
      original.authorizationValidFrom,
    ) ||
    !sameInstant(
      editForm.authorizationExpiresAt,
      original.authorizationExpiresAt,
    )
  );
}

async function saveEditTarget() {
  if (!editingTargetId.value) return;
  try {
    validateDomainTarget(editForm.targetValue, editForm.targetType);
    const ports = normalizeAllowedPorts(
      editSelectedPorts.value,
      "",
      editFullPortAccess.value,
    );
    if (targetAuthorizationChanged(ports)) {
      await ElMessageBox.confirm(
        "目标地址、类型、端口、授权记录、授权时间窗或启用状态已经变化。保存后会改变可执行的检测范围，请确认变更仍有明确授权。",
        "确认授权范围变更",
        {
          confirmButtonText: "确认并保存",
          cancelButtonText: "取消",
          type: "warning",
        },
      );
    }
    editSaving.value = true;
    await endpoints.updateTarget(editingTargetId.value, {
      name: editForm.name,
      targetValue: editForm.targetValue,
      targetType: editForm.targetType,
      authorizationNote: editForm.authorizationNote,
      allowedPorts: ports,
      enabled: editForm.enabled,
      authorizationValidFrom: editForm.authorizationValidFrom
        ? new Date(editForm.authorizationValidFrom).toISOString()
        : undefined,
      authorizationExpiresAt: editForm.authorizationExpiresAt
        ? new Date(editForm.authorizationExpiresAt).toISOString()
        : undefined,
    });
    editDialog.value = false;
    await load();
    ElMessage.success("目标已更新");
  } catch (error) {
    if (error === "cancel" || error === "close") return;
    ElMessage.error(toErrorMessage(error, "更新失败"));
  } finally {
    editSaving.value = false;
  }
}

function askCopilot(row: Target) {
  copilot.prepare({
    targetId: row.id,
    refs: [{ type: "target", id: row.id, targetId: row.id, title: row.name }],
    mode: "plan",
    prompt:
      "评估这个授权目标的检测范围，并生成一份由低风险到高价值、严格遵守端口白名单的检测计划。",
  });
  void router.push("/");
}

async function downloadTargetReport(row: Target) {
  reporting.value = row.id;
  try {
    const { data } = await endpoints.downloadTargetReportPdf(row.id);
    downloadBlob(data, `target-${row.id}-security-report.pdf`);
  } catch (error) {
    ElMessage.error(
      error instanceof EmptyDownloadError
        ? error.message
        : "目标 PDF 报告生成失败",
    );
  } finally {
    reporting.value = undefined;
  }
}

onMounted(load);
</script>

<template>
  <section class="panel targets-page workspace-list-page">
    <div class="section-head">
      <div>
        <h3>目标</h3>
        <p>仅保存已获授权的地址和允许检测的端口。</p>
      </div>
      <el-button type="primary" @click="openCreate">新增目标</el-button>
    </div>
    <OfflineState
      v-if="offline || !rows.length"
      title="暂无目标"
      :description="
        offline ? '无法连接后端服务。' : '新增目标后才能创建检测任务。'
      "
    />
    <el-table v-else :data="pagedRows">
      <el-table-column prop="name" label="名称" min-width="130" />
      <el-table-column prop="targetValue" label="地址" min-width="190" />
      <el-table-column prop="targetType" label="类型" width="90" />
      <el-table-column prop="allowedPorts" label="端口" min-width="120" />
      <el-table-column
        prop="authorizationNote"
        label="授权记录"
        min-width="220"
        show-overflow-tooltip
      />
      <el-table-column label="授权有效期" min-width="176">
        <template #default="scope">
          <div
            class="target-authorization-window"
            :title="targetAuthorizationTitle(scope.row)"
          >
            <span class="target-authorization-source">
              {{ targetAuthorizationWindow(scope.row).sourceLabel }}
            </span>
            <span>
              <small>起</small>
              {{
                compactDateTime(targetAuthorizationWindow(scope.row).validFrom)
              }}
            </span>
            <span>
              <small>止</small>
              {{
                compactDateTime(targetAuthorizationWindow(scope.row).expiresAt)
              }}
            </span>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="90"
        ><template #default="scope"
          ><el-tag
            size="small"
            :type="scope.row.enabled ? 'success' : 'info'"
            >{{ scope.row.enabled ? "启用" : "停用" }}</el-tag
          ></template
        ></el-table-column
      >
      <el-table-column label="操作" width="285"
        ><template #default="scope"
          ><el-button
            class="target-action-ai"
            type="primary"
            :icon="MagicStick"
            @click="askCopilot(scope.row)"
            >AI 规划</el-button
          ><el-button
            class="target-action-report"
            :loading="reporting === scope.row.id"
            @click="downloadTargetReport(scope.row)"
            >目标 PDF</el-button
          ><el-button
            class="target-action-edit"
            type="primary"
            link
            @click="openEditTarget(scope.row)"
            >编辑</el-button
          ><el-button
            class="target-action-delete"
            type="danger"
            link
            @click="remove(scope.row)"
            >删除</el-button
          ></template
        ></el-table-column
      >
    </el-table>
    <AppPagination
      v-model:page="page"
      v-model:page-size="pageSize"
      class="targets-pagination"
      :total="total"
    />
  </section>

  <el-dialog
    v-model="dialog"
    title="新增授权目标"
    class="app-dialog app-dialog--md target-dialog"
    align-center
    destroy-on-close
  >
    <p class="app-dialog__intro">登记已获得明确授权的地址和允许检测的端口。</p>
    <el-alert
      v-if="saveError"
      :title="saveError"
      type="error"
      show-icon
      :closable="false"
      class="target-save-error"
    />
    <el-form label-position="top" class="target-form">
      <el-form-item label="归属评估项目" required>
        <el-select
          v-model="form.projectId"
          placeholder="选择该目标归属的评估项目"
          style="width: 100%"
          @change="applyProjectAuthorizationDefaults"
        >
          <el-option
            v-for="p in projects"
            :key="p.id"
            :label="`${p.name}（${projectStatusLabel(p.status)}）`"
            :value="p.id"
          />
        </el-select>
      </el-form-item>
      <div class="target-form-row">
        <el-form-item label="名称"
          ><el-input v-model="form.name" placeholder="用于内部识别"
        /></el-form-item>
        <el-form-item label="目标类型"
          ><el-select v-model="form.targetType"
            ><el-option label="域名" value="domain" /><el-option
              label="IP 地址"
              value="ip" /><el-option label="URL" value="url" /></el-select
        ></el-form-item>
      </div>
      <el-form-item label="地址"
        ><el-input
          v-model="form.targetValue"
          placeholder="example.com 或 192.0.2.10"
      /></el-form-item>
      <el-form-item label="授权记录"
        ><el-input
          v-model="form.authorizationNote"
          type="textarea"
          :rows="2"
          placeholder="填写授权来源、允许测试的范围和有效期"
      /></el-form-item>
      <div class="target-form-row">
        <el-form-item label="目标授权生效时间"
          ><el-date-picker
            v-model="form.authorizationValidFrom"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            format="YYYY-MM-DD HH:mm"
            placeholder="跟随项目授权开始"
        /></el-form-item>
        <el-form-item label="目标授权到期时间"
          ><el-date-picker
            v-model="form.authorizationExpiresAt"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            format="YYYY-MM-DD HH:mm"
            placeholder="跟随项目授权结束"
        /></el-form-item>
      </div>
      <p class="target-time-hint">
        默认带入所选项目的授权时间；如单独修改，将作为该目标的额外授权时间限制。
      </p>
      <el-form-item label="端口授权" class="port-form-item">
        <div class="port-picker">
          <div class="full-port-option">
            <div>
              <b>全端口授权（1-65535）</b
              ><small>允许使用 Nmap 执行全端口扫描，扫描时间可能较长。</small>
            </div>
            <el-switch v-model="fullPortAccess" />
          </div>
          <el-select
            v-model="selectedPorts"
            :disabled="fullPortAccess"
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
          <p class="port-hint">
            {{
              fullPortAccess
                ? "将保存为 1-65535；执行端口检测时会使用 Nmap，普通 TCP 探测仍只适合少量端口。"
                : "支持单个端口和端口范围，可用逗号、分号或空格分隔，保存时自动合并去重。"
            }}
          </p>
        </div>
      </el-form-item>
      <div class="target-enabled-row">
        <div>
          <strong>启用目标</strong
          ><small>保存后允许使用该目标创建检测任务</small>
        </div>
        <el-switch v-model="form.enabled" />
      </div>
    </el-form>
    <template #footer
      ><el-button @click="dialog = false">取消</el-button
      ><el-button
        type="primary"
        :loading="saving"
        :disabled="!form.name || !form.targetValue || !form.authorizationNote"
        @click="create"
        >保存目标</el-button
      ></template
    >
  </el-dialog>
  <el-dialog
    v-model="editDialog"
    title="编辑授权目标"
    class="app-dialog app-dialog--md target-dialog"
    align-center
    destroy-on-close
  >
    <el-form label-position="top" class="target-form">
      <div class="target-form-row">
        <el-form-item label="目标名称">
          <el-input v-model="editForm.name" placeholder="例如：主站" />
        </el-form-item>
        <el-form-item label="目标类型">
          <el-select v-model="editForm.targetType">
            <el-option label="域名" value="domain" />
            <el-option label="IP 地址" value="ip" />
            <el-option label="URL" value="url" />
          </el-select>
        </el-form-item>
      </div>
      <el-form-item label="目标地址">
        <el-input
          v-model="editForm.targetValue"
          placeholder="例如：example.com"
        />
      </el-form-item>
      <el-form-item label="授权记录">
        <el-input
          v-model="editForm.authorizationNote"
          type="textarea"
          :rows="2"
          placeholder="填写授权来源和范围限制"
        />
      </el-form-item>
      <el-form-item label="允许端口">
        <div class="port-picker">
          <div class="full-port-option">
            <div>
              <b>全端口 (1-65535)</b>
              <small>使用 Nmap 扫描全端口，耗时较长</small>
            </div>
            <el-switch v-model="editFullPortAccess" />
          </div>
          <el-select
            v-if="!editFullPortAccess"
            v-model="editSelectedPorts"
            multiple
            filterable
            allow-create
            collapse-tags
            collapse-tags-tooltip
            default-first-option
            placeholder="选择常用端口"
          >
            <el-option
              v-for="opt in COMMON_PORT_OPTIONS"
              :key="opt.value"
              :label="opt.label"
              :value="opt.value"
            />
          </el-select>
          <p class="port-hint">
            {{
              editFullPortAccess
                ? "将保存为 1-65535；执行端口检测时会使用 Nmap，普通 TCP 探测仍只适合少量端口。"
                : "支持单个端口和端口范围，可用逗号、分号或空格分隔，保存时自动合并去重。"
            }}
          </p>
        </div>
      </el-form-item>
      <div class="target-form-row">
        <el-form-item label="目标授权开始">
          <el-date-picker
            v-model="editForm.authorizationValidFrom"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            format="YYYY-MM-DD HH:mm"
            :placeholder="inheritedTimePlaceholder('start')"
            :editable="false"
          />
        </el-form-item>
        <el-form-item label="目标授权结束">
          <el-date-picker
            v-model="editForm.authorizationExpiresAt"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            format="YYYY-MM-DD HH:mm"
            :placeholder="inheritedTimePlaceholder('end')"
            :editable="false"
          />
        </el-form-item>
      </div>
      <div
        v-if="
          (!editForm.authorizationValidFrom ||
            !editForm.authorizationExpiresAt) &&
          editingProjects.length
        "
        class="target-inherited-time"
      >
        <span v-for="project in editingProjects" :key="project.id">
          未单独设置的时间将沿用项目 <b>{{ project.name }}</b>
          <span>
            开始 {{ compactDateTime(project.authorizationValidFrom) }} · 结束
            {{ compactDateTime(project.authorizationExpiresAt) }}
          </span>
        </span>
      </div>
      <p
        v-else-if="
          !editForm.authorizationValidFrom && !editForm.authorizationExpiresAt
        "
        class="target-time-hint"
      >
        当前目标没有单独保存授权时间，也没有读取到所属项目的授权时间。
      </p>
      <div class="target-enabled-row">
        <div>
          <strong>启用目标</strong>
          <small>保存后允许使用该目标创建检测任务</small>
        </div>
        <el-switch v-model="editForm.enabled" />
      </div>
    </el-form>
    <template #footer>
      <el-button @click="editDialog = false">取消</el-button>
      <el-button
        type="primary"
        :loading="editSaving"
        :disabled="
          !editForm.name || !editForm.targetValue || !editForm.authorizationNote
        "
        @click="saveEditTarget"
        >保存修改</el-button
      >
    </template>
  </el-dialog>
</template>

<style scoped>
.targets-pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}
.targets-page .section-head h3 {
  font-size: var(--type-section-title);
}
.targets-page .section-head p {
  font-size: var(--type-section-desc);
  line-height: 1.5;
}
.targets-page .section-head :deep(.el-button) {
  font-size: 12px;
}
.targets-page :deep(.el-table .cell) {
  line-height: 1.45;
}
.target-save-error {
  margin-bottom: 16px;
}
.target-form-row {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}
.target-form-row :deep(.el-select) {
  width: 100%;
}
.target-form-row :deep(.el-date-editor),
.target-form-row :deep(.el-date-picker) {
  width: 100% !important;
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
.target-time-hint {
  margin: -6px 2px 14px;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.55;
}
.target-inherited-time {
  margin: -6px 2px 14px;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.55;
}
.target-inherited-time > span {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 12px;
  align-items: baseline;
}
.target-inherited-time > span > b {
  color: var(--app-text);
  font-weight: 600;
}
.target-inherited-time > span > span {
  flex: none;
}
.target-inherited-time > strong {
  color: var(--app-text);
  font-weight: 600;
}
.target-inherited-time > span {
  display: flex;
  min-width: 0;
  justify-content: space-between;
  gap: 12px;
}
.target-inherited-time > span > b {
  overflow: hidden;
  color: var(--app-text);
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.target-inherited-time > span > span {
  flex: none;
}
.target-authorization-window {
  display: grid;
  min-width: 0;
  gap: 2px;
  color: var(--app-text);
  font-size: 12px;
  line-height: 1.35;
}
.target-authorization-window > span:not(.target-authorization-source) {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.target-authorization-window small {
  display: inline-block;
  width: 14px;
  color: var(--app-muted);
  font-size: 11px;
}
.target-authorization-source {
  width: max-content;
  max-width: 100%;
  overflow: hidden;
  color: var(--app-muted);
  font-size: 11px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.target-enabled-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-top: 4px;
  padding: 10px 12px;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-soft);
}
.target-enabled-row > div {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.target-enabled-row strong {
  color: var(--app-text);
  font-size: 13px;
}
.target-enabled-row small {
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.55;
}
@media (max-width: 600px) {
  .target-form-row {
    grid-template-columns: 1fr;
  }
}
.targets-page :deep(.el-table) {
  font-size: 14px;
}
.targets-page :deep(.el-table th.el-table__cell) {
  font-size: 14px;
  font-weight: 600;
}
.targets-page :deep(.el-table td.el-table__cell .cell) {
  font-size: 13px;
}
.targets-page :deep(.el-tag) {
  font-size: 11px;
}
.targets-page :deep(.el-button.is-link) {
  font-size: 12px;
}
.targets-page :deep(.target-action-ai) {
  height: 32px;
  padding: 0 11px;
  border: 1px solid var(--app-accent);
  border-radius: 5px;
  background: var(--app-accent);
  color: #fff;
  font-size: 12px;
  font-weight: 650;
}
.targets-page :deep(.target-action-ai:hover),
.targets-page :deep(.target-action-ai:focus) {
  border-color: var(--app-accent-dark);
  background: var(--app-accent-dark);
  color: #fff;
}
.targets-page :deep(.target-action-ai .el-icon) {
  color: #fff;
}
.targets-page :deep(.target-action-report) {
  height: 32px;
  padding: 0 10px;
  border: 1px solid #b8c2ce;
  border-radius: 5px;
  background: #fff;
  color: #263647;
  font-size: 12px;
  font-weight: 600;
}
.targets-page :deep(.target-action-report:hover),
.targets-page :deep(.target-action-report:focus) {
  border-color: #52708e;
  background: #eef4f8;
  color: #172a3d;
}
.targets-page :deep(.target-action-delete.el-button--danger.is-link),
.targets-page
  :deep(
    .el-table__body
      tr.current-row
      .target-action-delete.el-button--danger.is-link
  ) {
  --el-button-text-color: var(--fluent-danger-bg);
  --el-button-hover-text-color: var(--fluent-danger-hover-bg);
  --el-button-active-text-color: var(--fluent-danger-hover-bg);
  color: var(--fluent-danger-bg) !important;
  font-size: 12px;
  font-weight: 600;
}
.targets-page :deep(.target-action-delete.el-button--danger.is-link > span),
.targets-page
  :deep(
    .el-table__body
      tr.current-row
      .target-action-delete.el-button--danger.is-link
      > span
  ) {
  color: inherit !important;
}
.targets-page :deep(.target-action-delete.el-button--danger.is-link:hover),
.targets-page :deep(.target-action-delete.el-button--danger.is-link:focus),
.targets-page
  :deep(.target-action-delete.el-button--danger.is-link:focus-visible),
.targets-page :deep(.target-action-delete.el-button--danger.is-link:active),
.targets-page
  :deep(
    .el-table__body
      tr.current-row
      .target-action-delete.el-button--danger.is-link:hover
  ),
.targets-page
  :deep(
    .el-table__body
      tr.current-row
      .target-action-delete.el-button--danger.is-link:focus-visible
  ) {
  color: var(--fluent-danger-hover-bg) !important;
}
.targets-page :deep(.el-table__body tr.current-row .target-action-report) {
  color: #263647;
}
.target-form {
  margin: 0;
  padding: 0;
  border: 0;
  background: transparent;
  box-shadow: none;
}
.target-form-row {
  gap: 16px;
}
.port-picker {
  gap: 10px;
}
.full-port-option {
  padding: 8px 2px 12px;
  border: 0;
  border-bottom: 1px solid var(--app-border);
  border-radius: 0;
  background: transparent;
}
.target-enabled-row {
  margin-top: 6px;
  padding: 13px 2px 2px;
  border: 0;
  border-top: 1px solid var(--app-border);
  border-radius: 0;
  background: transparent;
}
</style>
v-for="port in COMMON_PORT_OPTIONS" v-for="opt in COMMON_PORT_OPTIONS"
v-for="port in COMMON_PORT_OPTIONS" v-for="opt in COMMON_PORT_OPTIONS"
