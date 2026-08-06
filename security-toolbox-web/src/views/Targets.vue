<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import { Location, MagicStick } from "../components/fluentIcons";
import {
  endpoints,
  safeGet,
  type Target,
  type AssessmentProject,
} from "../api";
import AppPagination from "../components/AppPagination.vue";
import OfflineState from "../components/OfflineState.vue";
import { useClientPagination } from "../composables/useClientPagination";
import { useCopilotStore } from "../stores/copilot";
import { toErrorMessage } from "../utils/errorMessage";

const copilot = useCopilotStore();
const router = useRouter();

const rows = ref<Target[]>([]);
const projects = ref<AssessmentProject[]>([]);
const offline = ref(false);
const dialog = ref(false);
const saving = ref(false);
const saveError = ref("");
const reporting = ref<number>();
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
const customPorts = ref("");
const fullPortAccess = ref(false);
const commonPortOptions = [
  { label: "HTTP · 80", value: "80" },
  { label: "HTTPS · 443", value: "443" },
  { label: "SSH · 22", value: "22" },
  { label: "FTP · 21", value: "21" },
  { label: "SMTP · 25", value: "25" },
  { label: "DNS · 53", value: "53" },
  { label: "POP3 · 110", value: "110" },
  { label: "IMAP · 143", value: "143" },
  { label: "SMB · 445", value: "445" },
  { label: "MySQL · 3306", value: "3306" },
  { label: "RDP · 3389", value: "3389" },
  { label: "PostgreSQL · 5432", value: "5432" },
  { label: "Redis · 6379", value: "6379" },
  { label: "HTTP 备用 · 8080", value: "8080" },
  { label: "HTTPS 备用 · 8443", value: "8443" },
];

function normalizePorts() {
  if (fullPortAccess.value) return "1-65535";
  const source = [
    ...selectedPorts.value,
    ...customPorts.value.split(/[，,;；\s]+/),
  ].filter(Boolean);
  const normalized = new Set<string>();

  for (const raw of source) {
    const token = raw.trim().replace(/[—–~～]/g, "-");
    const match = token.match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
    if (!match) throw new Error(`端口格式无效：${raw}`);
    const start = Number(match[1]);
    const end = match[2] ? Number(match[2]) : undefined;
    if (
      start < 1 ||
      start > 65535 ||
      (end !== undefined && (end < 1 || end > 65535 || end < start))
    ) {
      throw new Error(`端口范围无效：${raw}`);
    }
    normalized.add(end === undefined ? String(start) : `${start}-${end}`);
  }

  if (!normalized.size) throw new Error("请至少选择或填写一个允许端口");
  return [...normalized]
    .sort((a, b) => Number(a.split("-")[0]) - Number(b.split("-")[0]))
    .join(",");
}

async function load() {
  const [targetResult, projectResult] = await Promise.all([
    safeGet(endpoints.targets, [] as Target[]),
    safeGet(endpoints.projects, [] as AssessmentProject[]),
  ]);
  rows.value = targetResult.data;
  projects.value = projectResult.data;
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
    authorizationValidFrom: "",
    authorizationExpiresAt: "",
  });
  selectedPorts.value = ["80", "443"];
  customPorts.value = "";
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
    form.allowedPorts = normalizePorts();
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
    const url = URL.createObjectURL(data);
    const a = document.createElement("a");
    a.href = url;
    a.download = `target-${row.id}-security-report.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  } catch {
    ElMessage.error("目标 PDF 报告生成失败");
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
    width="560px"
    class="app-dialog app-dialog--sm target-dialog"
    align-center
    destroy-on-close
  >
    <template #header>
      <div class="target-dialog-heading">
        <span class="target-dialog-icon"
          ><el-icon><Location /></el-icon
        ></span>
        <div>
          <strong>新增授权目标</strong
          ><small>登记已获得明确授权的地址和允许检测的端口</small>
        </div>
      </div>
    </template>
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
        >
          <el-option
            v-for="p in projects"
            :key="p.id"
            :label="`${p.name}（${p.status}）`"
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
        <el-form-item label="授权生效时间"
          ><el-date-picker
            v-model="form.authorizationValidFrom"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ss"
            placeholder="立即生效"
        /></el-form-item>
        <el-form-item label="授权到期时间"
          ><el-date-picker
            v-model="form.authorizationExpiresAt"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ss"
            placeholder="长期有效"
        /></el-form-item>
      </div>
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
            collapse-tags
            collapse-tags-tooltip
            placeholder="选择常用端口"
          >
            <el-option
              v-for="port in commonPortOptions"
              :key="port.value"
              :label="port.label"
              :value="port.value"
            />
          </el-select>
          <el-input
            v-model="customPorts"
            :disabled="fullPortAccess"
            clearable
            placeholder="手动填写，如 8000, 8080-8090"
          >
            <template #prefix>自定义</template>
          </el-input>
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
  grid-template-columns: minmax(0, 1fr) 150px;
  gap: 16px;
}
.target-form-row :deep(.el-select) {
  width: 100%;
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
.targets-page :deep(.target-action-delete) {
  font-size: 12px;
  font-weight: 600;
}
.targets-page :deep(.el-table__body tr.current-row .target-action-report) {
  color: #263647;
}
.targets-page :deep(.el-table__body tr.current-row .target-action-delete) {
  color: #b42318;
}
.target-dialog-heading {
  display: flex;
  align-items: center;
  gap: 12px;
}
.target-dialog-heading > div {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 4px;
}
.target-dialog-heading strong {
  color: var(--app-text);
  font-size: 16px;
  font-weight: 650;
  line-height: 1.25;
}
.target-dialog-heading small {
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.45;
}
.target-dialog-icon {
  display: grid;
  width: 36px;
  height: 36px;
  flex: none;
  place-items: center;
  border-radius: 9px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font-size: 18px;
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
:global(.target-dialog .el-form-item) {
  margin-bottom: 18px;
}
:global(.target-dialog .el-form-item__label) {
  height: auto;
  margin-bottom: 7px;
  padding: 0;
  color: var(--app-text) !important;
  font-size: 13px;
  font-weight: 650;
  line-height: 1.4;
}
:global(.target-dialog .el-input__wrapper),
:global(.target-dialog .el-select__wrapper),
:global(.target-dialog .el-textarea__inner) {
  border-radius: 8px;
  background: var(--app-surface);
  font-size: 13px;
  box-shadow: 0 0 0 1px var(--app-border-strong) inset;
}
:global(.target-dialog .el-input__wrapper:hover),
:global(.target-dialog .el-select__wrapper:hover),
:global(.target-dialog .el-textarea__inner:hover) {
  box-shadow: 0 0 0 1px var(--app-muted) inset;
}
:global(.target-dialog .el-input__wrapper.is-focus),
:global(.target-dialog .el-select__wrapper.is-focused),
:global(.target-dialog .el-textarea__inner:focus) {
  box-shadow:
    0 0 0 1px var(--app-accent) inset,
    0 0 0 3px var(--app-accent-soft);
}
:global(.target-dialog .el-textarea__inner) {
  min-height: 78px !important;
  padding: 10px 11px;
}
</style>
