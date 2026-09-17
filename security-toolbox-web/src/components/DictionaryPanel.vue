<script setup lang="ts">
import { computed, nextTick, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import AppPagination from "./AppPagination.vue";
import { ArrowDown, CircleCheck } from "./fluentIcons";
import { toErrorMessage } from "../utils/errorMessage";
import type {
  DictionaryApi,
  DictionaryView,
} from "./dictionaryTypes";

const props = withDefaults(
  defineProps<{
    title: string;
    description?: string;
    api: DictionaryApi;
    validateWord: (word: string) => string;
    addPlaceholder?: string;
    importPlaceholder?: string;
    removePlaceholder?: string;
    unit?: string;
    fileAccept?: string;
  }>(),
  {
    description: "用于枚举的词库",
    addPlaceholder: "每行一个词条",
    importPlaceholder: "每行一个词条，也可从文件导入或直接拖拽文件到此处",
    removePlaceholder: "粘贴每行一个要删除的词条",
    unit: "词条",
    fileAccept: ".txt,text/plain",
  },
);

const expanded = ref(false);
const panelRef = ref<HTMLElement | null>(null);
const loaded = ref(false);
const loading = ref(false);
const saving = ref(false);
const importing = ref(false);
const deleting = ref(false);
const view = ref<DictionaryView>({ source: "", wordCount: 0 });
const words = ref<Array<{ word: string }>>([]);
const wordPage = ref(1);
const wordPageSize = ref(30);
const wordTotal = ref(0);
const wordLoading = ref(false);
const wordQuery = ref("");
const selected = ref<string[]>([]);
const addText = ref("");
const addProblems = ref<string[]>([]);
const importText = ref("");
const importSummary = ref("");
const removeText = ref("");
const fileInput = ref<HTMLInputElement | null>(null);
const fileDragActive = ref(false);

function parseText(text: string): string[] {
  return String(text || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}

function validateAdditions(): string[] {
  const lines = parseText(addText.value);
  if (!lines.length) return [];
  const seen = new Set<string>();
  const problems: string[] = [];
  for (const line of lines) {
    const issue = props.validateWord(line);
    if (issue) {
      problems.push(`${line || "<空行>"}：${issue}`);
      continue;
    }
    const word = line.toLowerCase();
    if (seen.has(word)) {
      problems.push(`${line}：重复词条`);
      continue;
    }
    seen.add(word);
  }
  return problems.slice(0, 200);
}

const addProblemList = computed(() => validateAdditions());

async function loadWords() {
  wordLoading.value = true;
  try {
    const pageData = await props.api.words(
      wordQuery.value,
      wordPage.value,
      wordPageSize.value,
    );
    words.value = pageData.words.map((word) => ({ word }));
    wordTotal.value = pageData.total;
    if (wordPage.value > 1 && !pageData.words.length) {
      wordPage.value = 1;
      await loadWords();
      return;
    }
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "词条列表加载失败"));
  } finally {
    wordLoading.value = false;
  }
}

watch(wordQuery, () => {
  wordPage.value = 1;
  void loadWords();
});
watch([wordPage, wordPageSize], () => void loadWords());

function onSelectionChange(rows: Array<{ word: string }>) {
  selected.value = rows.map((row) => row.word);
}

function clearSelection() {
  selected.value = [];
}

watch(expanded, (value) => {
  if (value && !loaded.value) {
    loaded.value = true;
    void loadView();
    void loadWords();
  }
  if (value) {
    void nextTick(() => {
      panelRef.value?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }
});

async function loadView() {
  loading.value = true;
  try {
    view.value = await props.api.view();
    addText.value = "";
    addProblems.value = [];
    importText.value = "";
    importSummary.value = "";
    removeText.value = "";
    selected.value = [];
  } catch (error) {
    ElMessage.error(toErrorMessage(error, `${props.title}加载失败`));
  } finally {
    loading.value = false;
  }
}

async function saveAdditions() {
  if (saving.value) return;
  const problems = validateAdditions();
  if (problems.length) {
    ElMessage.error("新增词条校验未通过，请修正后重试");
    return;
  }
  const additions = parseText(addText.value);
  if (!additions.length) {
    ElMessage.warning(`请先输入要新增的${props.unit}（每行一个）`);
    return;
  }
  try {
    saving.value = true;
    const result = await props.api.update(additions, []);
    view.value = result.view;
    addText.value = "";
    addProblems.value = [];
    selected.value = [];
    ElMessage.success(
      `已新增 ${result.added} 条，当前共 ${result.view.wordCount} 条`,
    );
    await loadWords();
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "新增词条保存失败"));
  } finally {
    saving.value = false;
  }
}

async function importWords() {
  if (importing.value) return;
  if (!importText.value.trim()) {
    ElMessage.warning(`请先粘贴要批量导入的${props.unit}（每行一个）`);
    return;
  }
  importing.value = true;
  try {
    const result = await props.api.importText(importText.value);
    if (result.imported) {
      await loadView();
      await loadWords();
    }
    importSummary.value = `导入 ${result.imported}，跳过 ${result.invalid}，已存在 ${result.duplicates}`;
    if (result.issues.length) {
      ElMessageBox.alert(
        result.issues.slice(0, 20).join("\n"),
        "无效词条被跳过",
        { type: "warning", customClass: "dict-import-issues" },
      );
    } else {
      ElMessage.success(`导入完成：新增 ${result.imported} 条`);
    }
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "批量导入失败"));
  } finally {
    importing.value = false;
  }
}

async function removeSelected() {
  if (deleting.value) return;
  const targets = selected.value.slice();
  if (!targets.length) {
    ElMessage.warning("请先勾选要删除的词条");
    return;
  }
  const confirmed = await ElMessageBox.confirm(
    `确认删除选中的 ${targets.length} 个词条？`,
    "删除词条",
    { type: "warning", confirmButtonText: "删除", cancelButtonText: "取消" },
  ).catch(() => null);
  if (!confirmed) return;
  await removeWords(targets);
}

async function removeInput() {
  if (deleting.value) return;
  const targets = parseText(removeText.value);
  if (!targets.length) {
    ElMessage.warning(`请粘贴要删除的${props.unit}（每行一个）`);
    return;
  }
  await removeWords(targets);
  removeText.value = "";
}

async function removeWords(targets: string[]) {
  deleting.value = true;
  try {
    const result = await props.api.update([], targets);
    view.value = result.view;
    selected.value = [];
    const missing = result.missing ?? [];
    if (result.removed > 0) {
      ElMessage.success(
        `已删除 ${result.removed} 条，剩余 ${result.view.wordCount} 条`,
      );
    }
    if (missing.length) {
      const preview = missing.slice(0, 20).join("、");
      const suffix = missing.length > 20 ? ` 等 ${missing.length} 条` : "";
      ElMessage.warning(
        `${missing.length} 条词条不存在，未删除：${preview}${suffix}`,
      );
    } else if (result.removed === 0) {
      ElMessage.info("没有可删除的词条");
    }
    await loadWords();
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "删除失败"));
  } finally {
    deleting.value = false;
  }
}

function pickFile() {
  fileInput.value?.click();
}

async function onFileSelected(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  input.value = "";
  if (file) await loadFile(file);
}

async function onFileDrop(event: DragEvent) {
  fileDragActive.value = false;
  const file = event.dataTransfer?.files?.[0];
  if (file) await loadFile(file);
}

function onDragLeave(event: DragEvent) {
  const card = event.currentTarget as HTMLElement | null;
  const related = event.relatedTarget as Node | null;
  if (!card || !related || !card.contains(related)) {
    fileDragActive.value = false;
  }
}

async function loadFile(file: File) {
  if (file.size > 5 * 1024 * 1024) {
    ElMessage.warning("文件过大（超过 5MB），请拆分后再导入");
    return;
  }
  try {
    importText.value = await file.text();
    ElMessage.success(`已读取 ${file.name}，正在导入…`);
    await importWords();
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "读取文件失败"));
  }
}
</script>

<template>
  <section ref="panelRef" class="subdomain-dict-panel" :class="{ collapsed: !expanded }">
    <header class="subdomain-dict-panel-heading">
      <button
        type="button"
        class="subdomain-dict-panel-toggle"
        :aria-expanded="expanded"
        :aria-label="expanded ? `收起${title}` : `展开${title}`"
        @click="expanded = !expanded"
      >
        <el-icon class="subdomain-dict-panel-chevron">
          <ArrowDown />
        </el-icon>
        <span class="subdomain-dict-panel-copy">
          <strong>{{ title }}</strong>
          <span v-if="view.wordCount"
            >{{ view.source === "MANAGED" ? "已托管" : "内置默认" }} ·
            {{ view.wordCount }} 条{{ unit }}</span
          >
          <span v-else>{{ description }}</span>
        </span>
      </button>
    </header>
    <div
      class="fluent-collapsible subdomain-dict-collapse"
      :class="{ 'is-collapsed': !expanded }"
      :aria-hidden="!expanded"
      :inert="!expanded"
    >
      <div class="fluent-collapsible-inner">
        <div v-loading="loading" class="subdomain-dict">
          <div v-if="view.source" class="subdomain-dict-meta">
            <div class="subdomain-dict-meta-info">
              <el-tag
                size="small"
                :type="view.source === 'MANAGED' ? 'success' : 'info'"
              >
                {{ view.source === "MANAGED" ? "可托管词典" : "内置默认词典" }}
              </el-tag>
              <span
                >共 {{ view.wordCount }} 条。内置词典只读；新增或导入后会自动生成托管词典并被枚举立即使用。</span
              >
            </div>
            <el-button size="small" :loading="saving" @click="void loadView()"
              >刷新信息</el-button
            >
          </div>

          <div class="subdomain-dict-section">
            <div class="subdomain-dict-section-head">
              <span>当前词条（共 {{ wordTotal }} 条）</span>
              <div class="subdomain-dict-tools">
                <el-input
                  v-model="wordQuery"
                  clearable
                  size="small"
                  placeholder="搜索词条"
                  class="subdomain-dict-search"
                />
                <el-button
                  size="small"
                  type="danger"
                  plain
                  :disabled="!selected.length"
                  :loading="deleting"
                  @click="removeSelected"
                  >删除勾选 ({{ selected.length }})</el-button
                >
              </div>
            </div>
            <div v-loading="wordLoading" class="subdomain-dict-table">
              <el-table
                :data="words"
                size="small"
                :show-header="false"
                max-height="240"
                @selection-change="onSelectionChange"
                @select-all="clearSelection"
                @select="clearSelection"
              >
                <el-table-column type="selection" width="36" />
                <el-table-column prop="word" min-width="0" show-overflow-tooltip />
              </el-table>
              <div
                v-if="!wordLoading && !words.length"
                class="subdomain-dict-empty"
              >
                暂无匹配词条
              </div>
            </div>
            <div class="subdomain-dict-pager">
              <span>共 {{ wordTotal }} 条</span>
              <AppPagination
                v-if="wordTotal > wordPageSize"
                v-model:page="wordPage"
                v-model:page-size="wordPageSize"
                :total="wordTotal"
              />
            </div>
          </div>

          <div class="subdomain-dict-grid">
            <div class="subdomain-dict-card">
              <div class="subdomain-dict-card-head">
                <span class="subdomain-dict-card-title">新增词条</span>
                <span class="subdomain-dict-card-hint">每行一个</span>
              </div>
              <el-input
                v-model="addText"
                class="subdomain-dict-editor"
                type="textarea"
                resize="none"
                spellcheck="false"
                :placeholder="addPlaceholder"
              />
              <div
                v-if="addProblemList.length"
                class="fingerprint-rule-editor-issues"
                role="alert"
              >
                <div
                  v-for="(problem, index) in addProblemList.slice(0, 30)"
                  :key="`${problem}-${index}`"
                  class="fingerprint-rule-editor-issue"
                >
                  <el-tag size="small" type="danger">校验错误</el-tag>
                  <span>{{ problem }}</span>
                </div>
                <div
                  v-if="addProblemList.length > 30"
                  class="subdomain-dict-more-issues"
                >
                  还有 {{ addProblemList.length - 30 }} 处错误…
                </div>
              </div>
              <div
                v-else-if="addText.trim()"
                class="fingerprint-rule-editor-ok"
              >
                <el-icon><CircleCheck /></el-icon>
                <span>校验通过，保存后追加到词典。</span>
              </div>
              <div class="subdomain-dict-card-actions">
                <el-button
                  type="primary"
                  size="small"
                  :loading="saving"
                  :disabled="!addText.trim()"
                  @click="saveAdditions"
                  >新增词条</el-button
                >
              </div>
            </div>

            <div
              class="subdomain-dict-card"
              :class="{ 'is-dragover': fileDragActive }"
              @dragover.prevent="fileDragActive = true"
              @dragleave="onDragLeave"
              @drop.prevent="onFileDrop"
            >
              <div class="subdomain-dict-card-head">
                <span class="subdomain-dict-card-title">批量导入</span>
                <span class="subdomain-dict-card-hint">空行、# 注释自动忽略</span>
              </div>
              <el-input
                v-model="importText"
                class="subdomain-dict-editor"
                type="textarea"
                resize="none"
                spellcheck="false"
                :placeholder="importPlaceholder"
              />
              <div v-if="importSummary" class="subdomain-dict-hint">
                {{ importSummary }}
              </div>
              <div class="subdomain-dict-card-actions">
                <el-button size="small" @click="pickFile">从文件导入</el-button>
                <el-button
                  type="primary"
                  size="small"
                  :loading="importing"
                  :disabled="!importText.trim()"
                  @click="importWords"
                  >批量导入</el-button
                >
              </div>
              <input
                ref="fileInput"
                type="file"
                :accept="fileAccept"
                class="subdomain-dict-file-input"
                @change="onFileSelected"
              />
            </div>

            <div class="subdomain-dict-card">
              <div class="subdomain-dict-card-head">
                <span class="subdomain-dict-card-title">批量删除</span>
                <span class="subdomain-dict-card-hint">仅删除词典中已存在的词条</span>
              </div>
              <el-input
                v-model="removeText"
                class="subdomain-dict-editor"
                type="textarea"
                resize="none"
                spellcheck="false"
                :placeholder="removePlaceholder"
              />
              <div class="subdomain-dict-card-actions">
                <el-button
                  type="danger"
                  plain
                  size="small"
                  :disabled="!removeText.trim()"
                  :loading="deleting"
                  @click="removeInput"
                  >批量删除</el-button
                >
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.subdomain-dict-panel {
  display: block;
  margin: 0 0 14px;
  overflow: hidden;
  border: 1px solid var(--app-border, var(--el-border-color));
  border-radius: 10px;
  background: var(--app-surface-soft, var(--el-fill-color-light));
}
.subdomain-dict-panel-heading {
  display: flex;
  min-height: 52px;
  box-sizing: border-box;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 9px 14px;
}
.subdomain-dict-panel-toggle {
  display: flex;
  min-width: 0;
  flex: 1 1 auto;
  align-items: center;
  gap: 9px;
  padding: 0;
  border: 0;
  outline: 0;
  background: transparent;
  color: inherit;
  cursor: pointer;
  font: inherit;
  text-align: left;
}
.subdomain-dict-panel-toggle:focus-visible {
  border-radius: var(--fluent-radius-control, 4px);
  box-shadow: 0 0 0 2px var(--app-accent-soft);
}
.subdomain-dict-panel-chevron {
  flex: 0 0 auto;
  color: var(--app-muted, var(--el-text-color-secondary));
  transition: transform var(--fluent-collapse-motion);
}
.subdomain-dict-panel.collapsed .subdomain-dict-panel-chevron {
  transform: rotate(-90deg);
}
.subdomain-dict-panel-copy {
  display: flex;
  min-width: 0;
  flex-direction: column;
}
.subdomain-dict-panel-copy strong {
  overflow: hidden;
  color: var(--app-text, var(--el-text-color-primary));
  font-size: 13px;
  line-height: 1.4;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.subdomain-dict-panel-copy > span {
  overflow: hidden;
  margin-top: 2px;
  color: var(--app-text-muted);
  font-size: 12px;
  line-height: 1.4;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.subdomain-dict {
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 14px;
}
.subdomain-dict-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
  align-items: stretch;
}
.subdomain-dict-card {
  display: flex;
  min-height: 248px;
  flex-direction: column;
  gap: 10px;
  padding: 14px;
  border: 1px solid var(--app-border, var(--el-border-color-lighter));
  border-radius: 10px;
  background: var(--app-surface, var(--el-bg-color));
  transition:
    border-color var(--fluent-fast, 0.15s),
    box-shadow var(--fluent-fast, 0.15s);
}
.subdomain-dict-card.is-dragover {
  border-color: var(--app-accent, var(--el-color-primary));
  box-shadow: 0 0 0 2px var(--app-accent-soft, var(--el-color-primary-light-8));
}
.subdomain-dict-card-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
}
.subdomain-dict-card-title {
  color: var(--app-text-strong);
  font-size: 13px;
  font-weight: 600;
}
.subdomain-dict-card-hint {
  overflow: hidden;
  color: var(--app-text-muted);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.subdomain-dict-card-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}
.subdomain-dict-card .fingerprint-rule-editor-issues {
  max-height: 120px;
  overflow-y: auto;
}
.fingerprint-rule-editor-issues {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.fingerprint-rule-editor-issue {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 7px 10px;
  border: 1px solid var(--el-color-danger-light-7, #fde2e2);
  border-radius: var(--fluent-radius-control, 4px);
  background: var(--el-color-danger-light-9, #fef0f0);
  color: var(--el-color-danger, #f56c6c);
  font-size: 12px;
  line-height: 1.5;
}
.fingerprint-rule-editor-ok {
  display: flex;
  align-items: center;
  gap: 7px;
  color: var(--el-color-success, #67c23a);
  font-size: 12px;
}
.fingerprint-rule-editor-ok .el-icon {
  flex: none;
}
.subdomain-dict-file-input {
  display: none;
}
.subdomain-dict-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--app-border, var(--el-border-color-lighter));
  color: var(--app-text-muted);
  font-size: 12px;
  line-height: 1.5;
}
.subdomain-dict-meta-info {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 10px;
}
.subdomain-dict-section {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.subdomain-dict-section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  font-size: 13px;
  font-weight: 600;
  color: var(--app-text-strong);
}
.subdomain-dict-tools {
  display: flex;
  align-items: center;
  gap: 8px;
}
.subdomain-dict-search {
  width: 180px;
}
.subdomain-dict-table {
  overflow: hidden;
}
.subdomain-dict-empty {
  padding: 18px;
  text-align: center;
  color: var(--app-text-muted);
  font-size: 13px;
}
.subdomain-dict-pager {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 12px;
  color: var(--app-text-muted);
  font-size: 12px;
}
.subdomain-dict-editor {
  display: flex;
  flex: 1 1 auto;
}
.subdomain-dict-editor :deep(.el-textarea__inner) {
  height: 100%;
  min-height: 132px;
  font-family: var(--app-mono-font, ui-monospace, monospace);
}
.subdomain-dict-hint {
  color: var(--el-color-success, #67c23a);
  font-size: 12px;
}
.subdomain-dict-more-issues {
  color: var(--app-text-muted);
  font-size: 12px;
}
@media (max-width: 1024px) {
  .subdomain-dict-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
@media (max-width: 640px) {
  .subdomain-dict-tools {
    flex-wrap: wrap;
  }
  .subdomain-dict-search {
    width: 100%;
  }
  .subdomain-dict-grid {
    grid-template-columns: 1fr;
  }
}
</style>
