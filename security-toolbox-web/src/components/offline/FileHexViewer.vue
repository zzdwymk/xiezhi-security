<script setup lang="ts">
import { computed, ref } from "vue";
import { ElMessage } from "element-plus";
import { ArrowRight, Files, UploadFilled } from "../fluentIcons";
import {
  buildHexRows,
  clampHexOffset,
  formatHexOffset,
  HEX_VIEW_DEFAULT_PAGE_SIZE,
  parseHexOffset,
} from "../../utils/fileHexViewer";
import { toErrorMessage } from "../../utils/errorMessage";

const file = ref<File>();
const bytes = ref(new Uint8Array());
const offset = ref(0);
const offsetInput = ref("0x0");
const loading = ref(false);
const dragOver = ref(false);
let readSequence = 0;

const pageSize = HEX_VIEW_DEFAULT_PAGE_SIZE;
const rows = computed(() =>
  buildHexRows(bytes.value, offset.value, file.value?.size || 0),
);
const pageStart = computed(() => (bytes.value.length ? offset.value : 0));
const pageEnd = computed(() =>
  bytes.value.length ? offset.value + bytes.value.length - 1 : 0,
);
const canPrevious = computed(() => Boolean(file.value) && offset.value > 0);
const canNext = computed(
  () => Boolean(file.value) && offset.value + bytes.value.length < (file.value?.size || 0),
);

function formatSize(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(2)} KB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(2)} MB`;
  return `${(value / 1024 ** 3).toFixed(2)} GB`;
}

async function readChunk(nextOffset: number) {
  const selectedFile = file.value;
  if (!selectedFile) return;
  const sequence = ++readSequence;
  const safeOffset = clampHexOffset(nextOffset, selectedFile.size, pageSize);
  loading.value = true;
  try {
    const buffer = await selectedFile
      .slice(safeOffset, Math.min(selectedFile.size, safeOffset + pageSize))
      .arrayBuffer();
    if (sequence !== readSequence) return;
    offset.value = safeOffset;
    bytes.value = new Uint8Array(buffer);
    offsetInput.value = `0x${safeOffset.toString(16).toUpperCase()}`;
  } catch (error) {
    if (sequence === readSequence) {
      ElMessage.error(toErrorMessage(error, "读取文件分块失败"));
    }
  } finally {
    if (sequence === readSequence) loading.value = false;
  }
}

async function openFile(selectedFile: File) {
  file.value = selectedFile;
  bytes.value = new Uint8Array();
  offset.value = 0;
  offsetInput.value = "0x0";
  await readChunk(0);
}

function selectFile(event: Event) {
  const target = event.target as HTMLInputElement;
  const selectedFile = target.files?.[0];
  if (selectedFile) void openFile(selectedFile);
  target.value = "";
}

function onDragOver(event: DragEvent) {
  event.preventDefault();
  dragOver.value = true;
}

function onDragLeave(event: DragEvent) {
  event.preventDefault();
  dragOver.value = false;
}

function onDrop(event: DragEvent) {
  event.preventDefault();
  dragOver.value = false;
  const selectedFile = event.dataTransfer?.files?.[0];
  if (selectedFile) void openFile(selectedFile);
}

function jumpToOffset() {
  if (!file.value) return ElMessage.warning("请先选择文件");
  try {
    void readChunk(parseHexOffset(offsetInput.value));
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "偏移量无效"));
  }
}
</script>

<template>
  <div class="offline-tool-body file-hex-viewer">
    <div class="offline-notice">
      文件只在本机按 512 字节分块读取，不会一次载入整个文件，也不会上传或执行。
    </div>
    <label
      v-if="!file"
      class="file-drop hex-file-drop"
      :class="{ loading, 'drag-over': dragOver }"
      @dragover="onDragOver"
      @dragleave="onDragLeave"
      @drop="onDrop"
    >
      <input type="file" :disabled="loading" @change="selectFile" />
      <el-icon><UploadFilled /></el-icon>
      <strong>选择要查看的本地文件</strong>
      <small>支持大文件，仅读取当前分块</small>
    </label>

    <template v-else>
      <div class="hex-viewer-filebar">
        <span class="hex-viewer-file-icon"><el-icon><Files /></el-icon></span>
        <span class="hex-viewer-file-copy">
          <strong :title="file.name">{{ file.name }}</strong>
          <small>{{ formatSize(file.size) }} · {{ file.type || "未提供 MIME" }}</small>
        </span>
        <label class="hex-viewer-replace">
          <input type="file" :disabled="loading" @change="selectFile" />
          更换文件
        </label>
      </div>

      <div class="hex-viewer-toolbar">
        <div class="hex-viewer-navigation">
          <el-button :disabled="loading || !canPrevious" @click="readChunk(offset - pageSize)">
            上一页
          </el-button>
          <el-button :disabled="loading || !canNext" @click="readChunk(offset + pageSize)">
            下一页
          </el-button>
        </div>
        <form class="hex-viewer-jump" @submit.prevent="jumpToOffset">
          <label for="hex-viewer-offset">跳转偏移</label>
          <el-input
            id="hex-viewer-offset"
            v-model="offsetInput"
            :disabled="loading"
            placeholder="0x200 或 512"
            aria-label="文件偏移量"
          />
          <el-button native-type="submit" type="primary" :loading="loading">
            <el-icon><ArrowRight /></el-icon>跳转
          </el-button>
        </form>
        <span class="hex-viewer-range">
          0x{{ formatHexOffset(pageStart, file.size) }}
          – 0x{{ formatHexOffset(pageEnd, file.size) }}
        </span>
      </div>

      <div v-loading="loading" class="hex-viewer-table-wrap">
        <table class="hex-viewer-table">
          <thead>
            <tr>
              <th>Offset</th>
              <th class="hex-viewer-hex-heading">
                <span v-for="column in 16" :key="column">{{ (column - 1).toString(16).toUpperCase().padStart(2, "0") }}</span>
              </th>
              <th>ASCII</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in rows" :key="row.offset">
              <th scope="row">{{ row.offsetLabel }}</th>
              <td class="hex-viewer-hex-cells">
                <span
                  v-for="(cell, index) in row.hexCells"
                  :key="`${row.offset}-${index}`"
                  :class="{ empty: !cell }"
                >{{ cell || "00" }}</span>
              </td>
              <td class="hex-viewer-ascii">{{ row.ascii }}</td>
            </tr>
          </tbody>
        </table>
        <div v-if="!rows.length" class="hex-viewer-empty">该文件为空文件。</div>
      </div>
    </template>
  </div>
</template>
