<script setup lang="ts">
import { ref } from "vue";
import { ElMessage } from "element-plus";
import { CopyDocument, UploadFilled } from "../fluentIcons";
import { bytesToHex, md5Bytes } from "../../utils/offlineCrypto";
import { toErrorMessage } from "../../utils/errorMessage";

interface FileResult {
  name: string;
  size: number;
  mime: string;
  detectedType: string;
  magic: string;
  entropy: number;
  hashes: Record<string, string>;
}

const loading = ref(false);
const result = ref<FileResult>();

function detectType(bytes: Uint8Array) {
  const hex = bytesToHex(bytes.subarray(0, 16)).toUpperCase();
  if (hex.startsWith("52494646") && hex.slice(16, 24) === "57454250")
    return "WebP 图片";
  const signatures: Array<[string, string[]]> = [
    ["PNG 图片", ["89504E470D0A1A0A"]],
    ["JPEG 图片", ["FFD8FF"]],
    ["GIF 图片", ["474946383761", "474946383961"]],
    ["PDF 文档", ["25504446"]],
    ["ZIP / Office / JAR 压缩容器", ["504B0304", "504B0506", "504B0708"]],
    ["DOS MZ / Windows PE 候选文件", ["4D5A"]],
    ["ELF 可执行文件", ["7F454C46"]],
    ["GZIP 压缩文件", ["1F8B08"]],
    ["RAR 压缩文件", ["526172211A0700", "526172211A070100"]],
    ["7-Zip 压缩文件", ["377ABCAF271C"]],
    ["RIFF 容器", ["52494646"]],
    ["SQLite 数据库", ["53514C69746520666F726D6174203300"]],
  ];
  return (
    signatures.find(([, values]) =>
      values.some((value) => hex.startsWith(value)),
    )?.[0] || "未知或纯文本类型"
  );
}

function calculateEntropy(bytes: Uint8Array) {
  if (!bytes.length) return 0;
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte]++;
  let entropy = 0;
  for (const count of counts) {
    if (!count) continue;
    const probability = count / bytes.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

async function selectFile(event: Event) {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];
  if (!file) return;
  if (file.size > 128 * 1024 * 1024) {
    target.value = "";
    return ElMessage.error("为避免占用过多内存，单个文件最大支持 128 MB");
  }
  loading.value = true;
  try {
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const [sha1, sha256, sha512] = await Promise.all([
      crypto.subtle.digest("SHA-1", buffer),
      crypto.subtle.digest("SHA-256", buffer),
      crypto.subtle.digest("SHA-512", buffer),
    ]);
    result.value = {
      name: file.name,
      size: file.size,
      mime: file.type || "浏览器未提供",
      detectedType: detectType(bytes),
      magic: bytesToHex(bytes.subarray(0, 16)).toUpperCase() || "空文件",
      entropy: calculateEntropy(bytes),
      hashes: {
        MD5: md5Bytes(bytes),
        "SHA-1": bytesToHex(new Uint8Array(sha1)),
        "SHA-256": bytesToHex(new Uint8Array(sha256)),
        "SHA-512": bytesToHex(new Uint8Array(sha512)),
      },
    };
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "文件分析失败"));
  } finally {
    loading.value = false;
    target.value = "";
  }
}

async function copy(value: string) {
  try {
    await navigator.clipboard.writeText(value);
    ElMessage.success("已复制");
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "复制失败"));
  }
}

function formatSize(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(2)} KB`;
  return `${(value / 1024 ** 2).toFixed(2)} MB`;
}
</script>

<template>
  <div class="offline-tool-body file-inspector">
    <div class="offline-notice">
      文件只在当前页面内读取，用于魔数、熵和哈希计算；不会上传、执行或解压文件。
    </div>
    <label class="file-drop" :class="{ loading }">
      <input type="file" :disabled="loading" @change="selectFile" />
      <el-icon><UploadFilled /></el-icon>
      <strong>{{ loading ? "正在计算文件摘要…" : "选择本地文件" }}</strong>
      <small>最大 128 MB</small>
    </label>
    <template v-if="result">
      <div class="file-meta-grid">
        <article>
          <span>文件名</span><strong>{{ result.name }}</strong>
        </article>
        <article>
          <span>文件大小</span><strong>{{ formatSize(result.size) }}</strong>
        </article>
        <article>
          <span>浏览器 MIME</span><strong>{{ result.mime }}</strong>
        </article>
        <article>
          <span>魔数推断</span><strong>{{ result.detectedType }}</strong>
        </article>
        <article>
          <span>信息熵</span><strong>{{ result.entropy.toFixed(4) }} / 8</strong
          ><small>{{
            result.entropy > 7.2
              ? "高熵，可能经过压缩或加密"
              : "未表现出异常高熵"
          }}</small>
        </article>
        <article>
          <span>文件头 16 字节</span><code>{{ result.magic }}</code>
        </article>
      </div>
      <div class="hash-results file-hash-results">
        <article v-for="(value, name) in result.hashes" :key="name">
          <header>
            <strong>{{ name }}</strong
            ><button type="button" @click="copy(value)">
              <el-icon><CopyDocument /></el-icon>复制
            </button>
          </header>
          <code>{{ value }}</code>
        </article>
      </div>
    </template>
  </div>
</template>
