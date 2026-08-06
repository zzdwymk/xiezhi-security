<script setup lang="ts">
import { computed, ref } from "vue";
import { ElMessage } from "element-plus";
import { CopyDocument } from "../fluentIcons";
import {
  defangIoc,
  extractIocs,
  refangIoc,
  type IocResult,
} from "../../utils/networkSecurity";

const input = ref("");
const result = ref<IocResult>();
const defanged = ref(false);

const sections = computed(() =>
  result.value
    ? [
        { key: "urls", label: "URL", values: result.value.urls },
        { key: "domains", label: "域名", values: result.value.domains },
        { key: "ipv4", label: "IPv4", values: result.value.ipv4 },
        { key: "emails", label: "邮箱", values: result.value.emails },
        { key: "md5", label: "MD5", values: result.value.md5 },
        { key: "sha1", label: "SHA-1", values: result.value.sha1 },
        { key: "sha256", label: "SHA-256", values: result.value.sha256 },
        { key: "cves", label: "CVE", values: result.value.cves },
      ].filter((section) => section.values.length)
    : [],
);

const total = computed(() =>
  sections.value.reduce((sum, section) => sum + section.values.length, 0),
);

function extract() {
  result.value = extractIocs(input.value);
  defanged.value = false;
  if (!total.value) ElMessage.warning("没有识别出常见 IOC");
}

function displayValues(values: string[]) {
  return (defanged.value ? values.map(defangIoc) : values).join("\n");
}

function toggleDefang() {
  defanged.value = !defanged.value;
}

function refangInput() {
  input.value = refangIoc(input.value);
  result.value = undefined;
}

async function copy(value: string) {
  if (!value) return;
  await navigator.clipboard.writeText(value);
  ElMessage.success("已复制");
}
</script>

<template>
  <div class="offline-tool-body ioc-extractor">
    <div class="offline-notice">
      从告警、日志、邮件或报告文本中提取常见威胁指标；不会查询信誉库或连接这些地址。
    </div>
    <label class="offline-field"
      >待分析文本<textarea
        v-model="input"
        placeholder="粘贴包含 URL、域名、IP、文件哈希或 CVE 编号的文本"
      />
    </label>
    <div class="offline-actions">
      <el-button type="primary" @click="extract">提取 IOC</el-button>
      <el-button :disabled="!result" @click="toggleDefang">{{
        defanged ? "显示原始格式" : "安全化显示（Defang）"
      }}</el-button>
      <el-button @click="refangInput">还原输入中的 [.] / hxxp</el-button>
    </div>
    <div v-if="result" class="ioc-summary">
      共提取 <strong>{{ total }}</strong> 个去重指标，覆盖
      {{ sections.length }} 种类型
    </div>
    <div v-if="sections.length" class="ioc-result-grid">
      <article v-for="section in sections" :key="section.key">
        <header>
          <strong>{{ section.label }}</strong
          ><span>{{ section.values.length }}</span
          ><button type="button" @click="copy(displayValues(section.values))">
            <el-icon><CopyDocument /></el-icon>
          </button>
        </header>
        <textarea :value="displayValues(section.values)" readonly />
      </article>
    </div>
  </div>
</template>
