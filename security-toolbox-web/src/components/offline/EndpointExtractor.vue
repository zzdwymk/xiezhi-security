<script setup lang="ts">
import { ref } from "vue";
import { ElMessage } from "element-plus";
import {
  extractEndpoints,
  type EndpointResult,
} from "../../utils/networkSecurity";
import { toErrorMessage } from "../../utils/errorMessage";

const baseUrl = ref("");
const input = ref("");
const result = ref<EndpointResult>();

function extract() {
  try {
    result.value = extractEndpoints(input.value, baseUrl.value);
    if (!result.value.urls.length && !result.value.paths.length)
      ElMessage.warning("未发现 URL 或接口路径");
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "提取失败，请检查输入内容"));
  }
}
</script>

<template>
  <div class="offline-tool-body endpoint-extractor">
    <div class="offline-notice">
      参考 JS 链接提取工具的思路，但只分析粘贴到这里的源码或文本，不抓取网站。
    </div>
    <label class="offline-field compact"
      >基础 URL（可选）
      <el-input
        v-model="baseUrl"
        placeholder="例如 https://example.com/app/，用于补全相对路径"
      />
    </label>
    <label class="offline-field"
      >HTML / JavaScript / 日志文本
      <el-input
        v-model="input"
        type="textarea"
        :autosize="{ minRows: 3 }"
        placeholder="粘贴源码后提取绝对 URL、相对接口路径和域名"
      />
    </label>
    <div class="offline-actions">
      <el-button type="primary" @click="extract">提取端点</el-button>
    </div>
    <div v-if="result" class="endpoint-results">
      <article>
        <header>
          <strong>完整 URL</strong><span>{{ result.urls.length }}</span>
        </header>
        <el-input :value="result.urls.join('\n')" type="textarea" :autosize="{ minRows: 3 }" readonly />
      </article>
      <article>
        <header>
          <strong>相对路径</strong><span>{{ result.paths.length }}</span>
        </header>
        <el-input :value="result.paths.join('\n')" type="textarea" :autosize="{ minRows: 3 }" readonly />
      </article>
      <article>
        <header>
          <strong>关联域名</strong><span>{{ result.domains.length }}</span>
        </header>
        <el-input :value="result.domains.join('\n')" type="textarea" :autosize="{ minRows: 3 }" readonly />
      </article>
    </div>
  </div>
</template>
