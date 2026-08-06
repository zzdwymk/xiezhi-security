<script setup lang="ts">
import { ref } from "vue";
import { ElMessage } from "element-plus";
import {
  parseHttpMessage,
  type HttpMessageInfo,
} from "../../utils/networkSecurity";
import { toErrorMessage } from "../../utils/errorMessage";

const input = ref("");
const result = ref<HttpMessageInfo>();

function analyze() {
  try {
    result.value = parseHttpMessage(input.value);
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "解析失败，请检查报文格式"));
  }
}

function loadResponseExample() {
  input.value = `HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Server: example-server/1.0
Set-Cookie: session=example; Path=/
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin

<html>example</html>`;
  analyze();
}
</script>

<template>
  <div class="offline-tool-body http-analyzer">
    <div class="offline-notice">
      粘贴从代理、抓包或日志中复制的原始报文。本工具只解析文本，不重放请求。
    </div>
    <label class="offline-field"
      >原始 HTTP 报文
      <textarea
        v-model="input"
        placeholder="GET /api/user HTTP/1.1&#10;Host: example.com&#10;..."
      />
    </label>
    <div class="offline-actions">
      <el-button type="primary" @click="analyze">解析报文</el-button>
      <el-button @click="loadResponseExample">载入响应示例</el-button>
      <el-button
        text
        @click="
          input = '';
          result = undefined;
        "
        >清空</el-button
      >
    </div>
    <template v-if="result">
      <div class="http-summary">
        <span>{{ result.type === "request" ? "HTTP 请求" : "HTTP 响应" }}</span>
        <strong>{{ result.startLine }}</strong>
        <small
          >{{ result.headers.length }} 个请求/响应头 · 正文
          {{ result.body.length }} 字符</small
        >
      </div>
      <div class="http-analysis-grid">
        <section>
          <h3>报文头</h3>
          <div class="http-header-list">
            <div
              v-for="(header, index) in result.headers"
              :key="`${header.name}-${index}`"
            >
              <code>{{ header.name }}</code
              ><span>{{ header.value }}</span>
            </div>
          </div>
        </section>
        <section>
          <h3>
            {{ result.type === "response" ? "安全响应头检查" : "请求注意事项" }}
          </h3>
          <div v-if="!result.checks.length" class="http-no-checks">
            没有发现需要提示的项目
          </div>
          <div class="header-check-list">
            <article
              v-for="check in result.checks"
              :key="`${check.name}-${check.message}`"
              :class="check.status"
            >
              <i /><span
                ><strong>{{ check.name }}</strong
                ><small>{{ check.message }}</small></span
              >
            </article>
          </div>
        </section>
      </div>
      <section v-if="result.body" class="http-body-preview">
        <h3>正文预览</h3>
        <pre>{{ result.body }}</pre>
      </section>
    </template>
  </div>
</template>
