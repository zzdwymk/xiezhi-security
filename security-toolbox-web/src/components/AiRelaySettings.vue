<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from "vue";
import MarkdownBody from "./MarkdownBody.vue";

const bridge = window.toolboxDesktop;
const emit = defineEmits<{ "saved-mode": [enabled: boolean] }>();
const settings = reactive<AiRelaySettings>({ enabled: false, providers: [] });
const originals = new Map<string, AiRelayProvider>();
const status = ref<AiRelayStatus>();
const loading = ref(true);
const saving = ref(false);
const refreshing = ref(false);
const testing = ref<string>();
const fetchingModels = ref<string>();
const modelLists = reactive<Record<string, string[]>>({});
const modelMessages = reactive<Record<string, string>>({});
const message = ref("");
const messageType = ref<"success" | "error" | "info">("info");
const results = reactive<Record<string, { ok: boolean; message: string; target?: string; reply?: string }>>({});
const testPrompt = ref("你好，请简短介绍自己。");
const selected = ref("");
const provider = computed(() => settings.providers.find((item) => item.id === selected.value));
const busy = computed(() => loading.value || saving.value || Boolean(testing.value) || Boolean(fetchingModels.value));
const savedSnapshot = ref(JSON.stringify(settings));
const dirty = computed(() => JSON.stringify(settings) !== savedSnapshot.value);
const canSave = computed(() => !busy.value && dirty.value && (!settings.enabled || settings.providers.some((item) => item.enabled)));
defineExpose({ save, busy, saving, canSave, dirty });

watch(() => settings.providers.map((item) => ({ id: item.id, connection: JSON.stringify([item.baseUrl, item.apiKey, item.apiMode, item.codexHeaders]) })), (next, previous) => {
  const old = new Map(previous.map((item) => [item.id, item.connection]));
  for (const item of next) {
    if (old.get(item.id) !== item.connection) {
      delete modelLists[item.id];
      delete modelMessages[item.id];
    }
  }
});

function upstreamMessage(code: string, ok = false): string {
  if (ok) return "线路测试成功，已收到完整模型回答。";
  const messages: Record<string, string> = {
    invalid_test_prompt: "测试内容不能为空，且最多 4000 字。",
    invalid_responses_request: "上游不接受当前 Responses 请求格式，请检查 Codex 兼容模式（HTTP 400）。",
    model_not_found: "此 API 不支持所选模型，请获取模型列表后重新选择。",
    upstream_overloaded: "上游模型负载已达上限，请稍后重试或添加另一条 API 线路。",
    upstream_unavailable: "上游没有可用的模型通道，请更换模型或 API 线路。",
    http_404: "接口或模型不存在（HTTP 404）。Codex 模型请使用 Responses，并开启 Codex 兼容模式。",
    http_401: "API 身份验证失败，请检查密钥（HTTP 401）。",
    http_403: "API 拒绝访问，请检查密钥权限（HTTP 403）。",
    http_429: "API 请求过多或额度不足（HTTP 429）。",
    http_500: "上游服务内部错误（HTTP 500）。",
    timeout: "上游响应超时。",
    connection_failed: "无法连接此 API，请检查地址和网络。",
    upstream_incomplete: "上游响应不完整，未展示本次回答。",
    empty_answer: "上游未返回有效回答。",
    all_providers_unavailable: "本次请求尝试的线路均不可用。",
    no_enabled_providers: "没有已启用的线路。",
    all_providers_cooling_down: "所有线路都在冷却中，请稍后重试。",
    request_cancelled: "本次请求已取消。",
  };
  return messages[code] || (/^http_\d{3}$/.test(code)
    ? `上游请求失败（HTTP ${code.slice(5)}）。`
    : "上游请求失败，请检查配置后重试。");
}

function errorMessage(error: unknown) {
  const raw = error instanceof Error ? error.message : String(error);
  return raw.replace(/^Error invoking remote method '[^']+':\s*/i, "")
    .replace(/^(?:Error:\s*)?UserFacingError:\s*/i, "");
}

function applySettings(value: AiRelaySettings) {
  settings.enabled = value.enabled;
  emit("saved-mode", value.enabled);
  settings.providers = value.providers.map((item) => ({ ...item, apiKey: "" }));
  originals.clear();
  for (const item of settings.providers) originals.set(item.id, { ...item });
  savedSnapshot.value = JSON.stringify(settings);
  if (!settings.providers.some((item) => item.id === selected.value)) {
    selected.value = settings.providers[0]?.id ?? "";
  }
}

async function refreshStatus() {
  if (!bridge?.getAiRelayStatus) return;
  refreshing.value = true;
  try {
    status.value = await bridge.getAiRelayStatus();
  } catch (error) {
    message.value = `无法读取运行状态：${errorMessage(error)}`;
    messageType.value = "error";
  } finally {
    refreshing.value = false;
  }
}

onMounted(async () => {
  try {
    if (!bridge?.getAiRelaySettings) throw new Error("当前桌面版本不支持 API 线路，请更新 EXE。");
    applySettings(await bridge.getAiRelaySettings());
    await refreshStatus();
  } catch (error) {
    message.value = errorMessage(error);
    messageType.value = "error";
  } finally {
    loading.value = false;
  }
});

function addProvider() {
  if (settings.providers.length >= 16) return;
  const item: AiRelayProvider = {
    id: crypto.randomUUID(), name: `线路 ${settings.providers.length + 1}`,
    baseUrl: "", model: "", apiMode: "chat_completions", codexHeaders: false,
    enabled: true, apiKey: "",
  };
  settings.providers.push(item);
  selected.value = item.id;
}

function removeProvider(id: string) {
  settings.providers = settings.providers.filter((item) => item.id !== id);
  if (!settings.providers.length) settings.enabled = false;
  delete results[id];
  selected.value = settings.providers[0]?.id ?? "";
  message.value = "线路已从草稿移除，保存后生效。";
  messageType.value = "info";
}

function validate(item: AiRelayProvider, requireModel = true): string {
  if (!item.name.trim()) return "请填写线路名称。";
  if (requireModel && !item.model.trim()) return `${item.name}：请填写模型名称。`;
  let url: URL;
  try { url = new URL(item.baseUrl); } catch { return `${item.name}：请输入完整 API 地址。`; }
  if (!["https:", "http:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    return `${item.name}：API 地址须为 HTTP(S) 地址，不能包含账号、密码、查询参数或片段。`;
  }
  const original = originals.get(item.id);
  if (original?.hasApiKey && original.baseUrl.replace(/\/+$/, "") !== item.baseUrl.trim().replace(/\/+$/, "") && !item.apiKey?.trim()) {
    return `${item.name}：API 地址已更改，请为新地址重新填写密钥。`;
  }
  return "";
}

async function save() {
  if (busy.value || !dirty.value) return false;
  message.value = "";
  const invalid = settings.providers.map((item) => validate(item)).find(Boolean);
  if (invalid || (settings.enabled && !settings.providers.some((item) => item.enabled))) {
    message.value = invalid || "请至少添加并启用一条 API 线路。";
    messageType.value = "error";
    return false;
  }
  saving.value = true;
  try {
    if (!bridge?.saveAiRelaySettings) throw new Error("当前桌面版本不支持保存 API 线路。");
    const payload: AiRelaySettings = {
      enabled: settings.enabled,
      providers: settings.providers.map((item) => ({ ...item, name: item.name.trim(), baseUrl: item.baseUrl.trim(), model: item.model.trim() })),
    };
    applySettings(await bridge.saveAiRelaySettings(payload));
    message.value = "线路配置已保存。";
    messageType.value = "success";
    await refreshStatus();
    return true;
  } catch (error) {
    message.value = errorMessage(error);
    messageType.value = "error";
    return false;
  } finally { saving.value = false; }
}

async function test(item: AiRelayProvider) {
  delete results[item.id];
  if (!testPrompt.value.trim()) {
    results[item.id] = { ok: false, message: "请输入测试内容。" };
    return;
  }
  if (testPrompt.value.length > 4000) {
    results[item.id] = { ok: false, message: "测试内容不能超过 4000 字符。" };
    return;
  }
  const invalid = validate(item);
  if (invalid) { results[item.id] = { ok: false, message: invalid }; return; }
  testing.value = item.id;
  try {
    if (!bridge?.testAiRelayProvider) throw new Error("当前桌面版本不支持线路测试。");
    const result = await bridge.testAiRelayProvider({ ...item }, testPrompt.value);
    results[item.id] = { ...result, message: upstreamMessage(result.reason || result.message, result.ok), target: `${item.model} · ${item.baseUrl} · ${item.apiMode === 'responses' ? 'Responses' : 'Chat Completions'}` };
  } catch (error) {
    results[item.id] = { ok: false, message: errorMessage(error), target: `${item.model} · ${item.baseUrl}` };
  } finally {
    testing.value = undefined;
    await refreshStatus();
  }
}

async function fetchModels(item: AiRelayProvider) {
  const invalid = validate(item, false);
  if (invalid) { modelMessages[item.id] = invalid; return; }
  fetchingModels.value = item.id;
  try {
    if (!bridge?.listAiRelayModels) throw new Error("当前桌面版本不支持获取模型列表。");
    const result = await bridge.listAiRelayModels({ ...item });
    modelLists[item.id] = result.models;
    modelMessages[item.id] = result.models.length
      ? `已获取 ${result.models.length} 个模型，可筛选选择，也可手动输入。`
      : "此 API 未返回模型列表，请手动输入模型名称。";
  } catch (error) {
    modelMessages[item.id] = errorMessage(error);
  } finally { fetchingModels.value = undefined; }
}

function cooldown(until: number) {
  return until > Date.now() ? `冷却至 ${new Date(until).toLocaleTimeString()}` : "未处于冷却期";
}
</script>

<template>
  <div v-loading="loading" class="relay-settings">
    <p class="relay-description">一条线路直接使用，多条线路自动轮询，失败时切换。</p>
    <div class="relay-toolbar">
      <el-switch v-model="settings.enabled" :disabled="busy || !settings.providers.length" active-text="使用 API 线路" />
    </div>
    <el-alert v-if="message" :title="message" :type="messageType" :closable="false" show-icon />

    <div v-if="settings.providers.length" class="relay-editor">
      <nav class="relay-list" aria-label="API 线路">
        <div class="relay-toolbar"><strong>线路</strong><el-button size="small" :disabled="busy || settings.providers.length >= 16" @click="addProvider">添加 API</el-button></div>
        <button v-for="item in settings.providers" :key="item.id" type="button" class="relay-list-item" :class="{ selected: selected === item.id }" @click="selected = item.id">
          <strong>{{ item.name || '未命名线路' }}</strong>
          <small>{{ item.enabled ? '已启用' : '已停用' }} · {{ item.model || '未填模型' }}</small>
        </button>
      </nav>
      <el-form v-if="provider" :key="provider.id" class="relay-form" label-position="top" :disabled="busy">
        <el-form-item label="线路名称"><el-input v-model="provider.name" maxlength="80" placeholder="例如：主用 API" /></el-form-item>
        <el-form-item label="API 基础地址"><el-input v-model="provider.baseUrl" placeholder="https://api.example.com/v1" /></el-form-item>
        <el-form-item label="模型名称">
          <div class="relay-model-picker">
            <el-select v-model="provider.model" filterable allow-create default-first-option placeholder="选择或手动输入模型 ID" style="flex: 1; min-width: 0">
              <el-option v-for="model in modelLists[provider.id] ?? []" :key="model" :label="model" :value="model" />
            </el-select>
            <el-button :loading="fetchingModels === provider.id" @click="fetchModels(provider)">获取模型列表</el-button>
          </div>
          <small v-if="modelMessages[provider.id]" class="relay-help">{{ modelMessages[provider.id] }}</small>
        </el-form-item>
        <el-form-item label="API Key">
          <el-input v-model="provider.apiKey" type="password" autocomplete="new-password" :placeholder="provider.hasApiKey ? '已存密钥；留空保留原密钥' : '输入密钥；本地匿名 API 可留空'" />
          <small v-if="provider.hasApiKey" class="relay-help">更换地址需重新填写密钥。</small>
        </el-form-item>
        <el-form-item><el-switch v-model="provider.enabled" active-text="启用此线路" /></el-form-item>
        <details class="relay-details">
          <summary>高级选项</summary>
          <el-form-item label="接口协议">
            <el-select v-model="provider.apiMode" style="width: 100%" @change="provider.apiMode !== 'responses' && (provider.codexHeaders = false)">
              <el-option label="Chat Completions" value="chat_completions" />
              <el-option label="Responses" value="responses" />
            </el-select>
          </el-form-item>
          <el-form-item><el-checkbox v-model="provider.codexHeaders" @change="provider.codexHeaders && (provider.apiMode = 'responses')">Codex 兼容模式（Responses）</el-checkbox></el-form-item>
        </details>
        <details class="relay-details">
          <summary>测试连接</summary>
          <el-form-item label="测试内容">
            <el-input v-model="testPrompt" type="textarea" :rows="3" maxlength="4000" show-word-limit placeholder="输入要发送给模型的内容" />
          </el-form-item>
          <el-button :loading="testing === provider.id" :disabled="!testPrompt.trim()" @click="test(provider)">发送测试</el-button>
          <el-alert v-if="results[provider.id]" :title="results[provider.id]!.message" :type="results[provider.id]!.ok ? 'success' : 'error'" :closable="false" show-icon />
          <MarkdownBody v-if="results[provider.id]?.ok && results[provider.id]?.reply" class="relay-test-reply" :content="results[provider.id]!.reply!" />
          <small v-if="results[provider.id]?.target" class="relay-help">测试目标：{{ results[provider.id]!.target }}</small>
        </details>
        <el-button type="danger" link @click="removeProvider(provider.id)">删除线路</el-button>
      </el-form>
    </div>
    <div v-else class="relay-empty"><span>尚未添加 API</span><el-button type="primary" :disabled="busy" @click="addProvider">添加 API</el-button></div>

    <details class="relay-status relay-details">
      <summary>运行状态与重试机制</summary>
      <div class="relay-toolbar">
        <strong>运行状态</strong>
        <el-button size="small" :loading="refreshing" @click="refreshStatus">刷新状态</el-button>
      </div>
      <p v-if="status">{{ !status.enabled ? 'API 线路未启用' : status.running ? '线路服务运行中；可用性以请求结果为准' : '已启用，线路服务未运行' }}</p>
      <p v-else>尚未取得运行状态。</p>
      <div v-for="item in status?.providers ?? []" :key="item.id" class="relay-status-row">
        <strong>{{ item.name }}</strong>
        <span>请求 {{ item.requests }} · 成功 {{ item.successes }} · 失败 {{ item.failures }} · {{ cooldown(item.cooldownUntil) }}</span>
        <small v-if="item.lastError">最近错误：{{ upstreamMessage(item.lastReason || item.lastError) }}</small>
      </div>
      <p class="relay-help">每次请求每条线路最多尝试一次；单线路最多 30 秒，总计最多 40 秒，失败冷却 30 秒。收到完整回答后展示。启停会短暂重启服务，线路修改保存后对新请求生效。最多 16 条线路。</p>
    </details>
  </div>
</template>

<style scoped>
.relay-settings { display: grid; gap: 16px; max-height: 73vh; overflow-y: auto; padding: 2px 8px 4px 2px; }
.relay-description, .relay-help { color: var(--el-text-color-secondary); font-size: 13px; line-height: 1.6; margin: 0; }
.relay-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.relay-editor { display: grid; grid-template-columns: 180px minmax(0, 1fr); gap: 20px; }
.relay-list { display: flex; flex-direction: column; gap: 8px; }
.relay-list-item { display: grid; gap: 6px; text-align: left; border: 1px solid var(--el-border-color); color: var(--el-text-color-primary); background: var(--el-fill-color-blank); border-radius: 7px; padding: 12px; cursor: pointer; overflow-wrap: anywhere; }
.relay-list-item.selected { border-color: var(--el-color-primary); background: var(--el-color-primary-light-9); }
.relay-list small { color: var(--el-text-color-secondary); }
.relay-form { min-width: 0; }
.relay-model-picker { display: flex; gap: 8px; width: 100%; }
.relay-form .el-alert { margin-top: 12px; }
.relay-help { display: block; flex-basis: 100%; margin-top: 10px; }
.relay-status { border-top: 1px solid var(--el-border-color); padding-top: 14px; font-size: 13px; }
.relay-status-row { display: grid; gap: 5px; padding: 8px 0; overflow-wrap: anywhere; }
.relay-status-row small { color: var(--el-color-danger); }
.relay-empty { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 20px; border: 1px dashed var(--el-border-color); border-radius: 8px; color: var(--el-text-color-secondary); }
.relay-details > summary { cursor: pointer; color: var(--el-text-color-secondary); font-size: 13px; padding-bottom: 12px; }
.relay-details[open] > summary { margin-bottom: 4px; }
.relay-test-reply { margin: 12px 0; padding: 12px; border-radius: var(--fluent-radius-control, 6px); background: var(--el-fill-color-light); }
@media (max-width: 660px) { .relay-editor { grid-template-columns: 1fr; } .relay-list { flex-direction: row; flex-wrap: wrap; } }
</style>
