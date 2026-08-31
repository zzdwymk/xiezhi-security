<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Aim,
  ArrowRight,
  ChatDotRound,
  Compass,
  Delete,
  Document,
  Download,
  Key,
  MagicStick,
  Setting,
  Tools,
} from "../components/fluentIcons";
import { useCopilotStore } from "../stores/copilot";
import { useAuthStore } from "../stores/auth";
import { useConversationStore } from "../stores/conversations";
import { endpoints } from "../api";
import { toErrorMessage } from "../utils/errorMessage";

const router = useRouter();
const auth = useAuthStore();
const copilot = useCopilotStore();
const conversations = useConversationStore();
const isDesktop = Boolean(window.toolboxDesktop);
const canClearData = computed(() => auth.user?.role === "ADMIN");
const clearingData = ref(false);
const clearDataResult = ref<{
  type: "success" | "error";
  message: string;
}>();
const pwdVisible = ref(false);
const pwdSaving = ref(false);
const pwdForm = reactive({ current: "", next: "", confirm: "" });
async function changeLoginPassword() {
  if (pwdSaving.value) return;
  if (!pwdForm.current.trim()) return ElMessage.warning("请输入当前密码");
  if (pwdForm.next.length < 8) return ElMessage.warning("新密码至少 8 位");
  if (pwdForm.next !== pwdForm.confirm)
    return ElMessage.warning("两次输入的新密码不一致");
  pwdSaving.value = true;
  try {
    await endpoints.changePassword({
      currentPassword: pwdForm.current,
      newPassword: pwdForm.next,
    });
    let desktopSyncFailed = false;
    if (isDesktop && window.toolboxDesktop?.setDesktopAdminPassword) {
      try {
        await window.toolboxDesktop.setDesktopAdminPassword(pwdForm.next);
      } catch {
        desktopSyncFailed = true;
      }
    }
    ElMessage.success(
      desktopSyncFailed
        ? "登录密码已修改，但本机凭据同步失败；请重新登录或重试同步"
        : "登录密码已修改；账号密码 / 本机凭据 / Windows Hello 均已同步为新密码",
    );
    pwdVisible.value = false;
    pwdForm.current = "";
    pwdForm.next = "";
    pwdForm.confirm = "";
  } catch (error: any) {
    ElMessage.error(errorText(error, "修改登录密码失败"));
  } finally {
    pwdSaving.value = false;
  }
}
const aiDialog = ref(false);
const aiLoading = ref(false);
const aiTesting = ref(false);
const embeddingTesting = ref(false);
const aiSaving = ref(false);
const windowMaterial = ref<WindowMaterial>("mica");
const materialSaving = ref(false);
const aiStatus = ref<AiSettingsStatus>();
const icpDialog = ref(false);
const icpLoading = ref(false);
const icpSaving = ref(false);
const icpStatus = ref<IcpSettingsStatus>();
const icpForm = reactive<IcpSettingsInput>({ apiUrl: "" });
const githubDialog = ref(false);
const githubLoading = ref(false);
const githubSaving = ref(false);
const githubStatus = ref<GithubTokenSettingsStatus>();
const githubForm = reactive<{ token: string }>({ token: "" });
const toolDownloadDialog = ref(false);
const toolDownloadLoading = ref(false);
const toolDownloadSaving = ref(false);
const toolDownloadStatus = ref<ToolDownloadSettingsStatus>();
const toolDownloadForm = reactive({ mode: "github" as "github" | "custom", mirror: "" });
const aiForm = reactive<AiSettingsInput>({
  baseUrl: "https://api.openai.com",
  model: "gpt-4.1-mini",
  retrievalBackend: "bm25",
  embeddingModel: "text-embedding-3-small",
  embeddingConnectionMode: "shared",
  embeddingBaseUrl: "https://api.openai.com",
  embeddingApiKey: "",
  apiKey: "",
  proxyMode: false,
});

const hasIndependentEmbedding = computed(
  () =>
    aiStatus.value?.retrievalBackend === "real_embedding" &&
    aiStatus.value.embeddingConnectionMode === "custom",
);

const aiServiceSummary = computed(() => {
  if (!isDesktop) return "网页模式请通过服务端配置";
  const status = aiStatus.value;
  if (!status) return "正在读取配置";

  const chatSummary =
    status.provider === "openai-compatible"
      ? status.proxyMode
        ? `对话使用本地代理连接（${status.model}）`
        : `对话服务已连接（${status.model}）`
      : "对话使用本地规则";
  const embeddingConnection =
    status.embeddingConnectionMode === "shared"
      ? "复用对话连接"
      : "单独配置";
  const embeddingState =
    status.embeddingConnectionMode === "shared" &&
    status.provider !== "openai-compatible"
      ? "向量检索待连接"
      : "向量检索";
  const retrievalSummary =
    status.retrievalBackend === "real_embedding"
      ? `${embeddingState}（${embeddingConnection} · ${status.embeddingModel}）`
      : "关键词检索";
  const keySummary =
    status.provider === "openai-compatible" && status.keyHint
      ? ` · ${status.keyHint}`
      : "";
  return `${chatSummary} · ${retrievalSummary}${keySummary}`;
});

const toolDownloadSummary = computed(() => {
  if (!isDesktop) return "网页模式请通过服务端环境变量配置";
  const mirror = toolDownloadStatus.value?.configuredMirror || "";
  if (mirror) return `已使用镜像源 · ${mirror}`;
  return "直连 GitHub 官方源（连接不稳定时可改用镜像源）";
});

const aiConnectionAlert = computed(() => {
  if (aiStatus.value?.provider === "openai-compatible") {
    return {
      type: "success" as const,
      title: aiStatus.value.proxyMode
        ? "对话服务已通过本地代理连接"
        : aiStatus.value.keyHint
          ? `对话服务已启用（${aiStatus.value.keyHint}）`
          : "对话服务已启用",
    };
  }
  if (hasIndependentEmbedding.value) {
    return {
      type: "info" as const,
      title: "对话使用本地规则；向量检索使用单独配置的连接。",
    };
  }
  return {
    type: "warning" as const,
    title: "尚未配置对话服务，对话会使用本地规则生成计划和回答。",
  };
});

function rerunSetup() {
  localStorage.removeItem("security_toolbox_setup_complete_v2");
  router.push({ path: "/setup", query: { redirect: "/settings" } });
}

function troubleshootWithCopilot() {
  const provider = aiStatus.value?.provider || "local-rules";
  copilot.open({
    mode: "troubleshoot",
    prompt: "请根据当前 AI 服务的非敏感配置状态，给出连接诊断和配置检查步骤。",
    entity: {
      type: "ai-settings-status",
      title: "AI 模型服务状态",
      source: "settings",
      summary:
        "仅共享 provider、model、代理模式与连接配置状态；API Key、Key 提示和 API 地址均未发送。",
      data: {
        provider,
        model: aiStatus.value?.model || aiForm.model,
        retrievalBackend:
          aiStatus.value?.retrievalBackend || aiForm.retrievalBackend,
        embeddingModel:
          aiStatus.value?.embeddingModel || aiForm.embeddingModel,
        embeddingConnectionMode:
          aiStatus.value?.embeddingConnectionMode ||
          aiForm.embeddingConnectionMode,
        proxyMode: Boolean(aiStatus.value?.proxyMode),
        configured:
          aiStatus.value?.provider === "openai-compatible" ||
          hasIndependentEmbedding.value,
      },
    },
  });
  void router.push("/");
}

function errorText(error: unknown, fallback: string) {
  return toErrorMessage(error, fallback);
}

function clearDataErrorText(error: unknown) {
  const status = (error as { response?: { status?: number } })?.response?.status;
  if (status === 400)
    return "仍有等待中或运行中的任务，或流量代理正在启动或运行；请先结束后再清空";
  if (status === 403) return "当前账号没有清空业务数据的管理员权限";
  return errorText(error, "清空业务数据失败");
}

function clearBusinessDataCaches() {
  conversations.clear();
  copilot.clear();
  localStorage.removeItem("security_toolbox_ai_conversations_v1");
  localStorage.removeItem("security_toolbox_dashboard_target");
  localStorage.removeItem("security_toolbox_traffic_chats_v1");
}

async function clearBusinessData() {
  if (clearingData.value) return;
  if (!canClearData.value)
    return ElMessage.warning("只有管理员可以清空业务数据");

  try {
    await ElMessageBox.confirm(
      "将永久删除项目、授权目标、任务、发现、审批、扫描结果、计划任务、流量记录和 AI 业务数据。管理员账户、工作流规范、检测规则、漏洞定义、流量过滤器和应用设置会保留。此操作不可撤销。",
      "清空全部业务数据",
      {
        confirmButtonText: "继续",
        cancelButtonText: "取消",
        type: "error",
      },
    );
    await ElMessageBox.prompt(
      "请输入 CLEAR 确认永久清空。存在等待中或运行中的任务、正在启动或运行的流量代理时，系统会拒绝操作。",
      "最终确认",
      {
        confirmButtonText: "永久清空",
        cancelButtonText: "取消",
        type: "error",
        inputPlaceholder: "CLEAR",
        inputPattern: /^CLEAR$/,
        inputErrorMessage: "请输入大写 CLEAR",
        inputValidator: (value) =>
          value === "CLEAR" ? true : "请输入大写 CLEAR",
      },
    );

    clearingData.value = true;
    clearDataResult.value = undefined;
    const { data } = await endpoints.clearBusinessData();
    clearBusinessDataCaches();
    const count = Number.isFinite(data.deletedRecords)
      ? data.deletedRecords
      : 0;
    clearDataResult.value = {
      type: "success",
      message: `已清空 ${count} 条业务记录，清空操作审计已保留`,
    };
    ElMessage.success("业务数据已清空");
  } catch (error) {
    if (error === "cancel" || error === "close") return;
    const message = clearDataErrorText(error);
    clearDataResult.value = { type: "error", message };
    ElMessage.error(message);
  } finally {
    clearingData.value = false;
  }
}

async function loadMicaSetting() {
  if (!window.toolboxDesktop?.getWindowMaterial) return;
  windowMaterial.value = await window.toolboxDesktop.getWindowMaterial();
}

async function changeWindowMaterial(material: WindowMaterial) {
  if (!window.toolboxDesktop?.setWindowMaterial) return;
  const previous = windowMaterial.value;
  materialSaving.value = true;
  try {
    windowMaterial.value =
      await window.toolboxDesktop.setWindowMaterial(material);
    const labels: Record<WindowMaterial, string> = {
      none: "关闭",
      mica: "Mica",
      acrylic: "Acrylic",
    };
    ElMessage.success(`窗口材质已切换为 ${labels[windowMaterial.value]}`);
  } catch (error) {
    windowMaterial.value = previous;
    ElMessage.error(errorText(error, "无法修改窗口材质设置"));
  } finally {
    materialSaving.value = false;
  }
}

async function loadAiSettings(open = false) {
  if (open) aiDialog.value = true;
  if (!window.toolboxDesktop?.getAiSettings) return;
  aiLoading.value = true;
  try {
    aiStatus.value = await window.toolboxDesktop.getAiSettings();
    aiForm.baseUrl = aiStatus.value.baseUrl;
    aiForm.model = aiStatus.value.model;
    aiForm.retrievalBackend = aiStatus.value.retrievalBackend;
    aiForm.embeddingModel = aiStatus.value.embeddingModel;
    aiForm.embeddingConnectionMode = aiStatus.value.embeddingConnectionMode;
    aiForm.embeddingBaseUrl = aiStatus.value.embeddingBaseUrl;
    aiForm.apiKey = "";
    aiForm.embeddingApiKey = "";
    aiForm.proxyMode = aiStatus.value.proxyMode;
  } catch (error) {
    ElMessage.error(errorText(error, "无法读取 AI 设置"));
  } finally {
    aiLoading.value = false;
  }
}

async function testEmbedding() {
  if (!window.toolboxDesktop?.testEmbeddingSettings)
    return ElMessage.warning("向量连接测试仅支持桌面应用");
  embeddingTesting.value = true;
  try {
    const result = await window.toolboxDesktop.testEmbeddingSettings({ ...aiForm });
    ElMessage.success(result.message);
  } catch (error) {
    ElMessage.error(errorText(error, "向量服务连接失败"));
  } finally {
    embeddingTesting.value = false;
  }
}

async function testAi() {
  if (!window.toolboxDesktop?.testAiSettings)
    return ElMessage.warning("AI 设置仅支持桌面应用");
  aiTesting.value = true;
  try {
    const result = await window.toolboxDesktop.testAiSettings({ ...aiForm });
    ElMessage.success(`连接成功，模型返回：${result.message}`);
  } catch (error) {
    ElMessage.error(errorText(error, "AI API 连接失败"));
  } finally {
    aiTesting.value = false;
  }
}

async function saveAi() {
  if (!window.toolboxDesktop?.saveAiSettings)
    return ElMessage.warning("AI 设置仅支持桌面应用");
  try {
    await ElMessageBox.confirm(
      "应用新配置会短暂重启本地服务。请先确认当前没有正在执行的扫描任务。",
      "保存 AI 设置",
      {
        confirmButtonText: "保存并重启",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    aiSaving.value = true;
    aiStatus.value = await window.toolboxDesktop.saveAiSettings({ ...aiForm });
    aiForm.apiKey = "";
    aiForm.embeddingApiKey = "";
    aiDialog.value = false;
    ElMessage.success("AI 设置已保存，本地服务已重新加载");
  } catch (error) {
    if (error !== "cancel" && error !== "close")
      ElMessage.error(errorText(error, "AI 设置保存失败"));
  } finally {
    aiSaving.value = false;
  }
}

async function clearEmbeddingApiKey() {
  if (!window.toolboxDesktop?.clearEmbeddingApiKey) return;
  try {
    await ElMessageBox.confirm(
      "清除后，单独配置的向量服务将不再发送鉴权密钥。确定继续吗？",
      "清除向量 API Key",
      { confirmButtonText: "清除", cancelButtonText: "取消", type: "warning" },
    );
    aiSaving.value = true;
    aiStatus.value = await window.toolboxDesktop.clearEmbeddingApiKey({
      ...aiForm,
      embeddingApiKey: "",
    });
    aiForm.embeddingApiKey = "";
    ElMessage.success("向量 API Key 已清除");
  } catch (error) {
    if (error !== "cancel" && error !== "close")
      ElMessage.error(errorText(error, "向量 API Key 清除失败"));
  } finally {
    aiSaving.value = false;
  }
}

async function clearApiKey() {
  if (!window.toolboxDesktop?.clearAiApiKey) return;
  try {
    await ElMessageBox.confirm(
      aiForm.proxyMode
        ? "清除后仍会通过 CCS 代理调用，但不再发送鉴权密钥。"
        : "清除后将切换回本地规则模式，确定继续吗？",
      "清除 API Key",
      {
        confirmButtonText: "清除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    aiSaving.value = true;
    aiStatus.value = await window.toolboxDesktop.clearAiApiKey({
      ...aiForm,
      apiKey: "",
    });
    aiForm.apiKey = "";
    ElMessage.success(
      aiForm.proxyMode
        ? "API Key 已清除，当前使用无密钥 CCS 代理模式"
        : "API Key 已清除，当前使用本地规则模式",
    );
  } catch (error) {
    if (error !== "cancel" && error !== "close")
      ElMessage.error(errorText(error, "API Key 清除失败"));
  } finally {
    aiSaving.value = false;
  }
}

async function loadIcpSettings(open = false) {
  if (open) icpDialog.value = true;
  if (!window.toolboxDesktop?.getIcpSettings) return;
  icpLoading.value = true;
  try {
    icpStatus.value = await window.toolboxDesktop.getIcpSettings();
    icpForm.apiUrl = "";
  } catch (error) {
    ElMessage.error(errorText(error, "无法读取 ICP 数据源设置"));
  } finally {
    icpLoading.value = false;
  }
}

async function saveIcpSettings() {
  if (!window.toolboxDesktop?.saveIcpSettings)
    return ElMessage.warning("ICP 数据源设置仅支持桌面应用");
  if (!icpForm.apiUrl.trim())
    return ElMessage.warning("请输入 HTTPS 的 ICP API 地址");
  try {
    await ElMessageBox.confirm(
      "保存后会短暂重启本地服务。可在地址中使用 {domain} 作为待查询域名占位符。",
      "保存 ICP 数据源",
      {
        confirmButtonText: "保存并重启",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    icpSaving.value = true;
    icpStatus.value = await window.toolboxDesktop.saveIcpSettings({
      apiUrl: icpForm.apiUrl.trim(),
    });
    icpForm.apiUrl = "";
    icpDialog.value = false;
    ElMessage.success("ICP 数据源已加密保存，本地服务已重新加载");
  } catch (error) {
    if (error !== "cancel" && error !== "close")
      ElMessage.error(errorText(error, "ICP 数据源保存失败"));
  } finally {
    icpSaving.value = false;
  }
}

async function clearIcpSettings() {
  if (!window.toolboxDesktop?.clearIcpSettings) return;
  try {
    await ElMessageBox.confirm(
      "清除后 ICP 批量查询会显示“需要配置”，确定继续吗？",
      "清除 ICP 数据源",
      {
        confirmButtonText: "清除并重启",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    icpSaving.value = true;
    icpStatus.value = await window.toolboxDesktop.clearIcpSettings();
    icpForm.apiUrl = "";
    icpDialog.value = false;
    ElMessage.success("ICP 数据源已清除");
  } catch (error) {
    if (error !== "cancel" && error !== "close")
      ElMessage.error(errorText(error, "ICP 数据源清除失败"));
  } finally {
    icpSaving.value = false;
  }
}

async function loadToolDownloadSettings(open = false) {
  if (open) toolDownloadDialog.value = true;
  if (!window.toolboxDesktop?.getToolDownloadSettings) return;
  toolDownloadLoading.value = true;
  try {
    toolDownloadStatus.value = await window.toolboxDesktop.getToolDownloadSettings();
    const mirror = toolDownloadStatus.value?.configuredMirror || "";
    toolDownloadForm.mode = mirror ? "custom" : "github";
    toolDownloadForm.mirror = mirror;
  } catch (error) {
    ElMessage.error(errorText(error, "无法读取工具下载源设置"));
  } finally {
    toolDownloadLoading.value = false;
  }
}

const TOOL_DOWNLOAD_PRESETS = [
  { label: "直连 GitHub 官方源", value: "" },
  {
    label: "ghfast.top 反代（nsis.app）",
    value: "https://ghfast.top/",
  },
  {
    label: "gh-proxy 反代（ghproxy.net）",
    value: "https://ghproxy.net/https://github.com/",
  },
];

async function saveToolDownloadSettings() {
  if (!window.toolboxDesktop?.saveToolDownloadSettings)
    return ElMessage.warning("工具下载源仅支持桌面应用");
  const mirror =
    toolDownloadForm.mode === "custom"
      ? (toolDownloadForm.mirror || "").trim()
      : "";
  toolDownloadSaving.value = true;
  try {
    toolDownloadStatus.value = await window.toolboxDesktop.saveToolDownloadSettings({
      downloadMirror: mirror,
    });
    toolDownloadDialog.value = false;
    ElMessage.success(
      mirror
        ? "工具下载源已切换为镜像源，对后续安装生效"
        : "工具下载源已切换回 GitHub 官方源",
    );
  } catch (error) {
    ElMessage.error(errorText(error, "工具下载源保存失败"));
  } finally {
    toolDownloadSaving.value = false;
  }
}

async function loadGithubTokenSettings(open = false) {
  if (open) githubDialog.value = true;
  if (!window.toolboxDesktop?.getGithubTokenSettings) return;
  githubLoading.value = true;
  try {
    githubStatus.value = await window.toolboxDesktop.getGithubTokenSettings();
    githubForm.token = "";
  } catch (error) {
    ElMessage.error(errorText(error, "无法读取 GitHub 访问令牌设置"));
  } finally {
    githubLoading.value = false;
  }
}

async function saveGithubToken() {
  if (!window.toolboxDesktop?.saveGithubTokenSettings)
    return ElMessage.warning("GitHub 访问令牌仅支持桌面应用");
  const token = githubForm.token.trim();
  if (!token) return ElMessage.warning("请粘贴 GitHub Personal Access Token");
  githubSaving.value = true;
  try {
    githubStatus.value = await window.toolboxDesktop.saveGithubTokenSettings({
      token,
    });
    githubForm.token = "";
    githubDialog.value = false;
    ElMessage.success("GitHub 访问令牌已用 Windows 安全存储加密保存");
  } catch (error) {
    ElMessage.error(errorText(error, "GitHub 访问令牌保存失败"));
  } finally {
    githubSaving.value = false;
  }
}

async function clearGithubToken() {
  if (!window.toolboxDesktop?.saveGithubTokenSettings) return;
  try {
    await ElMessageBox.confirm(
      "清除后同步漏洞库将再次使用未登录的 GitHub 限额（每小时 60 次），确定继续吗？",
      "清除 GitHub 访问令牌",
      {
        confirmButtonText: "清除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
    githubSaving.value = true;
    githubStatus.value = await window.toolboxDesktop.saveGithubTokenSettings({
      clear: true,
    });
    githubForm.token = "";
    githubDialog.value = false;
    ElMessage.success("GitHub 访问令牌已清除");
  } catch (error) {
    if (error !== "cancel" && error !== "close")
      ElMessage.error(errorText(error, "GitHub 访问令牌清除失败"));
  } finally {
    githubSaving.value = false;
  }
}

onMounted(() => {
  void loadAiSettings();
  void loadIcpSettings();
  void loadGithubTokenSettings();
  void loadMicaSetting();
});

watch(
  () => aiForm.proxyMode,
  (enabled) => {
    if (enabled && aiForm.baseUrl === "https://api.openai.com")
      aiForm.baseUrl = "http://127.0.0.1:15721";
    if (enabled && aiForm.model === "gpt-4.1-mini")
      aiForm.model = "gpt-5.6-sol";
  },
);
</script>

<template>
  <div class="settings-page">
    <header class="simple-page-heading">
      <span>系统设置</span>
      <h1>工作区与运行环境</h1>
      <p>管理外观、AI 接入、授权范围、系统依赖和本地审计记录。</p>
    </header>

    <div class="settings-stack">
      <section class="settings-group">
        <header class="settings-group-title">外观</header>
        <div class="settings-list">
          <div class="settings-row settings-row--control">
            <el-icon class="settings-row-icon"><Setting /></el-icon>
            <span class="settings-row-copy">
              <strong>窗口背景材质</strong>
              <small>关闭为纯色，Mica 较柔和，Acrylic 为明显的透明毛玻璃</small>
            </span>
            <el-select
              v-model="windowMaterial"
              class="material-select"
              size="default"
              :disabled="!isDesktop || materialSaving"
              @change="changeWindowMaterial"
            >
              <el-option label="Mica" value="mica" />
              <el-option label="Acrylic（毛玻璃）" value="acrylic" />
              <el-option label="关闭（纯色）" value="none" />
            </el-select>
          </div>
        </div>
      </section>

      <section class="settings-group">
        <header class="settings-group-title">AI 与外部服务</header>
        <div class="settings-list">
          <button
            type="button"
            class="settings-row"
            @click="loadAiSettings(true)"
          >
            <el-icon class="settings-row-icon"><ChatDotRound /></el-icon>
            <span class="settings-row-copy">
              <strong>AI 模型服务</strong>
              <small>{{ aiServiceSummary }}</small>
            </span>
            <el-icon class="settings-row-chevron"><ArrowRight /></el-icon>
          </button>
          <button
            type="button"
            class="settings-row"
            @click="loadIcpSettings(true)"
          >
            <el-icon class="settings-row-icon"><Compass /></el-icon>
            <span class="settings-row-copy">
              <strong>ICP 备案数据源</strong>
              <small v-if="!isDesktop"
                >网页模式请通过 ICP_API_URL 环境变量配置</small
              >
              <small v-else-if="icpStatus?.configured"
                >已配置 · {{ icpStatus.endpointHint }} · Windows 安全存储</small
              >
              <small v-else>尚未配置手动数据源；可启用内置工信部查询或接入可信 HTTPS 服务</small>
            </span>
            <el-icon class="settings-row-chevron"><ArrowRight /></el-icon>
          </button>
          <button
            type="button"
            class="settings-row"
            @click="loadGithubTokenSettings(true)"
          >
            <el-icon class="settings-row-icon"><Key /></el-icon>
            <span class="settings-row-copy">
              <strong>GitHub 访问令牌</strong>
              <small v-if="!isDesktop"
                >网页模式请通过 GITHUB_TOKEN 环境变量配置</small
              >
              <small v-else-if="githubStatus?.source === 'env'"
                >已通过环境变量启用 · {{ githubStatus.hint }}</small
              >
              <small v-else-if="githubStatus?.configured"
                >已配置 · {{ githubStatus.hint }}</small
              >
              <small v-else
                >未配置时同步漏洞库受未登录限额限制（每小时 60 次）</small
              >
            </span>
            <el-icon class="settings-row-chevron"><ArrowRight /></el-icon>
          </button>
          <button
            type="button"
            class="settings-row"
            @click="loadToolDownloadSettings(true)"
          >
            <el-icon class="settings-row-icon"><Download /></el-icon>
            <span class="settings-row-copy">
              <strong>工具下载源</strong>
              <small v-if="!isDesktop"
                >网页模式请通过 TOOL_DOWNLOAD_MIRROR 环境变量配置</small
              >
              <small v-else>{{ toolDownloadSummary }}</small>
            </span>
            <el-icon class="settings-row-chevron"><ArrowRight /></el-icon>
          </button>
          <button
            type="button"
            class="settings-row"
            @click="troubleshootWithCopilot"
          >
            <el-icon class="settings-row-icon"><MagicStick /></el-icon>
            <span class="settings-row-copy">
              <strong>AI 配置诊断</strong>
              <small
                >仅把服务商、模型和连接状态交给 Copilot，不发送 API Key</small
              >
            </span>
            <el-icon class="settings-row-chevron"><ArrowRight /></el-icon>
          </button>
        </div>
      </section>

      <section class="settings-group">
        <header class="settings-group-title">安全与访问</header>
        <div class="settings-list">
          <button
            type="button"
            class="settings-row"
            @click="router.push('/targets')"
          >
            <el-icon class="settings-row-icon"><Aim /></el-icon>
            <span class="settings-row-copy">
              <strong>授权目标</strong>
              <small>登记允许主动检测的系统、地址和端口范围</small>
            </span>
            <el-icon class="settings-row-chevron"><ArrowRight /></el-icon>
          </button>
          <button type="button" class="settings-row" @click="pwdVisible = true">
            <el-icon class="settings-row-icon"><Key /></el-icon>
            <span class="settings-row-copy">
              <strong>修改登录密码</strong>
              <small
                >设置后可用账号密码登录；桌面版首次请先用本机凭据 / Windows
                Hello 进入</small
              >
            </span>
            <el-icon class="settings-row-chevron"><ArrowRight /></el-icon>
          </button>
        </div>
      </section>

      <section class="settings-group">
        <header class="settings-group-title">系统与审计</header>
        <div class="settings-list">
          <button type="button" class="settings-row" @click="rerunSetup">
            <el-icon class="settings-row-icon"><Tools /></el-icon>
            <span class="settings-row-copy">
              <strong>依赖检测与工具安装</strong>
              <small>重新运行完整依赖检测，查看缺失项并安装</small>
            </span>
            <el-icon class="settings-row-chevron"><ArrowRight /></el-icon>
          </button>
          <button
            type="button"
            class="settings-row"
            @click="router.push('/audits')"
          >
            <el-icon class="settings-row-icon"><Document /></el-icon>
            <span class="settings-row-copy">
              <strong>操作审计</strong>
              <small>查看检测、登录和配置变更记录</small>
            </span>
            <el-icon class="settings-row-chevron"><ArrowRight /></el-icon>
          </button>
        </div>
      </section>

      <section class="settings-group settings-group--danger">
        <header class="settings-group-title">危险操作</header>
        <div class="settings-list settings-list--danger">
          <div class="settings-row settings-row--control settings-row--danger">
            <el-icon class="settings-row-icon"><Delete /></el-icon>
            <span class="settings-row-copy">
              <strong>清空业务数据</strong>
              <small
                v-if="clearDataResult"
                class="clear-data-status"
                :class="`clear-data-status--${clearDataResult.type}`"
                role="status"
                aria-live="polite"
                >{{ clearDataResult.message }}</small
              >
              <small v-else-if="clearingData" role="status" aria-live="polite"
                >正在清空业务数据，请勿关闭应用</small
              >
              <small v-else-if="canClearData"
                >永久删除项目、任务、结果、流量记录和 AI 数据；账户、规则与设置会保留</small
              >
              <small v-else>仅管理员可以执行此操作</small>
            </span>
            <el-button
              type="danger"
              plain
              :loading="clearingData"
              :disabled="!canClearData || clearingData"
              @click="clearBusinessData"
              >清空数据</el-button
            >
          </div>
        </div>
      </section>

      <section class="settings-group">
        <header class="settings-group-title">关于</header>
        <div class="settings-list">
          <div class="settings-row settings-row--static settings-version">
            <el-icon class="settings-row-icon"><Setting /></el-icon>
            <span class="settings-row-copy">
              <strong>Xiezhi Desktop</strong>
              <small>本地前后端分离安全测试工作台</small>
            </span>
            <code class="settings-version-code">0.2.0</code>
          </div>
        </div>
      </section>
    </div>
    <el-dialog
      v-model="pwdVisible"
      title="修改登录密码"
      class="app-dialog app-dialog--sm"
      align-center
      append-to-body
      destroy-on-close
    >
      <el-form label-position="top" @keyup.enter="changeLoginPassword">
        <el-form-item label="当前密码"
          ><el-input
            v-model="pwdForm.current"
            type="password"
            show-password
            autocomplete="current-password"
            placeholder="请输入当前登录密码"
            :disabled="pwdSaving"
        /></el-form-item>
        <el-form-item label="新密码（至少 8 位）"
          ><el-input
            v-model="pwdForm.next"
            type="password"
            show-password
            autocomplete="new-password"
            placeholder="请输入新密码"
            :disabled="pwdSaving"
        /></el-form-item>
        <el-form-item label="确认新密码"
          ><el-input
            v-model="pwdForm.confirm"
            type="password"
            show-password
            autocomplete="new-password"
            placeholder="请再次输入新密码"
            :disabled="pwdSaving"
        /></el-form-item>
      </el-form>
      <template #footer>
        <el-button :disabled="pwdSaving" @click="pwdVisible = false"
          >取消</el-button
        >
        <el-button
          type="primary"
          :loading="pwdSaving"
          @click="changeLoginPassword"
          >保存</el-button
        >
      </template>
    </el-dialog>

    <el-dialog
      v-model="icpDialog"
      title="ICP备案数据源"
      class="app-dialog app-dialog--md"
      align-center
      append-to-body
      destroy-on-close
    >
      <div v-loading="icpLoading" class="icp-settings-dialog">
        <el-alert
          v-if="icpStatus?.configured"
          :title="`已配置：${icpStatus.endpointHint}`"
          type="success"
          :closable="false"
          show-icon
        />
        <el-alert
          v-else
          title="可选用内置工信部备案查询，或接入你信任且有权使用的 HTTPS 查询服务；程序不内置来源不明的免费备案接口。"
          type="warning"
          :closable="false"
          show-icon
        />
        <el-form label-position="top" class="icp-settings-form">
          <el-form-item label="ICP API 地址">
            <el-input
              v-model="icpForm.apiUrl"
              type="password"
              show-password
              autocomplete="new-password"
              :placeholder="
                icpStatus?.configured
                  ? '留空表示保持现有配置'
                  : 'https://example.com/icp?domain={domain}'
              "
              :disabled="!isDesktop || icpSaving"
            />
            <p>
              支持 <code>{domain}</code> 占位符；没有占位符时程序会自动追加
              <code>domain=待查询域名</code>。包含在查询参数中的 Key 会一并使用
              Windows 安全存储加密。启用内置工信部查询后，会先尝试直连
              <code>beian.miit.gov.cn</code>，失败或需人工点选验证时自动回退到这里。
            </p>
          </el-form-item>
        </el-form>
      </div>
      <template #footer>
        <div class="app-dialog__footer-row">
          <el-button
            v-if="icpStatus?.configured"
            type="danger"
            plain
            :disabled="icpSaving"
            @click="clearIcpSettings"
            >清除配置</el-button
          >
          <span class="app-dialog__footer-spacer" />
          <el-button @click="icpDialog = false">取消</el-button>
          <el-button
            type="primary"
            :loading="icpSaving"
            :disabled="!isDesktop || !icpForm.apiUrl.trim()"
            @click="saveIcpSettings"
            >保存并应用</el-button
          >
        </div>
      </template>
    </el-dialog>

    <el-dialog
      v-model="githubDialog"
      title="GitHub 访问令牌"
      class="app-dialog app-dialog--md"
      align-center
      append-to-body
      destroy-on-close
    >
      <div v-loading="githubLoading" class="icp-settings-form">
        <el-alert
          v-if="!isDesktop"
          title="当前是网页模式，请通过后端 GITHUB_TOKEN / GH_TOKEN 环境变量配置。"
          type="info"
          :closable="false"
          show-icon
        />
        <el-alert
          v-else-if="githubStatus?.source === 'env'"
          :title="`已通过环境变量启用：${githubStatus.hint}`"
          type="success"
          :closable="false"
          show-icon
        />
        <el-alert
          v-else-if="githubStatus?.configured"
          :title="`已配置：${githubStatus.hint}`"
          type="success"
          :closable="false"
          show-icon
        />
        <el-alert
          v-else
          title="未登录 GitHub 时每小时仅 60 次 API 额度，校园/公司共享出口 IP 很快用尽，导致同步漏洞库报“访问频率超限”。"
          type="warning"
          :closable="false"
          show-icon
        />
        <el-form label-position="top" class="icp-settings-form">
          <el-form-item label="Personal Access Token">
            <el-input
              v-model="githubForm.token"
              type="password"
              show-password
              autocomplete="new-password"
              :placeholder="
                githubStatus?.configured
                  ? '留空表示保持现有令牌'
                  : 'ghp_… 或 github_pat_…'
              "
              :disabled="
                !isDesktop || githubStatus?.source === 'env' || githubSaving
              "
            />
            <p>
              在 GitHub「Settings → Developer settings → Personal access
              tokens」创建即可，无需任何仓库权限（public 只读足够）。令牌使用
              Windows 安全存储加密，仅用于把 GitHub API 限额提升到每小时 5000
              次。<template v-if="githubStatus?.source === 'env'"
                >当前已由环境变量提供，如需改用应用内令牌请先取消该环境变量。</template
              >
            </p>
          </el-form-item>
        </el-form>
      </div>
      <template #footer>
        <div class="app-dialog__footer-row">
          <el-button
            v-if="githubStatus?.configured && githubStatus?.source !== 'env'"
            type="danger"
            plain
            :disabled="githubSaving"
            @click="clearGithubToken"
            >清除令牌</el-button
          >
          <span class="app-dialog__footer-spacer" />
          <el-button @click="githubDialog = false">取消</el-button>
          <el-button
            type="primary"
            :loading="githubSaving"
            :disabled="
              !isDesktop ||
              githubStatus?.source === 'env' ||
              !githubForm.token.trim()
            "
            @click="saveGithubToken"
            >保存</el-button
          >
        </div>
      </template>
    </el-dialog>

    <el-dialog
      v-model="toolDownloadDialog"
      title="工具下载源"
      class="app-dialog app-dialog--md"
      align-center
      append-to-body
      destroy-on-close
    >
      <div v-loading="toolDownloadLoading" class="icp-settings-form">
        <el-alert
          v-if="!isDesktop"
          title="当前是网页模式，请通过服务端 TOOL_DOWNLOAD_MIRROR 环境变量配置下载源。"
          type="info"
          :closable="false"
          show-icon
        />
        <el-alert
          v-else
          title="部分网络连不上 GitHub release（常见提示“连接超时/SSL 中断”）。可改用镜像源前缀，把下载改写为 前缀 + 完整 GitHub 地址。"
          type="warning"
          :closable="false"
          show-icon
        />
        <el-form label-position="top" class="icp-settings-form">
          <el-form-item label="下载方式">
            <el-radio-group v-model="toolDownloadForm.mode" :disabled="!isDesktop">
              <el-radio label="github">直连 GitHub</el-radio>
              <el-radio label="custom">自定义镜像源</el-radio>
            </el-radio-group>
          </el-form-item>
          <el-form-item v-if="toolDownloadForm.mode === 'custom'" label="镜像前缀">
            <el-input
              v-model="toolDownloadForm.mirror"
              placeholder="https://ghfast.top/ 或 https://gh-proxy.example/https://github.com/"
              :disabled="!isDesktop || toolDownloadSaving"
            />
            <p>
              常用预置：
              <el-link
                type="primary"
                class="mirror-preset"
                @click="toolDownloadForm.mirror = TOOL_DOWNLOAD_PRESETS[1].value"
                >ghfast.top</el-link
              >
              ·
              <el-link
                type="primary"
                class="mirror-preset"
                @click="toolDownloadForm.mirror = TOOL_DOWNLOAD_PRESETS[2].value"
                >ghproxy.net</el-link
              >
            </p>
            <p>
              需以 <code>https://</code> 开头；程序会拼成「前缀 +
              <code>/https://github.com/…</code>」，并把镜像主机加入下载授权白名单。
            </p>
          </el-form-item>
        </el-form>
      </div>
      <template #footer>
        <div class="app-dialog__footer-row">
          <el-button
            v-if="toolDownloadStatus?.configuredMirror"
            type="danger"
            plain
            :disabled="toolDownloadSaving"
            @click="toolDownloadForm.mode = 'github'; toolDownloadForm.mirror = ''; saveToolDownloadSettings()"
            >恢复直连</el-button
          >
          <span class="app-dialog__footer-spacer" />
          <el-button @click="toolDownloadDialog = false">取消</el-button>
          <el-button
            type="primary"
            :loading="toolDownloadSaving"
            :disabled="
              !isDesktop ||
              (toolDownloadForm.mode === 'custom' && !toolDownloadForm.mirror.trim())
            "
            @click="saveToolDownloadSettings"
            >保存并应用</el-button
          >
        </div>
      </template>
    </el-dialog>

    <el-dialog
      v-model="aiDialog"
      title="AI 模型服务"
      class="app-dialog app-dialog--md ai-model-dialog"
      align-center
      append-to-body
      destroy-on-close
    >
      <div v-loading="aiLoading" class="ai-settings-dialog">
        <el-alert
          v-if="!isDesktop"
          title="当前是网页模式，请通过 AI_BASE_URL、AI_API_KEY、AI_MODEL 环境变量配置后端。"
          type="info"
          :closable="false"
          show-icon
        />
        <el-alert
          v-else
          :title="aiConnectionAlert.title"
          :type="aiConnectionAlert.type"
          :closable="false"
          show-icon
        />

        <el-form label-position="top" class="ai-settings-form">
          <el-form-item label="API 地址">
            <el-input
              v-model="aiForm.baseUrl"
              placeholder="https://api.openai.com"
              :disabled="!isDesktop"
            />
            <p>
              支持 CCS 的根地址、以 <code>/v1</code> 结尾的地址，或完整
              <code>/v1/chat/completions</code> 地址，保存时会自动规范化。
            </p>
          </el-form-item>
          <el-form-item label="CCS 本地代理">
            <el-switch
              v-model="aiForm.proxyMode"
              active-text="通过 CCS / 本地 OpenAI 兼容代理调用"
              :disabled="!isDesktop"
            />
            <p>
              启用后允许代理不要求 API Key；如果 CCS
              设置了访问令牌，仍可在下方填写。
            </p>
          </el-form-item>
          <el-form-item v-if="!aiForm.proxyMode" label="API Key">
            <el-input
              v-model="aiForm.apiKey"
              type="password"
              show-password
              autocomplete="new-password"
              :placeholder="
                aiStatus?.hasApiKey
                  ? '留空表示继续使用已保存的密钥'
                  : '请输入 API Key'
              "
              :disabled="!isDesktop"
            />
            <p>密钥使用 Windows 安全存储加密，不会写入浏览器 localStorage。</p>
          </el-form-item>
          <el-form-item label="模型名称">
            <el-input
              v-model="aiForm.model"
              placeholder="gpt-4.1-mini"
              :disabled="!isDesktop"
            />
          </el-form-item>
          <el-form-item label="知识检索方式">
            <el-segmented
              v-model="aiForm.retrievalBackend"
              :options="[
                { label: 'BM25 关键词', value: 'bm25' },
                { label: '真实向量嵌入', value: 'real_embedding' },
              ]"
              :disabled="!isDesktop"
            />
            <p>
              BM25 不调用向量服务；真实向量嵌入可复用对话连接，也可单独配置。
            </p>
          </el-form-item>
          <el-form-item
            v-if="aiForm.retrievalBackend === 'real_embedding'"
            label="向量服务连接方式"
          >
            <el-segmented
              v-model="aiForm.embeddingConnectionMode"
              :options="[
                { label: '复用对话连接', value: 'shared' },
                { label: '单独配置', value: 'custom' },
              ]"
              :disabled="!isDesktop"
            />
          </el-form-item>
          <el-form-item
            v-if="
              aiForm.retrievalBackend === 'real_embedding' &&
              aiForm.embeddingConnectionMode === 'custom'
            "
            label="向量 API 地址"
          >
            <el-input
              v-model="aiForm.embeddingBaseUrl"
              placeholder="https://api.openai.com"
              :disabled="!isDesktop"
            />
          </el-form-item>
          <el-form-item
            v-if="
              aiForm.retrievalBackend === 'real_embedding' &&
              aiForm.embeddingConnectionMode === 'custom'
            "
            label="向量 API Key"
          >
            <el-input
              v-model="aiForm.embeddingApiKey"
              type="password"
              show-password
              autocomplete="new-password"
              :placeholder="
                aiStatus?.hasEmbeddingApiKey
                  ? '留空表示继续使用已保存的密钥'
                  : '可留空（服务不要求密钥时）'
              "
              :disabled="!isDesktop"
            />
          </el-form-item>
          <el-form-item
            v-if="aiForm.retrievalBackend === 'real_embedding'"
            label="Embedding 模型"
          >
            <el-input
              v-model="aiForm.embeddingModel"
              placeholder="text-embedding-3-small"
              :disabled="!isDesktop"
            />
          </el-form-item>
        </el-form>
      </div>
      <template #footer>
        <div class="app-dialog__footer-row">
          <el-button
            v-if="aiStatus?.hasApiKey"
            type="danger"
            plain
            :disabled="aiSaving"
            @click="clearApiKey"
            >清除对话密钥</el-button
          >
          <el-button
            v-if="
              aiForm.retrievalBackend === 'real_embedding' &&
              aiForm.embeddingConnectionMode === 'custom' &&
              aiStatus?.hasEmbeddingApiKey
            "
            type="danger"
            plain
            :disabled="aiSaving"
            @click="clearEmbeddingApiKey"
            >清除向量密钥</el-button
          >
          <span class="app-dialog__footer-spacer" />
          <el-button @click="aiDialog = false">取消</el-button>
          <el-tooltip
            content="会真实发送一次极短对话请求，可能产生少量费用"
            placement="top"
            :show-after="350"
          ><el-button
              :loading="aiTesting"
              :disabled="!isDesktop || aiSaving"
              aria-label="测试连接"
              @click="testAi"
              >测试连接</el-button
            ></el-tooltip
          >
          <el-button
            v-if="aiForm.retrievalBackend === 'real_embedding'"
            :loading="embeddingTesting"
            :disabled="!isDesktop || aiSaving || aiTesting"
            @click="testEmbedding"
            >测试向量连接</el-button
          >
          <el-button
            type="primary"
            :loading="aiSaving"
            :disabled="!isDesktop || aiTesting"
            @click="saveAi"
            >保存并应用</el-button
          >
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.ai-settings-dialog {
  min-height: 320px;
}
.ai-settings-form,
.icp-settings-form {
  margin-top: 18px;
}
.ai-settings-form p,
.icp-settings-form p {
  margin: 6px 0 0;
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.55;
}
.ai-settings-form code,
.icp-settings-form code {
  font-family: Consolas, monospace;
}
.icp-settings-dialog {
  min-height: 190px;
}
.material-select {
  width: 168px;
}

.settings-page {
  width: min(100%, 860px);
  margin: 0 auto;
  padding-bottom: 28px;
}

.simple-page-heading {
  display: flex !important;
  flex-direction: column !important;
  align-items: flex-start !important;
  gap: 6px;
  margin: 0 0 22px !important;
}

.simple-page-heading span {
  color: var(--app-muted);
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0;
}

.simple-page-heading h1 {
  margin: 0;
  font-size: 24px;
  font-weight: 650;
  line-height: 1.25;
}

.simple-page-heading p {
  margin: 0;
  max-width: 52ch;
  color: var(--app-muted);
  font-size: 13px;
  line-height: 1.55;
}

.settings-stack {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

.settings-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.settings-group-title {
  padding: 0 4px;
  color: var(--app-muted);
  font-size: 12px;
  font-weight: 650;
  letter-spacing: 0;
}

.settings-list {
  overflow: hidden;
  border: 1px solid var(--app-border);
  border-radius: 14px;
  background: var(--app-surface);
  box-shadow: var(
    --fluent-shadow-2,
    0 1px 2px color-mix(in srgb, var(--app-text) 6%, transparent)
  );
}

.settings-row {
  display: grid !important;
  grid-template-columns: 40px minmax(0, 1fr) auto !important;
  align-items: center !important;
  gap: 14px !important;
  width: 100% !important;
  min-height: 74px !important;
  margin: 0 !important;
  padding: 14px 18px !important;
  border: 0 !important;
  border-bottom: 1px solid var(--app-border) !important;
  border-radius: 0 !important;
  background: transparent !important;
  box-shadow: none !important;
  color: inherit !important;
  text-align: left !important;
  font: inherit !important;
}

.settings-list > .settings-row:last-child,
.settings-list > .settings-version:last-child {
  border-bottom: 0 !important;
}

button.settings-row {
  cursor: pointer;
}

button.settings-row:hover {
  background: var(--app-surface-soft) !important;
  transform: none !important;
}

button.settings-row:active {
  transform: none !important;
}

.settings-row-icon {
  display: grid !important;
  width: 36px !important;
  height: 36px !important;
  place-items: center !important;
  border-radius: 10px !important;
  background: color-mix(in srgb, var(--app-accent) 12%, transparent) !important;
  color: var(--app-accent) !important;
  font-size: 18px !important;
}

.settings-row-copy {
  display: flex !important;
  min-width: 0 !important;
  flex-direction: column !important;
  gap: 4px !important;
}

.settings-row-copy strong {
  color: var(--app-text) !important;
  font-size: 14px !important;
  font-weight: 650 !important;
  line-height: 1.35 !important;
}

.settings-row-copy small {
  display: -webkit-box !important;
  overflow: hidden !important;
  color: var(--app-muted) !important;
  font-size: 12px !important;
  line-height: 1.45 !important;
  -webkit-box-orient: vertical !important;
  -webkit-line-clamp: 2 !important;
}

.settings-row-chevron {
  color: color-mix(in srgb, var(--app-muted) 85%, transparent) !important;
  font-size: 14px !important;
}

.settings-row--control {
  cursor: default;
}

.settings-row--static {
  cursor: default;
}

.settings-list--danger {
  border-color: color-mix(in srgb, var(--el-color-danger) 42%, var(--app-border));
}

.settings-row--danger .settings-row-icon {
  background: color-mix(
    in srgb,
    var(--el-color-danger) 12%,
    transparent
  ) !important;
  color: var(--el-color-danger) !important;
}

.settings-row--danger .settings-row-copy strong {
  color: var(--el-color-danger) !important;
}

.settings-row--danger .settings-row-copy small {
  -webkit-line-clamp: unset !important;
}

.clear-data-status--success {
  color: var(--el-color-success) !important;
}

.clear-data-status--error {
  color: var(--el-color-danger) !important;
}

.settings-version-code {
  min-width: 52px;
  padding: 4px 8px;
  border-radius: 999px;
  background: var(--app-surface-soft, #f4f7f8);
  color: var(--app-muted);
  font-family: Consolas, "Segoe UI Mono", monospace;
  font-size: 12px;
  font-weight: 600;
  line-height: 1;
  text-align: center;
}

.material-select :deep(.el-select__wrapper) {
  min-height: 34px;
  border-radius: 10px;
}

@media (max-width: 720px) {
  .settings-page {
    width: 100%;
  }

  .settings-row,
  .settings-row--control {
    grid-template-columns: 36px minmax(0, 1fr) !important;
    align-items: start !important;
    gap: 12px !important;
    min-height: 0 !important;
    padding: 14px 14px !important;
  }

  .settings-row-icon {
    width: 32px !important;
    height: 32px !important;
    margin-top: 2px !important;
    font-size: 16px !important;
  }

  .settings-row-chevron,
  .settings-version-code,
  .material-select {
    grid-column: 2;
    justify-self: start;
  }

  .material-select {
    width: 100%;
    margin-top: 2px;
  }

  .settings-version-code {
    margin-top: 2px;
  }

  .settings-row--danger > .el-button {
    grid-column: 2;
    justify-self: start;
    margin: 2px 0 0;
  }

}
</style>
