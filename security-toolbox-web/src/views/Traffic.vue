<script setup lang="ts">
// @ts-nocheck
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  CircleCheck,
  Connection,
  Delete,
  Dismiss,
  Filter,
  InfoCircle,
  MagicStick,
  Plus,
  Promotion,
  QuestionFilled,
  Refresh,
  Search,
  Star,
  StarFilled,
  VideoPause,
  VideoPlay,
  Warning,
} from "../components/fluentIcons";
import { api, type Target } from "../api";
import AppPagination from "../components/AppPagination.vue";
import { useClientPagination } from "../composables/useClientPagination";
import { useCopilotStore } from "../stores/copilot";
import { toErrorMessage } from "../utils/errorMessage";
import { renderMarkdown } from "../utils/markdown";
import { useSelectionIndicator } from "../composables/useSelectionIndicator";

const copilot = useCopilotStore();
const router = useRouter();

interface TrafficStatus {
  running: boolean;
  listenHost?: string;
  listenPort?: number;
  capturedCount?: number;
  targetId?: number;
  handlingMode?: string;
  mitmEnabled?: boolean;
  caFingerprint?: string;
  capturing?: boolean;
}

interface TrafficSession {
  id: number | string;
  sessionId?: number | string;
  targetId?: number;
  protocol?: string;
  method?: string;
  scheme?: string;
  url?: string;
  host?: string;
  port?: number;
  path?: string;
  statusCode?: number;
  contentType?: string;
  durationMs?: number;
  requestBytes?: number;
  riskLevel?: string;
  createdAt?: string;
  requestHeaders?: Record<string, string>;
  responseHeaders?: Record<string, string>;
  requestBody?: string;
  responseBody?: string;
  marked?: boolean;
}

interface ReplayForm {
  targetId?: number;
  method: string;
  url: string;
  headers: string;
  body: string;
}

interface ReplayResult {
  statusCode?: number;
  reasonPhrase?: string;
  responseHeaders?: Record<string, string> | string;
  responseBody?: string;
  bodyEncoding?: string;
  contentType?: string;
  responseBytes?: number;
  durationMs?: number;
  truncated?: boolean;
}

interface ReplayTab {
  id: string;
  title: string;
  sourcePacketId?: number | string;
  form: ReplayForm;
  packet: string;
  result?: ReplayResult;
  error?: string;
  sending: boolean;
}

interface AiSuggestion {
  suggestionId?: number;
  summary?: string;
  riskLevel?: string;
  reasons?: string[];
  nextSteps?: string[];
  canAutoHandle?: boolean;
  status?: string;
  taskId?: number;
}

interface CaptureFilterRule {
  id: number;
  listType: "BLACKLIST" | "WHITELIST";
  type: "URL" | "DOMAIN" | "KEYWORD";
  pattern: string;
  enabled: boolean;
  createdAt?: string;
}

const HTTP_METHODS = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "HEAD",
  "OPTIONS",
  "TRACE",
  "CONNECT",
];

interface TrafficChatMessage {
  id: string;
  role: "USER" | "ASSISTANT";
  content: string;
  createdAt: string;
}

const status = ref<TrafficStatus>({ running: false, capturedCount: 0 });
const sessions = ref<TrafficSession[]>([]);
const selectedId = ref<number | string>();
const packetTabsElement = ref<HTMLElement | null>(null);
const replayDocumentTabsElement = ref<HTMLElement | null>(null);
const filter = ref("");
const loading = ref(false);
const changingProxy = ref(false);
const deletingId = ref<number | string>();
const markingId = ref<number | string>();
const clearingSessions = ref(false);
const analyzing = ref(false);
const autoHandle = ref(false);
const changingCapture = ref(false);
const browserRunning = ref(false);
const suggestion = ref<AiSuggestion>();
const serviceUnavailable = ref(false);
const packetTab = ref<"request" | "response">("request");
const replayDialogVisible = ref(false);
const replayTargets = ref<Target[]>([]);
const replayTargetLocked = ref(false);
const replayPreparing = ref(false);
const replaying = ref(false);
const replayInlineOpen = ref(false);
const replayTabs = ref<ReplayTab[]>([]);
const activeReplayTabId = ref("");
let replayTabSequence = 0;
const captureFilterDialogVisible = ref(false);
const captureFilters = ref<CaptureFilterRule[]>([]);
const {
  page: captureFilterPage,
  pageSize: captureFilterPageSize,
  pagedItems: pagedCaptureFilters,
} = useClientPagination(captureFilters);
const captureFiltersLoading = ref(false);
const captureFilterSaving = ref(false);
const captureFilterForm = ref<{
  id?: number;
  listType: "BLACKLIST" | "WHITELIST";
  type: "URL" | "DOMAIN" | "KEYWORD";
  pattern: string;
  enabled: boolean;
}>({
  listType: "BLACKLIST",
  type: "DOMAIN",
  pattern: "",
  enabled: true,
});
const TRAFFIC_CHAT_STORAGE_KEY = "security_toolbox_traffic_chats_v1";
const trafficChats = ref<Record<string, TrafficChatMessage[]>>(
  loadStoredTrafficChats(),
);
const pendingTrafficChats = ref<Record<string, boolean>>({});
const trafficChatPrompt = ref("");
const chatMessagesElement = ref<HTMLElement>();
let refreshTimer: number | undefined;
let removeCaptureBrowserListener: (() => void) | undefined;

const selected = computed(() =>
  sessions.value.find((item) => item.id === selectedId.value),
);
const activeReplayTab = computed(() =>
  replayTabs.value.find((tab) => tab.id === activeReplayTabId.value),
);
const replayForm = computed(
  () =>
    activeReplayTab.value?.form || {
      method: "GET",
      url: "",
      headers: "",
      body: "",
    },
);
const replayPacket = computed({
  get: () => activeReplayTab.value?.packet || "",
  set: (value) => {
    if (activeReplayTab.value) activeReplayTab.value.packet = value;
  },
});
const replayResult = computed(() => activeReplayTab.value?.result);
const currentTrafficChat = computed(() =>
  selectedId.value == null
    ? []
    : trafficChats.value[String(selectedId.value)] || [],
);
const currentTrafficChatSending = computed(() =>
  selectedId.value == null
    ? false
    : Boolean(pendingTrafficChats.value[String(selectedId.value)]),
);
const replayBodyIncomplete = computed(() => {
  const source = sessions.value.find(
    (item) => item.id === activeReplayTab.value?.sourcePacketId,
  );
  const bytes = Number(source?.requestBytes || 0);
  return (
    bytes >
    new TextEncoder().encode(splitReplayPacket(replayPacket.value).body).length
  );
});
const captureBrowserAvailable = computed(() =>
  Boolean(window.toolboxDesktop?.launchCaptureBrowser),
);
const captureBrowserTooltip = computed(() =>
  status.value.mitmEnabled && status.value.caFingerprint
    ? "使用隔离的临时浏览器会话自动配置本机代理，并仅在该会话内信任本地抓包 CA；不会修改系统代理。HTTPS 流量可解密捕获，支持 HTTP/1.1 与 HTTP/2。"
    : "使用隔离的临时浏览器会话自动配置本机代理；不会修改系统代理。HTTPS 当前仅捕获 CONNECT 元数据。",
);
const filteredSessions = computed(() => {
  const keyword = filter.value.trim().toLowerCase();
  if (!keyword) return sessions.value;
  return sessions.value.filter((item) =>
    `${item.method || ""} ${item.url || item.host || ""} ${item.path || ""}`
      .toLowerCase()
      .includes(keyword),
  );
});
const {
  page: sessionPage,
  pageSize: sessionPageSize,
  pagedItems: pagedSessions,
  resetPage: resetSessionPage,
} = useClientPagination(filteredSessions);
watch(filter, resetSessionPage);
useSelectionIndicator({
  container: packetTabsElement,
  activeSelector: "button.active",
  dependencies: [packetTab],
  orientation: "horizontal",
  sizeRatio: 0.72,
  minSize: 22,
  maxSize: 56,
  indicatorSelector: ".packet-tabs-indicator",
});
useSelectionIndicator({
  container: replayDocumentTabsElement,
  activeSelector: "button.active",
  dependencies: [activeReplayTabId, replayTabs],
  orientation: "horizontal",
  sizeRatio: 0.72,
  minSize: 22,
  maxSize: 150,
  indicatorSelector: ".replay-document-tabs-indicator",
});
const proxyAddress = computed(
  () =>
    `${status.value.listenHost || "127.0.0.1"}:${status.value.listenPort || 8088}`,
);
const activeCaptureFilterCount = computed(
  () => captureFilters.value.filter((rule) => rule.enabled).length,
);
const markedSessionCount = computed(
  () => sessions.value.filter((item) => item.marked).length,
);
const unmarkedSessionCount = computed(
  () => sessions.value.length - markedSessionCount.value,
);
const captureFilterPlaceholder = computed(() =>
  captureFilterForm.value.type === "DOMAIN"
    ? "例如：example.com（同时匹配子域名）"
    : captureFilterForm.value.type === "URL"
      ? "例如：/api/health 或 https://example.com/static/"
      : "例如：analytics、favicon、content-type",
);

async function openCaptureBrowser() {
  if (!status.value.running || !window.toolboxDesktop?.launchCaptureBrowser)
    return false;
  try {
    const browserStatus = await window.toolboxDesktop.launchCaptureBrowser({
      proxyHost: status.value.listenHost || "127.0.0.1",
      proxyPort: status.value.listenPort || 19080,
      targetUrl: "about:blank",
      caFingerprint: status.value.mitmEnabled
        ? status.value.caFingerprint
        : undefined,
    });
    browserRunning.value = browserStatus.running;
    return browserStatus.running;
  } catch (error) {
    browserRunning.value = false;
    ElMessage.warning(`浏览器启动失败：${readableError(error)}`);
    return false;
  }
}

function readableError(error: unknown) {
  const value = error as {
    response?: { data?: { message?: string }; status?: number };
    message?: string;
    code?: string;
  };
  if (value.response?.status === 404) return "当前本地引擎尚未启用流量代理模块";
  if (
    value.code === "ECONNABORTED" ||
    value.message?.toLowerCase().includes("timeout")
  )
    return "AI 分析等待超时，请检查模型连接后重试";
  return toErrorMessage(error, "操作失败");
}

function loadStoredTrafficChats() {
  try {
    const value = JSON.parse(
      localStorage.getItem(TRAFFIC_CHAT_STORAGE_KEY) || "{}",
    );
    return value && typeof value === "object" ? value : {};
  } catch {
    return {};
  }
}

function persistTrafficChats() {
  const entries = Object.entries(trafficChats.value)
    .filter(([, messages]) => Array.isArray(messages) && messages.length)
    .slice(-30)
    .map(([packetId, messages]) => [packetId, messages.slice(-40)]);
  localStorage.setItem(
    TRAFFIC_CHAT_STORAGE_KEY,
    JSON.stringify(Object.fromEntries(entries)),
  );
}

async function scrollTrafficChat() {
  await nextTick();
  if (chatMessagesElement.value)
    chatMessagesElement.value.scrollTop =
      chatMessagesElement.value.scrollHeight;
}

function appendTrafficChat(
  packetId: string,
  role: "USER" | "ASSISTANT",
  content: string,
) {
  const message: TrafficChatMessage = {
    id:
      globalThis.crypto?.randomUUID?.() ||
      `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    role,
    content,
    createdAt: new Date().toISOString(),
  };
  trafficChats.value = {
    ...trafficChats.value,
    [packetId]: [...(trafficChats.value[packetId] || []), message].slice(-40),
  };
  persistTrafficChats();
  if (String(selectedId.value) === packetId) void scrollTrafficChat();
}

function clearTrafficChat() {
  if (selectedId.value == null) return;
  const packetId = String(selectedId.value);
  const next = { ...trafficChats.value };
  delete next[packetId];
  trafficChats.value = next;
  persistTrafficChats();
}

async function sendTrafficChat() {
  const packet = selected.value;
  const prompt = trafficChatPrompt.value.trim();
  if (!packet || !prompt) return;
  const packetId = String(packet.id);
  if (pendingTrafficChats.value[packetId]) return;
  const history = (trafficChats.value[packetId] || [])
    .slice(-12)
    .map((message) => ({
      role: message.role,
      content: message.content,
    }));
  appendTrafficChat(packetId, "USER", prompt);
  trafficChatPrompt.value = "";
  pendingTrafficChats.value = {
    ...pendingTrafficChats.value,
    [packetId]: true,
  };
  try {
    const { data } = await api.post(
      `/traffic/packets/${encodeURIComponent(packetId)}/chat`,
      { prompt, history },
      { timeout: 210_000 },
    );
    appendTrafficChat(packetId, "ASSISTANT", data.answer || "AI 未返回回答。");
  } catch (error) {
    appendTrafficChat(
      packetId,
      "ASSISTANT",
      `分析失败：${readableError(error)}`,
    );
  } finally {
    pendingTrafficChats.value = {
      ...pendingTrafficChats.value,
      [packetId]: false,
    };
  }
}

function handleTrafficChatKeydown(event: KeyboardEvent) {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    void sendTrafficChat();
  }
}

function openTrafficCopilot() {
  const packet = selected.value;
  if (!packet) return;
  const safeLabel = `${(packet.method || "GET").toUpperCase()} ${packet.host || "流量会话"}${packet.path || ""}`;
  copilot.prepare({
    targetId: packet.targetId,
    refs: [
      {
        type: "traffic",
        id: packet.id,
        targetId: packet.targetId,
        title: safeLabel,
      },
    ],
    mode: "analyze",
    prompt:
      "分析这条流量的认证、会话、输入处理和数据暴露风险，列出证据、误报边界及安全的下一步验证计划。",
  });
  void router.push("/");
}

const DANGEROUS_METHODS = new Set([
  "PUT",
  "DELETE",
  "TRACE",
  "TRACK",
  "CONNECT",
  "PATCH",
]);
const trafficSecurityPoints = computed(() => {
  const packet = selected.value as any;
  if (!packet)
    return [] as {
      label: string;
      value: string;
      items?: string[];
      level: string;
      badge?: string;
    }[];
  const points: {
    label: string;
    value: string;
    items?: string[];
    level: string;
    badge?: string;
  }[] = [];
  const url = String(packet.url || `${packet.host || ""}${packet.path || ""}`);
  const https =
    url.toLowerCase().startsWith("https") || Number(packet.port) === 443;
  points.push({
    label: "传输加密",
    badge: https ? "已加密" : "明文传输",
    value: https ? "HTTPS（通道已加密）" : "HTTP（明文，易被窃听或篡改）",
    level: https ? "ok" : "warn",
  });
  const method = String(packet.method || "GET").toUpperCase();
  const isDangerous = DANGEROUS_METHODS.has(method);
  points.push({
    label: "请求方法",
    badge: method,
    value: isDangerous ? `${method}（敏感/写操作，需确认授权）` : method,
    level: isDangerous ? "warn" : "info",
  });
  if (packet.statusCode) {
    const code = Number(packet.statusCode);
    const isError = code >= 500;
    const isClientError = code >= 400 && code < 500;
    points.push({
      label: "响应状态",
      badge: `HTTP ${packet.statusCode}`,
      value: `HTTP ${packet.statusCode}`,
      level: isError ? "warn" : isClientError ? "warn" : "info",
    });
  }
  const reqHeaders = String(packet.requestHeaders || "").toLowerCase();
  const hasCookie = reqHeaders.includes("cookie:");
  points.push({
    label: "会话凭证",
    badge: hasCookie ? "携带Cookie" : "无Cookie",
    value: hasCookie ? "请求携带 Cookie（关注会话固定与越权）" : "未见 Cookie",
    level: hasCookie ? "warn" : "info",
  });
  const respHeaders = String(packet.responseHeaders || "").toLowerCase();
  if (respHeaders) {
    const missing = [
      "content-security-policy",
      "x-frame-options",
      "strict-transport-security",
    ].filter((h) => !respHeaders.includes(h));
    points.push({
      label: "安全响应头",
      badge: missing.length ? `${missing.length}项缺失` : "配置齐全",
      value: missing.length ? "缺失：" : "常见安全头齐全",
      items: missing.length ? missing : undefined,
      level: missing.length ? "warn" : "ok",
    });
  }
  return points;
});

function resetCaptureFilterForm() {
  captureFilterForm.value = {
    listType: "BLACKLIST",
    type: "DOMAIN",
    pattern: "",
    enabled: true,
  };
}

function captureFilterTypeLabel(type: string) {
  if (type === "DOMAIN") return "域名";
  if (type === "URL") return "URL";
  return "关键字";
}

async function loadCaptureFilters(showError = false) {
  captureFiltersLoading.value = true;
  try {
    const { data } = await api.get<CaptureFilterRule[]>("/traffic/filters");
    captureFilters.value = Array.isArray(data) ? data : [];
  } catch (error) {
    if (showError) ElMessage.error(readableError(error));
  } finally {
    captureFiltersLoading.value = false;
  }
}

async function openCaptureFilterDialog() {
  captureFilterDialogVisible.value = true;
  resetCaptureFilterForm();
  await loadCaptureFilters(true);
}

function editCaptureFilter(rule: CaptureFilterRule) {
  captureFilterForm.value = {
    id: rule.id,
    listType: rule.listType,
    type: rule.type,
    pattern: rule.pattern,
    enabled: rule.enabled,
  };
}

async function saveCaptureFilter() {
  const form = captureFilterForm.value;
  if (!form.pattern.trim() || captureFilterSaving.value) return;
  captureFilterSaving.value = true;
  try {
    const body = {
      listType: form.listType,
      type: form.type,
      pattern: form.pattern.trim(),
      enabled: form.enabled,
    };
    if (form.id) await api.put(`/traffic/filters/${form.id}`, body);
    else await api.post("/traffic/filters", body);
    ElMessage.success(form.id ? "抓包名单规则已更新" : "抓包名单规则已添加");
    resetCaptureFilterForm();
    await loadCaptureFilters();
  } catch (error) {
    ElMessage.error(readableError(error));
  } finally {
    captureFilterSaving.value = false;
  }
}

async function toggleCaptureFilter(rule: CaptureFilterRule) {
  try {
    await api.put(`/traffic/filters/${rule.id}`, {
      listType: rule.listType,
      type: rule.type,
      pattern: rule.pattern,
      enabled: rule.enabled,
    });
  } catch (error) {
    ElMessage.error(readableError(error));
    await loadCaptureFilters();
  }
}

async function deleteCaptureFilter(rule: CaptureFilterRule) {
  try {
    await ElMessageBox.confirm(
      `确定删除这条${rule.listType === "BLACKLIST" ? "黑名单" : "白名单"}规则吗？\n${rule.pattern}`,
      "删除抓包规则",
      {
        type: "warning",
        confirmButtonText: "删除",
        cancelButtonText: "取消",
      },
    );
  } catch {
    return;
  }
  try {
    await api.delete(`/traffic/filters/${rule.id}`);
    if (captureFilterForm.value.id === rule.id) resetCaptureFilterForm();
    await loadCaptureFilters();
    ElMessage.success("抓包名单规则已删除");
  } catch (error) {
    ElMessage.error(readableError(error));
  }
}

async function load(showError = false) {
  loading.value = true;
  try {
    const [statusResult, sessionsResult] = await Promise.all([
      api.get<TrafficStatus>("/traffic/status"),
      api.get<TrafficSession[]>("/traffic/sessions"),
    ]);
    status.value = { ...status.value, ...statusResult.data };
    sessions.value = Array.isArray(sessionsResult.data)
      ? sessionsResult.data
      : [];
    if (
      selectedId.value &&
      !sessions.value.some((item) => item.id === selectedId.value)
    ) {
      selectedId.value = sessions.value[0]?.id;
      suggestion.value = undefined;
    }
    if (!selectedId.value && sessions.value.length)
      selectedId.value = sessions.value[0].id;
    serviceUnavailable.value = false;
    if (window.toolboxDesktop?.getCaptureBrowserStatus) {
      const browserStatus = await window.toolboxDesktop
        .getCaptureBrowserStatus()
        .catch(() => undefined);
      if (browserStatus) browserRunning.value = browserStatus.running;
    }
  } catch (error) {
    serviceUnavailable.value = true;
    if (showError) ElMessage.warning(readableError(error));
  } finally {
    loading.value = false;
  }
}

async function ensureProxyRunning() {
  if (status.value.running) return true;
  const result = await api.post<TrafficStatus>("/traffic/proxy/start", {
    handlingMode: "ASK",
  });
  status.value = { ...status.value, ...result.data };
  serviceUnavailable.value = false;
  return status.value.running;
}

// Launch the isolated capture browser WITHOUT starting interception. The proxy
// is brought up only so the browser has a route; nothing is recorded until the
// user explicitly starts capture.
async function startCaptureBrowser() {
  changingProxy.value = true;
  try {
    if (!(await ensureProxyRunning())) {
      ElMessage.error("代理启动失败");
      return;
    }
    if (await openCaptureBrowser()) {
      ElMessage.success(
        `抓包浏览器已启动：${proxyAddress.value}（未拦截，点击“开始拦截”才记录流量）`,
      );
    } else {
      ElMessage.info("抓包浏览器未启动");
    }
  } catch (error) {
    ElMessage.error(readableError(error));
  } finally {
    changingProxy.value = false;
  }
}

async function stopCaptureBrowser() {
  if (window.toolboxDesktop?.closeCaptureBrowser) {
    await window.toolboxDesktop.closeCaptureBrowser().catch(() => undefined);
  }
  browserRunning.value = false;
}

// Start/stop packet interception independently of the browser. Turning it off
// leaves the proxy and browser running so browsing can continue un-recorded.
async function toggleCapture() {
  changingCapture.value = true;
  try {
    if (!(await ensureProxyRunning())) {
      ElMessage.error("代理启动失败");
      return;
    }
    const enabled = !status.value.capturing;
    const result = await api.post<TrafficStatus>("/traffic/proxy/capture", {
      enabled,
    });
    status.value = { ...status.value, ...result.data };
    ElMessage.success(
      enabled ? "已开始拦截流量" : "已停止拦截（浏览器仍可继续使用）",
    );
  } catch (error) {
    ElMessage.error(readableError(error));
  } finally {
    changingCapture.value = false;
  }
}

async function toggleProxy() {
  changingProxy.value = true;
  try {
    const action = status.value.running ? "stop" : "start";
    if (action === "stop" && window.toolboxDesktop?.closeCaptureBrowser) {
      await window.toolboxDesktop.closeCaptureBrowser().catch(() => undefined);
      browserRunning.value = false;
    }
    const result = await api.post<TrafficStatus>(
      `/traffic/proxy/${action}`,
      action === "start"
        ? {
            handlingMode: "ASK",
          }
        : {},
    );
    status.value = { ...status.value, ...result.data };
    serviceUnavailable.value = false;
    ElMessage.success(
      status.value.running ? `代理已启动：${proxyAddress.value}` : "代理已停止",
    );
  } catch (error) {
    ElMessage.error(readableError(error));
  } finally {
    changingProxy.value = false;
  }
}

async function executeSuggestion() {
  if (!suggestion.value?.suggestionId) return;
  try {
    const result = await api.post<AiSuggestion>(
      `/traffic/suggestions/${suggestion.value.suggestionId}/execute`,
    );
    suggestion.value = result.data;
    ElMessage.success(
      result.data.taskId
        ? `已创建检测任务 #${result.data.taskId}`
        : "建议已执行",
    );
  } catch (error) {
    ElMessage.error(readableError(error));
  }
}

async function analyzeSelected() {
  if (!selected.value) return;
  const packetId = String(selected.value.id);
  analyzing.value = true;
  suggestion.value = undefined;
  try {
    const result = await api.post<AiSuggestion>(
      `/traffic/sessions/${packetId}/analyze`,
      {
        mode: autoHandle.value ? "AUTO_WITH_CONFIRMATION" : "SUGGEST_ONLY",
      },
      { timeout: 210_000 },
    );
    suggestion.value = result.data;
    const answer = [
      result.data.summary || "分析完成。",
      result.data.reasons?.length
        ? `判断依据：\n${result.data.reasons.map((item) => `- ${item}`).join("\n")}`
        : "",
      result.data.nextSteps?.length
        ? `下一步建议：\n${result.data.nextSteps.map((item) => `- ${item}`).join("\n")}`
        : "",
    ]
      .filter(Boolean)
      .join("\n\n");
    appendTrafficChat(packetId, "ASSISTANT", answer);
  } catch (error) {
    const message = readableError(error);
    appendTrafficChat(packetId, "ASSISTANT", `分析失败：${message}`);
    ElMessage.error(message);
  } finally {
    analyzing.value = false;
  }
}

function originalPacketValue(
  value: Record<string, string> | string | undefined,
) {
  if (value == null) return "";
  return typeof value === "string"
    ? value
    : Object.entries(value)
        .map(([key, item]) => `${key}: ${item}`)
        .join("\n");
}

async function toggleSessionMarked(item: TrafficSession) {
  if (markingId.value !== undefined || clearingSessions.value) return;
  const marked = !item.marked;
  markingId.value = item.id;
  try {
    const { data } = await api.put<TrafficSession>(
      `/traffic/sessions/${encodeURIComponent(String(item.id))}/marked`,
      { marked },
    );
    Object.assign(item, data);
    ElMessage.success(marked ? "会话已标记，清空时将保留" : "已取消标记");
  } catch (error) {
    ElMessage.error(readableError(error));
  } finally {
    markingId.value = undefined;
  }
}

async function deleteSession(item: TrafficSession) {
  if (deletingId.value !== undefined || clearingSessions.value) return;
  const label =
    item.url || `${item.host || ""}${item.path || ""}` || `#${item.id}`;
  try {
    await ElMessageBox.confirm(
      `确定删除这条流量记录吗？\n${label}`,
      "删除流量记录",
      {
        type: "warning",
        confirmButtonText: "删除",
        cancelButtonText: "取消",
      },
    );
  } catch {
    return;
  }
  deletingId.value = item.id;
  try {
    await api.delete(
      `/traffic/sessions/${encodeURIComponent(String(item.id))}`,
    );
    if (selectedId.value === item.id) {
      const index = sessions.value.findIndex(
        (session) => session.id === item.id,
      );
      selectedId.value =
        sessions.value[index + 1]?.id ?? sessions.value[index - 1]?.id;
      suggestion.value = undefined;
    }
    sessions.value = sessions.value.filter((session) => session.id !== item.id);
    const nextChats = { ...trafficChats.value };
    delete nextChats[String(item.id)];
    trafficChats.value = nextChats;
    persistTrafficChats();
    status.value = {
      ...status.value,
      capturedCount: Math.max(0, (status.value.capturedCount || 0) - 1),
    };
    ElMessage.success("流量记录已删除");
  } catch (error) {
    ElMessage.error(readableError(error));
  } finally {
    deletingId.value = undefined;
  }
}

async function clearSessions() {
  if (
    !unmarkedSessionCount.value ||
    clearingSessions.value ||
    deletingId.value !== undefined
  )
    return;
  try {
    await ElMessageBox.confirm(
      `确定清空 ${unmarkedSessionCount.value} 条未标记流量吗？${markedSessionCount.value ? `已标记的 ${markedSessionCount.value} 条会话会保留。` : ""}代理不会停止。`,
      "清空未标记流量",
      {
        type: "warning",
        confirmButtonText: "清空未标记项",
        cancelButtonText: "取消",
      },
    );
  } catch {
    return;
  }
  clearingSessions.value = true;
  try {
    await api.delete("/traffic/sessions");
    const retainedSessions = sessions.value.filter((item) => item.marked);
    const retainedIds = new Set(
      retainedSessions.map((item) => String(item.id)),
    );
    sessions.value = retainedSessions;
    if (
      selectedId.value !== undefined &&
      !retainedIds.has(String(selectedId.value))
    ) {
      selectedId.value = retainedSessions[0]?.id;
      suggestion.value = undefined;
    }
    trafficChats.value = Object.fromEntries(
      Object.entries(trafficChats.value).filter(([id]) => retainedIds.has(id)),
    );
    persistTrafficChats();
    status.value = { ...status.value, capturedCount: retainedSessions.length };
    ElMessage.success(
      markedSessionCount.value
        ? "未标记流量已清空，标记会话已保留"
        : "流量会话已清空",
    );
  } catch (error) {
    ElMessage.error(readableError(error));
  } finally {
    clearingSessions.value = false;
  }
}

function selectSession(item: TrafficSession) {
  selectedId.value = item.id;
  suggestion.value = undefined;
  packetTab.value = "request";
  void scrollTrafficChat();
}

function formatPacketValue(value?: Record<string, string> | string) {
  if (!value) return "暂无数据";
  if (typeof value === "string") return value;
  return (
    Object.entries(value)
      .map(([key, item]) => `${key}: ${item}`)
      .join("\n") || "暂无数据"
  );
}

function combinePacket(
  startLine: string,
  headers: Record<string, string> | string | undefined,
  body: string | undefined,
) {
  const rawHeaders = originalPacketValue(headers).trim();
  const firstLine = rawHeaders.split(/\r?\n/, 1)[0]?.trim() || "";
  const hasStartLine = /^(?:[A-Z]+\s+\S+\s+HTTP\/\d|HTTP\/\d)/i.test(firstLine);
  const headerBlock = [hasStartLine ? "" : startLine, rawHeaders]
    .filter(Boolean)
    .join("\n");
  const rawBody = body || "";
  if (!headerBlock && !rawBody) return "暂无数据";
  return rawBody ? `${headerBlock}\n\n${rawBody}` : headerBlock;
}

function formatRequestPacket(packet: TrafficSession) {
  const version = isHttp2Protocol(packet.protocol) ? "HTTP/2" : "HTTP/1.1";
  const path = packet.path || "/";
  return combinePacket(
    `${(packet.method || "GET").toUpperCase()} ${path} ${version}`,
    packet.requestHeaders,
    packet.requestBody,
  );
}

function formatResponsePacket(packet: TrafficSession) {
  const version = isHttp2Protocol(packet.protocol) ? "HTTP/2" : "HTTP/1.1";
  return combinePacket(
    `${version} ${packet.statusCode || ""}`.trim(),
    packet.responseHeaders,
    packet.responseBody,
  );
}

function formatReplayResponsePacket(result: ReplayResult) {
  return combinePacket(
    `HTTP/1.1 ${result.statusCode || ""} ${result.reasonPhrase || ""}`.trim(),
    result.responseHeaders,
    result.responseBody,
  );
}

function editablePacketValue(
  value: Record<string, string> | string | undefined,
  kind: "headers" | "body",
) {
  if (!value) return "";
  return typeof value === "string"
    ? value
    : Object.entries(value)
        .map(([key, item]) => `${key}: ${item}`)
        .join("\n");
}

function editableRequestHeaders(
  value: Record<string, string> | string | undefined,
) {
  const headers = editablePacketValue(value, "headers");
  const lines = headers.split(/\r?\n/);
  if (/^[A-Z]+\s+\S+\s+HTTP\/\d(?:\.\d)?$/i.test(lines[0]?.trim() || ""))
    lines.shift();
  return lines.join("\n").replace(/^\n+/, "");
}

function packetRequestUrl(packet: TrafficSession) {
  if (packet.url) return packet.url;
  const scheme =
    packet.scheme ||
    (String(packet.protocol || "")
      .toUpperCase()
      .includes("HTTPS")
      ? "https"
      : "http");
  const host = packet.host || "";
  const port =
    packet.port &&
    !(
      (scheme === "http" && packet.port === 80) ||
      (scheme === "https" && packet.port === 443)
    )
      ? `:${packet.port}`
      : "";
  return `${scheme}://${host}${port}${packet.path || "/"}`;
}

function composeReplayPacket(headers: string, body: string) {
  const normalizedHeaders = String(headers || "")
    .replace(/\r\n/g, "\n")
    .trimEnd();
  const normalizedBody = String(body || "").replace(/\r\n/g, "\n");
  return normalizedBody
    ? `${normalizedHeaders}\n\n${normalizedBody}`
    : normalizedHeaders;
}

function splitReplayPacket(value: string) {
  const normalized = String(value || "").replace(/\r\n/g, "\n");
  const separator = /\n[ \t]*\n/.exec(normalized);
  if (!separator || separator.index === undefined)
    return { headers: normalized.trimEnd(), body: "" };
  const bodyStart = separator.index + separator[0].length;
  return {
    headers: normalized.slice(0, separator.index).trimEnd(),
    body: normalized.slice(bodyStart),
  };
}

function replayTabTitle(form: ReplayForm | undefined, sequence: number) {
  if (!form?.url) return `请求 ${sequence}`;
  try {
    return `${form.method || "GET"} ${new URL(form.url).pathname || "/"}`;
  } catch {
    return `${form.method || "GET"} 请求 ${sequence}`;
  }
}

function createReplayTab(
  form?: ReplayForm,
  packet = "",
  sourcePacketId?: number | string,
) {
  const id = `replay-${Date.now()}-${++replayTabSequence}`;
  const sequence = replayTabs.value.length + 1;
  replayTabs.value.push({
    id,
    title: replayTabTitle(form, sequence),
    sourcePacketId,
    form: form
      ? { ...form }
      : { method: "GET", url: "", headers: "", body: "" },
    packet,
    sending: false,
  });
  activeReplayTabId.value = id;
  replayInlineOpen.value = true;
  packetTab.value = "replay";
}

function resetReplayRequest() {
  createReplayTab(undefined, "", selected.value?.id);
}

function closeReplayTab(id: string) {
  const index = replayTabs.value.findIndex((tab) => tab.id === id);
  if (index < 0) return;
  replayTabs.value.splice(index, 1);
  if (activeReplayTabId.value === id) {
    activeReplayTabId.value =
      replayTabs.value[Math.min(index, replayTabs.value.length - 1)]?.id || "";
  }
}

async function openReplayDialog() {
  const packet = selected.value;
  if (!packet || replayPreparing.value || replaying.value) return;
  replayPreparing.value = true;
  const form = {
    method: (packet.method || "GET").toUpperCase(),
    url: packetRequestUrl(packet),
    headers: editableRequestHeaders(packet.requestHeaders),
    body: editablePacketValue(packet.requestBody, "body"),
  };
  createReplayTab(
    form,
    composeReplayPacket(form.headers, form.body),
    packet.id,
  );
  replayDialogVisible.value = false;
  replayPreparing.value = false;
}

async function sendReplay() {
  const tab = activeReplayTab.value;
  const form = tab?.form;
  if (
    !tab ||
    !form ||
    !form.method.trim() ||
    !form.url.trim() ||
    replaying.value
  )
    return;
  if (tab.sourcePacketId == null) {
    tab.error =
      "该请求没有关联原始流量，请先从流量会话点击“发包”创建重放请求。";
    return;
  }
  const packetParts = splitReplayPacket(replayPacket.value);
  form.headers = packetParts.headers;
  form.body = packetParts.body;
  replaying.value = true;
  tab.sending = true;
  tab.result = undefined;
  tab.error = undefined;
  try {
    const { data } = await api.post<ReplayResult>(
      `/traffic/packets/${encodeURIComponent(String(tab.sourcePacketId))}/replay`,
      {
        method: form.method.trim().toUpperCase(),
        url: form.url.trim(),
        headers: form.headers,
        body: form.body,
      },
      { timeout: 45_000 },
    );
    tab.result = data;
    ElMessage.success("请求已发送");
  } catch (error) {
    tab.error = readableError(error);
    ElMessage.error(tab.error);
  } finally {
    tab.sending = false;
    replaying.value = false;
  }
}

function isHttp2Protocol(value?: string) {
  const normalized = String(value || "")
    .trim()
    .toUpperCase()
    .replace(/[\s_-]/g, "");
  return (
    normalized === "H2" ||
    normalized === "HTTP2" ||
    normalized === "HTTP/2" ||
    normalized === "HTTPS2"
  );
}

onMounted(() => {
  void load();
  void loadCaptureFilters();
  if (window.toolboxDesktop?.onCaptureBrowserClosed) {
    removeCaptureBrowserListener = window.toolboxDesktop.onCaptureBrowserClosed(
      () => {
        browserRunning.value = false;
      },
    );
  }
  refreshTimer = window.setInterval(() => {
    if (!loading.value) void load();
  }, 2500);
});
onUnmounted(() => {
  if (refreshTimer) window.clearInterval(refreshTimer);
  removeCaptureBrowserListener?.();
});
</script>

<template>
  <div class="traffic-page codex-traffic-page">
    <header class="traffic-toolbar codex-traffic-toolbar">
      <div class="traffic-workspace-title">
        <strong>流量工作区</strong>
        <span
          class="proxy-state"
          :class="{ running: status.running, capturing: status.capturing }"
          ><i></i
          >{{
            !status.running
              ? "未启动"
              : status.capturing
                ? "正在拦截"
                : "已连接·未拦截"
          }}</span
        >
        <code>{{ proxyAddress }}</code>
      </div>
      <div class="traffic-toolbar-actions codex-toolbar-actions">
        <el-tooltip
          v-if="captureBrowserAvailable && !browserRunning"
          :content="captureBrowserTooltip"
          placement="bottom"
          effect="light"
          :show-arrow="false"
          :show-after="350"
          popper-class="traffic-tooltip traffic-tooltip--wide"
        >
          <el-button
            class="capture-browser-reopen"
            :loading="changingProxy"
            @click="startCaptureBrowser"
            ><el-icon><Connection /></el-icon>启动抓包浏览器</el-button
          >
        </el-tooltip>
        <template v-else-if="browserRunning">
          <span class="capture-browser-state"><i />浏览器已连接</span>
          <el-button class="capture-browser-reopen" @click="stopCaptureBrowser"
            >关闭浏览器</el-button
          >
        </template>
        <el-button
          class="capture-filter-button"
          @click="openCaptureFilterDialog"
          ><el-icon><Filter /></el-icon>黑白名单<span
            v-if="activeCaptureFilterCount"
            class="capture-filter-count"
            >{{ activeCaptureFilterCount }}</span
          ></el-button
        >
        <el-tooltip
          content="刷新流量"
          placement="bottom"
          effect="light"
          :show-arrow="false"
          :show-after="350"
          popper-class="traffic-tooltip"
        >
          <button
            type="button"
            class="quiet-icon-button traffic-refresh"
            aria-label="刷新流量"
            :disabled="loading"
            @click="load(true)"
          >
            <el-icon :class="{ rotating: loading }"><Refresh /></el-icon>
          </button>
        </el-tooltip>
        <el-button
          :type="status.capturing ? 'default' : 'primary'"
          :loading="changingCapture"
          class="capture-toggle"
          @click="toggleCapture"
        >
          <el-icon
            ><VideoPause v-if="status.capturing" /><VideoPlay v-else
          /></el-icon>
          {{ status.capturing ? "停止拦截" : "开始拦截" }}
        </el-button>
        <el-button
          v-if="status.running"
          class="proxy-toggle"
          :loading="changingProxy"
          @click="toggleProxy"
          >停止代理</el-button
        >
      </div>
    </header>

    <el-alert
      v-if="serviceUnavailable"
      title="流量代理模块尚未就绪；界面会保留，待本地引擎提供 /api/traffic 接口后即可使用。"
      type="info"
      show-icon
      :closable="false"
    />

    <div class="traffic-workbench codex-traffic-workbench">
      <section class="traffic-list-pane traffic-session-rail">
        <header class="session-rail-header">
          <div>
            <span class="session-rail-title"
              ><strong>流量会话</strong><em>{{ sessions.length }}</em
              ><small v-if="markedSessionCount"
                >已标记 {{ markedSessionCount }}</small
              ></span
            ><el-button
              text
              type="danger"
              size="small"
              :disabled="!unmarkedSessionCount || deletingId !== undefined"
              :loading="clearingSessions"
              @click="clearSessions"
              >清空未标记</el-button
            >
          </div>
          <el-input
            v-model="filter"
            class="traffic-session-filter"
            :prefix-icon="Search"
            placeholder="筛选 URL、Host 或方法"
            clearable
          />
        </header>
        <div v-if="!filteredSessions.length" class="traffic-empty">
          <el-icon><Connection /></el-icon><strong>等待流量</strong>
          <p>启动代理，让浏览器或其他客户端流量经过本机。</p>
        </div>
        <el-dropdown
          v-for="item in pagedSessions"
          v-else
          :key="item.id"
          trigger="contextmenu"
          @command="
            (cmd: 'mark' | 'delete') =>
              cmd === 'mark' ? toggleSessionMarked(item) : deleteSession(item)
          "
        >
          <div
            class="traffic-row-wrap"
            :class="{ active: selectedId === item.id, marked: item.marked }"
          >
            <button
              type="button"
              class="traffic-row"
              :class="{ active: selectedId === item.id }"
              @click="selectSession(item)"
            >
              <span class="session-row-main">
                <span class="session-row-title"
                  ><b :class="(item.method || 'GET').toLowerCase()">{{
                    item.method || "GET"
                  }}</b
                  ><strong>{{
                    item.host || item.url || "未知地址"
                  }}</strong></span
                >
                <small>{{ item.path || item.url || "/" }}</small>
              </span>
              <span class="session-row-meta"
                ><el-icon
                  v-if="item.marked"
                  class="session-marked-flag"
                  aria-label="已标记"
                  ><StarFilled /></el-icon
                ><span
                  v-if="isHttp2Protocol(item.protocol)"
                  class="packet-protocol h2"
                  >HTTP/2</span
                ><code>{{ item.statusCode || "-" }}</code
                ><i :class="(item.riskLevel || 'NONE').toLowerCase()">{{
                  item.riskLevel || "—"
                }}</i></span
              >
            </button>
          </div>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item
                command="mark"
                :disabled="markingId === item.id || clearingSessions"
                >{{ item.marked ? "取消标记" : "标记会话" }}</el-dropdown-item
              >
              <el-dropdown-item
                command="delete"
                class="is-danger"
                :disabled="deletingId === item.id || clearingSessions"
                >删除这条流量</el-dropdown-item
              >
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <AppPagination
          v-model:page="sessionPage"
          v-model:page-size="sessionPageSize"
          :total="filteredSessions.length"
          layout="prev, pager, next"
        />
      </section>

      <section class="traffic-detail-pane packet-editor-pane">
        <div v-if="!selected" class="traffic-detail-empty">
          <el-icon><Connection /></el-icon><strong>选择一条流量会话</strong
          ><span>请求和响应内容会显示在这里</span>
        </div>
        <template v-else>
          <header class="traffic-detail-head">
            <div class="packet-title">
              <b>{{ selected.method || "GET" }}</b
              ><strong>{{
                selected.url || `${selected.host || ""}${selected.path || ""}`
              }}</strong>
            </div>
            <div class="packet-head-actions">
              <div class="packet-meta">
                <span
                  v-if="isHttp2Protocol(selected.protocol)"
                  class="packet-protocol h2"
                  >HTTP/2</span
                ><span v-if="selected.statusCode"
                  >HTTP {{ selected.statusCode }}</span
                ><span v-if="selected.durationMs"
                  >{{ selected.durationMs }} ms</span
                >
              </div>
              <el-tooltip
                content="把这条流量转交给 AI 智能体：可跨工具规划并派发授权检测任务（需已绑定授权目标）"
                placement="bottom"
                :show-after="350"
                ><el-button
                  size="small"
                  type="primary"
                  class="packet-copilot-button"
                  @click="openTrafficCopilot"
                  ><el-icon><MagicStick /></el-icon>转交 AI 智能体</el-button
                ></el-tooltip
              >
              <el-button
                type="primary"
                size="small"
                :loading="replayPreparing"
                @click="openReplayDialog"
                ><el-icon><Promotion /></el-icon>发送到重放器</el-button
              >
            </div>
          </header>
          <nav
            ref="packetTabsElement"
            class="packet-tabs"
            aria-label="报文内容"
          >
            <span
              class="fluent-selection-indicator packet-tabs-indicator"
              aria-hidden="true"
            />
            <button
              type="button"
              :class="{ active: packetTab === 'request' }"
              @click="packetTab = 'request'"
            >
              请求
            </button>
            <button
              type="button"
              :class="{ active: packetTab === 'response' }"
              @click="packetTab = 'response'"
            >
              响应
            </button>
            <button
              type="button"
              :class="{ active: packetTab === 'replay' }"
              @click="packetTab = 'replay'"
            >
              重放器
            </button>
          </nav>
          <section v-if="packetTab === 'replay'" class="inline-replay-editor">
            <header>
              <strong>请求重放器</strong>
              <div>
                <el-button
                  type="primary"
                  size="small"
                  :loading="replaying"
                  :disabled="
                    !replayForm.method.trim() || !replayForm.url.trim()
                  "
                  @click="sendReplay"
                  >发包</el-button
                >
              </div>
            </header>
            <nav
              ref="replayDocumentTabsElement"
              class="replay-document-tabs"
              aria-label="重放请求标签"
            >
              <span
                class="fluent-selection-indicator replay-document-tabs-indicator"
                aria-hidden="true"
              />
              <button
                v-for="tab in replayTabs"
                :key="tab.id"
                type="button"
                :class="{ active: tab.id === activeReplayTabId }"
                @click="activeReplayTabId = tab.id"
              >
                <i
                  class="replay-tab-status"
                  :class="
                    tab.sending
                      ? 'sending'
                      : tab.error
                        ? 'failed'
                        : tab.result
                          ? 'success'
                          : ''
                  "
                />
                <span>{{ tab.title }}</span>
                <el-tooltip
                  content="关闭标签"
                  placement="top"
                  effect="light"
                  :show-arrow="false"
                  :show-after="350"
                  popper-class="traffic-tooltip"
                >
                  <b aria-label="关闭标签" @click.stop="closeReplayTab(tab.id)"
                    ><el-icon><Dismiss /></el-icon
                  ></b>
                </el-tooltip>
              </button>
              <el-tooltip
                content="新建请求"
                placement="top"
                effect="light"
                :show-arrow="false"
                :show-after="350"
                popper-class="traffic-tooltip"
              >
                <button
                  type="button"
                  class="replay-tab-add"
                  aria-label="新建请求"
                  @click="resetReplayRequest"
                >
                  <el-icon><Plus /></el-icon>
                </button>
              </el-tooltip>
            </nav>
            <template v-if="activeReplayTab">
              <div class="replay-request-line">
                <el-select
                  v-model="activeReplayTab.form.method"
                  :disabled="activeReplayTab.sending"
                  filterable
                  allow-create
                  default-first-option
                  placeholder="GET"
                >
                  <el-option
                    v-for="m in HTTP_METHODS"
                    :key="m"
                    :label="m"
                    :value="m"
                  />
                </el-select>
                <el-input
                  v-model="activeReplayTab.form.url"
                  :disabled="activeReplayTab.sending"
                  placeholder="https://example.com/path"
                />
              </div>
              <label class="replay-packet-editor"
                >请求数据包<el-input
                  v-model="activeReplayTab.packet"
                  type="textarea"
                  :disabled="activeReplayTab.sending"
                  spellcheck="false"
                  placeholder="Header-Name: value&#10;&#10;可选请求体"
              /></label>
              <section class="replay-response">
                <header>
                  <div>
                    <strong>{{
                      activeReplayTab.result
                        ? `HTTP ${activeReplayTab.result.statusCode || "-"}`
                        : "响应数据包"
                    }}</strong
                    ><span>{{
                      activeReplayTab.result?.reasonPhrase || ""
                    }}</span>
                  </div>
                  <div class="replay-response-meta">
                    <span
                      v-if="activeReplayTab.result?.durationMs !== undefined"
                      >{{ activeReplayTab.result.durationMs }} ms</span
                    ><span
                      v-if="activeReplayTab.result?.responseBytes !== undefined"
                      >{{ activeReplayTab.result.responseBytes }} bytes</span
                    ><el-tag
                      v-if="activeReplayTab.result?.truncated"
                      size="small"
                      type="warning"
                      >响应内容已截断</el-tag
                    >
                  </div>
                </header>
                <div
                  v-if="activeReplayTab.sending"
                  class="replay-response-state"
                >
                  <el-icon class="is-loading"><Refresh /></el-icon
                  ><strong>正在发送请求</strong
                  ><span>请稍候，服务器响应将显示在这里。</span>
                </div>
                <div
                  v-else-if="activeReplayTab.error"
                  class="replay-response-state error"
                >
                  <strong>请求发送失败</strong
                  ><span>{{ activeReplayTab.error }}</span>
                </div>
                <div
                  v-else-if="!activeReplayTab.result"
                  class="replay-response-state"
                >
                  <strong>尚未发送</strong
                  ><span
                    >编辑请求数据后点击“发包”，响应数据包会保留在当前标签中。</span
                  >
                </div>
                <div v-else class="replay-response-packet">
                  <h3>
                    Response Packet
                    <small v-if="activeReplayTab.result.bodyEncoding">{{
                      activeReplayTab.result.bodyEncoding
                    }}</small>
                  </h3>
                  <pre>{{
                    formatReplayResponsePacket(activeReplayTab.result) ||
                    "服务器已响应，但响应内容为空。"
                  }}</pre>
                </div>
              </section>
            </template>
            <div v-else class="replay-empty-state">
              <strong>暂无重放请求</strong
              ><span>点击“新建请求”，或从流量会话点击“发包”创建标签。</span>
            </div>
          </section>
          <div v-else class="packet-sections packet-editor">
            <template v-if="packetTab === 'request'">
              <article class="raw-packet-card">
                <h3>请求报文</h3>
                <pre>{{ formatRequestPacket(selected) }}</pre>
              </article>
            </template>
            <template v-else-if="packetTab === 'response'">
              <article class="raw-packet-card">
                <h3>响应报文</h3>
                <pre>{{ formatResponsePacket(selected) }}</pre>
              </article>
            </template>
          </div>
        </template>
      </section>

      <aside class="traffic-ai-pane traffic-points-pane">
        <header class="ai-thread-header">
          <span class="ai-mark"
            ><el-icon><Connection /></el-icon
          ></span>
          <div>
            <strong>本条流量安全要点</strong
            ><small>基于所选报文的本地快速研判，不派发任务</small>
          </div>
        </header>
        <div class="traffic-points-body">
          <div v-if="!selected" class="traffic-points-empty">
            选择一条流量，这里会给出该报文的加密、请求方法、会话凭证与安全响应头等要点。
          </div>
          <ul v-else class="traffic-points-list">
            <li
              v-for="point in trafficSecurityPoints"
              :key="point.label"
              class="fluent-point-card fluent-infobar"
              :class="point.level"
            >
              <div class="fluent-infobar__icon" :class="point.level">
                <el-icon v-if="point.level === 'ok'"><CircleCheck /></el-icon>
                <el-icon v-else-if="point.level === 'warn'"
                  ><Warning
                /></el-icon>
                <el-icon v-else><InfoCircle /></el-icon>
              </div>
              <div class="fluent-infobar__content">
                <div class="fluent-infobar__title-row">
                  <span class="fluent-infobar__title">{{ point.label }}</span>
                  <span
                    v-if="point.badge"
                    class="fluent-infobar__badge"
                    :class="point.level"
                    >{{ point.badge }}</span
                  >
                </div>
                <div class="fluent-infobar__message">
                  <template v-if="point.items">
                    <div v-for="item in point.items" :key="item">{{ item }}</div>
                  </template>
                  <template v-else>{{ point.value }}</template>
                </div>
              </div>
            </li>
          </ul>
        </div>
        <footer class="traffic-points-foot">
          <small
            >需要 AI 深入分析或据此派发检测，请点击上方“转交 AI 智能体”。</small
          >
        </footer>
      </aside>
    </div>

    <el-dialog
      v-model="captureFilterDialogVisible"
      title="抓包黑白名单"
      class="app-dialog app-dialog--wide"
      align-center
    >
      <el-alert
        title="黑名单命中后不保存；启用任意白名单后，仅保存命中白名单且未命中黑名单的流量。规则修改后立即生效。"
        type="info"
        show-icon
        :closable="false"
      />
      <div class="capture-filter-editor">
        <el-select v-model="captureFilterForm.listType" style="width: 112px">
          <el-option label="黑名单" value="BLACKLIST" />
          <el-option label="白名单" value="WHITELIST" />
        </el-select>
        <el-select v-model="captureFilterForm.type" style="width: 112px">
          <el-option label="域名" value="DOMAIN" />
          <el-option label="URL" value="URL" />
          <el-option label="关键字" value="KEYWORD" />
        </el-select>
        <el-input
          v-model="captureFilterForm.pattern"
          :placeholder="captureFilterPlaceholder"
          clearable
          @keyup.enter="saveCaptureFilter"
        />
        <el-switch
          v-model="captureFilterForm.enabled"
          inline-prompt
          active-text="启"
          inactive-text="停"
        />
        <el-button
          type="primary"
          :loading="captureFilterSaving"
          :disabled="!captureFilterForm.pattern.trim()"
          @click="saveCaptureFilter"
          ><el-icon><Plus /></el-icon
          >{{ captureFilterForm.id ? "保存" : "添加" }}</el-button
        >
        <el-button v-if="captureFilterForm.id" @click="resetCaptureFilterForm"
          >取消</el-button
        >
      </div>
      <el-table
        v-loading="captureFiltersLoading"
        :data="pagedCaptureFilters"
        size="small"
        class="capture-filter-table"
        empty-text="暂无抓包黑白名单规则"
      >
        <el-table-column label="名单" width="86"
          ><template #default="scope"
            ><el-tag
              size="small"
              :type="scope.row.listType === 'BLACKLIST' ? 'danger' : 'success'"
              >{{
                scope.row.listType === "BLACKLIST" ? "黑名单" : "白名单"
              }}</el-tag
            ></template
          ></el-table-column
        >
        <el-table-column label="匹配方式" width="92"
          ><template #default="scope">{{
            captureFilterTypeLabel(scope.row.type)
          }}</template></el-table-column
        >
        <el-table-column
          prop="pattern"
          label="匹配内容"
          min-width="260"
          :show-overflow-tooltip="{
            effect: 'light',
            placement: 'top',
            popperClass: 'traffic-tooltip',
            showArrow: false,
            showAfter: 350,
          }"
        />
        <el-table-column label="启用" width="72"
          ><template #default="scope"
            ><el-switch
              v-model="scope.row.enabled"
              @change="toggleCaptureFilter(scope.row)" /></template
        ></el-table-column>
        <el-table-column label="操作" width="112"
          ><template #default="scope"
            ><el-button
              link
              type="primary"
              @click="editCaptureFilter(scope.row)"
              >编辑</el-button
            ><el-button
              link
              type="danger"
              @click="deleteCaptureFilter(scope.row)"
              >删除</el-button
            ></template
          ></el-table-column
        >
      </el-table>
      <AppPagination
        v-model:page="captureFilterPage"
        v-model:page-size="captureFilterPageSize"
        class="capture-filter-pagination"
        :total="captureFilters.length"
      />
      <p class="capture-filter-help">
        域名匹配不区分大小写并包含子域名；URL
        使用完整地址包含匹配；关键字会检查方法、URL、请求和响应头、请求和响应体。
      </p>
      <template #footer>
        <el-button @click="captureFilterDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="replayDialogVisible"
      title="HTTP 发包器"
      class="app-dialog app-dialog--wide"
      align-center
      destroy-on-close
    >
      <div class="traffic-replay-dialog">
        <div v-if="false" class="replay-authorized-target">
          <label>授权目标</label>
          <el-select
            v-model="replayForm.targetId"
            :disabled="replayTargetLocked || replaying"
            placeholder="选择授权目标"
          >
            <el-option
              v-for="target in replayTargets"
              :key="target.id"
              :label="target.name"
              :value="target.id"
            >
              <span>{{ target.name }}</span
              ><small>{{ target.targetValue }}</small>
            </el-option>
          </el-select>
          <small
            >请求只能发送到所选授权目标及其允许端口，服务端会再次校验；当前以
            HTTP/1.1 语义发送。</small
          >
        </div>

        <div class="replay-request-line">
          <el-select
            v-model="replayForm.method"
            :disabled="replaying"
            filterable
            allow-create
            default-first-option
          >
            <el-option
              v-for="method in [
                'GET',
                'POST',
                'PUT',
                'PATCH',
                'DELETE',
                'HEAD',
                'OPTIONS',
              ]"
              :key="method"
              :label="method"
              :value="method"
            />
          </el-select>
          <el-input
            v-model="replayForm.url"
            :disabled="replaying"
            placeholder="https://example.com/path"
          />
        </div>

        <label class="replay-packet-editor"
          >请求数据包<el-input
            v-model="replayPacket"
            type="textarea"
            :rows="14"
            :disabled="replaying"
            spellcheck="false"
            placeholder="Header-Name: value&#10;&#10;可选请求体"
        /></label>
        <el-alert
          v-if="replayBodyIncomplete"
          title="原始请求体可能未完整保存（当前内容短于抓包记录），请在发送前补全并确认请求体。"
          type="warning"
          show-icon
          :closable="false"
        />

        <section v-if="replayResult" class="replay-response">
          <header>
            <div>
              <strong>HTTP {{ replayResult.statusCode || "-" }}</strong
              ><span>{{ replayResult.reasonPhrase }}</span>
            </div>
            <div class="packet-meta">
              <span v-if="replayResult.durationMs !== undefined"
                >{{ replayResult.durationMs }} ms</span
              >
              <span v-if="replayResult.responseBytes !== undefined"
                >{{ replayResult.responseBytes }} bytes</span
              >
              <el-tag v-if="replayResult.truncated" size="small" type="warning"
                >内容已截断</el-tag
              >
            </div>
          </header>
          <div class="replay-response-packet">
            <h3>
              Response Packet
              <small v-if="replayResult.bodyEncoding">{{
                replayResult.bodyEncoding
              }}</small>
            </h3>
            <pre>{{ formatReplayResponsePacket(replayResult) }}</pre>
          </div>
        </section>
      </div>
      <template #footer>
        <el-button :disabled="replaying" @click="replayDialogVisible = false"
          >关闭</el-button
        >
        <el-button
          type="primary"
          :loading="replaying"
          :disabled="!replayForm.method.trim() || !replayForm.url.trim()"
          @click="sendReplay"
          >发送请求</el-button
        >
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.codex-traffic-page {
  display: flex;
  flex-direction: column;
  min-height: 0;
  height: 100%;
  color: var(--app-text);
  background: transparent;
}
.codex-traffic-toolbar {
  min-height: 32px;
  margin: 0;
  padding: 0;
  align-items: flex-start;
  border: 0;
  border-radius: 0;
  background: transparent;
  box-shadow: none;
}
.traffic-workspace-title {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 10px;
}
.traffic-workspace-title > strong {
  font-size: 14px;
  font-weight: 600;
}
.traffic-workspace-title > code {
  color: var(--app-muted);
  font:
    12px/1.4 ui-monospace,
    SFMono-Regular,
    Consolas,
    monospace;
}
.codex-toolbar-actions {
  gap: 8px;
}
.capture-browser-option {
  margin: 0 3px 0 6px;
  color: var(--app-muted);
  font-size: 11px;
  white-space: nowrap;
}
.capture-browser-option :deep(.el-checkbox__label) {
  padding-left: 5px;
  font-size: 11px;
}
.capture-browser-state {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #39735f;
  font-size: 11px;
  white-space: nowrap;
}
.capture-browser-state i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #37a272;
  box-shadow: 0 0 0 3px #e0f0e8;
}
.capture-browser-reopen {
  min-height: 32px;
  height: 32px;
  padding: 0 10px;
  border-radius: 7px;
  font-size: 11px;
}
.capture-filter-button {
  min-height: 32px;
  height: 32px;
  padding: 0 10px;
  border-radius: 7px;
  font-size: 11px;
}
.capture-filter-count {
  display: inline-grid;
  min-width: 20px;
  height: 20px;
  margin-left: 4px;
  place-items: center;
  padding: 0 5px;
  border-radius: 999px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font-size: 11px;
}
.capture-filter-editor {
  display: grid;
  grid-template-columns: 112px 112px minmax(220px, 1fr) 42px auto auto;
  align-items: center;
  gap: 8px;
  margin: 14px 0 12px;
}
.capture-filter-table {
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface);
}
.capture-filter-help {
  margin: 10px 2px 0;
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.6;
}
.capture-filter-pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}
.traffic-refresh {
  width: 32px;
  height: 32px;
  border-radius: 8px;
}
.proxy-toggle {
  min-width: 92px;
  border-radius: 8px;
}
.codex-traffic-page > :deep(.el-alert) {
  margin: 8px 12px 0;
}
.codex-traffic-workbench {
  grid-template-columns: 300px minmax(420px, 1fr) 340px;
  border: 0;
  border-radius: 0;
  background: transparent;
}
.traffic-session-rail {
  position: relative;
  display: flex;
  padding-bottom: 8px;
  flex-direction: column;
  background: var(--app-surface);
}
.traffic-session-rail > .session-rail-header {
  flex: none;
  min-height: 0;
  padding: 12px;
  border-color: var(--app-border);
  background: var(--app-surface-strong);
}
.traffic-session-rail > .traffic-empty {
  position: absolute;
  inset: 0;
  min-height: 0;
  gap: 8px;
  pointer-events: none;
}
.traffic-empty > :deep(.el-icon),
.traffic-detail-empty > :deep(.el-icon) {
  font-size: 24px;
}
.traffic-empty > strong,
.traffic-detail-empty > strong {
  margin: 0;
  color: var(--app-text);
  font-size: 13px;
  line-height: 1.3;
}
.traffic-empty > p,
.traffic-detail-empty > span {
  margin: 0;
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.5;
}
.session-rail-header > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 9px !important;
}
.session-rail-title {
  display: flex;
  align-items: center;
  gap: 8px;
}
.session-rail-title > strong {
  color: var(--app-text);
  font-size: 13px;
  font-weight: 620;
}
.session-rail-title > em {
  min-width: 22px;
  padding: 2px 7px;
  border-radius: 10px;
  background: var(--app-surface-soft);
  color: var(--app-muted);
  font-size: 11px;
  font-style: normal;
  text-align: center;
}
.session-rail-title > small {
  color: var(--app-accent);
  font-size: 11px;
  font-weight: 600;
}
.session-rail-header :deep(.el-button) {
  min-height: 32px;
  height: 32px;
  padding: 0 8px;
  font-size: 11px;
}
.session-rail-header :deep(.el-input__wrapper) {
  border-radius: 8px;
  box-shadow: 0 0 0 1px var(--app-border) inset;
  background: var(--app-surface);
}
.traffic-row-wrap {
  position: relative;
  margin: 2px 8px;
  border-radius: 8px;
}
.traffic-session-rail :deep(.el-dropdown) {
  display: block;
  width: 100%;
}
.traffic-row {
  grid-template-columns: minmax(0, 1fr) auto;
  min-height: 64px;
  gap: 10px;
  padding: 8px 10px;
  border: 0;
  border-radius: 8px;
  background: transparent;
  transition:
    background 0.12s,
    color 0.12s;
}
.traffic-row:hover {
  background: var(--app-surface-soft);
}
.traffic-row.active {
  background: var(--app-accent-soft);
  box-shadow: none;
}
.traffic-row-wrap.marked:not(.active) .traffic-row {
  background: var(--app-accent-soft);
}
.traffic-row-mark,
.traffic-row-delete {
  position: absolute;
  top: 50%;
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  transform: translateY(-50%);
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--app-muted);
  cursor: pointer;
  opacity: 0;
  transition:
    opacity 0.12s,
    background 0.12s,
    color 0.12s;
}
.traffic-row-mark {
  right: 48px;
}
.traffic-row-delete {
  right: 8px;
}
.traffic-row-wrap:hover .traffic-row-mark,
.traffic-row-wrap:hover .traffic-row-delete,
.traffic-row-mark:focus-visible,
.traffic-row-delete:focus-visible,
.traffic-row-mark.marked {
  opacity: 1;
}
.traffic-row-mark:hover,
.traffic-row-mark.marked {
  background: var(--app-accent-soft);
  color: var(--app-accent);
}
.traffic-row-delete:hover {
  background: #f4dede;
  color: #b43d3d;
}
.traffic-row-mark:disabled,
.traffic-row-delete:disabled {
  cursor: wait;
  opacity: 0.45;
}
.session-row-main {
  display: flex;
  min-width: 0;
  flex-direction: column;
}
.session-row-title {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
}
.session-row-title > b {
  flex: none;
  color: #3973a5;
  font:
    700 10px/1.3 ui-monospace,
    SFMono-Regular,
    Consolas,
    monospace;
}
.session-row-title > b.post {
  color: #9a6825;
}
.session-row-title > strong {
  overflow: hidden;
  color: var(--app-text);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.session-row-main > small {
  overflow: hidden;
  margin-top: 5px;
  color: var(--app-muted);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.session-row-meta {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 8px;
}
.session-marked-flag {
  color: var(--app-accent);
  font-size: 13px;
}
.packet-protocol {
  padding: 2px 6px;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-soft);
  color: var(--app-muted);
  font:
    600 11px/1.3 ui-monospace,
    SFMono-Regular,
    Consolas,
    monospace;
}
.packet-protocol.h2 {
  border-color: #bdd8cc;
  background: #eaf4ef;
  color: #2f705a;
}
.session-row-meta code {
  color: var(--app-muted);
  font-size: 11px;
}
.session-row-meta i {
  color: var(--app-muted);
  font-size: 11px;
  font-style: normal;
}
.session-row-meta i.high,
.session-row-meta i.critical {
  color: #bd3e3e;
}
.session-row-meta i.medium {
  color: #966920;
}
.packet-editor-pane {
  display: flex;
  flex-direction: column;
  background: var(--app-surface);
}
.traffic-detail-empty {
  display: flex;
  height: 100%;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 8px;
  padding-top: 0;
  box-sizing: border-box;
  transform: translateY(-24px);
  color: var(--app-muted);
  text-align: center;
}
.traffic-session-rail > .traffic-empty {
  transform: translateY(-24px);
}
.traffic-detail-head {
  position: static;
  min-height: 54px;
  padding: 8px 14px;
}
.inline-replay-editor {
  min-height: 0;
  flex: 1;
  overflow: auto;
  margin: 0;
  padding: 12px 14px;
  border: 0;
  border-radius: 0;
  background: var(--app-surface);
}
.inline-replay-editor,
.inline-replay-editor * {
  scrollbar-width: none;
}
.inline-replay-editor::-webkit-scrollbar,
.inline-replay-editor *::-webkit-scrollbar {
  display: none;
  width: 0;
  height: 0;
}
.inline-replay-tabs {
  display: flex;
  height: 32px;
  gap: 14px;
  padding: 0 14px;
  border-bottom: 1px solid var(--app-border);
}
.inline-replay-tabs button {
  border: 0;
  border-bottom: 2px solid transparent;
  background: transparent;
  color: var(--app-muted);
  font-size: 11px;
  cursor: pointer;
}
.inline-replay-tabs button.active {
  border-bottom-color: var(--app-accent);
  color: var(--app-accent);
  font-weight: 600;
}
.inline-replay-editor > header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}
.inline-replay-editor > header strong {
  color: var(--app-text);
  font-size: 12px;
}
.replay-document-tabs {
  display: flex;
  min-height: 40px;
  gap: 8px;
  overflow-x: auto;
  margin: 0 0 10px;
  padding: 4px;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-soft);
  scrollbar-width: none;
}
.replay-document-tabs::-webkit-scrollbar {
  display: none;
}
.replay-document-tabs > button {
  display: flex;
  min-width: 0;
  max-width: 210px;
  height: 32px;
  flex: none;
  align-items: center;
  gap: 8px;
  padding: 0 8px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--app-muted);
  font-size: 11px;
  cursor: pointer;
}
.replay-document-tabs > button:hover {
  background: var(--app-surface);
  color: var(--app-text);
}
.replay-document-tabs > button.active {
  background: var(--app-surface-strong);
  color: var(--app-text);
  box-shadow: 0 1px 2px color-mix(in srgb, var(--app-text) 6%, transparent);
}
.replay-document-tabs button > .replay-tab-status {
  width: 6px;
  height: 6px;
  flex: none;
  border-radius: 50%;
  background: var(--app-border-strong);
}
.replay-document-tabs button > .replay-tab-status.sending {
  background: var(--app-accent);
  animation: thinking 1.2s infinite;
}
.replay-document-tabs button > .replay-tab-status.success {
  background: #39a36d;
}
.replay-document-tabs button > .replay-tab-status.failed {
  background: #c84f4f;
}
.replay-document-tabs button > span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.replay-document-tabs button > b {
  display: grid;
  width: 30px;
  height: 30px;
  flex: none;
  margin-left: 2px;
  place-items: center;
  border-radius: 4px;
  font-size: 14px;
  font-weight: 400;
}
.replay-document-tabs button > b:hover {
  background: color-mix(in srgb, var(--app-text) 10%, transparent);
}
.replay-document-tabs > .replay-tab-add {
  width: 32px;
  min-width: 32px;
  padding: 0;
  justify-content: center;
  color: var(--app-muted);
  font-size: 16px;
}
.replay-document-tabs > .replay-tab-add > .el-icon {
  width: 16px;
  height: 16px;
  background: transparent;
  color: inherit;
}
.replay-document-tabs > .replay-tab-add:hover {
  color: var(--app-accent);
}
.inline-replay-editor .replay-request-line {
  grid-template-columns: 110px minmax(0, 1fr);
}
.inline-replay-editor .replay-packet-editor {
  margin-top: 8px;
}
.inline-replay-editor .replay-packet-editor :deep(textarea) {
  height: clamp(220px, 35vh, 420px) !important;
  min-height: 220px !important;
  resize: none !important;
}
.replay-empty-state,
.replay-response-state {
  display: flex;
  min-height: 190px;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 8px;
  padding: 24px;
  color: var(--app-muted);
  text-align: center;
}
.replay-empty-state strong,
.replay-response-state strong {
  color: var(--app-text);
  font-size: 12px;
}
.replay-empty-state span,
.replay-response-state span {
  max-width: 440px;
  font-size: 11px;
  line-height: 1.6;
}
.replay-response-state > .el-icon {
  color: var(--app-accent);
  font-size: 20px;
}
.replay-response-state.error strong {
  color: #b94343;
}
.replay-response-meta {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
}
.packet-title {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
  line-height: 1.3;
}
.packet-title > b {
  flex: none;
  padding: 3px 6px;
  border-radius: 5px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font:
    700 10px/1.3 ui-monospace,
    SFMono-Regular,
    Consolas,
    monospace;
}
.packet-title > strong {
  overflow: hidden;
  color: var(--app-text);
  font-size: 12px;
  font-weight: 500;
  line-height: 1.3;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.packet-head-actions {
  display: flex;
  flex: none;
  align-items: center;
  gap: 8px;
}
.packet-meta {
  display: flex;
  flex: none;
  gap: 10px;
  color: var(--app-muted);
  font-size: 11px;
}
.packet-head-actions :deep(.el-button) {
  min-height: 32px;
  height: 32px;
  padding: 0 10px;
  border-radius: 7px;
  font-size: 11px;
}
.packet-tabs {
  display: flex;
  height: 39px;
  flex: none;
  gap: 20px;
  padding: 0 15px;
  border-bottom: 1px solid var(--app-border);
}
.packet-tabs button {
  position: relative;
  display: flex;
  align-items: center;
  border: 0;
  background: none;
  color: var(--app-muted);
  font: 400 11px/1.3 inherit;
  cursor: pointer;
}
.packet-tabs button.active {
  color: var(--app-text);
  font-weight: 600;
}
.packet-tabs button.active::after {
  position: absolute;
  right: 0;
  bottom: -1px;
  left: 0;
  height: 2px;
  border-radius: 2px;
  background: var(--app-accent);
  content: "";
}
.packet-editor {
  flex: 1;
  overflow: auto;
  padding: 14px;
  background: var(--app-bg);
}
.packet-editor article {
  border: 1px solid var(--app-border);
  border-radius: var(--traffic-card-radius);
  background: var(--app-surface-strong);
  box-shadow: 0 1px 2px color-mix(in srgb, var(--app-text) 5%, transparent);
  margin-bottom: 0;
  transition: border-color 120ms ease;
}
.packet-editor article:hover {
  border-color: var(--app-border-strong);
}
.packet-editor .raw-packet-card {
  min-height: 100%;
}
.packet-editor h3 {
  margin: 0;
  padding: 8px 12px;
  border-bottom: 1px solid var(--app-border);
  color: var(--app-muted);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0;
}
.packet-editor pre {
  max-height: none;
  min-height: 82px;
  margin: 0;
  padding: 12px;
  border: 0;
  border-radius: 0;
  background: transparent;
  color: var(--app-text);
  font-size: 12px;
  line-height: 1.65;
}
.packet-editor .raw-packet-card pre {
  min-height: 320px;
  white-space: pre-wrap;
  word-break: break-all;
}
.replay-response-grid {
  grid-template-columns: minmax(0, 1fr);
}
.ai-thread-pane {
  padding: 0;
  background: var(--app-surface);
}
.traffic-points-pane {
  display: flex;
  flex-direction: column;
  min-width: 0;
  background: var(--app-surface);
}
.traffic-points-body {
  flex: 1;
  overflow-y: auto;
  padding: 12px 14px;
}
.traffic-points-empty {
  padding: 12px 4px;
  color: var(--app-muted);
  font-size: var(--type-caption);
  line-height: 1.6;
}
.traffic-points-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.traffic-points-list li.fluent-point-card.fluent-infobar {
  display: flex;
  flex-direction: row;
  align-items: flex-start;
  gap: 10px;
  padding: 10px;
  border: 1px solid transparent;
  border-radius: 8px;
  background: var(--app-surface);
  transition: background-color 120ms ease, border-color 120ms ease;
}
.traffic-points-list li.fluent-point-card.fluent-infobar.ok {
  background: light-dark(rgba(16, 124, 16, 0.07), rgba(74, 222, 74, 0.09));
  border-color: light-dark(rgba(16, 124, 16, 0.16), rgba(74, 222, 74, 0.18));
}
.traffic-points-list li.fluent-point-card.fluent-infobar.info {
  background: light-dark(rgba(0, 90, 158, 0.06), rgba(96, 169, 246, 0.08));
  border-color: light-dark(rgba(0, 90, 158, 0.14), rgba(96, 169, 246, 0.16));
}
.traffic-points-list li.fluent-point-card.fluent-infobar.warn {
  background: light-dark(rgba(255, 193, 7, 0.10), rgba(255, 183, 77, 0.12));
  border-color: light-dark(rgba(255, 193, 7, 0.18), rgba(255, 183, 77, 0.20));
}
.traffic-points-list .fluent-infobar__icon {
  display: flex;
  flex-shrink: 0;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  margin-top: 1px;
  font-size: 15px;
}
.traffic-points-list .fluent-infobar__icon.ok {
  color: light-dark(#107c10, #54b054);
}
.traffic-points-list .fluent-infobar__icon.info {
  color: light-dark(#0f6cbd, #479ef5);
}
.traffic-points-list .fluent-infobar__icon.warn {
  color: light-dark(#bc4b09, #f7823b);
}
.traffic-points-list .fluent-infobar__content {
  flex: 1;
  min-width: 0;
}
.traffic-points-list .fluent-infobar__title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 4px;
}
.traffic-points-list .fluent-infobar__title {
  font-size: 12px;
  font-weight: 600;
  color: var(--app-text);
  line-height: 1.35;
}
.traffic-points-list .fluent-infobar__badge {
  flex-shrink: 0;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  white-space: nowrap;
}
.traffic-points-list .fluent-infobar__badge.ok {
  color: light-dark(#107c10, #a5e6a5);
}
.traffic-points-list .fluent-infobar__badge.info {
  color: light-dark(#0f6cbd, #93c9f7);
}
.traffic-points-list .fluent-infobar__badge.warn {
  color: light-dark(#bc4b09, #ffbf7a);
}
.traffic-points-list .fluent-infobar__message {
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.5;
  word-break: break-word;
}
.traffic-points-foot {
  padding: 10px 14px;
  border-top: 1px solid var(--app-border);
  color: var(--app-muted);
  line-height: 1.5;
}
.traffic-points-foot > small {
  display: block;
  font-size: 13px;
  line-height: 1.55;
  overflow-wrap: anywhere;
}
.ai-thread-header {
  flex: none;
  min-height: 54px;
  margin: 0 !important;
  padding: 9px 14px;
  border-bottom: 1px solid var(--app-border);
}
.ai-mark {
  width: 30px;
  height: 30px;
  border-radius: 9px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
}
.ai-thread-header strong {
  font-size: 13px !important;
}
.ai-thread-header small {
  color: var(--app-muted) !important;
  font-size: 11px !important;
}
.ai-clear-chat {
  display: grid;
  min-width: 32px;
  min-height: 32px;
  margin-left: auto;
  padding: 0 8px;
  place-items: center;
  border: 0;
  border-radius: 5px;
  background: transparent;
  color: var(--app-muted);
  font-size: 11px;
  cursor: pointer;
}
.ai-clear-chat:hover {
  background: var(--app-surface-soft);
  color: var(--app-text);
}
.ai-thread-body {
  flex: 1;
  overflow: auto;
  padding: 16px 14px;
}
.assistant-message {
  color: var(--app-text);
  font-size: 12px;
  line-height: 1.65;
}
.intro-message {
  padding-bottom: 15px;
  border-bottom: 1px solid var(--app-border);
}
.intro-message p {
  margin: 0;
}
.traffic-chat-message {
  display: flex;
  margin-bottom: 13px;
  flex-direction: column;
  align-items: flex-start;
}
.traffic-chat-message > strong {
  margin: 0 4px 4px;
  color: var(--app-muted);
  font-size: 11px;
}
.traffic-chat-message > p {
  max-width: 94%;
  margin: 0;
  padding: 9px 11px;
  border: 1px solid var(--app-border);
  border-radius: 4px 11px 11px;
  background: var(--app-surface-soft);
  color: var(--app-text);
  font-size: 11px;
  line-height: 1.65;
  white-space: pre-wrap;
  word-break: break-word;
}
.traffic-markdown {
  max-width: 94%;
  padding: 9px 11px;
  border: 1px solid var(--app-border);
  border-radius: 4px 11px 11px;
  background: var(--app-surface-soft);
  color: var(--app-text);
  font-size: 11px;
  line-height: 1.65;
  word-break: break-word;
}
.traffic-markdown :deep(> :first-child) {
  margin-top: 0;
}
.traffic-markdown :deep(> :last-child) {
  margin-bottom: 0;
}
.traffic-markdown :deep(p) {
  margin: 0 0 7px;
}
.traffic-markdown :deep(h1),
.traffic-markdown :deep(h2),
.traffic-markdown :deep(h3) {
  margin: 11px 0 6px;
  line-height: 1.35;
}
.traffic-markdown :deep(h1) {
  font-size: 16px;
}
.traffic-markdown :deep(h2) {
  font-size: 14px;
}
.traffic-markdown :deep(h3) {
  font-size: 12px;
}
.traffic-markdown :deep(ul),
.traffic-markdown :deep(ol) {
  margin: 6px 0 8px;
  padding-left: 19px;
}
.traffic-markdown :deep(code) {
  padding: 1px 4px;
  border-radius: 3px;
  background: var(--app-surface);
  font:
    10px ui-monospace,
    Consolas,
    monospace;
}
.traffic-markdown :deep(pre) {
  max-width: 100%;
  overflow: auto;
  margin: 7px 0;
  padding: 8px;
  border-radius: 5px;
  background: #111827;
  color: #e5edf7;
  white-space: pre;
}
.traffic-markdown :deep(pre code) {
  padding: 0;
  background: transparent;
  color: inherit;
}
.traffic-markdown :deep(a) {
  color: var(--app-accent);
}
.traffic-markdown :deep(blockquote) {
  margin: 7px 0;
  padding: 5px 8px;
  border-left: 3px solid var(--app-accent);
  background: var(--app-accent-soft);
}
.traffic-markdown :deep(table) {
  display: block;
  max-width: 100%;
  overflow: auto;
  border-collapse: collapse;
}
.traffic-markdown :deep(th),
.traffic-markdown :deep(td) {
  padding: 4px 6px;
  border: 1px solid var(--app-border);
}
.traffic-chat-message.user {
  align-items: flex-end;
}
.traffic-chat-message.user > strong {
  text-align: right;
}
.traffic-chat-message.user > p {
  border-color: var(--app-accent-soft-strong);
  border-radius: 11px 4px 11px 11px;
  background: var(--app-accent-soft);
}
.thinking-message {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 18px 0;
}
.thinking-message span {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: var(--app-muted);
  animation: thinking 1.2s infinite ease-in-out;
}
.thinking-message span:nth-child(2) {
  animation-delay: 0.15s;
}
.thinking-message span:nth-child(3) {
  animation-delay: 0.3s;
}
.ai-result {
  margin-top: 16px;
  padding: 0;
  border: 0;
  border-radius: 0;
  background: transparent;
}
.ai-result h3 {
  margin: 9px 0 14px;
  font-size: 13px;
}
.ai-result section > strong {
  font-size: 11px;
}
.ai-result ul,
.ai-result ol {
  color: var(--app-muted);
  font-size: 11px;
}
.traffic-reference-dialog {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.reference-packet-preview {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 9px;
  padding: 12px;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-soft);
}
.reference-packet-preview > span {
  padding: 3px 6px;
  border-radius: 5px;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  font:
    700 10px ui-monospace,
    Consolas,
    monospace;
}
.reference-packet-preview > strong {
  overflow: hidden;
  color: var(--app-text);
  font:
    11px ui-monospace,
    Consolas,
    monospace;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.reference-packet-preview > small {
  color: var(--app-muted);
  font-size: 11px;
}
.traffic-reference-dialog > label {
  display: flex;
  flex-direction: column;
  gap: 8px;
  color: var(--app-text);
  font-size: 11px;
  font-weight: 600;
}
.traffic-reference-dialog > p {
  margin: 0;
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.6;
}
.traffic-replay-dialog {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding-right: 2px;
}
.replay-authorized-target {
  display: grid;
  grid-template-columns: 76px minmax(220px, 1fr);
  align-items: center;
  gap: 8px 10px;
}
.replay-authorized-target > label {
  color: var(--app-text);
  font-size: 11px;
  font-weight: 600;
}
.replay-authorized-target > small {
  grid-column: 2;
  color: var(--app-muted);
  font-size: 11px;
}
.replay-request-line {
  display: grid;
  grid-template-columns: 116px minmax(0, 1fr);
  gap: 8px;
}
.replay-packet-editor {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 8px;
  color: var(--app-text);
  font-size: 11px;
  font-weight: 600;
}
.replay-packet-editor :deep(textarea) {
  min-height: 210px;
  color: var(--app-text);
  font:
    11px/1.55 ui-monospace,
    SFMono-Regular,
    Consolas,
    monospace;
}
.replay-packet-editor :deep(.el-textarea__inner:focus),
.replay-packet-editor :deep(.el-textarea__inner:focus-visible) {
  /* Let the global Fluent focus ring (bottom accent stroke + border) apply. */
  outline: none;
}
.replay-response {
  overflow: hidden;
  margin-top: 14px;
  border: 1px solid var(--app-border);
  border-radius: 9px;
  background: var(--app-surface-soft);
}
.replay-response > header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--app-border);
  background: var(--app-surface);
}
.replay-response > header > div:first-child {
  display: flex;
  min-width: 0;
  align-items: baseline;
  gap: 8px;
}
.replay-response > header strong {
  color: #2f705a;
  font:
    700 12px ui-monospace,
    SFMono-Regular,
    Consolas,
    monospace;
}
.replay-response > header span {
  color: var(--app-muted);
  font-size: 11px;
}
.replay-response-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  padding: 10px;
}
.replay-response-grid article {
  min-width: 0;
  overflow: hidden;
  border: 1px solid var(--app-border);
  border-radius: 7px;
  background: var(--app-surface);
}
.replay-response-grid h3 {
  margin: 0;
  padding: 7px 9px;
  border-bottom: 1px solid var(--app-border);
  color: var(--app-muted);
  font-size: 11px;
}
.replay-response-grid h3 small {
  margin-left: 5px;
  color: var(--app-muted);
  font-weight: 400;
}
.replay-response-grid pre {
  height: clamp(180px, 28vh, 340px);
  min-height: 180px;
  max-height: none;
  margin: 0;
  overflow: auto;
  padding: 9px;
  color: var(--app-text);
  font:
    11px/1.55 ui-monospace,
    SFMono-Regular,
    Consolas,
    monospace;
  white-space: pre-wrap;
  word-break: break-word;
}
.replay-response-packet {
  min-width: 0;
  background: transparent;
}
.replay-response-packet h3 {
  margin: 0;
  padding: 8px 12px;
  border-bottom: 1px solid var(--app-border);
  color: var(--app-muted);
  font-size: 11px;
}
.replay-response-packet h3 small {
  margin-left: 5px;
  color: var(--app-muted);
  font-weight: 400;
}
.replay-response-packet pre {
  height: clamp(180px, 28vh, 340px);
  min-height: 180px;
  max-height: none;
  margin: 0;
  overflow: auto;
  padding: 12px;
  color: var(--app-text);
  background: transparent;
  font:
    11px/1.55 ui-monospace,
    SFMono-Regular,
    Consolas,
    monospace;
  white-space: pre-wrap;
  word-break: break-word;
}
.ai-composer {
  flex: none;
  padding: 12px;
  border-top: 1px solid var(--app-border);
  background: var(--app-surface-soft);
}
.ai-composer > .el-button {
  width: 100%;
  border-radius: 8px;
}
.ai-composer > small {
  display: block;
  margin-top: 8px;
  color: var(--app-muted);
  font-size: 11px;
  text-align: center;
}
.ai-quick-analyze {
  min-height: 32px;
  height: 32px;
  font-size: 11px;
}
.traffic-chat-composer {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 34px;
  align-items: end;
  gap: 8px;
  margin-top: 9px;
  padding: 7px 7px 7px 10px;
  border: 1px solid var(--app-border);
  border-radius: 10px;
  background: var(--app-surface);
}
.traffic-chat-composer:focus-within {
  border-color: var(--app-accent);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--app-accent) 8%, transparent);
}
.traffic-chat-composer textarea {
  width: 100%;
  min-height: 42px;
  max-height: 110px;
  resize: vertical;
  padding: 2px 0;
  border: 0;
  outline: 0;
  background: transparent;
  color: var(--app-text);
  font-family: inherit;
  font-size: 12px;
  line-height: 1.5;
}
.traffic-chat-composer textarea::placeholder {
  color: var(--app-muted);
}
.traffic-chat-composer > button {
  display: grid;
  width: 34px;
  height: 34px;
  place-items: center;
  border: 0;
  border-radius: 8px;
  background: var(--app-accent);
  color: white;
  cursor: pointer;
}
.traffic-chat-composer > button:disabled {
  border: 1px solid var(--app-border-strong);
  background: var(--app-surface-soft);
  color: var(--app-text);
  cursor: default;
}
.ai-mode-row {
  margin-bottom: 10px;
  padding: 0;
  border: 0;
  background: transparent;
}
.ai-mode-row strong {
  color: var(--app-text);
}
.ai-mode-row small {
  color: var(--app-muted);
  font-size: 11px;
}
.ai-risk {
  font-size: 11px;
}

/* Fluent WinUI 3: compact controls, layered panes and restrained selection. */
.codex-traffic-page {
  --traffic-control-height: 32px;
  --traffic-control-radius: 4px;
  --traffic-card-radius: 8px;
  --traffic-pane-divider: 1px solid var(--app-border);
  height: 100%;
  overflow: hidden;
  font-family: "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
}
.codex-traffic-toolbar {
  min-height: 32px;
  padding: 0;
  align-items: flex-start;
  border: 0;
  background: transparent;
  box-shadow: none;
}
.traffic-workspace-title > strong {
  font-family: var(--fluent-font-display);
  font-size: var(--page-title-size, 18px);
  font-weight: var(--fluent-weight-semibold, 600);
  line-height: 1.3;
  letter-spacing: 0;
}
.codex-toolbar-actions {
  align-items: center;
  gap: 8px;
}
.codex-toolbar-actions :deep(.el-button + .el-button) {
  margin-left: 0;
}
.codex-traffic-page :deep(.el-button) {
  min-height: var(--traffic-control-height);
  padding: 0 12px;
  border-radius: var(--traffic-control-radius);
  border-color: var(--app-border-strong);
  background: var(--app-surface-strong);
  color: var(--app-text);
  box-shadow: 0 1px 1px color-mix(in srgb, var(--app-text) 5%, transparent);
  font-weight: 500;
}
.codex-traffic-page :deep(.el-button:hover) {
  border-color: var(--app-border-strong);
  background: var(--app-surface-soft);
  color: var(--app-text);
}
.codex-traffic-page :deep(.el-button:active) {
  transform: translateY(1px);
  box-shadow: none;
}
.codex-traffic-page :deep(.el-button--primary) {
  border-color: var(--app-accent);
  background: var(--app-accent);
  color: #fff;
}
.codex-traffic-page :deep(.el-button--primary:hover) {
  border-color: var(--app-accent);
  background: color-mix(in srgb, var(--app-accent) 88%, white);
  color: #fff;
}
.codex-traffic-page :deep(.packet-copilot-button) {
  border-color: var(--fluent-action-bg) !important;
  background: var(--fluent-action-bg) !important;
  color: var(--fluent-action-fg) !important;
}
.codex-traffic-page :deep(.packet-copilot-button:hover) {
  border-color: var(--app-accent) !important;
  background: color-mix(in srgb, var(--app-accent) 88%, white) !important;
  color: #fff !important;
}
.codex-traffic-page :deep(.packet-copilot-button .el-icon),
.codex-traffic-page :deep(.packet-copilot-button span) {
  color: inherit !important;
}
.codex-traffic-page :deep(.el-button.is-disabled) {
  opacity: 1;
  border-color: var(--app-border-strong);
  background: var(--app-surface-soft);
  color: var(--app-text);
}
.codex-traffic-page :deep(.el-button--primary.is-disabled) {
  border-color: var(--app-border-strong);
  background: var(--app-surface-soft);
  color: var(--app-text);
}
.codex-traffic-page :deep(.el-button.is-text),
.codex-traffic-page :deep(.el-button.is-link) {
  min-height: 32px;
  padding: 0 8px;
  border-color: transparent;
  background: transparent;
  box-shadow: none;
}
.codex-traffic-page :deep(.el-input__wrapper),
.codex-traffic-page :deep(.el-select__wrapper),
.codex-traffic-page :deep(.el-textarea__inner) {
  min-height: var(--traffic-control-height);
  border-radius: var(--traffic-control-radius);
  background: var(--app-surface-strong);
  box-shadow: 0 0 0 1px var(--app-border-strong) inset;
}
.codex-traffic-page :deep(.el-input__wrapper:hover),
.codex-traffic-page :deep(.el-select__wrapper:hover),
.codex-traffic-page :deep(.el-textarea__inner:hover) {
  box-shadow: 0 0 0 1px var(--app-muted) inset;
}
.codex-traffic-page :deep(.el-input__wrapper.is-focus),
.codex-traffic-page :deep(.el-select__wrapper.is-focused),
.codex-traffic-page :deep(.el-textarea__inner:focus) {
  box-shadow:
    0 -2px 0 var(--app-accent) inset,
    0 0 0 1px var(--app-border-strong) inset;
}
.codex-traffic-workbench {
  gap: 0;
  border: 1px solid var(--app-border);
  border-radius: var(--traffic-card-radius);
  background: var(--app-bg);
  box-shadow: none;
}
.codex-traffic-page :deep(.el-button--danger),
.codex-traffic-page :deep(.el-button--danger.is-link) {
  border-color: var(--fluent-danger-bg, #c50f1f);
  background: var(--fluent-danger-bg, #c50f1f);
  color: #fff;
}
.codex-traffic-page :deep(.el-button--danger:hover),
.codex-traffic-page :deep(.el-button--danger.is-link:hover) {
  border-color: var(--fluent-danger-hover-bg, #a80000);
  background: var(--fluent-danger-hover-bg, #a80000);
  color: #fff;
}

/* text/link 风格 danger 按钮保持透明背景，避免 hover 时一片全红 */
.codex-traffic-page :deep(.el-button--danger.is-text),
.codex-traffic-page :deep(.el-button--danger.is-link) {
  border-color: transparent;
  background: transparent;
  color: var(--fluent-danger-bg, #c50f1f);
}
.codex-traffic-page :deep(.el-button--danger.is-text:hover),
.codex-traffic-page :deep(.el-button--danger.is-link:hover) {
  border-color: transparent;
  background: rgba(197, 15, 31, 0.1);
  color: var(--fluent-danger-hover-bg, #a80000);
}
.traffic-session-rail,
.packet-editor-pane,
.ai-thread-pane {
  min-width: 0;
  background: var(--app-surface);
}
.traffic-session-rail {
  border-right: var(--traffic-pane-divider);
}
.packet-editor-pane {
  border-right: var(--traffic-pane-divider);
}
.traffic-session-rail > .session-rail-header,
.traffic-detail-head,
.ai-thread-header {
  min-height: 52px;
  background: var(--app-surface-soft);
  border-bottom: var(--traffic-pane-divider);
}
.session-rail-header :deep(.el-input__wrapper) {
  border-radius: var(--traffic-control-radius);
}
.session-rail-header :deep(.traffic-session-filter .el-input__wrapper) {
  min-height: var(--traffic-control-height);
  height: var(--traffic-control-height);
  padding: 0 9px;
  border: 0;
  border-radius: var(--traffic-control-radius);
  background: var(--app-surface-strong);
  box-shadow: 0 0 0 1px var(--app-border) inset !important;
}
.session-rail-header :deep(.traffic-session-filter .el-input__wrapper:hover) {
  box-shadow: 0 0 0 1px var(--app-border-strong) inset !important;
}
.session-rail-header
  :deep(.traffic-session-filter .el-input__wrapper.is-focus) {
  box-shadow:
    inset 0 0 0 1px var(--app-border),
    inset 0 -2px 0 var(--app-accent) !important;
}
.session-rail-header :deep(.traffic-session-filter .el-input__prefix) {
  margin-right: 7px;
  color: var(--app-muted);
}
.session-rail-header :deep(.traffic-session-filter .el-input__prefix-inner) {
  font-size: 14px;
}
.session-rail-header :deep(.traffic-session-filter .el-input__inner) {
  height: var(--traffic-control-height);
  color: var(--app-text);
  font-size: 13px;
  line-height: var(--traffic-control-height);
}
.traffic-row-wrap {
  margin: 2px 6px;
  border-radius: var(--traffic-control-radius);
}
.traffic-row {
  min-height: 64px;
  border-radius: var(--traffic-control-radius);
  transition: background-color 100ms ease;
}
.traffic-row:hover {
  background: var(--app-surface-soft);
}
.traffic-row.active {
  position: relative;
  background: var(--app-accent-soft);
  color: var(--app-text);
}
.traffic-row::before {
  content: "";
  position: absolute;
  top: 50%;
  left: 0;
  width: 3px;
  height: 44px;
  transform: translateY(-50%) scaleY(0.3);
  opacity: 0;
  border-radius: 999px;
  background: var(--app-accent, #2563eb);
  transition:
    transform 0.22s cubic-bezier(0.1, 0.9, 0.2, 1),
    opacity 0.16s ease;
  pointer-events: none;
}
.traffic-row.active::before {
  opacity: 1;
  transform: translateY(-50%) scaleY(1);
}
.traffic-row-wrap.marked:not(.active) .traffic-row {
  background: var(--app-surface-soft);
}
.traffic-row-mark,
.traffic-row-delete {
  border-radius: var(--traffic-control-radius);
}
.packet-tabs,
.inline-replay-tabs {
  height: 40px;
  gap: 8px;
  padding: 4px 10px;
  background: var(--app-surface-soft);
}
.packet-tabs button,
.inline-replay-tabs button {
  min-width: 76px;
  padding: 0 12px;
  border: 0;
  border-radius: var(--traffic-control-radius);
  color: var(--app-muted);
}
.packet-tabs button {
  justify-content: center;
  font-size: 12px !important;
}
.packet-tabs button:hover,
.inline-replay-tabs button:hover {
  background: var(--app-surface);
  color: var(--app-text);
}
.packet-tabs button.active,
.inline-replay-tabs button.active {
  background: var(--app-surface-strong);
  color: var(--app-text);
  font-weight: 600;
}
.packet-tabs button.active::after {
  right: 18px;
  bottom: 1px;
  left: 18px;
  height: 2px;
}
.inline-replay-tabs button.active {
  border-bottom: 0;
  box-shadow: none;
}
.packet-editor {
  padding: 12px;
  background: var(--app-bg);
}
.reference-packet-preview,
.replay-response,
.replay-response-grid article {
  border-radius: var(--traffic-card-radius);
  border-color: var(--app-border);
  background: var(--app-surface-strong);
  box-shadow: 0 1px 2px color-mix(in srgb, var(--app-text) 5%, transparent);
  transition:
    border-color 120ms ease,
    background-color 120ms ease;
}
.reference-packet-preview:hover {
  border-color: var(--app-border-strong);
}
.ai-thread-body {
  background: var(--app-surface);
}
.traffic-chat-message > p {
  border-radius: 4px 8px 8px;
  background: var(--app-surface-soft);
}
.traffic-chat-message.user > p {
  border-radius: 8px 4px 8px 8px;
  background: var(--app-accent-soft);
}
.traffic-chat-composer {
  border-radius: var(--traffic-card-radius);
  background: var(--app-surface-strong);
}
.traffic-chat-composer > button {
  border-radius: var(--traffic-control-radius);
}
.ai-composer {
  background: var(--app-surface-soft);
}
.capture-filter-table {
  border-radius: var(--traffic-card-radius);
  background: var(--app-surface-strong);
}
.capture-filter-table :deep(.el-table) {
  font-size: 14px;
}
.capture-filter-table :deep(.el-table th.el-table__cell) {
  font-size: 14px;
  font-weight: 600;
}
.capture-filter-table :deep(.el-table td.el-table__cell .cell) {
  font-size: 13px;
}
.capture-filter-table :deep(.el-tag) {
  font-size: 11px;
}
.capture-filter-table :deep(.el-button.is-link) {
  font-size: 12px;
}
.codex-traffic-page :deep(.el-table),
.codex-traffic-page :deep(.el-table tr),
.codex-traffic-page :deep(.el-table th.el-table__cell),
.codex-traffic-page :deep(.el-table td.el-table__cell) {
  background: transparent;
  color: var(--app-text);
}
.codex-traffic-page :deep(.el-table__row:hover > td.el-table__cell) {
  background: var(--app-surface-soft);
}

:global(.traffic-tooltip.el-popper) {
  max-width: min(320px, calc(100vw - 24px));
  padding: 7px 10px !important;
  border: 1px solid var(--app-hover-popup-border) !important;
  border-radius: 6px !important;
  background: var(--app-hover-popup-bg) !important;
  color: var(--app-hover-popup-text) !important;
  font-size: 11px !important;
  line-height: 1.5 !important;
  white-space: normal !important;
  overflow-wrap: anywhere;
  box-shadow: 0 8px 24px rgba(25, 38, 32, 0.2) !important;
}
:global(.traffic-tooltip--wide.el-popper) {
  max-width: min(360px, calc(100vw - 24px));
  padding: 9px 11px !important;
  font-size: 12px !important;
  line-height: 1.6 !important;
}
:global(.traffic-tooltip .el-popper__arrow) {
  display: none !important;
}
@keyframes thinking {
  0%,
  60%,
  100% {
    opacity: 0.35;
    transform: translateY(0);
  }
  30% {
    opacity: 1;
    transform: translateY(-2px);
  }
}
@media (min-width: 1800px) {
  .codex-traffic-workbench {
    grid-template-columns: 340px minmax(560px, 1fr) 390px;
  }
}
@media (max-width: 1400px) {
  .codex-traffic-workbench {
    grid-template-columns: 270px minmax(0, 1fr) 300px;
  }
}
@media (max-width: 1250px) {
  .codex-traffic-workbench {
    grid-template-columns: 250px minmax(0, 1fr);
  }
  .traffic-points-pane {
    display: none;
  }
}
@media (max-width: 1120px) {
  .capture-browser-state {
    display: none;
  }
}
@media (max-width: 980px) {
  .traffic-workspace-title > code,
  .capture-browser-option {
    display: none;
  }
  .capture-filter-editor {
    grid-template-columns: 1fr 1fr;
  }
  .capture-filter-editor :deep(.el-input) {
    grid-column: 1/-1;
  }
}
@media (max-width: 760px) {
  .replay-response-grid {
    grid-template-columns: 1fr;
  }
  .replay-authorized-target {
    grid-template-columns: 1fr;
  }
  .replay-authorized-target > small {
    grid-column: 1;
  }
}
</style>
