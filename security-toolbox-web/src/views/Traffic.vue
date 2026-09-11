<script setup lang="ts">
// @ts-nocheck
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  ArrowDown,
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
import { severityLabel } from "../utils/aiPresentation";
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

interface FuzzHit {
  payload: string;
  statusCode?: number;
  reason?: string;
  durationMs?: number;
  responseBytes?: number;
  digestPrefix?: string;
  effectiveStatus?: number;
  changed?: boolean;
}

interface FuzzResult {
  payloadCount?: number;
  url?: string;
  results?: FuzzHit[];
  engine?: "ZAP" | "LOOP";
}

const fuzzForm = ref<ReplayForm>({
  method: "GET",
  url: "",
  headers: "",
  body: "",
});
type FuzzCombinationType =
  | "SNIPER"
  | "BATTERING_RAM"
  | "PITCHFORK"
  | "PITCHFORK_LONGEST"
  | "CLUSTER_BOMB"
  | "LONGEST"
  | "SHORTEST"
  | "CARTESIAN";

const FUZZ_ATTACK_TYPES = [
  {
    value: "SNIPER",
    label: "狙击手 (Sniper)",
    shortDesc: "单字典，逐位置依次测试",
    desc: "单字典：依次对每个占位符注入测试，其余占位符保持原始基础值不变",
  },
  {
    value: "BATTERING_RAM",
    label: "攻城槌 (Battering ram)",
    shortDesc: "单字典，所有位置同时替换",
    desc: "单字典：所有占位符在单次请求中同时替换为同一个 payload",
  },
  {
    value: "PITCHFORK",
    label: "草叉 (Pitchfork - 最短对齐)",
    shortDesc: "多字典并发，按行同步推进",
    desc: "多字典：每个占位符独立配置字典，按行同步取值，达到最短字典长度时结束",
  },
  {
    value: "PITCHFORK_LONGEST",
    label: "草叉 (Pitchfork - 最长对齐)",
    shortDesc: "多字典并发，短字典复用末项",
    desc: "多字典：每个占位符独立配置字典，按行同步取值，短字典自动复用最后一行",
  },
  {
    value: "CLUSTER_BOMB",
    label: "集束炸弹 (Cluster bomb)",
    shortDesc: "多字典笛卡尔积全组合",
    desc: "多字典：每个占位符独立配置字典，进行全排列笛卡尔积组合测试",
  },
] as const;

const FUZZ_PAYLOAD_PRESETS = [
  {
    label: "SQL 注入探测 (SQLi)",
    payloads: [
      "'",
      "\"",
      "' OR '1'='1",
      "\" OR \"1\"=\"1",
      "' UNION SELECT NULL--",
      "1' ORDER BY 1--",
      "admin'--",
      "1 AND 1=1",
      "1 AND 1=2",
      "sleep(5)#",
    ],
  },
  {
    label: "XSS 跨站脚本探测",
    payloads: [
      "<scr" + "ipt>alert(1)</scr" + "ipt>",
      "\"><img src=x onerror=alert(1)>",
      "<svg onload=alert(1)>",
      "javascript:alert(1)",
      "'><scr" + "ipt>alert(document.domain)</scr" + "ipt>",
      "<iframe src=\"javascript:alert(1)\">",
    ],
  },
  {
    label: "路径穿越 / LFI 探测",
    payloads: [
      "../",
      "../../../../etc/passwd",
      "..\\..\\..\\..\\windows\\win.ini",
      "/etc/passwd",
      "C:\\boot.ini",
      "%2e%2e%2f%2e%2e%2fetc/passwd",
    ],
  },
  {
    label: "命令执行注入探测 (RCE)",
    payloads: [
      ";id",
      "|id",
      "`id`",
      "$(id)",
      "& whoami",
      "| whoami",
    ],
  },
  {
    label: "常见弱口令 / 凭证",
    payloads: [
      "admin",
      "123456",
      "password",
      "root",
      "12345678",
      "admin123",
      "guest",
      "111111",
    ],
  },
  {
    label: "布尔与边界逻辑值",
    payloads: [
      "true",
      "false",
      "1",
      "0",
      "-1",
      "null",
      "undefined",
      "NaN",
    ],
  },
];

const fuzzPayloadGroups = ref<Record<string, string>>({});
const fuzzCombination = ref<FuzzCombinationType>("SNIPER");
const fuzzSharedPayload = ref("test\ndebug\nadmin");
const activeFuzzGroup = ref("");

const isSinglePayloadMode = computed(
  () => fuzzCombination.value === "SNIPER" || fuzzCombination.value === "BATTERING_RAM",
);

const currentAttackType = computed(() =>
  FUZZ_ATTACK_TYPES.find((item) => item.value === fuzzCombination.value) || FUZZ_ATTACK_TYPES[0],
);

const numbersGenDialogVisible = ref(false);
const numbersGenForm = ref({
  from: 1,
  to: 20,
  step: 1,
});

const fuzzVariables = computed(() => {
  const found = new Set<string>();
  const scan = (value: string | undefined) => {
    const text = String(value || "");
    const re = /§([^§\r\n]+)§/g;
    let m;
    while ((m = re.exec(text))) {
      const name = m[1].trim();
      if (name) found.add(name);
    }
  };
  scan(fuzzForm.value.url);
  scan(fuzzRawPacket.value);
  if (fuzzForm.value.headers) scan(fuzzForm.value.headers);
  if (fuzzForm.value.body) scan(fuzzForm.value.body);
  return [...found];
});

function getFuzzPayload(name: string): string {
  if (fuzzPayloadGroups.value[name] === undefined) {
    fuzzPayloadGroups.value[name] = fuzzSharedPayload.value || "test\ndebug\nadmin";
  }
  return fuzzPayloadGroups.value[name];
}

const estimatedFuzzRequests = computed(() => {
  const vars = fuzzVariables.value;
  if (!vars.length) return 0;
  if (isSinglePayloadMode.value) {
    const lines = fuzzSharedPayload.value
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    const count = lines.length;
    if (count === 0) return 0;
    if (fuzzCombination.value === "BATTERING_RAM") {
      return count;
    }
    // SNIPER:
    return vars.length * count;
  } else {
    const counts = vars.map((name) => {
      const text = getFuzzPayload(name);
      return text
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean).length;
    });
    if (counts.some((c) => c === 0)) {
      if (fuzzCombination.value === "PITCHFORK" || fuzzCombination.value === "SHORTEST") return 0;
    }
    if (fuzzCombination.value === "PITCHFORK" || fuzzCombination.value === "SHORTEST") {
      return Math.min(...counts);
    }
    if (fuzzCombination.value === "PITCHFORK_LONGEST" || fuzzCombination.value === "LONGEST") {
      return Math.max(...counts);
    }
    // CLUSTER_BOMB / CARTESIAN:
    return counts.reduce((acc, curr) => acc * curr, 1);
  }
});

function ensureFuzzGroups() {
  const vars = fuzzVariables.value;
  for (const name of vars) {
    if (fuzzPayloadGroups.value[name] === undefined) {
      fuzzPayloadGroups.value[name] = fuzzSharedPayload.value || "test\ndebug\nadmin";
    }
  }
  if (vars.length && (!activeFuzzGroup.value || !vars.includes(activeFuzzGroup.value))) {
    activeFuzzGroup.value = vars[0];
  }
}

const totalMultiPayloadLines = computed(() => {
  return fuzzVariables.value.reduce((sum, name) => {
    const text = getFuzzPayload(name);
    return sum + (text || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean).length;
  }, 0);
});

function handleImportCommand(cmd: string) {
  if (cmd === "clipboard") {
    importFuzzFromClipboard();
  } else if (cmd === "file") {
    pickFuzzFile();
  }
}
const fuzzFileInput = ref<HTMLInputElement>();
const fuzzUrlInput = ref();
const fuzzHeadersInput = ref();
const fuzzBodyInput = ref();
const fuzzRawInput = ref();
const fuzzRawPacket = ref("");
const fuzzBackdropRef = ref<HTMLElement>();
const fuzzUrlBackdropRef = ref<HTMLElement>();

function highlightPlaceholders(text: string): string {
  if (!text) return "";
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  const marked = escaped.replace(
    /§([^§\r\n]+)§/g,
    '<mark class="fuzz-placeholder-mark">§$1§</mark>',
  );
  return marked.endsWith("\n") ? marked + " " : marked;
}

const highlightedRawPacketHtml = computed(() => {
  return highlightPlaceholders(fuzzRawPacket.value);
});

const highlightedUrlHtml = computed(() => {
  return highlightPlaceholders(fuzzForm.value.url);
});

function syncRawEditorScroll() {
  const textarea = fuzzRawInput.value?.$el?.querySelector("textarea") as HTMLTextAreaElement | null;
  if (textarea && fuzzBackdropRef.value) {
    fuzzBackdropRef.value.scrollTop = textarea.scrollTop;
    fuzzBackdropRef.value.scrollLeft = textarea.scrollLeft;
  }
}

function syncUrlEditorScroll() {
  const input = fuzzUrlInput.value?.$el?.querySelector("input") as HTMLInputElement | null;
  if (input && fuzzUrlBackdropRef.value) {
    fuzzUrlBackdropRef.value.scrollLeft = input.scrollLeft;
  }
}

watch(fuzzRawPacket, () => {
  nextTick(syncRawEditorScroll);
});

watch(fuzzVariables, () => {
  ensureFuzzGroups();
}, { immediate: true });

watch(
  () => fuzzForm.value.url,
  () => {
    nextTick(syncUrlEditorScroll);
  },
);
const fuzzRunning = ref(false);
const fuzzEngine = ref<"auto" | "zap" | "loop">("auto");
const fuzzResult = ref<FuzzResult>();
const fuzzError = ref("");
const fuzzPlaceholderHint = "\u00a7name\u00a7（在 URL、请求头或请求体中标记模糊点，每个 payload 会替换该占位符逐一重放）";

const sessionSelection = ref<Set<number | string>>(new Set());
const selectedSessionCount = computed(() => sessionSelection.value.size);
const multiSelectMode = ref(false);
const fuzzBatchWithSelection = ref(false);
const fuzzBatchResults = ref<Record<string, FuzzResult>>({});
const fuzzFocusPacketId = ref<number | string>();

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
const sessionDropdownRefs = new Map<
  string,
  { handleClose?: () => void }
>();
let openSessionDropdownId = "";
function setSessionDropdownRef(id: string, el: unknown) {
  if (el) sessionDropdownRefs.set(id, el as { handleClose?: () => void });
  else sessionDropdownRefs.delete(id);
}
function onSessionDropdownVisible(visible: boolean, id: string) {
  if (visible) {
    if (openSessionDropdownId && openSessionDropdownId !== id) {
      sessionDropdownRefs.get(openSessionDropdownId)?.handleClose?.();
    }
    openSessionDropdownId = id;
  } else if (openSessionDropdownId === id) {
    openSessionDropdownId = "";
  }
}

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
  const fuzzForPacket = fuzzBatchResults.value[String(packet.id)];
  if (fuzzForPacket?.results?.length) {
    const changed = fuzzForPacket.results.filter((hit) => hit.changed).length;
    points.push({
      label: "模糊命中",
      badge: changed ? `${changed} 个变更` : "全部同基线",
      value: changed
        ? `本会话最近一轮模糊有 ${changed}/${fuzzForPacket.results.length} 个响应相对基线变化，建议在模糊器逐条重放核实真反射。`
        : `本会话最近一轮模糊 ${fuzzForPacket.results.length} 次响应均与基线一致。`,
      level: changed ? "warn" : "ok",
    });
  }
  const levelPriority: Record<string, number> = {
    ok: 1,
    info: 2,
    warn: 3,
  };
  return points.sort(
    (a, b) => (levelPriority[a.level] ?? 99) - (levelPriority[b.level] ?? 99)
  );
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

async function deleteSessionAction(item: TrafficSession) {
  const targets = actionSessions();
  if (targets.length > 1) {
    await deleteSelectedSessions(targets);
    return;
  }
  await deleteSession(item);
}

async function deleteSelectedSessions(targets: TrafficSession[]) {
  if (!targets.length || clearingSessions.value) return;
  const label =
    targets.length === 1
      ? targets[0].url || `#${targets[0].id}`
      : `所选 ${targets.length} 条流量记录`;
  try {
    await ElMessageBox.confirm(
      `确定删除${targets.length === 1 ? "这条" : "这"}流量记录吗？\n${label}`,
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
  clearingSessions.value = true;
  try {
    const ids = targets.map((item) => item.id);
    for (const id of ids) {
      await api.delete(`/traffic/sessions/${encodeURIComponent(String(id))}`);
    }
    const idSet = new Set(ids);
    sessions.value = sessions.value.filter((session) => !idSet.has(session.id));
    if (selectedId.value !== undefined && idSet.has(selectedId.value)) {
      selectedId.value = sessions.value[0]?.id;
      suggestion.value = undefined;
    }
    sessionSelection.value = new Set();
    const nextChats = { ...trafficChats.value };
    ids.forEach((id) => delete nextChats[String(id)]);
    trafficChats.value = nextChats;
    persistTrafficChats();
    status.value = {
      ...status.value,
      capturedCount: Math.max(
        0,
        (status.value.capturedCount || 0) - ids.length,
      ),
    };
    ElMessage.success(`已删除 ${ids.length} 条流量记录`);
  } catch (error) {
    ElMessage.error(readableError(error));
  } finally {
    clearingSessions.value = false;
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

let longPressTimer: number | undefined;
let suppressClickId: number | string | undefined;
let suppressClickUntil = 0;
function cancelLongPress() {
  if (longPressTimer) window.clearTimeout(longPressTimer);
  longPressTimer = undefined;
}
function beginRowPress(item: TrafficSession, event?: PointerEvent) {
  cancelLongPress();
  if (event && event.button !== 0) return;
  if (multiSelectMode.value) return;
  longPressTimer = window.setTimeout(() => enterMultiSelect(item), 520);
}

function enterMultiSelect(item: TrafficSession) {
  if (multiSelectMode.value) return;
  multiSelectMode.value = true;
  const next = new Set(sessionSelection.value);
  next.add(item.id);
  sessionSelection.value = next;
  selectedId.value = item.id;
  suppressClickId = item.id;
  suppressClickUntil = Date.now() + 320;
}

function handleSessionClick(item: TrafficSession) {
  cancelLongPress();
  if (suppressClickId === item.id || Date.now() < suppressClickUntil) {
    suppressClickId = undefined;
    suppressClickUntil = 0;
    return;
  }
  if (multiSelectMode.value) {
    toggleSessionSelection(item);
    return;
  }
  selectSession(item);
}

function isSessionSelected(id: number | string) {
  return sessionSelection.value.has(id);
}

function toggleSessionSelection(item: TrafficSession) {
  const next = new Set(sessionSelection.value);
  if (next.has(item.id)) next.delete(item.id);
  else next.add(item.id);
  sessionSelection.value = next;
  selectedId.value = item.id;
}

function toggleMultiSelectMode() {
  multiSelectMode.value = !multiSelectMode.value;
  suppressClickUntil = Date.now() + 260;
  if (multiSelectMode.value) {
    if (!sessionSelection.value.size && selected.value) {
      sessionSelection.value = new Set([selected.value.id]);
    }
  } else {
    sessionSelection.value = new Set();
  }
}

function exitMultiSelect() {
  if (!multiSelectMode.value) return;
  multiSelectMode.value = false;
  sessionSelection.value = new Set();
}

function onWindowPointerDown(event: PointerEvent) {
  if (!multiSelectMode.value) return;
  const target = event.target as HTMLElement | null;
  if (!target) return;
  if (target.closest && target.closest(".traffic-session-rail")) return;
  if (target.closest && target.closest(".el-popper, .el-dropdown-menu")) return;
  exitMultiSelect();
}

function pickSessionForContextMenu(item: TrafficSession) {
  if (!multiSelectMode.value) {
    if (!sessionSelection.value.has(item.id)) {
      sessionSelection.value = new Set([item.id]);
    }
  }
  selectedId.value = item.id;
}

function actionSessions(): TrafficSession[] {
  if (sessionSelection.value.size) {
    const selected = [...sessionSelection.value];
    return sessions.value.filter((item) => selected.includes(item.id));
  }
  return selected.value ? [selected.value] : [];
}

async function sendSelectedToReplay() {
  const targets = actionSessions();
  if (!targets.length) return ElMessage.warning("请先选择流量会话");
  replayPreparing.value = true;
  try {
    for (const packet of targets) {
      if (replayTabs.value.some((tab) => tab.sourcePacketId === packet.id)) {
        continue;
      }
      const form = {
        method: (packet.method || "GET").toUpperCase(),
        url: packetRequestUrl(packet),
        headers: editableRequestHeaders(packet.requestHeaders),
        body: editablePacketValue(packet.requestBody, "body"),
      };
      createReplayTab(form, composeReplayPacket(form.headers, form.body), packet.id);
    }
    ElMessage.success(`已创建 ${replayTabs.value.length} 个重放请求`);
  } finally {
    replayPreparing.value = false;
  }
}

function openFuzz() {
  const targets = actionSessions();
  if (!targets.length) return ElMessage.warning("请先选择流量会话");
  fuzzBatchWithSelection.value = targets.length > 1;
  sessionSelection.value = new Set(targets.map((item) => item.id));
  const focus = targets[targets.length - 1];
  selectedId.value = focus.id;
  fuzzFocusPacketId.value = focus.id;
  fuzzForm.value = {
    method: (focus.method || "GET").toUpperCase(),
    url: packetRequestUrl(focus),
    headers: editableRequestHeaders(focus.requestHeaders),
    body: editablePacketValue(focus.requestBody, "body"),
  };
  fuzzRawPacket.value = formatRequestPacket(focus);
  fuzzResult.value = fuzzBatchResults.value[String(focus.id)];
  fuzzError.value = "";
  packetTab.value = "fuzz";
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

function hasFuzzPlaceholder(value: string | undefined) {
  return /§[^§]+§/.test(String(value || ""));
}

/** 把完整 HTTP 原始请求报文拆分为 method / url / headers / body。 */
function parseRawFuzzPacket(raw: string) {
  const text = String(raw || "").replace(/\r\n/g, "\n");
  const firstBreak = text.indexOf("\n\n");
  const headSection = firstBreak === -1 ? text : text.slice(0, firstBreak);
  const bodySection = firstBreak === -1 ? "" : text.slice(firstBreak + 2);
  const lines = headSection.split("\n");
  const requestLine = lines.length ? lines[0] : "";
  const [method, requestTarget] = requestLine.trim().split(/\s+/);
  let headers = lines.slice(1).join("\r\n");
  if (!headers.trim()) headers = "";
  let body = bodySection;
  return { method, requestTarget, headers, body };
}

function splitFuzzPacket() {
  if (!fuzzForm.value) return;
  const parts = splitReplayPacket(
    composeReplayPacket(fuzzForm.value.headers, fuzzForm.value.body),
  );
  fuzzForm.value.headers = parts.headers;
  fuzzForm.value.body = parts.body;
}

function currentFuzzGroupName(): string | undefined {
  if (activeFuzzGroup.value && fuzzVariables.value.includes(activeFuzzGroup.value)) {
    return activeFuzzGroup.value;
  }
  if (fuzzVariables.value.length) return fuzzVariables.value[0];
  return undefined;
}

function appendToFuzzGroup(text: string) {
  const lines = text
    .replace(/^\uFEFF/, "")
    .split(/\r\n|\r|\n/)
    .map((item) => item.trim())
    .filter(Boolean);
  if (!lines.length) return false;
  if (isSinglePayloadMode.value) {
    const current = fuzzSharedPayload.value || "";
    fuzzSharedPayload.value = [current, ...lines].filter(Boolean).join("\n");
    return true;
  }
  const name = currentFuzzGroupName();
  if (!name) return false;
  const current = getFuzzPayload(name) || "";
  fuzzPayloadGroups.value[name] = [current, ...lines].filter(Boolean).join("\n");
  return true;
}

function clearFuzzGroups(clearAll = false) {
  if (isSinglePayloadMode.value || clearAll) {
    if (isSinglePayloadMode.value) {
      fuzzSharedPayload.value = "";
    }
    for (const name of fuzzVariables.value) {
      fuzzPayloadGroups.value[name] = "";
    }
    ElMessage.success("已清空所有 Payload 字典");
  } else {
    const name = currentFuzzGroupName();
    if (name) {
      fuzzPayloadGroups.value[name] = "";
      ElMessage.success(`已清空 §${name}§ 的 Payload 字典`);
    } else {
      for (const v of fuzzVariables.value) {
        fuzzPayloadGroups.value[v] = "";
      }
      ElMessage.success("已清空所有 Payload 字典");
    }
  }
}

function applyFuzzPreset(payloads: readonly string[]) {
  const text = payloads.join("\n");
  if (isSinglePayloadMode.value) {
    fuzzSharedPayload.value = text;
    ElMessage.success(`已载入 ${payloads.length} 行预设 Payload 到通用字典`);
  } else {
    const name = currentFuzzGroupName();
    if (!name) {
      ElMessage.warning("请先在请求中标记一个占位符");
      return;
    }
    fuzzPayloadGroups.value[name] = text;
    ElMessage.success(`已向 §${name}§ 载入 ${payloads.length} 行预设 Payload`);
  }
}

function applyNumbersGenerator() {
  const list: string[] = [];
  const from = Number(numbersGenForm.value.from) || 1;
  const to = Number(numbersGenForm.value.to) || 20;
  const step = Math.max(1, Number(numbersGenForm.value.step) || 1);
  for (let i = from; i <= to && list.length < 200; i += step) {
    list.push(String(i));
  }
  const text = list.join("\n");
  if (isSinglePayloadMode.value) {
    fuzzSharedPayload.value = text;
  } else {
    const name = currentFuzzGroupName();
    if (name) {
      fuzzPayloadGroups.value[name] = text;
    }
  }
  numbersGenDialogVisible.value = false;
  ElMessage.success(`已生成 ${list.length} 个数字 Payload (范围 ${from}..${to})`);
}

function importFuzzFromClipboard() {
  navigator.clipboard
    .readText()
    .then((text) => {
      if (!text.trim()) {
        ElMessage.warning("剪贴板没有可导入的内容");
        return;
      }
      const ok = appendToFuzzGroup(text);
      if (ok) {
        const count = text.trim().split(/\r?\n/).length;
        if (isSinglePayloadMode.value) {
          ElMessage.success(`已向通用 Payload 字典导入 ${count} 行`);
        } else {
          const name = currentFuzzGroupName();
          ElMessage.success(`已向 §${name}§ 导入 ${count} 行 payload`);
        }
      }
    })
    .catch(() => {
      ElMessage.error("读取剪贴板失败，请检查浏览器剪贴板权限");
    });
}

function pickFuzzFile() {
  fuzzFileInput.value?.click();
}

function onFuzzFileSelected(event: Event) {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];
  target.value = "";
  if (!file) return;
  const reader = new FileReader();
  reader.onerror = () => {
    ElMessage.error("读取文件失败");
  };
  reader.onload = () => {
    const text = String(reader.result || "");
    if (!text.trim()) {
      ElMessage.warning("文件内容为空，没有可导入的 payload");
      return;
    }
    const ok = appendToFuzzGroup(text);
    if (ok) {
      const lines = text.trim().split(/\r?\n/).length;
      const bytes = new Blob([text]).size;
      if (isSinglePayloadMode.value) {
        ElMessage.success(`已从 ${file.name} 导入 ${lines} 行 payload（${bytes} 字节）到通用字典`);
      } else {
        const name = currentFuzzGroupName();
        ElMessage.success(`已向 §${name}§ 从 ${file.name} 导入 ${lines} 行 payload（${bytes} 字节）`);
      }
    }
  };
  reader.readAsText(file, "utf-8");
}

function insertFuzzPlaceholder(target: "url" | "headers" | "body") {
  const inputRef = target === "url" ? fuzzUrlInput : target === "headers" ? fuzzHeadersInput : fuzzBodyInput;
  const inputEl = inputRef.value?.$el?.querySelector?.("textarea") || inputRef.value?.$el?.querySelector?.("input");
  const value = fuzzForm.value[target];
  if (!inputEl) {
    fuzzForm.value[target] = value + "\u00a7name\u00a7";
    ensureFuzzGroups();
    nextTick(syncUrlEditorScroll);
    return;
  }
  const start = inputEl.selectionStart ?? value.length;
  const end = inputEl.selectionEnd ?? value.length;
  const selected = value.slice(start, end);
  if (selected) {
    fuzzForm.value[target] = value.slice(0, start) + "\u00a7" + selected + "\u00a7" + value.slice(end);
    const anchor = start + 1;
    requestAnimationFrame(() => {
      inputEl.focus({ preventScroll: true });
      inputEl.setSelectionRange(anchor, anchor + selected.length);
      syncUrlEditorScroll();
    });
  } else {
    fuzzForm.value[target] = value.slice(0, start) + "\u00a7name\u00a7" + value.slice(end);
    const anchor = start + 1 + 4;
    requestAnimationFrame(() => {
      inputEl.focus({ preventScroll: true });
      inputEl.setSelectionRange(anchor, anchor + 4);
      syncUrlEditorScroll();
    });
  }
  ensureFuzzGroups();
  nextTick(syncUrlEditorScroll);
}

function insertRawPlaceholder() {
  const inputEl = fuzzRawInput.value?.$el?.querySelector?.("textarea") || fuzzRawInput.value?.$el?.querySelector?.("input");
  const value = fuzzRawPacket.value;
  if (!inputEl) {
    fuzzRawPacket.value = value + "\u00a7name\u00a7";
    ensureFuzzGroups();
    nextTick(syncRawEditorScroll);
    return;
  }
  const start = inputEl.selectionStart ?? value.length;
  const end = inputEl.selectionEnd ?? value.length;
  const selected = value.slice(start, end);
  if (selected) {
    fuzzRawPacket.value = value.slice(0, start) + "\u00a7" + selected + "\u00a7" + value.slice(end);
    const anchor = start + 1;
    requestAnimationFrame(() => {
      inputEl.focus({ preventScroll: true });
      inputEl.setSelectionRange(anchor, anchor + selected.length);
      syncRawEditorScroll();
    });
  } else {
    fuzzRawPacket.value = value.slice(0, start) + "\u00a7name\u00a7" + value.slice(end);
    const anchor = start + 1 + 4;
    requestAnimationFrame(() => {
      inputEl.focus({ preventScroll: true });
      inputEl.setSelectionRange(anchor, anchor + 4);
      syncRawEditorScroll();
    });
  }
  ensureFuzzGroups();
  nextTick(syncRawEditorScroll);
}

async function runFuzz() {
  const targets = actionSessions();
  const form = fuzzForm.value;
  if (!targets.length || fuzzRunning.value) return;
  if (fuzzRawPacket.value.trim()) {
    const parsed = parseRawFuzzPacket(fuzzRawPacket.value);
    if (parsed.method) form.method = parsed.method;
    if (parsed.requestTarget && /^https?:\/\//.test(parsed.requestTarget)) {
      form.url = parsed.requestTarget;
    }
    form.headers = parsed.headers;
    form.body = parsed.body;
  }
  if (!form.method.trim() || !form.url.trim()) return;
  splitFuzzPacket();
  if (!fuzzVariables.value.length) {
    ElMessage.warning(`请在 URL 或请求数据包中标记 “§name§” 占位符`);
    return;
  }
  ensureFuzzGroups();
  const multiPayloads: Record<string, string[]> = {};
  let singleList: string[] = [];
  if (isSinglePayloadMode.value) {
    singleList = (fuzzSharedPayload.value || "")
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean);
    for (const name of fuzzVariables.value) {
      multiPayloads[name] = singleList;
    }
  } else {
    for (const name of fuzzVariables.value) {
      const text = getFuzzPayload(name);
      const items = text
        .split(/\r?\n/)
        .map((item) => item.trim())
        .filter(Boolean);
      if (items.length) multiPayloads[name] = items;
    }
  }
  const hasAnyPayload = isSinglePayloadMode.value
    ? singleList.length > 0
    : Object.values(multiPayloads).some((list) => list.length > 0);
  if (!hasAnyPayload && fuzzEngine.value !== "zap") {
    ElMessage.warning("至少需要一行 fuzz payload");
    return;
  }
  fuzzRunning.value = true;
  fuzzError.value = "";
  const results: Record<string, FuzzResult> = {};
  let total = 0;
  try {
    for (const packet of targets) {
      const { data } = await api.post<FuzzResult>(
        `/traffic/packets/${encodeURIComponent(String(packet.id))}/fuzz`,
        {
          method: form.method.trim().toUpperCase(),
          url: form.url.trim(),
          headers: form.headers,
          body: form.body,
          multiPayloads,
          payloads: isSinglePayloadMode.value ? singleList : null,
          combination: fuzzCombination.value,
          engine: fuzzEngine.value === "auto" ? undefined : fuzzEngine.value.toUpperCase(),
        },
        { timeout: 120_000 },
      );
      results[String(packet.id)] = data;
      total += data.results?.length || 0;
    }
    fuzzBatchResults.value = results;
    fuzzFocusPacketId.value = selectedId.value ?? targets[0].id;
    fuzzResult.value = results[String(fuzzFocusPacketId.value)];
    const changed = Object.values(results).reduce(
      (sum, r) => sum + (r.results?.filter((h) => h.changed).length || 0),
      0,
    );
    ElMessage.success(
      `模糊测试完成：${targets.length} 个会话，${total} 次响应，${changed} 个变更命中`,
    );
  } catch (error) {
    fuzzError.value = readableError(error);
    ElMessage.error(fuzzError.value);
  } finally {
    fuzzRunning.value = false;
  }
}

function focusFuzzResult(packetId: number | string) {
  fuzzFocusPacketId.value = packetId;
  fuzzResult.value = fuzzBatchResults.value[String(packetId)] ?? fuzzResult.value;
}

const fuzzChangedHits = computed(() => {
  const result = fuzzResult.value;
  if (!result?.results) return 0;
  return result.results.filter((hit) => hit.changed).length;
});

async function fuzzHitToReplay(hit: FuzzHit) {
  const focus = fuzzFocusPacketId.value ?? selectedId.value;
  if (focus == null) return;
  const packet = sessions.value.find((item) => item.id === focus);
  if (!packet) return;
  const form = {
    method: fuzzForm.value.method.toUpperCase(),
    url: fuzzForm.value.url.replace("\u00a7name\u00a7", hit.payload),
    headers: fuzzForm.value.headers.replace("\u00a7name\u00a7", hit.payload),
    body: fuzzForm.value.body.replace("\u00a7name\u00a7", hit.payload),
  };
  createReplayTab(form, composeReplayPacket(form.headers, form.body), packet.id);
  packetTab.value = "replay";
  ElMessage.info("已带入该 hit 到重放器，可核对响应");
}

function fuzzHitStatus(hit: FuzzHit) {
  if (hit.effectiveStatus == null) return "-";
  return `HTTP ${hit.effectiveStatus}`;
}

interface TargetedScanHit {
  title: string;
  severity: string;
  description: string;
  parameter?: string;
  evidence?: string;
  solution?: string;
}

interface TargetedScanResult {
  packetId: number;
  engine: string;
  status: string;
  hits: TargetedScanHit[];
  message: string;
}

const targetedScanVisible = ref(false);
const targetedScanLoading = ref(false);
const targetedScanResult = ref<TargetedScanResult | null>(null);
const targetedScanEngine = ref<"ZAP" | "XRAY">("ZAP");

const fuzzPresets = ref<
  Array<{ id: string; name: string; category: string; payloads: string[] }>
>([]);
const selectedFuzzPreset = ref("");

async function loadFuzzPresets() {
  try {
    const { data } = await api.get<
      Array<{ id: string; name: string; category: string; payloads: string[] }>
    >("/traffic/fuzz/presets");
    if (data && data.length) {
      fuzzPresets.value = data;
    }
  } catch {
    fuzzPresets.value = [
      {
        id: "SQLI_BASIC",
        name: "SQL 注入基础探针 (FuzzDB)",
        category: "SQL Injection",
        payloads: [
          "'",
          "\"",
          "1' OR '1'='1",
          "1 OR 1=1",
          "admin' --",
          "1' AND SLEEP(5)--",
          "1' UNION SELECT NULL--",
        ],
      },
      {
        id: "XSS_CORE",
        name: "XSS 跨站脚本载荷 (FuzzDB)",
        category: "Cross-Site Scripting",
        payloads: [
          "<script>alert(1)<\/script>",
          "\"><img src=x onerror=alert(1)>",
          "<svg/onload=alert(1)>",
          "javascript:alert(1)",
        ],
      },
      {
        id: "PATH_TRAVERSAL",
        name: "目录穿越与敏感文件 (FuzzDB)",
        category: "Path Traversal",
        payloads: [
          "../../../../etc/passwd",
          "..\\..\\..\\..\\windows\\win.ini",
          "....//....//....//etc/passwd",
          "/WEB-INF/web.xml",
          "/.env",
        ],
      },
      {
        id: "CMD_INJECTION",
        name: "OS 命令注入探针 (FuzzDB)",
        category: "Command Injection",
        payloads: ["; id", "| whoami", "& ping -c 1 127.0.0.1", "`id`", "$(whoami)"],
      },
      {
        id: "AUTH_WORDLIST",
        name: "常见用户名与弱口令",
        category: "Authentication",
        payloads: [
          "admin",
          "root",
          "guest",
          "test",
          "password",
          "123456",
          "admin123",
        ],
      },
      {
        id: "BOUNDARY_FORMAT",
        name: "边界异常与特殊截断字符",
        category: "Format & Special",
        payloads: [
          "%00",
          "\\u0000",
          "%0d%0a",
          "%0a",
          "%20",
          "%ff",
          "{{7*7}}",
        ],
      },
    ];
  }
}

function applySelectedFuzzPreset(presetId?: string) {
  if (!presetId) return;
  const preset = fuzzPresets.value.find((p) => p.id === presetId);
  if (!preset) return;
  fuzzSharedPayload.value = preset.payloads.join("\n");
  for (const name of fuzzVariables.value) {
    fuzzPayloadGroups.value[name] = fuzzSharedPayload.value;
  }
  ElMessage.success(`已载入「${preset.name}」共 ${preset.payloads.length} 项载荷`);
}

async function runZapScan(item?: TrafficSession | null) {
  const targetItem = item || selected.value;
  if (!targetItem?.id) return ElMessage.warning("请先选择一条流量记录");
  targetedScanEngine.value = "ZAP";
  targetedScanLoading.value = true;
  targetedScanResult.value = null;
  targetedScanVisible.value = true;
  try {
    const { data } = await api.post<TargetedScanResult>(
      `/traffic/packets/${targetItem.id}/zap-scan`,
      {
        strength: "MEDIUM",
        policy: "Default Policy",
      },
      { timeout: 180_000 },
    );
    targetedScanResult.value = data;
    if (data.hits && data.hits.length > 0) {
      ElMessage.warning(`ZAP 扫描完成，发现 ${data.hits.length} 项风险`);
    } else {
      ElMessage.success("ZAP 定向检测完成，未发现高危注入漏洞");
    }
  } catch (err: any) {
    ElMessage.error(toErrorMessage(err, "ZAP 定向扫描失败"));
  } finally {
    targetedScanLoading.value = false;
  }
}

async function runXrayScan(item?: TrafficSession | null) {
  const targetItem = item || selected.value;
  if (!targetItem?.id) return ElMessage.warning("请先选择一条流量记录");
  targetedScanEngine.value = "XRAY";
  targetedScanLoading.value = true;
  targetedScanResult.value = null;
  targetedScanVisible.value = true;
  try {
    const { data } = await api.post<TargetedScanResult>(
      `/traffic/packets/${targetItem.id}/xray-scan`,
      {
        allPocs: true,
      },
      { timeout: 180_000 },
    );
    targetedScanResult.value = data;
    if (data.hits && data.hits.length > 0) {
      ElMessage.warning(`Xray 靶向探测完成，命中 ${data.hits.length} 项漏洞`);
    } else {
      ElMessage.success("Xray 靶向探测完成，未命中已知组件漏洞");
    }
  } catch (err: any) {
    ElMessage.error(toErrorMessage(err, "Xray 靶向探测失败"));
  } finally {
    targetedScanLoading.value = false;
  }
}

function handleSecurityProbeCommand(cmd: string | number | object) {
  if (cmd === "zap") {
    runZapScan(selected.value);
  } else if (cmd === "xray") {
    runXrayScan(selected.value);
  }
}

onMounted(() => {
  void load();
  void loadCaptureFilters();
  void loadFuzzPresets();
  window.addEventListener("pointerdown", onWindowPointerDown);
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
  window.removeEventListener("pointerdown", onWindowPointerDown);
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

    <div class="traffic-workbench codex-traffic-workbench">
      <section
          class="traffic-list-pane traffic-session-rail"
          @click.self="exitMultiSelect"
        >
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
              class="clear-unmarked-btn"
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
          :ref="(el: unknown) => setSessionDropdownRef(item.id, el)"
          @visible-change="(visible: boolean) => {
            if (visible) pickSessionForContextMenu(item);
            onSessionDropdownVisible(visible, item.id);
          }"
          @command="
            (cmd) =>
              cmd === 'mark'
                ? toggleSessionMarked(item)
                : cmd === 'delete'
                  ? deleteSessionAction(item)
                  : cmd === 'replay'
                    ? sendSelectedToReplay()
                    : cmd === 'zap'
                      ? runZapScan(item)
                      : cmd === 'xray'
                        ? runXrayScan(item)
                        : openFuzz()
          "
        >
          <div
            class="traffic-row-wrap"
            :class="{
              active: selectedId === item.id,
              marked: item.marked,
              selected: multiSelectMode && isSessionSelected(item.id),
            }"
          >
            <button
              type="button"
              class="traffic-row"
              :class="{
                active: selectedId === item.id,
              }"
              @click="handleSessionClick(item)"
              @dblclick="toggleMultiSelectMode"
              @pointerdown="beginRowPress(item, $event)"
              @pointerup="cancelLongPress"
              @pointerleave="cancelLongPress"
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
                <small>{{
                  item.path || item.url || "/"
                }}</small>
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
                command="replay"
                :disabled="clearingSessions"
                >发送到重放器<small v-if="selectedSessionCount"
                  >（{{ selectedSessionCount }}）</small
                ></el-dropdown-item
              >
              <el-dropdown-item
                command="fuzz"
                :disabled="clearingSessions"
                >发送到模糊测试<small v-if="selectedSessionCount"
                  >（{{ selectedSessionCount }}）</small
                ></el-dropdown-item
              >
              <el-dropdown-item
                command="zap"
                :disabled="clearingSessions"
                >ZAP 定向探测</el-dropdown-item
              >
              <el-dropdown-item
                command="xray"
                :disabled="clearingSessions"
                >Xray 靶向探测</el-dropdown-item
              >
              <el-dropdown-item
                divided
                command="mark"
                :disabled="markingId === item.id || clearingSessions"
                >{{ item.marked ? "取消标记" : "标记会话" }}</el-dropdown-item
              >
              <el-dropdown-item
                command="delete"
                class="is-danger"
                :disabled="deletingId === item.id || clearingSessions"
                >{{ selectedSessionCount > 1 ? `删除所选（${selectedSessionCount}）` : "删除这条流量" }}</el-dropdown-item
              >
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <AppPagination
          v-model:page="sessionPage"
          v-model:page-size="sessionPageSize"
          :total="filteredSessions.length"
          layout="prev, pager, next"
          small
          class="traffic-session-pagination"
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
              <b>{{ selected.method || "GET" }}</b>
              <strong :title="selected.url || `${selected.host || ''}${selected.path || ''}`">{{
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
              <el-dropdown
                trigger="click"
                @command="handleSecurityProbeCommand"
              >
                <el-button
                  size="small"
                  :loading="targetedScanLoading"
                >
                  安全探测<el-icon class="el-icon--right"><ArrowDown /></el-icon>
                </el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="zap">
                      <span style="font-weight: 500">ZAP 定向注入探测</span>
                    </el-dropdown-item>
                    <el-dropdown-item command="xray">
                      <span style="font-weight: 500">Xray 靶向 PoC 探测</span>
                    </el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
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
            <button
              type="button"
              :class="{ active: packetTab === 'fuzz' }"
              @click="packetTab = 'fuzz'"
            >
              模糊器
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
          <section v-else-if="packetTab === 'fuzz'" class="inline-replay-editor">
            <header>
              <strong>模糊测试</strong>
              <div class="fuzz-head-actions">
                <el-radio-group
                  v-model="fuzzEngine"
                  size="small"
                  class="fuzz-engine-switch"
                >
                  <el-radio-button value="auto">自动</el-radio-button>
                  <el-radio-button value="zap">ZAP</el-radio-button>
                  <el-radio-button value="loop">内置循环</el-radio-button>
                </el-radio-group>
                <el-select
                  v-model="selectedFuzzPreset"
                  size="small"
                  placeholder="载荷预设 (FuzzDB)"
                  style="width: 190px"
                  @change="applySelectedFuzzPreset"
                  clearable
                >
                  <el-option
                    v-for="preset in fuzzPresets"
                    :key="preset.id"
                    :label="preset.name"
                    :value="preset.id"
                  />
                </el-select>
                <el-select
                  v-if="fuzzBatchWithSelection && Object.keys(fuzzBatchResults).length"
                  v-model="fuzzFocusPacketId"
                  size="small"
                  style="width: 200px"
                  @change="focusFuzzResult"
                  placeholder="选择查看结果的会话"
                >
                  <el-option
                    v-for="item in actionSessions()"
                    :key="item.id"
                    :label="`${item.method} ${item.host || '#'}${item.path || ''}`"
                    :value="item.id"
                  >
                    <span>{{ item.method }}</span
                    ><small>{{ item.host || `#${item.id}` }}{{ item.path || "" }}</small>
                  </el-option>
                </el-select>
                <el-button
                  type="primary"
                  size="small"
                  :loading="fuzzRunning"
                  :disabled="
                    !fuzzForm.method.trim() ||
                    !fuzzForm.url.trim() ||
                    (fuzzEngine !== 'zap' && !fuzzVariables.length)
                  "
                  @click="runFuzz"
                  >{{
                    fuzzEngine === "zap" ? "运行 ZAP 模糊测试" : "运行模糊测试"
                  }}</el-button
                >
              </div>
            </header>
            <div class="replay-request-line">
              <el-select
                v-model="fuzzForm.method"
                :disabled="fuzzRunning"
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
              <div class="fuzz-url-wrap">
                <div class="fuzz-url-input-wrap" @scroll.capture="syncUrlEditorScroll">
                  <div
                    ref="fuzzUrlBackdropRef"
                    class="fuzz-url-backdrop"
                    aria-hidden="true"
                    v-html="highlightedUrlHtml"
                  ></div>
                  <el-input
                    ref="fuzzUrlInput"
                    v-model="fuzzForm.url"
                    :disabled="fuzzRunning"
                    placeholder="https://example.com/path（可用 §name§ 标记模糊点）"
                    @input="syncUrlEditorScroll"
                    @keyup="syncUrlEditorScroll"
                  />
                </div>
                <el-button
                  size="small"
                  :disabled="fuzzRunning"
                  @click="insertFuzzPlaceholder('url')"
                  >添加占位符</el-button
                >
              </div>
            </div>
            <div class="replay-packet-editor">
              <span class="fuzz-field-head">
                <span>请求数据包（完整原始报文）</span>
                <div v-if="fuzzVariables.length" class="fuzz-field-chips">
                  <span class="fuzz-chips-label">占位符:</span>
                  <span
                    v-for="name in fuzzVariables"
                    :key="name"
                    class="fuzz-ph-pill"
                  >§{{ name }}§</span>
                </div>
                <el-button
                  size="small"
                  link
                  :disabled="fuzzRunning"
                  @click="insertRawPlaceholder"
                  >添加占位符</el-button
                >
              </span>
              <div class="fuzz-highlight-editor" @scroll.capture="syncRawEditorScroll">
                <div
                  ref="fuzzBackdropRef"
                  class="fuzz-raw-backdrop"
                  aria-hidden="true"
                  v-html="highlightedRawPacketHtml"
                ></div>
                <el-input
                  ref="fuzzRawInput"
                  v-model="fuzzRawPacket"
                  type="textarea"
                  :rows="8"
                  :disabled="fuzzRunning"
                  spellcheck="false"
                  placeholder="POST /submit HTTP/1.1&#10;Host: example.com&#10;Content-Type: application/x-www-form-urlencoded&#10;&#10;q=&#167;name&#167;"
                  @input="syncRawEditorScroll"
                />
              </div>
            </div>
            <section
              v-if="fuzzEngine !== 'zap'"
              class="fuzz-payload-panel"
            >
              <!-- 头部：标题、攻击模式下拉与统计胶囊 -->
              <div class="fuzz-panel-header">
                <div class="fuzz-header-title-group">
                  <span class="fuzz-panel-title">Payload 设置</span>
                  <el-select
                    v-model="fuzzCombination"
                    size="small"
                    class="fuzz-mode-select"
                    :disabled="fuzzRunning"
                  >
                    <el-option
                      v-for="item in FUZZ_ATTACK_TYPES"
                      :key="item.value"
                      :label="item.label"
                      :value="item.value"
                    >
                      <div class="fuzz-option-row">
                        <span class="fuzz-opt-name">{{ item.label }}</span>
                        <small class="fuzz-opt-tip">{{ item.shortDesc }}</small>
                      </div>
                    </el-option>
                  </el-select>
                </div>

                <div class="fuzz-header-pills">
                  <span class="fuzz-stat-pill">
                    <span class="pill-k">位置</span>
                    <b class="pill-v">{{ fuzzVariables.length }}</b>
                  </span>
                  <span class="fuzz-stat-pill" :class="{ 'is-warn': estimatedFuzzRequests > 200 }">
                    <span class="pill-k">预计重放</span>
                    <b class="pill-v">{{ estimatedFuzzRequests }} 次</b>
                  </span>
                </div>
              </div>

              <!-- 模式说明与占位符状态整合条（单一轻量 Ribbon，消除双重边框横幅） -->
              <div class="fuzz-context-ribbon">
                <el-icon class="fuzz-ribbon-icon"><InfoCircle /></el-icon>
                <span class="fuzz-ribbon-desc">{{ currentAttackType.desc }}</span>
                <span class="fuzz-ribbon-divider"></span>
                <div v-if="fuzzVariables.length" class="fuzz-ribbon-vars">
                  <span class="fuzz-ribbon-var-label">标记点:</span>
                  <span v-for="name in fuzzVariables" :key="name" class="fuzz-ph-pill">§{{ name }}§</span>
                  <el-button
                    v-if="isSinglePayloadMode && fuzzVariables.length > 1"
                    link
                    type="primary"
                    size="small"
                    style="margin-left: 8px; font-size: 11px"
                    @click="fuzzCombination = 'CLUSTER_BOMB'"
                  >
                    切换为多字典模式 (集束炸弹) ➔
                  </el-button>
                </div>
                <span v-else class="fuzz-ribbon-novars">未标记占位符（在上方请求报文中选中文本点击“添加占位符”）</span>
              </div>

              <!-- 编辑器工具栏：单行 Fluent CommandBar -->
              <div class="fuzz-editor-toolbar">
                <div class="fuzz-editor-meta">
                  <span class="fuzz-editor-title">
                    {{ isSinglePayloadMode ? "通用字典列表" : `字典集合 (${fuzzVariables.length} 组)` }}
                  </span>
                  <span class="fuzz-editor-lines">
                    {{ isSinglePayloadMode ? (fuzzSharedPayload.split(/\r?\n/).filter(Boolean)).length : totalMultiPayloadLines }} 行
                  </span>
                </div>

                <div class="fuzz-editor-actions">
                  <el-dropdown trigger="click" :disabled="fuzzRunning" @command="applyFuzzPreset">
                    <el-button size="small" :disabled="fuzzRunning">
                      常用预设 ▾
                    </el-button>
                    <template #dropdown>
                      <el-dropdown-menu>
                        <el-dropdown-item
                          v-for="(p, idx) in FUZZ_PAYLOAD_PRESETS"
                          :key="idx"
                          :command="p.payloads"
                        >
                          {{ p.label }} ({{ p.payloads.length }} 条)
                        </el-dropdown-item>
                      </el-dropdown-menu>
                    </template>
                  </el-dropdown>

                  <el-button
                    size="small"
                    :disabled="fuzzRunning"
                    @click="numbersGenDialogVisible = true"
                  >数字序列...</el-button>

                  <el-dropdown trigger="click" :disabled="fuzzRunning" @command="handleImportCommand">
                    <el-button size="small" type="primary" plain :disabled="fuzzRunning">
                      导入 ▾
                    </el-button>
                    <template #dropdown>
                      <el-dropdown-menu>
                        <el-dropdown-item command="clipboard">从剪贴板导入</el-dropdown-item>
                        <el-dropdown-item command="file">从文件导入 (.txt, .dic)...</el-dropdown-item>
                      </el-dropdown-menu>
                    </template>
                  </el-dropdown>

                  <input
                    ref="fuzzFileInput"
                    type="file"
                    hidden
                    accept=".txt,.lst,.dic,.payload,.csv,.wordlist,.text,text/plain"
                    :disabled="fuzzRunning"
                    @change="onFuzzFileSelected"
                  />

                  <el-dropdown v-if="!isSinglePayloadMode && fuzzVariables.length > 1" trigger="click" :disabled="fuzzRunning" @command="(c) => clearFuzzGroups(c === 'all')">
                    <el-button size="small" link type="danger" class="fuzz-clear-btn" :disabled="fuzzRunning">
                      清空 ▾
                    </el-button>
                    <template #dropdown>
                      <el-dropdown-menu>
                        <el-dropdown-item command="current">清空当前 Set (§{{ currentFuzzGroupName() || '选中' }}§)</el-dropdown-item>
                        <el-dropdown-item command="all" divided>清空全部 Set</el-dropdown-item>
                      </el-dropdown-menu>
                    </template>
                  </el-dropdown>
                  <el-button
                    v-else
                    size="small"
                    link
                    type="danger"
                    class="fuzz-clear-btn"
                    :disabled="fuzzRunning"
                    @click="clearFuzzGroups(false)"
                  >清空</el-button>
                </div>
              </div>

              <!-- 编辑区域：单字典或多字典 -->
              <div class="fuzz-editor-body">
                <div v-if="isSinglePayloadMode" class="fuzz-editor-frame">
                  <el-input
                    v-model="fuzzSharedPayload"
                    type="textarea"
                    :rows="5"
                    :disabled="fuzzRunning"
                    spellcheck="false"
                    placeholder="每行一个 payload&#10;admin&#10;test&#10;debug&#10;1' OR '1'='1"
                  />
                </div>

                <div v-else-if="fuzzVariables.length" class="fuzz-multi-list">
                  <div
                    v-for="(name, index) in fuzzVariables"
                    :key="name"
                    class="fuzz-multi-item"
                    :class="{ 'is-focused': activeFuzzGroup === name }"
                    @click="activeFuzzGroup = name"
                  >
                    <div class="fuzz-multi-head">
                      <span class="fuzz-set-badge">Set {{ index + 1 }}</span>
                      <span class="fuzz-set-name">§{{ name }}§</span>
                      <span class="fuzz-set-count">
                        {{ ((getFuzzPayload(name) || '').split(/\r?\n/).filter(Boolean)).length }} 行
                      </span>
                    </div>
                    <el-input
                      :model-value="getFuzzPayload(name)"
                      type="textarea"
                      :rows="3"
                      :disabled="fuzzRunning"
                      spellcheck="false"
                      placeholder="每行一个 payload"
                      @focus="activeFuzzGroup = name"
                      @update:model-value="(v) => (fuzzPayloadGroups[name] = v)"
                    />
                  </div>
                </div>
                <div v-else class="fuzz-empty-groups">
                  <span>尚未标记占位符。请在上方请求报文中选中文本点击“添加占位符”。</span>
                </div>
              </div>
            </section>
            <section class="replay-response">
              <header>
                <div>
                  <strong>{{
                    fuzzResult
                      ? `完成 · ${fuzzResult.results?.length || 0} 次响应`
                      : "模糊结果"
                  }}</strong>
                </div>
              </header>
              <div
                v-if="fuzzRunning"
                class="replay-response-state"
              >
                <el-icon class="is-loading"><Refresh /></el-icon
                ><strong>正在逐个重放请求</strong
                ><span>每个 payload 会替换占位符后按顺序发送并对比基线。</span>
              </div>
              <div v-else-if="fuzzError" class="replay-response-state error">
                <strong>模糊测试失败</strong><span>{{ fuzzError }}</span>
              </div>
              <div
                v-else-if="!fuzzResult"
                class="replay-response-state"
              >
                <strong>尚未运行</strong
                ><span
                  >在 URL / 请求头 / 请求体标记占位符，添加 payload
                  后点击“运行模糊测试”。</span
                >
              </div>
              <div
                v-else-if="fuzzResult.results && fuzzResult.results.length"
                class="fuzz-results"
              >
                <div class="fuzz-result-summary">
                  <el-tag
                    size="small"
                    :type="fuzzResult.engine === 'ZAP' ? 'warning' : 'info'"
                    effect="plain"
                    >{{
                      fuzzResult.engine === "ZAP"
                        ? "引擎：ZAP FuzzDB"
                        : "引擎：自研循环重放"
                    }}</el-tag
                  ><span>响应 {{ fuzzResult.results.length }} 次</span
                  ><span v-if="fuzzChangedHits" class="fuzz-summary-changed"
                    >{{ fuzzChangedHits }} 个变更命中</span
                  ><span v-else>全部同基线</span>
                </div>
                <table class="fuzz-result-table">
                  <thead>
                    <tr>
                      <th>状态</th>
                      <th>响应体</th>
                      <th>耗时</th>
                      <th>字节</th>
                      <th>Hash</th>
                      <th>payload</th>
                      <th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="(hit, index) in fuzzResult.results"
                      :key="index"
                    >
                      <td
                        class="fuzz-hit-status"
                        :class="{ changed: hit.changed }"
                        >{{ fuzzHitStatus(hit) }}</td
                      >
                      <td class="fuzz-hit-diff">{{
                        hit.changed ? "变更" : "同基线"
                      }}</td>
                      <td>{{
                        hit.durationMs !== undefined
                          ? `${hit.durationMs} ms`
                          : "-"
                      }}</td>
                      <td>{{
                        hit.responseBytes !== undefined
                          ? hit.responseBytes
                          : "-"
                      }}</td>
                      <td>{{ hit.digestPrefix || "-" }}</td>
                      <td>
                        <code class="fuzz-hit-payload">{{ hit.payload }}</code>
                      </td>
                      <td>
                        <el-button
                          v-if="hit.changed"
                          link
                          type="primary"
                          size="small"
                          @click="fuzzHitToReplay(hit)"
                          >重放</el-button
                        >
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div v-else class="replay-response-state">
                <strong>无结果</strong>
              </div>
            </section>
          </section>
          <div v-else class="packet-sections packet-editor">
            <template v-if="packetTab === 'request'">
              <article class="raw-packet-card">
                <h3>请求报文</h3>
                <el-input
                  class="raw-packet-text"
                  type="textarea"
                  :model-value="formatRequestPacket(selected)"
                  readonly
                  resize="none"
                  spellcheck="false"
                />
              </article>
            </template>
            <template v-else-if="packetTab === 'response'">
              <article class="raw-packet-card">
                <h3>响应报文</h3>
                <el-input
                  class="raw-packet-text"
                  type="textarea"
                  :model-value="formatResponsePacket(selected)"
                  readonly
                  resize="none"
                  spellcheck="false"
                />
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
      v-model="targetedScanVisible"
      :title="targetedScanEngine === 'ZAP' ? 'OWASP ZAP 定向主动探测' : 'Xray 靶向 PoC 探测'"
      width="680px"
      append-to-body
      class="app-dialog"
      align-center
    >
      <div
        v-loading="targetedScanLoading"
        :element-loading-text="targetedScanEngine === 'ZAP' ? '正在针对当前报文上下文运行 ZAP 深度注入与语法探针...' : '正在针对当前报文上下文运行 Xray 漏洞组件验证...'"
        style="min-height: 160px"
      >
        <div v-if="targetedScanResult">
          <el-alert
            :type="targetedScanResult.hits && targetedScanResult.hits.length ? 'warning' : 'success'"
            :closable="false"
            show-icon
            style="margin-bottom: 14px"
          >
            <template #title>
              <strong>{{ targetedScanResult.message }}</strong>
            </template>
          </el-alert>

          <div v-if="targetedScanResult.hits && targetedScanResult.hits.length" class="targeted-hits-list">
            <el-collapse accordion>
              <el-collapse-item
                v-for="(hit, idx) in targetedScanResult.hits"
                :key="idx"
                :name="idx"
              >
                <template #title>
                  <div style="display: flex; align-items: center; gap: 8px; width: 100%">
                    <el-tag :type="hit.severity === 'HIGH' || hit.severity === 'CRITICAL' ? 'danger' : 'warning'" size="small">
                      {{ severityLabel(hit.severity) }}
                    </el-tag>
                    <strong style="font-size: 13px">{{ hit.title }}</strong>
                    <small v-if="hit.parameter" style="color: var(--app-muted); margin-left: auto; margin-right: 12px">参数: {{ hit.parameter }}</small>
                  </div>
                </template>
                <div style="font-size: 12px; line-height: 1.6; padding: 4px 8px">
                  <p><strong>描述：</strong>{{ hit.description }}</p>
                  <p v-if="hit.evidence" style="margin-top: 4px"><strong>证据：</strong><code>{{ hit.evidence }}</code></p>
                  <p v-if="hit.solution" style="margin-top: 4px; color: var(--el-color-success-dark-2)"><strong>修复建议：</strong>{{ hit.solution }}</p>
                </div>
              </el-collapse-item>
            </el-collapse>
          </div>
          <div v-else style="text-align: center; padding: 24px 0; color: var(--app-muted)">
            未发现明确的注入点或匹配漏洞，建议结合业务逻辑继续使用 Fuzz 模块进行变异测试。
          </div>
        </div>
      </div>
      <template #footer>
        <el-button size="small" @click="targetedScanVisible = false">关闭</el-button>
        <el-button
          size="small"
          type="primary"
          :disabled="targetedScanLoading"
          @click="targetedScanEngine === 'ZAP' ? runZapScan() : runXrayScan()"
        >
          重新测试
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="numbersGenDialogVisible"
      title="数字序列发生器 (Numbers Payload)"
      width="380px"
      append-to-body
      class="app-dialog"
      align-center
    >
      <el-form label-position="left" label-width="70px" size="small" style="margin-top: 10px">
        <el-form-item label="起始值">
          <el-input-number v-model="numbersGenForm.from" :min="0" :max="100000" style="width: 100%" />
        </el-form-item>
        <el-form-item label="结束值">
          <el-input-number v-model="numbersGenForm.to" :min="0" :max="100000" style="width: 100%" />
        </el-form-item>
        <el-form-item label="步长">
          <el-input-number v-model="numbersGenForm.step" :min="1" :max="1000" style="width: 100%" />
        </el-form-item>
        <div style="font-size: 11px; color: var(--app-muted); margin-bottom: 6px">
          预计生成 {{ Math.max(0, Math.floor((Number(numbersGenForm.to) - Number(numbersGenForm.from)) / (Number(numbersGenForm.step) || 1)) + 1) }} 个数字（系统单次上限 200 项）
        </div>
      </el-form>
      <template #footer>
        <el-button size="small" @click="numbersGenDialogVisible = false">取消</el-button>
        <el-button size="small" type="primary" @click="applyNumbersGenerator">生成并填入字典</el-button>
      </template>
    </el-dialog>

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
        <el-table-column label="名单" width="75"
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
        <el-table-column label="匹配方式" width="85"
          ><template #default="scope">{{
            captureFilterTypeLabel(scope.row.type)
          }}</template></el-table-column
        >
        <el-table-column
          prop="pattern"
          label="匹配内容"
          min-width="160"
          show-overflow-tooltip
        />
        <el-table-column label="启用" width="65"
          ><template #default="scope"
            ><el-switch
              v-model="scope.row.enabled"
              @change="toggleCaptureFilter(scope.row)" /></template
        ></el-table-column
        >
        <el-table-column label="操作" width="100"
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
  padding-bottom: 0;
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
.traffic-session-rail > .traffic-session-pagination {
  position: sticky;
  z-index: 3;
  bottom: 0;
  flex: none;
  margin-top: auto;
  padding: 6px 8px;
  border-top: var(--traffic-pane-divider, 1px solid var(--app-border));
  background: var(--app-surface);
}
.traffic-session-rail > .traffic-session-pagination > .el-pagination,
.traffic-session-rail > .traffic-session-pagination :deep(.el-pagination) {
  justify-content: center;
  flex-wrap: nowrap;
  margin: 0;
  white-space: nowrap;
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
  line-height: 1.5;
  padding-bottom: 2px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.session-row-main > small {
  overflow: hidden;
  margin-top: 3px;
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.45;
  padding-bottom: 1px;
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
  min-height: 46px;
  padding: 6px 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
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
  display: grid;
  grid-template-columns: 110px minmax(0, 1fr);
  gap: 14px;
  align-items: center;
  margin: 0 !important;
}
.inline-replay-editor .replay-request-line > .el-select {
  width: 100%;
}
.inline-replay-editor .replay-request-line .fuzz-url-wrap {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
}
.inline-replay-editor .replay-request-line .fuzz-url-wrap .fuzz-url-input-wrap {
  flex: 1;
  min-width: 0;
}
.inline-replay-editor .replay-packet-editor .fuzz-field-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
}
.inline-replay-editor .replay-packet-editor .fuzz-field-head > span:first-child {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.fuzz-url-input-wrap {
  position: relative;
  flex: 1;
  min-width: 0;
  display: flex;
}
.fuzz-url-backdrop {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  overflow: hidden;
  pointer-events: none;
  border: var(--fluent-stroke-thin) solid transparent;
  border-radius: var(--fluent-radius-control);
  padding: 0 11px;
  display: flex;
  align-items: center;
  box-sizing: border-box;
  font-family: var(--el-font-family-mono, Consolas, monospace);
  font-size: 12px;
  white-space: nowrap;
  color: transparent;
  background: transparent;
  z-index: 1;
}
.fuzz-url-input-wrap :deep(.el-input) {
  position: relative;
  z-index: 2;
  width: 100%;
}
.fuzz-url-input-wrap :deep(.el-input__wrapper) {
  background: transparent !important;
}
.fuzz-url-input-wrap :deep(.el-input__inner) {
  font-family: var(--el-font-family-mono, Consolas, monospace);
  font-size: 12px;
}
.fuzz-field-chips {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-left: 8px;
}
.fuzz-chips-label {
  font-size: var(--type-micro);
  color: var(--app-muted);
  font-weight: normal;
}
.fuzz-highlight-editor {
  position: relative;
  width: 100%;
}
.fuzz-raw-backdrop {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  overflow: hidden;
  pointer-events: none;
  border: var(--fluent-stroke-thin) solid transparent;
  border-radius: var(--fluent-radius-control);
  padding: 10px 12px;
  box-sizing: border-box;
  font-family: var(--el-font-family-mono, Consolas, monospace) !important;
  font-size: 12px !important;
  line-height: 20px !important;
  white-space: pre-wrap !important;
  word-break: break-all !important;
  color: transparent;
  background: transparent;
  z-index: 1;
}
.fuzz-highlight-editor :deep(.el-textarea) {
  position: relative;
  z-index: 2;
}
.fuzz-highlight-editor :deep(.el-textarea__inner) {
  background: transparent !important;
  font-family: var(--el-font-family-mono, Consolas, monospace) !important;
  font-size: 12px !important;
  line-height: 20px !important;
  padding: 10px 12px !important;
  white-space: pre-wrap !important;
  word-break: break-all !important;
  box-sizing: border-box !important;
  height: clamp(220px, 35vh, 420px) !important;
  min-height: 220px !important;
  resize: none !important;
}
.fuzz-placeholder-mark {
  color: transparent;
  background: light-dark(rgba(247, 130, 59, 0.32), rgba(247, 130, 59, 0.45));
  outline: 1px solid light-dark(#d9651a, #f7823b);
  border-radius: 2px;
  box-shadow: 0 0 4px light-dark(rgba(247, 130, 59, 0.35), rgba(247, 130, 59, 0.45));
  padding: 1px 0;
  margin: 0;
}
.inline-replay-editor .replay-packet-editor {
  margin-top: 20px !important;
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
.replay-packet-editor.fuzz-payloads {
  margin-top: 12px;
}
.fuzz-group-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.fuzz-group-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.fuzz-group-name {
  color: var(--app-accent);
  font-weight: 600;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
}
.fuzz-results {
  overflow: auto;
  margin-top: 10px;
  padding: 10px 12px;
  border: var(--fluent-stroke-thin) solid var(--app-border);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface);
  box-shadow: var(--fluent-card-shadow);
}
.fuzz-result-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 11px;
}
.fuzz-result-table th {
  padding: 6px 8px;
  border-bottom: 1px solid var(--app-border, rgba(120, 130, 140, 0.2));
  color: var(--app-muted);
  font-weight: 600;
  text-align: left;
  white-space: nowrap;
}
.fuzz-result-table td {
  padding: 6px 8px;
  border-bottom: 1px solid rgba(120, 130, 140, 0.12);
  vertical-align: top;
  white-space: nowrap;
}
.fuzz-result-table tr:hover td {
  background: var(--app-surface-soft);
}
.fuzz-result-table tr:nth-child(even) td {
  background: color-mix(in srgb, CanvasText 2%, transparent);
}
.fuzz-result-table tr:hover td:empty {
  background: var(--app-surface-soft);
}
.fuzz-hit-status.changed {
  color: light-dark(#bc4b09, #f7823b);
  font-weight: var(--fluent-weight-semibold);
  background: light-dark(rgba(255, 193, 7, 0.10), rgba(255, 183, 77, 0.12));
  padding: 2px 8px;
  border-radius: var(--fluent-radius-control);
}
.fuzz-hit-diff {
  color: var(--app-muted);
}
.fuzz-hit-payload {
  max-width: 260px;
  overflow: hidden;
  text-overflow: ellipsis;
  color: var(--app-text);
  font: var(--type-micro) ui-monospace, SFMono-Regular, Consolas, monospace;
  white-space: nowrap;
}
.fuzz-head-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.fuzz-engine-switch {
  flex: none;
}
.fuzz-engine-switch :deep(.el-radio-button__inner) {
  font-size: 11px;
  padding: 6px 10px;
}
.fuzz-payload-panel {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-top: 14px;
  padding: 12px 14px;
  border-radius: var(--fluent-radius-card);
  border: var(--fluent-stroke-thin) solid var(--app-border);
  background: var(--app-surface);
  box-shadow: var(--fluent-shadow-2);
}
.fuzz-panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
}
.fuzz-header-title-group {
  display: flex;
  align-items: center;
  gap: 10px;
}
.fuzz-panel-title {
  font-size: var(--type-section-desc);
  font-weight: var(--fluent-weight-semibold);
  color: var(--app-text);
  white-space: nowrap;
}
.fuzz-mode-select {
  width: 220px;
}
.fuzz-option-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.fuzz-opt-name {
  font-weight: var(--fluent-weight-medium);
}
.fuzz-opt-tip {
  color: var(--app-muted);
  font-size: var(--type-micro);
}
.fuzz-header-pills {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.fuzz-stat-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px;
  border-radius: var(--fluent-radius-circular);
  background: color-mix(in srgb, CanvasText 4%, transparent);
  border: var(--fluent-stroke-thin) solid var(--app-border);
  font-size: var(--type-micro);
  color: var(--app-muted);
}
.fuzz-stat-pill .pill-v {
  color: var(--app-text);
  font-weight: var(--fluent-weight-semibold);
}
.fuzz-stat-pill.is-warn {
  border-color: color-mix(in srgb, var(--fluent-warning-bg) 40%, transparent);
  background: color-mix(in srgb, var(--fluent-warning-bg) 10%, transparent);
}
.fuzz-stat-pill.is-warn .pill-v {
  color: light-dark(#b26200, #f5a623);
}
.fuzz-context-ribbon {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  padding: 7px 12px;
  border-radius: var(--fluent-radius-control);
  background: color-mix(in srgb, var(--app-accent) 6%, transparent);
  border: var(--fluent-stroke-thin) solid color-mix(in srgb, var(--app-accent) 18%, transparent);
  font-size: var(--type-micro);
  color: var(--app-text);
  line-height: 1.4;
}
.fuzz-ribbon-icon {
  color: var(--app-accent);
  font-size: 14px;
  flex: none;
}
.fuzz-ribbon-desc {
  color: var(--app-text);
}
.fuzz-ribbon-divider {
  width: 1px;
  height: 12px;
  background: color-mix(in srgb, var(--app-accent) 25%, transparent);
  margin: 0 2px;
}
.fuzz-ribbon-vars {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.fuzz-ribbon-var-label {
  color: var(--app-muted);
}
.fuzz-ph-pill {
  display: inline-block;
  padding: 1px 7px;
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface);
  border: var(--fluent-stroke-thin) solid color-mix(in srgb, var(--app-accent) 30%, transparent);
  color: var(--app-accent);
  font-family: var(--el-font-family-mono, Consolas, monospace);
  font-weight: var(--fluent-weight-semibold);
  font-size: 11px;
}
.fuzz-ph-none {
  color: var(--app-muted);
  font-style: italic;
}
.fuzz-editor-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 4px 0 2px;
}
.fuzz-editor-meta {
  display: inline-flex;
  align-items: baseline;
  gap: 6px;
}
.fuzz-editor-title {
  font-size: var(--type-caption);
  font-weight: var(--fluent-weight-semibold);
  color: var(--app-text);
}
.fuzz-editor-lines {
  font-size: var(--type-micro);
  color: var(--app-muted);
}
.fuzz-editor-actions {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.fuzz-editor-actions .el-button {
  height: 28px;
  font-size: var(--type-micro);
}
.fuzz-editor-frame :deep(.el-textarea__inner) {
  font-family: var(--el-font-family-mono, Consolas, monospace);
  font-size: 12px;
  line-height: 1.6;
}
.fuzz-multi-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.fuzz-multi-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 10px 12px;
  border-radius: var(--fluent-radius-control);
  border: var(--fluent-stroke-thin) solid var(--app-border);
  background: var(--app-surface-soft);
  transition: border-color var(--fluent-duration-fast) var(--fluent-curve-standard);
}
.fuzz-multi-item.is-focused {
  border-color: var(--app-accent);
}
.fuzz-multi-head {
  display: flex;
  align-items: center;
  gap: 8px;
}
.fuzz-set-badge {
  display: inline-block;
  padding: 1px 6px;
  border-radius: var(--fluent-radius-control);
  background: color-mix(in srgb, var(--app-accent) 15%, transparent);
  color: var(--app-accent);
  font-size: 10px;
  font-weight: var(--fluent-weight-semibold);
}
.fuzz-set-name {
  color: var(--app-accent);
  font-family: var(--el-font-family-mono, Consolas, monospace);
  font-weight: var(--fluent-weight-semibold);
}
.fuzz-set-count {
  margin-left: auto;
  font-size: var(--type-micro);
  color: var(--app-muted);
}
.fuzz-empty-groups {
  padding: 16px;
  text-align: center;
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface);
  border: var(--fluent-stroke-thin) dashed var(--app-border);
  color: var(--app-muted);
  font-size: var(--type-caption);
}
.fuzz-result-summary {
  display: flex;
  gap: 12px;
  align-items: center;
  padding: 8px 0;
  font-size: var(--type-micro);
  color: var(--app-muted);
  border-bottom: var(--fluent-stroke-thin) solid var(--app-border);
}
.fuzz-summary-changed {
  color: light-dark(#bc4b09, #f7823b);
  font-weight: var(--fluent-weight-semibold);
}
.traffic-row-wrap.selected {
  background: rgba(80, 120, 220, 0.08);
}
.traffic-row {
  position: relative;
}
.packet-title {
  display: flex;
  flex: 1;
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
  flex: 1;
  min-width: 0;
  overflow: hidden;
  color: var(--app-text);
  font-size: 12px;
  font-weight: 500;
  line-height: 1.45;
  padding-bottom: 1px;
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
  min-height: 0;
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
  display: flex;
  height: 100%;
  min-height: 0;
  flex: 1;
  flex-direction: column;
  overflow: hidden;
  border: 0;
  border-radius: 0;
  background: transparent;
  box-shadow: none;
}
.packet-editor .raw-packet-card:hover {
  border-color: transparent;
}
.packet-editor .raw-packet-card .el-input,
.packet-editor .raw-packet-card .el-textarea {
  flex: 1;
  min-height: 0;
  width: 100%;
}
.packet-editor h3 {
  margin: 0;
  padding: 8px 12px;
  border-bottom: 0;
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
.packet-editor .raw-packet-card :deep(.raw-packet-text) {
  flex: 1;
  min-height: 0;
  width: 100%;
}
.packet-editor .raw-packet-card :deep(.raw-packet-text .el-textarea__inner) {
  height: 100%;
  min-height: 460px;
  padding: 12px;
  border: 0;
  border-radius: 0;
  background: transparent;
  color: var(--app-text);
  font-family: var(--el-font-family-mono, Consolas, monospace);
  font-size: 12px;
  line-height: 1.65;
  white-space: pre-wrap;
  word-break: break-all;
  resize: none;
  overflow: auto;
  box-shadow: none;
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
  display: grid !important;
  grid-template-columns: 116px minmax(0, 1fr);
  gap: 14px !important;
  align-items: center;
  margin: 0 0 12px !important;
}
.replay-request-line > .el-select {
  width: 100% !important;
}
.replay-packet-editor {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 10px;
  margin-top: 12px !important;
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
.codex-traffic-page :deep(.el-button--danger.is-text.clear-unmarked-btn:hover),
.codex-traffic-page :deep(.el-button--danger.is-link.fuzz-clear-btn:hover) {
  background: transparent;
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
  height: 24px;
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
