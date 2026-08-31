<script setup lang="ts">
import {
  computed,
  nextTick,
  onBeforeUnmount,
  onMounted,
  ref,
  shallowRef,
  watch,
} from "vue";
import { useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Check,
  Plus,
  Delete,
  QuestionFilled,
  Refresh,
  CircleCheck,
  FolderOpened,
  Warning,
  VideoPlay,
  VideoPause,
  ArrowDown,
  Dismiss,
  Setting,
} from "../components/fluentIcons";
import FluentIcon from "../components/FluentIcon.vue";
import {
  Handle,
  MarkerType,
  Position,
  SelectionMode,
  VueFlow,
  type Connection,
  type Edge,
  type EdgeMouseEvent,
  type GraphNode,
  type Node,
  type NodeMouseEvent,
  type NodeDragEvent,
  useVueFlow,
} from "@vue-flow/core";
import "@vue-flow/core/dist/style.css";
import "@vue-flow/core/dist/theme-default.css";
import {
  endpoints,
  streamWorkflowSuggestions,
  type AssessmentProject,
  type ProjectTarget,
  type ProjectTaskRecord,
  type Target,
  type WorkflowGraphEdgeSpec,
  type WorkflowGraphNodeSpec,
  type WorkflowRunDetail,
  type WorkflowRunSummary,
  type WorkflowSpecV2,
  type WorkflowStepSpec,
  type WorkflowSuggestion,
  type WorkflowSuggestStreamEvent,
  type VulnerabilityDefinition,
} from "../api";
import { toErrorMessage } from "../utils/errorMessage";
import { taskbarProgress } from "../utils/taskbarProgress";
import WorkflowEdge from "./WorkflowEdge.vue";
import { COMMON_PORT_OPTIONS, normalizeAllowedPorts } from "../utils/ports";

type PhaseCode =
  | "engagement"
  | "recon"
  | "mapping"
  | "discovery"
  | "validation"
  | "impact"
  | "retest"
  | "report";
type NodeKind = "system" | "phase" | "tool";

interface PhaseMeta {
  code: PhaseCode;
  label: string;
  shortLabel: string;
  desc: string;
  icon: string;
}

interface EditorNodeData {
  nodeKind: NodeKind;
  phase: PhaseCode;
  label: string;
  desc: string;
  icon: string;
  tool?: string;
  risk?: string;
  parameters?: Record<string, unknown>;
}

interface NodeRunState {
  status:
    "pending" | "running" | "success" | "failed" | "skipped" | "cancelled";
  taskId?: number;
  log?: string;
  summary?: string;
  resultCount?: number;
  output?: unknown;
}

type EditorNode = Node<EditorNodeData> & { data: EditorNodeData };

const PHASES: PhaseMeta[] = [
  {
    code: "engagement",
    label: "项目启动与范围",
    shortLabel: "启动与范围",
    desc: "选择项目、目标、测试目标和停止条件。",
    icon: "rocket",
  },
  {
    code: "recon",
    label: "被动侦察",
    shortLabel: "被动侦察",
    desc: "先整理公开情报、项目资料和历史证据。",
    icon: "globe-search",
  },
  {
    code: "mapping",
    label: "资产与服务发现",
    shortLabel: "资产发现",
    desc: "识别授权资产、端口、服务、版本和 Web 信息。",
    icon: "map",
  },
  {
    code: "discovery",
    label: "漏洞发现",
    shortLabel: "漏洞发现",
    desc: "结合指纹与规则筛选潜在风险。",
    icon: "beaker",
  },
  {
    code: "validation",
    label: "安全验证",
    shortLabel: "安全验证",
    desc: "以最小影响方式补充证据，不执行未授权利用。",
    icon: "shield-checkmark",
  },
  {
    code: "impact",
    label: "影响评估",
    shortLabel: "影响评估",
    desc: "说明业务影响、暴露面、可信度与优先级。",
    icon: "chart",
  },
  {
    code: "retest",
    label: "复测与修复确认",
    shortLabel: "复测修复",
    desc: "验证修复结果并记录扫描 Diff。",
    icon: "sync",
  },
  {
    code: "report",
    label: "报告交付",
    shortLabel: "报告交付",
    desc: "生成证据链、风险结论、整改建议并归档。",
    icon: "report",
  },
];
const phaseOf = (code: string) =>
  PHASES.find((item) => item.code === code) ?? PHASES[0];
const PHASE_NODE_IDS: Record<PhaseCode, string> = {
  engagement: "engage",
  recon: "recon",
  mapping: "map",
  discovery: "discovery",
  validation: "validate",
  impact: "impact",
  retest: "retest",
  report: "report",
};

const SUBAGENTS: {
  tool: string;
  name: string;
  icon: string;
  desc: string;
  risk: string;
  phase: PhaseCode;
}[] = [
  {
    tool: "retrieve_project_context",
    name: "项目情报检索",
    icon: "book",
    desc: "读取项目资料、历史任务与已有证据（只读）",
    risk: "SAFE",
    phase: "recon",
  },
  {
    tool: "tcp_ports",
    name: "授权端口探测",
    icon: "plug",
    desc: "仅在授权端口范围内探测 TCP 存活情况",
    risk: "SAFE",
    phase: "mapping",
  },
  {
    tool: "nmap_service_scan",
    name: "服务与版本识别",
    icon: "server",
    desc: "识别开放端口上的服务和版本信息",
    risk: "SAFE",
    phase: "mapping",
  },
  {
    tool: "http_headers",
    name: "Web 基础信息采集",
    icon: "globe",
    desc: "采集 HTTP 响应头等低影响证据",
    risk: "SAFE",
    phase: "mapping",
  },
  {
    tool: "http_security_check",
    name: "Web 风险检查",
    icon: "shield",
    desc: "检查常见 HTTP 安全配置问题",
    risk: "SAFE",
    phase: "discovery",
  },
  {
    tool: "tls_config",
    name: "TLS 配置检查",
    icon: "lock",
    desc: "检查 HTTPS、证书和 TLS 基础配置",
    risk: "SAFE",
    phase: "mapping",
  },
  {
    tool: "nuclei_scan",
    name: "Nuclei 漏洞模板扫描",
    icon: "shield-task",
    desc: "使用 Nuclei 安全模板检查授权目标，执行前需人工确认",
    risk: "CAUTION",
    phase: "discovery",
  },
  {
    tool: "afrog_scan",
    name: "Afrog PoC 漏洞扫描",
    icon: "shield-task",
    desc: "使用已同步的 Afrog PoC 检查授权 Web 目标，执行前需人工确认",
    risk: "CAUTION",
    phase: "discovery",
  },
  {
    tool: "xray_scan",
    name: "Xray PoC 漏洞扫描",
    icon: "shield-task",
    desc: "使用已同步的 Xray PoC 检查授权 Web 目标，执行前需人工确认",
    risk: "CAUTION",
    phase: "discovery",
  },
  {
    tool: "fscan_scan",
    name: "fscan 主机扫描",
    icon: "shield-task",
    desc: "对授权主机做端口、服务指纹与安全漏洞指纹扫描，爆破/弱口令类默认关闭",
    risk: "CAUTION",
    phase: "discovery",
  },
];
const agentOf = (tool?: string) => SUBAGENTS.find((item) => item.tool === tool);

const SUGGESTION_KIND_LABELS: Record<string, string> = {
  coverage_gap: "覆盖不足",
  orchestration: "编排建议",
  retest_gap: "复测缺口",
  gap: "缺少步骤",
  order: "执行顺序",
  coverage: "覆盖建议",
  risk: "风险提示",
  empty: "流程待补充",
  parallel: "并行建议",
  orphan: "未连线节点",
  preset: "模板建议",
  focus: "当前节点",
  tip: "优化建议",
};

const SUGGESTION_TERM_LABELS: Record<string, string> = {
  coverage_gap: "覆盖不足",
  orchestration: "工作流编排",
  retest_gap: "复测缺口",
  engagement: "项目启动与范围",
  recon: "被动侦察",
  mapping: "资产与服务发现",
  discovery: "漏洞发现",
  validation: "安全验证",
  impact: "影响评估",
  retest: "复测与修复确认",
  report: "报告交付",
};

function suggestionKindLabel(kind?: string) {
  return (
    SUGGESTION_KIND_LABELS[String(kind || "").toLowerCase()] || "工作流建议"
  );
}

function localizeSuggestionText(value?: string) {
  let text = String(value || "");
  Object.entries(SUGGESTION_TERM_LABELS).forEach(([term, label]) => {
    text = text.replace(new RegExp(`\\b${term}\\b`, "gi"), label);
  });
  return text;
}

function suggestSourceLabel(source?: string) {
  const map: Record<string, string> = {
    "llm+local": "大模型+本地规则",
    "local-rules": "本地规则",
    local: "本地规则",
    llm: "大模型",
  };
  const key = String(source || "").trim().toLowerCase();
  return map[key] || String(source || "");
}

const PRESETS = [
  {
    value: "standard",
    label: "标准红队评估",
    desc: "从侦察、资产发现到复测报告的完整闭环。",
  },
  {
    value: "quick-web",
    label: "快速 Web 评估",
    desc: "适合单个网站的低影响快速检查。",
  },
  {
    value: "asset-inventory",
    label: "资产盘点",
    desc: "优先梳理授权资产、端口和服务版本。",
  },
  {
    value: "retest",
    label: "漏洞复测",
    desc: "针对已有发现验证修复效果并交付 Diff。",
  },
] as const;
type PresetCode = (typeof PRESETS)[number]["value"];

const loading = ref(false);
const saving = ref(false);
const projects = ref<AssessmentProject[]>([]);
const selectedProjectId = ref<number>();
const workflowSnapshot = ref<
  Pick<
    WorkflowSpecV2,
    | "workflowId"
    | "scopeId"
    | "revision"
    | "specDigest"
    | "updatedBy"
    | "updatedAt"
  >
>({});
const targets = ref<Target[]>([]);
const projectTargetLinks = ref<ProjectTarget[]>([]);
const selectedTargetId = ref<number>();
const targetInputVisible = ref(false);
const targetInputSaving = ref(false);
const workflowConfigVisible = ref(false);
const workflowContextMenu = ref({
  visible: false,
  x: 0,
  y: 0,
  nodeId: "",
});
const clipboardNode = shallowRef<EditorNode | null>(null);
const pasteOffset = ref(0);
const lastPaneContextPoint = ref<{ x: number; y: number } | null>(null);
const targetInput = ref({
  name: "",
  targetValue: "",
  targetType: "domain",
  authorizationNote: "",
});
const targetInputSelectedPorts = ref<string[]>(["80", "443"]);
const targetInputFullPortAccess = ref(false);
const router = useRouter();
const executing = ref(false);
const executeProgress = ref(0);
const executeIndeterminate = ref(false);
const executeStatus = ref("待执行");
const executeLogs = ref<string[]>([]);
const executeTaskIds = ref<number[]>([]);
const nodeRuns = ref<Record<string, NodeRunState>>({});
const workflowRuns = ref<WorkflowRunSummary[]>([]);
const selectedRunId = ref<number>();
const activeRunId = ref<number>();
const selectedRunDetail = ref<WorkflowRunDetail>();
const viewingRunSnapshot = ref(false);
const stoppingRun = ref(false);
const nodeDetailVisible = ref(false);
const nodeDetailNodeId = ref("");
let runPollGeneration = 0;
const showGuide = ref(false);
const preset = ref<PresetCode>("standard");
const nodes = shallowRef<EditorNode[]>([]);
const edges = shallowRef<Edge[]>([]);
const selectedNodeId = ref("");
const selectedNodeIds = ref<string[]>([]);
const selectedEdgeId = ref("");
const hoveredEdgeId = ref("");
const UNDO_LIMIT = 60;
const graphHistory = shallowRef<HistorySnapshot[]>([]);
const graphFuture = shallowRef<HistorySnapshot[]>([]);
interface HistorySnapshot {
  nodes: EditorNode[];
  edges: Edge[];
}
let pendingDragSnapshot: HistorySnapshot | null = null;
const selectedPhase = ref<PhaseCode>("mapping");
const phaseLibraryExpanded = ref(true);
const capabilityLibraryExpanded = ref(true);
const rightSidebarTab = ref<"library" | "node">("library");
const graphValidation = ref<string[]>([]);
const graphNotice = ref("");
const suggestLoading = ref(false);
const suggestNote = ref("");
const suggestSource = ref("");
const suggestions = ref<WorkflowSuggestion[]>([]);
const suggestExpanded = ref(false);
const suggestHeight = ref<number | null>(null);
const SUGGEST_MIN_HEIGHT = 96;
const SUGGEST_MAX_HEIGHT = 900;
let suggestResizeStartY = 0;
let suggestResizeOriginH = 0;
let suggestResizing = false;
const suggestPanelEl = ref<HTMLElement | null>(null);

function startSuggestResize(event: PointerEvent) {
  suggestResizing = true;
  suggestResizeStartY = event.clientY;
  const rect = suggestPanelEl.value?.getBoundingClientRect();
  const measured = rect ? rect.height : 0;
  suggestResizeOriginH =
    suggestHeight.value ??
    (measured > 0
      ? measured
      : Math.min(220, window.innerHeight * 0.28));
  document.body.classList.add("is-resizing-suggest");
  window.addEventListener("pointermove", onSuggestResizeMove);
  window.addEventListener("pointerup", endSuggestResize);
  event.preventDefault();
}

function onSuggestResizeMove(event: PointerEvent) {
  if (!suggestResizing) return;
  const delta = suggestResizeStartY - event.clientY;
  const next = suggestResizeOriginH + delta;
  suggestHeight.value = Math.min(
    SUGGEST_MAX_HEIGHT,
    Math.max(SUGGEST_MIN_HEIGHT, next),
  );
}

function endSuggestResize() {
  suggestResizing = false;
  document.body.classList.remove("is-resizing-suggest");
  window.removeEventListener("pointermove", onSuggestResizeMove);
  window.removeEventListener("pointerup", endSuggestResize);
}
let suggestTimer: ReturnType<typeof setTimeout> | undefined;
let suggestSeq = 0;
let loadSeq = 0;
let suggestAbort: AbortController | undefined;
const {
  fitView,
  setViewport,
  zoomIn,
  zoomOut,
  screenToFlowCoordinate,
  flowToScreenCoordinate,
  getViewport,
  nodeLookup,
} = useVueFlow("red-team-workflow");
const flowCanvas = ref<HTMLElement | null>(null);
const workflowEditorLayoutRef = ref<HTMLElement | null>(null);
const isFullscreen = ref(false);
const libraryScroll = ref<HTMLElement | null>(null);
const nodeInputEditor = ref<HTMLElement | null>(null);

interface AlignGuideSegment {
  axis: "x" | "y";
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}
interface AlignRuler {
  axis: "x" | "y";
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  x: number;
  y: number;
  label: string;
}
const dragGuides = ref<AlignGuideSegment[]>([]);
const dragRulers = ref<AlignRuler[]>([]);
const isAligning = ref(false);
const ALIGN_SNAP_DISTANCE = 8;

function alignToScreen(x: number, y: number) {
  const vp = getViewport();
  return { x: x * vp.zoom + vp.x, y: y * vp.zoom + vp.y };
}

const WORKFLOW_LAYOUT = {
  startX: 24,
  phaseStartX: 240,
  phaseStepX: 520,
  phaseY: 300,
  toolOffsetX: 260,
  toolGapY: 170,
} as const;

function zoomCanvasIn() {
  void zoomIn();
}
function zoomCanvasOut() {
  void zoomOut();
}
function fitWorkflowCanvas(duration: number | unknown = 0) {
  const dur = typeof duration === "number" ? duration : 0;
  void fitView({
    padding: 0.18,
    maxZoom: 0.95,
    ...(dur > 0 ? { duration: dur } : {}),
  });
}

async function enterFullscreen() {
  const el = workflowEditorLayoutRef.value;
  isFullscreen.value = true;
  nextTick(() => {
    fitWorkflowCanvas(340);
  });
  if (!el) return;
  // 延迟让视口平滑舒展动画先播放，避免浏览器底层硬切导致的画面黑闪与打断
  setTimeout(async () => {
    if (!isFullscreen.value) return;
    try {
      if (el.requestFullscreen) {
        await el.requestFullscreen();
      } else if ((el as any).webkitRequestFullscreen) {
        await (el as any).webkitRequestFullscreen();
      }
    } catch {
      // 降级使用视口全屏
    }
  }, 180);
}

async function exitFullscreen() {
  isFullscreen.value = false;
  nextTick(() => {
    fitWorkflowCanvas(280);
  });
  try {
    if (
      document.fullscreenElement ||
      (document as any).webkitFullscreenElement
    ) {
      if (document.exitFullscreen) {
        await document.exitFullscreen();
      } else if ((document as any).webkitExitFullscreen) {
        await (document as any).webkitExitFullscreen();
      }
    }
  } catch {
    // ignore
  }
}

function toggleFullscreen() {
  const isFs = Boolean(
    isFullscreen.value ||
      document.fullscreenElement ||
      (document as any).webkitFullscreenElement,
  );
  if (isFs) {
    void exitFullscreen();
  } else {
    void enterFullscreen();
  }
}

function onFullscreenChange() {
  const fsElem =
    document.fullscreenElement || (document as any).webkitFullscreenElement;
  isFullscreen.value = Boolean(
    fsElem &&
      workflowEditorLayoutRef.value &&
      (fsElem === workflowEditorLayoutRef.value ||
        workflowEditorLayoutRef.value.contains(fsElem)),
  );
  nextTick(() => {
    fitWorkflowCanvas(300);
  });
}

function onWorkflowWindowResize() {
  closeWorkflowContextMenu();
  fitWorkflowCanvas();
}

function workflowToolY(index: number, count: number) {
  return (
    WORKFLOW_LAYOUT.phaseY +
    (index - Math.max(0, count - 1) / 2) * WORKFLOW_LAYOUT.toolGapY
  );
}

const sortedPhases = computed(() => PHASES);
const filteredAgents = computed(() =>
  SUBAGENTS.filter((agent) => agent.phase === selectedPhase.value),
);
const selectedNode = computed(() =>
  nodes.value.find((node) => node.id === selectedNodeId.value),
);
const selectedToolNode = computed(() =>
  selectedNode.value?.data.nodeKind === "tool" ? selectedNode.value : undefined,
);
const toolNodes = computed(() =>
  nodes.value.filter((node) => node.data.nodeKind === "tool"),
);
const phaseNodes = computed(() =>
  nodes.value.filter((node) => node.data.nodeKind === "phase"),
);
const hasCanonicalPhaseNode = (phase: PhaseCode) =>
  nodes.value.some(
    (node) => node.id === phaseNodeId(phase) && node.data.nodeKind === "phase",
  );
const connectedEdgeCount = computed(() => edges.value.length);
const graphReady = computed(
  () => graphValidation.value.length === 0 && nodes.value.length > 2,
);
const linkedTargets = computed(() =>
  targets.value.filter((target) =>
    projectTargetLinks.value.some((link) => link.targetId === target.id),
  ),
);
const selectedTarget = computed(() =>
  linkedTargets.value.find((target) => target.id === selectedTargetId.value),
);
const selectedProject = computed(() =>
  projects.value.find((project) => project.id === selectedProjectId.value),
);
const selectedPresetLabel = computed(
  () =>
    PRESETS.find((item) => item.value === preset.value)?.label || "未选择模板",
);
const contextMenuNode = computed(() =>
  nodes.value.find((node) => node.id === workflowContextMenu.value.nodeId),
);
const WORKFLOW_PROJECT_STORAGE_KEY = "security_toolbox_workflow_project_v1";
const TERMINAL_RUN_STATUSES = new Set([
  "COMPLETED",
  "PARTIAL_FAILED",
  "STOPPED",
  "FAILED",
]);

function safeId(text: string) {
  return text
    .replace(/[^a-zA-Z0-9_-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase();
}

function uniqueId(prefix: string) {
  let index = 1;
  let id = `${prefix}-${index}`;
  const ids = new Set(nodes.value.map((node) => node.id));
  while (ids.has(id)) {
    index += 1;
    id = `${prefix}-${index}`;
  }
  return id;
}

function phaseNodeId(phase: PhaseCode) {
  return PHASE_NODE_IDS[phase];
}

function nodeData(
  kind: NodeKind,
  phase: PhaseCode,
  label?: string,
  tool?: string,
  parameters?: Record<string, unknown>,
): EditorNodeData {
  const meta = phaseOf(phase);
  const agent = agentOf(tool);
  return {
    nodeKind: kind,
    phase,
    label: label || agent?.name || meta.label,
    desc: agent?.desc || meta.desc,
    icon: agent?.icon || meta.icon,
    tool,
    risk: agent?.risk,
    ...(tool ? { parameters: workflowToolParameters(tool, parameters) } : {}),
  };
}

function workflowToolParameters(
  tool?: string,
  parameters?: Record<string, unknown>,
) {
  if (parameters && Object.keys(parameters).length) return { ...parameters };
  if (
    tool === "afrog_scan" ||
    tool === "xray_scan" ||
    tool === "nuclei_scan"
  )
    return { allPocs: true };
  if (tool === "http_security_check") return { check: "cookies" };
  if (tool === "nmap_service_scan") return { mode: "quick" };
  if (tool === "fscan_scan") return { vulnMode: "SAFE" };
  return {};
}

function updateSelectedToolParameters(
  patch: Record<string, unknown | undefined>,
) {
  const nodeId = selectedToolNode.value?.id;
  if (!nodeId) return;
  nodes.value = nodes.value.map((node) => {
    if (node.id !== nodeId) return node;
    const parameters = { ...(node.data.parameters || {}) };
    Object.entries(patch).forEach(([key, value]) => {
      if (value === undefined) delete parameters[key];
      else parameters[key] = value;
    });
    return {
      ...node,
      data: { ...node.data, parameters },
    };
  });
}

const selectedPortsInput = computed({
  get: () =>
    String(
      selectedToolNode.value?.data.parameters?.ports ||
        selectedTarget.value?.allowedPorts ||
        "80,443",
    ),
  set: (value: string) => updateSelectedToolParameters({ ports: value.trim() }),
});

const selectedNmapMode = computed({
  get: () => String(selectedToolNode.value?.data.parameters?.mode || "quick"),
  set: (value: string) => updateSelectedToolParameters({ mode: value }),
});

const selectedFscanVulnMode = computed({
  get: () =>
    String(
      selectedToolNode.value?.data.parameters?.vulnMode || "SAFE",
    ).toUpperCase(),
  set: (value: string) =>
    updateSelectedToolParameters({ vulnMode: value.toUpperCase() }),
});

const selectedHttpCheck = computed({
  get: () =>
    String(selectedToolNode.value?.data.parameters?.check || "cookies"),
  set: (value: string) => updateSelectedToolParameters({ check: value }),
});

const selectedAllPocs = computed({
  get: () =>
    selectedToolNode.value?.data.parameters?.allPocs === true ||
    !Array.isArray(selectedToolNode.value?.data.parameters?.pocCodes),
  set: (value: boolean) =>
    updateSelectedToolParameters(
      value
        ? { allPocs: true, pocCodes: undefined }
        : { allPocs: undefined, pocCodes: [] },
    ),
});

const selectedPocCodesList = computed({
  get: () => {
    const value = selectedToolNode.value?.data.parameters?.pocCodes;
    return Array.isArray(value) ? value : [];
  },
  set: (values: string[]) => {
    const codes = values
      .map((item) => item.trim().toUpperCase())
      .filter(Boolean)
      .slice(0, 50);
    updateSelectedToolParameters({ pocCodes: codes, allPocs: undefined });
  },
});

const pocOptions = ref<VulnerabilityDefinition[]>([]);
const pocLoading = ref(false);
let pocLoadGeneration = 0;

function scannerSourceForTool(tool?: string): "NUCLEI" | "AFROG" | "XRAY" | undefined {
  if (tool === "nuclei_scan") return "NUCLEI";
  if (tool === "afrog_scan") return "AFROG";
  if (tool === "xray_scan") return "XRAY";
  return undefined;
}

function formatPocOptionLabel(item: VulnerabilityDefinition) {
  return `${item.sourceExternalId || item.vulnerabilityCode} · ${item.name}`;
}

function pocSeverityTagType(severity?: string) {
  if (severity === "CRITICAL" || severity === "HIGH") return "danger";
  if (severity === "MEDIUM") return "warning";
  if (severity === "LOW") return "info";
  return "success";
}

async function loadPocOptionsForTool(search = "") {
  const tool = selectedToolNode.value?.data.tool;
  const source = scannerSourceForTool(tool);
  if (!source) {
    pocOptions.value = [];
    return;
  }
  const generation = ++pocLoadGeneration;
  pocLoading.value = true;
  try {
    const { data } = await endpoints.vulnerabilities({
      page: 0,
      size: 150,
      source,
      query: search.trim() || undefined,
    });
    if (generation !== pocLoadGeneration) return;

    const currentCodes = selectedPocCodesList.value;
    const merged = new Map<string, VulnerabilityDefinition>();
    for (const item of pocOptions.value) {
      if (currentCodes.includes(item.vulnerabilityCode)) {
        merged.set(item.vulnerabilityCode, item);
      }
    }
    for (const item of data.content || []) {
      merged.set(item.vulnerabilityCode, item);
    }
    pocOptions.value = [...merged.values()];
  } catch {
    if (generation === pocLoadGeneration) {
      pocOptions.value = [];
    }
  } finally {
    if (generation === pocLoadGeneration) {
      pocLoading.value = false;
    }
  }
}

watch(
  () => selectedToolNode.value?.data.tool,
  (tool) => {
    if (tool && scannerSourceForTool(tool)) {
      void loadPocOptionsForTool();
    } else {
      pocOptions.value = [];
    }
  },
  { immediate: true },
);

function makeNode(
  id: string,
  kind: NodeKind,
  phase: PhaseCode,
  position: { x: number; y: number },
  label?: string,
  tool?: string,
  parameters?: Record<string, unknown>,
): EditorNode {
  const system = kind === "system";
  return {
    id,
    type: "workflowNode",
    position,
    data: nodeData(kind, phase, label, tool, parameters),
    draggable: !system,
    selectable: true,
    connectable: true,
    deletable: !system,
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
  };
}

function makeEdge(
  source: string,
  target: string,
  id = `edge-${source}-${target}`,
): Edge {
  return {
    id,
    source,
    target,
    type: "workflowEdge",
    markerEnd: MarkerType.ArrowClosed,
    animated: false,
  };
}

function phaseToolMap(code: PresetCode): Record<PhaseCode, string[]> {
  if (code === "quick-web")
    return {
      engagement: [],
      recon: ["retrieve_project_context"],
      mapping: ["http_headers", "tls_config"],
      discovery: [
        "http_security_check",
        "fscan_scan",
        "nuclei_scan",
        "afrog_scan",
        "xray_scan",
      ],
      validation: [],
      impact: [],
      retest: [],
      report: [],
    };
  if (code === "asset-inventory")
    return {
      engagement: [],
      recon: ["retrieve_project_context"],
      mapping: ["nmap_service_scan", "fscan_scan", "http_headers", "tls_config"],
      discovery: [],
      validation: [],
      impact: [],
      retest: [],
      report: [],
    };
  if (code === "retest")
    return {
      engagement: [],
      recon: ["retrieve_project_context"],
      mapping: [],
      discovery: [],
      validation: ["http_security_check"],
      impact: [],
      retest: ["http_security_check", "nuclei_scan", "afrog_scan", "xray_scan"],
      report: [],
    };
  return {
    engagement: [],
    recon: ["retrieve_project_context"],
    mapping: ["nmap_service_scan", "http_headers", "tls_config"],
    discovery: [
      "http_security_check",
      "fscan_scan",
      "nuclei_scan",
      "afrog_scan",
      "xray_scan",
    ],
    validation: [],
    impact: [],
    retest: [],
    report: [],
  };
}

function emptyPhaseToolMap(): Record<PhaseCode, string[]> {
  return {
    engagement: [],
    recon: [],
    mapping: [],
    discovery: [],
    validation: [],
    impact: [],
    retest: [],
    report: [],
  };
}

function buildPreset(code: PresetCode, retainedSteps?: WorkflowStepSpec[]) {
  const tools = retainedSteps?.length
    ? emptyPhaseToolMap()
    : phaseToolMap(code);
  const migrated = retainedSteps?.length ? retainedSteps : [];
  const migratedByTool = new Map<string, WorkflowStepSpec[]>();
  if (migrated.length) {
    migrated.forEach((step) => {
      const phase = inferPhase(step.tool);
      tools[phase].push(step.tool);
      migratedByTool.set(step.tool, [
        ...(migratedByTool.get(step.tool) || []),
        step,
      ]);
    });
  }
  const resultNodes: EditorNode[] = [];
  const resultEdges: Edge[] = [];
  resultNodes.push(
    makeNode(
      "__start__",
      "system",
      "engagement",
      { x: WORKFLOW_LAYOUT.startX, y: WORKFLOW_LAYOUT.phaseY + 18 },
      "开始",
    ),
  );
  PHASES.forEach((phase, index) => {
    const x = WORKFLOW_LAYOUT.phaseStartX + index * WORKFLOW_LAYOUT.phaseStepX;
    resultNodes.push(
      makeNode(phaseNodeId(phase.code), "phase", phase.code, {
        x,
        y: WORKFLOW_LAYOUT.phaseY,
      }),
    );
  });
  resultNodes.push(
    makeNode(
      "__end__",
      "system",
      "report",
      {
        x:
          WORKFLOW_LAYOUT.phaseStartX +
          PHASES.length * WORKFLOW_LAYOUT.phaseStepX,
        y: WORKFLOW_LAYOUT.phaseY + 18,
      },
      "结束",
    ),
  );

  // Each phase has a stable milestone node. Tool nodes branch from that
  // milestone and converge on the next phase, making parallel execution visible.
  resultEdges.push(makeEdge("__start__", phaseNodeId(PHASES[0].code)));
  PHASES.forEach((phase, index) => {
    const milestone = phaseNodeId(phase.code);
    const next =
      index < PHASES.length - 1
        ? phaseNodeId(PHASES[index + 1].code)
        : "__end__";
    const phaseTools = tools[phase.code] || [];
    const counts = new Map<string, number>();
    const phaseToolNodeIds: string[] = [];
    phaseTools.forEach((tool, toolIndex) => {
      const occurrence = (counts.get(tool) || 0) + 1;
      counts.set(tool, occurrence);
      const agent = agentOf(tool);
      if (!agent) return;
      const id = `tool-${safeId(tool)}-${phase.code}-${occurrence}`;
      const migratedStep = migratedByTool.get(tool)?.[occurrence - 1];
      resultNodes.push(
        makeNode(
          id,
          "tool",
          phase.code,
          {
            x:
              WORKFLOW_LAYOUT.phaseStartX +
              index * WORKFLOW_LAYOUT.phaseStepX +
              WORKFLOW_LAYOUT.toolOffsetX,
            y: workflowToolY(toolIndex, phaseTools.length),
          },
          undefined,
          tool,
          migratedStep?.parameters,
        ),
      );
      phaseToolNodeIds.push(id);
    });
    if (!phaseToolNodeIds.length) {
      resultEdges.push(makeEdge(milestone, next));
    } else if (phaseTools.some((tool) => agentOf(tool)?.risk === "CAUTION")) {
      let upstream = milestone;
      phaseToolNodeIds.forEach((id) => {
        resultEdges.push(makeEdge(upstream, id));
        upstream = id;
      });
      resultEdges.push(makeEdge(upstream, next));
    } else {
      phaseToolNodeIds.forEach((id) => {
        resultEdges.push(makeEdge(milestone, id));
        resultEdges.push(makeEdge(id, next));
      });
    }
  });
  pushHistory();
  nodes.value = resultNodes;
  edges.value = dedupeEdges(resultEdges);
  selectedNodeId.value = "";
  selectedEdgeId.value = "";
  graphValidation.value = [];
  graphNotice.value = `${PRESETS.find((item) => item.value === code)?.label || "红队评估"}已载入，可拖动节点并手动连接依赖。`;
  void refit("start");
}

function inferPhase(tool?: string): PhaseCode {
  if (tool === "retrieve_project_context") return "recon";
  if (
    tool === "http_security_check" ||
    tool === "nuclei_scan" ||
    tool === "afrog_scan" ||
    tool === "xray_scan" ||
    tool === "fscan_scan"
  )
    return "discovery";
  if (tool) return "mapping";
  return "validation";
}

function dedupeEdges(items: Edge[]) {
  const seen = new Set<string>();
  return items.filter((edge) => {
    const key = `${edge.source}->${edge.target}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function graphSpecNodes(): WorkflowGraphNodeSpec[] {
  return nodes.value.map((node) => ({
    id: node.id,
    type: node.data.nodeKind,
    label: node.data.label,
    phase: node.data.phase,
    ...(node.data.tool ? { tool: node.data.tool } : {}),
    position: {
      x: Math.round(node.position.x),
      y: Math.round(node.position.y),
    },
  }));
}

function graphSpecEdges(): WorkflowGraphEdgeSpec[] {
  return edges.value.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
  }));
}

function topologicalGroups() {
  const indegree = new Map(nodes.value.map((node) => [node.id, 0]));
  const outgoing = new Map<string, string[]>();
  edges.value.forEach((edge) => {
    if (!indegree.has(edge.source) || !indegree.has(edge.target)) return;
    indegree.set(edge.target, (indegree.get(edge.target) || 0) + 1);
    if (!outgoing.has(edge.source)) outgoing.set(edge.source, []);
    outgoing.get(edge.source)!.push(edge.target);
  });
  const queue = nodes.value
    .filter((node) => (indegree.get(node.id) || 0) === 0)
    .map((node) => node.id);
  const order: string[] = [];
  while (queue.length) {
    const id = queue.shift()!;
    order.push(id);
    (outgoing.get(id) || []).forEach((target) => {
      const next = (indegree.get(target) || 0) - 1;
      indegree.set(target, next);
      if (next === 0) queue.push(target);
    });
  }
  const level = new Map<string, number>(
    nodes.value.map((node) => [node.id, 0]),
  );
  order.forEach((id) => {
    const upstream = edges.value
      .filter((edge) => edge.target === id)
      .map((edge) => level.get(edge.source) || 0);
    const node = nodes.value.find((item) => item.id === id);
    level.set(
      id,
      node?.data.nodeKind === "tool"
        ? upstream.length
          ? Math.max(...upstream) + 1
          : 0
        : upstream.length
          ? Math.max(...upstream)
          : 0,
    );
  });
  return { order, level, acyclic: order.length === nodes.value.length };
}

function validateGraph() {
  const problems: string[] = [];
  const ids = new Set(nodes.value.map((node) => node.id));
  const start = nodes.value.find((node) => node.id === "__start__");
  const end = nodes.value.find((node) => node.id === "__end__");
  if (!start || !end) problems.push("必须保留固定的开始和结束节点");
  if (!nodes.value.some((node) => node.data.nodeKind === "phase"))
    problems.push("至少保留一个红队阶段节点");
  const seenConnections = new Set<string>();
  edges.value.forEach((edge) => {
    const key = `${edge.source}->${edge.target}`;
    if (!ids.has(edge.source) || !ids.has(edge.target))
      problems.push("存在指向不存在节点的连线");
    if (edge.source === edge.target) problems.push("不能连接节点自身");
    if (seenConnections.has(key)) problems.push("存在重复连线");
    seenConnections.add(key);
    if (edge.target === "__start__") problems.push("开始节点不能作为连线终点");
    if (edge.source === "__end__") problems.push("结束节点不能作为连线起点");
  });
  const incoming = new Map<string, number>(
    nodes.value.map((node) => [node.id, 0]),
  );
  const outgoing = new Map<string, number>(
    nodes.value.map((node) => [node.id, 0]),
  );
  edges.value.forEach((edge) => {
    incoming.set(edge.target, (incoming.get(edge.target) || 0) + 1);
    outgoing.set(edge.source, (outgoing.get(edge.source) || 0) + 1);
  });
  nodes.value.forEach((node) => {
    if (node.id !== "__start__" && (incoming.get(node.id) || 0) === 0)
      problems.push(`节点“${node.data.label}”没有上游依赖`);
    if (node.id !== "__end__" && (outgoing.get(node.id) || 0) === 0)
      problems.push(`节点“${node.data.label}”没有下游依赖`);
  });
  const topo = topologicalGroups();
  if (!topo.acyclic) problems.push("连线形成了环路，请调整依赖方向");
  const reachable = new Set<string>(["__start__"]);
  let changed = true;
  while (changed) {
    changed = false;
    edges.value.forEach((edge) => {
      if (reachable.has(edge.source) && !reachable.has(edge.target)) {
        reachable.add(edge.target);
        changed = true;
      }
    });
  }
  if (!reachable.has("__end__")) problems.push("开始节点无法到达结束节点");
  nodes.value.forEach((node) => {
    if (!reachable.has(node.id))
      problems.push(`节点“${node.data.label}”不在开始到结束的路径上`);
  });
  graphValidation.value = [...new Set(problems)];
  return graphValidation.value;
}

function onConnect(connection: Connection) {
  if (!connection.source || !connection.target) return;
  if (connection.source === connection.target) {
    ElMessage.warning("不能连接节点自身");
    return;
  }
  if (connection.target === "__start__" || connection.source === "__end__") {
    ElMessage.warning("开始只能出发，结束只能到达");
    return;
  }
  if (
    edges.value.some(
      (edge) =>
        edge.source === connection.source && edge.target === connection.target,
    )
  ) {
    ElMessage.info("这条依赖已经存在");
    return;
  }
  const edgeId = uniqueEdgeId(connection.source, connection.target);
  pushHistory();
  edges.value = [
    ...edges.value,
    makeEdge(connection.source, connection.target, edgeId),
  ];
  const check = validateGraph();
  if (check.some((item) => item.includes("环路"))) {
    edges.value = edges.value.filter((edge) => edge.id !== edgeId);
    ElMessage.warning("这条连线会形成环路，已撤销");
  }
}

function uniqueEdgeId(source: string, target: string) {
  const base = `edge-${safeId(source)}-${safeId(target)}`;
  const ids = new Set(edges.value.map((edge) => edge.id));
  let id = base;
  let index = 2;
  while (ids.has(id)) {
    id = `${base}-${index}`;
    index += 1;
  }
  return id;
}

function snapshotGraph(): HistorySnapshot {
  return {
    nodes: JSON.parse(JSON.stringify(nodes.value)),
    edges: JSON.parse(JSON.stringify(edges.value)),
  };
}
function graphsEqual(a: HistorySnapshot, b: HistorySnapshot) {
  return (
    JSON.stringify(a.nodes) === JSON.stringify(b.nodes) &&
    JSON.stringify(a.edges) === JSON.stringify(b.edges)
  );
}
// 记录一次图结构/位置变更前的快照。堆顶内容相同则合并，避免连续操作重复入栈。
// 可直接传入变更前的快照（用于拖动这类“先捕获再变更”的场景）。
function pushHistory(before?: HistorySnapshot) {
  if (viewingRunSnapshot.value || executing.value) return;
  const snap = before || snapshotGraph();
  const top = graphHistory.value[graphHistory.value.length - 1];
  if (top && graphsEqual(top, snap)) return;
  graphHistory.value = [...graphHistory.value.slice(-(UNDO_LIMIT - 1)), snap];
  graphFuture.value = [];
}
function restoreSnapshotStates(snapshot: HistorySnapshot) {
  nodes.value = snapshot.nodes;
  edges.value = snapshot.edges;
  selectedEdgeId.value = "";
  selectedNodeId.value = "";
  selectedNodeIds.value = [];
  validateGraph();
}
function undoGraph() {
  const prev = graphHistory.value.pop();
  if (!prev) {
    ElMessage.info("没有可撤销的操作");
    return;
  }
  const current = snapshotGraph();
  graphFuture.value = [...graphFuture.value, current];
  restoreSnapshotStates(prev);
}
function redoGraph() {
  const next = graphFuture.value.pop();
  if (!next) {
    ElMessage.info("没有可重做的操作");
    return;
  }
  const current = snapshotGraph();
  graphHistory.value = [...graphHistory.value, current];
  restoreSnapshotStates(next);
}

function onNodeClick(event: NodeMouseEvent) {
  closeWorkflowContextMenu();
  const isMulti = Boolean(
    event.event.ctrlKey || event.event.metaKey || event.event.shiftKey,
  );
  void selectCanvasNode(event.node.id, isMulti);
}
function selectNode(id: string, additive = false) {
  if (additive) {
    if (selectedNodeIds.value.includes(id)) {
      selectedNodeIds.value = selectedNodeIds.value.filter((i) => i !== id);
      selectedNodeId.value =
        selectedNodeIds.value[selectedNodeIds.value.length - 1] || "";
    } else {
      selectedNodeIds.value = [...selectedNodeIds.value, id];
      selectedNodeId.value = id;
    }
  } else {
    // 若该节点已经是当前多选集合的一员，点击/拖动时保持整个多选，
    // 避免拖动等交互触发单击把多选塌缩成单节点，导致无法批量原地克隆。
    const keepMulti =
      selectedNodeIds.value.length > 1 &&
      selectedNodeIds.value.includes(id);
    if (keepMulti) {
      selectedNodeId.value = id;
    } else {
      selectedNodeId.value = id;
      selectedNodeIds.value = id ? [id] : [];
    }
  }
  setSelectedEdge("");
}

function onSelectionChange(params: { nodes: Node[]; edges: Edge[] }) {
  const nodeIds = params.nodes.map((n) => n.id);
  selectedNodeIds.value = nodeIds;
  if (nodeIds.length === 1) {
    selectedNodeId.value = nodeIds[0];
  } else if (nodeIds.length > 1) {
    if (!selectedNodeId.value || !nodeIds.includes(selectedNodeId.value)) {
      selectedNodeId.value = nodeIds[0];
    }
  }
}
function nextAnimationFrame() {
  return new Promise<void>((resolve) =>
    window.requestAnimationFrame(() => resolve()),
  );
}
async function waitForLibrarySectionLayout(sectionId: string) {
  await nextTick();
  const section = libraryScroll.value?.querySelector<HTMLElement>(
    `#${sectionId}`,
  );
  const animations = section?.getAnimations({ subtree: true }) || [];
  if (animations.length) {
    await Promise.race([
      Promise.all(
        animations.map((animation) =>
          animation.finished.catch(() => undefined),
        ),
      ),
      new Promise<void>((resolve) => window.setTimeout(resolve, 260)),
    ]);
  } else {
    // Some browsers remove a just-finished CSS transition before getAnimations()
    // observes it. Keep a bounded fallback for the 160 ms grid expansion.
    await new Promise<void>((resolve) => window.setTimeout(resolve, 180));
  }
  await nextAnimationFrame();
  await nextAnimationFrame();
}
async function selectCanvasNode(id: string, additive = false) {
  selectNode(id, additive);
  const node = nodes.value.find((item) => item.id === id);
  if (!node || node.data.nodeKind === "system") return;

  const tool = node.data.tool;
  selectedPhase.value = tool
    ? agentOf(tool)?.phase || node.data.phase
    : node.data.phase;
  // Canvas selection always follows the executable capability library. Keep
  // the phase section in the state chosen by the user instead of reopening it
  // when a phase node is clicked.
  capabilityLibraryExpanded.value = true;

  if (rightSidebarTab.value === "library") {
  await waitForLibrarySectionLayout("workflow-capability-library-body");
  if (selectedNodeId.value !== id) return;
  const library = libraryScroll.value;
  if (!library) return;
  const target = tool
    ? Array.from(library.querySelectorAll<HTMLElement>(".library-item")).find(
        (item) => item.dataset.tool === tool,
      )
    : library.querySelector<HTMLElement>(".capability-library .library-item") ||
      library.querySelector<HTMLElement>(".capability-library-head");
  if (target) {
    // The library is a nested scroll container. Relying on scrollIntoView can
    // scroll the page instead of the library when the canvas is zoomed, leaving
    // the selected card partly below the library viewport. Calculate the target
    // position against this container so the whole card is visible immediately.
    const scrollTargetIntoLibrary = () => {
      const libraryBounds = library.getBoundingClientRect();
      const targetBounds = target.getBoundingClientRect();
      const targetTop =
        library.scrollTop + targetBounds.top - libraryBounds.top;
      const centeredTop =
        targetTop -
        Math.max(0, (library.clientHeight - targetBounds.height) / 2);
      library.scrollTo({
        top: Math.max(0, centeredTop),
        behavior: "auto",
      });
    };
    scrollTargetIntoLibrary();
    await nextAnimationFrame();
    const libraryBounds = library.getBoundingClientRect();
    const targetBounds = target.getBoundingClientRect();
    if (
      targetBounds.top < libraryBounds.top ||
      targetBounds.bottom > libraryBounds.bottom
    ) {
      scrollTargetIntoLibrary();
    }
  }
  } else {
    await nextTick();
    libraryScroll.value?.scrollTo({ top: 0, behavior: "auto" });
  }
}
function onEdgeClick(event: { edge: Edge }) {
  closeWorkflowContextMenu();
  setSelectedEdge(event.edge.id);
  selectedNodeId.value = "";
}
function onEdgeMouseEnter(payload: EdgeMouseEvent) {
  hoveredEdgeId.value = payload.edge.id;
}
function onEdgeMouseLeave() {
  hoveredEdgeId.value = "";
}
function onRemoveEdge(edgeId: string) {
  removeEdge(edgeId, true);
}
function onPaneClick() {
  closeWorkflowContextMenu();
  selectedNodeId.value = "";
  selectedNodeIds.value = [];
  setSelectedEdge("");
}

function closeWorkflowContextMenu() {
  workflowContextMenu.value.visible = false;
  workflowContextMenu.value.nodeId = "";
}

function showWorkflowContextMenu(event: MouseEvent, nodeId = "") {
  event.preventDefault();
  event.stopPropagation();
  const canvas = flowCanvas.value;
  if (!canvas) return;
  const bounds = canvas.getBoundingClientRect();
  const menuWidth = 208;
  const hasClipboard = !!clipboardNode.value;
  // 节点菜单：复制 + 配置/详情/删除；空白菜单：粘贴 + 配置等
  const menuHeight = nodeId ? (hasClipboard ? 176 : 144) + (nodeRuns.value[nodeId] ? 36 : 0) : hasClipboard ? 232 : 196;
  workflowConfigVisible.value = false;
  workflowContextMenu.value = {
    visible: true,
    x: Math.min(
      Math.max(event.clientX - bounds.left, 8),
      Math.max(8, bounds.width - menuWidth - 8),
    ),
    y: Math.min(
      Math.max(event.clientY - bounds.top, 8),
      Math.max(8, bounds.height - menuHeight - 8),
    ),
    nodeId,
  };
  if (!nodeId) {
    lastPaneContextPoint.value = { x: event.clientX, y: event.clientY };
  }
}

function onPaneContextMenu(event: MouseEvent) {
  selectedNodeId.value = "";
  setSelectedEdge("");
  lastPaneContextPoint.value = { x: event.clientX, y: event.clientY };
  showWorkflowContextMenu(event);
}

function onNodeContextMenu(event: NodeMouseEvent) {
  if (!(event.event instanceof MouseEvent)) return;
  selectNode(event.node.id);
  showWorkflowContextMenu(event.event, event.node.id);
}

function openWorkflowConfig() {
  closeWorkflowContextMenu();
  workflowConfigVisible.value = true;
}

async function configureContextNode() {
  const node = contextMenuNode.value;
  if (!node || node.id === "__start__") {
    openWorkflowConfig();
    return;
  }
  selectNode(node.id);
  selectedPhase.value = node.data.phase;
  rightSidebarTab.value = "node";
  closeWorkflowContextMenu();
  if (node.data.nodeKind !== "tool") return;
  await nextTick();
  const library = libraryScroll.value;
  if (!library || !nodeInputEditor.value) return;
  library.scrollTo({ top: 0, behavior: "smooth" });
  const bounds = library.getBoundingClientRect();
  if (bounds.bottom < 0 || bounds.top > window.innerHeight) {
    library.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

function openTargetInputFromCanvas() {
  closeWorkflowContextMenu();
  openTargetInput();
}

function showGuideFromCanvas() {
  closeWorkflowContextMenu();
  showGuide.value = true;
}

async function loadPresetFromContextMenu() {
  closeWorkflowContextMenu();
  await resetPreset();
}

function openContextNodeDetail() {
  const nodeId = contextMenuNode.value?.id;
  closeWorkflowContextMenu();
  if (nodeId) openNodeDetail(nodeId);
}

function fitWorkflowFromContextMenu() {
  closeWorkflowContextMenu();
  fitWorkflowCanvas();
}

function deleteContextNode() {
  const nodeId = contextMenuNode.value?.id;
  closeWorkflowContextMenu();
  if (nodeId) removeNode(nodeId);
}

function flowSelectedNodeIds(): string[] {
  // nodeLookup 反映 VueFlow 实时内部节点（含选中态），用它取框选结果最可靠，
  // 避免 app 的 selectedNodeIds 被框选后的单击/拖尾清空或塌缩。
  return Array.from(nodeLookup.value.values())
    .filter((n) => n.selected)
    .map((n) => n.id);
}
function setFlowSelection(ids: string[]) {
  const wanted = new Set(ids);
  nodeLookup.value.forEach((n) => {
    n.selected = wanted.has(n.id);
  });
}

function canCopyNode(node?: EditorNode | null) {
  const nodeSelectedIds = flowSelectedNodeIds();
  const activeIds = node
    ? [node.id]
    : [
        ...nodeSelectedIds,
        ...selectedNodeIds.value,
        ...(selectedNodeId.value ? [selectedNodeId.value] : []),
      ];
  const targets = [...new Set(activeIds)]
    .map((id) => nodes.value.find((n) => n.id === id))
    .filter((n): n is EditorNode => Boolean(n));
  if (!targets.length) return false;
  if (viewingRunSnapshot.value || executing.value) return false;
  // 只要选中集合里有可复制的节点即可复制，开始/结束节点会被 copySelectedNodes 跳过
  return targets.some(
    (n) => n.id !== "__start__" && n.id !== "__end__",
  );
}

function copyAndPasteNode(
  nodeId?: string,
  atFlowPosition?: { x: number; y: number },
) {
  const sourceId = nodeId || selectedNodeId.value || contextMenuNode.value?.id;
  const source = nodes.value.find((n) => n.id === sourceId);
  if (!source) {
    ElMessage.warning("请先选择要复制的节点");
    return null;
  }
  if (source.id === "__start__" || source.id === "__end__") {
    ElMessage.warning("开始和结束节点不可复制");
    return null;
  }
  if (viewingRunSnapshot.value) {
    ElMessage.warning("历史拓扑不可复制");
    return null;
  }
  if (
    source.data.nodeKind === "phase" &&
    hasCanonicalPhaseNode(source.data.phase as PhaseCode)
  ) {
    ElMessage.warning(
      `${phaseOf(source.data.phase as PhaseCode).shortLabel}阶段已在画布中，无法重复创建`,
    );
    return null;
  }
  clipboardNode.value = {
    ...source,
    data: JSON.parse(JSON.stringify(source.data)),
    position: { ...source.position },
  } as EditorNode;
  const newNode = pasteNode(atFlowPosition);
  if (newNode) {
    ElMessage.success(`已复制并创建“${newNode.data.label}”`);
  }
  return newNode;
}

function copyNode(nodeId?: string) {
  return copyAndPasteNode(nodeId);
}

function copyContextNode() {
  const nodeId = contextMenuNode.value?.id;
  if (nodeId) copyAndPasteNode(nodeId);
  closeWorkflowContextMenu();
}

function pasteNode(atFlowPosition?: { x: number; y: number }) {
  const source = clipboardNode.value;
  if (!source) {
    ElMessage.warning("剪贴板为空，请先复制节点");
    return null;
  }
  if (viewingRunSnapshot.value) {
    ElMessage.warning("历史拓扑不可粘贴");
    return null;
  }
  if (source.data.nodeKind === "phase") {
    const phase = source.data.phase as PhaseCode;
    if (hasCanonicalPhaseNode(phase)) {
      ElMessage.warning(`${phaseOf(phase).shortLabel}阶段已在画布中，无法重复粘贴`);
      return null;
    }
  }
  let newId: string;
  if (source.data.nodeKind === "tool" && source.data.tool) {
    newId = uniqueId(`tool-${safeId(source.data.tool)}-${source.data.phase}`);
  } else if (source.data.nodeKind === "phase") {
    newId = phaseNodeId(source.data.phase as PhaseCode);
  } else {
    newId = uniqueId(`node-${safeId(source.data.label)}`);
  }
  const offset = 36 + pasteOffset.value * 18;
  const basePos = atFlowPosition
    ? { x: atFlowPosition.x, y: atFlowPosition.y }
    : { x: source.position.x + offset, y: source.position.y + offset };
  pasteOffset.value = (pasteOffset.value + 1) % 8;
  const parameters = source.data.parameters ? JSON.parse(JSON.stringify(source.data.parameters)) : undefined;
  const newNode = makeNode(
    newId,
    source.data.nodeKind,
    source.data.phase,
    basePos,
    source.data.label,
    source.data.tool,
    parameters,
  );
  pushHistory();
  nodes.value = [...nodes.value, newNode];
  selectedNodeId.value = newId;
  selectedPhase.value = newNode.data.phase as PhaseCode;
  setFlowSelection([newId]);
  setSelectedEdge("");
  validateGraph();
  graphNotice.value = `已复制并创建“${newNode.data.label}”`;
  return newNode;
}

function pasteFromContextMenu() {
  const point = lastPaneContextPoint.value
    ? screenToFlowCoordinate({ x: lastPaneContextPoint.value.x, y: lastPaneContextPoint.value.y })
    : undefined;
  closeWorkflowContextMenu();
  pasteNode(point || undefined);
}

interface AlignRect {
  x: number;
  y: number;
  w: number;
  h: number;
}
const ALIGN_EDGES_WIDTH = 220;
const ALIGN_EDGES_HEIGHT = 120;

function alignRectOf(node: GraphNode): AlignRect {
  const w =
    node.dimensions?.width && node.dimensions.width > 0
      ? node.dimensions.width
      : ALIGN_EDGES_WIDTH;
  const h =
    node.dimensions?.height && node.dimensions.height > 0
      ? node.dimensions.height
      : ALIGN_EDGES_HEIGHT;
  const pos = node.position;
  return { x: pos.x, y: pos.y, w, h };
}

interface AlignCandidate {
  delta: number;
  guide: number;
  node: GraphNode;
  rect: AlignRect;
}

function resolveAlignCandidate(
  draggedRect: AlignRect,
  target: GraphNode,
  axis: "x" | "y",
): AlignCandidate | null {
  const rect = alignRectOf(target);
  const dEdges =
    axis === "x"
      ? [draggedRect.x, draggedRect.x + draggedRect.w / 2, draggedRect.x + draggedRect.w]
      : [draggedRect.y, draggedRect.y + draggedRect.h / 2, draggedRect.y + draggedRect.h];
  const tEdges =
    axis === "x"
      ? [rect.x, rect.x + rect.w / 2, rect.x + rect.w]
      : [rect.y, rect.y + rect.h / 2, rect.y + rect.h];
  let best: AlignCandidate | null = null;
  for (let s = 0; s < 3; s++) {
    for (let t = 0; t < 3; t++) {
      const delta = tEdges[t] - dEdges[s];
      if (Math.abs(delta) > ALIGN_SNAP_DISTANCE) continue;
      if (!best || Math.abs(delta) < Math.abs(best.delta)) {
        best = { delta, guide: tEdges[t], node: target, rect };
      }
    }
  }
  return best;
}

function buildAlignRuler(
  rulers: AlignRuler[],
  dragged: AlignRect,
  target: AlignRect,
  axis: "x" | "y",
) {
  const gap =
    axis === "x"
      ? target.x - (dragged.x + dragged.w)
      : target.y - (dragged.y + dragged.h);
  if (gap <= 0) return;
  const label = `${Math.round(gap)}px`;
  if (axis === "x") {
    const top = Math.min(dragged.y, target.y) - 28;
    rulers.push({
      axis,
      x1: dragged.x + dragged.w,
      y1: top,
      x2: dragged.x + dragged.w + gap,
      y2: top,
      x: dragged.x + dragged.w + gap / 2,
      y: top - 6,
      label,
    });
  } else {
    const left = Math.min(dragged.x, target.x) - 28;
    rulers.push({
      axis,
      x1: left,
      y1: dragged.y + dragged.h,
      x2: left,
      y2: dragged.y + dragged.h + gap,
      x: left - 6,
      y: dragged.y + dragged.h + gap / 2,
      label,
    });
  }
}

function buildDistanceRulers(
  rulers: AlignRuler[],
  dragged: AlignRect,
  targets: GraphNode[],
) {
  let leftRect: AlignRect | null = null;
  let rightRect: AlignRect | null = null;
  let topRect: AlignRect | null = null;
  let bottomRect: AlignRect | null = null;
  let leftDist = -1;
  let rightDist = -1;
  let topDist = -1;
  let bottomDist = -1;
  for (const t of targets) {
    const r = alignRectOf(t);
    const yOverlap = dragged.y < r.y + r.h && dragged.y + dragged.h > r.y;
    const xOverlap = dragged.x < r.x + r.w && dragged.x + dragged.w > r.x;
    if (yOverlap) {
      const gapL = dragged.x - (r.x + r.w);
      if (gapL >= 0 && (leftDist < 0 || gapL < leftDist)) {
        leftDist = gapL;
        leftRect = r;
      }
      const gapR = r.x - (dragged.x + dragged.w);
      if (gapR >= 0 && (rightDist < 0 || gapR < rightDist)) {
        rightDist = gapR;
        rightRect = r;
      }
    }
    if (xOverlap) {
      const gapT = dragged.y - (r.y + r.h);
      if (gapT >= 0 && (topDist < 0 || gapT < topDist)) {
        topDist = gapT;
        topRect = r;
      }
      const gapB = r.y - (dragged.y + dragged.h);
      if (gapB >= 0 && (bottomDist < 0 || gapB < bottomDist)) {
        bottomDist = gapB;
        bottomRect = r;
      }
    }
  }
  const midY = (dragged.y + dragged.h) / 2;
  const midX = (dragged.x + dragged.w) / 2;
  if (leftRect) pushGapRuler(rulers, "x", leftRect.x + leftRect.w, dragged.x, midY - 12);
  if (rightRect) pushGapRuler(rulers, "x", dragged.x + dragged.w, rightRect.x, midY + 12);
  if (topRect) pushGapRuler(rulers, "y", topRect.y + topRect.h, dragged.y, midX - 12);
  if (bottomRect) pushGapRuler(rulers, "y", dragged.y + dragged.h, bottomRect.y, midX + 12);
}

function pushGapRuler(
  rulers: AlignRuler[],
  axis: "x" | "y",
  a: number,
  b: number,
  cross: number,
) {
  const gap = Math.abs(b - a);
  if (gap <= 0) return;
  const label = `${Math.round(gap)}px`;
  if (axis === "x") {
    rulers.push({
      axis,
      x1: Math.min(a, b),
      y1: cross,
      x2: Math.max(a, b),
      y2: cross,
      x: (a + b) / 2,
      y: cross - 6,
      label,
    });
  } else {
    rulers.push({
      axis,
      x1: cross,
      y1: Math.min(a, b),
      x2: cross,
      y2: Math.max(a, b),
      x: cross - 6,
      y: (a + b) / 2,
      label,
    });
  }
}

interface SpacingCandidate {
  delta: number;
  axis: "x" | "y";
  a: AlignRect;
  b: AlignRect | null;
  gap: number;
  mode: "center" | "side";
  reverse?: boolean;
}

function guideVertical(
  guides: AlignGuideSegment[],
  x: number,
  y1: number,
  y2: number,
) {
  guides.push({ axis: "x", x1: x, y1, x2: x, y2 });
}
function guideH(
  guides: AlignGuideSegment[],
  y: number,
  x1: number,
  x2: number,
) {
  guides.push({ axis: "y", x1, y1: y, x2, y2: y });
}

function resolveSpacingCandidate(
  dragged: AlignRect,
  targets: GraphNode[],
  axis: "x" | "y",
): SpacingCandidate | null {
  let near: AlignRect | null = null; // 负方向邻居（左/上）
  let far: AlignRect | null = null; // 正方向邻居（右/下）
  for (const t of targets) {
    const r = alignRectOf(t);
    if (axis === "x") {
      const overlap = dragged.y < r.y + r.h && dragged.y + dragged.h > r.y;
      if (!overlap) continue;
      if (r.x + r.w <= dragged.x) {
        if (!near || dragged.x - (r.x + r.w) < dragged.x - (near.x + near.w)) {
          near = r;
        }
      } else if (r.x >= dragged.x + dragged.w) {
        if (!far || r.x - (dragged.x + dragged.w) < far.x - (dragged.x + dragged.w)) {
          far = r;
        }
      }
    } else {
      const overlap = dragged.x < r.x + r.w && dragged.x + dragged.w > r.x;
      if (!overlap) continue;
      if (r.y + r.h <= dragged.y) {
        if (!near || dragged.y - (r.y + r.h) < dragged.y - (near.y + near.h)) {
          near = r;
        }
      } else if (r.y >= dragged.y + dragged.h) {
        if (!far || r.y - (dragged.y + dragged.h) < far.y - (dragged.y + dragged.h)) {
          far = r;
        }
      }
    }
  }
  const refGap = referenceGap(axis, targets);
  let best: SpacingCandidate | null = null;
  const push = (cand: SpacingCandidate) => {
    if (!best || Math.abs(cand.delta) < Math.abs(best.delta)) {
      best = cand;
    }
  };
  if (near && far) {
    const slack = axis === "x"
      ? far.x - (near.x + near.w) - dragged.w
      : far.y - (near.y + near.h) - dragged.h;
    const spanStart = axis === "x" ? near.x + near.w : near.y + near.h;
    const spanEnd = axis === "x" ? far.x : far.y;
    const wanted = axis === "x"
      ? (spanStart + spanEnd - dragged.w) / 2
      : (spanStart + spanEnd - dragged.h) / 2;
    const delta = wanted - (axis === "x" ? dragged.x : dragged.y);
    if (slack > 0 && Math.abs(delta) <= ALIGN_SNAP_DISTANCE) {
      push({ delta, axis, a: near, b: far, gap: slack / 2, mode: "center" });
    }
  }
  if (refGap > 0) {
    if (near) {
      const wanted = axis === "x"
        ? near.x + near.w + refGap
        : near.y + near.h + refGap;
      const delta = wanted - (axis === "x" ? dragged.x : dragged.y);
      if (Math.abs(delta) <= ALIGN_SNAP_DISTANCE) {
        push({ delta, axis, a: near, b: null, gap: refGap, mode: "side" });
      }
    } else if (far) {
      const wanted = axis === "x"
        ? far.x - refGap - dragged.w
        : far.y - refGap - dragged.h;
      const delta = wanted - (axis === "x" ? dragged.x : dragged.y);
      if (Math.abs(delta) <= ALIGN_SNAP_DISTANCE) {
        push({ delta, axis, a: far, b: null, gap: refGap, mode: "side", reverse: true });
      }
    }
  }
  return best;
}

function referenceGap(axis: "x" | "y", targets: GraphNode[]): number {
  const rects = targets.map((t) => alignRectOf(t));
  const overlap = (a: AlignRect, b: AlignRect) =>
    axis === "x"
      ? a.y < b.y + b.h && a.y + a.h > b.y
      : a.x < b.x + b.w && a.x + a.w > b.x;
  const led = (a: AlignRect) => (axis === "x" ? a.x + a.w : a.y + a.h);
  const start = (a: AlignRect) => (axis === "x" ? a.x : a.y);
  let min = Number.POSITIVE_INFINITY;
  for (let i = 0; i < rects.length; i++) {
    for (let j = 0; j < rects.length; j++) {
      if (i === j) continue;
      if (!overlap(rects[i], rects[j])) continue;
      const gap = start(rects[j]) - led(rects[i]);
      if (gap >= 0 && gap < min) {
        min = gap;
      }
    }
  }
  if (Number.isFinite(min)) return min;
  return axis === "x"
    ? WORKFLOW_LAYOUT.toolOffsetX - ALIGN_EDGES_WIDTH
    : WORKFLOW_LAYOUT.toolGapY;
}

function onNodeDragStart(event: NodeDragEvent) {
  pendingDragSnapshot = snapshotGraph();
  isAligning.value = Boolean(
    (event.event as MouseEvent).ctrlKey || (event.event as MouseEvent).metaKey,
  );
}

function onNodeDrag(event: NodeDragEvent) {
  if (viewingRunSnapshot.value || executing.value) return;
  const drag = nodeLookup.value.get(event.node.id);
  if (!drag) return;
  const active = Boolean(
    (event.event as MouseEvent).ctrlKey || (event.event as MouseEvent).metaKey,
  );
  isAligning.value = active;
  if (!active) {
    dragGuides.value = [];
    dragRulers.value = [];
    return;
  }

  const dragged = alignRectOf(drag);
  let xBest: AlignCandidate | SpacingCandidate | null = null;
  let yBest: AlignCandidate | SpacingCandidate | null = null;
  const targets: GraphNode[] = [];
  nodeLookup.value.forEach((node) => {
    if (node.id !== drag.id && node.data?.nodeKind !== "system") {
      targets.push(node);
    }
  });
  for (let ti = 0; ti < targets.length; ti++) {
    const node = targets[ti];
    const xCand = resolveAlignCandidate(dragged, node, "x");
    if (xCand && (!xBest || Math.abs(xCand.delta) < Math.abs(xBest.delta))) {
      xBest = xCand;
    }
    const yCand = resolveAlignCandidate(dragged, node, "y");
    if (yCand && (!yBest || Math.abs(yCand.delta) < Math.abs(yBest.delta))) {
      yBest = yCand;
    }
  }

  const xSpace = resolveSpacingCandidate(dragged, targets, "x");
  const ySpace = resolveSpacingCandidate(dragged, targets, "y");
  let xUseSpace = false;
  let yUseSpace = false;
  if (xSpace && (!xBest || Math.abs(xSpace.delta) <= Math.abs(xBest.delta))) {
    xBest = xSpace;
    xUseSpace = true;
  }
  if (ySpace && (!yBest || Math.abs(ySpace.delta) <= Math.abs(yBest.delta))) {
    yBest = ySpace;
    yUseSpace = true;
  }

  const snapX = xBest ? dragged.x + xBest.delta : dragged.x;
  const snapY = yBest ? dragged.y + yBest.delta : dragged.y;
  drag.position = { x: snapX, y: snapY };

  const guides: AlignGuideSegment[] = [];
  const rulers: AlignRuler[] = [];
  const EXT = 14;
  buildDistanceRulers(rulers, { ...dragged, x: snapX, y: snapY }, targets);

  if (xBest) {
    if (xUseSpace) {
      const sp = xBest as SpacingCandidate;
      const aLeading = sp.reverse ? sp.a.x : sp.a.x + sp.a.w;
      const top = Math.min(snapY, sp.a.y, sp.b ? sp.b.y : snapY) - EXT;
      const bottom = Math.max(
        snapY + dragged.h,
        sp.a.y + sp.a.h,
        sp.b ? sp.b.y + sp.b.h : snapY + dragged.h,
      ) + EXT;
      guideVertical(guides, aLeading, top, bottom);
      if (sp.mode === "center" && sp.b) {
        guideVertical(guides, sp.b.x, top, bottom);
      }
      const midY =
        (Math.min(snapY, sp.a.y, sp.b ? sp.b.y : snapY) +
          Math.max(snapY + dragged.h, sp.a.y + sp.a.h, sp.b ? sp.b.y + sp.b.h : snapY + dragged.h)) /
        2;
      pushGapRuler(rulers, "x", aLeading, sp.reverse ? snapX + dragged.w : snapX, midY - 18);
      if (sp.mode === "center" && sp.b) {
        pushGapRuler(rulers, "x", snapX + dragged.w, sp.b.x, midY - 18);
      }
    } else {
      const tr = (xBest as AlignCandidate).rect;
      const top = Math.min(snapY, tr.y) - EXT;
      const bottom = Math.max(snapY + dragged.h, tr.y + tr.h) + EXT;
      guides.push({
        axis: "x",
        x1: (xBest as AlignCandidate).guide,
        y1: top,
        x2: (xBest as AlignCandidate).guide,
        y2: bottom,
      });
      buildAlignRuler(rulers, dragged, tr, "x");
    }
  }
  if (yBest) {
    if (yUseSpace) {
      const sp = yBest as SpacingCandidate;
      const aLeading = sp.reverse ? sp.a.y : sp.a.y + sp.a.h;
      const lx = Math.min(snapX, sp.a.x, sp.b ? sp.b.x : snapX) - EXT;
      const rx = Math.max(
        snapX + dragged.w,
        sp.a.x + sp.a.w,
        sp.b ? sp.b.x + sp.b.w : snapX + dragged.w,
      ) + EXT;
      guideH(guides, aLeading, lx, rx);
      if (sp.mode === "center" && sp.b) {
        guideH(guides, sp.b.y, lx, rx);
      }
      const midX =
        (Math.min(snapX, sp.a.x, sp.b ? sp.b.x : snapX) +
          Math.max(snapX + dragged.w, sp.a.x + sp.a.w, sp.b ? sp.b.x + sp.b.w : snapX + dragged.w)) /
        2;
      pushGapRuler(rulers, "y", aLeading, sp.reverse ? snapY + dragged.h : snapY, midX + 18);
      if (sp.mode === "center" && sp.b) {
        pushGapRuler(rulers, "y", snapY + dragged.h, sp.b.y, midX + 18);
      }
    } else {
      const tr = (yBest as AlignCandidate).rect;
      const left = Math.min(snapX, tr.x) - EXT;
      const right = Math.max(snapX + dragged.w, tr.x + tr.w) + EXT;
      guides.push({
        axis: "y",
        x1: left,
        y1: (yBest as AlignCandidate).guide,
        x2: right,
        y2: (yBest as AlignCandidate).guide,
      });
      buildAlignRuler(rulers, dragged, tr, "y");
    }
  }

  dragGuides.value = guides;
  dragRulers.value = rulers;
}

function onNodeDragStop(event: NodeDragEvent) {
  const current = nodes.value.find((node) => node.id === event.node.id);
  if (current)
    current.position = { x: event.node.position.x, y: event.node.position.y };
  // 位置确有变化时才把拖动前的快照记入历史，避免空拖动产生多余撤销步
  if (pendingDragSnapshot) {
    if (!graphsEqual(pendingDragSnapshot, snapshotGraph())) {
      pushHistory(pendingDragSnapshot);
    }
    pendingDragSnapshot = null;
  }
  dragGuides.value = [];
  dragRulers.value = [];
  isAligning.value = false;
}

function copySelectedNodes() {
  const targetIds = selectedNodeIds.value.length
    ? [...selectedNodeIds.value]
    : selectedNodeId.value
      ? [selectedNodeId.value]
      : [];
  // Shift 框选会通过 selection-change 更新 selectedNodeIds；但为避免框选结束后
  // 有一次单击/拖尾把多选塌缩漏掉，这里再把 VueFlow 内部标记为选中的节点并集进来。
  const flowSelected = flowSelectedNodeIds();
  const unionIds = [...new Set([...targetIds, ...flowSelected])];
  if (!unionIds.length) {
    ElMessage.warning("请先选择要复制的节点");
    return;
  }
  if (unionIds.length === 1) {
    copyAndPasteNode(unionIds[0]);
    return;
  }

  const validNodes = nodes.value.filter(
    (n) =>
      unionIds.includes(n.id) && n.id !== "__start__" && n.id !== "__end__",
  );
  if (!validNodes.length) {
    ElMessage.info("所选节点不可复制");
    return;
  }
  if (validNodes.length === 1 && unionIds.length > 1) {
    copyAndPasteNode(validNodes[0].id);
    return;
  }

  const offset = 36 + pasteOffset.value * 18;
  pasteOffset.value = (pasteOffset.value + 1) % 8;
  const newNodes: EditorNode[] = [];
  const newIds: string[] = [];
  const cloneIdMap = new Map<string, string>();

  for (const source of validNodes) {
    if (
      source.data.nodeKind === "phase" &&
      hasCanonicalPhaseNode(source.data.phase as PhaseCode)
    ) {
      continue;
    }
    let newId: string;
    if (source.data.nodeKind === "tool" && source.data.tool) {
      newId = uniqueId(`tool-${safeId(source.data.tool)}-${source.data.phase}`);
    } else if (source.data.nodeKind === "phase") {
      newId = phaseNodeId(source.data.phase as PhaseCode);
    } else {
      newId = uniqueId(`node-${safeId(source.data.label)}`);
    }

    const basePos = {
      x: source.position.x + offset,
      y: source.position.y + offset,
    };
    const parameters = source.data.parameters
      ? JSON.parse(JSON.stringify(source.data.parameters))
      : undefined;
    const newNode = makeNode(
      newId,
      source.data.nodeKind,
      source.data.phase,
      basePos,
      source.data.label,
      source.data.tool,
      parameters,
    );
    newNodes.push(newNode);
    newIds.push(newId);
    cloneIdMap.set(source.id, newId);
  }

  if (!newNodes.length) {
    ElMessage.warning("所选阶段已在画布中，无法重复创建");
    return;
  }

  pushHistory();
  nodes.value = [...nodes.value, ...newNodes];
  selectedNodeIds.value = newIds;
  selectedNodeId.value = newIds[0] || "";
  // 让 VueFlow 内部选中态跟随新克隆，避免原节点仍处选中态造成下次 Ctrl+C 重复克隆原集合
  setFlowSelection(newIds);

  // 保持选中集合内部的连线关系：源和目标都在被复制集合内时，克隆对应的边
  const newInternalEdges = edges.value
    .filter(
      (edge) =>
        cloneIdMap.has(edge.source) && cloneIdMap.has(edge.target),
    )
    .map((edge) =>
      makeEdge(cloneIdMap.get(edge.source)!, cloneIdMap.get(edge.target)!),
    );
  edges.value = dedupeEdges([...edges.value, ...newInternalEdges]);
  setSelectedEdge("");
  validateGraph();
  ElMessage.success(`已批量复制并克隆 ${newNodes.length} 个节点`);
}

function removeSelectedNodes() {
  const targetIds = selectedNodeIds.value.length
    ? [...selectedNodeIds.value]
    : selectedNodeId.value
      ? [selectedNodeId.value]
      : [];
  if (!targetIds.length) return;

  const validIds = targetIds.filter(
    (id) => id !== "__start__" && id !== "__end__",
  );
  if (!validIds.length) {
    ElMessage.info("开始和结束节点固定保留");
    return;
  }

  pushHistory();
  nodes.value = nodes.value.filter((node) => !validIds.includes(node.id));
  edges.value = edges.value.filter(
    (edge) =>
      !validIds.includes(edge.source) && !validIds.includes(edge.target),
  );
  selectedNodeId.value = "";
  selectedNodeIds.value = [];
  validateGraph();
  ElMessage.success(
    validIds.length === 1 ? "已删除节点" : `已批量删除 ${validIds.length} 个节点`,
  );
}

function removeSelectedEdge() {
  if (!selectedEdgeId.value) return;
  removeEdge(selectedEdgeId.value, true);
}

function removeSelectedNode() {
  removeSelectedNodes();
}

function removeEdge(edgeId: string, notify = false) {
  pushHistory();
  edges.value = edges.value.filter((edge) => edge.id !== edgeId);
  selectedEdgeId.value = "";
  hoveredEdgeId.value = "";
  validateGraph();
  if (notify) ElMessage.success("连线已删除");
}

function setSelectedEdge(id: string) {
  selectedEdgeId.value = id;
  edges.value = edges.value.map((edge) => ({
    ...edge,
    selected: Boolean(id) && edge.id === id,
  }));
}

function removeNode(id: string) {
  if (id === "__start__" || id === "__end__") {
    ElMessage.info("开始和结束节点固定保留");
    return;
  }
  const target = nodes.value.find((node) => node.id === id);
  if (!target) return;
  pushHistory();
  nodes.value = nodes.value.filter((node) => node.id !== id);
  edges.value = edges.value.filter(
    (edge) => edge.source !== id && edge.target !== id,
  );
  if (selectedNodeId.value === id) selectedNodeId.value = "";
  validateGraph();
}

function addPhaseNode(
  phase: PhaseCode,
  droppedPosition?: { x: number; y: number },
) {
  const existingId = phaseNodeId(phase);
  if (hasCanonicalPhaseNode(phase)) {
    selectedNodeId.value = existingId;
    selectedPhase.value = phase;
    ElMessage.info(`${phaseOf(phase).shortLabel}阶段已在画布中`);
    return;
  }
  const meta = phaseOf(phase);
  const phaseIndex = PHASES.findIndex((item) => item.code === phase);
  const position = droppedPosition || {
    x: WORKFLOW_LAYOUT.phaseStartX + phaseIndex * WORKFLOW_LAYOUT.phaseStepX,
    y: WORKFLOW_LAYOUT.phaseY,
  };
  pushHistory();
  nodes.value = [
    ...nodes.value,
    makeNode(existingId, "phase", phase, position),
  ];
  selectedNodeId.value = existingId;
  selectedPhase.value = phase;
  graphNotice.value = `已加回“${meta.shortLabel}”阶段，请重新连接它的上游和下游依赖。`;
  validateGraph();
}

function addToolNode(
  tool: string,
  phase = selectedPhase.value,
  droppedPosition?: { x: number; y: number },
) {
  const agent = agentOf(tool);
  if (!agent) return;
  const id = uniqueId(`tool-${safeId(tool)}-${phase}`);
  const phaseAnchor = nodes.value.find(
    (node) => node.id === phaseNodeId(phase),
  );
  const position = droppedPosition || {
    x: (phaseAnchor?.position.x || 420) + 185,
    y: 480 + (toolNodes.value.length % 4) * 112,
  };
  pushHistory();
  nodes.value = [
    ...nodes.value,
    makeNode(id, "tool", phase, position, undefined, tool),
  ];
  selectedNodeId.value = id;
  // Make the beginner path useful immediately: add a branch from the phase
  // milestone and into its first downstream node. Users can then redraw it.
  if (phaseAnchor) {
    const next = PHASES[PHASES.findIndex((item) => item.code === phase) + 1];
    const nextId = next ? phaseNodeId(next.code) : "__end__";
    const withoutBypass = edges.value.filter(
      (edge) => !(edge.source === phaseAnchor.id && edge.target === nextId),
    );
    edges.value = dedupeEdges([
      ...withoutBypass,
      makeEdge(phaseAnchor.id, id, uniqueEdgeId(phaseAnchor.id, id)),
      makeEdge(id, nextId, uniqueEdgeId(id, nextId)),
    ]);
  }
  validateGraph();
}

type LibraryDropPayload =
  | { type: "phase"; phase: PhaseCode }
  | { type: "tool"; tool: string; phase: PhaseCode };

function setLibraryDragPayload(event: DragEvent, payload: LibraryDropPayload) {
  event.dataTransfer?.setData(
    "application/x-workflow-library-item",
    JSON.stringify(payload),
  );
  if (event.dataTransfer) event.dataTransfer.effectAllowed = "copy";
}
function onPhaseDragStart(event: DragEvent, phase: PhaseCode) {
  if (hasCanonicalPhaseNode(phase)) {
    event.preventDefault();
    return;
  }
  setLibraryDragPayload(event, { type: "phase", phase });
}
function onLibraryDragStart(event: DragEvent, tool: string) {
  setLibraryDragPayload(event, {
    type: "tool",
    tool,
    phase: agentOf(tool)?.phase || selectedPhase.value,
  });
  // Keep the original payload so older drag handlers remain compatible.
  event.dataTransfer?.setData("application/x-workflow-tool", tool);
}
function onCanvasDrop(event: DragEvent) {
  const position = screenToFlowCoordinate({
    x: event.clientX,
    y: event.clientY,
  });
  const encoded = event.dataTransfer?.getData(
    "application/x-workflow-library-item",
  );
  if (encoded) {
    try {
      const payload = JSON.parse(encoded) as LibraryDropPayload;
      if (
        payload.type === "phase" &&
        PHASES.some((phase) => phase.code === payload.phase)
      ) {
        addPhaseNode(payload.phase, position);
        return;
      }
      if (payload.type === "tool" && agentOf(payload.tool)) {
        addToolNode(payload.tool, payload.phase, position);
        return;
      }
    } catch {
      // Fall through to the legacy tool-only payload.
    }
  }
  const legacyTool = event.dataTransfer?.getData("application/x-workflow-tool");
  if (legacyTool) addToolNode(legacyTool, selectedPhase.value, position);
}

async function resetPreset() {
  const choice = await ElMessageBox.confirm(
    "当前未保存的连线和节点会被替换为所选模板，是否继续？",
    "载入红队模板",
    { type: "warning" },
  ).catch(() => false);
  if (choice !== "confirm") return;
  buildPreset(preset.value);
}

function serializeGraph(): WorkflowSpecV2 {
  const topo = topologicalGroups();
  const firstToolLevel = toolNodes.value.length
    ? Math.min(...toolNodes.value.map((node) => topo.level.get(node.id) || 0))
    : 0;
  const steps: WorkflowStepSpec[] = toolNodes.value.map((node) => ({
    nodeId: node.id,
    tool: node.data.tool || "",
    label: node.data.label,
    parameters: workflowToolParameters(node.data.tool, node.data.parameters),
    risk: node.data.risk || "SAFE",
    requiresApproval: (node.data.risk || "SAFE") !== "SAFE",
    group: Math.max((topo.level.get(node.id) || 0) - firstToolLevel, 0),
  }));
  return {
    version: 2,
    preset: preset.value,
    steps,
    graph: { nodes: graphSpecNodes(), edges: graphSpecEdges() },
  };
}

async function save(): Promise<WorkflowSpecV2 | undefined> {
  const projectId = selectedProjectId.value;
  if (!projectId) {
    ElMessage.warning("请先选择评估项目");
    return undefined;
  }
  if (viewingRunSnapshot.value) {
    ElMessage.warning("当前正在查看历史拓扑，请先返回当前工作流");
    return undefined;
  }
  const problems = validateGraph();
  if (problems.length) {
    ElMessage.warning(problems[0]);
    return undefined;
  }
  saving.value = true;
  try {
    const { data } = await endpoints.saveWorkflowSpec(
      projectId,
      serializeGraph(),
    );
    if (selectedProjectId.value !== projectId) return;
    loadFromSpec(data);
    ElMessage.success("红队工作流已保存：连线依赖决定顺序，分叉节点可并行执行");
    graphNotice.value = "已保存。之后 AI 会按图中的依赖顺序组织受控任务。";
    return data;
  } catch {
    ElMessage.error("保存失败，请检查后端工作流服务");
    return undefined;
  } finally {
    saving.value = false;
  }
}

function workflowStatusIcon(status: string): string {
  switch (status) {
    case "running":
      return "arrow-clockwise";
    case "success":
      return "checkmark-circle";
    case "failed":
      return "dismiss-circle";
    case "skipped":
    case "cancelled":
      return "info";
    default:
      return "clock";
  }
}

function statusLabel(status: string): string {
  switch (status) {
    case "running":
      return "执行中";
    case "success":
      return "已完成";
    case "failed":
      return "失败";
    case "skipped":
      return "跳过";
    case "cancelled":
      return "已取消";
    default:
      return "待执行";
  }
}

function nodeStatusClass(nodeId: string): string {
  const run = nodeRuns.value[nodeId];
  if (!run) return "";
  return `is-status-${run.status}`;
}

function nodeStatusType(status: string): string {
  switch (status) {
    case "running":
      return "warning";
    case "success":
      return "success";
    case "failed":
      return "danger";
    case "skipped":
    case "cancelled":
      return "info";
    default:
      return "info";
  }
}

const nodeDetailRun = computed(() =>
  nodeDetailNodeId.value ? nodeRuns.value[nodeDetailNodeId.value] : undefined,
);
const nodeDetailTitle = computed(() => {
  const node = nodes.value.find((item) => item.id === nodeDetailNodeId.value);
  return node ? `节点详情：${node.data.label}` : "节点详情";
});

interface EndFinding {
  key: string;
  title: string;
  severity?: string;
  sourceTool?: string;
  vulnerabilityCode?: string;
  description?: string;
  evidence?: string;
  remediation?: string;
  taskId?: number;
}
const endFindingDetailVisible = ref(false);
const endFindingDetail = ref<EndFinding | null>(null);

const endNodeSummary = computed(() => {
  const tasks = selectedRunDetail.value?.tasks ?? [];
  const findings: EndFinding[] = [];
  const sevCount: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let finished = 0;
  for (const task of tasks) {
    if (["SUCCESS", "COMPLETED", "FAILED"].includes(task.status)) finished++;
    const result = parseTaskResult(task);
    const list = result?.findings;
    if (!Array.isArray(list)) continue;
    (list as Array<Record<string, unknown>>).forEach((f) => {
      const severity = String(f.severity ?? "").toLowerCase();
      if (["critical", "high", "medium", "low", "info"].includes(severity)) {
        sevCount[severity]++;
      }
      findings.push({
        key: `${task.id}-${findings.length}`,
        title:
          (typeof f.title === "string" && f.title) ||
          (typeof f.name === "string" && f.name) ||
          "未命名发现",
        severity: severity || undefined,
        sourceTool: task.toolCode,
        vulnerabilityCode:
          typeof f.vulnerabilityCode === "string"
            ? f.vulnerabilityCode
            : undefined,
        description:
          typeof f.description === "string" ? f.description : undefined,
        evidence: typeof f.evidence === "string" ? f.evidence : undefined,
        remediation:
          typeof f.remediation === "string" ? f.remediation : undefined,
        taskId: task.id,
      });
    });
  }
  return {
    findings,
    severity: sevCount,
    finished,
    total: tasks.length,
    run: selectedRunDetail.value?.run,
  };
});

function openEndFinding(finding: EndFinding) {
  endFindingDetail.value = finding;
  endFindingDetailVisible.value = true;
}

function endFindingTagType(severity?: string) {
  switch ((severity || "").toLowerCase()) {
    case "critical":
    case "high":
      return "danger" as const;
    case "medium":
      return "warning" as const;
    case "low":
      return "info" as const;
    default:
      return "info" as const;
  }
}

function syncEndResultsToCenter() {
  router.push("/findings");
  const count = endNodeSummary.value.findings.length;
  ElMessage.success(
    count
      ? `已留存 ${count} 条发现到结果中心`
      : "本轮运行未产生可留存的发现，已打开结果中心核对",
  );
}

function nodeRunLabel(run: NodeRunState): string {
  const suffix = run.resultCount ? ` · ${run.resultCount} 项` : "";
  return `${statusLabel(run.status)}${suffix}`;
}

function isRunTerminal(status: string) {
  return TERMINAL_RUN_STATUSES.has(status);
}

function runStatusLabel(status: string) {
  switch (status) {
    case "PREPARING":
      return "准备中";
    case "RUNNING":
      return "执行中";
    case "STOPPING":
      return "停止中";
    case "COMPLETED":
      return "已完成";
    case "PARTIAL_FAILED":
      return "部分失败";
    case "STOPPED":
      return "已停止";
    case "FAILED":
      return "执行失败";
    default:
      return status || "未知状态";
  }
}

function taskStatusLabel(status: string) {
  const labels: Record<string, string> = {
    PENDING: "待执行",
    QUEUED: "排队中",
    BLOCKED: "等待前置节点",
    RUNNING: "执行中",
    SUCCESS: "成功",
    FAILED: "失败",
    TIMEOUT: "超时",
    REJECTED: "已拒绝",
    CANCELLED: "已取消",
    SKIPPED: "已跳过",
    PREPARING: "准备中",
    STOPPING: "停止中",
    STOPPED: "已停止",
    PARTIAL_FAILED: "部分失败",
  };
  return labels[status] || status;
}

function nodeStatusFromTask(status: string): NodeRunState["status"] {
  if (["PENDING", "QUEUED", "BLOCKED"].includes(status)) return "pending";
  if (status === "RUNNING") return "running";
  if (status === "SUCCESS") return "success";
  if (status === "SKIPPED") return "skipped";
  if (status === "CANCELLED") return "cancelled";
  return "failed";
}

function parseTaskResult(
  task: ProjectTaskRecord,
): Record<string, any> | undefined {
  if (!task.resultJson) return undefined;
  try {
    const parsed = JSON.parse(task.resultJson);
    return parsed && typeof parsed === "object" ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function structuredResultCount(
  result?: Record<string, any>,
): number | undefined {
  if (!result) return undefined;
  const candidates = [
    result.findings,
    result.data?.findings,
    result.data?.openPorts,
    result.data?.items,
    result.data?.results,
  ];
  const found = candidates.find((value) => Array.isArray(value));
  return found?.length || undefined;
}

function nodeRunFromTask(task: ProjectTaskRecord): NodeRunState {
  const result = parseTaskResult(task);
  const summary =
    (typeof result?.summary === "string" && result.summary) ||
    task.errorMessage ||
    task.progressMessage ||
    undefined;
  return {
    status: nodeStatusFromTask(task.status),
    taskId: task.id,
    log: task.executionLog || task.errorMessage,
    summary,
    resultCount: structuredResultCount(result),
    output: result?.data ?? result,
  };
}

function runOptionLabel(run: WorkflowRunSummary) {
  const created = run.createdAt ? new Date(run.createdAt).toLocaleString() : "";
  return `#${run.id} · ${runStatusLabel(run.status)} · ${created}`;
}

function upsertWorkflowRun(run: WorkflowRunSummary) {
  const remaining = workflowRuns.value.filter((item) => item.id !== run.id);
  workflowRuns.value = [run, ...remaining].sort((a, b) => b.id - a.id);
}

function applyWorkflowRunDetail(detail: WorkflowRunDetail) {
  selectedRunDetail.value = detail;
  executeProgress.value = Math.max(0, Math.min(100, detail.run.progress || 0));
  executeStatus.value = runStatusLabel(detail.run.status);
  executeTaskIds.value = detail.tasks.map((task) => task.id);
  executeIndeterminate.value =
    !isRunTerminal(detail.run.status) &&
    detail.tasks.some(
      (task) =>
        ["PENDING", "BLOCKED", "RUNNING"].includes(task.status) &&
        !task.progressDeterminate,
    );
  executeLogs.value = [
    `[运行 #${detail.run.id}] ${detail.run.message || runStatusLabel(detail.run.status)}`,
    ...detail.tasks.map((task) => {
      const result = parseTaskResult(task);
      const summary =
        (typeof result?.summary === "string" && result.summary) ||
        task.errorMessage ||
        task.progressMessage ||
        "";
      return `[#${task.id}] ${task.toolCode} · ${taskStatusLabel(task.status)}${summary ? ` · ${summary}` : ""}`;
    }),
  ];
  if (linkedTargets.value.some((target) => target.id === detail.run.targetId)) {
    selectedTargetId.value = detail.run.targetId;
  }

  const matchesVisibleGraph =
    viewingRunSnapshot.value ||
    detail.run.workflowDigest === workflowSnapshot.value.specDigest;
  nodeRuns.value = matchesVisibleGraph
    ? Object.fromEntries(
        detail.tasks
          .filter((task) => task.workflowNodeId)
          .map((task) => [
            task.workflowNodeId as string,
            nodeRunFromTask(task),
          ]),
      )
    : {};
}

async function selectWorkflowRun(runId?: number) {
  if (!runId) return;
  const keepViewingSnapshot = viewingRunSnapshot.value;
  selectedRunId.value = runId;
  try {
    const { data } = await endpoints.workflowRun(runId);
    if (selectedRunId.value !== runId) return;
    if (keepViewingSnapshot) {
      loadFromSpec(data.spec);
    }
    applyWorkflowRunDetail(data);
    upsertWorkflowRun(data.run);
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "读取工作流运行记录失败"));
  }
}

async function refreshWorkflowRunList() {
  const projectId = selectedProjectId.value;
  if (!projectId) {
    workflowRuns.value = [];
    selectedRunId.value = undefined;
    activeRunId.value = undefined;
    selectedRunDetail.value = undefined;
    return;
  }
  const { data } = await endpoints.workflowRuns(projectId);
  if (selectedProjectId.value !== projectId) return;
  workflowRuns.value = data || [];
}

async function loadWorkflowRuns() {
  runPollGeneration += 1;
  try {
    await refreshWorkflowRunList();
    const active = workflowRuns.value.find((run) => !isRunTerminal(run.status));
    activeRunId.value = active?.id;
    executing.value = Boolean(active);
    const retained = workflowRuns.value.some(
      (run) => run.id === selectedRunId.value,
    )
      ? selectedRunId.value
      : undefined;
    const nextId = active?.id || retained || workflowRuns.value[0]?.id;
    if (nextId) await selectWorkflowRun(nextId);
    else {
      selectedRunId.value = undefined;
      selectedRunDetail.value = undefined;
      nodeRuns.value = {};
      executeLogs.value = [];
      executeStatus.value = "待执行";
      executeProgress.value = 0;
    }
    if (active) void pollWorkflowRun(active.id);
  } catch (error) {
    ElMessage.warning(toErrorMessage(error, "工作流运行历史加载失败"));
  }
}

async function pollWorkflowRun(runId: number) {
  const generation = ++runPollGeneration;
  while (generation === runPollGeneration) {
    try {
      const { data } = await endpoints.workflowRun(runId);
      if (generation !== runPollGeneration) return;
      upsertWorkflowRun(data.run);
      if (selectedRunId.value === runId) applyWorkflowRunDetail(data);
      if (isRunTerminal(data.run.status)) {
        activeRunId.value = undefined;
        executing.value = false;
        executeIndeterminate.value = false;
        await refreshWorkflowRunList();
        return;
      }
      activeRunId.value = runId;
      executing.value = true;
    } catch {
      if (generation !== runPollGeneration) return;
      executeStatus.value = "运行状态读取失败，正在重试";
    }
    await new Promise((resolve) => window.setTimeout(resolve, 750));
  }
}

async function clearSelectedRun() {
  const run = selectedRunDetail.value?.run;
  if (!run) return;
  if (!isRunTerminal(run.status))
    return ElMessage.warning("运行中的工作流不能清空");
  const confirmed = await ElMessageBox.confirm(
    `仅隐藏运行 #${run.id} 的工作流历史；关联任务和审计记录仍会保留。`,
    "清空本次运行",
    { type: "warning", confirmButtonText: "清空" },
  ).catch(() => false);
  if (confirmed !== "confirm") return;
  try {
    await endpoints.clearWorkflowRun(run.id);
    if (viewingRunSnapshot.value) await returnToCurrentWorkflow();
    selectedRunId.value = undefined;
    selectedRunDetail.value = undefined;
    await loadWorkflowRuns();
    ElMessage.success("本次工作流运行已从历史中清空");
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "清空工作流运行失败"));
  }
}

function viewSelectedRunSnapshot() {
  if (!selectedRunDetail.value) return;
  loadFromSpec(selectedRunDetail.value.spec);
  viewingRunSnapshot.value = true;
  applyWorkflowRunDetail(selectedRunDetail.value);
}

async function returnToCurrentWorkflow() {
  viewingRunSnapshot.value = false;
  await load();
  if (selectedRunDetail.value) applyWorkflowRunDetail(selectedRunDetail.value);
}

function parametersForExecution(step: WorkflowStepSpec) {
  const parameters = { ...(step.parameters || {}) };
  if (
    (step.tool === "tcp_ports" ||
      step.tool === "nmap_service_scan" ||
      step.tool === "fscan_scan") &&
    !String(parameters.ports || "").trim()
  ) {
    parameters.ports = selectedTarget.value?.allowedPorts || "80,443";
  }
  if (step.tool === "nmap_service_scan" && !parameters.mode) {
    parameters.mode = "quick";
  }
  if (step.tool === "fscan_scan" && !parameters.vulnMode) {
    parameters.vulnMode = "SAFE";
  }
  if (step.tool === "http_security_check" && !parameters.check) {
    parameters.check = "cookies";
  }
  if (
    (step.tool === "afrog_scan" ||
      step.tool === "xray_scan" ||
      step.tool === "nuclei_scan") &&
    parameters.allPocs !== true &&
    !Array.isArray(parameters.pocCodes)
  ) {
    parameters.allPocs = true;
  }
  return parameters;
}

function validateExecutionInputs(steps: WorkflowStepSpec[]) {
  for (const step of steps) {
    const parameters = parametersForExecution(step);
    if (
      (step.tool === "tcp_ports" ||
        step.tool === "nmap_service_scan" ||
        step.tool === "fscan_scan") &&
      !String(parameters.ports || "").trim()
    ) {
      return `步骤“${step.label || step.tool}”缺少端口输入`;
    }
    if (
      step.tool === "fscan_scan" &&
      !["SAFE", "FINGERPRINT", "FULL"].includes(
        String(parameters.vulnMode || "").toUpperCase(),
      )
    ) {
      return "fscan 扫描模式必须是 SAFE、FINGERPRINT 或 FULL";
    }
    if (
      step.tool === "nmap_service_scan" &&
      !["quick", "service"].includes(String(parameters.mode || ""))
    ) {
      return "Nmap 扫描模式必须是快速探测或服务识别";
    }
    if (
      step.tool === "http_security_check" &&
      !["cookies", "cors", "methods", "disclosure"].includes(
        String(parameters.check || ""),
      )
    ) {
      return "HTTP 风险检查类型无效";
    }
    if (
      step.tool === "afrog_scan" ||
      step.tool === "xray_scan" ||
      step.tool === "nuclei_scan"
    ) {
      const codes = parameters.pocCodes;
      if (parameters.allPocs !== true) {
        if (!Array.isArray(codes) || !codes.length || codes.length > 50) {
          return `步骤“${step.label || step.tool}”需要选择 1 到 50 个 PoC / 模板`;
        }
        if (
          codes.some((code) => !/^[A-Z]{2}-[A-F0-9]{24}$/.test(String(code)))
        ) {
          return `步骤“${step.label || step.tool}”包含无效 PoC / 模板编号`;
        }
      }
    }
  }
  return "";
}

async function executeWorkflow() {
  const projectId = selectedProjectId.value;
  const targetId = selectedTargetId.value;
  if (!projectId) return ElMessage.warning("请先选择评估项目");
  if (!targetId) return ElMessage.warning("请先选择授权目标");
  if (graphValidation.value.length) {
    return ElMessage.warning("工作流拓扑有误，请修正后再执行");
  }

  const steps = serializeGraph().steps || [];
  if (!steps.length) {
    return ElMessage.warning("当前工作流没有可执行步骤");
  }
  const inputProblem = validateExecutionInputs(steps);
  if (inputProblem) return ElMessage.warning(inputProblem);

  executing.value = true;
  // The preflight/approval phase has no cancellable run yet; do not expose a stale run id.
  runPollGeneration += 1;
  activeRunId.value = undefined;
  executeProgress.value = 0;
  executeIndeterminate.value = true;
  executeStatus.value = "准备执行";
  executeLogs.value = [`[工作流] 正在保存并预检，共 ${steps.length} 步`];
  executeTaskIds.value = [];
  nodeRuns.value = {};

  try {
    const confirmed = await ElMessageBox.confirm(
      `将保存当前画布并执行 ${steps.length} 个步骤。只有点击“执行工作流”才会启动任务。`,
      "执行红队工作流",
      { type: "warning" },
    ).catch(() => false);
    if (confirmed !== "confirm") return;

    saving.value = true;
    const { data: saved } = await endpoints.saveWorkflowSpec(
      projectId,
      serializeGraph(),
    );
    saving.value = false;
    loadFromSpec(saved);
    const identity = {
      projectId,
      targetId,
      workflowId: saved.workflowId!,
      workflowRevision: saved.revision!,
      workflowDigest: saved.specDigest!,
    };
    const { data: preflight } = await endpoints.preflightWorkflowRun(identity);
    const skippedNodeIds = preflight.issues.map((issue) => issue.nodeId);
    if (preflight.issues.length) {
      const issueText = preflight.issues
        .map((issue) => `${issue.label}：${issue.reason}`)
        .join("；");
      const skipConfirmed = await ElMessageBox.confirm(
        `${issueText}。是否明确跳过这些不可用节点并继续？依赖这些节点的后继步骤也会跳过。`,
        "工作流预检发现不可用节点",
        {
          type: "warning",
          confirmButtonText: "跳过并继续",
          cancelButtonText: "取消执行",
        },
      ).catch(() => false);
      if (skipConfirmed !== "confirm") return;
    }

    const approvedNodeIds: string[] = [];
    for (const step of saved.steps || []) {
      const nodeId = step.nodeId || step.tool;
      if (
        step.requiresApproval &&
        step.tool !== "retrieve_project_context" &&
        !skippedNodeIds.includes(nodeId)
      ) {
        const approved = await ElMessageBox.confirm(
          `步骤“${step.label || step.tool}”风险级别为 ${step.risk || "CAUTION"}，确认对当前授权目标执行？`,
          "确认高风险步骤",
          { type: "warning", confirmButtonText: "确认执行" },
        ).catch(() => false);
        if (approved !== "confirm") return;
        approvedNodeIds.push(nodeId);
      }
    }

    const { data: detail } = await endpoints.startWorkflowRun({
      ...identity,
      approvedNodeIds,
      skippedNodeIds,
    });
    viewingRunSnapshot.value = false;
    selectedRunId.value = detail.run.id;
    activeRunId.value = detail.run.id;
    applyWorkflowRunDetail(detail);
    upsertWorkflowRun(detail.run);
    await pollWorkflowRun(detail.run.id);
  } catch (error: any) {
    executeStatus.value = "执行失败";
    executeLogs.value.push(
      `[工作流] 错误：${toErrorMessage(error, "执行失败")}`,
    );
    ElMessage.error(toErrorMessage(error, "工作流执行失败"));
  } finally {
    saving.value = false;
    if (!activeRunId.value) {
      executing.value = false;
      executeIndeterminate.value = false;
    }
  }
}

async function stopExecution() {
  const runId = activeRunId.value;
  if (!runId || stoppingRun.value) return;
  stoppingRun.value = true;
  executeStatus.value = "正在停止";
  try {
    const { data } = await endpoints.stopWorkflowRun(runId);
    upsertWorkflowRun(data.run);
    if (selectedRunId.value === runId) applyWorkflowRunDetail(data);
    if (isRunTerminal(data.run.status)) {
      runPollGeneration += 1;
      activeRunId.value = undefined;
      executing.value = false;
      executeIndeterminate.value = false;
      await refreshWorkflowRunList();
    }
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "停止工作流失败"));
  } finally {
    stoppingRun.value = false;
  }
}

function openNodeDetail(nodeId: string) {
  const run = nodeRuns.value[nodeId];
  if (!run?.taskId) return;
  nodeDetailNodeId.value = nodeId;
  nodeDetailVisible.value = true;
}

function toEditorNode(
  spec: WorkflowGraphNodeSpec,
  parameters?: Record<string, unknown>,
): EditorNode {
  const kind =
    spec.type === "system" || spec.id === "__start__" || spec.id === "__end__"
      ? "system"
      : spec.type === "tool" || spec.tool
        ? "tool"
        : "phase";
  const phase = (
    PHASES.some((item) => item.code === spec.phase)
      ? spec.phase
      : inferPhase(spec.tool)
  ) as PhaseCode;
  const position = {
    x: Number.isFinite(spec.position?.x) ? spec.position.x : 100,
    y: Number.isFinite(spec.position?.y) ? spec.position.y : 250,
  };
  return makeNode(
    spec.id,
    kind,
    phase,
    position,
    spec.label,
    spec.tool,
    parameters,
  );
}

function loadFromSpec(data: WorkflowSpecV2) {
  let generatedPreset = false;
  workflowSnapshot.value = {
    workflowId: data.workflowId,
    scopeId: data.scopeId,
    revision: data.revision,
    specDigest: data.specDigest,
    updatedBy: data.updatedBy,
    updatedAt: data.updatedAt,
  };
  if (data?.graph?.nodes?.length && data.graph.edges) {
    const parametersByNode = new Map(
      (data.steps || [])
        .filter((step) => step.nodeId)
        .map((step) => [step.nodeId as string, step.parameters]),
    );
    nodes.value = data.graph.nodes.map((node) =>
      toEditorNode(node, parametersByNode.get(node.id)),
    );
    edges.value = dedupeEdges(
      data.graph.edges.map((edge) =>
        makeEdge(
          edge.source,
          edge.target,
          edge.id || `edge-${safeId(edge.source)}-${safeId(edge.target)}`,
        ),
      ),
    );
    preset.value = (
      PRESETS.some((item) => item.value === data.preset)
        ? data.preset
        : "standard"
    ) as PresetCode;
    graphValidation.value = validateGraph();
    const graphToolCount = nodes.value.filter(
      (node) => node.data.nodeKind === "tool",
    ).length;
    const savedStepCount = data.steps?.length || 0;
    if (
      !nodes.value.some((node) => node.id === "__start__") ||
      !nodes.value.some((node) => node.id === "__end__") ||
      (savedStepCount > 0 && graphToolCount !== savedStepCount)
    ) {
      buildPreset(preset.value, data.steps);
      generatedPreset = true;
    }
  } else {
    // Backward-compatible migration for the old steps-only endpoint.
    preset.value = "standard";
    buildPreset("standard", data?.steps);
    generatedPreset = true;
  }
  if (!generatedPreset) void refit();
}

async function load() {
  const sequence = ++loadSeq;
  const projectId = selectedProjectId.value;
  if (!projectId) {
    workflowSnapshot.value = {};
    buildPreset("standard");
    return;
  }
  loading.value = true;
  try {
    const { data } = await endpoints.getWorkflowSpec(projectId);
    if (sequence !== loadSeq || selectedProjectId.value !== projectId) return;
    loadFromSpec(data || {});
  } catch {
    if (sequence !== loadSeq || selectedProjectId.value !== projectId) return;
    workflowSnapshot.value = {};
    buildPreset("standard");
    ElMessage.warning("工作流服务暂不可用，已载入本地红队模板");
  } finally {
    if (sequence === loadSeq) loading.value = false;
  }
}

async function loadProjects() {
  try {
    const { data } = await endpoints.projects();
    projects.value = data || [];
    const stored = Number(localStorage.getItem(WORKFLOW_PROJECT_STORAGE_KEY));
    selectedProjectId.value =
      projects.value.find((project) => project.id === stored)?.id ||
      projects.value[0]?.id;
    await Promise.all([load(), loadProjectTargets()]);
    await loadWorkflowRuns();
  } catch {
    projects.value = [];
    selectedProjectId.value = undefined;
    workflowSnapshot.value = {};
    buildPreset("standard");
    ElMessage.warning("项目列表暂不可用，工作流编辑器已载入本地模板");
  }
}

async function loadProjectTargets() {
  const projectId = selectedProjectId.value;
  targets.value = [];
  projectTargetLinks.value = [];
  selectedTargetId.value = undefined;
  if (!projectId) return;
  try {
    const [linksResult, targetsResult] = await Promise.all([
      endpoints.projectTargets(projectId),
      endpoints.targets(),
    ]);
    projectTargetLinks.value = linksResult.data || [];
    targets.value = (targetsResult.data || []).filter(
      (target) => target.enabled,
    );
    selectedTargetId.value = linkedTargets.value[0]?.id;
  } catch {
    ElMessage.warning("项目目标列表加载失败");
  }
}

function openTargetInput() {
  if (!selectedProjectId.value) {
    ElMessage.warning("请先选择评估项目");
    return;
  }
  if (executing.value || viewingRunSnapshot.value) {
    ElMessage.info(
      viewingRunSnapshot.value
        ? "请先返回当前工作流，再新增授权输入"
        : "工作流执行期间不能新增授权输入",
    );
    return;
  }
  targetInput.value = {
    name: "",
    targetValue: "",
    targetType: "domain",
    authorizationNote: "",
  };
  targetInputSelectedPorts.value = ["80", "443"];
  targetInputFullPortAccess.value = false;
  targetInputVisible.value = true;
}

async function createTargetInput() {
  const projectId = selectedProjectId.value;
  const input = targetInput.value;
  if (!projectId) return ElMessage.warning("请先选择评估项目");
  if (
    !input.name.trim() ||
    !input.targetValue.trim() ||
    !input.authorizationNote.trim()
  ) {
    return ElMessage.warning("请填写名称、目标地址和授权记录");
  }
  let allowedPorts: string;
  try {
    allowedPorts = normalizeAllowedPorts(
      targetInputSelectedPorts.value,
      "",
      targetInputFullPortAccess.value,
    );
  } catch (error: any) {
    return ElMessage.warning(error?.message || "端口格式不正确");
  }
  targetInputSaving.value = true;
  try {
    const { data } = await endpoints.createTarget({
      name: input.name.trim(),
      targetValue: input.targetValue.trim(),
      targetType: input.targetType,
      allowedPorts,
      authorizationNote: input.authorizationNote.trim(),
      enabled: true,
      projectId,
    });
    await loadProjectTargets();
    selectedTargetId.value = data.id;
    targetInputVisible.value = false;
    ElMessage.success("自定义输入已登记为项目授权目标");
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.message || "自定义输入保存失败");
  } finally {
    targetInputSaving.value = false;
  }
}

async function changeProject(projectId: number) {
  localStorage.setItem(WORKFLOW_PROJECT_STORAGE_KEY, String(projectId));
  graphNotice.value = "";
  selectedNodeId.value = "";
  selectedEdgeId.value = "";
  await Promise.all([load(), loadProjectTargets()]);
  await loadWorkflowRuns();
}

async function refit(mode: "overview" | "start" = "overview") {
  await nextTick();
  window.setTimeout(() => {
    if (mode === "start") {
      const canvas = flowCanvas.value;
      const width = canvas?.clientWidth || 1000;
      const height = canvas?.clientHeight || 620;
      const zoom = Math.min(0.9, Math.max(0.78, width / 1100));
      const firstToolY = Math.min(
        ...nodes.value.map((node) => node.position.y),
      );
      const lastToolBottom = Math.max(
        ...nodes.value.map(
          (node) =>
            node.position.y +
            (node.data.nodeKind === "tool"
              ? 150
              : node.data.nodeKind === "system"
                ? 72
                : 108),
        ),
      );
      const graphHeight = lastToolBottom - firstToolY;
      void setViewport(
        {
          x: 24 - WORKFLOW_LAYOUT.startX * zoom,
          y:
            Math.max(24, (height - graphHeight * zoom) / 2) - firstToolY * zoom,
          zoom,
        },
        { duration: 180 },
      );
      return;
    }
    void fitView({ padding: 0.14, maxZoom: 0.95, duration: 180 });
  }, 50);
}

function suggestionSnapshot() {
  return {
    graph: {
      nodes: graphSpecNodes(),
      edges: graphSpecEdges(),
    },
    preset: preset.value,
    selectedNodeId: selectedNodeId.value || undefined,
    focus: selectedNode.value?.data?.label || "",
  };
}

async function refreshSuggestions(reason = "edit") {
  if (!nodes.value.length && reason !== "manual") return;
  const seq = ++suggestSeq;
  if (suggestAbort) suggestAbort.abort();
  suggestAbort = new AbortController();
  const signal = suggestAbort.signal;
  suggestLoading.value = true;
  suggestions.value = [];
  suggestNote.value = reason === "manual" ? "" : suggestNote.value;
  suggestSource.value = "";
  try {
    await streamWorkflowSuggestions(
      suggestionSnapshot(),
      (event: WorkflowSuggestStreamEvent) => {
        if (seq !== suggestSeq) return;
        if (event.type === "status") {
          if (event.message) suggestNote.value = String(event.message);
          return;
        }
        if (event.type === "suggestion" && event.suggestion) {
          const tip = event.suggestion;
          if (
            !suggestions.value.some(
              (item) => item.id === tip.id || item.title === tip.title,
            )
          ) {
            suggestions.value = [...suggestions.value, tip];
          }
          return;
        }
        if (event.type === "done") {
          suggestSource.value = event.source || suggestSource.value;
          if (event.note) suggestNote.value = String(event.note);
          else if (!suggestions.value.length)
            suggestNote.value = "暂无额外建议";
          return;
        }
        if (event.type === "error") {
          suggestNote.value = String(event.message || "工作流建议流中断");
        }
      },
      signal,
    );
  } catch (error: any) {
    if (signal.aborted || seq !== suggestSeq) return;
    if (reason === "manual") {
      suggestNote.value = "建议服务暂时不可用，请稍后重试";
      ElMessage.warning("无法获取工作流建议");
    }
  } finally {
    if (seq === suggestSeq) suggestLoading.value = false;
  }
}

function scheduleSuggestions() {
  if (suggestTimer) clearTimeout(suggestTimer);
  suggestTimer = setTimeout(() => {
    void refreshSuggestions("edit");
  }, 700);
}

function applySuggestion(item: WorkflowSuggestion) {
  const action = item.action;
  if (!action) return;
  if (action.type === "add_tool" && action.tool) {
    const phase = (
      PHASES.some((p) => p.code === action.phase)
        ? action.phase
        : agentOf(action.tool)?.phase || selectedPhase.value
    ) as PhaseCode;
    selectedPhase.value = phase;
    addToolNode(action.tool, phase);
    graphNotice.value = `已根据建议加入：${agentOf(action.tool)?.name || action.tool}`;
    return;
  }
  if (action.type === "focus_node" && action.nodeId) {
    selectedNodeId.value = action.nodeId;
    selectedEdgeId.value = "";
    graphNotice.value = "已定位到建议关注的节点";
  }
}

watch([nodes, edges], () => {
  if (
    selectedNodeId.value &&
    !nodes.value.some((node) => node.id === selectedNodeId.value)
  )
    selectedNodeId.value = "";
  if (
    selectedEdgeId.value &&
    !edges.value.some((edge) => edge.id === selectedEdgeId.value)
  )
    selectedEdgeId.value = "";
  if (nodes.value.length) validateGraph();
  scheduleSuggestions();
});

watch([selectedNodeId, preset], () => scheduleSuggestions());

function isTypingTarget(target: EventTarget | null) {
  const el = target instanceof HTMLElement ? target : null;
  return (
    !!el &&
    (el.tagName === "INPUT" ||
      el.tagName === "TEXTAREA" ||
      el.tagName === "SELECT" ||
      el.isContentEditable ||
      Boolean(
        el.closest(
          "input, textarea, select, [contenteditable='true'], [contenteditable='']",
        ),
      ))
  );
}
function onWorkflowKeydown(event: KeyboardEvent) {
  if (event.key === "Escape") {
    if (workflowContextMenu.value.visible) {
      closeWorkflowContextMenu();
      return;
    }
    if (workflowConfigVisible.value) {
      workflowConfigVisible.value = false;
      return;
    }
    if (isFullscreen.value) {
      void exitFullscreen();
      return;
    }
    selectedNodeId.value = "";
    selectedNodeIds.value = [];
    setSelectedEdge("");
    return;
  }
  if ((event.ctrlKey || event.metaKey) && !isTypingTarget(event.target)) {
    const key = event.key.toLowerCase();
    if (key === "z") {
      event.preventDefault();
      if (event.shiftKey) redoGraph();
      else undoGraph();
      return;
    }
    if (key === "y") {
      event.preventDefault();
      redoGraph();
      return;
    }
    if (
      key === "c" &&
      (selectedNodeId.value ||
        selectedNodeIds.value.length ||
        flowSelectedNodeIds().length)
    ) {
      if (canCopyNode()) {
        event.preventDefault();
        copySelectedNodes();
      }
      return;
    }
    if (key === "v" && clipboardNode.value) {
      if (!viewingRunSnapshot.value && !executing.value) {
        event.preventDefault();
        pasteNode();
      }
      return;
    }
  }
  if (
    (event.key !== "Delete" && event.key !== "Backspace") ||
    isTypingTarget(event.target)
  )
    return;
  if (selectedNodeId.value || selectedNodeIds.value.length) {
    event.preventDefault();
    removeSelectedNodes();
    return;
  }
  if (!selectedEdgeId.value) return;
  event.preventDefault();
  removeSelectedEdge();
}

watch(
  [executing, executeProgress, executeIndeterminate],
  ([isExec, prog, indet]) => {
    if (isExec) {
      if (!indet && typeof prog === "number" && prog > 0) {
        taskbarProgress.setProgress("workflow-run", prog / 100);
      } else {
        taskbarProgress.startIndeterminate("workflow-run");
      }
    } else {
      taskbarProgress.clearProgress("workflow-run");
      taskbarProgress.stopIndeterminate("workflow-run");
    }
  },
  { immediate: true },
);

onMounted(() => {
  scheduleSuggestions();
  window.addEventListener("keydown", onWorkflowKeydown);
  window.addEventListener("resize", onWorkflowWindowResize);
  document.addEventListener("fullscreenchange", onFullscreenChange);
  document.addEventListener("webkitfullscreenchange", onFullscreenChange);
  void loadProjects();
});
onBeforeUnmount(() => {
  taskbarProgress.clearProgress("workflow-run");
  taskbarProgress.stopIndeterminate("workflow-run");
  runPollGeneration += 1;
  if (suggestTimer) clearTimeout(suggestTimer);
  if (suggestAbort) suggestAbort.abort();
  window.removeEventListener("keydown", onWorkflowKeydown);
  window.removeEventListener("resize", onWorkflowWindowResize);
  document.removeEventListener("fullscreenchange", onFullscreenChange);
  document.removeEventListener("webkitfullscreenchange", onFullscreenChange);
  if (
    document.fullscreenElement &&
    document.fullscreenElement === workflowEditorLayoutRef.value
  ) {
    void document.exitFullscreen().catch(() => {});
  }
});
</script>

<template>
  <section class="panel workflow-page">
    <div class="section-head">
      <div class="workflow-head-copy">
        <h3>红队评估工作流</h3>
        <p>
          从任务启动到报告交付的完整闭环。拖动节点调整布局，从右侧连接点手动连线；分叉表示并行，汇合表示等待上游全部完成。
        </p>
        <div class="workflow-context-summary" aria-label="当前工作流配置">
          <span><b>项目</b>{{ selectedProject?.name || "未选择" }}</span>
          <span
            ><b>授权目标</b
            >{{
              selectedTarget
                ? `${selectedTarget.name} · ${selectedTarget.targetValue}`
                : "未选择"
            }}</span
          >
          <span><b>模板</b>{{ selectedPresetLabel }}</span>
        </div>
      </div>
      <div class="workflow-actions">
        <el-button
          type="primary"
          :loading="saving"
          @click="save"
          :disabled="executing || viewingRunSnapshot"
          ><el-icon><Check /></el-icon>保存工作流</el-button
        >
        <el-button
          type="success"
          :loading="executing"
          :disabled="
            !selectedTargetId || saving || viewingRunSnapshot || executing
          "
          @click="executeWorkflow"
        >
          <el-icon><VideoPlay /></el-icon>执行工作流
        </el-button>
        <el-button
          v-if="executing && activeRunId"
          type="danger"
          :loading="stoppingRun"
          @click="stopExecution"
        >
          <el-icon><VideoPause /></el-icon>停止
        </el-button>
      </div>
    </div>

    <Transition name="workflow-reveal">
      <el-alert
        v-if="showGuide"
        class="workflow-guide"
        type="info"
        :closable="true"
        show-icon
        @close="showGuide = false"
      >
        <template #title>五步完成一次评估</template>
        <ol class="guide-list">
          <li>
            <b>从开始出发</b>：默认模板已经连好“启动与范围 → 侦察 → 发现 → 验证
            → 复测 → 报告 → 结束”。
          </li>
          <li>
            <b>调整节点</b
            >：拖动阶段或工具节点；使用右侧能力卡的添加按钮把受控能力加入当前阶段。
          </li>
          <li>
            <b>手动连线</b
            >：从节点右侧圆点拖到下游节点左侧圆点。一个节点连出多条线代表并行，多个节点汇入同一节点代表等待全部完成。
          </li>
          <li>
            <b>填写输入</b
            >：选择项目授权目标，或新增输入；单击工具节点后在右侧填写端口、模式或检查项目。
          </li>
          <li>
            <b>保存或执行</b
            >：保存会生成项目工作流版本；执行会使用当前画布，高风险能力仍需人工确认。
          </li>
        </ol>
      </el-alert>
    </Transition>

    <div class="workflow-status-row">
      <span class="status-chip"
        ><el-icon><CircleCheck /></el-icon>{{ phaseNodes.length }} 个阶段 ·
        {{ toolNodes.length }} 个能力 · {{ connectedEdgeCount }} 条连线</span
      >
      <span v-if="graphReady" class="status-chip status-chip--ok"
        ><el-icon><CircleCheck /></el-icon>拓扑可保存</span
      >
      <span v-else class="status-chip status-chip--warn"
        ><el-icon><Warning /></el-icon>请修正拓扑后保存</span
      >
    </div>

    <el-alert
      v-if="graphNotice"
      class="graph-notice"
      type="success"
      :closable="true"
      :title="graphNotice"
      @close="graphNotice = ''"
    />
    <el-alert
      v-if="graphValidation.length"
      class="graph-validation"
      type="warning"
      :closable="false"
      show-icon
    >
      <template #title>当前拓扑需要调整</template>
      <ul>
        <li v-for="problem in graphValidation.slice(0, 5)" :key="problem">
          {{ problem }}
        </li>
      </ul>
    </el-alert>

    <div
      v-if="
        workflowRuns.length ||
        selectedRunDetail ||
        executing ||
        executeLogs.length
      "
      class="execute-panel"
      aria-label="工作流执行状态"
    >
      <div class="execute-head">
        <strong>工作流运行历史</strong>
        <div class="execute-head-actions">
          <el-select
            v-if="workflowRuns.length"
            v-model="selectedRunId"
            size="small"
            class="run-history-select"
            aria-label="工作流运行历史"
            @change="selectWorkflowRun"
          >
            <el-option
              v-for="run in workflowRuns"
              :key="run.id"
              :label="runOptionLabel(run)"
              :value="run.id"
            />
          </el-select>
          <span>{{ executeStatus }}</span>
          <el-button
            v-if="selectedRunDetail && !executing"
            size="small"
            type="danger"
            plain
            @click="clearSelectedRun"
          >
            清空结果
          </el-button>
          <el-button
            size="small"
            type="primary"
            plain
            @click="router.push('/findings')"
          >
            查看结果中心
          </el-button>
          <el-button
            v-if="
              selectedRunDetail &&
              selectedRunDetail.run.workflowDigest !==
                workflowSnapshot.specDigest &&
              !viewingRunSnapshot
            "
            size="small"
            type="primary"
            plain
            @click="viewSelectedRunSnapshot"
          >
            查看该次拓扑
          </el-button>
          <el-button
            v-if="viewingRunSnapshot"
            size="small"
            plain
            @click="returnToCurrentWorkflow"
          >
            返回当前工作流
          </el-button>
        </div>
      </div>
      <el-alert
        v-if="
          selectedRunDetail &&
          selectedRunDetail.run.workflowDigest !==
            workflowSnapshot.specDigest &&
          !viewingRunSnapshot
        "
        type="warning"
        :closable="false"
        title="当前画布版本与该次运行不同，节点结果暂不映射到当前拓扑。"
      />
      <el-progress
        :percentage="Math.round(executeProgress)"
        :status="
          executeStatus === '执行失败' || executeStatus === '部分任务失败'
            ? 'exception'
            : undefined
        "
        :indeterminate="executeIndeterminate"
        :duration="1.2"
      />
      <pre class="execute-log">{{ executeLogs.join("\n") }}</pre>
    </div>

    <div
      ref="workflowEditorLayoutRef"
      class="workflow-editor-layout"
      :class="{ 'is-fullscreen': isFullscreen }"
    >
      <section class="editor-card">
        <header class="editor-head">
          <div class="editor-head-copy">
            <h4>红队行动拓扑</h4>
            <p class="editor-head-desc">
              节点是评估阶段或受控能力，连线是依赖关系。开始和结束节点不可删除。
            </p>
          </div>
          <div class="editor-head-actions">
            <el-button
              size="small"
              :type="workflowConfigVisible ? 'primary' : 'default'"
              :aria-expanded="workflowConfigVisible"
              aria-controls="workflow-config-panel"
              @click="
                workflowConfigVisible
                  ? (workflowConfigVisible = false)
                  : openWorkflowConfig()
              "
            >
              <el-icon><Setting /></el-icon>工作流配置
            </el-button>
            <el-button size="small" :loading="loading" @click="load"
              ><el-icon><Refresh /></el-icon>重新加载</el-button
            >
          </div>
        </header>
        <div
          ref="flowCanvas"
          v-loading="loading"
          class="flow-canvas"
          @drop.prevent="onCanvasDrop"
          @dragover.prevent
        >
          <VueFlow
            id="red-team-workflow"
            v-model:nodes="nodes"
            v-model:edges="edges"
            :nodes-draggable="!viewingRunSnapshot"
            :nodes-connectable="!viewingRunSnapshot"
            :elements-selectable="true"
            :selection-mode="SelectionMode.Partial"
            :selection-key-code="'Shift'"
            :multi-selection-key-code="['Control', 'Meta']"
            :delete-key-code="null"
            :min-zoom="0.2"
            :max-zoom="1.6"
            class="red-team-flow"
            @connect="onConnect"
            @node-click="onNodeClick"
            @edge-click="onEdgeClick"
            @edge-mouse-enter="onEdgeMouseEnter"
            @edge-mouse-leave="onEdgeMouseLeave"
            @pane-click="onPaneClick"
            @pane-context-menu="onPaneContextMenu"
            @node-context-menu="onNodeContextMenu"
            @node-drag-start="onNodeDragStart"
            @node-drag="onNodeDrag"
            @node-drag-stop="onNodeDragStop"
            @selection-change="onSelectionChange"
          >
            <template #node-workflowNode="{ id, data }">
              <div
                class="workflow-node"
                :class="[
                  `workflow-node--${data.nodeKind}`,
                  `workflow-node--${data.phase}`,
                  { 'is-selected': id === selectedNodeId || selectedNodeIds.includes(id) },
                  nodeStatusClass(id),
                ]"
                @click.stop="onNodeClick({ node: nodes.find(n => n.id === id) || { id, data, position: { x: 0, y: 0 } }, event: $event } as any)"
                @dblclick="openNodeDetail(id)"
              >
                <Handle
                  v-if="id !== '__start__'"
                  type="target"
                  :position="Position.Left"
                  class="node-handle node-handle--target"
                />
                <div class="node-main">
                  <div class="node-topline">
                    <span class="node-icon"
                      ><FluentIcon :name="data.icon" /></span
                    ><span class="node-phase">{{
                      phaseOf(data.phase).shortLabel
                    }}</span
                    ><button
                      v-if="nodeRuns[id]"
                      type="button"
                      class="node-run-status"
                      :class="`is-${nodeRuns[id].status}`"
                      :aria-label="`查看${data.label}任务详情`"
                      title="查看任务详情"
                      @click.stop="openNodeDetail(id)"
                    >
                      <FluentIcon
                        :name="workflowStatusIcon(nodeRuns[id].status)"
                      /></button
                    ><button
                      v-if="data.nodeKind !== 'system' && !viewingRunSnapshot"
                      type="button"
                      class="node-remove"
                      aria-label="删除节点"
                      @click.stop="removeNode(id)"
                    >
                      <el-icon><Delete /></el-icon>
                    </button>
                  </div>
                  <strong>{{ data.label }}</strong>
                  <small>{{ data.desc }}</small>
                  <el-tag
                    v-if="data.tool"
                    size="small"
                    :type="data.risk === 'CAUTION' ? 'warning' : 'info'"
                    effect="plain"
                    >{{
                      nodeRuns[id]
                        ? nodeRunLabel(nodeRuns[id])
                        : data.risk === "CAUTION"
                          ? "需确认"
                          : "受控能力"
                    }}</el-tag
                  >
                </div>
                <Handle
                  v-if="id !== '__end__'"
                  type="source"
                  :position="Position.Right"
                  class="node-handle node-handle--source"
                />
              </div>
            </template>
            <template #edge-workflowEdge="edgeProps">
              <WorkflowEdge
                v-bind="edgeProps"
                :hovered="hoveredEdgeId === edgeProps.id"
                @remove="onRemoveEdge"
              />
            </template>
            <div class="workflow-zoom-controls" aria-label="画布缩放">
              <el-tooltip content="放大" placement="right" :show-after="350"
                ><button
                  type="button"
                  aria-label="放大"
                  @click.stop="zoomCanvasIn"
                >
                  <FluentIcon name="add" /></button
              ></el-tooltip>
              <el-tooltip content="缩小" placement="right" :show-after="350"
                ><button
                  type="button"
                  aria-label="缩小"
                  @click.stop="zoomCanvasOut"
                >
                  <FluentIcon name="subtract" /></button
              ></el-tooltip>
              <el-tooltip content="适应画布" placement="right" :show-after="350"
                ><button
                  type="button"
                  aria-label="适应画布"
                  @click.stop="fitWorkflowCanvas"
                >
                  <FluentIcon name="fit" /></button
              ></el-tooltip>
              <el-tooltip
                :content="isFullscreen ? '退出全屏' : '全屏显示'"
                placement="right"
                :show-after="350"
              >
                <button
                  type="button"
                  :aria-label="isFullscreen ? '退出全屏' : '全屏显示'"
                  @click.stop="toggleFullscreen"
                >
                  <FluentIcon
                    :name="isFullscreen ? 'fullscreen-exit' : 'fullscreen'"
                  />
                </button>
              </el-tooltip>
            </div>
          </VueFlow>
          <svg
            v-if="isAligning && (dragGuides.length || dragRulers.length)"
            class="workflow-align-overlay"
            aria-hidden="true"
          >
            <g
              v-for="(guide, i) in dragGuides"
              :key="`g-${i}`"
              class="align-guide"
              :class="`align-guide--${guide.axis}`"
            >
              <line
                :x1="alignToScreen(guide.x1, guide.y1).x"
                :y1="alignToScreen(guide.x1, guide.y1).y"
                :x2="alignToScreen(guide.x2, guide.y2).x"
                :y2="alignToScreen(guide.x2, guide.y2).y"
              />
            </g>
            <g
              v-for="(ruler, i) in dragRulers"
              :key="`r-${i}`"
              class="align-ruler"
              :class="`align-ruler--${ruler.axis}`"
            >
              <line
                :x1="alignToScreen(ruler.x1, ruler.y1).x"
                :y1="alignToScreen(ruler.x1, ruler.y1).y"
                :x2="alignToScreen(ruler.x2, ruler.y2).x"
                :y2="alignToScreen(ruler.x2, ruler.y2).y"
              />
              <rect
                class="align-ruler-badge"
                :x="alignToScreen(ruler.x, ruler.y).x - 22"
                :y="alignToScreen(ruler.x, ruler.y).y - 9"
                width="44"
                height="18"
                rx="4"
              />
              <text
                :x="alignToScreen(ruler.x, ruler.y).x"
                :y="alignToScreen(ruler.x, ruler.y).y"
                text-anchor="middle"
                dominant-baseline="middle"
                >{{ ruler.label }}</text
              >
            </g>
          </svg>
          <Transition name="workflow-popover">
            <aside
              v-if="workflowConfigVisible"
              id="workflow-config-panel"
              class="workflow-config-panel"
              role="dialog"
              aria-label="工作流配置"
              @click.stop
              @mousedown.stop
              @pointerdown.stop
              @wheel.stop
              @contextmenu.stop.prevent
            >
              <header class="workflow-config-head">
                <div>
                  <strong>工作流配置</strong>
                  <span>运行范围与拓扑模板</span>
                </div>
                <button
                  type="button"
                  aria-label="关闭工作流配置"
                  title="关闭"
                  @click="workflowConfigVisible = false"
                >
                  <el-icon><Dismiss /></el-icon>
                </button>
              </header>
              <div class="workflow-config-body">
                <label class="workflow-config-field">
                  <span>评估项目</span>
                  <el-select
                    v-model="selectedProjectId"
                    class="project-select"
                    aria-label="评估项目"
                    placeholder="选择评估项目"
                    :loading="loading"
                    :disabled="saving || executing || viewingRunSnapshot"
                    @change="changeProject"
                  >
                    <template #prefix
                      ><el-icon><FolderOpened /></el-icon
                    ></template>
                    <el-option
                      v-for="project in projects"
                      :key="project.id"
                      :value="project.id"
                      :label="project.name"
                    />
                  </el-select>
                </label>
                <label class="workflow-config-field">
                  <span>授权目标</span>
                  <el-select
                    v-model="selectedTargetId"
                    class="target-select"
                    aria-label="授权目标"
                    placeholder="选择授权目标"
                    :disabled="
                      !selectedProjectId || executing || viewingRunSnapshot
                    "
                  >
                    <el-option
                      v-for="target in linkedTargets"
                      :key="target.id"
                      :value="target.id"
                      :label="`${target.name} · ${target.targetValue}`"
                    />
                  </el-select>
                </label>
                <label class="workflow-config-field">
                  <span>工作流模板</span>
                  <el-select
                    v-model="preset"
                    class="preset-select"
                    aria-label="工作流模板"
                    :disabled="executing || viewingRunSnapshot"
                  >
                    <el-option
                      v-for="item in PRESETS"
                      :key="item.value"
                      :value="item.value"
                      :label="item.label"
                    />
                  </el-select>
                </label>
              </div>
              <footer class="workflow-config-actions">
                <el-button
                  :disabled="
                    !selectedProjectId || executing || viewingRunSnapshot
                  "
                  @click="openTargetInput"
                >
                  <el-icon><Plus /></el-icon>新增授权输入
                </el-button>
                <el-button
                  :disabled="executing || viewingRunSnapshot"
                  @click="resetPreset"
                >
                  <el-icon><Refresh /></el-icon>载入所选模板
                </el-button>
                <el-button @click="showGuide = !showGuide">
                  <el-icon><QuestionFilled /></el-icon>使用说明
                </el-button>
              </footer>
            </aside>
          </Transition>
          <Transition name="workflow-menu">
            <div
              v-if="workflowContextMenu.visible"
              class="workflow-context-menu"
              role="menu"
              aria-label="拓扑右键菜单"
              :style="{
                left: `${workflowContextMenu.x}px`,
                top: `${workflowContextMenu.y}px`,
              }"
              @click.stop
              @mousedown.stop
              @pointerdown.stop
              @wheel.stop
              @contextmenu.stop.prevent
            >
              <template v-if="!contextMenuNode">
                <button
                  type="button"
                  role="menuitem"
                  @click="openWorkflowConfig"
                >
                  <el-icon><Setting /></el-icon><span>工作流配置</span>
                </button>
                <button
                  type="button"
                  role="menuitem"
                  :disabled="
                    !selectedProjectId || executing || viewingRunSnapshot
                  "
                  @click="openTargetInputFromCanvas"
                >
                  <el-icon><Plus /></el-icon><span>新增授权输入</span>
                </button>
                <button
                  type="button"
                  role="menuitem"
                  :disabled="!clipboardNode || viewingRunSnapshot || executing"
                  @click="pasteFromContextMenu"
                >
                  <FluentIcon name="clipboard-paste" /><span>粘贴节点</span>
                  <small class="menu-shortcut">Ctrl+V</small>
                </button>
                <button
                  type="button"
                  role="menuitem"
                  :disabled="executing || viewingRunSnapshot"
                  @click="loadPresetFromContextMenu"
                >
                  <el-icon><Refresh /></el-icon><span>载入所选模板</span>
                </button>
                <button
                  type="button"
                  role="menuitem"
                  @click="showGuideFromCanvas"
                >
                  <el-icon><QuestionFilled /></el-icon><span>使用说明</span>
                </button>
                <button
                  type="button"
                  role="menuitem"
                  @click="fitWorkflowFromContextMenu"
                >
                  <FluentIcon name="fit" /><span>适应画布</span>
                </button>
              </template>
              <template v-else>
                <button
                  v-if="contextMenuNode.id === '__start__'"
                  type="button"
                  role="menuitem"
                  @click="configureContextNode"
                >
                  <el-icon><Setting /></el-icon><span>配置运行范围</span>
                </button>
                <button
                  v-else-if="contextMenuNode.data.nodeKind === 'tool'"
                  type="button"
                  role="menuitem"
                  @click="configureContextNode"
                >
                  <el-icon><Setting /></el-icon><span>配置节点参数</span>
                </button>
                <button
                  v-if="
                    contextMenuNode.data.nodeKind !== 'system' &&
                    !viewingRunSnapshot &&
                    !executing
                  "
                  type="button"
                  role="menuitem"
                  @click="copyContextNode"
                >
                  <FluentIcon name="copy" /><span>复制节点</span>
                  <small class="menu-shortcut">Ctrl+C</small>
                </button>
                <button
                  v-if="nodeRuns[contextMenuNode.id]"
                  type="button"
                  role="menuitem"
                  @click="openContextNodeDetail"
                >
                  <el-icon><CircleCheck /></el-icon><span>查看任务详情</span>
                </button>
                <button
                  v-if="
                    contextMenuNode.data.nodeKind !== 'system' &&
                    !viewingRunSnapshot
                  "
                  type="button"
                  role="menuitem"
                  class="is-danger"
                  @click="deleteContextNode"
                >
                  <el-icon><Delete /></el-icon><span>删除节点</span>
                </button>
                <span
                  v-if="
                    contextMenuNode.id === '__end__' &&
                    !nodeRuns[contextMenuNode.id]
                  "
                  class="workflow-context-menu-note"
                  >固定结束节点</span
                >
              </template>
            </div>
          </Transition>
        </div>
        <footer class="editor-foot">
          <span
            >提示：按住 Shift 拖动鼠标可框选多个节点；按住 Ctrl 点击可多选；Ctrl+C 批量复制 / Delete 批量删除。</span
          ><span v-if="selectedNodeIds.length > 1"
            >已多选 {{ selectedNodeIds.length }} 个节点：Ctrl+C 批量复制 / Delete 批量删除</span
          ><span v-else-if="selectedNode"
            >已选节点：{{ selectedNode.data.label
            }}{{
              selectedNode.data.nodeKind === "system"
                ? "（固定保留）"
                : "，Ctrl+C 直接复制 / Delete 删除"
            }}</span
          ><span v-else-if="selectedEdgeId"
            >已选连线：按 Delete 或点击连线上的 ✕ 删除</span
          >
        </footer>
      </section>

      <aside class="workflow-library">
        <div class="workflow-library-nav">
          <el-segmented
            v-model="rightSidebarTab"
            class="workflow-library-tabs"
            :options="[
              { label: '阶段与能力库', value: 'library' },
              { label: '节点配置', value: 'node' },
            ]"
          >
            <template #default="{ item }">
              <span class="workflow-tab-label">
                <FluentIcon
                  :name="item.value === 'library' ? 'branch-fork' : 'edit'"
                />
                <span>{{ item.label }}</span>
                <span
                  v-if="item.value === 'node' && selectedNode"
                  class="tab-node-badge"
                  title="已选中节点"
                />
              </span>
            </template>
          </el-segmented>
        </div>
        <div ref="libraryScroll" class="library-scroll">
         <div v-show="rightSidebarTab === 'node'" class="node-tab-pane">
         <section
           v-if="selectedToolNode"
           ref="nodeInputEditor"
           class="node-input-editor"
           aria-label="已选节点参数"
         >
            <div class="node-editor-header">
              <div class="node-editor-title-row">
                <h5 class="node-editor-title">已选节点 · {{ selectedToolNode.data.label }}</h5>
                <el-tag
                  size="small"
                  :type="agentOf(selectedToolNode.data.tool)?.risk === 'SAFE' ? 'info' : 'warning'"
                  effect="plain"
                  class="node-risk-tag"
                >
                  {{ phaseOf(selectedToolNode.data.phase).shortLabel }}
                </el-tag>
              </div>
              <p class="node-editor-desc">
                {{ agentOf(selectedToolNode.data.tool)?.desc || '在授权目标范围内执行具体的检测与分析任务。' }}
              </p>
            </div>

            <div class="node-editor-body">
            <el-form
              label-position="top"
              size="small"
              :disabled="executing || viewingRunSnapshot"
            >
              <el-form-item
                v-if="
                  ['tcp_ports', 'nmap_service_scan', 'fscan_scan'].includes(
                    selectedToolNode.data.tool || '',
                  )
                "
                label="扫描端口"
              >
                <el-input
                  v-model="selectedPortsInput"
                  placeholder="例如 80,443,8000-8100"
                />
                <small class="input-hint">
                  必须是当前授权目标端口范围的子集。
                </small>
              </el-form-item>

              <el-form-item
                v-if="selectedToolNode.data.tool === 'fscan_scan'"
                label="扫描模式"
              >
                <el-radio-group v-model="selectedFscanVulnMode">
                  <el-radio-button value="SAFE">安全（默认）</el-radio-button>
                  <el-radio-button value="FINGERPRINT"
                    >指纹</el-radio-button
                  >
                  <el-radio-button value="FULL">完整</el-radio-button>
                </el-radio-group>
                <small class="input-hint">
                  完整模式可能包含爆破/弱口令类检测，请在授权范围内谨慎使用。
                </small>
              </el-form-item>

              <el-form-item
                v-if="selectedToolNode.data.tool === 'nmap_service_scan'"
                label="识别模式"
              >
                <el-radio-group v-model="selectedNmapMode">
                  <el-radio-button value="quick">快速探测</el-radio-button>
                  <el-radio-button value="service">服务识别</el-radio-button>
                </el-radio-group>
              </el-form-item>

              <el-form-item
                v-if="selectedToolNode.data.tool === 'http_security_check'"
                label="检查项目"
              >
                <el-select v-model="selectedHttpCheck">
                  <el-option value="cookies" label="Cookie 安全属性" />
                  <el-option value="cors" label="CORS 跨域策略" />
                  <el-option value="methods" label="危险 HTTP 方法" />
                  <el-option value="disclosure" label="技术栈信息泄露" />
                </el-select>
              </el-form-item>

              <template
                v-if="
                  ['afrog_scan', 'xray_scan', 'nuclei_scan'].includes(
                    selectedToolNode.data.tool || '',
                  )
                "
              >
                <el-form-item label="PoC / 模板范围">
                  <el-checkbox v-model="selectedAllPocs">
                    使用已同步且启用的全部 PoC / 模板
                  </el-checkbox>
                </el-form-item>
                <el-form-item v-if="!selectedAllPocs" label="指定 PoC / 模板">
                  <el-select
                    v-model="selectedPocCodesList"
                    popper-class="workflow-poc-select-popper"
                    multiple
                    filterable
                    allow-create
                    remote
                    reserve-keyword
                    default-first-option
                    collapse-tags
                    collapse-tags-tooltip
                    :max-collapse-tags="2"
                    :multiple-limit="50"
                    :loading="pocLoading"
                    :placeholder="`下拉选择或直接输入编号 (如 NT-xxx)`"
                    :remote-method="loadPocOptionsForTool"
                    @visible-change="(visible: boolean) => visible && !pocOptions.length && loadPocOptionsForTool()"
                  >
                    <el-option
                      v-for="poc in pocOptions"
                      :key="poc.vulnerabilityCode"
                      :label="formatPocOptionLabel(poc)"
                      :value="poc.vulnerabilityCode"
                    >
                      <div class="workflow-poc-option">
                        <span class="workflow-poc-option-main">
                          <b>{{ poc.name }}</b>
                          <small>{{ poc.sourceExternalId || poc.vulnerabilityCode }}</small>
                        </span>
                        <span class="workflow-poc-option-tags">
                          <el-tag size="small" :type="pocSeverityTagType(poc.severity)" effect="plain">
                            {{ poc.severity }}
                          </el-tag>
                          <el-tag
                            v-if="poc.scanSafety && poc.scanSafety !== 'SAFE'"
                            size="small"
                            type="warning"
                            effect="plain"
                          >
                            {{ poc.scanSafety }}
                          </el-tag>
                        </span>
                      </div>
                    </el-option>
                  </el-select>
                  <small class="input-hint">
                    可搜索选择已有 PoC，或直接键入/粘贴编号后回车创建，最多 50 个。
                  </small>
                </el-form-item>
              </template>

              <div
                v-if="
                  [
                    'retrieve_project_context',
                    'http_headers',
                    'tls_config',
                  ].includes(selectedToolNode.data.tool || '')
                "
               class="node-input-empty"
             >
                <div class="node-empty-icon-wrap">
                  <FluentIcon name="info" />
                </div>
                <div class="node-empty-text">
                  <span class="node-empty-title">继承全局授权配置</span>
                  <p class="node-empty-desc">
                    此节点直接使用工作流配置中的授权目标与边界，无额外独立参数。
                  </p>
                </div>
              </div>
            </el-form>
            </div>
          </section>
            <section
              v-else-if="selectedNode"
              class="node-input-editor"
              aria-label="已选节点属性"
            >
              <template v-if="selectedNode.id === '__end__'">
                <div class="node-editor-header">
                  <div class="node-editor-title-row">
                    <h5 class="node-editor-title">结束节点 · {{ selectedNode.data.label }}</h5>
                    <el-tag size="small" type="success" effect="plain" class="node-risk-tag">结果</el-tag>
                  </div>
                  <p class="node-editor-desc">
                    聚合当前运行全部任务的发现并给出整体结论，可同步留存到结果中心。
                  </p>
                </div>
                <div class="node-editor-body">
                  <template v-if="selectedRunDetail">
                    <div class="end-run-stats">
                      <div class="end-run-stat">
                        <strong>{{ endNodeSummary.findings.length }}</strong>
                        <span>发现总数</span>
                      </div>
                      <div class="end-run-stat">
                        <strong>{{ endNodeSummary.finished }}/{{ endNodeSummary.total }}</strong>
                        <span>完成任务</span>
                      </div>
                      <div class="end-run-stat">
                        <strong>{{ runStatusLabel(selectedRunDetail.run.status) }}</strong>
                        <span>运行状态</span>
                      </div>
                    </div>
                    <div v-if="endNodeSummary.findings.length" class="end-severity-row">
                      <el-tag
                        v-for="sev in (['critical', 'high', 'medium', 'low', 'info'] as const)"
                        :key="sev"
                        size="small"
                        :type="endFindingTagType(sev)"
                        effect="plain"
                        class="end-severity-tag"
                      >
                        {{ sev }} {{ endNodeSummary.severity[sev] }}
                      </el-tag>
                    </div>
                    <h6 class="end-finding-head">发现明细</h6>
                    <p v-if="!endNodeSummary.findings.length" class="node-editor-hint">
                      本轮运行暂未产生可留存的发现。
                    </p>
                    <ul v-else class="end-finding-list">
                      <li
                        v-for="finding in endNodeSummary.findings"
                        :key="finding.key"
                        class="end-finding-item"
                        @click="openEndFinding(finding)"
                      >
                        <el-tag
                          size="small"
                          :type="endFindingTagType(finding.severity)"
                          effect="plain"
                          class="end-finding-sev"
                          >{{ (finding.severity || 'info').toUpperCase() }}</el-tag
                        >
                        <span class="end-finding-title">{{ finding.title }}</span>
                      </li>
                    </ul>
                    <el-button
                      size="small"
                      type="primary"
                      class="node-config-action"
                      @click="syncEndResultsToCenter"
                    >
                      同步到结果中心
                    </el-button>
                    <p class="node-editor-hint">
                      发现已随任务执行自动留存，点击同步打开结果中心核对与导出。
                    </p>
                  </template>
                  <template v-else>
                    <p class="node-editor-hint">尚未选择运行记录，先执行工作流或选择一次运行即可查看汇总结果。</p>
                  </template>
                </div>
              </template>
              <template v-else>
                <div class="node-editor-header">
                  <div class="node-editor-title-row">
                    <h5 class="node-editor-title">已选节点 · {{ selectedNode.data.label }}</h5>
                    <el-tag size="small" type="info" effect="plain" class="node-risk-tag">
                      {{ selectedNode.data.nodeKind === "phase" ? "流程阶段" : "全局起点" }}
                    </el-tag>
                  </div>
                  <p class="node-editor-desc">
                    {{ selectedNode.data.nodeKind === "phase" ? "用于组织能力依赖与执行流向，不直接发送网络请求。" : "定义项目评估范围与全局授权目标边界。" }}
                  </p>
                </div>
                <div class="node-editor-body">
                <div class="node-info-list">
                  <div class="node-info-item">
                    <span>节点类型</span>
                    <span>{{ selectedNode.data.nodeKind === "phase" ? "流程阶段分组节点" : "工作流起点（运行范围输入）" }}</span>
                  </div>
                  <div class="node-info-item">
                    <span>执行角色</span>
                    <span>{{ selectedNode.data.nodeKind === "phase" ? "固定阶段节点，用于组织能力流向与依赖关系，不直接发送网络请求。" : "定义评估项目的授权目标、端口范围及全局请求上下文。" }}</span>
                  </div>
                  <el-button
                    v-if="selectedNode.data.nodeKind === 'system'"
                    size="small"
                    type="primary"
                    plain
                    class="node-config-action"
                    @click="openWorkflowConfig"
                  >
                    配置全局运行范围
                  </el-button>
                </div>
                </div>
              </template>
            </section>
            <div v-else class="node-tab-empty">
              <FluentIcon name="edit" />
              <strong>未选择节点</strong>
              <p>在左侧画布中点击任意节点，即可在此查看或修改其输入参数与运行属性。</p>
            </div>
          </div>

          <div v-show="rightSidebarTab === 'library'" class="library-tab-pane">
          <div class="library-head">
            <div>
              <h4>能力库</h4>
              <p>阶段用于组织流程；能力是在授权范围内执行的具体检查。</p>
            </div>
          </div>

          <section
            class="phase-library"
            :class="{ collapsed: !phaseLibraryExpanded }"
            aria-label="流程阶段列表"
          >
            <div class="library-section-head">
              <button
                type="button"
                class="library-section-toggle"
                :aria-expanded="phaseLibraryExpanded"
                aria-controls="workflow-phase-library-body"
                :aria-label="
                  phaseLibraryExpanded ? '收起流程阶段' : '展开流程阶段'
                "
                @click="phaseLibraryExpanded = !phaseLibraryExpanded"
              >
                <el-icon class="library-section-chevron"><ArrowDown /></el-icon>
                <span>
                  <h5>流程阶段</h5>
                  <p>用于组织能力和依赖，不会直接执行检查。</p>
                </span>
              </button>
            </div>
            <div
              id="workflow-phase-library-body"
              class="library-section-body"
              :aria-hidden="!phaseLibraryExpanded"
              :inert="!phaseLibraryExpanded"
            >
              <div class="library-section-body-inner">
                <div class="phase-library-grid">
                  <div
                    v-for="phase in PHASES"
                    :key="phase.code"
                    class="phase-library-item"
                    :class="{
                      'is-present': hasCanonicalPhaseNode(phase.code),
                      'is-selected': selectedPhase === phase.code,
                    }"
                    :data-phase-code="phase.code"
                    :draggable="!hasCanonicalPhaseNode(phase.code)"
                    @click="selectedPhase = phase.code"
                    @dragstart="onPhaseDragStart($event, phase.code)"
                  >
                    <span class="phase-library-icon"
                      ><FluentIcon :name="phase.icon"
                    /></span>
                    <span class="phase-library-copy">
                      <strong>{{ phase.shortLabel }}</strong>
                      <small>流程阶段 · 用于组织能力和依赖</small>
                    </span>
                    <el-tooltip
                      :content="
                        hasCanonicalPhaseNode(phase.code)
                          ? '该阶段已在画布中'
                          : `加回${phase.shortLabel}阶段`
                      "
                      placement="left"
                      :show-after="350"
                    >
                      <button
                        type="button"
                        class="phase-library-action"
                        :class="{
                          'is-present': hasCanonicalPhaseNode(phase.code),
                        }"
                        :disabled="hasCanonicalPhaseNode(phase.code)"
                        :aria-label="
                          hasCanonicalPhaseNode(phase.code)
                            ? `${phase.shortLabel}阶段已添加`
                            : `加回${phase.shortLabel}阶段`
                        "
                        @click.stop="addPhaseNode(phase.code)"
                      >
                        <el-icon v-if="hasCanonicalPhaseNode(phase.code)"
                          ><Check
                        /></el-icon>
                        <el-icon v-else><Plus /></el-icon>
                      </button>
                    </el-tooltip>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section
            class="capability-library"
            :class="{ collapsed: !capabilityLibraryExpanded }"
            aria-label="受控能力列表"
          >
            <div class="library-section-head capability-library-head">
              <button
                type="button"
                class="library-section-toggle"
                :aria-expanded="capabilityLibraryExpanded"
                aria-controls="workflow-capability-library-body"
                :aria-label="
                  capabilityLibraryExpanded ? '收起受控能力' : '展开受控能力'
                "
                @click="capabilityLibraryExpanded = !capabilityLibraryExpanded"
              >
                <el-icon class="library-section-chevron"><ArrowDown /></el-icon>
                <span>
                  <h5>受控能力</h5>
                  <p>选择阶段后，只显示该阶段可执行的具体检查。</p>
                </span>
              </button>
              <el-select
                v-model="selectedPhase"
                size="small"
                aria-label="能力所属阶段"
              >
                <el-option
                  v-for="phase in sortedPhases"
                  :key="phase.code"
                  :value="phase.code"
                  :label="phase.shortLabel"
                />
              </el-select>
            </div>
            <div
              id="workflow-capability-library-body"
              class="library-section-body"
              :aria-hidden="!capabilityLibraryExpanded"
              :inert="!capabilityLibraryExpanded"
            >
              <div class="library-section-body-inner">
                <div
                  v-for="agent in filteredAgents"
                  :key="agent.tool"
                  class="library-item"
                  :class="{
                    caution: agent.risk !== 'SAFE',
                    'is-selected': selectedToolNode?.data.tool === agent.tool,
                  }"
                  :data-tool="agent.tool"
                  draggable="true"
                  @dragstart="onLibraryDragStart($event, agent.tool)"
                >
                  <span class="library-icon"
                    ><FluentIcon :name="agent.icon"
                  /></span>
                  <span class="library-copy"
                    ><strong>{{ agent.name }}</strong
                    ><small>{{ agent.desc }}</small
                    ><em
                      >{{ phaseOf(agent.phase).shortLabel }} ·
                      {{ agent.risk === "SAFE" ? "低影响" : "需人工确认" }}</em
                    ></span
                  >
                  <el-tooltip
                    content="加入选定阶段"
                    placement="left"
                    :show-after="350"
                    ><button
                      type="button"
                      class="library-add"
                      aria-label="加入选定阶段"
                      @click="addToolNode(agent.tool)"
                    >
                      <el-icon><Plus /></el-icon></button
                  ></el-tooltip>
                </div>
                <div v-if="!filteredAgents.length" class="library-empty">
                  <FluentIcon :name="phaseOf(selectedPhase).icon" />
                  <strong
                    >{{
                      phaseOf(selectedPhase).shortLabel
                    }}暂无可添加的受控能力</strong
                  >
                  <small>该阶段用于组织流程、确认结论或交付结果。</small>
                </div>
              </div>
            </div>
          </section>
          </div>
        </div>

        <div
          class="suggest-panel"
          ref="suggestPanelEl"
          :class="{ collapsed: !suggestExpanded }"
          :style="
            suggestExpanded && suggestHeight
              ? { height: suggestHeight + 'px', maxHeight: suggestHeight + 'px' }
              : undefined
          "
          aria-label="大模型实时建议"
        >
          <div
            v-if="suggestExpanded"
            class="suggest-resizer"
            title="拖动调整建议面板高度"
            @pointerdown="startSuggestResize"
          ></div>
          <div class="suggest-head">
            <button
              type="button"
              class="suggest-toggle"
              :aria-expanded="suggestExpanded"
              @click="suggestExpanded = !suggestExpanded"
            >
              <div>
                <h4>大模型实时建议</h4>
                <p v-if="suggestLoading">正在根据当前拓扑生成建议…</p>
                <p v-else-if="!suggestExpanded">
                  {{
                    suggestions.length
                      ? `已有 ${suggestions.length} 条建议，点击展开`
                      : "点击展开建议面板"
                  }}
                </p>
                <p v-else-if="suggestSource">来源：{{ suggestSourceLabel(suggestSource) }}</p>
                <p v-else>编辑工作流时自动刷新</p>
              </div>
              <span class="suggest-chevron" aria-hidden="true">{{
                suggestExpanded ? "收起" : "展开"
              }}</span>
            </button>
            <el-button
              size="small"
              :loading="suggestLoading"
              @click="refreshSuggestions('manual')"
              ><el-icon><Refresh /></el-icon>刷新</el-button
            >
          </div>
          <div
            id="workflow-suggestion-body"
            class="suggest-content"
            :aria-hidden="!suggestExpanded"
            :inert="!suggestExpanded"
          >
            <div class="suggest-content-inner">
              <p v-if="suggestNote" class="suggest-note">{{ suggestNote }}</p>
              <div
                v-if="!suggestions.length && !suggestLoading"
                class="suggest-empty"
              >
                暂无建议。添加或调整节点后，这里会给出编排提示。
              </div>
              <article
                v-for="item in suggestions"
                :key="item.id"
                class="suggest-card"
                :class="[`suggest-card--${item.severity || 'info'}`]"
              >
                <header>
                  <strong>{{ localizeSuggestionText(item.title) }}</strong>
                  <el-tag
                    size="small"
                    effect="plain"
                    :type="item.severity === 'warning' ? 'warning' : 'info'"
                    >{{ suggestionKindLabel(item.kind) }}</el-tag
                  >
                </header>
                <p>{{ localizeSuggestionText(item.detail) }}</p>
                <div v-if="item.action" class="suggest-actions">
                  <el-button
                    size="small"
                    type="primary"
                    plain
                    @click="applySuggestion(item)"
                  >
                    {{
                      item.action.type === "add_tool"
                        ? "一键加入"
                        : item.action.type === "focus_node"
                          ? "定位节点"
                          : "应用"
                    }}
                  </el-button>
                </div>
              </article>
            </div>
          </div>
        </div>
      </aside>
    </div>

    <el-dialog
      v-model="targetInputVisible"
      title="新增工作流输入"
      width="560px"
      append-to-body
    >
      <el-form label-position="top" :model="targetInput">
        <div class="target-input-grid">
          <el-form-item label="名称">
            <el-input v-model="targetInput.name" placeholder="用于内部识别" />
          </el-form-item>
          <el-form-item label="目标类型">
            <el-select v-model="targetInput.targetType">
              <el-option label="域名" value="domain" />
              <el-option label="IP 地址" value="ip" />
              <el-option label="URL" value="url" />
            </el-select>
          </el-form-item>
        </div>
        <el-form-item label="目标地址">
          <el-input
            v-model="targetInput.targetValue"
            placeholder="example.com、192.0.2.10 或 https://example.com"
          />
        </el-form-item>
        <el-form-item label="端口授权模式">
          <div class="port-picker">
            <div class="full-port-option">
              <div>
                <b>整机全端口模式（1-65535）</b>
                <small>将整台主机的所有端口作为目标，开放全暴露面深度探测（使用 Nmap）。</small>
              </div>
              <el-switch v-model="targetInputFullPortAccess" />
            </div>
            <div v-if="!targetInputFullPortAccess" class="custom-port-section">
              <span class="custom-port-label">允许测试的指定服务端口：</span>
              <el-select
                v-model="targetInputSelectedPorts"
                multiple
                filterable
                allow-create
                collapse-tags
                collapse-tags-tooltip
                default-first-option
                placeholder="选择常用端口或手动输入，如 8000, 8080-8090"
              >
                <el-option
                  v-for="port in COMMON_PORT_OPTIONS"
                  :key="port.value"
                  :label="port.label"
                  :value="port.value"
                />
              </el-select>
            </div>
            <p class="port-hint">
              {{
                targetInputFullPortAccess
                  ? "已开启整机全端口模式，将保存为 1-65535；适用于靶场或整机全面黑盒评估。"
                  : "已开启指定端口模式，超出此端口集合的请求将在执行前被平台授权守卫拦截保护。"
              }}
            </p>
          </div>
        </el-form-item>
        <el-form-item label="授权记录">
          <el-input
            v-model="targetInput.authorizationNote"
            type="textarea"
            :rows="3"
            placeholder="填写授权来源、允许测试的范围和停止条件"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="targetInputVisible = false">取消</el-button>
        <el-button
          type="primary"
          :loading="targetInputSaving"
          @click="createTargetInput"
        >
          登记并选中
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="nodeDetailVisible"
      :title="nodeDetailTitle"
      width="640px"
      append-to-body
    >
      <div v-if="nodeDetailRun" class="node-detail-body">
        <p class="node-detail-meta">
          <el-tag :type="nodeStatusType(nodeDetailRun.status)" effect="dark">
            {{ statusLabel(nodeDetailRun.status) }}
          </el-tag>
          <span v-if="nodeDetailRun.taskId"
            >任务 #{{ nodeDetailRun.taskId }}</span
          >
          <span v-if="nodeDetailRun.resultCount"
            >{{ nodeDetailRun.resultCount }} 项结果</span
          >
        </p>
        <p v-if="nodeDetailRun.summary" class="node-detail-summary">
          {{ nodeDetailRun.summary }}
        </p>
        <pre v-if="nodeDetailRun.output" class="node-detail-log">{{
          JSON.stringify(nodeDetailRun.output, null, 2)
        }}</pre>
        <pre v-if="nodeDetailRun.log" class="node-detail-log">{{
          nodeDetailRun.log
        }}</pre>
        <el-empty
          v-if="
            !nodeDetailRun.summary &&
            !nodeDetailRun.output &&
            !nodeDetailRun.log
          "
          description="暂无结构化输出"
        />
      </div>
    </el-dialog>

    <el-dialog
      v-model="endFindingDetailVisible"
      :title="endFindingDetail?.title || '发现详情'"
      width="620px"
      append-to-body
    >
      <div v-if="endFindingDetail" class="end-finding-detail">
        <div class="node-detail-meta">
          <el-tag :type="endFindingTagType(endFindingDetail.severity)" effect="dark">
            {{ (endFindingDetail.severity || 'info').toUpperCase() }}
          </el-tag>
          <span v-if="endFindingDetail.sourceTool"
            >来源：{{ endFindingDetail.sourceTool }}</span
          >
          <span v-if="endFindingDetail.vulnerabilityCode"
            >{{ endFindingDetail.vulnerabilityCode }}</span
          >
          <span v-if="endFindingDetail.taskId"
            >任务 #{{ endFindingDetail.taskId }}</span
          >
        </div>
        <p v-if="endFindingDetail.description" class="node-detail-summary">
          {{ endFindingDetail.description }}
        </p>
        <template v-if="endFindingDetail.evidence">
          <h6 class="end-finding-field">证据</h6>
          <pre class="node-detail-log">{{ endFindingDetail.evidence }}</pre>
        </template>
        <template v-if="endFindingDetail.remediation">
          <h6 class="end-finding-field">修复建议</h6>
          <p class="node-detail-summary">{{ endFindingDetail.remediation }}</p>
        </template>
      </div>
    </el-dialog>
  </section>
</template>

<style scoped>
.workflow-page.workflow-page {
  display: flex;
  flex-direction: column;
  gap: 0;
  min-height: 0;
  height: 100%;
  padding: 0;
  overflow: hidden;
}
.workflow-page > .section-head,
.workflow-page > .workflow-guide,
.workflow-page > .workflow-status-row,
.workflow-page > .graph-notice,
.workflow-page > .graph-validation,
.workflow-page > .el-alert {
  flex: none;
}
.workflow-page > .section-head {
  margin: 0 0 12px !important;
  gap: 12px !important;
  align-items: flex-start;
}
.workflow-page > .section-head h3 {
  margin: 0 !important;
  line-height: 1.3;
}
.workflow-head-copy {
  min-width: 0;
  flex: 1 1 auto;
}
.workflow-page > .section-head p {
  display: block !important;
  margin: 4px 0 0 !important;
  max-width: 62ch;
  line-height: 1.45 !important;
  white-space: normal !important;
  overflow: visible !important;
  -webkit-line-clamp: unset !important;
}
.workflow-context-summary {
  display: flex;
  min-width: 0;
  flex-wrap: wrap;
  gap: 3px 14px;
  margin-top: 7px;
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.5;
  white-space: normal;
}
.workflow-context-summary span {
  min-width: 0;
  max-width: 100%;
  overflow-wrap: anywhere;
  text-overflow: clip;
}
.workflow-context-summary b {
  margin-right: 5px;
  color: var(--app-text);
  font-weight: 600;
}
.workflow-actions {
  flex: 0 0 auto;
  gap: 8px !important;
}
.workflow-actions :deep(.el-button) {
  min-height: 30px !important;
}

.workflow-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.workflow-actions :deep(.el-button) {
  min-height: 32px;
  margin: 0;
}
.workflow-actions :deep(.el-select__wrapper) {
  min-height: 32px;
}
.preset-select {
  width: 170px;
}
.project-select {
  width: 200px;
}
.target-select {
  width: 240px;
}
.workflow-guide {
  margin: 0 0 10px;
}
.workflow-guide :deep(.el-alert) {
  padding: 8px 12px;
}
.workflow-guide :deep(.el-alert__title) {
  font-size: 12px;
  line-height: 1.35;
}
.workflow-guide :deep(.el-alert__description) {
  margin-top: 4px !important;
}
.guide-list {
  margin: 2px 0 0 !important;
  padding-left: 16px !important;
  line-height: 1.55 !important;
  font-size: 12px !important;
}
.guide-list li + li {
  margin-top: 2px;
}
.workflow-guide :deep(.el-alert__content) {
  max-width: 100%;
  overflow: visible;
}
.workflow-guide :deep(.el-alert__description) {
  margin-top: 6px;
  max-height: none;
  overflow: visible;
}
.guide-list b {
  color: var(--app-text);
}
.workflow-status-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  margin: 0 0 4px;
}
.status-chip {
  min-height: 28px !important;
  padding: 0 9px !important;
  font-size: 11px !important;
}
.status-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-height: 32px;
  padding: 0 11px;
  border: 1px solid var(--app-border);
  border-radius: 999px;
  background: var(--app-surface-soft);
  color: var(--app-muted);
  font-size: var(--type-caption);
}
.status-chip--ok {
  border-color: color-mix(in srgb, #2e9d67 55%, var(--app-border));
  color: #18794e;
}
.status-chip--warn {
  border-color: color-mix(in srgb, #c88719 55%, var(--app-border));
  color: #8a5a08;
}
.graph-notice,
.graph-validation {
  margin-bottom: 4px;
}
.graph-notice :deep(.el-alert),
.graph-validation :deep(.el-alert),
.workflow-guide :deep(.el-alert) {
  position: relative;
  display: flex;
  align-items: center;
}
.graph-notice :deep(.el-alert__content),
.workflow-guide :deep(.el-alert__content) {
  display: flex;
  align-items: center;
  min-height: 22px;
  padding-right: 8px;
}
.graph-notice :deep(.el-alert__title) {
  line-height: 22px;
  padding: 0;
}
.graph-notice :deep(.el-alert__close-btn),
.graph-validation :deep(.el-alert__close-btn),
.workflow-guide :deep(.el-alert__close-btn) {
  top: 50% !important;
  right: 12px !important;
  transform: translateY(-50%);
  margin-top: 0 !important;
  display: inline-flex !important;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  font-size: 14px;
  line-height: 1;
}

.graph-validation ul {
  margin: 4px 0 0;
  padding-left: 17px;
  line-height: 1.6;
}
.workflow-editor-layout {
  display: grid;
  flex: 1 1 auto;
  grid-template-columns: minmax(0, 1fr) minmax(380px, 420px);
  gap: 18px;
  align-items: stretch;
  min-height: 0;
  height: 100%;
}
.workflow-editor-layout.is-fullscreen,
.workflow-editor-layout:fullscreen,
.workflow-editor-layout:-webkit-full-screen {
  position: fixed !important;
  top: 0 !important;
  left: 0 !important;
  right: 0 !important;
  bottom: 0 !important;
  width: 100vw !important;
  height: 100vh !important;
  z-index: 2000 !important;
  background-color: light-dark(#eaf3fb, #12161f) !important;
  background-image:
    radial-gradient(
      circle at 1px 1px,
      light-dark(rgba(0, 120, 212, 0.18), rgba(255, 255, 255, 0.07)) 1.2px,
      transparent 0
    ),
    radial-gradient(
      ellipse 80% 50% at 50% 0%,
      light-dark(rgba(0, 120, 212, 0.16), rgba(0, 120, 212, 0.22)) 0%,
      transparent 80%
    ),
    linear-gradient(
      135deg,
      light-dark(#edf6fd, #161c28) 0%,
      light-dark(#e3eef9, #0e121a) 100%
    ) !important;
  background-size: 24px 24px, 100% 100%, 100% 100% !important;
  padding: 14px !important;
  box-sizing: border-box !important;
  margin: 0 !important;
  grid-template-columns: minmax(0, 1fr) minmax(380px, 420px) !important;
  gap: 14px !important;
  min-height: 100vh !important;
  animation: fluentFullscreenEnter 300ms cubic-bezier(0.1, 0.9, 0.2, 1) both;
}
.workflow-editor-layout:fullscreen,
.workflow-editor-layout:-webkit-full-screen {
  position: static !important;
  width: 100% !important;
  height: 100% !important;
}
.workflow-editor-layout.is-fullscreen .editor-card,
.workflow-editor-layout:fullscreen .editor-card,
.workflow-editor-layout:-webkit-full-screen .editor-card {
  height: 100% !important;
  min-height: 0 !important;
  box-shadow: var(--fluent-shadow-16) !important;
  animation: fluentCardRise 320ms cubic-bezier(0.1, 0.9, 0.2, 1) both;
}
.workflow-editor-layout.is-fullscreen .workflow-library,
.workflow-editor-layout:fullscreen .workflow-library,
.workflow-editor-layout:-webkit-full-screen .workflow-library {
  height: 100% !important;
  min-height: 0 !important;
  box-shadow: var(--fluent-shadow-16) !important;
  animation: fluentCardRise 320ms cubic-bezier(0.1, 0.9, 0.2, 1) 50ms both;
}
.workflow-editor-layout.is-fullscreen .flow-canvas,
.workflow-editor-layout:fullscreen .flow-canvas,
.workflow-editor-layout:-webkit-full-screen .flow-canvas {
  height: 100% !important;
  min-height: 0 !important;
}

@keyframes fluentFullscreenEnter {
  from {
    opacity: 0;
    transform: scale(0.96);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}

@keyframes fluentCardRise {
  from {
    opacity: 0.7;
    transform: translateY(12px) scale(0.985);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}
.editor-card {
  display: flex;
  min-height: 0;
  height: 100%;
  flex-direction: column;
  overflow: hidden;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface);
}
.workflow-library {
  display: flex;
  height: 100%;
  min-height: 0;
  flex: none;
  flex-direction: column;
  overflow: hidden;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface);
}
.editor-card > .editor-head,
.workflow-page .editor-head {
  display: flex !important;
  flex-direction: row !important;
  align-items: center !important;
  justify-content: space-between !important;
  gap: 16px 20px !important;
  width: 100%;
  box-sizing: border-box;
  padding: 12px 16px !important;
  border-bottom: 1px solid var(--app-border);
}
.editor-head-copy {
  display: flex;
  min-width: 0;
  flex: 1 1 auto;
  flex-direction: column;
  gap: 4px;
}
.editor-head-copy h4 {
  margin: 0 !important;
  color: var(--app-text);
  font-size: 14px !important;
  font-weight: 600;
  line-height: 1.35;
}
.editor-head-desc {
  display: block !important;
  margin: 0 !important;
  max-width: 52ch;
  color: var(--app-muted) !important;
  font-size: 12px !important;
  line-height: 1.5 !important;
  white-space: normal !important;
  overflow: visible !important;
  -webkit-line-clamp: unset !important;
}
.editor-head-actions {
  display: flex !important;
  flex: 0 0 auto !important;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  margin-left: 0 !important;
}
.editor-head-actions :deep(.el-button) {
  min-height: 30px !important;
  margin: 0 !important;
  padding: 0 12px !important;
}
.library-head h4 {
  margin: 0;
  color: var(--app-text);
  font-size: var(--type-section-desc);
}
.library-head p {
  margin: 4px 0 0;
  color: var(--app-muted);
  font-size: var(--type-micro);
  line-height: 1.55;
}
.editor-head-actions {
  display: flex !important;
  flex: 0 0 auto !important;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
  align-items: center;
  margin-left: auto;
}
.editor-head-actions :deep(.el-button) {
  min-height: 30px !important;
  margin: 0 !important;
  padding: 0 12px !important;
}
.flow-canvas {
  position: relative;
  flex: 1 1 auto;
  height: auto;
  min-height: 0;
  overflow: hidden;
  background: var(--app-surface-soft);
  user-select: none;
  -webkit-user-select: none;
}
.flow-canvas :deep(.vue-flow__selection) {
  border: 1.5px dashed var(--app-accent) !important;
  border-radius: 4px;
  background: color-mix(in srgb, var(--app-accent) 14%, transparent) !important;
  pointer-events: none;
  z-index: 100;
}
.flow-canvas :deep(.vue-flow__nodesselection-rect) {
  border: 1px dashed color-mix(in srgb, var(--app-accent) 60%, var(--app-border)) !important;
  border-radius: var(--fluent-radius-card);
  background: color-mix(in srgb, var(--app-accent) 5%, transparent) !important;
}
.workflow-align-overlay {
  position: absolute;
  inset: 0;
  z-index: 9;
  width: 100%;
  height: 100%;
  overflow: visible;
  pointer-events: none;
}
.align-guide line {
  stroke: var(--app-accent);
  stroke-width: 1.5;
  stroke-dasharray: 4 4;
  vector-effect: non-scaling-stroke;
}
.align-ruler line {
  stroke: color-mix(in srgb, var(--app-accent) 75%, var(--app-text));
  stroke-width: 1.5;
  vector-effect: non-scaling-stroke;
}
.align-ruler-badge {
  fill: var(--app-surface-strong);
  stroke: color-mix(in srgb, var(--app-accent) 60%, var(--app-border));
}
.align-ruler text {
  fill: var(--app-text);
  font-size: 11px;
  font-weight: 600;
  font-family: var(--app-font-ui, inherit);
  user-select: none;
}
.workflow-config-panel {
  position: absolute;
  z-index: 12;
  top: 12px;
  right: 12px;
  display: flex;
  width: min(344px, calc(100% - 24px));
  max-height: calc(100% - 24px);
  box-sizing: border-box;
  flex-direction: column;
  overflow: auto;
  border: 1px solid var(--app-border-strong);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface-strong);
  box-shadow: var(--fluent-shadow-16);
}
.workflow-popover-enter-active,
.workflow-popover-leave-active {
  transform-origin: top right;
  transition:
    opacity var(--fluent-duration-fast, 150ms)
      var(--fluent-curve-standard, ease),
    transform
      var(--fluent-collapse-motion, 220ms cubic-bezier(0.1, 0.9, 0.2, 1));
}
.workflow-popover-enter-from,
.workflow-popover-leave-to {
  opacity: 0;
  transform: translateY(-6px) scale(0.985);
}
.workflow-config-head {
  display: flex;
  min-height: 48px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 10px 8px 12px;
  border-bottom: 1px solid var(--app-border);
}
.workflow-config-head > div {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 1px;
}
.workflow-config-head strong {
  color: var(--app-text);
  font-size: 13px;
  line-height: 1.4;
}
.workflow-config-head span {
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.4;
}
.workflow-config-head button {
  display: grid;
  width: 28px;
  height: 28px;
  flex: 0 0 28px;
  place-items: center;
  padding: 0;
  border: 0;
  border-radius: var(--fluent-radius-control);
  background: transparent;
  color: var(--app-muted);
  cursor: pointer;
}
.workflow-config-head button:hover {
  background: var(--app-surface-soft);
  color: var(--app-text);
}
.workflow-config-body {
  display: grid;
  gap: 9px;
  padding: 10px 12px 8px;
}
.workflow-config-field {
  display: grid;
  min-width: 0;
  gap: 4px;
  color: var(--app-muted);
  font-size: 11px;
  line-height: 1.4;
}
.workflow-page .workflow-config-panel .project-select,
.workflow-page .workflow-config-panel .target-select,
.workflow-page .workflow-config-panel .preset-select {
  width: 100%;
}
.workflow-config-actions {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 7px;
  padding: 4px 12px 12px;
}
.workflow-config-actions :deep(.el-button) {
  width: 100%;
  min-width: 0;
  min-height: 30px;
  margin: 0;
  padding: 0 8px;
}
.workflow-config-actions :deep(.el-button:last-child) {
  grid-column: 1 / -1;
}
.workflow-context-menu {
  position: absolute;
  z-index: 20;
  display: grid;
  width: min(208px, calc(100% - 16px));
  max-height: calc(100% - 16px);
  box-sizing: border-box;
  gap: 2px;
  overflow: auto;
  padding: 6px;
  border: 1px solid var(--app-border-strong);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface-strong);
  box-shadow: var(--fluent-shadow-16);
}
.workflow-menu-enter-active,
.workflow-menu-leave-active {
  transform-origin: top left;
  transition:
    opacity var(--fluent-duration-fast, 150ms)
      var(--fluent-curve-standard, ease),
    transform
      var(--fluent-collapse-motion, 220ms cubic-bezier(0.1, 0.9, 0.2, 1));
}
.workflow-menu-enter-from,
.workflow-menu-leave-to {
  opacity: 0;
  transform: translateY(-4px) scale(0.98);
}
.workflow-context-menu button {
  display: grid;
  grid-template-columns: 22px minmax(0, 1fr) auto;
  min-height: 32px;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  border: 0;
  border-radius: var(--fluent-radius-control);
  background: transparent;
  color: var(--app-text);
  cursor: pointer;
  font: inherit;
  font-size: 12px;
  line-height: 1.4;
  text-align: left;
}
.workflow-context-menu .menu-shortcut {
  margin-left: 8px;
  color: var(--app-muted);
  font-size: 11px;
  white-space: nowrap;
}
.workflow-context-menu button:hover:not(:disabled) {
  background: var(--app-accent-soft);
  color: var(--app-accent-dark);
}
.workflow-context-menu button:disabled {
  color: var(--app-disabled-text, var(--app-muted));
  cursor: not-allowed;
  opacity: 0.58;
}
.workflow-context-menu button.is-danger {
  color: var(--el-color-danger);
}
.workflow-context-menu button .el-icon,
.workflow-context-menu button > :deep(.fluent-icon) {
  justify-self: center;
  font-size: 15px;
}
.workflow-context-menu-note {
  padding: 8px;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.4;
}
.red-team-flow :deep(.vue-flow__edge) {
  cursor: pointer;
}
.red-team-flow :deep(.vue-flow__edge:hover .vue-flow__edge-path) {
  stroke: #c17c11;
  stroke-width: 3;
}
.workflow-zoom-controls {
  position: absolute;
  z-index: 5;
  bottom: 12px;
  left: 12px;
  display: grid;
  overflow: hidden;
  border: 1px solid var(--app-border-strong);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-strong);
  box-shadow: var(--fluent-shadow-4);
}
.workflow-zoom-controls button {
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  padding: 0;
  border: 0;
  border-bottom: 1px solid var(--app-border);
  background: transparent;
  color: var(--app-text);
  cursor: pointer;
  font-size: 16px;
}
.workflow-zoom-controls button:last-child {
  border-bottom: 0;
}
.workflow-zoom-controls button:hover {
  background: var(--app-accent-soft);
  color: var(--app-accent-dark);
}
.red-team-flow {
  background-image: radial-gradient(
    circle,
    color-mix(in srgb, var(--app-border-strong) 45%, transparent) 1px,
    transparent 1px
  );
  background-size: 18px 18px;
}
.red-team-flow :deep(.vue-flow__edge-path) {
  stroke: color-mix(in srgb, var(--app-accent) 74%, var(--app-border-strong));
  stroke-width: 2;
}
.red-team-flow :deep(.vue-flow__edge.selected .vue-flow__edge-path) {
  stroke: #c17c11;
  stroke-width: 3;
}
.red-team-flow :deep(.vue-flow__connection-path) {
  stroke: var(--app-accent);
  stroke-width: 2;
}
.red-team-flow :deep(.vue-flow__handle) {
  width: 9px;
  height: 9px;
  border: 2px solid var(--app-surface);
  background: var(--app-accent);
}
.workflow-node {
  position: relative;
  width: 190px;
  min-height: 108px;
  padding: 9px 11px;
  border: 1px solid var(--app-border-strong);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface-strong);
  color: var(--app-text);
  box-shadow: var(--fluent-card-shadow);
  transition:
    border-color var(--fluent-fast),
    box-shadow var(--fluent-fast),
    transform var(--fluent-fast);
}
.workflow-node:hover,
.workflow-node.is-selected {
  border-color: var(--app-accent);
  box-shadow:
    0 0 0 2px color-mix(in srgb, var(--app-accent) 22%, transparent),
    var(--fluent-card-shadow);
}
.workflow-node--system {
  width: 126px;
  min-height: 72px;
  border-style: dashed;
  background: var(--app-surface);
  text-align: center;
}
.workflow-node--system .node-topline {
  justify-content: center;
}
.workflow-node--system .node-phase {
  display: none;
}
.workflow-node--tool {
  min-height: 120px;
}
.workflow-node--engagement {
  border-color: color-mix(in srgb, #3a8ee6 55%, var(--app-border-strong));
}
.workflow-node--recon {
  border-color: color-mix(in srgb, #7c6fcd 52%, var(--app-border-strong));
}
.workflow-node--mapping {
  border-color: color-mix(in srgb, #228b8b 55%, var(--app-border-strong));
}
.workflow-node--discovery {
  border-color: color-mix(in srgb, #b7791f 58%, var(--app-border-strong));
}
.workflow-node--validation {
  border-color: color-mix(in srgb, #2e9d67 58%, var(--app-border-strong));
}
.workflow-node--impact {
  border-color: color-mix(in srgb, #bd5b9b 52%, var(--app-border-strong));
}
.workflow-node--retest {
  border-color: color-mix(in srgb, #7d6ac7 58%, var(--app-border-strong));
}
.workflow-node--report {
  border-color: color-mix(in srgb, #4a7bb8 52%, var(--app-border-strong));
}
.node-main {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 4px;
}
.node-topline {
  display: flex;
  align-items: center;
  gap: 6px;
  min-height: 30px;
}
.node-icon {
  display: inline-grid;
  place-items: center;
  color: var(--app-accent);
  font-size: 18px;
}
.node-phase {
  overflow: hidden;
  color: var(--app-muted);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.node-main strong {
  overflow: hidden;
  font-size: var(--type-caption);
  text-overflow: ellipsis;
  white-space: nowrap;
}
.node-main small {
  display: -webkit-box;
  min-height: 27px;
  overflow: hidden;
  color: var(--app-muted);
  font-size: 10px;
  line-height: 1.35;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}
.node-main .el-tag {
  align-self: flex-start;
  margin-top: 2px;
  font-size: 10px;
}
.node-remove {
  display: grid;
  width: 30px;
  height: 30px;
  margin-left: auto;
  place-items: center;
  border: 0;
  border-radius: var(--fluent-radius-control);
  background: transparent;
  color: var(--app-muted);
  cursor: pointer;
}
.node-remove:hover {
  background: var(--app-surface-soft);
  color: #c8503f;
}

.node-run-status {
  display: inline-grid;
  width: 18px;
  height: 18px;
  margin-left: auto;
  padding: 0;
  place-items: center;
  border: 0;
  border-radius: 50%;
  background: transparent;
  cursor: pointer;
  font-size: 12px;
}
.node-run-status.is-running {
  color: var(--app-warning);
  animation: workflow-spin 1.2s linear infinite;
}
.node-run-status.is-success {
  color: var(--app-success);
  background: color-mix(in srgb, var(--app-success) 12%, transparent);
}
.node-run-status.is-failed {
  color: var(--app-danger);
  background: color-mix(in srgb, var(--app-danger) 12%, transparent);
}
.node-run-status.is-skipped,
.node-run-status.is-cancelled,
.node-run-status.is-pending {
  color: var(--app-muted);
  background: var(--app-surface-subtle);
}

.workflow-node.is-status-running {
  border-color: var(--app-warning);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--app-warning) 20%, transparent);
}
.workflow-node.is-status-success {
  border-color: var(--app-success);
  background: color-mix(in srgb, var(--app-success) 6%, var(--app-surface));
}
.workflow-node.is-status-failed {
  border-color: var(--app-danger);
  background: color-mix(in srgb, var(--app-danger) 6%, var(--app-surface));
}
.workflow-node.is-status-skipped,
.workflow-node.is-status-cancelled {
  opacity: 0.72;
}

@keyframes workflow-spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

.execute-panel {
  flex: none;
  margin: 0 20px 12px;
  padding: 12px 16px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface);
}
.execute-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
  font-size: var(--type-caption);
}
.execute-head strong {
  font-weight: 600;
}
.execute-head-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 12px;
}
.run-history-select {
  width: min(320px, 42vw);
}
.execute-panel > .el-alert {
  margin-bottom: 10px;
}
.execute-log {
  max-height: 160px;
  margin: 10px 0 0;
  overflow: auto;
  padding: 8px 10px;
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-subtle);
  color: var(--app-text);
  font-family: var(--fluent-mono);
  font-size: 11px;
  line-height: 1.5;
  white-space: pre-wrap;
}

.node-detail-body {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.node-detail-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 0;
  font-size: var(--type-caption);
}
.node-detail-log {
  max-height: 360px;
  overflow: auto;
  margin: 0;
  padding: 12px;
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-subtle);
  font-family: var(--fluent-mono);
  font-size: 12px;
  line-height: 1.5;
  white-space: pre-wrap;
}
.node-handle {
  z-index: 3;
}
.editor-foot {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 10px 14px;
  padding: 12px 16px;
  color: var(--app-muted);
  font-size: var(--type-micro);
  line-height: 1.5;
}
.workflow-library {
  padding: 14px 14px 12px;
  min-height: 0;
}
.library-head {
  flex: none;
}
.library-scroll {
  flex: 1 1 auto;
  min-height: 0;
  overflow: auto;
  overscroll-behavior: contain;
  padding-right: 6px;
  margin-bottom: 4px;
  scrollbar-gutter: stable;
  scrollbar-width: thin;
}
.library-scroll::-webkit-scrollbar {
  width: 10px;
}
.library-scroll::-webkit-scrollbar-thumb {
  border: 2px solid transparent;
  border-radius: 999px;
  background: color-mix(in srgb, var(--app-border-strong) 88%, transparent);
  background-clip: padding-box;
}
.library-scroll::-webkit-scrollbar-thumb:hover {
  background: color-mix(
    in srgb,
    var(--app-accent) 55%,
    var(--app-border-strong)
  );
  background-clip: padding-box;
}
.node-detail-summary {
  margin: 0;
  color: var(--app-text);
  font-size: var(--type-caption);
  line-height: 1.6;
}
.workflow-library-nav {
  flex: none;
  margin-bottom: 16px;
}
.workflow-library-tabs {
  width: 100%;
}
.workflow-library-tabs :deep(.el-segmented) {
  --el-segmented-color: var(--app-muted);
  --el-segmented-bg-color: var(--app-surface-soft);
  --el-segmented-item-selected-color: var(--app-text);
  --el-segmented-item-selected-bg-color: var(--app-surface-strong);
  --el-segmented-item-hover-color: var(--app-text);
  --el-segmented-item-hover-bg-color: transparent;
  --el-segmented-item-active-bg-color: transparent;
  --el-border-radius-base: var(--fluent-radius-circular);
  min-height: 32px;
  padding: 2px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-circular);
  background: var(--el-segmented-bg-color);
}
.workflow-library-tabs :deep(.el-segmented__group) {
  display: flex;
  width: 100%;
}
.workflow-library-tabs :deep(.el-segmented__item) {
  min-width: 0;
  flex: 1;
  min-height: 28px;
  border-radius: var(--fluent-radius-circular);
  color: var(--app-muted);
  font-weight: 500;
  transition: color var(--fluent-duration-fast, 150ms)
    var(--fluent-curve-standard, ease);
}
.workflow-library-tabs :deep(.el-segmented__item:hover) {
  color: var(--app-text);
}
.workflow-library-tabs :deep(.el-segmented__item.is-selected) {
  color: var(--el-segmented-item-selected-color);
  font-weight: 600;
}
.workflow-library-tabs :deep(.el-segmented__item-selected) {
  background: var(--el-segmented-item-selected-bg-color);
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-circular);
  box-shadow: var(--fluent-shadow-2);
  box-sizing: border-box;
  width: 50% !important;
  transform: translateX(0) translateZ(0) !important;
  transition: transform var(--fluent-duration-normal, 200ms)
    var(--fluent-curve-standard, ease);
}
.workflow-library-tabs :deep(.el-segmented__group):has(
    .el-segmented__item.is-selected:last-child
  )
  .el-segmented__item-selected {
  transform: translateX(100%) translateZ(0) !important;
}
.workflow-tab-label {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  font-size: var(--type-caption);
  font-weight: inherit;
  line-height: 1.2;
}
.workflow-tab-label :deep(.fluent-icon) {
  font-size: 14px;
}
.tab-node-badge {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background-color: var(--app-accent);
}
.node-info-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-top: 0;
}
.node-info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: var(--type-caption);
  color: var(--app-text);
}
.node-info-item > span:first-child {
  font-size: var(--type-micro);
  color: var(--app-muted);
  font-weight: 600;
  letter-spacing: 0.01em;
}
.node-info-item > span:last-child {
  line-height: 1.6;
}
.node-config-action {
  margin-top: 16px;
  width: 100%;
}
.node-tab-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 36px 16px;
  border: 1px dashed var(--app-border);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-subtle);
  color: var(--app-muted);
  gap: 8px;
}
.node-tab-empty .fluent-system-icon {
  font-size: 28px;
  color: var(--app-muted);
  opacity: 0.6;
  margin-bottom: 2px;
}
.node-tab-empty strong {
  font-size: var(--type-body);
  color: var(--app-text);
  font-weight: 600;
}
.node-tab-empty p {
  margin: 0;
  font-size: var(--type-caption);
  line-height: 1.5;
  max-width: 240px;
}
.node-input-editor {
  margin-bottom: 16px;
  padding: 12px 16px 16px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-soft);
}
.node-input-editor :deep(.el-form-item) {
  margin-bottom: 16px;
}
.node-input-editor :deep(.el-select),
.node-input-editor :deep(.el-radio-group) {
  width: 100%;
}
.node-input-editor :deep(.el-radio-button) {
  flex: 1;
}
.node-input-editor :deep(.el-radio-button__inner) {
  width: 100%;
}
.input-hint {
  display: block;
  margin-top: 8px;
  color: var(--app-muted);
  font-size: var(--type-micro);
  line-height: 1.5;
}
.workflow-poc-option {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  width: 100%;
  padding: 2px 0;
}
.workflow-poc-option-main {
  display: flex;
  flex-direction: column;
  min-width: 0;
  gap: 2px;
}
.workflow-poc-option-main b {
  font-size: var(--type-caption);
  color: var(--app-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.workflow-poc-option-main small {
  font-size: var(--type-micro);
  color: var(--app-muted);
  font-family: var(--fluent-mono, monospace);
}
.workflow-poc-option-tags {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-shrink: 0;
}
:global(.workflow-poc-select-popper) {
  min-width: 320px !important;
  max-width: min(480px, calc(100vw - 32px)) !important;
}
:global(.workflow-poc-select-popper .el-select-dropdown__item) {
  height: auto !important;
  min-height: 42px !important;
  padding: 6px 14px !important;
  line-height: 1.4 !important;
}
.node-editor-header {
  margin-bottom: 16px;
}
.node-editor-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.node-editor-title {
  margin: 0;
  color: var(--app-text);
  font-size: var(--type-caption);
  font-weight: 600;
  line-height: 1.4;
  letter-spacing: -0.01em;
}
.node-editor-desc {
  margin: 8px 0 0;
  color: var(--app-muted);
  font-size: var(--type-micro);
  line-height: 1.6;
}
.node-editor-hint {
  margin: 10px 0 0;
  color: var(--app-muted);
  font-size: var(--type-micro);
  line-height: 1.6;
}
.end-run-stats {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 8px;
  margin-bottom: 12px;
}
.end-run-stat {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: 8px 4px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card);
  background: var(--app-surface-soft);
}
.end-run-stat strong {
  color: var(--app-accent);
  font-size: var(--type-caption);
  line-height: 1.2;
}
.end-run-stat span {
  color: var(--app-muted);
  font-size: var(--type-micro);
}
.end-severity-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin: 4px 0 12px;
}
.end-finding-head {
  margin: 0 0 6px;
  color: var(--app-text);
  font-size: var(--type-caption);
  font-weight: 600;
}
.end-finding-list {
  margin: 0;
  padding: 0;
  list-style: none;
  max-height: 180px;
  overflow: auto;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-card);
}
.end-finding-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 10px;
  cursor: pointer;
  border-bottom: 1px solid var(--app-border-subtle, var(--app-border));
}
.end-finding-item:last-child {
  border-bottom: none;
}
.end-finding-item:hover {
  background: color-mix(in srgb, var(--app-accent) 8%, transparent);
}
.end-finding-sev {
  flex: none;
}
.end-finding-title {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: var(--type-caption);
  color: var(--app-text);
}
.end-finding-field {
  margin: 12px 0 4px;
  color: var(--app-muted);
  font-size: var(--type-micro);
  font-weight: 600;
}
.end-finding-detail {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.node-risk-tag {
  flex: none;
}
.node-editor-body {
  border-top: 1px solid var(--app-border-subtle, var(--app-border));
  padding-top: 16px;
}
.node-input-empty {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 16px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-subtle);
  line-height: 1.6;
}
.node-empty-icon-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: color-mix(in srgb, var(--app-accent) 12%, transparent);
  color: var(--app-accent);
  font-size: 14px;
  margin-top: 2px;
}
.node-empty-text {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.node-empty-title {
  font-size: var(--type-caption);
  font-weight: 600;
  color: var(--app-text);
  line-height: 1.4;
  letter-spacing: -0.005em;
}
.node-empty-desc {
  margin: 0;
  font-size: var(--type-micro);
  color: var(--app-muted);
  line-height: 1.6;
}
.target-input-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(150px, 0.55fr);
  gap: 12px;
}
.suggest-panel {
  display: flex;
  flex: 0 0 auto;
  max-height: min(220px, 28vh);
  flex-direction: column;
  gap: 8px;
  margin: 8px 0 0;
  padding: 12px 0 0;
  overflow: auto;
  overscroll-behavior: contain;
  border-top: 1px solid var(--app-border);
  scrollbar-width: thin;
}
.suggest-panel.collapsed {
  max-height: none;
  overflow: visible;
}
.suggest-resizer {
  flex: none;
  height: 8px;
  margin: -4px 0 -4px;
  cursor: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='28' height='28' viewBox='0 0 28 28'%3E%3Cpath d='M14 2 L9.5 7 L18.5 7 Z M14 26 L9.5 21 L18.5 21 Z' fill='%23000'/%3E%3C/svg%3E") 14 14, ns-resize;
  touch-action: none;
  user-select: none;
}
.is-resizing-suggest {
  cursor: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='28' height='28' viewBox='0 0 28 28'%3E%3Cpath d='M14 2 L9.5 7 L18.5 7 Z M14 26 L9.5 21 L18.5 21 Z' fill='%23000'/%3E%3C/svg%3E") 14 14, ns-resize !important;
  user-select: none !important;
}
.suggest-content {
  display: block;
  max-height: 520px;
  min-height: 0;
  overflow: hidden;
  opacity: 1;
  transition: max-height var(--fluent-collapse-motion, 260ms
        cubic-bezier(0.1, 0.9, 0.2, 1)),
    opacity var(--fluent-duration-fast, 150ms) var(--fluent-curve-standard, ease);
}
.suggest-content-inner {
  display: grid;
  gap: 8px;
  overflow: visible;
}
.suggest-panel.collapsed .suggest-content {
  max-height: 0;
  opacity: 0;
  pointer-events: none;
}
.suggest-toggle {
  display: flex;
  flex: 1;
  min-width: 0;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
  padding: 0;
  border: 0;
  background: transparent;
  color: inherit;
  text-align: left;
  cursor: pointer;
}
.suggest-chevron {
  flex: none;
  margin-top: 2px;
  color: var(--app-accent);
  font-size: var(--type-micro);
  white-space: nowrap;
}
.suggest-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
}
.suggest-head h4 {
  margin: 0;
  font-size: var(--type-caption);
}
.suggest-head p {
  margin: 4px 0 0;
  color: var(--app-muted);
  font-size: var(--type-micro);
  line-height: 1.4;
}
.suggest-note {
  margin: 0;
  color: var(--app-muted);
  font-size: var(--type-micro);
  line-height: 1.45;
}
.suggest-empty {
  padding: 10px 12px;
  border: 1px dashed var(--app-border);
  border-radius: var(--fluent-radius-control);
  color: var(--app-muted);
  font-size: var(--type-micro);
  line-height: 1.5;
}
.suggest-card {
  display: grid;
  gap: 6px;
  padding: 10px 11px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-strong);
}
.suggest-card--warning {
  border-color: color-mix(in srgb, #d69a2b 45%, var(--app-border));
  background: color-mix(in srgb, #d69a2b 8%, var(--app-surface-strong));
}
.suggest-card header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.suggest-card strong {
  min-width: 0;
  overflow: hidden;
  font-size: var(--type-caption);
  text-overflow: ellipsis;
  white-space: nowrap;
}
.suggest-card p {
  margin: 0;
  color: var(--app-text);
  font-size: var(--type-micro);
  line-height: 1.5;
}
.suggest-actions {
  display: flex;
  justify-content: flex-end;
}

.library-head {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--app-border);
}
.library-head :deep(.el-select__wrapper) {
  min-height: 32px;
}
.phase-library {
  padding: 12px 0 14px;
  border-bottom: 1px solid var(--app-border);
}
.library-section-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
}
.library-section-toggle {
  display: flex;
  min-width: 0;
  flex: 1;
  align-items: flex-start;
  justify-content: flex-start;
  gap: 8px;
  padding: 0;
  border: 0;
  outline: 0;
  background: transparent;
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
}
.library-section-toggle > span {
  min-width: 0;
  flex: 1;
}
.library-section-toggle:focus-visible {
  border-radius: var(--fluent-radius-control);
  box-shadow: 0 0 0 2px var(--app-accent-soft);
}
.library-section-chevron {
  flex: none;
  margin-top: 1px;
  color: var(--app-muted);
  transition: transform
    var(--fluent-collapse-motion, 220ms cubic-bezier(0.1, 0.9, 0.2, 1));
}
.library-section-body {
  display: grid;
  grid-template-rows: minmax(0, 1fr);
  opacity: 1;
  transition:
    grid-template-rows
      var(--fluent-collapse-motion, 220ms cubic-bezier(0.1, 0.9, 0.2, 1)),
    opacity var(--fluent-duration-fast, 150ms)
      var(--fluent-curve-standard, ease);
}
.library-section-body-inner {
  min-height: 0;
  overflow: hidden;
  transform: translateY(0);
  transition: transform
    var(--fluent-collapse-motion, 220ms cubic-bezier(0.1, 0.9, 0.2, 1));
}
.phase-library.collapsed .library-section-body,
.capability-library.collapsed .library-section-body {
  grid-template-rows: minmax(0, 0fr);
  opacity: 0;
  pointer-events: none;
}
.phase-library.collapsed .library-section-body-inner,
.capability-library.collapsed .library-section-body-inner {
  transform: translateY(-4px);
}
.phase-library.collapsed .library-section-chevron,
.capability-library.collapsed .library-section-chevron {
  transform: rotate(-90deg);
}
.library-section-head h5 {
  margin: 0;
  color: var(--app-text);
  font-size: var(--type-caption);
}
.library-section-head p {
  margin: 3px 0 0;
  color: var(--app-muted);
  font-size: var(--type-micro);
  line-height: 1.45;
}
.phase-library-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 7px;
  margin-top: 10px;
}
.phase-library-item {
  display: grid;
  min-width: 0;
  min-height: 54px;
  grid-template-columns: 24px minmax(0, 1fr) 28px;
  align-items: center;
  gap: 7px;
  padding: 7px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-strong);
  cursor: grab;
}
.phase-library-item.is-present {
  background: var(--app-surface-soft);
  cursor: default;
}
.phase-library-item.is-selected {
  border-color: var(--app-accent);
}
.phase-library-icon {
  display: grid;
  place-items: center;
  color: var(--app-accent);
  font-size: 16px;
}
.phase-library-copy {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 2px;
}
.phase-library-copy strong {
  overflow: hidden;
  font-size: var(--type-micro);
  text-overflow: ellipsis;
  white-space: nowrap;
}
.phase-library-copy small {
  overflow: hidden;
  color: var(--app-muted);
  font-size: 10px;
  line-height: 1.3;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.phase-library-action {
  display: grid;
  width: 28px;
  height: 28px;
  place-items: center;
  border: 0;
  border-radius: var(--fluent-radius-control);
  background: transparent;
  color: var(--app-accent);
  cursor: pointer;
}
.phase-library-action:not(:disabled):hover {
  background: var(--app-accent-soft);
}
.phase-library-action.is-present {
  color: var(--app-success);
  cursor: default;
}
.capability-library {
  padding-top: 14px;
}
.capability-library-head {
  align-items: center;
  margin-bottom: 2px;
}
.capability-library-head :deep(.el-select) {
  width: 132px;
  flex: none;
}
.capability-library-head :deep(.el-select__wrapper) {
  min-height: 32px;
}
.library-item {
  position: relative;
  display: grid;
  min-height: 68px;
  grid-template-columns: 32px minmax(0, 1fr) 32px;
  align-items: center;
  gap: 10px;
  margin-top: 10px;
  padding: 11px 9px;
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control);
  background: var(--app-surface-strong);
  cursor: grab;
}
.library-item:hover {
  border-color: var(--app-accent);
}
.library-item.caution {
  border-color: color-mix(in srgb, #d69a2b 48%, var(--app-border));
  background: color-mix(in srgb, #d69a2b 9%, var(--app-surface-strong));
}
.library-item.is-selected {
  border-color: var(--app-accent);
  background: color-mix(
    in srgb,
    var(--app-accent) 8%,
    var(--app-surface-strong)
  );
  box-shadow: none;
}
.library-icon {
  display: grid;
  place-items: center;
  color: var(--app-accent);
  font-size: 19px;
}
.library-copy {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 3px;
}
.library-copy strong {
  overflow: hidden;
  font-size: var(--type-caption);
  text-overflow: ellipsis;
  white-space: nowrap;
}
.library-copy small {
  color: var(--app-muted);
  font-size: var(--type-micro);
  line-height: 1.45;
}
.library-copy em {
  color: var(--app-muted);
  font-size: var(--type-micro);
  font-style: normal;
}
.library-add {
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border: 0;
  border-radius: var(--fluent-radius-control);
  background: transparent;
  color: var(--app-accent);
  cursor: pointer;
}
.library-add:hover {
  background: var(--app-accent-soft);
}
.library-empty {
  display: grid;
  min-height: 132px;
  place-items: center;
  align-content: center;
  gap: 7px;
  padding: 18px 12px;
  color: var(--app-muted);
  text-align: center;
}
.library-empty > svg {
  width: 24px;
  height: 24px;
  color: var(--app-accent);
}
.library-empty strong {
  color: var(--app-text);
  font-size: var(--type-body);
}
.library-empty small {
  line-height: 1.5;
}
.workflow-reveal-enter-active,
.workflow-reveal-leave-active {
  overflow: hidden;
  transform-origin: top;
  transition:
    opacity var(--fluent-duration-fast, 150ms)
      var(--fluent-curve-standard, ease),
    transform
      var(--fluent-collapse-motion, 220ms cubic-bezier(0.1, 0.9, 0.2, 1));
}
.workflow-reveal-enter-from,
.workflow-reveal-leave-to {
  opacity: 0;
  transform: translateY(-6px) scaleY(0.96);
}
@media (max-width: 1100px) {
  .workflow-editor-layout {
    grid-template-columns: 1fr;
  }
  .workflow-page .workflow-editor-layout .editor-card {
    height: 580px !important;
    min-height: 580px !important;
  }
  .workflow-page .workflow-editor-layout .flow-canvas {
    height: auto !important;
    min-height: 420px !important;
  }
  .workflow-page .workflow-editor-layout .workflow-library {
    display: flex;
    height: auto !important;
    flex-direction: column;
    max-height: none;
  }
  .library-scroll {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0 12px;
    max-height: none;
    min-height: 240px;
  }
  .library-head,
  .suggest-panel,
  .phase-library,
  .capability-library {
    grid-column: 1 / -1;
  }
}
@media (max-width: 700px) {
  .editor-card > .editor-head,
  .workflow-page .editor-head {
    flex-direction: column !important;
    align-items: stretch !important;
  }
  .editor-head-actions {
    width: 100%;
    justify-content: flex-start;
  }
  .workflow-actions {
    width: 100%;
  }
  .workflow-actions :deep(.el-button) {
    flex: 1 1 auto;
  }
  .preset-select {
    width: min(220px, 100%);
  }
  .project-select,
  .target-select {
    width: 100%;
  }
  .target-input-grid {
    grid-template-columns: 1fr;
    gap: 0;
  }
  .workflow-library {
    display: block;
  }
  .flow-canvas {
    min-height: 420px;
    height: auto;
  }
  .workflow-config-panel {
    top: 8px;
    right: 8px;
    width: calc(100% - 16px);
    max-height: calc(100% - 16px);
  }
}

/* workflow extra tall */
.workflow-page > .section-head {
  margin-bottom: 8px !important;
}
.workflow-page > .workflow-status-row {
  margin-bottom: 4px !important;
}
.workflow-page > .graph-notice,
.workflow-page > .graph-validation {
  margin-bottom: 4px !important;
}
.workflow-editor-layout {
  min-height: calc(100vh - 220px);
}
.editor-foot {
  padding: 8px 14px !important;
  font-size: 11px !important;
}
.port-picker {
  display: grid;
  width: 100%;
  gap: 10px;
}
.port-picker :deep(.el-select) {
  width: 100%;
}
.full-port-option {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 10px 12px;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-soft);
}
.full-port-option div {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 4px;
}
.full-port-option b {
  color: var(--app-text);
  font-size: 13px;
}
.full-port-option small {
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.55;
}
.custom-port-section {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-top: 6px;
}
.custom-port-label {
  font-size: 12px;
  color: var(--app-muted);
}
.port-hint {
  margin: 0 2px;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.55;
}

@media (min-width: 1201px) {
  .workflow-page > .section-head {
    align-items: center !important;
    margin-bottom: 6px !important;
  }
  .workflow-page > .section-head > .workflow-actions {
    flex-wrap: nowrap !important;
  }
  .workflow-page .project-select {
    width: clamp(170px, 12vw, 200px);
  }
  .workflow-page .target-select {
    width: clamp(200px, 16vw, 250px);
  }
  .workflow-page .preset-select {
    width: clamp(145px, 10vw, 170px);
  }
  .workflow-page > .workflow-status-row {
    min-height: 28px;
    margin-bottom: 4px !important;
  }
}
</style>
