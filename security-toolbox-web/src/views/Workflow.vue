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
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Check,
  Plus,
  Delete,
  QuestionFilled,
  Refresh,
  CircleCheck,
  FolderOpened,
  Flag,
  Warning,
} from "../components/fluentIcons";
import FluentIcon from "../components/FluentIcon.vue";
import {
  Handle,
  MarkerType,
  Position,
  VueFlow,
  type Connection,
  type Edge,
  type EdgeMouseEvent,
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
  type WorkflowGraphEdgeSpec,
  type WorkflowGraphNodeSpec,
  type WorkflowSpecV2,
  type WorkflowStepSpec,
  type WorkflowSuggestion,
  type WorkflowSuggestStreamEvent,
} from "../api";
import WorkflowEdge from "./WorkflowEdge.vue";

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
    name: "受控漏洞模板扫描",
    icon: "shield-task",
    desc: "使用受限模板发现风险，执行前需人工确认",
    risk: "CAUTION",
    phase: "discovery",
  },
];
const agentOf = (tool?: string) => SUBAGENTS.find((item) => item.tool === tool);

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
const showGuide = ref(false);
const preset = ref<PresetCode>("standard");
const nodes = shallowRef<EditorNode[]>([]);
const edges = shallowRef<Edge[]>([]);
const selectedNodeId = ref("");
const selectedEdgeId = ref("");
const hoveredEdgeId = ref("");
const selectedPhase = ref<PhaseCode>("mapping");
const graphValidation = ref<string[]>([]);
const graphNotice = ref("");
const suggestLoading = ref(false);
const suggestNote = ref("");
const suggestSource = ref("");
const suggestions = ref<WorkflowSuggestion[]>([]);
const suggestExpanded = ref(false);
let suggestTimer: ReturnType<typeof setTimeout> | undefined;
let suggestSeq = 0;
let loadSeq = 0;
let suggestAbort: AbortController | undefined;
const { fitView, zoomIn, zoomOut } = useVueFlow("red-team-workflow");

function zoomCanvasIn() {
  void zoomIn();
}
function zoomCanvasOut() {
  void zoomOut();
}
function fitWorkflowCanvas() {
  void fitView({ padding: 0.2, maxZoom: 0.95 });
}

const sortedPhases = computed(() => PHASES);
const selectedNode = computed(() =>
  nodes.value.find((node) => node.id === selectedNodeId.value),
);
const toolNodes = computed(() =>
  nodes.value.filter((node) => node.data.nodeKind === "tool"),
);
const phaseNodes = computed(() =>
  nodes.value.filter((node) => node.data.nodeKind === "phase"),
);
const connectedEdgeCount = computed(() => edges.value.length);
const graphReady = computed(
  () => graphValidation.value.length === 0 && nodes.value.length > 2,
);
const selectedProject = computed(() =>
  projects.value.find((project) => project.id === selectedProjectId.value),
);
const hasWorkflowSnapshot = computed(
  () =>
    Boolean(workflowSnapshot.value.workflowId) &&
    Number(workflowSnapshot.value.revision) > 0 &&
    Boolean(workflowSnapshot.value.specDigest),
);

const WORKFLOW_PROJECT_STORAGE_KEY = "security_toolbox_workflow_project_v1";

function workflowUpdatedAt(value?: string) {
  if (!value) return "";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString("zh-CN");
}

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
  };
}

function makeNode(
  id: string,
  kind: NodeKind,
  phase: PhaseCode,
  position: { x: number; y: number },
  label?: string,
  tool?: string,
): EditorNode {
  const system = kind === "system";
  return {
    id,
    type: "workflowNode",
    position,
    data: nodeData(kind, phase, label, tool),
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
      discovery: ["http_security_check", "nuclei_scan"],
      validation: [],
      impact: [],
      retest: [],
      report: [],
    };
  if (code === "asset-inventory")
    return {
      engagement: [],
      recon: ["retrieve_project_context"],
      mapping: ["nmap_service_scan", "http_headers", "tls_config"],
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
      retest: ["http_security_check", "nuclei_scan"],
      report: [],
    };
  return {
    engagement: [],
    recon: ["retrieve_project_context"],
    mapping: ["nmap_service_scan", "http_headers", "tls_config"],
    discovery: ["http_security_check", "nuclei_scan"],
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
  if (migrated.length) {
    migrated.forEach((step) => {
      const phase = inferPhase(step.tool);
      tools[phase].push(step.tool);
    });
  }
  const resultNodes: EditorNode[] = [];
  const resultEdges: Edge[] = [];
  resultNodes.push(
    makeNode("__start__", "system", "engagement", { x: 20, y: 270 }, "开始"),
  );
  PHASES.forEach((phase, index) => {
    const x = 220 + index * 390;
    resultNodes.push(
      makeNode(phaseNodeId(phase.code), "phase", phase.code, { x, y: 270 }),
    );
  });
  resultNodes.push(
    makeNode(
      "__end__",
      "system",
      "report",
      { x: 220 + PHASES.length * 390, y: 270 },
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
    phaseTools.forEach((tool, toolIndex) => {
      const occurrence = (counts.get(tool) || 0) + 1;
      counts.set(tool, occurrence);
      const agent = agentOf(tool);
      if (!agent) return;
      const id = `tool-${safeId(tool)}-${phase.code}-${occurrence}`;
      const y = 96 + (toolIndex % 4) * 112;
      resultNodes.push(
        makeNode(
          id,
          "tool",
          phase.code,
          { x: 220 + index * 390 + 190, y },
          undefined,
          tool,
        ),
      );
      resultEdges.push(makeEdge(milestone, id));
      resultEdges.push(makeEdge(id, next));
    });
    if (!phaseTools.length) resultEdges.push(makeEdge(milestone, next));
  });
  nodes.value = resultNodes;
  edges.value = dedupeEdges(resultEdges);
  selectedNodeId.value = "";
  selectedEdgeId.value = "";
  graphValidation.value = [];
  graphNotice.value = `${PRESETS.find((item) => item.value === code)?.label || "红队评估"}已载入，可拖动节点并手动连接依赖。`;
  void refit();
}

function inferPhase(tool?: string): PhaseCode {
  if (tool === "retrieve_project_context") return "recon";
  if (tool === "http_security_check" || tool === "nuclei_scan")
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

function onNodeClick(event: NodeMouseEvent) {
  selectedNodeId.value = event.node.id;
  setSelectedEdge("");
}
function onEdgeClick(event: { edge: Edge }) {
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
  selectedNodeId.value = "";
  setSelectedEdge("");
}
function onNodeDragStop(event: NodeDragEvent) {
  const current = nodes.value.find((node) => node.id === event.node.id);
  if (current)
    current.position = { x: event.node.position.x, y: event.node.position.y };
}

function removeSelectedEdge() {
  if (!selectedEdgeId.value) return;
  removeEdge(selectedEdgeId.value, true);
}

function removeEdge(edgeId: string, notify = false) {
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
  nodes.value = nodes.value.filter((node) => node.id !== id);
  edges.value = edges.value.filter(
    (edge) => edge.source !== id && edge.target !== id,
  );
  if (selectedNodeId.value === id) selectedNodeId.value = "";
  validateGraph();
}

function addPhaseNode() {
  const phase = selectedPhase.value;
  const meta = phaseOf(phase);
  const id = uniqueId(`phase-${phase}`);
  const position = { x: 380 + nodes.value.length * 28, y: 500 };
  nodes.value = [
    ...nodes.value,
    makeNode(id, "phase", phase, position, `${meta.label}（自定义）`),
  ];
  selectedNodeId.value = id;
  graphNotice.value = "已添加阶段节点，请从右侧拖动连接点建立上游和下游依赖。";
  validateGraph();
}

function addToolNode(tool: string, phase = selectedPhase.value) {
  const agent = agentOf(tool);
  if (!agent) return;
  const id = uniqueId(`tool-${safeId(tool)}-${phase}`);
  const phaseAnchor = nodes.value.find(
    (node) => node.id === phaseNodeId(phase),
  );
  const position = {
    x: (phaseAnchor?.position.x || 420) + 185,
    y: 480 + (toolNodes.value.length % 4) * 112,
  };
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

function onLibraryDragStart(event: DragEvent, tool: string) {
  event.dataTransfer?.setData("application/x-workflow-tool", tool);
  if (event.dataTransfer) event.dataTransfer.effectAllowed = "copy";
}
function onCanvasDrop(event: DragEvent) {
  const tool = event.dataTransfer?.getData("application/x-workflow-tool");
  if (!tool) return;
  addToolNode(tool, selectedPhase.value);
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
    parameters: {},
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

async function save() {
  const projectId = selectedProjectId.value;
  if (!projectId) {
    ElMessage.warning("请先选择评估项目");
    return;
  }
  const problems = validateGraph();
  if (problems.length) {
    ElMessage.warning(problems[0]);
    return;
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
  } catch {
    ElMessage.error("保存失败，请检查后端工作流服务");
  } finally {
    saving.value = false;
  }
}

function toEditorNode(spec: WorkflowGraphNodeSpec): EditorNode {
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
  return makeNode(spec.id, kind, phase, position, spec.label, spec.tool);
}

function loadFromSpec(data: WorkflowSpecV2) {
  workflowSnapshot.value = {
    workflowId: data.workflowId,
    scopeId: data.scopeId,
    revision: data.revision,
    specDigest: data.specDigest,
    updatedBy: data.updatedBy,
    updatedAt: data.updatedAt,
  };
  if (data?.graph?.nodes?.length && data.graph.edges) {
    nodes.value = data.graph.nodes.map(toEditorNode);
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
    }
  } else {
    // Backward-compatible migration for the old steps-only endpoint.
    preset.value = "standard";
    buildPreset("standard", data?.steps);
  }
  void refit();
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
    await load();
  } catch {
    projects.value = [];
    selectedProjectId.value = undefined;
    workflowSnapshot.value = {};
    buildPreset("standard");
    ElMessage.warning("项目列表暂不可用，工作流编辑器已载入本地模板");
  }
}

async function changeProject(projectId: number) {
  localStorage.setItem(WORKFLOW_PROJECT_STORAGE_KEY, String(projectId));
  graphNotice.value = "";
  selectedNodeId.value = "";
  selectedEdgeId.value = "";
  await load();
}

async function refit() {
  await nextTick();
  window.setTimeout(() => {
    void fitView({ padding: 0.14, duration: 180 });
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
  const el = target as HTMLElement | null;
  return (
    !!el &&
    (el.tagName === "INPUT" ||
      el.tagName === "TEXTAREA" ||
      el.tagName === "SELECT" ||
      el.isContentEditable)
  );
}
function onWorkflowKeydown(event: KeyboardEvent) {
  if (event.key === "Escape") {
    selectedNodeId.value = "";
    setSelectedEdge("");
    return;
  }
  if (
    (event.key === "Delete" || event.key === "Backspace") &&
    selectedEdgeId.value &&
    !isTypingTarget(event.target)
  ) {
    event.preventDefault();
    removeSelectedEdge();
  }
}

onMounted(() => {
  scheduleSuggestions();
  window.addEventListener("keydown", onWorkflowKeydown);
  void loadProjects();
});
onBeforeUnmount(() => {
  if (suggestTimer) clearTimeout(suggestTimer);
  if (suggestAbort) suggestAbort.abort();
  window.removeEventListener("keydown", onWorkflowKeydown);
});
</script>

<template>
  <section class="panel workflow-page">
    <div class="section-head">
      <div>
        <h3>红队评估工作流</h3>
        <p>
          从任务启动到报告交付的完整闭环。拖动节点调整布局，从右侧连接点手动连线；分叉表示并行，汇合表示等待上游全部完成。
        </p>
      </div>
      <div class="workflow-actions">
        <el-select
          v-model="selectedProjectId"
          class="project-select"
          aria-label="评估项目"
          placeholder="选择评估项目"
          :loading="loading"
          :disabled="saving"
          @change="changeProject"
        >
          <template #prefix><el-icon><FolderOpened /></el-icon></template>
          <el-option
            v-for="project in projects"
            :key="project.id"
            :value="project.id"
            :label="project.name"
          />
        </el-select>
        <el-button @click="showGuide = !showGuide"
          ><el-icon><QuestionFilled /></el-icon>使用说明</el-button
        >
        <el-select
          v-model="preset"
          class="preset-select"
          aria-label="工作流模板"
        >
          <el-option
            v-for="item in PRESETS"
            :key="item.value"
            :value="item.value"
            :label="item.label"
          />
        </el-select>
        <el-button @click="resetPreset"
          ><el-icon><Refresh /></el-icon>载入模板</el-button
        >
        <el-button type="primary" :loading="saving" @click="save"
          ><el-icon><Check /></el-icon>保存工作流</el-button
        >
      </div>
    </div>

    <el-alert
      v-if="showGuide"
      class="workflow-guide"
      type="info"
      :closable="true"
      show-icon
      @close="showGuide = false"
    >
      <template #title>小白也能用：四步完成一次评估</template>
      <ol class="guide-list">
        <li>
          <b>从开始出发</b>：默认模板已经连好“启动与范围 → 侦察 → 发现 → 验证 →
          复测 → 报告 → 结束”。
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
          <b>保存前检查</b
          >：系统会检查环路、孤立节点以及“开始”是否能到达“结束”；高风险能力仍需人工确认。
        </li>
      </ol>
    </el-alert>

    <div class="workflow-status-row">
      <span class="status-chip">
        <el-icon><FolderOpened /></el-icon>{{ selectedProject?.name || "未选择项目" }}
      </span>
      <span
        class="status-chip workflow-snapshot-chip"
        :data-fluent-tooltip="workflowSnapshot.workflowId || '保存后由服务端生成'"
      >
        Workflow {{ workflowSnapshot.workflowId || "尚未保存" }}
      </span>
      <span class="status-chip workflow-snapshot-chip">
        Revision {{ workflowSnapshot.revision || "未生成" }}
      </span>
      <span
        class="status-chip workflow-snapshot-chip"
        :class="{ 'status-chip--ok': hasWorkflowSnapshot }"
        :data-fluent-tooltip="workflowSnapshot.specDigest || '保存后由服务端计算'"
      >
        Digest {{ workflowSnapshot.specDigest || "未生成" }}
      </span>
      <span
        v-if="workflowSnapshot.updatedAt"
        class="status-chip workflow-snapshot-chip"
      >
        {{ workflowSnapshot.updatedBy || "系统" }} ·
        {{ workflowUpdatedAt(workflowSnapshot.updatedAt) }}
      </span>
      <span class="status-chip"
        ><el-icon><Flag /></el-icon>固定入口：开始 → 结束</span
      >
      <span class="status-chip"
        ><FluentIcon name="shield-checkmark" />每个动作自动复核授权范围</span
      >
      <span class="status-chip"
        ><el-icon><CircleCheck /></el-icon>{{ phaseNodes.length }} 个阶段节点 ·
        {{ toolNodes.length }} 个受控能力节点</span
      >
      <span class="status-chip"
        ><el-icon><Refresh /></el-icon>{{ connectedEdgeCount }} 条依赖连线</span
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

    <div class="workflow-editor-layout">
      <section class="editor-card">
        <header class="editor-head">
          <div class="editor-head-copy">
            <h4>红队行动拓扑</h4>
            <p class="editor-head-desc">
              节点是评估阶段或受控能力，连线是依赖关系。开始和结束节点不可删除。
            </p>
          </div>
          <div class="editor-head-actions">
            <el-button size="small" @click="addPhaseNode"
              ><el-icon><Plus /></el-icon>添加阶段节点</el-button
            >
            <el-button size="small" :loading="loading" @click="load"
              ><el-icon><Refresh /></el-icon>重新加载</el-button
            >
          </div>
        </header>
        <div
          v-loading="loading"
          class="flow-canvas"
          @drop.prevent="onCanvasDrop"
          @dragover.prevent
        >
          <VueFlow
            id="red-team-workflow"
            v-model:nodes="nodes"
            v-model:edges="edges"
            :nodes-draggable="true"
            :nodes-connectable="true"
            :elements-selectable="true"
            :delete-key-code="null"
            :min-zoom="0.2"
            :max-zoom="1.6"
            fit-view-on-init
            class="red-team-flow"
            @connect="onConnect"
            @node-click="onNodeClick"
            @edge-click="onEdgeClick"
            @edge-mouse-enter="onEdgeMouseEnter"
            @edge-mouse-leave="onEdgeMouseLeave"
            @pane-click="onPaneClick"
            @node-drag-stop="onNodeDragStop"
          >
            <template #node-workflowNode="{ id, data }">
              <div
                class="workflow-node"
                :class="[
                  `workflow-node--${data.nodeKind}`,
                  `workflow-node--${data.phase}`,
                  { 'is-selected': id === selectedNodeId },
                ]"
                @click.stop="selectedNodeId = id"
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
                      v-if="data.nodeKind !== 'system'"
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
                      data.risk === "CAUTION" ? "需确认" : "受控能力"
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
            </div>
          </VueFlow>
        </div>
        <footer class="editor-foot">
          <span
            >提示：悬停高亮连线，单击选中后按 Delete 键或点击连线上的 ✕
            删除；拖动节点只改变布局，不会改变执行顺序。</span
          ><span v-if="selectedNode"
            >已选节点：{{ selectedNode.data.label }}</span
          ><span v-else-if="selectedEdgeId"
            >已选连线：按 Delete 或点击连线上的 ✕ 删除</span
          >
        </footer>
      </section>

      <aside class="workflow-library">
        <div class="library-head">
          <div>
            <h4>受控能力库</h4>
            <p>选择目标阶段后使用添加按钮，或把能力卡拖入画布。</p>
          </div>
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

        <div class="library-scroll" aria-label="受控能力列表">
          <div
            v-for="agent in SUBAGENTS"
            :key="agent.tool"
            class="library-item"
            :class="{ caution: agent.risk !== 'SAFE' }"
            draggable="true"
            @dragstart="onLibraryDragStart($event, agent.tool)"
          >
            <span class="library-icon"><FluentIcon :name="agent.icon" /></span>
            <span class="library-copy"
              ><strong>{{ agent.name }}</strong
              ><small>{{ agent.desc }}</small
              ><em
                >{{
                  phaseOf(
                    selectedPhase === agent.phase ? selectedPhase : agent.phase,
                  ).shortLabel
                }}
                · {{ agent.risk === "SAFE" ? "低影响" : "需人工确认" }}</em
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
          <div class="phase-legend">
            <strong>阶段导航</strong
            ><span v-for="phase in PHASES" :key="phase.code"
              ><i><FluentIcon :name="phase.icon" /></i
              >{{ phase.shortLabel }}</span
            >
          </div>
        </div>

        <div
          class="suggest-panel"
          :class="{ collapsed: !suggestExpanded }"
          aria-label="大模型实时建议"
        >
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
                <p v-else-if="suggestSource">来源：{{ suggestSource }}</p>
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
          <template v-if="suggestExpanded">
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
                <strong>{{ item.title }}</strong>
                <el-tag
                  size="small"
                  effect="plain"
                  :type="item.severity === 'warning' ? 'warning' : 'info'"
                  >{{ item.kind || "tip" }}</el-tag
                >
              </header>
              <p>{{ item.detail }}</p>
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
          </template>
        </div>
      </aside>
    </div>
  </section>
</template>

<style scoped>
.workflow-page {
  display: flex;
  flex-direction: column;
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
.workflow-page > .section-head p {
  margin: 4px 0 0 !important;
  max-width: 62ch;
  line-height: 1.45 !important;
}
.workflow-actions {
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
.workflow-snapshot-chip {
  max-width: min(100%, 360px);
  overflow-wrap: anywhere;
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
  margin: 0 0 10px;
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
  margin-bottom: 10px;
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
  flex: 1 1 auto;
  height: auto;
  min-height: 0;
  overflow: hidden;
  background: var(--app-surface-soft);
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
.library-item {
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
.phase-legend {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px 12px;
  margin-top: 18px;
  padding-top: 14px;
  border-top: 1px solid var(--app-border);
  color: var(--app-muted);
  font-size: var(--type-micro);
}
.phase-legend strong {
  grid-column: 1 / -1;
  color: var(--app-text);
  font-size: var(--type-caption);
}
.phase-legend span {
  display: flex;
  min-height: 24px;
  align-items: center;
  gap: 6px;
}
.phase-legend i {
  font-style: normal;
}
@media (max-width: 1100px) {
  .workflow-editor-layout {
    grid-template-columns: 1fr;
  }
  .workflow-library {
    display: flex;
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
  .phase-legend {
    grid-column: 1 / -1;
  }
  .phase-legend {
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
  .preset-select {
    width: min(220px, 100%);
  }
  .workflow-library {
    display: block;
  }
  .flow-canvas {
    min-height: 420px;
    height: auto;
  }
}

/* workflow extra tall */
.workflow-page > .section-head {
  margin-bottom: 8px !important;
}
.workflow-page > .workflow-status-row {
  margin-bottom: 8px !important;
}
.workflow-page > .graph-notice,
.workflow-page > .graph-validation {
  margin-bottom: 8px !important;
}
.workflow-editor-layout {
  min-height: calc(100vh - 220px);
}
.editor-foot {
  padding: 8px 14px !important;
  font-size: 11px !important;
}
</style>
