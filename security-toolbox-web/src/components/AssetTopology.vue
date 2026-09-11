<script setup lang="ts">
import { computed, ref, watch, nextTick, onMounted, onUnmounted } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  endpoints,
  type AssessmentProject,
  type DiscoveryResult,
  type ProjectFindingRecord,
} from "../api";
import { formatDateTime } from "../utils/dateTime";
import {
  clearNodePositions,
  loadGlobalPrefs,
  loadNodePositions,
  saveGlobalPrefs,
  saveNodePositions,
} from "../utils/topologyPersistence";
import FluentIcon from "./FluentIcon.vue";

const props = withDefaults(
  defineProps<{
    projectId: number | "all";
    assets: DiscoveryResult[];
    hubLabel?: string;
    loading?: boolean;
    projects?: AssessmentProject[];
    findings?: ProjectFindingRecord[];
  }>(),
  {
    hubLabel: "项目中心",
    loading: false,
    projects: () => [],
    findings: () => [],
  },
);

const emit = defineEmits<{
  (e: "change"): void;
}>();

// 容器与视口
const containerRef = ref<HTMLElement | null>(null);
const canvasWrapRef = ref<HTMLElement | null>(null);
const svgRef = ref<SVGSVGElement | null>(null);
const viewportWidth = ref(1100);
const viewportHeight = ref(660);
const isFullscreen = ref(false);

// 平移与缩放
const zoom = ref(1);
const pan = ref({ x: 0, y: 0 });
const isDraggingCanvas = ref(false);
const canvasDragStart = ref({ x: 0, y: 0 });
const hasDragged = ref(false);

// 节点与中心卡片自定义拖拽位置记录: Map<id, { x, y }> (按项目持久化为本地)
const customPositions = ref<Record<string | number, { x: number; y: number }>>({});
const draggingNodeId = ref<number | null>(null);
const draggingHubId = ref<string | null>(null);
const nodeDragStart = ref({ clientX: 0, clientY: 0, initX: 0, initY: 0 });

// 视图模式与动效 (全局偏好持久化为本地)
type LayoutMode = "orbit" | "tree" | "mindmap";
const persistedPrefs = loadGlobalPrefs();
const layoutMode = ref<LayoutMode>(persistedPrefs.layoutMode ?? "tree");
const enableFlowAnim = ref(persistedPrefs.enableFlowAnim);
const showMinimap = ref(persistedPrefs.showMinimap);

// 聚光灯过滤维度 (null 为无，'waf', 'https', 'http')
const spotlightFilter = ref<string | null>(null);
const focusedDomain = ref<string | null>(null);
const isFocusedDomainIp = computed(() => {
  if (!focusedDomain.value) return false;
  return isIpAddress(focusedDomain.value);
});
const searchQuery = ref("");

// 鹰眼小地图交互状态
const minimapSvgRef = ref<SVGSVGElement | null>(null);
const isDraggingMinimap = ref(false);
const minimapDragStart = ref({ clientX: 0, clientY: 0, initPanX: 0, initPanY: 0 });

// 选中与悬停
const selectedNodeId = ref<number | null>(null);
const hoveredNodeId = ref<number | null>(null);
const drawerVisible = ref(false);

// 右键上下文菜单
interface ContextMenuState {
  visible: boolean;
  x: number;
  y: number;
  node: LayoutNode | null;
}
const contextMenu = ref<ContextMenuState>({
  visible: false,
  x: 0,
  y: 0,
  node: null,
});

// 判断是否为 IPv4 地址
const IPV4_REGEX = /^(?:(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.){3}(?:\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$/;

// 常见复合后缀 (二重顶级域名)
const DOUBLE_TLDS = new Set([
  "com.cn", "org.cn", "net.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
  "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk",
  "com.hk", "org.hk", "net.hk", "edu.hk",
  "com.tw", "org.tw", "net.tw", "edu.tw",
  "com.au", "net.au", "org.au", "edu.au",
  "co.jp", "ne.jp", "ac.jp", "go.jp",
]);

function isIpAddress(hostOrIp: string): boolean {
  if (!hostOrIp) return false;
  const clean = stripHostPort(hostOrIp);
  return IPV4_REGEX.test(clean) || clean.split(":").length >= 3 || clean.toLowerCase() === "localhost";
}

function stripHostPort(rawHost: string): string {
  let clean = String(rawHost || "").trim();
  if (clean.startsWith("[")) {
    const closingBracket = clean.indexOf("]");
    if (closingBracket >= 0) return clean.slice(1, closingBracket);
  }
  const colonCount = (clean.match(/:/g) || []).length;
  if (colonCount >= 2) return clean.replace(/^\[|\]$/g, "");
  if (colonCount === 1) return clean.slice(0, clean.lastIndexOf(":"));
  return clean;
}

function extractRootDomain(rawHostname: string): { rootDomain: string; isIp: boolean } {
  if (!rawHostname) return { rootDomain: "未知", isIp: false };
  const clean = stripHostPort(rawHostname);
  if (isIpAddress(clean)) {
    return { rootDomain: clean, isIp: true };
  }
  const parts = clean.split(".");
  if (parts.length <= 2) {
    return { rootDomain: clean, isIp: false };
  }
  const lastTwo = parts.slice(-2).join(".").toLowerCase();
  if (DOUBLE_TLDS.has(lastTwo) && parts.length >= 3) {
    return { rootDomain: parts.slice(-3).join("."), isIp: false };
  }
  return { rootDomain: parts.slice(-2).join("."), isIp: false };
}

// 解析 URL 主机与协议
function parseHost(url?: string): { host: string; protocol: string; path: string; rootDomain: string; isIp: boolean } {
  if (!url) return { host: "未知资产", protocol: "http", path: "", rootDomain: "未知", isIp: false };
  try {
    const parsed = new URL(normalizeAssetUrl(url));
    const host = parsed.hostname + (parsed.port ? `:${parsed.port}` : "");
    const { rootDomain, isIp } = extractRootDomain(parsed.hostname);
    return {
      host,
      protocol: parsed.protocol.replace(":", "").toLowerCase(),
      path: parsed.pathname === "/" ? "" : parsed.pathname,
      rootDomain,
      isIp,
    };
  } catch {
    const clean = url.replace(/^https?:\/\//i, "");
    const parts = clean.split("/");
    const host = parts[0] || "资产";
    const hostname = stripHostPort(host);
    const { rootDomain, isIp } = extractRootDomain(hostname);
    return {
      host,
      protocol: /^https/i.test(url) ? "https" : "http",
      path: parts.slice(1).join("/"),
      rootDomain,
      isIp,
    };
  }
}

// 提取关键标签
function getNodeBadges(asset: DiscoveryResult): string[] {
  const badges: string[] = [];
  const info = parseHost(asset.url);
  badges.push(info.protocol.toUpperCase());

  if (asset.wafName || asset.waf) {
    badges.push("WAF");
  }
  if (asset.framework && typeof asset.framework === "string") {
    const fw = asset.framework.split(/[,/]/)[0].trim();
    if (fw && badges.length < 2) badges.push(fw);
  } else if (asset.server && typeof asset.server === "string") {
    const srv = asset.server.split("/")[0].trim();
    if (srv && badges.length < 2) badges.push(srv);
  }
  return badges.slice(0, 2);
}

// 统计指标
const stats = computed(() => {
  const list = props.assets || [];
  const total = list.length;
  const hosts = new Set<string>();
  let wafCount = 0;
  let httpsCount = 0;
  let httpCount = 0;

  for (const item of list) {
    const info = parseHost(item.url);
    if (info.host) hosts.add(info.host);
    if (item.wafName || item.waf) wafCount++;
    if (info.protocol === "https") httpsCount++;
    else httpCount++;
  }

  return {
    total,
    uniqueHosts: hosts.size,
    wafCount,
    httpsCount,
    httpCount,
  };
});

// 当前选中的资产详情
const selectedAsset = computed(() => {
  if (selectedNodeId.value == null) return null;
  return props.assets.find((a) => a.id === selectedNodeId.value) || null;
});

const BASELINE_RISK_TOOLS = new Set([
  "http_headers",
  "tcp_ports",
  "nmap_service_scan",
]);
const BASELINE_RISK_CODES = new Set([
  "STB-WEB-001",
  "STB-WEB-005",
  "STB-TLS-001",
  "STB-NET-001",
  "STB-SMB-SMBV1",
]);

function findingIsVulnerability(finding: {
  severity?: string;
  sourceTool?: string;
  vulnerabilityCode?: string | null;
}) {
  const tool = String(finding.sourceTool || "").trim().toLowerCase();
  const code = String(finding.vulnerabilityCode || "").trim().toUpperCase();
  const sev = String(finding.severity || "").trim().toUpperCase();

  if (BASELINE_RISK_TOOLS.has(tool)) return false;
  if (BASELINE_RISK_CODES.has(code)) return false;
  if (sev === "LOW" || sev === "INFO") return false;
  if (sev === "CRITICAL" || sev === "HIGH") return true;
  return Boolean(code);
}

// 总览中相同目标可以归属不同项目，卡片和详情只关联本项目的发现。
function getAssetFindings(asset: DiscoveryResult) {
  const targetId = Number(asset.targetId);
  const host = stripHostPort(parseHost(asset.url).host).toLowerCase();
  const url = (asset.url || "").toLowerCase();
  return (props.findings || []).filter((f) => {
    const findingProjectId = f.projectId ?? (typeof props.projectId === "number" ? props.projectId : undefined);
    if (Number(findingProjectId) !== Number(asset.projectId)) return false;
    // Findings are target-scoped in the report API. Keep this association
    // while retaining the project guard above; URL/evidence matching below
    // also supports path-specific findings.
    if (Number(f.targetId) === targetId && targetId > 0) return true;
    const cleanHost = host;
    const fEvidence = String(f.evidence || "").toLowerCase();
    const fDesc = String(f.description || "").toLowerCase();
    const fTitle = String(f.title || "").toLowerCase();
    if (cleanHost && (fEvidence.includes(cleanHost) || fDesc.includes(cleanHost) || fTitle.includes(cleanHost))) return true;
    if (url && fEvidence.includes(url)) return true;
    return false;
  });
}

const selectedNodeFindings = computed(() =>
  selectedAsset.value ? getAssetFindings(selectedAsset.value) : [],
);

const HUB_W = 216;
const HUB_H = 68;
const CARD_W = 228;
const CARD_H = 68;
const DOMAIN_BRANCH_W = 180;
const DOMAIN_BRANCH_H = 34;

function compactLabel(value: string, limit: number) {
  let units = 0;
  let label = "";
  for (const character of value) {
    units += character.charCodeAt(0) > 255 ? 2 : 1;
    if (units > limit) return `${label.slice(0, -1)}…`;
    label += character;
  }
  return label;
}

export interface HubTheme {
  id: string;
  name: string;
  gradStart: string;
  gradEnd: string;
  haloColor: string;
  shadowColor: string;
  iconPath: string;
}

// 微软 Fluent 2 统一规范：所有中心节点共用同一套克制的 Communication Blue 品牌 + 官方盾牌图标，
// 用项目标题区分不同中心卡片，避免多色多图标造成的视觉噪音。
const FLUENT_HUB_THEMES: HubTheme[] = [
  {
    id: "blue",
    name: "Communication Blue",
    gradStart: "#0078d4",
    gradEnd: "#005a9e",
    haloColor: "rgba(0, 120, 212, 0.14)",
    shadowColor: "#0078d4",
    // @fluentui/svg-icons: shield_24_filled
    iconPath:
      "M3 5.75c0-.41.34-.75.75-.75 2.66 0 5.26-.94 7.8-2.85.27-.2.63-.2.9 0C14.99 4.05 17.59 5 20.25 5c.41 0 .75.34.75.75V11c0 5-2.96 8.68-8.73 10.95a.75.75 0 0 1-.54 0C5.96 19.68 3 16 3 11V5.75Z",
  },
];

export interface LayoutHub {
  id: string;
  projectId: number;
  name: string;
  theme: HubTheme;
  x: number;
  y: number;
  assetCount: number;
  hostCount: number;
}

// 布局数据类型
interface LayoutNode {
  id: number;
  asset: DiscoveryResult;
  x: number;
  y: number;
  host: string;
  protocol: string;
  badges: string[];
  rootDomain: string;
  isIp: boolean;
  isMatch: boolean;
  isSpotlight: boolean;
  statusKind?: "waf" | "https" | "http";
  urlPath?: string;
  vulnCount: number;
  riskCount: number;
  findings: ProjectFindingRecord[];
}

type AssetKind = "target" | "probe" | "path";

function getAssetKind(asset: DiscoveryResult | null | undefined): AssetKind {
  if (asset?._assetKind === "target" || asset?._isTargetAsset === true) {
    return "target";
  }
  if (asset?._assetKind === "path" || asset?._webPath === true) {
    return "path";
  }
  return "probe";
}

function isWebPathAsset(asset: DiscoveryResult | null | undefined): boolean {
  return getAssetKind(asset) === "path";
}

function getAssetRemovalAction(asset: DiscoveryResult | null | undefined): "probe" | "target" | "none" {
  if (!asset || props.projectId === "all") return "none";
  const kind = getAssetKind(asset);
  // Discovered paths are maintained by recon collectors and have no single
  // delete endpoint. Ignore stale IDs from merged records instead of
  // treating a path as an authorized target.
  if (kind === "path") return "none";
  if (kind === "target") {
    const targetLinkId = Number(asset._targetLinkId);
    return Number.isSafeInteger(targetLinkId) && targetLinkId > 0 ? "target" : "none";
  }
  // ProjectDetail feeds the component's original discovery rows directly,
  // before the all-project loader adds `_probeResultId`.  For an untagged
  // probe, its own primary key is the safe fallback; path and target records
  // were returned above and never reach this branch.
  const probeId = Number(asset._probeResultId ?? asset.id);
  if (Number.isSafeInteger(probeId) && probeId > 0) return "probe";
  return "none";
}

function assetRemovalLabel(asset: DiscoveryResult | null | undefined): string {
  if (props.projectId === "all") return "全部项目总览不可删除";
  const action = getAssetRemovalAction(asset);
  if (action === "probe") return "移除探测记录";
  if (action === "target") return "解除项目授权目标";
  if (getAssetKind(asset) === "path") return "测绘路径由系统维护";
  return "无法移除该资产";
}

function statusBadgeWidth(node: Pick<LayoutNode, "vulnCount" | "riskCount">): number {
  if (node.vulnCount > 0 || node.riskCount > 0) {
    const count = node.vulnCount > 0 ? node.vulnCount : node.riskCount;
    return 58 + Math.max(0, String(count).length - 1) * 6;
  }
  return 48;
}

interface MindmapDomainNode {
  id: string;
  domain: string;
  isIp: boolean;
  x: number;
  y: number;
  w: number;
  h: number;
  nodeCount: number;
  isMatch: boolean;
}

interface DomainClusterEnclosure {
  domain: string;
  isIp: boolean;
  x: number;
  y: number;
  width: number;
  height: number;
  nodeCount: number;
  isMatch: boolean;
  labelWidth: number;
}

interface LayoutEdge {
  id: string;
  sourceId: number | "hub" | string;
  targetId: number | string;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  path: string;
}

// 计算直线与矩形外边框的精确物理交点
function getRectIntersection(
  cx: number,
  cy: number,
  w: number,
  h: number,
  targetX: number,
  targetY: number,
): { x: number; y: number } {
  const dx = targetX - cx;
  const dy = targetY - cy;
  if (dx === 0 && dy === 0) return { x: cx, y: cy };

  const hw = w / 2;
  const hh = h / 2;

  // 判断相交在左右垂直边还是上下水平边
  if (Math.abs(dy) * hw <= Math.abs(dx) * hh) {
    const sign = dx > 0 ? 1 : -1;
    return {
      x: cx + sign * hw,
      y: cy + sign * hw * (dy / dx),
    };
  } else {
    const sign = dy > 0 ? 1 : -1;
    return {
      x: cx + sign * hh * (dx / dy),
      y: cy + sign * hh,
    };
  }
}

// AABB 矩形防重叠碰撞分离器 (保证卡片之间与各中心卡片绝对不产生任何物理压叠)
function resolveNodeCollisions(
  nodes: LayoutNode[],
  hubs: LayoutHub[],
  customMap: Record<string | number, { x: number; y: number }>,
) {
  if (nodes.length <= 1 && hubs.length <= 1) return;
  const maxIterations = 24;
  const paddingX = 26; // 卡片间水平安全距离
  const paddingY = 18; // 卡片间垂直安全距离
  const minHubDistX = (HUB_W + CARD_W) / 2 + 32;
  const minHubDistY = (HUB_H + CARD_H) / 2 + 24;

  for (let iter = 0; iter < maxIterations; iter++) {
    let hasCollision = false;

    // 1. 避让所有中心卡片
    for (const hub of hubs) {
      for (const node of nodes) {
        if (customMap[node.id] != null) continue;
        const dx = node.x - hub.x;
        const dy = node.y - hub.y;
        const overlapX = minHubDistX - Math.abs(dx);
        const overlapY = minHubDistY - Math.abs(dy);

        if (overlapX > 0 && overlapY > 0) {
          hasCollision = true;
          if (overlapX < overlapY) {
            node.x += (dx >= 0 ? 1 : -1) * overlapX;
          } else {
            node.y += (dy >= 0 ? 1 : -1) * overlapY;
          }
        }
      }
    }

    // 2. 节点相互碰撞避让 (AABB)
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];

        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const overlapX = CARD_W + paddingX - Math.abs(dx);
        const overlapY = CARD_H + paddingY - Math.abs(dy);

        if (overlapX > 0 && overlapY > 0) {
          hasCollision = true;
          const aCustom = customMap[a.id] != null;
          const bCustom = customMap[b.id] != null;

          if (overlapX < overlapY) {
            const push = overlapX * 0.52;
            const sign = dx >= 0 ? 1 : -1;
            if (!aCustom && !bCustom) {
              a.x -= sign * push;
              b.x += sign * push;
            } else if (!aCustom) {
              a.x -= sign * overlapX;
            } else if (!bCustom) {
              b.x += sign * overlapX;
            }
          } else {
            const push = overlapY * 0.52;
            const sign = dy >= 0 ? 1 : -1;
            if (!aCustom && !bCustom) {
              a.y -= sign * push;
              b.y += sign * push;
            } else if (!aCustom) {
              a.y -= sign * overlapY;
            } else if (!bCustom) {
              b.y += sign * overlapY;
            }
          }
        }
      }
    }

    if (!hasCollision) break;
  }
}

const cx = computed(() => viewportWidth.value / 2);
const cy = computed(() => viewportHeight.value / 2);

// 科学椭圆环轨：契合 16:9 宽屏及 224x64 矩形卡片物理几何，彻底告别内外圈撞车
const orbitRings = computed(() => {
  const count = props.assets.filter((asset) => asset.id != null).length;
  if (!count) return [];

  const ringCounts = count <= 5
    ? [count]
    : count <= 12
      ? [Math.min(5, Math.ceil(count * 0.4)), count - Math.min(5, Math.ceil(count * 0.4))]
      : [5, Math.min(10, count - 5), Math.max(0, count - 15)].filter((c) => c > 0);

  const minRx0 = (HUB_W + CARD_W) / 2 + 56;
  const minRy0 = (HUB_H + CARD_H) / 2 + 48;

  let prevRx = 0;
  let prevRy = 0;
  let startIdx = 0;

  return ringCounts.map((ringCount, index) => {
    const chordRx = ringCount > 1
      ? ((CARD_W + 36) * ringCount) / (2 * Math.PI)
      : 0;
    const chordRy = ringCount > 1
      ? ((CARD_H + 28) * ringCount) / (2 * Math.PI)
      : 0;

    const rx = Math.max(
      minRx0,
      chordRx,
      index > 0 ? prevRx + CARD_W + 52 : 0,
    );
    const ry = Math.max(
      minRy0,
      chordRy,
      index > 0 ? prevRy + CARD_H + 56 : 0,
    );

    const angleOffset = (index % 2 === 1 ? Math.PI / Math.max(1, ringCount) : 0) - Math.PI / 2;

    const ring = { rx, ry, count: ringCount, startIdx, angleOffset };
    prevRx = rx;
    prevRy = ry;
    startIdx += ringCount;
    return ring;
  });
});

function getAssetStatusKind(asset: DiscoveryResult, protocol: string): "waf" | "https" | "http" {
  if (asset.wafName || asset.waf) return "waf";
  if (protocol === "https") return "https";
  return "http";
}

const hubPosition = computed(() => {
  if (layoutMode.value === "mindmap") {
    const leftAnchor = Math.max(HUB_W / 2 + 60, cx.value - (viewportWidth.value > 1200 ? 440 : 380));
    return {
      x: leftAnchor,
      y: cy.value,
    };
  }
  return { x: cx.value, y: cy.value };
});

// 计算全部中心节点与资产节点坐标与连线 (支持单项目模式与全部项目多中心模式)
const layoutData = computed<{
  hubs: LayoutHub[];
  nodes: LayoutNode[];
  edges: LayoutEdge[];
  domainNodes: MindmapDomainNode[];
}>(() => {
  const q = searchQuery.value.trim().toLowerCase();
  const allAssets = props.assets.filter((a) => a.id != null).sort((a, b) =>
    parseHost(a.url).host.localeCompare(parseHost(b.url).host) || a.id! - b.id!,
  );
  const nodes: LayoutNode[] = [];
  const edges: LayoutEdge[] = [];
  const domainNodes: MindmapDomainNode[] = [];

  const isAll = props.projectId === "all";
  const hubs: LayoutHub[] = [];

  if (!isAll) {
    // 单项目模式：仅展示 1 个中心节点
    const hostSet = new Set<string>();
    allAssets.forEach((a) => {
      const h = parseHost(a.url).host;
      if (h) hostSet.add(h);
    });
    const hubId = "hub";
    const custom = customPositions.value[hubId];
    hubs.push({
      id: hubId,
      projectId: typeof props.projectId === "number" ? props.projectId : 0,
      name: props.hubLabel || "项目中心",
      theme: FLUENT_HUB_THEMES[0],
      x: custom ? custom.x : hubPosition.value.x,
      y: custom ? custom.y : hubPosition.value.y,
      assetCount: allAssets.length,
      hostCount: hostSet.size,
    });
  } else {
    // 全部项目模式：为每个评估项目生成独立的专属中心节点
    const projectMap = new Map<number, string>();
    (props.projects || []).forEach((p) => {
      projectMap.set(p.id, p.name);
    });
    allAssets.forEach((a) => {
      if (a.projectId != null && !projectMap.has(a.projectId)) {
        projectMap.set(a.projectId, (a.projectName as string) || `项目 #${a.projectId}`);
      }
    });

    const projectIds = Array.from(projectMap.keys());
    // 仅保留包含实际资产的项目（防止未关联资产的空项目在中心扎堆堆叠）
    const pidsWithAssets = projectIds.filter((pid) =>
      allAssets.some((a) => a.projectId === pid),
    );
    const targetProjectIds = pidsWithAssets.length > 0 ? pidsWithAssets : (projectIds.slice(0, 1));

    if (targetProjectIds.length === 0) {
      const hubId = "hub-all";
      const custom = customPositions.value[hubId];
      hubs.push({
        id: hubId,
        projectId: 0,
        name: "全部项目",
        theme: FLUENT_HUB_THEMES[0],
        x: custom ? custom.x : cx.value,
        y: custom ? custom.y : cy.value,
        assetCount: 0,
        hostCount: 0,
      });
    } else {
      targetProjectIds.forEach((pid, idx) => {
        const pAssets = allAssets.filter((a) => a.projectId === pid);
        const hostSet = new Set<string>();
        pAssets.forEach((a) => {
          const h = parseHost(a.url).host;
          if (h) hostSet.add(h);
        });
        const hubId = `hub-${pid}`;
        const custom = customPositions.value[hubId];
        hubs.push({
          id: hubId,
          projectId: pid,
          name: projectMap.get(pid) || `项目 #${pid}`,
          theme: FLUENT_HUB_THEMES[0],
          x: custom ? custom.x : cx.value,
          y: custom ? custom.y : cy.value,
          assetCount: pAssets.length,
          hostCount: hostSet.size,
        });
      });
    }
  }

  if (!allAssets.length) return { hubs, nodes, edges, domainNodes };

  // 节点生成帮助函数
  function createLayoutNode(
    asset: DiscoveryResult,
    autoX: number,
    autoY: number,
  ): LayoutNode {
    const custom = customPositions.value[asset.id!];
    const nx = custom ? custom.x : autoX;
    const ny = custom ? custom.y : autoY;

    const { host, protocol, rootDomain, isIp } = parseHost(asset.url);
    const badges = getNodeBadges(asset);

    // 解析 URL 路径（如有）
    let urlPath = "";
    if (asset.url) {
      try {
        const u = new URL(normalizeAssetUrl(asset.url));
        if (u.pathname && u.pathname !== "/") {
          urlPath = u.pathname + (u.search || "");
        }
      } catch {
        // ignore
      }
    }

    // 匹配关联在该资产上的漏洞与风险发现项
    const nodeFindings = getAssetFindings(asset);

    const vulnCount = nodeFindings.filter(findingIsVulnerability).length;
    const riskCount = nodeFindings.length - vulnCount;

    const isSearchMatch =
      !q ||
      (asset.url || "").toLowerCase().includes(q) ||
      host.toLowerCase().includes(q) ||
      urlPath.toLowerCase().includes(q) ||
      nodeFindings.some((f) => (f.title || "").toLowerCase().includes(q)) ||
      [asset.server, asset.framework, asset.wafName, ...badges].some((value) =>
        typeof value === "string" && value.toLowerCase().includes(q),
      );

    let isSpotlight = true;
    if (focusedDomain.value) {
      isSpotlight = rootDomain === focusedDomain.value || host.includes(focusedDomain.value);
    } else if (spotlightFilter.value === "waf") {
      isSpotlight = Boolean(asset.wafName || asset.waf);
    } else if (spotlightFilter.value === "https") {
      isSpotlight = protocol === "https";
    } else if (spotlightFilter.value === "http") {
      isSpotlight = protocol === "http";
    }

    const isMatch = isSearchMatch && isSpotlight;
    const statusKind = getAssetStatusKind(asset, protocol);

    return {
      id: asset.id!,
      asset,
      x: nx,
      y: ny,
      host,
      protocol,
      badges,
      rootDomain,
      isIp,
      isMatch,
      isSpotlight,
      statusKind,
      urlPath,
      vulnCount,
      riskCount,
      findings: nodeFindings,
    };
  }

  // ------------------------- 布局算法分支 -------------------------
  if (layoutMode.value === "orbit") {
    if (hubs.length === 1) {
      // 单中心环轨
      const centerPoint = { x: hubs[0].x, y: hubs[0].y };
      orbitRings.value.forEach((ring) => {
        const ringAssets = allAssets.slice(ring.startIdx, ring.startIdx + ring.count);
        ringAssets.forEach((asset, idx) => {
          const angle = ring.angleOffset + (2 * Math.PI * idx) / Math.max(1, ring.count);
          const autoX = centerPoint.x + ring.rx * Math.cos(angle);
          const autoY = centerPoint.y + ring.ry * Math.sin(angle);
          const node = createLayoutNode(asset, autoX, autoY);
          nodes.push(node);
        });
      });

      resolveNodeCollisions(nodes, hubs, customPositions.value);

      nodes.forEach((node) => {
        const p1 = getRectIntersection(centerPoint.x, centerPoint.y, HUB_W, HUB_H, node.x, node.y);
        const p2 = getRectIntersection(node.x, node.y, CARD_W, CARD_H, centerPoint.x, centerPoint.y);
        const currentAngle = Math.atan2(node.y - centerPoint.y, node.x - centerPoint.x);
        const midX = (p1.x + p2.x) / 2 + Math.sin(currentAngle) * 10;
        const midY = (p1.y + p2.y) / 2 - Math.cos(currentAngle) * 10;
        const path = `M ${p1.x} ${p1.y} Q ${midX} ${midY} ${p2.x} ${p2.y}`;

        edges.push({
          id: `edge-${node.id}`,
          sourceId: hubs[0].id,
          targetId: node.id,
          x1: p1.x,
          y1: p1.y,
          x2: p2.x,
          y2: p2.y,
          path,
        });
      });
    } else {
      // 多中心星座环轨模式 (Multi-Hub Constellation Orbit)
      const M = hubs.length;
      const constellationRadius = Math.max(380, M * 150);

      hubs.forEach((hub, i) => {
        const angle = (2 * Math.PI * i) / M - Math.PI / 2;
        const autoHubX = cx.value + constellationRadius * Math.cos(angle);
        const autoHubY = cy.value + constellationRadius * Math.sin(angle);
        if (customPositions.value[hub.id] == null) {
          hub.x = autoHubX;
          hub.y = autoHubY;
        }

        const pAssets = allAssets.filter((a) => a.projectId === hub.projectId);
        const count = pAssets.length;
        if (count > 0) {
          const ringRx = Math.max((HUB_W + CARD_W) / 2 + 54, ((CARD_W + 36) * count) / (2 * Math.PI));
          const ringRy = Math.max((HUB_H + CARD_H) / 2 + 44, ((CARD_H + 28) * count) / (2 * Math.PI));
          pAssets.forEach((asset, idx) => {
            const assetAngle = -Math.PI / 2 + (2 * Math.PI * idx) / count;
            const autoX = hub.x + ringRx * Math.cos(assetAngle);
            const autoY = hub.y + ringRy * Math.sin(assetAngle);
            const node = createLayoutNode(asset, autoX, autoY);
            nodes.push(node);
          });
        }
      });

      resolveNodeCollisions(nodes, hubs, customPositions.value);

      const hubsMap = new Map(hubs.map((h) => [h.projectId, h]));
      nodes.forEach((node) => {
        const targetHub = hubsMap.get(node.asset.projectId) || hubs[0];
        const p1 = getRectIntersection(targetHub.x, targetHub.y, HUB_W, HUB_H, node.x, node.y);
        const p2 = getRectIntersection(node.x, node.y, CARD_W, CARD_H, targetHub.x, targetHub.y);
        const currentAngle = Math.atan2(node.y - targetHub.y, node.x - targetHub.x);
        const midX = (p1.x + p2.x) / 2 + Math.sin(currentAngle) * 10;
        const midY = (p1.y + p2.y) / 2 - Math.cos(currentAngle) * 10;
        const path = `M ${p1.x} ${p1.y} Q ${midX} ${midY} ${p2.x} ${p2.y}`;

        edges.push({
          id: `edge-${node.id}`,
          sourceId: targetHub.id,
          targetId: node.id,
          x1: p1.x,
          y1: p1.y,
          x2: p2.x,
          y2: p2.y,
          path,
        });
      });
    }
  } else if (layoutMode.value === "mindmap") {
    // 思维导图模式 (支持多项目各自分支)
    const leftAnchor = Math.max(HUB_W / 2 + 60, cx.value - (viewportWidth.value > 1200 ? 440 : 380));

    // 计算各项目的思维导图高度
    const clusterSeparation = 120;
    const clusterHeights = hubs.map((hub) => {
      const pAssets = allAssets.filter((a) => a.projectId === hub.projectId);
      const rootDomains = new Set(pAssets.map((a) => parseHost(a.url).rootDomain));
      return Math.max(HUB_H + 80, rootDomains.size * 64 + pAssets.length * (CARD_H + 22));
    });
    const totalHeight =
      clusterHeights.reduce((a, b) => a + b, 0) +
      Math.max(0, hubs.length - 1) * clusterSeparation;
    let currentClusterY = cy.value - totalHeight / 2;

    hubs.forEach((hub, hIdx) => {
      const clusterHeight = clusterHeights[hIdx];
      const autoHubY = currentClusterY + clusterHeight / 2;
      const autoHubX = leftAnchor;
      if (customPositions.value[hub.id] == null) {
        hub.x = autoHubX;
        hub.y = autoHubY;
      }

      const pAssets = allAssets.filter((a) => a.projectId === hub.projectId);
      const domainGroups = new Map<string, DiscoveryResult[]>();
      pAssets.forEach((a) => {
        const rd = parseHost(a.url).rootDomain;
        if (!domainGroups.has(rd)) domainGroups.set(rd, []);
        domainGroups.get(rd)!.push(a);
      });

      const sortedDomains = Array.from(domainGroups.keys()).sort((a, b) => a.localeCompare(b));
      const domainX = hub.x + HUB_W / 2 + 130;
      const leafX = domainX + DOMAIN_BRANCH_W / 2 + 160;
      const verticalGap = CARD_H + 20;
      const domainSeparation = 26;

      let subTotalHeight = 0;
      const groupHeights = sortedDomains.map((d) => {
        const count = domainGroups.get(d)!.length;
        const h = Math.max(DOMAIN_BRANCH_H + 16, count * verticalGap);
        subTotalHeight += h;
        return h;
      });
      subTotalHeight += Math.max(0, sortedDomains.length - 1) * domainSeparation;

      let currentDomainY = hub.y - subTotalHeight / 2;

      sortedDomains.forEach((rootDomain, dIdx) => {
        const groupAssets = domainGroups.get(rootDomain)!;
        const blockHeight = groupHeights[dIdx];
        const startLeafY = currentDomainY + (blockHeight - (groupAssets.length - 1) * verticalGap) / 2;
        const branchY = currentDomainY + blockHeight / 2;

        let anyAssetMatch = false;

        groupAssets.forEach((asset, idx) => {
          const autoX = leafX;
          const autoY = startLeafY + idx * verticalGap;
          const node = createLayoutNode(asset, autoX, autoY);
          if (node.isMatch) anyAssetMatch = true;
          nodes.push(node);

          const lx1 = domainX + DOMAIN_BRANCH_W / 2;
          const ly1 = branchY;
          const lx2 = node.x - CARD_W / 2;
          const ly2 = node.y;
          const ldx = lx2 - lx1;
          const leafPath = `M ${lx1} ${ly1} C ${lx1 + ldx * 0.5} ${ly1}, ${lx2 - ldx * 0.5} ${ly2}, ${lx2} ${ly2}`;

          edges.push({
            id: `edge-branch-${asset.id}`,
            sourceId: `domain-${hub.id}-${rootDomain}`,
            targetId: asset.id!,
            x1: lx1,
            y1: ly1,
            x2: lx2,
            y2: ly2,
            path: leafPath,
          });
        });

        const branchId = `domain-${hub.id}-${rootDomain}`;
        const isDomainIp = isIpAddress(rootDomain);
        domainNodes.push({
          id: branchId,
          domain: rootDomain,
          isIp: isDomainIp,
          x: domainX,
          y: branchY,
          w: DOMAIN_BRANCH_W,
          h: DOMAIN_BRANCH_H,
          nodeCount: groupAssets.length,
          isMatch: anyAssetMatch,
        });

        const hx1 = hub.x + HUB_W / 2;
        const hy1 = hub.y;
        const hx2 = domainX - DOMAIN_BRANCH_W / 2;
        const hy2 = branchY;
        const hdx = hx2 - hx1;
        const hubPath = `M ${hx1} ${hy1} C ${hx1 + hdx * 0.5} ${hy1}, ${hx2 - hdx * 0.5} ${hy2}, ${hx2} ${hy2}`;

        edges.push({
          id: `edge-hub-${branchId}`,
          sourceId: hub.id,
          targetId: branchId,
          x1: hx1,
          y1: hy1,
          x2: hx2,
          y2: hy2,
          path: hubPath,
        });

        currentDomainY += blockHeight + domainSeparation;
      });

      currentClusterY += clusterHeight + clusterSeparation;
    });

    resolveNodeCollisions(nodes, hubs, customPositions.value);
  } else {
    // 树状模式 (Tree Mode)
    if (hubs.length === 1) {
      // 单中心树状
      const hub = hubs[0];
      const hostGroups = new Map<string, DiscoveryResult[]>();
      allAssets.forEach((a) => {
        const h = parseHost(a.url).host;
        if (!hostGroups.has(h)) hostGroups.set(h, []);
        hostGroups.get(h)!.push(a);
      });

      const groupedAssets = Array.from(hostGroups.values()).flat();
      const leftCount = Math.ceil(groupedAssets.length / 2);
      const sideGroups = [groupedAssets.slice(0, leftCount), groupedAssets.slice(leftCount)];
      const verticalGap = CARD_H + 20;
      const horizontalOffset = Math.max(
        (HUB_W + CARD_W) / 2 + 96,
        Math.min(380, (viewportWidth.value - CARD_W) / 2 - 48),
      );

      sideGroups.forEach((groupAssets, sideIndex) => {
        const direction = sideIndex === 0 ? -1 : 1;
        const startY = hub.y - ((groupAssets.length - 1) * verticalGap) / 2;
        groupAssets.forEach((asset, index) => {
          const autoX = hub.x + direction * horizontalOffset;
          const autoY = startY + index * verticalGap;
          const node = createLayoutNode(asset, autoX, autoY);
          nodes.push(node);
        });
      });

      resolveNodeCollisions(nodes, hubs, customPositions.value);

      nodes.forEach((node) => {
        const edgeDirection = node.x >= hub.x ? 1 : -1;
        const x1 = hub.x + (edgeDirection * HUB_W) / 2;
        const y1 = hub.y;
        const x2 = node.x - (edgeDirection * CARD_W) / 2;
        const y2 = node.y;
        const dx = x2 - x1;
        const path = `M ${x1} ${y1} C ${x1 + dx * 0.45} ${y1}, ${x2 - dx * 0.45} ${y2}, ${x2} ${y2}`;

        edges.push({
          id: `edge-${node.id}`,
          sourceId: hub.id,
          targetId: node.id,
          x1,
          y1,
          x2,
          y2,
          path,
        });
      });
    } else {
      // 多中心树状集群模式 (Multi-Project Tree Clusters)
      let totalTreeHeight = 0;
      const clusterHeights = hubs.map((hub) => {
        const pAssets = allAssets.filter((a) => a.projectId === hub.projectId);
        const rows = Math.max(1, Math.ceil(pAssets.length / 2));
        const h = Math.max(HUB_H + 40, rows * (CARD_H + 20) + 40);
        totalTreeHeight += h;
        return h;
      });
      totalTreeHeight += (hubs.length - 1) * 80;

      let currentTreeY = cy.value - totalTreeHeight / 2;

      hubs.forEach((hub, hIdx) => {
        const clusterHeight = clusterHeights[hIdx];
        const autoHubY = currentTreeY + clusterHeight / 2;
        const autoHubX = cx.value;
        if (customPositions.value[hub.id] == null) {
          hub.x = autoHubX;
          hub.y = autoHubY;
        }

        const pAssets = allAssets.filter((a) => a.projectId === hub.projectId);
        const hostGroups = new Map<string, DiscoveryResult[]>();
        pAssets.forEach((a) => {
          const h = parseHost(a.url).host;
          if (!hostGroups.has(h)) hostGroups.set(h, []);
          hostGroups.get(h)!.push(a);
        });

        const groupedAssets = Array.from(hostGroups.values()).flat();
        const leftCount = Math.ceil(groupedAssets.length / 2);
        const sideGroups = [groupedAssets.slice(0, leftCount), groupedAssets.slice(leftCount)];
        const verticalGap = CARD_H + 20;
        const horizontalOffset = Math.max((HUB_W + CARD_W) / 2 + 96, 360);

        sideGroups.forEach((groupAssets, sideIndex) => {
          const direction = sideIndex === 0 ? -1 : 1;
          const startY = hub.y - ((groupAssets.length - 1) * verticalGap) / 2;
          groupAssets.forEach((asset, index) => {
            const autoX = hub.x + direction * horizontalOffset;
            const autoY = startY + index * verticalGap;
            const node = createLayoutNode(asset, autoX, autoY);
            nodes.push(node);
          });
        });

        currentTreeY += clusterHeight + 80;
      });

      resolveNodeCollisions(nodes, hubs, customPositions.value);

      const hubsMap = new Map(hubs.map((h) => [h.projectId, h]));
      nodes.forEach((node) => {
        const targetHub = hubsMap.get(node.asset.projectId) || hubs[0];
        const edgeDirection = node.x >= targetHub.x ? 1 : -1;
        const x1 = targetHub.x + (edgeDirection * HUB_W) / 2;
        const y1 = targetHub.y;
        const x2 = node.x - (edgeDirection * CARD_W) / 2;
        const y2 = node.y;
        const dx = x2 - x1;
        const path = `M ${x1} ${y1} C ${x1 + dx * 0.45} ${y1}, ${x2 - dx * 0.45} ${y2}, ${x2} ${y2}`;

        edges.push({
          id: `edge-${node.id}`,
          sourceId: targetHub.id,
          targetId: node.id,
          x1,
          y1,
          x2,
          y2,
          path,
        });
      });
    }
  }

  return { hubs, nodes, edges, domainNodes };
});

// 计算同主域半透明聚类围栏 (>= 2 个节点时绘制气泡底板，理顺资产星系)
const clusterEnclosures = computed<DomainClusterEnclosure[]>(() => {
  if (layoutMode.value === "orbit") return [];
  const nodes = layoutData.value.nodes;
  const domainMap = new Map<string, LayoutNode[]>();

  for (const node of nodes) {
    if (!domainMap.has(node.rootDomain)) domainMap.set(node.rootDomain, []);
    domainMap.get(node.rootDomain)!.push(node);
  }

  const clusters: DomainClusterEnclosure[] = [];
  const padX = 18;
  const padY = 16;

  domainMap.forEach((domainNodes, domain) => {
    if (domainNodes.length < 2) return;
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;
    let isMatch = false;
    const isIp = domainNodes[0]?.isIp ?? isIpAddress(domain);

    for (const n of domainNodes) {
      minX = Math.min(minX, n.x - CARD_W / 2);
      maxX = Math.max(maxX, n.x + CARD_W / 2);
      minY = Math.min(minY, n.y - CARD_H / 2);
      maxY = Math.max(maxY, n.y + CARD_H / 2);
      if (n.isMatch) isMatch = true;
    }

    const label = `${domain} · ${domainNodes.length} 资产`;
    const labelWidth = Math.min(260, Math.max(110, label.length * 7.5 + 24));

    clusters.push({
      domain,
      isIp,
      x: minX - padX,
      y: minY - padY,
      width: maxX - minX + padX * 2,
      height: maxY - minY + padY * 2,
      nodeCount: domainNodes.length,
      isMatch,
      labelWidth,
    });
  });

  return clusters;
});

const matchedNodeIds = computed(() => {
  const set = new Set<number | string>(
    layoutData.value.nodes.filter((node) => node.isMatch).map((node) => node.id),
  );
  (layoutData.value.domainNodes || []).forEach((dn) => {
    if (dn.isMatch) set.add(dn.id);
  });
  return set;
});

const sceneBounds = computed(() => {
  const nodes = layoutData.value.nodes;
  const hubs = layoutData.value.hubs;
  const dNodes = layoutData.value.domainNodes || [];

  let left = Infinity;
  let right = -Infinity;
  let top = Infinity;
  let bottom = -Infinity;

  for (const hub of hubs) {
    left = Math.min(left, hub.x - HUB_W / 2);
    right = Math.max(right, hub.x + HUB_W / 2);
    top = Math.min(top, hub.y - HUB_H / 2);
    bottom = Math.max(bottom, hub.y + HUB_H / 2);
  }

  for (const node of nodes) {
    left = Math.min(left, node.x - CARD_W / 2);
    right = Math.max(right, node.x + CARD_W / 2);
    top = Math.min(top, node.y - CARD_H / 2);
    bottom = Math.max(bottom, node.y + CARD_H / 2);
  }

  for (const dn of dNodes) {
    left = Math.min(left, dn.x - dn.w / 2);
    right = Math.max(right, dn.x + dn.w / 2);
    top = Math.min(top, dn.y - dn.h / 2);
    bottom = Math.max(bottom, dn.y + dn.h / 2);
  }

  if (!Number.isFinite(left)) {
    left = cx.value - HUB_W / 2;
    right = cx.value + HUB_W / 2;
    top = cy.value - HUB_H / 2;
    bottom = cy.value + HUB_H / 2;
  }

  const padX = 64;
  const padY = 56;
  left -= padX;
  right += padX;
  top -= padY;
  bottom += padY;

  return { left, top, width: Math.max(100, right - left), height: Math.max(100, bottom - top) };
});

const minimapTransform = computed(() => {
  const bounds = sceneBounds.value;
  const scale = Math.min(180 / bounds.width, 100 / bounds.height);
  return {
    scale,
    x: 100 - (bounds.left + bounds.width / 2) * scale,
    y: 60 - (bounds.top + bounds.height / 2) * scale,
  };
});

const minimapViewfinder = computed(() => {
  const map = minimapTransform.value;
  return {
    x: map.x - pan.value.x / zoom.value * map.scale,
    y: map.y - pan.value.y / zoom.value * map.scale,
    width: viewportWidth.value / zoom.value * map.scale,
    height: viewportHeight.value / zoom.value * map.scale,
  };
});

function setZoom(value: number, anchor = { x: cx.value, y: cy.value }) {
  const nextZoom = Math.min(2.5, Math.max(0.1, value));
  pan.value = {
    x: anchor.x - (anchor.x - pan.value.x) / zoom.value * nextZoom,
    y: anchor.y - (anchor.y - pan.value.y) / zoom.value * nextZoom,
  };
  zoom.value = nextZoom;
}

function zoomIn() {
  setZoom(zoom.value + 0.15);
}

function zoomOut() {
  setZoom(zoom.value - 0.15);
}

function fitView() {
  const bounds = sceneBounds.value;
  const scale = Math.min(
    1,
    Math.max(1, viewportWidth.value - 48) / bounds.width,
    Math.max(1, viewportHeight.value - 88) / bounds.height,
  );
  zoom.value = scale;
  pan.value = {
    x: cx.value - (bounds.left + bounds.width / 2) * scale,
    y: cy.value - 12 - (bounds.top + bounds.height / 2) * scale,
  };
}

async function resetView() {
  customPositions.value = {};
  if (props.projectId != null) clearNodePositions(props.projectId);
  await nextTick();
  fitView();
}

function onWheel(e: WheelEvent) {
  e.preventDefault();
  const rect = canvasWrapRef.value?.getBoundingClientRect();
  if (!rect) return;
  const delta = e.deltaY < 0 ? 0.08 : -0.08;
  setZoom(zoom.value + delta, { x: e.clientX - rect.left, y: e.clientY - rect.top });
}

// 画布背景拖拽平移
function onCanvasMouseDown(e: MouseEvent) {
  if (e.button !== 0) return;
  closeContextMenu();
  isDraggingCanvas.value = true;
  hasDragged.value = false;
  canvasDragStart.value = { x: e.clientX - pan.value.x, y: e.clientY - pan.value.y };
}

// 中心节点拖拽定位
function onHubMouseDown(e: MouseEvent, hub: LayoutHub) {
  if (e.button !== 0) return;
  e.stopPropagation();
  closeContextMenu();
  draggingHubId.value = hub.id;
  hasDragged.value = false;
  nodeDragStart.value = {
    clientX: e.clientX,
    clientY: e.clientY,
    initX: hub.x,
    initY: hub.y,
  };
}

// 节点拖拽定位
function onNodeMouseDown(e: MouseEvent, node: LayoutNode) {
  if (e.button !== 0) return;
  e.stopPropagation();
  closeContextMenu();
  draggingNodeId.value = node.id;
  hasDragged.value = false;
  nodeDragStart.value = {
    clientX: e.clientX,
    clientY: e.clientY,
    initX: node.x,
    initY: node.y,
  };
}

// 全局鼠标移动
function onGlobalMouseMove(e: MouseEvent) {
  if (draggingHubId.value != null) {
    if (!hasDragged.value && Math.hypot(e.clientX - nodeDragStart.value.clientX, e.clientY - nodeDragStart.value.clientY) < 3) return;
    hasDragged.value = true;
    const dx = (e.clientX - nodeDragStart.value.clientX) / zoom.value;
    const dy = (e.clientY - nodeDragStart.value.clientY) / zoom.value;
    customPositions.value = {
      ...customPositions.value,
      [draggingHubId.value]: {
        x: nodeDragStart.value.initX + dx,
        y: nodeDragStart.value.initY + dy,
      },
    };
  } else if (draggingNodeId.value != null) {
    if (!hasDragged.value && Math.hypot(e.clientX - nodeDragStart.value.clientX, e.clientY - nodeDragStart.value.clientY) < 3) return;
    hasDragged.value = true;
    const dx = (e.clientX - nodeDragStart.value.clientX) / zoom.value;
    const dy = (e.clientY - nodeDragStart.value.clientY) / zoom.value;
    customPositions.value = {
      ...customPositions.value,
      [draggingNodeId.value]: {
        x: nodeDragStart.value.initX + dx,
        y: nodeDragStart.value.initY + dy,
      },
    };
  } else if (isDraggingMinimap.value && minimapSvgRef.value) {
    const rect = minimapSvgRef.value.getBoundingClientRect();
    const map = minimapTransform.value;
    if (rect.width > 0 && rect.height > 0 && map.scale > 0) {
      // 鼠标在小地图屏幕上的移动量 -> 小地图 SVG viewBox 坐标增量
      const dMinimapX = ((e.clientX - minimapDragStart.value.clientX) / rect.width) * 200;
      const dMinimapY = ((e.clientY - minimapDragStart.value.clientY) / rect.height) * 120;
      // 取景框在小地图向右下移动，主画布应向左上平移，系数为 zoom / scale
      const ratio = zoom.value / map.scale;
      pan.value = {
        x: minimapDragStart.value.initPanX - dMinimapX * ratio,
        y: minimapDragStart.value.initPanY - dMinimapY * ratio,
      };
    }
  } else if (isDraggingCanvas.value) {
    hasDragged.value = true;
    pan.value = {
      x: e.clientX - canvasDragStart.value.x,
      y: e.clientY - canvasDragStart.value.y,
    };
  }
}

// 全局鼠标松开
function onGlobalMouseUp() {
  isDraggingCanvas.value = false;
  isDraggingMinimap.value = false;
  draggingNodeId.value = null;
  draggingHubId.value = null;
}

// 小地图坐标换算到主画布平移
function panToMinimapPoint(minimapX: number, minimapY: number) {
  const map = minimapTransform.value;
  if (!map.scale) return;
  // 小地图坐标反求拓扑场景中点坐标 (sceneX, sceneY)
  const sceneX = (minimapX - map.x) / map.scale;
  const sceneY = (minimapY - map.y) / map.scale;
  // 让视口中心 (cx, cy) 对准 (sceneX, sceneY)
  pan.value = {
    x: cx.value - sceneX * zoom.value,
    y: cy.value - sceneY * zoom.value,
  };
}

// 小地图鼠标按下：支持点击跳转与拖拽取景框快速移动
function onMinimapMouseDown(e: MouseEvent) {
  if (e.button !== 0 || !minimapSvgRef.value) return;
  e.stopPropagation();
  e.preventDefault();
  closeContextMenu();

  const rect = minimapSvgRef.value.getBoundingClientRect();
  const clickX = ((e.clientX - rect.left) / rect.width) * 200;
  const clickY = ((e.clientY - rect.top) / rect.height) * 120;

  const vf = minimapViewfinder.value;
  const inViewfinder =
    clickX >= vf.x &&
    clickX <= vf.x + vf.width &&
    clickY >= vf.y &&
    clickY <= vf.y + vf.height;

  if (!inViewfinder) {
    // 点击了取景框外部，直接将视野中心移动到点击位置
    panToMinimapPoint(clickX, clickY);
  }

  // 记录拖拽初始状态
  isDraggingMinimap.value = true;
  minimapDragStart.value = {
    clientX: e.clientX,
    clientY: e.clientY,
    initPanX: pan.value.x,
    initPanY: pan.value.y,
  };
}

// 节点点击交互
function handleNodeClick(node: LayoutNode, fromKeyboard = false) {
  if (hasDragged.value && !fromKeyboard) return;
  selectedNodeId.value = node.id;
  drawerVisible.value = true;
}

// 右键上下文菜单交互
function onNodeContextMenu(e: MouseEvent, node: LayoutNode) {
  e.preventDefault();
  e.stopPropagation();
  if (!canvasWrapRef.value) return;
  const rect = canvasWrapRef.value.getBoundingClientRect();
  contextMenu.value = {
    visible: true,
    x: Math.max(8, Math.min(e.clientX - rect.left, rect.width - 220)),
    y: Math.max(8, Math.min(e.clientY - rect.top, rect.height - 240)),
    node,
  };
}

function closeContextMenu() {
  contextMenu.value.visible = false;
}

// 聚焦同域名或同主机资产
function focusSameDomain(node: LayoutNode | null) {
  if (!node) return;
  if (focusedDomain.value === node.rootDomain) {
    focusedDomain.value = null;
    ElMessage.info("已取消聚焦");
  } else {
    focusedDomain.value = node.rootDomain;
    const desc = node.isIp ? `主机「${node.rootDomain}」` : `主域「${node.rootDomain}」`;
    ElMessage.success(`已聚焦${desc}关联资产`);
  }
  closeContextMenu();
}

// 聚光灯快速切换
function toggleSpotlight(type: string) {
  if (spotlightFilter.value === type) {
    spotlightFilter.value = null;
  } else {
    spotlightFilter.value = type;
    focusedDomain.value = null;
  }
}

// 导出拓扑为高清图片
async function exportTopologyImage() {
  if (!svgRef.value) return;
  let objectUrl: string | undefined;
  try {
    const svgEl = svgRef.value;
    const exportedSvg = svgEl.cloneNode(true) as SVGSVGElement;
    const originals = [svgEl, ...svgEl.querySelectorAll("*")];
    const copies = [exportedSvg, ...exportedSvg.querySelectorAll("*")];
    const styleProperties = [
      "fill", "fill-opacity", "stroke", "stroke-width", "stroke-opacity",
      "stroke-linecap", "stroke-dasharray", "opacity", "font-family",
      "font-size", "font-weight", "letter-spacing", "text-anchor",
    ];
    // Standalone SVG images cannot inherit the page's scoped styles or theme variables.
    originals.forEach((original, index) => {
      const style = getComputedStyle(original);
      const copy = copies[index] as SVGElement;
      for (const property of styleProperties) {
        const value = style.getPropertyValue(property);
        if (!value.includes("url(")) copy.style.setProperty(property, value);
      }
    });
    const svgData = new XMLSerializer().serializeToString(exportedSvg);
    const svgBlob = new Blob([svgData], { type: "image/svg+xml;charset=utf-8" });
    objectUrl = URL.createObjectURL(svgBlob);
    const img = new Image();
    img.src = objectUrl;
    await img.decode();
    const canvas = document.createElement("canvas");
    canvas.width = viewportWidth.value * 2;
    canvas.height = viewportHeight.value * 2;
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("Canvas unavailable");
    ctx.scale(2, 2);
    ctx.fillStyle = getComputedStyle(containerRef.value!).backgroundColor;
    ctx.fillRect(0, 0, viewportWidth.value, viewportHeight.value);
    ctx.drawImage(img, 0, 0);
    const a = document.createElement("a");
    a.download = `资产拓扑-${props.hubLabel}-${Date.now()}.png`;
    a.href = canvas.toDataURL("image/png");
    a.click();
    ElMessage.success("已导出拓扑图片");
  } catch {
    ElMessage.error("导出图片失败");
  } finally {
    if (objectUrl) URL.revokeObjectURL(objectUrl);
  }
}

// 删除节点
async function confirmRemoveNode(id: number, hostName?: string) {
  closeContextMenu();
  const target = props.assets.find((a) => a.id === id);
  const action = getAssetRemovalAction(target);
  if (!target || action === "none") {
    if (props.projectId === "all") {
      ElMessage.warning("全部项目总览仅支持查看，请进入具体项目后操作");
    } else if (getAssetKind(target) === "path") {
      ElMessage.info("测绘路径由系统自动维护，当前没有单条删除接口");
    } else {
      ElMessage.warning("该资产没有可用的后端记录，无法删除");
    }
    return;
  }

  const targetProjectId =
    typeof props.projectId === "number" ? props.projectId : target.projectId;
  if (!Number.isSafeInteger(targetProjectId)) {
    ElMessage.warning("无法确定资产所属项目");
    return;
  }

  if (action === "target") {
    const targetId = Number(target.targetId);
    if (!Number.isSafeInteger(targetId) || targetId <= 0) {
      ElMessage.warning("该授权目标缺少有效目标编号");
      return;
    }
    try {
      await ElMessageBox.confirm(
        `确定解除项目「${props.hubLabel || "当前项目"}」与目标「${hostName || "该目标"}」的授权绑定吗？`,
        "解除项目授权目标",
        {
          confirmButtonText: "解除绑定",
          cancelButtonText: "取消",
          type: "warning",
          confirmButtonClass: "el-button--danger",
        },
      );
      await endpoints.removeProjectTarget(targetProjectId, targetId);
      ElMessage.success("已解除项目授权目标");
      if (selectedNodeId.value === id) {
        drawerVisible.value = false;
        selectedNodeId.value = null;
      }
      emit("change");
    } catch (err: any) {
      if (err !== "cancel" && err !== "close") {
        ElMessage.error(err?.response?.data?.message || err?.message || "解除绑定失败");
      }
    }
    return;
  }

  const probeId = Number(target._probeResultId ?? target.id);
  if (!Number.isSafeInteger(probeId) || probeId <= 0) {
    ElMessage.info(
      "该资产没有可删除的探测记录，测绘路径由系统自动维护",
    );
    return;
  }
  try {
    await ElMessageBox.confirm(
      `确定要删除资产节点「${hostName || "该节点"}」对应的探测记录吗？`,
      "移除探测记录",
      {
        confirmButtonText: "确定移除",
        cancelButtonText: "取消",
        type: "warning",
        confirmButtonClass: "el-button--danger",
      },
    );
    await endpoints.deleteDiscoveryResult(targetProjectId, probeId);
    ElMessage.success("已成功删除资产节点");
    if (selectedNodeId.value === id) {
      drawerVisible.value = false;
      selectedNodeId.value = null;
    }
    emit("change");
  } catch (err: any) {
    if (err !== "cancel" && err !== "close") {
      ElMessage.error(err?.response?.data?.message || err?.message || "删除失败");
    }
  }
}

// 复制链接
async function copyUrl(url?: string) {
  closeContextMenu();
  if (!url) return;
  try {
    await navigator.clipboard.writeText(url);
    ElMessage.success("已复制资产 URL 到剪贴板");
  } catch {
    ElMessage.error("复制失败，请手动复制");
  }
}

// 规范化外部资产 URL (自动补全缺省协议，防止相对路由解析错误)
function normalizeAssetUrl(url?: string): string {
  if (!url) return "";
  const trimmed = url.trim();
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  const match = /^(https?:\/\/)([^/?#]*)([\s\S]*)$/i.exec(withScheme);
  if (!match) return withScheme;
  const [, scheme, authority, suffix] = match;
  const userInfoEnd = authority.lastIndexOf("@");
  const userInfo = userInfoEnd >= 0 ? authority.slice(0, userInfoEnd + 1) : "";
  const host = userInfoEnd >= 0 ? authority.slice(userInfoEnd + 1) : authority;
  if (host.startsWith("[") || (host.match(/:/g) || []).length < 2) {
    return withScheme;
  }
  return `${scheme}${userInfo}[${host}]${suffix}`;
}

// 在新窗口/系统默认外部浏览器打开资产
async function openAssetInNewWindow(url?: string) {
  closeContextMenu();
  if (!url) return;
  const targetUrl = normalizeAssetUrl(url);
  try {
    const desktop = (window as any).toolboxDesktop;
    if (desktop?.openExternal) {
      const opened = await desktop.openExternal(targetUrl);
      if (opened) return;
    }
  } catch {
    // fallback
  }
  window.open(targetUrl, "_blank", "noopener,noreferrer");
}

// 格式化证据 JSON
function formatEvidence(evidence: unknown): string {
  if (!evidence) return "";
  if (typeof evidence === "string") {
    try {
      const parsed = JSON.parse(evidence);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return evidence;
    }
  }
  return JSON.stringify(evidence, null, 2);
}

interface FingerprintItem {
  id?: string;
  name?: string;
  category?: string;
  confidence?: number;
  evidence?: string[];
}

interface ParsedEvidence {
  title?: string;
  status?: number | string;
  ruleCatalog?: {
    version?: string;
    ruleCount?: number;
  };
  fingerprints?: FingerprintItem[];
  headers?: string[];
}

const parsedEvidence = computed<ParsedEvidence | null>(() => {
  const raw = selectedAsset.value?.evidence || selectedAsset.value?.technologies;
  if (!raw) return null;
  if (typeof raw === "object") return raw as ParsedEvidence;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") return parsed as ParsedEvidence;
  } catch {
    return null;
  }
  return null;
});

async function copyEvidence() {
  const raw = selectedAsset.value?.evidence || selectedAsset.value?.technologies;
  if (!raw) return;
  const text = formatEvidence(raw);
  try {
    await navigator.clipboard.writeText(text);
    ElMessage.success("已复制证据数据");
  } catch {
    ElMessage.error("复制失败，请手动复制");
  }
}

// 全屏切换
async function toggleFullscreen() {
  if (!containerRef.value) return;
  try {
    if (!document.fullscreenElement) await containerRef.value.requestFullscreen();
    else await document.exitFullscreen();
  } catch {
    ElMessage.error("无法切换全屏视图");
  }
}

function onFullscreenChange() {
  isFullscreen.value = document.fullscreenElement === containerRef.value;
}

// 监听容器尺寸
function updateContainerSize() {
  if (canvasWrapRef.value) {
    viewportWidth.value = Math.max(1, canvasWrapRef.value.clientWidth);
    viewportHeight.value = Math.max(1, canvasWrapRef.value.clientHeight);
  }
}

let resizeObserver: ResizeObserver | null = null;
let positionSaveTimer: ReturnType<typeof setTimeout> | null = null;
watch([viewportWidth, viewportHeight], fitView, { flush: "post" });
watch(layoutMode, () => {
  // 切换布局模式按原有交互重置为自动布局，持久化随之清空。
  void resetView();
});
watch(() => props.projectId, () => {
  selectedNodeId.value = null;
  hoveredNodeId.value = null;
  drawerVisible.value = false;
  searchQuery.value = "";
  spotlightFilter.value = null;
  focusedDomain.value = null;
  closeContextMenu();
  customPositions.value =
    props.projectId != null ? loadNodePositions(props.projectId) : {};
  void fitView();
});
watch(() => props.assets.map((asset) => asset.id).join(","), () => {
  if (!props.assets.some((asset) => asset.id === selectedNodeId.value)) {
    selectedNodeId.value = null;
    drawerVisible.value = false;
  }
  void fitView();
}, { flush: "post" });

// 按项目防抖持久化节点自定义位置
watch(customPositions, () => {
  if (props.projectId == null) return;
  if (positionSaveTimer != null) clearTimeout(positionSaveTimer);
  positionSaveTimer = setTimeout(() => {
    saveNodePositions(props.projectId, customPositions.value);
  }, 300);
}, { deep: true });

// 全局偏好持久化
watch([layoutMode, enableFlowAnim, showMinimap], () => {
  saveGlobalPrefs({
    layoutMode: layoutMode.value,
    enableFlowAnim: enableFlowAnim.value,
    showMinimap: showMinimap.value,
  });
});

onMounted(() => {
  updateContainerSize();
  if (props.projectId != null) {
    customPositions.value = loadNodePositions(props.projectId);
  }
  if (canvasWrapRef.value && window.ResizeObserver) {
    resizeObserver = new ResizeObserver(() => {
      updateContainerSize();
    });
    resizeObserver.observe(canvasWrapRef.value);
  }
  document.addEventListener("fullscreenchange", onFullscreenChange);
  document.addEventListener("mousemove", onGlobalMouseMove);
  document.addEventListener("mouseup", onGlobalMouseUp);
});

onUnmounted(() => {
  if (positionSaveTimer != null) clearTimeout(positionSaveTimer);
  if (resizeObserver) {
    resizeObserver.disconnect();
  }
  document.removeEventListener("fullscreenchange", onFullscreenChange);
  document.removeEventListener("mousemove", onGlobalMouseMove);
  document.removeEventListener("mouseup", onGlobalMouseUp);
});
</script>

<template>
  <div
    ref="containerRef"
    class="asset-topology-container"
    :class="{ 'is-fullscreen': isFullscreen }"
    @click="closeContextMenu"
  >
    <!-- 顶部 Fluent CommandBar 控制栏 -->
    <header class="topology-toolbar fluent-command-bar">
      <div class="toolbar-left">
        <!-- 统计与聚光灯聚焦胶囊条 (Fluent 2 Filter Chips) -->
        <div class="stats-pills">
          <button
            type="button"
            class="stat-pill fluent-chip"
            :class="{ active: spotlightFilter === null && !focusedDomain }"
            :aria-pressed="spotlightFilter === null && !focusedDomain"
            @click="spotlightFilter = null; focusedDomain = null"
          >
            <span class="stat-dot dot-accent" />
            <span class="stat-label">全部资产</span>
            <span class="stat-badge">{{ stats.total }}</span>
          </button>

          <button
            type="button"
            class="stat-pill fluent-chip"
            :class="{ active: spotlightFilter === 'https' }"
            :aria-pressed="spotlightFilter === 'https'"
            @click="toggleSpotlight('https')"
          >
            <span class="stat-dot dot-success" />
            <span class="stat-label">HTTPS</span>
            <span class="stat-badge badge-success">{{ stats.httpsCount }}</span>
          </button>

          <button
            type="button"
            class="stat-pill fluent-chip"
            :class="{ active: spotlightFilter === 'http' }"
            :aria-pressed="spotlightFilter === 'http'"
            @click="toggleSpotlight('http')"
          >
            <span class="stat-dot dot-info" />
            <span class="stat-label">HTTP</span>
            <span class="stat-badge badge-info">{{ stats.httpCount }}</span>
          </button>

          <button
            type="button"
            v-if="stats.wafCount > 0"
            class="stat-pill fluent-chip"
            :class="{ active: spotlightFilter === 'waf' }"
            :aria-pressed="spotlightFilter === 'waf'"
            @click="toggleSpotlight('waf')"
          >
            <span class="stat-dot dot-warning" />
            <span class="stat-label">WAF</span>
            <span class="stat-badge badge-warning">{{ stats.wafCount }}</span>
          </button>

          <el-tag
            v-if="focusedDomain"
            size="small"
            closable
            class="focused-domain-tag fluent-tag"
            @close="focusedDomain = null"
          >
            {{ isFocusedDomainIp ? `聚焦主机: ${focusedDomain}` : `聚焦主域: ${focusedDomain}` }}
          </el-tag>
        </div>
        <div class="toolbar-meta-group">
          <div class="host-meta-badge" title="当前拓扑覆盖独立主机数">
            <FluentIcon name="server" :size="12" />
            <span>{{ stats.uniqueHosts }} 个主机</span>
          </div>
          <div v-if="props.projectId === 'all'" class="host-meta-badge" title="当前拓扑覆盖项目数">
            <FluentIcon name="folder" :size="12" />
            <span>{{ layoutData.hubs.length }} 个项目</span>
          </div>
        </div>
      </div>

      <div class="toolbar-center">
        <el-input
          v-model="searchQuery"
          placeholder="搜索域名、服务或技术栈"
          aria-label="搜索资产"
          clearable
          size="small"
          class="topology-search-input fluent-input"
        >
          <template #prefix>
            <FluentIcon name="search" :size="14" />
          </template>
        </el-input>
      </div>

      <div class="toolbar-right">
        <!-- Fluent 2 标准分段控件 (Segmented Control) -->
        <div class="fluent-segmented-control" role="tablist" aria-label="布局模式">
          <button
            type="button"
            role="tab"
            class="segmented-item"
            :class="{ 'is-active': layoutMode === 'tree' }"
            :aria-selected="layoutMode === 'tree'"
            title="树状拓扑布局"
            @click="layoutMode = 'tree'"
          >
            <FluentIcon name="branch-fork" :size="13" />
            <span>树状</span>
          </button>
          <button
            type="button"
            role="tab"
            class="segmented-item"
            :class="{ 'is-active': layoutMode === 'orbit' }"
            :aria-selected="layoutMode === 'orbit'"
            title="环轨拓扑布局"
            @click="layoutMode = 'orbit'"
          >
            <FluentIcon name="globe" :size="13" />
            <span>环轨</span>
          </button>
          <button
            type="button"
            role="tab"
            class="segmented-item"
            :class="{ 'is-active': layoutMode === 'mindmap' }"
            :aria-selected="layoutMode === 'mindmap'"
            title="思维导图布局"
            @click="layoutMode = 'mindmap'"
          >
            <FluentIcon name="diagram" :size="13" />
            <span>导图</span>
          </button>
        </div>

        <el-popover placement="bottom-end" :width="208" trigger="click" :teleported="!isFullscreen">
          <template #reference>
            <button class="fluent-command-btn" title="视图选项" aria-label="视图选项">
              <FluentIcon name="settings" />
            </button>
          </template>
          <div class="view-options">
            <el-checkbox v-model="enableFlowAnim">连接动画</el-checkbox>
            <el-checkbox v-model="showMinimap">显示缩略图</el-checkbox>
            <div class="menu-divider" />
            <button class="view-option-action" @click="resetView">
              <FluentIcon name="arrow-reset" /> 重置节点位置
            </button>
            <button class="view-option-action" :disabled="!assets.length" @click="exportTopologyImage">
              <FluentIcon name="arrow-download" /> 导出 PNG
            </button>
          </div>
        </el-popover>

        <!-- 全屏模式 -->
        <button
          class="fluent-command-btn"
          :title="isFullscreen ? '退出全屏' : '全屏模式'"
          :aria-label="isFullscreen ? '退出全屏' : '全屏模式'"
          @click="toggleFullscreen"
        >
          <FluentIcon :name="isFullscreen ? 'fullscreen-exit' : 'fullscreen'" :size="14" />
        </button>
      </div>
    </header>

    <!-- 主画布区域 -->
    <div
      ref="canvasWrapRef"
      class="topology-canvas-wrap"
      :class="{
        'cursor-grab': !isDraggingCanvas && draggingNodeId == null,
        'cursor-grabbing': isDraggingCanvas || draggingNodeId != null,
      }"
      @wheel="onWheel"
      @mousedown="onCanvasMouseDown"
      @dblclick="fitView"
    >
      <!-- 加载遮罩 -->
      <div v-if="loading" class="topology-state-overlay">
        <el-icon class="is-loading" :size="24"><FluentIcon name="arrow-clockwise" /></el-icon>
        <span class="state-copy">正在加载资产…</span>
      </div>

      <!-- 空数据提示 -->
      <div v-else-if="!assets.length" class="topology-state-overlay">
        <div class="empty-icon-wrap">
          <FluentIcon name="globe-search" :size="36" />
        </div>
        <h4>暂无资产节点</h4>
        <p>{{ props.projectId === 'all' ? '全部项目暂无资产记录' : '当前项目暂无资产记录' }}</p>
      </div>

      <!-- SVG 拓扑网络画布 -->
      <svg
        v-else
        ref="svgRef"
        class="topology-svg"
        :width="viewportWidth"
        :height="viewportHeight"
      >
        <defs>
          <!-- 背景网格点阵 -->
          <pattern
            id="dotGrid"
            width="24"
            height="24"
            patternUnits="userSpaceOnUse"
          >
            <circle cx="12" cy="12" r="0.8" fill="var(--app-border, #d8dadd)" opacity="0.45" />
          </pattern>

          <!-- 画布中心柔和科技纵深环境光 (内聚低饱和度，不抢占主体视觉) -->
          <radialGradient id="centerAmbientGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#0078d4" stop-opacity="0.05" />
            <stop offset="50%" stop-color="#0078d4" stop-opacity="0.015" />
            <stop offset="100%" stop-color="#0078d4" stop-opacity="0" />
          </radialGradient>

          <!-- 现代卡片微阴影 -->
          <filter id="nodeCardShadow" x="-20%" y="-25%" width="140%" height="155%">
            <feDropShadow dx="0" dy="1" stdDeviation="2" flood-color="#0f172a" flood-opacity="0.05" />
            <feDropShadow dx="0" dy="3" stdDeviation="6" flood-color="#0f172a" flood-opacity="0.04" />
          </filter>

          <!-- 现代卡片悬停微阴影 -->
          <filter id="nodeCardHoverShadow" x="-25%" y="-30%" width="150%" height="165%">
            <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#0f172a" flood-opacity="0.08" />
            <feDropShadow dx="0" dy="6" stdDeviation="12" flood-color="#0f172a" flood-opacity="0.06" />
          </filter>

          <!-- 节点选中态柔和微光光晕阴影 (Fluent Selection Halo) -->
          <filter id="nodeCardSelectedShadow" x="-30%" y="-35%" width="160%" height="175%">
            <feDropShadow dx="0" dy="0" stdDeviation="2.5" flood-color="#0078d4" flood-opacity="0.45" />
            <feDropShadow dx="0" dy="3" stdDeviation="8" flood-color="#0078d4" flood-opacity="0.2" />
            <feDropShadow dx="0" dy="1" stdDeviation="2" flood-color="#0f172a" flood-opacity="0.06" />
          </filter>

          <!-- 中心指挥核心深邃立体阴影 -->
          <filter id="hubCardShadow" x="-20%" y="-25%" width="140%" height="160%">
            <feDropShadow dx="0" dy="3" stdDeviation="7" flood-color="#0078d4" flood-opacity="0.16" />
            <feDropShadow dx="0" dy="1" stdDeviation="2" flood-color="#0f172a" flood-opacity="0.06" />
          </filter>

          <!-- 中心节点品牌徽章统一渐变 (Fluent Communication Blue) -->
          <linearGradient id="hubIconGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#0078d4" />
            <stop offset="100%" stop-color="#005a9e" />
          </linearGradient>

          <!-- HTTPS 绿色品牌渐变 -->
          <linearGradient id="httpsGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#168b48" />
            <stop offset="100%" stop-color="#0f6d37" />
          </linearGradient>

          <!-- HTTP 蓝色品牌渐变 -->
          <linearGradient id="httpGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#2d8fd5" />
            <stop offset="100%" stop-color="#1867a5" />
          </linearGradient>
        </defs>

        <!-- 底层实心纯色背景与网格点阵 (杜绝全屏下透出底层暗色) -->
        <rect width="100%" height="100%" fill="var(--app-surface-strong, #ffffff)" pointer-events="none" />
        <rect width="100%" height="100%" fill="url(#dotGrid)" pointer-events="none" />

        <!-- 缩放与平移视口容器 -->
        <g
          class="topology-scene"
          :transform="`translate(${pan.x}, ${pan.y}) scale(${zoom})`"
        >
          <!-- 画布各中心节点柔和纵深微光 (紧密内聚在中心卡片周围，不向外漫散) -->
          <ellipse
            v-for="hub in layoutData.hubs"
            :key="`ambient-${hub.id}`"
            :cx="hub.x"
            :cy="hub.y"
            :rx="HUB_W * 0.85"
            :ry="HUB_H * 1.15"
            fill="url(#centerAmbientGlow)"
            pointer-events="none"
          />

          <!-- 环轨背景同心线 (仅在环轨模式展示，提供优雅纵深感) -->
          <g v-if="layoutMode === 'orbit'" class="orbit-rings-layer" pointer-events="none">
            <ellipse
              v-for="(ring, rIdx) in orbitRings"
              :key="`ring-${rIdx}`"
              :cx="cx"
              :cy="cy"
              :rx="ring.rx"
              :ry="ring.ry"
              class="orbit-guide-circle"
              :class="{ 'is-dashed': rIdx > 0 }"
            />
          </g>

          <!-- ==================== 图层 0.6: 同主域半透明聚类围栏 (Grouping Enclosures) ==================== -->
          <g v-if="layoutMode !== 'orbit'" class="topology-clusters" pointer-events="none">
            <g
              v-for="cluster in clusterEnclosures"
              :key="`cluster-${cluster.domain}`"
              class="cluster-group"
              :class="{
                'is-dimmed': !cluster.isMatch,
                'is-focused': focusedDomain === cluster.domain,
              }"
            >
              <!-- 半透明气泡底板 -->
              <rect
                :x="cluster.x"
                :y="cluster.y"
                :width="cluster.width"
                :height="cluster.height"
                rx="14"
                class="cluster-rect"
              />
              <!-- 左上角主域胶囊标签 (支持点击聚焦) -->
              <g
                :transform="`translate(${cluster.x + 14}, ${cluster.y - 11})`"
                pointer-events="all"
                class="cluster-label-chip"
                @click.stop="focusedDomain = focusedDomain === cluster.domain ? null : cluster.domain"
              >
                <rect
                  x="0"
                  y="0"
                  :width="cluster.labelWidth"
                  height="22"
                  rx="5"
                  class="cluster-label-bg"
                />
                <text
                  :x="cluster.labelWidth / 2"
                  y="14.5"
                  class="cluster-label-text"
                  text-anchor="middle"
                >
                  {{ cluster.domain }} · {{ cluster.nodeCount }} 资产
                </text>
              </g>
            </g>
          </g>

          <!-- ==================== 图层 1: 连线图层 (真实端点物理接驳) ==================== -->
          <g class="topology-edges" pointer-events="none">
            <g
              v-for="edge in layoutData.edges"
              :key="edge.id"
              class="edge-group"
              :class="{
                'is-hovered': hoveredNodeId === edge.targetId,
                'is-selected': selectedNodeId === edge.targetId,
                'is-flowing': enableFlowAnim,
                'is-dimmed': typeof edge.targetId === 'number' && !matchedNodeIds.has(edge.targetId),
              }"
            >
              <!-- 基础连线与光效连线 -->
              <path :d="edge.path" class="edge-base-line" />
              <path v-if="enableFlowAnim" :d="edge.path" class="edge-flow-line" />

              <!-- 起止物理接驳端点 (Connection Ports)，消除假连感！ -->
              <circle :cx="edge.x2" :cy="edge.y2" r="3" class="edge-port-dot port-target" />
            </g>
          </g>

          <!-- ==================== 图层 2: 中心项目核心 (Fluent Command Hub Cards) ==================== -->
          <g
            v-for="hub in layoutData.hubs"
            :key="hub.id"
            class="topology-hub-node"
            :class="{ 'is-custom-dragged': customPositions[hub.id] != null }"
            :transform="`translate(${hub.x}, ${hub.y})`"
            @mouseenter="hoveredNodeId = null"
            @mousedown="onHubMouseDown($event, hub)"
          >
            <!-- 外部柔和呼吸微光光晕 (使用各自主题的主题色) -->
            <rect
              :x="-HUB_W / 2 - 3"
              :y="-HUB_H / 2 - 3"
              :width="HUB_W + 6"
              :height="HUB_H + 6"
              rx="10"
              class="hub-card-halo"
              :style="{ fill: hub.theme.haloColor }"
              pointer-events="none"
            />

            <!-- 主卡片背景 (不透明实心遮盖底层连线) -->
            <rect
              :x="-HUB_W / 2"
              :y="-HUB_H / 2"
              :width="HUB_W"
              :height="HUB_H"
              rx="8"
              class="hub-card-bg"
              filter="url(#hubCardShadow)"
            />

            <!-- 左侧品牌色图标底座 (36x36 渐变圆角底座) -->
            <g :transform="`translate(${-HUB_W / 2 + 12}, -18)`" pointer-events="none">
              <rect
                x="0"
                y="0"
                width="36"
                height="36"
                rx="8"
                class="hub-icon-base"
                fill="url(#hubIconGrad)"
              />
              <!-- 微软官方 Fluent System Icon: 官方矢量路径 -->
              <svg x="6" y="6" width="24" height="24" viewBox="0 0 24 24">
                <path
                  :d="hub.theme.iconPath"
                  fill="#ffffff"
                />
              </svg>
            </g>

            <!-- 右侧文字区域：垂直分层，字阶疏朗 -->
            <g :transform="`translate(${-HUB_W / 2 + 58}, 0)`" pointer-events="none">
              <title>{{ hub.name }}</title>
              <!-- 第一行：项目名称 -->
              <text y="-5" class="hub-title-text" text-anchor="start">
                {{ compactLabel(hub.name, 18) }}
              </text>

              <!-- 第二行：状态微标与资产计数 -->
              <g transform="translate(0, 15)">
                <circle cx="4" cy="-3.5" r="3.5" class="hub-status-dot" :style="{ fill: hub.theme.gradStart }" />
                <text x="13" y="0" class="hub-subtitle-text" text-anchor="start">
                  {{ hub.assetCount }} 资产 · {{ hub.hostCount }} 主机
                </text>
              </g>
            </g>
          </g>

          <!-- ==================== 图层 2.5: 思维导图主域分支中继胶囊 (仅导图模式) ==================== -->
          <g v-if="layoutMode === 'mindmap'" class="topology-domain-branches">
            <g
              v-for="dNode in layoutData.domainNodes"
              :key="dNode.id"
              class="domain-branch-group"
              :class="{
                'is-dimmed': !dNode.isMatch,
                'is-focused': focusedDomain === dNode.domain,
              }"
              :transform="`translate(${dNode.x}, ${dNode.y})`"
              role="button"
              tabindex="0"
              @click.stop="focusedDomain = focusedDomain === dNode.domain ? null : dNode.domain"
            >
              <title>{{ dNode.isIp ? `主机: ${dNode.domain}` : `主域: ${dNode.domain}` }} ({{ dNode.nodeCount }} 资产，点击聚焦)</title>
              <!-- 分支胶囊背景 -->
              <rect
                :x="-dNode.w / 2"
                :y="-dNode.h / 2"
                :width="dNode.w"
                :height="dNode.h"
                rx="17"
                class="domain-branch-bg"
              />
              <!-- 导图小图标 -->
              <g :transform="`translate(${-dNode.w / 2 + 10}, -8)`">
                <circle cx="8" cy="8" r="8" class="domain-icon-dot" />
                <svg x="2" y="2" width="12" height="12" viewBox="0 0 24 24" fill="none">
                  <path
                    v-if="dNode.isIp"
                    d="M4 5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5Zm2-.5a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h12a.5.5 0 0 0 .5-.5V5a.5.5 0 0 0-.5-.5H6Zm-2 9.5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-3Zm2-.5a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h12a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5H6Z"
                    class="glyph-fill"
                  />
                  <path
                    v-else
                    d="M12 2a10 10 0 1 1 0 20 10 10 0 0 1 0-20Zm2.94 14.5H9.06c.65 2.41 1.79 4 2.94 4s2.29-1.59 2.94-4Zm-7.43 0H4.79a8.53 8.53 0 0 0 4.09 3.41c-.52-.82-.95-1.85-1.27-3.02l-.1-.39Zm11.7 0H16.5c-.32 1.33-.79 2.5-1.37 3.41a8.53 8.53 0 0 0 3.9-3.13l.2-.28ZM7.1 10H3.74v.02a8.52 8.52 0 0 0 .3 4.98h3.18a20.3 20.3 0 0 1-.13-5Zm8.3 0H8.6a18.97 18.97 0 0 0 .14 5h6.52a18.5 18.5 0 0 0 .14-5Zm4.87 0h-3.35a20.85 20.85 0 0 1-.13 5h3.18a8.48 8.48 0 0 0 .3-5Z"
                    class="glyph-fill"
                  />
                </svg>
              </g>
              <!-- 主域 / 主机名称 -->
              <text
                :x="-dNode.w / 2 + 32"
                y="4"
                class="domain-branch-title"
                text-anchor="start"
              >
                {{ compactLabel(dNode.domain, 18) }}
              </text>
              <!-- 数量徽标 -->
              <rect
                :x="dNode.w / 2 - 28"
                y="-9"
                width="20"
                height="18"
                rx="9"
                class="domain-branch-count-bg"
              />
              <text
                :x="dNode.w / 2 - 18"
                y="3.5"
                class="domain-branch-count"
                text-anchor="middle"
              >
                {{ dNode.nodeCount }}
              </text>
            </g>
          </g>

          <!-- ==================== 图层 3: 资产节点卡片列表 (Fluent Asset Cards) ==================== -->
          <g class="topology-nodes">
            <g
              v-for="node in layoutData.nodes"
              :key="node.id"
              class="node-card-group"
              :class="{
                'is-dimmed': !node.isMatch,
                'is-hovered': hoveredNodeId === node.id,
                'is-selected': selectedNodeId === node.id,
                'is-custom-dragged': customPositions[node.id] != null,
              }"
              role="button"
              tabindex="0"
              :aria-label="node.asset.url || node.host"
              :transform="`translate(${node.x}, ${node.y})`"
              @mouseenter="hoveredNodeId = node.id"
              @mouseleave="hoveredNodeId = null"
              @mousedown="onNodeMouseDown($event, node)"
              @click.stop="handleNodeClick(node)"
              @keydown.enter.prevent="handleNodeClick(node, true)"
              @keydown.space.prevent="handleNodeClick(node, true)"
              @contextmenu="onNodeContextMenu($event, node)"
            >
              <title>{{ node.asset.url || node.host }}</title>
              <!-- 实心卡片背景 (立体浮起微投影，高危漏洞红光晕，风险橙光晕) -->
              <rect
                :x="-CARD_W / 2"
                :y="-CARD_H / 2"
                :width="CARD_W"
                :height="CARD_H"
                rx="8"
                class="node-card-bg"
                :class="{
                  'card--has-vuln': node.vulnCount > 0,
                  'card--has-risk': node.riskCount > 0 && node.vulnCount === 0,
                }"
                :filter="selectedNodeId === node.id ? 'url(#nodeCardSelectedShadow)' : hoveredNodeId === node.id ? 'url(#nodeCardHoverShadow)' : 'url(#nodeCardShadow)'"
              />

              <!-- 右上角态势徽标 (宽度随计数增长，使用 Fluent 图形而非 emoji) -->
              <g
                v-if="node.vulnCount > 0"
                :transform="`translate(${CARD_W / 2 - statusBadgeWidth(node) - 8}, ${-CARD_H / 2 + 7})`"
              >
                <rect
                  x="0"
                  y="0"
                  :width="statusBadgeWidth(node)"
                  height="18"
                  rx="4"
                  class="node-badge-bg badge--vuln"
                />
                <svg x="5" y="1" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
                  <path
                    d="M8.35 2.15a.5.5 0 0 0-.7 0A5.72 5.72 0 0 1 3.5 4a.5.5 0 0 0-.5.5v3c0 3.22 1.64 5.4 4.84 6.47.1.04.22.04.32 0C11.36 12.91 13 10.72 13 7.5v-3a.5.5 0 0 0-.5-.5c-1.53 0-2.9-.61-4.15-1.85ZM4 4.98a6.65 6.65 0 0 0 4-1.8 6.64 6.64 0 0 0 4 1.8V7.5c0 1.43-.36 2.57-1.02 3.45A6.13 6.13 0 0 1 8 12.97a6.13 6.13 0 0 1-2.98-2.02A5.57 5.57 0 0 1 4 7.5V4.98Zm4.5.52a.5.5 0 0 0-1 0v3a.5.5 0 0 0 1 0v-3Zm.25 5.25a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0Z"
                    class="node-badge-icon"
                  />
                </svg>
                <text x="23" y="12.5" text-anchor="start" class="node-badge-text">
                  {{ node.vulnCount }} 漏洞
                </text>
              </g>
              <g
                v-else-if="node.riskCount > 0"
                :transform="`translate(${CARD_W / 2 - statusBadgeWidth(node) - 8}, ${-CARD_H / 2 + 7})`"
              >
                <rect
                  x="0"
                  y="0"
                  :width="statusBadgeWidth(node)"
                  height="18"
                  rx="4"
                  class="node-badge-bg badge--risk"
                />
                <svg x="5" y="1" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
                  <path
                    d="M5.82 2.28a2.5 2.5 0 0 1 4.36 0l4.5 8A2.5 2.5 0 0 1 12.5 14h-9a2.5 2.5 0 0 1-2.18-3.72l4.5-8Zm3.49.48a1.5 1.5 0 0 0-2.62 0l-4.5 8a1.5 1.5 0 0 0 1.31 2.24h9a1.5 1.5 0 0 0 1.3-2.23l-4.5-8ZM8 9.5A.75.75 0 1 1 8 11a.75.75 0 0 1 0-1.5ZM8 5c.28 0 .5.22.5.5V8a.5.5 0 0 1-1 0V5.5c0-.28.22-.5.5-.5Z"
                    class="node-badge-icon"
                  />
                </svg>
                <text x="23" y="12.5" text-anchor="start" class="node-badge-text">
                  {{ node.riskCount }} 风险
                </text>
              </g>
              <g
                v-else
                :transform="`translate(${CARD_W / 2 - statusBadgeWidth(node) - 8}, ${-CARD_H / 2 + 7})`"
              >
                <rect
                  x="0"
                  y="0"
                  :width="statusBadgeWidth(node)"
                  height="18"
                  rx="4"
                  class="node-badge-bg badge--safe"
                />
                <svg x="5" y="1" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
                  <path
                    d="M2 8a6 6 0 1 1 12 0A6 6 0 0 1 2 8Zm6-7a7 7 0 1 0 0 14A7 7 0 0 0 8 1Zm2.85 5.85a.5.5 0 0 0-.7-.7l-2.9 2.9-1.4-1.4a.5.5 0 1 0-.7.7L6.9 10.1c.2.2.5.2.7 0l3.25-3.25Z"
                    class="node-badge-icon"
                  />
                </svg>
                <text x="23" y="12.5" text-anchor="start" class="node-badge-text">安全</text>
              </g>

              <!-- 自定义位置图钉指示微点 -->
              <circle
                v-if="customPositions[node.id] != null"
                :cx="CARD_W / 2 - 10"
                :cy="-CARD_H / 2 + 10"
                r="3"
                class="node-pinned-indicator"
              >
                <title>已自定义摆放位置</title>
              </circle>

              <!-- 左侧协议微图标区 (官方 @fluentui/svg-icons 系统图标) -->
              <g :transform="`translate(${-CARD_W / 2 + 12}, -14)`">
                <rect
                  x="0"
                  y="0"
                  width="28"
                  height="28"
                  rx="6"
                  :class="['node-icon-box', `box-${node.protocol}`]"
                />
                <!-- HTTPS: 官方 lock_closed_24_regular 矢量图标 -->
                <svg
                  v-if="node.protocol === 'https'"
                  x="5"
                  y="5"
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  class="icon-glyph-https"
                >
                  <path
                    d="M12 1a5 5 0 0 1 5 5v2.01c1.68.13 3 1.53 3 3.24v7.5c0 1.8-1.46 3.25-3.25 3.25h-9.5A3.25 3.25 0 0 1 4 18.75v-7.5a3.25 3.25 0 0 1 3-3.24V6a5 5 0 0 1 5-5ZM7.25 9.5c-.97 0-1.75.78-1.75 1.75v7.5c0 .97.78 1.75 1.75 1.75h9.5c.97 0 1.75-.78 1.75-1.75v-7.5c0-.97-.78-1.75-1.75-1.75h-9.5ZM12 13.75a1.25 1.25 0 1 1 0 2.5 1.25 1.25 0 0 1 0-2.5ZM12 2.5A3.5 3.5 0 0 0 8.5 6v2h7V6A3.5 3.5 0 0 0 12 2.5Z"
                    class="glyph-fill"
                  />
                </svg>
                <!-- HTTP: 官方 globe_24_regular 矢量图标 (彻底废除无语义实心白圆点) -->
                <svg
                  v-else
                  x="5"
                  y="5"
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  class="icon-glyph-http"
                >
                  <path
                    d="M12 2a10 10 0 1 1 0 20 10 10 0 0 1 0-20Zm2.94 14.5H9.06c.65 2.41 1.79 4 2.94 4s2.29-1.59 2.94-4Zm-7.43 0H4.79a8.53 8.53 0 0 0 4.09 3.41c-.52-.82-.95-1.85-1.27-3.02l-.1-.39Zm11.7 0H16.5c-.32 1.33-.79 2.5-1.37 3.41a8.53 8.53 0 0 0 3.9-3.13l.2-.28ZM7.1 10H3.74v.02a8.52 8.52 0 0 0 .3 4.98h3.18a20.3 20.3 0 0 1-.13-5Zm8.3 0H8.6a18.97 18.97 0 0 0 .14 5h6.52a18.5 18.5 0 0 0 .14-5Zm4.87 0h-3.35a20.85 20.85 0 0 1-.13 5h3.18a8.48 8.48 0 0 0 .3-5ZM8.88 4.09h-.02a8.53 8.53 0 0 0-4.61 4.4l3.05.01c.31-1.75.86-3.28 1.58-4.41Zm3.12-.6-.12.01c-1.26.12-2.48 2.12-3.05 5h6.34c-.56-2.87-1.78-4.87-3.04-5H12Zm3.12.6.1.17A12.64 12.64 0 0 1 16.7 8.5h3.05a8.53 8.53 0 0 0-4.34-4.29l-.29-.12Z"
                    class="glyph-fill"
                  />
                </svg>
              </g>

              <!-- 右侧文字排版区域 (左对齐，层级分明，不与图标或连线挤压) -->
              <g :transform="`translate(${-CARD_W / 2 + 48}, 0)`">
                <!-- 第一行：URL 路径（若有）或 主机名 / 域名 (主标题，字号清晰，留足显示空间) -->
                <text
                  y="-5"
                  class="node-title-text"
                  text-anchor="start"
                >
                  {{ node.urlPath ? compactLabel(node.urlPath, 16) : compactLabel(node.host, 16) }}
                </text>

                <!-- 第二行：标签微徽标组 (Fluent 2 标准字阶与留白) -->
                <g transform="translate(0, 14)">
                  <!-- 标签 1 (URL 或 协议) -->
                  <g v-if="node.urlPath" transform="translate(0, 0)">
                    <rect x="0" y="-8.5" width="38" height="17" rx="3.5" class="node-tag-bg tag-url" />
                    <text x="19" y="3.5" text-anchor="middle" class="node-tag-text">URL</text>
                  </g>
                  <g v-else-if="node.badges[0]" transform="translate(0, 0)">
                    <rect x="0" y="-8.5" width="44" height="17" rx="3.5" class="node-tag-bg tag-protocol" />
                    <text x="22" y="3.5" text-anchor="middle" class="node-tag-text">{{ node.badges[0] }}</text>
                  </g>
                  <!-- 标签 2 (主机或服务) -->
                  <g v-if="node.urlPath" transform="translate(42, 0)">
                    <rect x="0" y="-8.5" width="76" height="17" rx="3.5" class="node-tag-bg tag-generic" />
                    <text x="38" y="3.5" text-anchor="middle" class="node-tag-text">{{ compactLabel(node.host, 10) }}</text>
                  </g>
                  <g v-else-if="node.badges[1]" transform="translate(48, 0)">
                    <rect
                      x="0"
                      y="-8.5"
                      :width="node.badges[1].length > 5 ? 54 : 42"
                      height="17"
                      rx="3.5"
                      :class="['node-tag-bg', node.badges[1] === 'WAF' ? 'tag-waf' : 'tag-generic']"
                    />
                    <text
                      :x="node.badges[1].length > 5 ? 27 : 21"
                      y="3.5"
                      text-anchor="middle"
                      class="node-tag-text"
                    >
                      {{ node.badges[1].slice(0, 6) }}
                    </text>
                  </g>
                </g>
              </g>

            </g>
          </g>
        </g>
      </svg>

      <div v-if="assets.length" class="canvas-controls" @mousedown.stop @dblclick.stop @wheel.stop>
        <div class="zoom-controls">
          <button class="fluent-command-btn" title="缩小" aria-label="缩小" @click="zoomOut">
            <FluentIcon name="subtract" />
          </button>
          <span class="zoom-level">{{ Math.round(zoom * 100) }}%</span>
          <button class="fluent-command-btn" title="放大" aria-label="放大" @click="zoomIn">
            <FluentIcon name="add" />
          </button>
          <span class="divider-v" />
          <button class="fluent-command-btn" title="适应画布" aria-label="适应画布" @click="fitView">
            <FluentIcon name="fit" />
          </button>
        </div>
      </div>

      <!-- 鹰眼雷达微型小地图 (Fluent Overlay) -->
      <div v-if="showMinimap && assets.length > 0" class="topology-minimap" @dblclick.stop @wheel.stop>
        <div class="minimap-header">
          <span>缩略图</span>
          <button class="minimap-close" title="隐藏缩略图" aria-label="隐藏缩略图" @click="showMinimap = false"><FluentIcon name="dismiss" /></button>
        </div>
        <div class="minimap-body">
          <svg
            ref="minimapSvgRef"
            viewBox="0 0 200 120"
            class="minimap-svg"
            :class="{ 'is-dragging': isDraggingMinimap }"
            @mousedown="onMinimapMouseDown"
          >
            <!-- 视口取景框 (置于底层，半透明高亮展示当前视野范围) -->
            <rect
              :x="minimapViewfinder.x"
              :y="minimapViewfinder.y"
              :width="minimapViewfinder.width"
              :height="minimapViewfinder.height"
              class="minimap-viewfinder"
            />
            <!-- 中心宿主小方块群 (置于取景框上方) -->
            <rect
              v-for="hub in layoutData.hubs"
              :key="`mini-${hub.id}`"
              :x="minimapTransform.x + hub.x * minimapTransform.scale - 5"
              :y="minimapTransform.y + hub.y * minimapTransform.scale - 5"
              width="10"
              height="10"
              rx="2"
              :fill="hub.theme.shadowColor"
            />
            <!-- 导图分支中继微点 (仅在导图模式呈现) -->
            <rect
              v-for="dNode in layoutData.domainNodes"
              :key="`mini-${dNode.id}`"
              :x="minimapTransform.x + dNode.x * minimapTransform.scale - 3"
              :y="minimapTransform.y + dNode.y * minimapTransform.scale - 2"
              width="6"
              height="4"
              rx="1.5"
              fill="#64748b"
              :opacity="dNode.isMatch ? 0.8 : 0.3"
            />
            <!-- 节点微点 (置于最顶层，带清晰外边框，绝不被任何色块遮挡) -->
            <circle
              v-for="node in layoutData.nodes"
              :key="`mini-${node.id}`"
              :cx="minimapTransform.x + node.x * minimapTransform.scale"
              :cy="minimapTransform.y + node.y * minimapTransform.scale"
              r="2.5"
              :fill="node.protocol === 'https' ? '#107c41' : 'var(--app-accent, #0078d4)'"
              stroke="#ffffff"
              stroke-width="0.6"
              :opacity="node.isMatch ? 0.95 : 0.35"
            />
          </svg>
        </div>
      </div>

      <!-- 右键上下文快捷菜单 (Fluent Flyout) -->
      <div
        v-if="contextMenu.visible && contextMenu.node"
        class="topology-context-menu fluent-flyout"
        :style="{ left: `${contextMenu.x}px`, top: `${contextMenu.y}px` }"
        @click.stop
        @mousedown.stop
      >
        <div class="menu-header">
          <span class="menu-host">{{ contextMenu.node.host }}</span>
        </div>
        <div class="menu-item fluent-menu-item" @click="handleNodeClick(contextMenu.node!, true)">
          <FluentIcon name="eye" :size="14" />
          <span>查看资产详情</span>
        </div>
        <div
          v-if="contextMenu.node.asset.url"
          class="menu-item fluent-menu-item"
          @click="copyUrl(contextMenu.node!.asset.url)"
        >
          <FluentIcon name="copy" :size="14" />
          <span>复制完整 URL</span>
        </div>
        <div class="menu-item fluent-menu-item" @click="focusSameDomain(contextMenu.node)">
          <FluentIcon name="target" :size="14" />
          <span>{{ focusedDomain === contextMenu.node.rootDomain ? '取消聚焦' : contextMenu.node.isIp ? '仅聚焦该主机资产' : '仅聚焦同主域资产' }}</span>
        </div>
        <div
          v-if="contextMenu.node.asset.url"
          class="menu-item fluent-menu-item link-item"
          @click="openAssetInNewWindow(contextMenu.node!.asset.url)"
        >
          <FluentIcon name="globe" :size="14" />
          <span>在新窗口打开</span>
        </div>
        <div class="menu-divider fluent-divider" />
        <div
          class="menu-item fluent-menu-item text-danger"
          @click="confirmRemoveNode(contextMenu.node!.id, contextMenu.node!.host)"
        >
          <FluentIcon name="delete" :size="14" />
          <span>{{ assetRemovalLabel(contextMenu.node.asset) }}</span>
        </div>
      </div>
    </div>

    <!-- 资产深度详情抽屉 (Fluent Drawer) -->
    <el-drawer
      v-model="drawerVisible"
      title="资产详情"
      size="min(420px, 100vw)"
      direction="rtl"
      :append-to-body="!isFullscreen"
      custom-class="asset-detail-drawer"
    >
      <div v-if="selectedAsset" class="drawer-body">
        <!-- 资产头部概览卡片 -->
        <div class="asset-hero-card fluent-hero">
          <div class="hero-icon-box">
            <FluentIcon
              :name="parseHost(selectedAsset.url).protocol === 'https' ? 'shield-checkmark' : 'globe'"
              :size="26"
            />
          </div>
          <div class="hero-info">
            <h3 class="hero-host">{{ parseHost(selectedAsset.url).host }}</h3>
            <div class="hero-tags">
              <el-tag size="small" effect="light" type="primary">
                {{ parseHost(selectedAsset.url).protocol.toUpperCase() }}
              </el-tag>
              <el-tag
                v-if="isWebPathAsset(selectedAsset)"
                size="small"
                effect="plain"
                type="success"
              >
                Web 路径资产
              </el-tag>
              <el-tag
                v-if="selectedNodeFindings.filter(findingIsVulnerability).length > 0"
                size="small"
                effect="dark"
                type="danger"
              >
                <FluentIcon name="shield" />
                {{ selectedNodeFindings.filter(findingIsVulnerability).length }} 漏洞
              </el-tag>
              <el-tag
                v-else-if="selectedNodeFindings.length > 0"
                size="small"
                effect="plain"
                type="warning"
              >
                <FluentIcon name="warning" />
                {{ selectedNodeFindings.length }} 风险
              </el-tag>
              <el-tag
                v-else
                size="small"
                effect="plain"
                type="success"
              >
                安全
              </el-tag>
              <el-tag
                v-if="selectedAsset.wafName || selectedAsset.waf"
                size="small"
                effect="dark"
                type="warning"
              >
                WAF 防火墙
              </el-tag>
              <el-tag
                v-if="selectedAsset.confidence"
                size="small"
                effect="plain"
                type="info"
              >
                置信度: {{ selectedAsset.confidence }}%
              </el-tag>
            </div>
          </div>
        </div>

        <!-- 关联安全发现 (漏洞与风险) -->
        <div v-if="selectedNodeFindings.length" class="detail-section">
          <h4 class="section-title">
            <span>关联安全发现 ({{ selectedNodeFindings.length }} 项)</span>
          </h4>
          <div class="topology-findings-list">
            <div
              v-for="f in selectedNodeFindings"
              :key="f.id"
              class="topology-finding-card"
              :class="findingIsVulnerability(f) ? 'card--vuln' : 'card--risk'"
            >
              <div class="finding-card-header">
                <el-tag
                  size="small"
                  effect="light"
                  :type="findingIsVulnerability(f) ? 'danger' : 'warning'"
                  class="finding-type-badge"
                >
                  {{ findingIsVulnerability(f) ? "漏洞" : "风险点" }}
                </el-tag>
                <span class="finding-card-title" :title="f.title">{{ f.title }}</span>
              </div>
              <p class="finding-card-desc">{{ f.description }}</p>
              <div v-if="f.evidence" class="finding-card-evidence">
                <code>{{ f.evidence.slice(0, 160) }}</code>
              </div>
            </div>
          </div>
        </div>

        <!-- 核心属性列表 -->
        <div class="detail-section">
          <h4 class="section-title">基础与网络信息</h4>
          <div class="detail-prop-row">
            <span class="prop-key">完整 URL:</span>
            <div class="prop-val url-val">
              <span class="url-text" :title="selectedAsset.url">{{ selectedAsset.url || '-' }}</span>
              <button
                type="button"
                class="url-copy-btn"
                title="复制完整 URL"
                @click="copyUrl(selectedAsset.url)"
              >
                <FluentIcon name="copy" :size="12" />
                <span>复制</span>
              </button>
            </div>
          </div>

          <div v-if="selectedAsset.targetValue" class="detail-prop-row">
            <span class="prop-key">所属探测目标:</span>
            <span class="prop-val mono">{{ selectedAsset.targetValue }}</span>
          </div>

          <div v-if="selectedAsset.server" class="detail-prop-row">
            <span class="prop-key">Web 服务器:</span>
            <span class="prop-val bold">{{ selectedAsset.server }}</span>
          </div>

          <div v-if="selectedAsset.framework" class="detail-prop-row">
            <span class="prop-key">应用框架:</span>
            <span class="prop-val bold text-accent">{{ selectedAsset.framework }}</span>
          </div>

          <div v-if="selectedAsset.wafName || selectedAsset.waf" class="detail-prop-row">
            <span class="prop-key">防护 WAF:</span>
            <span class="prop-val text-warning">{{ selectedAsset.wafName || selectedAsset.waf }}</span>
          </div>

          <div v-if="selectedAsset.detectedAt || selectedAsset.createdAt" class="detail-prop-row">
            <span class="prop-key">探测入库时间:</span>
            <span class="prop-val">{{ formatDateTime(selectedAsset.detectedAt || selectedAsset.createdAt) }}</span>
          </div>
        </div>

        <!-- 证据 / 指纹详情 (符合 Fluent 2 规范的数据呈现体系) -->
        <div v-if="selectedAsset.evidence || selectedAsset.technologies" class="detail-section">
          <h4 class="section-title">指纹与匹配证据</h4>

          <!-- 结构化指纹匹配实体卡片 (Fluent Entity List) -->
          <div v-if="parsedEvidence?.fingerprints?.length" class="evidence-entity-list">
            <div
              v-for="(fp, idx) in parsedEvidence.fingerprints"
              :key="idx"
              class="evidence-entity-card"
            >
              <div class="entity-card-header">
                <span class="entity-name">{{ fp.name || fp.id }}</span>
                <span v-if="fp.category" class="fluent-badge-category">{{ fp.category }}</span>
                <span v-if="fp.confidence" class="fluent-badge-confidence">{{ fp.confidence }}% 置信</span>
              </div>
              <div v-if="fp.evidence?.length" class="entity-evidence-tags">
                <span v-for="(ev, eIdx) in fp.evidence" :key="eIdx" class="entity-tag">
                  {{ ev }}
                </span>
              </div>
            </div>
          </div>

          <!-- Fluent 2 标准 Code Snippet 容器 (改造为支持底边高亮的只读文本域) -->
          <div class="raw-data-section">
            <div class="raw-data-header">
              <span class="code-header-title">
                <FluentIcon name="document" :size="13" />
                <span>原始数据 (JSON)</span>
              </span>
              <button
                type="button"
                class="fluent-subtle-btn"
                title="复制原始 JSON"
                @click="copyEvidence"
              >
                <FluentIcon name="copy" :size="12" />
                <span>复制</span>
              </button>
            </div>
            <el-input
              :model-value="formatEvidence(selectedAsset.evidence || selectedAsset.technologies)"
              type="textarea"
              :autosize="{ minRows: 6, maxRows: 12 }"
              readonly
              placeholder="暂无原始数据"
              class="raw-data-textarea"
            />
          </div>
        </div>

        <!-- 底部快捷操作条 -->
        <div class="drawer-actions">
          <el-button
            v-if="selectedAsset.url"
            type="primary"
            class="fluent-action-btn fluent-primary-btn"
            @click="openAssetInNewWindow(selectedAsset.url)"
          >
            在新窗口访问
          </el-button>
          <el-button
            type="danger"
            plain
            class="fluent-action-btn"
            @click="confirmRemoveNode(selectedAsset.id!, parseHost(selectedAsset.url).host)"
          >
            {{ assetRemovalLabel(selectedAsset) }}
          </el-button>
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<style scoped>
/* Fluent UI 容器体系 */
.asset-topology-container {
  position: relative;
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  min-width: 0;
  background: var(--app-surface-strong, #ffffff);
  border: 1px solid var(--app-border, #e2e8f0);
  border-radius: 6px;
  overflow: hidden;
  box-shadow: none;
  font-family: var(--fluent-font);
  container-type: inline-size;
}

.asset-topology-container.is-fullscreen,
.asset-topology-container:fullscreen {
  position: fixed;
  inset: 0;
  z-index: 2500;
  border-radius: 0;
  border: none;
  background: var(--app-surface-strong, #ffffff) !important;
}

/* 顶部 Fluent CommandBar 控制栏 */
.topology-toolbar {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  padding: 10px 16px 0;
  background: var(--app-surface-strong, #ffffff);
  border-bottom: 1px solid var(--app-border, #e2e8f0);
  z-index: 10;
  gap: 8px 16px;
  flex-shrink: 0;
}

.toolbar-left {
  grid-column: 1 / -1;
  grid-row: 2;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  min-width: 0;
  margin: 0 -16px;
  padding: 6px 16px;
  border-top: 1px solid var(--app-border, #e2e8f0);
  background: var(--app-surface-soft, #fbfcfe);
}

.stats-pills {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

/* Fluent 2 胶囊标签 (Filter Chips) */
.stat-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 8px;
  height: 26px;
  background: var(--app-surface-strong, #ffffff);
  border: 1px solid var(--app-border, #e2e8f0);
  border-radius: var(--fluent-radius-control, 4px);
  font: inherit;
  font-size: 12px;
  color: var(--app-muted, #64748b);
  cursor: pointer;
  transition: color 120ms ease, background-color 120ms ease, border-color 120ms ease, box-shadow 120ms ease;
  user-select: none;
  box-sizing: border-box;
}

.stat-pill:hover {
  background: var(--app-surface-soft, #f8fafc);
  border-color: var(--app-border-strong, #cbd5e1);
  color: var(--app-text, #0f172a);
}

.stat-pill.active {
  background: var(--app-accent-soft, #edf5fb);
  border-color: var(--app-accent, #0078d4);
  color: var(--app-accent, #0078d4);
  font-weight: var(--fluent-weight-semibold, 600);
}

.stat-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 18px;
  height: 16px;
  padding: 0 5px;
  border-radius: 9999px;
  background: rgba(0, 0, 0, 0.05);
  font-size: 11px;
  font-weight: 600;
  line-height: 1;
  color: var(--app-text, #0f172a);
}

.stat-pill.active .stat-badge {
  background: color-mix(in srgb, var(--app-accent, #0078d4) 16%, transparent);
  color: var(--app-accent, #0078d4);
}

.focused-domain-tag {
  font-size: 11px;
  border-radius: var(--fluent-radius-control, 4px);
}

.stat-dot {
  width: 5px;
  height: 5px;
  border-radius: 50%;
}

.dot-accent {
  background: var(--app-accent, #0078d4);
}

.dot-success {
  background: #107c41;
}

.dot-info {
  background: #507b98;
}

.dot-warning {
  background: #aa8a42;
}

.stat-label {
  font-weight: var(--fluent-weight-regular, 400);
}

.toolbar-meta-group {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}

.host-meta-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 8px;
  height: 24px;
  font-size: 12px;
  font-weight: 500;
  color: var(--app-muted, #64748b);
  background: var(--app-surface-strong, #ffffff);
  border: 1px solid var(--app-border, #e2e8f0);
  border-radius: var(--fluent-radius-control, 4px);
  user-select: none;
}

.toolbar-center {
  grid-row: 1;
  width: 280px;
  max-width: 100%;
  min-width: 0;
}

.topology-search-input :deep(.el-input__wrapper) {
  border-radius: var(--fluent-radius-control, 4px);
}

.toolbar-right {
  grid-row: 1;
  display: flex;
  align-items: center;
  gap: 6px;
}

/* Fluent 2 标准分段控件 (Segmented Control) */
.fluent-segmented-control {
  display: inline-flex;
  align-items: center;
  padding: 2px;
  background: var(--app-surface-soft, #f1f5f9);
  border: 1px solid var(--app-border, #e2e8f0);
  border-radius: var(--fluent-radius-control, 4px);
  gap: 2px;
  user-select: none;
}

.segmented-item {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 10px;
  height: 26px;
  border: 1px solid transparent;
  border-radius: 3px;
  background: transparent;
  color: var(--app-muted, #64748b);
  font-family: var(--fluent-font);
  font-size: 12px;
  font-weight: var(--fluent-weight-medium, 500);
  cursor: pointer;
  transition: color 120ms cubic-bezier(0.33, 1, 0.68, 1), background-color 120ms cubic-bezier(0.33, 1, 0.68, 1), box-shadow 120ms cubic-bezier(0.33, 1, 0.68, 1);
  box-sizing: border-box;
}

.segmented-item:hover:not(.is-active) {
  color: var(--app-text, #0f172a);
  background: rgba(0, 0, 0, 0.04);
}

.segmented-item.is-active {
  background: var(--app-surface-strong, #ffffff);
  color: var(--app-text, #0f172a);
  font-weight: var(--fluent-weight-semibold, 600);
  border-color: rgba(0, 0, 0, 0.06);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.06), 0 0 1px rgba(0, 0, 0, 0.04);
}

.divider-v {
  width: 1px;
  height: 18px;
  background: var(--app-border, #e2e8f0);
  margin: 0 4px;
}

/* Fluent 浮动控件组：深浅主题高对比度自适应 */
.zoom-controls {
  display: flex;
  align-items: center;
  background: var(--app-surface-strong, #ffffff);
  border: 1px solid var(--app-border-strong, #cbd5e1);
  border-radius: var(--fluent-radius-control, 6px);
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.18), 0 1px 3px rgba(0, 0, 0, 0.1);
  padding: 3px 6px;
  gap: 4px;
  color: var(--app-text, #0f172a);
}

:root[data-system-theme="dark"] .zoom-controls,
html.dark .zoom-controls,
[data-theme="dark"] .zoom-controls {
  background: rgba(30, 32, 44, 0.95) !important;
  border: 1px solid rgba(255, 255, 255, 0.22) !important;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5) !important;
  color: #ffffff !important;
}

.canvas-controls {
  position: absolute;
  bottom: 16px;
  left: 16px;
  z-index: 12;
}

.zoom-level {
  font-size: var(--fluent-caption2-size, 11px);
  font-weight: 700;
  color: var(--app-text, #0f172a);
  min-width: 38px;
  text-align: center;
  user-select: none;
}

:root[data-system-theme="dark"] .zoom-level,
html.dark .zoom-level,
[data-theme="dark"] .zoom-level {
  color: #f8fafc !important;
}

/* Fluent Command 按钮规范 */
.fluent-command-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  flex: 0 0 32px;
  padding: 0;
  border: none;
  background: transparent;
  border-radius: var(--fluent-radius-control, 4px);
  color: var(--app-text);
  cursor: pointer;
  font-size: 17px;
  transition: color 120ms ease, background-color 120ms ease;
}

.fluent-command-btn:hover {
  background: var(--app-accent-soft, #f0fdf4);
  color: var(--app-accent, #0078d4);
}

.fluent-command-btn.active {
  background: var(--app-accent-soft-strong, #bae6fd);
  color: var(--app-accent, #0078d4);
}

.zoom-controls .fluent-command-btn {
  color: var(--app-text, #0f172a);
}

:root[data-system-theme="dark"] .zoom-controls .fluent-command-btn,
html.dark .zoom-controls .fluent-command-btn,
[data-theme="dark"] .zoom-controls .fluent-command-btn {
  color: #f8fafc !important;
}

.zoom-controls .fluent-command-btn:hover {
  background: var(--app-accent-soft, rgba(0, 120, 212, 0.1));
  color: var(--app-accent, #0078d4);
}

:root[data-system-theme="dark"] .zoom-controls .fluent-command-btn:hover,
html.dark .zoom-controls .fluent-command-btn:hover,
[data-theme="dark"] .zoom-controls .fluent-command-btn:hover {
  background: rgba(255, 255, 255, 0.14) !important;
  color: #38bdf8 !important;
}

.zoom-controls .divider-v {
  background: var(--app-border, #cbd5e1);
}

:root[data-system-theme="dark"] .zoom-controls .divider-v,
html.dark .zoom-controls .divider-v,
[data-theme="dark"] .zoom-controls .divider-v {
  background: rgba(255, 255, 255, 0.2) !important;
}

.view-options {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.view-options :deep(.el-checkbox) {
  margin-right: 0;
}

.view-option-action {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  border: 0;
  border-radius: 4px;
  padding: 8px;
  background: transparent;
  color: var(--app-text);
  font: inherit;
  font-size: 13px;
  cursor: pointer;
}

.view-option-action:hover {
  background: var(--app-surface-soft);
}

.view-option-action:disabled {
  opacity: 0.5;
  cursor: default;
}

/* 画布容器 */
.topology-canvas-wrap {
  position: relative;
  flex: 1;
  width: 100%;
  min-height: 220px;
  overflow: hidden;
  user-select: none;
  background: var(--app-surface-strong, #ffffff);
}

.cursor-grab {
  cursor: grab;
}

.cursor-grabbing {
  cursor: grabbing;
}

.topology-svg {
  display: block;
  width: 100%;
  height: 100%;
}

/* 状态遮罩 */
.topology-state-overlay {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  color: var(--app-muted);
  font-size: var(--fluent-body1-size, 14px);
  background: var(--app-surface);
  z-index: 5;
  text-align: center;
  padding: 20px;
}

.empty-icon-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 64px;
  height: 64px;
  border-radius: 50%;
  background: var(--app-accent-soft);
  color: var(--app-accent);
  margin-bottom: 4px;
}

.topology-state-overlay h4 {
  margin: 0;
  font-size: var(--fluent-subtitle1-size, 18px);
  font-weight: var(--fluent-weight-semibold, 600);
  color: var(--app-text);
}

.topology-state-overlay p {
  margin: 0;
  max-width: 360px;
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
  line-height: var(--fluent-caption1-line, 16px);
}

/* 环轨引导同心线 */
.orbit-guide-circle {
  fill: none;
  stroke: var(--app-border, #cbd5e1);
  stroke-width: 1;
  opacity: 0.4;
}

.orbit-guide-circle.is-dashed {
  stroke-dasharray: 4 6;
  opacity: 0.28;
}

/* Geometry updates immediately so dragged nodes stay attached to their edges. */
.edge-base-line {
  fill: none;
  stroke: var(--app-border-strong, #c8cdd1);
  stroke-width: 1.2;
  stroke-linecap: round;
  transition: stroke 120ms ease, opacity 120ms ease;
}

.edge-flow-line {
  fill: none;
  stroke: var(--app-accent, #0078d4);
  stroke-width: 1.4;
  stroke-linecap: round;
  stroke-dasharray: 6 12;
  opacity: 0.45;
  transition: opacity 120ms ease;
}

.edge-group.is-flowing .edge-flow-line {
  animation: cyberFlow 2.8s linear infinite;
}

@keyframes cyberFlow {
  from {
    stroke-dashoffset: 36;
  }
  to {
    stroke-dashoffset: 0;
  }
}

.edge-group.is-hovered .edge-base-line,
.edge-group.is-selected .edge-base-line {
  stroke: var(--app-accent, #0078d4);
  stroke-width: 1.6;
}

.edge-group.is-hovered .edge-flow-line,
.edge-group.is-selected .edge-flow-line {
  opacity: 0.8;
}

.edge-group.is-dimmed {
  opacity: 0.12;
}

/* 真实物理端点端口 (Connection Sockets)，彻底告别悬空假连 */
.edge-port-dot {
  fill: var(--app-surface-strong, #ffffff);
  stroke: var(--app-border, #cbd5e1);
  stroke-width: 1.2;
  opacity: 0;
  transition: fill 120ms ease, stroke 120ms ease, opacity 120ms ease;
}

.port-target {
  fill: var(--app-surface-strong, #ffffff);
  stroke: var(--app-accent, #0078d4);
}

.edge-group.is-hovered .edge-port-dot,
.edge-group.is-selected .edge-port-dot {
  fill: var(--app-accent, #0078d4);
  stroke: #ffffff;
  opacity: 1;
}

/* ==================== 中心宿主 Fluent Command Core 卡片 ==================== */
.topology-hub-node {
  cursor: grab;
  outline: none;
  user-select: none;
}

.topology-hub-node:active {
  cursor: grabbing;
}

.hub-card-halo {
  fill: none;
  stroke: var(--app-accent, #0078d4);
  stroke-width: 1.5;
  opacity: 0.15;
  transition: opacity 180ms ease, stroke-width 180ms ease;
}

.topology-hub-node:hover .hub-card-halo {
  opacity: 0.35;
  stroke-width: 2.5;
}

.hub-card-bg {
  fill: var(--app-surface-strong, #ffffff);
  stroke: var(--app-accent, #0078d4);
  stroke-width: 1.5;
  transition: stroke 150ms ease, fill 150ms ease;
}

.topology-hub-node:hover .hub-card-bg {
  stroke: var(--fluent3-reveal-border, #0078d4);
}

.hub-icon-base {
  filter: drop-shadow(0 2px 4px rgba(0, 120, 212, 0.28));
}

.hub-title-text {
  fill: var(--app-text, #0f172a);
  font-size: 14px;
  font-weight: var(--fluent-weight-semibold, 600);
  font-family: var(--fluent-font);
  letter-spacing: 0;
  pointer-events: none;
}

.hub-status-dot {
  fill: #107c41;
  animation: hubDotPulse 2.4s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

@keyframes hubDotPulse {
  0%, 100% { opacity: 0.7; transform: scale(1); }
  50% { opacity: 1; transform: scale(1.15); }
}

.hub-subtitle-text {
  fill: var(--app-muted, #64748b);
  font-size: 11px;
  font-weight: var(--fluent-weight-medium, 500);
  font-family: var(--fluent-font);
  pointer-events: none;
}

/* ==================== 同主域聚类围栏 (Domain Cluster Enclosures) ==================== */
.cluster-group {
  transition: opacity 160ms ease;
}

.cluster-group.is-dimmed {
  opacity: 0.12;
}

.cluster-rect {
  fill: rgba(0, 120, 212, 0.028);
  stroke: rgba(0, 120, 212, 0.16);
  stroke-width: 1;
  stroke-dasharray: 4 4;
  transition: stroke 160ms ease, fill 160ms ease;
}

.cluster-group.is-focused .cluster-rect {
  fill: rgba(0, 120, 212, 0.055);
  stroke: var(--app-accent, #0078d4);
  stroke-width: 1.5;
  stroke-dasharray: none;
}

.cluster-label-chip {
  cursor: pointer;
}

.cluster-label-bg {
  fill: var(--app-surface-strong, #ffffff);
  stroke: rgba(0, 120, 212, 0.22);
  stroke-width: 1;
  filter: drop-shadow(0 1px 2px rgba(15, 23, 42, 0.05));
  transition: stroke 120ms ease, fill 120ms ease;
}

.cluster-label-chip:hover .cluster-label-bg {
  stroke: var(--app-accent, #0078d4);
  fill: #f4f9fd;
}

.cluster-label-text {
  fill: var(--app-accent, #0078d4);
  font-size: 11px;
  font-weight: var(--fluent-weight-semibold, 600);
  font-family: var(--fluent-font);
  user-select: none;
}

/* ==================== 思维导图主域分支胶囊节点 ==================== */
.domain-branch-group {
  cursor: pointer;
  outline: none;
  transition: opacity 160ms ease;
}

.domain-branch-group.is-dimmed {
  opacity: 0.15;
}

.domain-branch-bg {
  fill: var(--app-surface-soft, #f8fafc);
  stroke: var(--app-border-strong, #cbd5e1);
  stroke-width: 1.2;
  filter: drop-shadow(0 1.5px 3px rgba(15, 23, 42, 0.05));
  transition: fill 140ms ease, stroke 140ms ease, filter 140ms ease;
}

.domain-branch-group:hover .domain-branch-bg {
  stroke: var(--app-accent, #0078d4);
  fill: #fafdff;
  filter: drop-shadow(0 2px 6px rgba(0, 120, 212, 0.18));
}

.domain-branch-group.is-focused .domain-branch-bg {
  stroke: var(--app-accent, #0078d4);
  stroke-width: 1.6;
  fill: var(--app-accent-soft, #edf5fb);
}

.domain-icon-dot {
  fill: var(--app-accent-soft, #e1effa);
}

.domain-branch-title {
  fill: var(--app-text, #0f172a);
  font-size: 12px;
  font-weight: var(--fluent-weight-semibold, 600);
  font-family: var(--fluent-font);
  user-select: none;
}

.domain-branch-count-bg {
  fill: rgba(0, 120, 212, 0.08);
}

.domain-branch-count {
  fill: var(--app-accent, #0078d4);
  font-size: 10.5px;
  font-weight: 700;
  font-family: var(--fluent-font);
  user-select: none;
}

/* ==================== Fluent 2/3 资产节点微卡片 ==================== */
.node-card-group {
  cursor: grab;
  transition: opacity var(--fluent-fast);
  outline: none;
}

.node-card-group:active {
  cursor: grabbing;
}

.node-card-bg {
  fill: var(--app-surface-strong, #ffffff);
  stroke: var(--app-border, #cbd5e1);
  stroke-width: 1.2;
  transition: fill 150ms ease, stroke 150ms ease, filter 150ms ease;
}

/* 漏洞态势与风险态势显式边框 */
.node-card-bg.card--has-vuln {
  stroke: var(--fluent-danger-bg, #b42318) !important;
  stroke-width: 1.8px !important;
  filter: drop-shadow(0 0 6px color-mix(in srgb, var(--fluent-danger-bg, #b42318) 28%, transparent));
}

.node-card-bg.card--has-risk {
  stroke: var(--fluent-warning-bg, #8a4b08) !important;
  stroke-width: 1.5px !important;
}

/* 态势徽标 (右上角) */
.node-badge-bg.badge--vuln {
  fill: var(--fluent-danger-bg, #b42318);
}

.node-badge-bg.badge--risk {
  fill: var(--fluent-warning-bg, #8a4b08);
}

.node-badge-bg.badge--safe {
  fill: var(--fluent-success-bg, #107c41);
}

.node-badge-icon,
.node-badge-text {
  fill: #ffffff;
  pointer-events: none;
}

.node-badge-text {
  font-size: 10px;
  font-weight: 600;
  font-family: var(--fluent-font);
  letter-spacing: 0;
}

.node-tag-bg.tag-url {
  fill: rgba(0, 120, 212, 0.12);
  stroke: rgba(0, 120, 212, 0.28);
}

/* 抽屉内关联漏洞/风险卡片列表：遵循 Fluent 2 Card / MessageBar 规范，绝无左侧厚边条 */
.topology-findings-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-top: 10px;
}

.topology-finding-card {
  padding: 12px 14px;
  border-radius: var(--fluent-radius-card, 8px);
  border: 1px solid var(--app-border, #e2e8f0);
  background: var(--app-surface-soft, rgba(0, 0, 0, 0.02));
  transition: all var(--fluent-fast, 150ms ease);
}

.topology-finding-card.card--vuln {
  border: 1px solid light-dark(rgba(239, 68, 68, 0.32), rgba(239, 68, 68, 0.45)) !important;
  background: light-dark(rgba(239, 68, 68, 0.04), rgba(239, 68, 68, 0.1)) !important;
}

.topology-finding-card.card--risk {
  border: 1px solid light-dark(rgba(245, 158, 11, 0.32), rgba(245, 158, 11, 0.45)) !important;
  background: light-dark(rgba(245, 158, 11, 0.04), rgba(245, 158, 11, 0.1)) !important;
}

.finding-card-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.finding-type-badge {
  font-weight: 600;
  border-radius: 4px;
}

.finding-card-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--app-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.finding-card-desc {
  font-size: 12px;
  color: var(--app-muted, #64748b);
  margin: 0 0 8px 0;
  line-height: 1.45;
}

.finding-card-evidence {
  font-size: 11px;
  background: light-dark(rgba(0, 0, 0, 0.04), rgba(255, 255, 255, 0.06));
  padding: 6px 8px;
  border-radius: 4px;
  border: 1px solid light-dark(rgba(0, 0, 0, 0.06), rgba(255, 255, 255, 0.08));
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Fluent 3 Reveal 悬停效果 */
.node-card-group:hover .node-card-bg {
  stroke: var(--app-accent, #0078d4);
  stroke-width: 1.5;
  fill: var(--app-surface-strong, #ffffff);
}

.node-card-group.is-selected .node-card-bg,
.node-card-group:focus-visible .node-card-bg {
  stroke: var(--app-accent, #0078d4) !important;
  stroke-width: 2px !important;
  filter: drop-shadow(0 0 10px color-mix(in srgb, var(--app-accent) 45%, transparent)) !important;
}

.node-card-group.is-dimmed {
  opacity: 0.18;
}

.node-pinned-indicator {
  fill: var(--app-accent, #0078d4);
  opacity: 0.85;
}

/* 图标容器小方块 (Fluent Subtle Tint 风格) */
.node-icon-box {
  transition: filter var(--fluent-fast);
}

.box-https {
  fill: color-mix(in srgb, #10b981 16%, var(--app-surface));
  stroke: color-mix(in srgb, #10b981 32%, var(--app-border));
  stroke-width: 0.8;
}

.box-http {
  fill: color-mix(in srgb, #0078d4 16%, var(--app-surface));
  stroke: color-mix(in srgb, #0078d4 32%, var(--app-border));
  stroke-width: 0.8;
}

.icon-glyph-https .glyph-fill {
  fill: #10b981;
}

.icon-glyph-http .glyph-fill {
  fill: #38bdf8;
}

.node-card-group:hover .node-icon-box {
  filter: brightness(0.97);
}

/* 域名标题：清晰字阶，使用 Fluent 规范系统字体 */
.node-title-text {
  fill: var(--app-text, #0f172a);
  font-size: 12.5px;
  font-weight: var(--fluent-weight-semibold, 600);
  font-family: var(--fluent-font, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif);
  letter-spacing: 0;
  pointer-events: none;
}

/* Fluent Badge 标签组 */
.node-tag-bg {
  fill: var(--app-surface-soft, #f1f5f9);
  stroke: var(--app-border, #e2e8f0);
  stroke-width: 0.8;
}

.node-tag-bg.tag-protocol {
  fill: rgba(0, 0, 0, 0.035);
  stroke: rgba(0, 0, 0, 0.08);
}

.node-tag-bg.tag-generic {
  fill: var(--app-surface-soft, #f1f5f9);
  stroke: var(--app-border, #e2e8f0);
}

.node-tag-bg.tag-waf {
  fill: #fff4ce;
  stroke: #fde39a;
}

.node-tag-text {
  fill: var(--app-muted, #475569);
  font-size: 10px;
  font-weight: var(--fluent-weight-semibold, 600);
  font-family: var(--fluent-font);
  pointer-events: none;
}

.node-tag-bg.tag-waf + .node-tag-text {
  fill: #8a4d00;
}

/* 鹰眼雷达微型小地图 (Fluent Overlay) */
.topology-minimap {
  position: absolute;
  right: 16px;
  bottom: 16px;
  width: 160px;
  background: var(--app-surface-strong, #ffffff);
  border: 1px solid var(--app-border, #cbd5e1);
  border-radius: var(--fluent-radius-card, 8px);
  box-shadow: none;
  overflow: hidden;
  z-index: 15;
  user-select: none;
  font-family: var(--fluent-font);
}

.minimap-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 4px 8px;
  background: var(--app-surface-soft, #f1f5f9);
  font-size: var(--fluent-caption2-size, 10px);
  font-weight: var(--fluent-weight-semibold, 600);
  color: var(--app-muted);
}

.minimap-close {
  border: none;
  background: transparent;
  color: var(--app-muted);
  cursor: pointer;
  font-size: 13px;
  line-height: 1;
  padding: 0;
}

.minimap-body {
  padding: 4px;
}

.minimap-svg {
  display: block;
  width: 100%;
  height: 90px;
  background: var(--app-surface-soft, #f8fafc);
  border-radius: var(--fluent-radius-control, 4px);
  cursor: crosshair;
}

.minimap-svg.is-dragging {
  cursor: grabbing;
}

.minimap-viewfinder {
  fill: color-mix(in srgb, var(--app-accent, #0078d4) 14%, transparent);
  stroke: var(--app-accent, #0078d4);
  stroke-width: 1.2;
  cursor: grab;
  transition: fill 120ms ease;
}

.minimap-svg:hover .minimap-viewfinder {
  fill: color-mix(in srgb, var(--app-accent, #0078d4) 22%, transparent);
}

.minimap-svg.is-dragging .minimap-viewfinder {
  cursor: grabbing;
}

/* 右键 Fluent Flyout 上下文菜单 */
.topology-context-menu {
  position: absolute;
  background: var(--app-overlay-bg, #ffffff);
  border: 1px solid var(--app-border, #e2e8f0);
  border-radius: var(--fluent-radius-overlay, 8px);
  box-shadow: var(--fluent-shadow-28);
  padding: 4px;
  min-width: 164px;
  z-index: 50;
  font-family: var(--fluent-font);
}

.menu-header {
  padding: 4px 8px 6px;
  border-bottom: 1px solid var(--app-border, #f1f5f9);
  margin-bottom: 4px;
}

.menu-host {
  font-size: var(--fluent-caption2-size, 11px);
  font-weight: var(--fluent-weight-semibold, 600);
  color: var(--app-text);
  display: block;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 150px;
}

.menu-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  border-radius: var(--fluent-radius-control, 4px);
  font-size: var(--fluent-caption1-size, 12px);
  color: var(--app-text);
  cursor: pointer;
  text-decoration: none;
  transition: all var(--fluent-fast);
}

.menu-item:hover {
  background: var(--app-accent-soft, #f3f4f6);
  color: var(--app-accent, #0078d4);
}

.menu-item.text-danger {
  color: #d83b01;
}

.menu-item.text-danger:hover {
  background: #fdf3f2;
}

.menu-divider {
  height: 1px;
  background: var(--app-border, #f1f5f9);
  margin: 4px 0;
}

/* Fluent Drawer 样式 */
.drawer-body {
  display: flex;
  flex-direction: column;
  gap: 20px;
  padding: 4px;
  font-family: var(--fluent-font);
}

.asset-hero-card {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 16px;
  background: transparent;
  border-radius: var(--fluent-radius-card, 8px);
  border: 1px solid var(--app-border, #e2e8f0);
}

.hero-icon-box {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 46px;
  height: 46px;
  border-radius: var(--fluent-radius-card, 8px);
  background: var(--app-accent, #0078d4);
  color: #ffffff;
  flex-shrink: 0;
}

.hero-info {
  overflow: hidden;
}

.hero-host {
  margin: 0 0 6px;
  font-size: var(--fluent-subtitle2-size, 15px);
  font-weight: var(--fluent-weight-semibold, 600);
  color: var(--app-text);
  word-break: break-all;
}

.hero-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.detail-section {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.section-title {
  margin: 0;
  font-size: var(--fluent-body1-size, 14px);
  font-weight: var(--fluent-weight-semibold, 600);
  color: var(--app-text);
  line-height: 20px;
}

.detail-prop-row {
  display: flex;
  align-items: center;
  min-height: 24px;
  gap: 8px;
  font-size: var(--fluent-caption1-size, 12px);
  line-height: 20px;
}

.prop-key {
  color: var(--app-muted);
  min-width: 86px;
  flex-shrink: 0;
  line-height: 20px;
}

.prop-val {
  color: var(--app-text);
  word-break: break-all;
  line-height: 20px;
}

.prop-val.bold {
  font-weight: var(--fluent-weight-semibold, 600);
}

.prop-val.mono {
  font-family: "Cascadia Code", "Consolas", monospace;
}

.prop-val.text-accent {
  color: var(--app-accent, #0078d4);
}

.prop-val.text-warning {
  color: #d83b01;
}

.url-val {
  display: flex;
  align-items: center;
  gap: 6px;
  line-height: 20px;
}

.url-text {
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  line-height: 20px;
}

.url-copy-btn {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  padding: 1px 6px;
  height: 20px;
  background: transparent;
  border: none;
  border-radius: 3px;
  color: var(--app-accent, #0078d4);
  font-size: 11px;
  font-family: inherit;
  line-height: 1;
  cursor: pointer;
  transition: all 120ms ease;
  user-select: none;
}

.url-copy-btn:hover {
  background: var(--app-accent-soft, #e0f2fe);
  color: var(--app-accent-dark, #005a9e);
}

/* Fluent 2 结构化指纹匹配卡片 */
.evidence-entity-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.evidence-entity-card {
  padding: 8px 12px;
  background: var(--app-surface-soft, #f8fafc);
  border: 1px solid var(--app-border, #e2e8f0);
  border-radius: var(--fluent-radius-control, 4px);
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.entity-card-header {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.entity-name {
  font-size: 12px;
  font-weight: var(--fluent-weight-semibold, 600);
  color: var(--app-text);
}

.fluent-badge-category {
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 10px;
  font-weight: var(--fluent-weight-medium, 500);
  background: var(--app-accent-soft, #e0f2fe);
  color: var(--app-accent, #0078d4);
}

.fluent-badge-confidence {
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 10px;
  font-weight: var(--fluent-weight-medium, 500);
  background: #f0fdf4;
  color: #166534;
  border: 1px solid #bbf7d0;
}

.entity-evidence-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.entity-tag {
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 10.5px;
  font-family: var(--font-mono, "Cascadia Code", "Consolas", monospace);
  background: var(--app-surface-strong, #ffffff);
  border: 1px solid var(--app-border, #e2e8f0);
  color: var(--app-muted, #64748b);
}

/* 原始数据 (JSON) 文本域容器 */
.raw-data-section {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-top: 4px;
}

.raw-data-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 2px;
  font-size: 11px;
}

.code-header-title {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--app-muted, #64748b);
  font-weight: var(--fluent-weight-medium, 500);
}

.fluent-subtle-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 7px;
  background: transparent;
  border: none;
  border-radius: 3px;
  color: var(--app-muted, #64748b);
  font-size: 11px;
  cursor: pointer;
  transition: all 120ms ease;
}

.fluent-subtle-btn:hover {
  background: var(--app-surface-soft, #f1f5f9);
  color: var(--app-accent, #0078d4);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
}

.raw-data-textarea :deep(.el-textarea__inner) {
  font-family: var(--font-mono, "Cascadia Code", "Consolas", monospace);
  font-size: 11.5px;
  line-height: 1.55;
  white-space: pre;
  color: var(--app-text, #1e293b);
  background: var(--app-surface-strong, #ffffff) !important;
  border: 0 !important;
  border-radius: var(--fluent-radius-control, 4px) !important;
  box-shadow: 0 0 0 1px var(--app-border, #e2e8f0) inset !important;
  transition: box-shadow 150ms ease;
}

.raw-data-textarea :deep(.el-textarea__inner:hover) {
  box-shadow: 0 0 0 1px var(--app-border-strong, #cbd5e1) inset !important;
}

.raw-data-textarea :deep(.el-textarea__inner:focus),
.raw-data-textarea :deep(.el-textarea__inner:focus-within) {
  outline: none !important;
  box-shadow:
    inset 0 0 0 1px var(--app-border, #cbd5e1),
    inset 0 -2px 0 0 var(--app-accent, #0078d4) !important;
}

.drawer-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 10px;
  margin-top: 12px;
  padding-top: 16px;
  border-top: 1px solid var(--app-border, #f1f5f9);
}

.fluent-action-btn,
:deep(.fluent-action-btn) {
  border-radius: var(--fluent-radius-control, 4px);
  text-decoration: none !important;
}

.fluent-action-btn:hover,
.fluent-action-btn:focus,
.fluent-action-btn:active,
:deep(.fluent-action-btn:hover),
:deep(.fluent-action-btn:focus),
:deep(.fluent-action-btn:active) {
  text-decoration: none !important;
}

.drawer-actions :deep(a.fluent-action-btn),
.drawer-actions a.fluent-action-btn {
  text-decoration: none !important;
}

/* 保证主按钮悬浮不发生刺眼变色与下划线跳变 */
.fluent-action-btn.fluent-primary-btn,
:deep(.fluent-action-btn.fluent-primary-btn) {
  background-color: var(--app-accent, #0078d4) !important;
  border-color: var(--app-accent, #0078d4) !important;
  color: #ffffff !important;
  text-decoration: none !important;
}

.fluent-action-btn.fluent-primary-btn:hover,
.fluent-action-btn.fluent-primary-btn:focus,
.fluent-action-btn.fluent-primary-btn:active,
:deep(.fluent-action-btn.fluent-primary-btn:hover),
:deep(.fluent-action-btn.fluent-primary-btn:focus),
:deep(.fluent-action-btn.fluent-primary-btn:active) {
  background-color: var(--app-accent, #0078d4) !important;
  border-color: var(--app-accent, #0078d4) !important;
  color: #ffffff !important;
  text-decoration: none !important;
  box-shadow: none !important;
}

.fluent-action-btn.fluent-primary-btn :deep(span),
:deep(.fluent-action-btn.fluent-primary-btn span) {
  color: #ffffff !important;
  text-decoration: none !important;
}

@container (max-width: 560px) {
  .topology-toolbar {
    grid-template-columns: minmax(0, 1fr);
    padding: 10px 12px 0;
    gap: 8px;
  }

  .toolbar-center {
    width: 100%;
  }

  .toolbar-right {
    grid-row: 2;
    justify-content: flex-end;
  }

  .mode-switch {
    margin-right: auto;
  }

  .toolbar-left {
    grid-row: 3;
    margin: 0 -12px;
    padding: 6px 8px;
  }

  .stat-pill {
    gap: 4px;
    padding: 4px 6px;
  }

  .host-count {
    display: none;
  }

  .topology-minimap {
    bottom: 64px;
    right: 12px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .edge-flow-line {
    animation: none !important;
  }
}
</style>
