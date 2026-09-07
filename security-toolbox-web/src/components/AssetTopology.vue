<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { endpoints, type DiscoveryResult } from "../api";
import FluentIcon from "./FluentIcon.vue";

const props = withDefaults(
  defineProps<{
    projectId: number;
    assets: DiscoveryResult[];
    hubLabel?: string;
    loading?: boolean;
  }>(),
  {
    hubLabel: "项目中心",
    loading: false,
  },
);

const emit = defineEmits<{
  (e: "change"): void;
}>();

// 容器与视口
const containerRef = ref<HTMLElement | null>(null);
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

// 节点自定义拖拽位置记录: Map<nodeId, { x, y }>
const customPositions = ref<Record<number, { x: number; y: number }>>({});
const draggingNodeId = ref<number | null>(null);
const nodeDragStart = ref({ clientX: 0, clientY: 0, initX: 0, initY: 0 });

// 视图模式与动效
type LayoutMode = "orbit" | "tree";
const layoutMode = ref<LayoutMode>("orbit");
const enableFlowAnim = ref(true);
const isSonarScanning = ref(false);
const showMinimap = ref(true);

// 聚光灯过滤维度 (null 为无，'waf', 'https', 'http')
const spotlightFilter = ref<string | null>(null);
const focusedDomain = ref<string | null>(null);
const searchQuery = ref("");

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

// 解析 URL 主机与协议
function parseHost(url?: string): { host: string; protocol: string; path: string; rootDomain: string } {
  if (!url) return { host: "未知资产", protocol: "http", path: "", rootDomain: "未知" };
  try {
    const parsed = new URL(url.startsWith("http") ? url : `http://${url}`);
    const host = parsed.hostname + (parsed.port ? `:${parsed.port}` : "");
    const parts = parsed.hostname.split(".");
    const rootDomain = parts.length >= 2 ? parts.slice(-2).join(".") : parsed.hostname;
    return {
      host,
      protocol: parsed.protocol.replace(":", "").toLowerCase(),
      path: parsed.pathname === "/" ? "" : parsed.pathname,
      rootDomain,
    };
  } catch {
    const clean = url.replace(/^https?:\/\//, "");
    const parts = clean.split("/");
    const host = parts[0] || "资产";
    const hParts = host.split(".");
    return {
      host,
      protocol: url.startsWith("https") ? "https" : "http",
      path: parts.slice(1).join("/"),
      rootDomain: hParts.length >= 2 ? hParts.slice(-2).join(".") : host,
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

// 尺寸规范：宽敞呼吸感，杜绝文字被挡
const HUB_W = 200;
const HUB_H = 62;
const CARD_W = 184;
const CARD_H = 52;

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
  isMatch: boolean;
  isSpotlight: boolean;
}

interface LayoutEdge {
  id: string;
  sourceId: number | "hub";
  targetId: number;
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

const cx = computed(() => viewportWidth.value / 2);
const cy = computed(() => viewportHeight.value / 2);

// 计算全部节点坐标与连线
const layoutData = computed<{ nodes: LayoutNode[]; edges: LayoutEdge[] }>(() => {
  const q = searchQuery.value.trim().toLowerCase();
  const allAssets = props.assets.filter((a) => a.id != null);
  const nodes: LayoutNode[] = [];
  const edges: LayoutEdge[] = [];

  if (!allAssets.length) return { nodes, edges };

  const centerPoint = {
    x: layoutMode.value === "orbit" ? cx.value : 180,
    y: cy.value,
  };

  if (layoutMode.value === "orbit") {
    // 辐射环轨：拉大半径，确保 184px 卡片绝不互相遮挡
    const count = allAssets.length;
    let rings: Array<{ radius: number; count: number; startIdx: number }> = [];

    if (count <= 6) {
      rings = [{ radius: 240, count, startIdx: 0 }];
    } else if (count <= 16) {
      const inner = Math.min(6, Math.ceil(count * 0.4));
      rings = [
        { radius: 230, count: inner, startIdx: 0 },
        { radius: 370, count: count - inner, startIdx: inner },
      ];
    } else {
      const r1 = 6;
      const r2 = 12;
      rings = [
        { radius: 230, count: Math.min(count, r1), startIdx: 0 },
        { radius: 370, count: Math.min(Math.max(0, count - r1), r2), startIdx: r1 },
        { radius: 510, count: Math.max(0, count - r1 - r2), startIdx: r1 + r2 },
      ];
    }

    rings.forEach((ring, rIdx) => {
      const ringAssets = allAssets.slice(ring.startIdx, ring.startIdx + ring.count);
      const angleOffset = (rIdx % 2 === 1 ? Math.PI / ring.count : 0) - Math.PI / 2;

      ringAssets.forEach((asset, idx) => {
        const angle = angleOffset + (2 * Math.PI * idx) / Math.max(1, ring.count);
        const autoX = centerPoint.x + ring.radius * Math.cos(angle);
        const autoY = centerPoint.y + ring.radius * Math.sin(angle);

        const custom = customPositions.value[asset.id!];
        const nx = custom ? custom.x : autoX;
        const ny = custom ? custom.y : autoY;

        const { host, protocol, rootDomain } = parseHost(asset.url);
        const badges = getNodeBadges(asset);

        const isSearchMatch =
          !q ||
          (asset.url || "").toLowerCase().includes(q) ||
          host.toLowerCase().includes(q) ||
          badges.some((b) => b.toLowerCase().includes(q));

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

        nodes.push({
          id: asset.id!,
          asset,
          x: nx,
          y: ny,
          host,
          protocol,
          badges,
          rootDomain,
          isMatch,
          isSpotlight,
        });

        // 精确计算连接线在中心卡片边界与目标卡片边界的交点，形成真实的物理插接！
        const p1 = getRectIntersection(centerPoint.x, centerPoint.y, HUB_W, HUB_H, nx, ny);
        const p2 = getRectIntersection(nx, ny, CARD_W, CARD_H, centerPoint.x, centerPoint.y);

        const midX = (p1.x + p2.x) / 2 + Math.sin(angle) * 12;
        const midY = (p1.y + p2.y) / 2 - Math.cos(angle) * 12;
        const path = `M ${p1.x} ${p1.y} Q ${midX} ${midY} ${p2.x} ${p2.y}`;

        edges.push({
          id: `edge-${asset.id}`,
          sourceId: "hub",
          targetId: asset.id!,
          x1: p1.x,
          y1: p1.y,
          x2: p2.x,
          y2: p2.y,
          path,
        });
      });
    });
  } else {
    // 树状流向布局 (Hierarchical Tree)
    const hubX = 180;
    const hubY = centerPoint.y;

    const hostGroups = new Map<string, DiscoveryResult[]>();
    allAssets.forEach((a) => {
      const h = parseHost(a.url).host;
      if (!hostGroups.has(h)) hostGroups.set(h, []);
      hostGroups.get(h)!.push(a);
    });

    const totalAssets = allAssets.length;
    const verticalGap = Math.max(64, Math.min(90, 560 / Math.max(1, totalAssets)));
    const startY = Math.max(80, hubY - (totalAssets * verticalGap) / 2 + 30);

    let currentY = startY;
    Array.from(hostGroups.entries()).forEach(([, groupAssets]) => {
      groupAssets.forEach((asset) => {
        const autoX = hubX + 400;
        const autoY = currentY;
        currentY += verticalGap;

        const custom = customPositions.value[asset.id!];
        const nx = custom ? custom.x : autoX;
        const ny = custom ? custom.y : autoY;

        const { host, protocol, rootDomain } = parseHost(asset.url);
        const badges = getNodeBadges(asset);

        const isSearchMatch =
          !q ||
          (asset.url || "").toLowerCase().includes(q) ||
          host.toLowerCase().includes(q) ||
          badges.some((b) => b.toLowerCase().includes(q));

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

        nodes.push({
          id: asset.id!,
          asset,
          x: nx,
          y: ny,
          host,
          protocol,
          badges,
          rootDomain,
          isMatch,
          isSpotlight,
        });

        // 树状模式：严密贴合中心卡片右侧边缘中点与目标卡片左侧边缘中点！
        const x1 = hubX + HUB_W / 2;
        const y1 = hubY;
        const x2 = nx - CARD_W / 2;
        const y2 = ny;
        const dx = x2 - x1;
        const path = `M ${x1} ${y1} C ${x1 + dx * 0.45} ${y1}, ${x2 - dx * 0.45} ${y2}, ${x2} ${y2}`;

        edges.push({
          id: `edge-${asset.id}`,
          sourceId: "hub",
          targetId: asset.id!,
          x1,
          y1,
          x2,
          y2,
          path,
        });
      });
    });
  }

  return { nodes, edges };
});

// 鹰眼雷达取景框坐标与几何计算（与主画布视口精确同步）
const minimapViewfinder = computed(() => {
  const scale = 0.14;
  const z = zoom.value || 1;
  const sceneLeft = -pan.value.x / z;
  const sceneTop = -pan.value.y / z;
  const sceneWidth = viewportWidth.value / z;
  const sceneHeight = viewportHeight.value / z;

  const x = 100 + (sceneLeft - cx.value) * scale;
  const y = 60 + (sceneTop - cy.value) * scale;
  const width = Math.max(12, sceneWidth * scale);
  const height = Math.max(8, sceneHeight * scale);

  return { x, y, width, height };
});

// 缩放与平移操作
function zoomIn() {
  zoom.value = Math.min(2.5, +(zoom.value + 0.15).toFixed(2));
}

function zoomOut() {
  zoom.value = Math.max(0.3, +(zoom.value - 0.15).toFixed(2));
}

function resetView() {
  zoom.value = 1;
  pan.value = { x: 0, y: 0 };
  customPositions.value = {};
  focusedDomain.value = null;
  spotlightFilter.value = null;
}

function onWheel(e: WheelEvent) {
  e.preventDefault();
  const delta = e.deltaY < 0 ? 0.08 : -0.08;
  const newZoom = Math.min(2.5, Math.max(0.35, +(zoom.value + delta).toFixed(2)));
  zoom.value = newZoom;
}

// 画布背景拖拽平移
function onCanvasMouseDown(e: MouseEvent) {
  if (e.button !== 0) return;
  closeContextMenu();
  isDraggingCanvas.value = true;
  hasDragged.value = false;
  canvasDragStart.value = { x: e.clientX - pan.value.x, y: e.clientY - pan.value.y };
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
  if (draggingNodeId.value != null) {
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
  draggingNodeId.value = null;
}

// 节点点击交互
function handleNodeClick(node: LayoutNode) {
  if (hasDragged.value) return;
  selectedNodeId.value = node.id;
  drawerVisible.value = true;
}

// 右键上下文菜单交互
function onNodeContextMenu(e: MouseEvent, node: LayoutNode) {
  e.preventDefault();
  e.stopPropagation();
  if (!containerRef.value) return;
  const rect = containerRef.value.getBoundingClientRect();
  contextMenu.value = {
    visible: true,
    x: e.clientX - rect.left,
    y: e.clientY - rect.top,
    node,
  };
}

function closeContextMenu() {
  contextMenu.value.visible = false;
}

// 聚焦同域名资产
function focusSameDomain(node: LayoutNode | null) {
  if (!node) return;
  if (focusedDomain.value === node.rootDomain) {
    focusedDomain.value = null;
    ElMessage.info("已取消聚焦同域");
  } else {
    focusedDomain.value = node.rootDomain;
    ElMessage.success(`已聚焦「${node.rootDomain}」同域名资产`);
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

// 触发声呐雷达探测脉冲动画
function triggerSonarScan() {
  if (isSonarScanning.value) return;
  isSonarScanning.value = true;
  ElMessage.success("正在向资产拓扑广播探测脉冲…");
  setTimeout(() => {
    isSonarScanning.value = false;
  }, 2600);
}

// 导出拓扑为高清图片
async function exportTopologyImage() {
  if (!svgRef.value) return;
  try {
    const svgEl = svgRef.value;
    const svgData = new XMLSerializer().serializeToString(svgEl);
    const svgBlob = new Blob([svgData], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(svgBlob);

    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = viewportWidth.value * 2;
      canvas.height = viewportHeight.value * 2;
      const ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.scale(2, 2);
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(0, 0, viewportWidth.value, viewportHeight.value);
        ctx.drawImage(img, 0, 0);
        const a = document.createElement("a");
        a.download = `资产拓扑-${props.hubLabel}-${Date.now()}.png`;
        a.href = canvas.toDataURL("image/png");
        a.click();
        URL.revokeObjectURL(url);
        ElMessage.success("已导出拓扑高清图片");
      }
    };
    img.src = url;
  } catch {
    ElMessage.error("导出图片失败");
  }
}

// 删除节点
async function confirmRemoveNode(id: number, hostName?: string) {
  closeContextMenu();
  try {
    await ElMessageBox.confirm(
      `确定要删除资产节点「${hostName || "该节点"}」吗？删除后将从当前项目的资产测绘拓扑中移除。`,
      "移除资产节点",
      {
        confirmButtonText: "确定移除",
        cancelButtonText: "取消",
        type: "warning",
        confirmButtonClass: "el-button--danger",
      },
    );
    await endpoints.deleteDiscoveryResult(props.projectId, id);
    ElMessage.success("已成功删除资产节点");
    if (selectedNodeId.value === id) {
      drawerVisible.value = false;
      selectedNodeId.value = null;
    }
    emit("change");
  } catch (err: any) {
    if (err !== "cancel") {
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

// 全屏切换
function toggleFullscreen() {
  if (!containerRef.value) return;
  if (!document.fullscreenElement) {
    containerRef.value.requestFullscreen?.().catch(() => {});
    isFullscreen.value = true;
  } else {
    document.exitFullscreen?.().catch(() => {});
    isFullscreen.value = false;
  }
}

// 监听容器尺寸
function updateContainerSize() {
  if (containerRef.value) {
    viewportWidth.value = Math.max(760, containerRef.value.clientWidth);
    viewportHeight.value = Math.max(560, containerRef.value.clientHeight);
  }
}

let resizeObserver: ResizeObserver | null = null;
onMounted(() => {
  updateContainerSize();
  if (containerRef.value && window.ResizeObserver) {
    resizeObserver = new ResizeObserver(() => {
      updateContainerSize();
    });
    resizeObserver.observe(containerRef.value);
  }
  document.addEventListener("fullscreenchange", () => {
    isFullscreen.value = !!document.fullscreenElement;
  });
});

onUnmounted(() => {
  if (resizeObserver) {
    resizeObserver.disconnect();
  }
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
        <!-- 统计与聚光灯聚焦胶囊条 -->
        <div class="stats-pills">
          <div
            class="stat-pill fluent-pill"
            :class="{ active: spotlightFilter === null && !focusedDomain }"
            title="点击重置为全量视角"
            @click="spotlightFilter = null; focusedDomain = null"
          >
            <span class="stat-dot dot-accent" />
            <span class="stat-label">全部资产</span>
            <span class="stat-value">{{ stats.total }}</span>
          </div>

          <div
            class="stat-pill fluent-pill"
            :class="{ active: spotlightFilter === 'https' }"
            title="聚光灯高亮 HTTPS 资产"
            @click="toggleSpotlight('https')"
          >
            <span class="stat-dot dot-success" />
            <span class="stat-label">HTTPS</span>
            <span class="stat-value">{{ stats.httpsCount }}</span>
          </div>

          <div
            class="stat-pill fluent-pill"
            :class="{ active: spotlightFilter === 'http' }"
            title="聚光灯高亮 HTTP 资产"
            @click="toggleSpotlight('http')"
          >
            <span class="stat-dot dot-info" />
            <span class="stat-label">HTTP</span>
            <span class="stat-value">{{ stats.httpCount }}</span>
          </div>

          <div
            v-if="stats.wafCount > 0"
            class="stat-pill fluent-pill"
            :class="{ active: spotlightFilter === 'waf' }"
            title="聚光灯高亮 WAF 保护目标"
            @click="toggleSpotlight('waf')"
          >
            <span class="stat-dot dot-warning" />
            <span class="stat-label">WAF防护</span>
            <span class="stat-value">{{ stats.wafCount }}</span>
          </div>

          <el-tag
            v-if="focusedDomain"
            size="small"
            closable
            class="focused-domain-tag fluent-tag"
            @close="focusedDomain = null"
          >
            聚焦主域: {{ focusedDomain }}
          </el-tag>
        </div>
      </div>

      <div class="toolbar-center">
        <el-input
          v-model="searchQuery"
          placeholder="搜索域名/服务/技术栈..."
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
        <!-- 布局模式切换 -->
        <el-radio-group v-model="layoutMode" size="small" class="mode-switch fluent-segmented">
          <el-radio-button value="orbit">
            <span class="btn-inner"><FluentIcon name="globe" :size="13" /> 环轨</span>
          </el-radio-button>
          <el-radio-button value="tree">
            <span class="btn-inner"><FluentIcon name="branch-fork" :size="13" /> 树状</span>
          </el-radio-button>
        </el-radio-group>

        <!-- 声呐探测脉冲 -->
        <el-tooltip content="发射声呐雷达探测脉冲" placement="top">
          <button
            class="fluent-command-btn sonar-btn"
            :class="{ active: isSonarScanning }"
            @click="triggerSonarScan"
          >
            <FluentIcon name="rocket" :size="14" />
          </button>
        </el-tooltip>

        <!-- 动效流光开关 -->
        <el-tooltip content="流光光效" placement="top">
          <button
            class="fluent-command-btn"
            :class="{ active: enableFlowAnim }"
            @click="enableFlowAnim = !enableFlowAnim"
          >
            <FluentIcon name="sparkle" :size="14" />
          </button>
        </el-tooltip>

        <div class="divider-v" />

        <!-- 缩放控制 -->
        <div class="zoom-controls fluent-zoom-box">
          <button class="fluent-command-btn compact" title="缩小" @click="zoomOut">
            <FluentIcon name="subtract" :size="13" />
          </button>
          <span class="zoom-level">{{ Math.round(zoom * 100) }}%</span>
          <button class="fluent-command-btn compact" title="放大" @click="zoomIn">
            <FluentIcon name="add" :size="13" />
          </button>
          <button class="fluent-command-btn compact" title="自适应居中" @click="resetView">
            <FluentIcon name="fit" :size="14" />
          </button>
        </div>

        <!-- 小地图切换 -->
        <el-tooltip content="显示/隐藏雷达小地图" placement="top">
          <button
            class="fluent-command-btn"
            :class="{ active: showMinimap }"
            @click="showMinimap = !showMinimap"
          >
            <FluentIcon name="map" :size="14" />
          </button>
        </el-tooltip>

        <!-- 导出图片 -->
        <el-tooltip content="导出拓扑高清图 (PNG)" placement="top">
          <button class="fluent-command-btn" @click="exportTopologyImage">
            <FluentIcon name="arrow-download" :size="14" />
          </button>
        </el-tooltip>

        <!-- 全屏模式 -->
        <button
          class="fluent-command-btn"
          :title="isFullscreen ? '退出全屏' : '全屏模式'"
          @click="toggleFullscreen"
        >
          <FluentIcon :name="isFullscreen ? 'fullscreen-exit' : 'fullscreen'" :size="14" />
        </button>
      </div>
    </header>

    <!-- 主画布区域 -->
    <div
      class="topology-canvas-wrap"
      :class="{
        'cursor-grab': !isDraggingCanvas && draggingNodeId == null,
        'cursor-grabbing': isDraggingCanvas || draggingNodeId != null,
      }"
      @wheel="onWheel"
      @mousedown="onCanvasMouseDown"
      @mousemove="onGlobalMouseMove"
      @mouseup="onGlobalMouseUp"
      @mouseleave="onGlobalMouseUp"
      @dblclick="resetView"
    >
      <!-- 加载遮罩 -->
      <div v-if="loading" class="topology-state-overlay">
        <el-icon class="is-loading" :size="24"><FluentIcon name="arrow-sync" /></el-icon>
        <span class="state-copy">正在加载安全资产拓扑…</span>
      </div>

      <!-- 空数据提示 -->
      <div v-else-if="!assets.length" class="topology-state-overlay">
        <div class="empty-icon-wrap">
          <FluentIcon name="globe-search" :size="36" />
        </div>
        <h4>暂无资产节点</h4>
        <p>运行资产探测或 ZAP 爬虫任务后，发现的 Web 目标与服务将自动在此构建拓扑。</p>
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
            <circle cx="12" cy="12" r="1.2" fill="var(--app-border, #cbd5e1)" opacity="0.75" />
          </pattern>

          <!-- 柔和阴影滤镜 -->
          <filter id="fluentCardShadow" x="-10%" y="-10%" width="120%" height="130%">
            <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#0f172a" flood-opacity="0.08" />
          </filter>

          <filter id="fluentHubShadow" x="-20%" y="-20%" width="140%" height="150%">
            <feDropShadow dx="0" dy="4" stdDeviation="10" flood-color="var(--app-accent, #0078d4)" flood-opacity="0.22" />
          </filter>

          <!-- 连线动态渐变 -->
          <linearGradient id="linkGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="var(--app-accent, #0078d4)" stop-opacity="0.7" />
            <stop offset="50%" stop-color="var(--app-accent-soft-strong, #60a5fa)" stop-opacity="0.5" />
            <stop offset="100%" stop-color="var(--app-accent, #0078d4)" stop-opacity="0.25" />
          </linearGradient>

          <!-- 高亮连线渐变 -->
          <linearGradient id="linkHighlight" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="var(--app-accent, #0078d4)" stop-opacity="1" />
            <stop offset="100%" stop-color="#00b7c3" stop-opacity="0.9" />
          </linearGradient>
        </defs>

        <!-- 底层网格背景 -->
        <rect width="100%" height="100%" fill="url(#dotGrid)" pointer-events="none" />

        <!-- 缩放与平移视口容器 -->
        <g
          class="topology-scene"
          :transform="`translate(${pan.x}, ${pan.y}) scale(${zoom})`"
        >
          <!-- 轨道环背景线 (仅辐射模式展示) -->
          <g v-if="layoutMode === 'orbit'" class="orbit-rings" pointer-events="none">
            <circle :cx="cx" :cy="cy" r="230" class="orbit-circle" />
            <circle v-if="assets.length > 6" :cx="cx" :cy="cy" r="370" class="orbit-circle dashed" />
            <circle v-if="assets.length > 16" :cx="cx" :cy="cy" r="510" class="orbit-circle dashed" />
          </g>

          <!-- 声呐雷达扫描扩散波 -->
          <g
            v-if="isSonarScanning"
            :transform="`translate(${layoutMode === 'orbit' ? cx : 180}, ${cy})`"
            pointer-events="none"
          >
            <circle cx="0" cy="0" r="10" class="sonar-wave wave-1" />
            <circle cx="0" cy="0" r="10" class="sonar-wave wave-2" />
            <circle cx="0" cy="0" r="10" class="sonar-wave wave-3" />
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
                'is-sonar-active': isSonarScanning,
              }"
            >
              <!-- 基础连线与光效连线 -->
              <path :d="edge.path" class="edge-base-line" />
              <path :d="edge.path" class="edge-flow-line" />

              <!-- 起止物理接驳端点 (Connection Ports)，消除假连感！ -->
              <circle :cx="edge.x1" :cy="edge.y1" r="2.5" class="edge-port-dot port-source" />
              <circle :cx="edge.x2" :cy="edge.y2" r="3" class="edge-port-dot port-target" />
            </g>
          </g>

          <!-- ==================== 图层 2: 中心项目核心 (Fluent Command Hub Card) ==================== -->
          <!-- 彻底告别丑陋圆球，采用现代 Fluent 宽幅指挥核心卡片，文字绝对清晰不挡！ -->
          <g
            class="topology-hub-node"
            :transform="`translate(${layoutMode === 'orbit' ? cx : 180}, ${cy})`"
            @mouseenter="hoveredNodeId = null"
          >
            <!-- 外层呼吸微光光环 (必须 pointer-events="none"，防止抖动抽搐) -->
            <rect
              :x="-HUB_W / 2 - 8"
              :y="-HUB_H / 2 - 8"
              :width="HUB_W + 16"
              :height="HUB_H + 16"
              rx="12"
              class="hub-glow-halo"
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
              filter="url(#fluentHubShadow)"
            />

            <!-- 左侧品牌色图标底座 (36x36 圆角小块) -->
            <g :transform="`translate(${-HUB_W / 2 + 12}, ${-18})`" pointer-events="none">
              <rect
                x="0"
                y="0"
                width="36"
                height="36"
                rx="6"
                class="hub-icon-base"
              />
              <!-- Fluent 安全盾牌图标 -->
              <path
                d="M18 7L8 11V18C8 23.5 12.2 28.5 18 30C23.8 28.5 28 23.5 28 18V11L18 7Z"
                fill="#ffffff"
              />
            </g>

            <!-- 右侧文字区域：垂直分层，字阶疏朗，绝对不会互相遮挡！ -->
            <g :transform="`translate(${-HUB_W / 2 + 58}, 0)`" pointer-events="none">
              <!-- 第一行：项目名称 (完整清晰展示) -->
              <text y="-4" class="hub-title-text" text-anchor="start">
                {{ hubLabel }}
              </text>

              <!-- 第二行：状态微标与资产计数 -->
              <g transform="translate(0, 15)">
                <circle cx="4" cy="-3" r="3" class="hub-status-dot" />
                <text x="12" y="0" class="hub-subtitle-text" text-anchor="start">
                  测绘中心 · {{ assets.length }} 资产
                </text>
              </g>
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
                'is-sonar-pinged': isSonarScanning,
                'is-custom-dragged': customPositions[node.id] != null,
              }"
              :transform="`translate(${node.x}, ${node.y})`"
              @mouseenter="hoveredNodeId = node.id"
              @mouseleave="hoveredNodeId = null"
              @mousedown="onNodeMouseDown($event, node)"
              @click.stop="handleNodeClick(node)"
              @contextmenu="onNodeContextMenu($event, node)"
            >
              <!-- 实心卡片背景 (不透明实心遮盖底层连线，确保文字绝无穿透干扰) -->
              <rect
                :x="-CARD_W / 2"
                :y="-CARD_H / 2"
                :width="CARD_W"
                :height="CARD_H"
                rx="6"
                class="node-card-bg"
                filter="url(#fluentCardShadow)"
              />

              <!-- Fluent 3 标准 Selection Slider (宽 3px，高度居中 24px，圆角胶囊状) -->
              <rect
                :x="-CARD_W / 2"
                :y="-12"
                width="3"
                height="24"
                rx="1.5"
                class="node-selection-slider"
              />

              <!-- 自定义手动拖拽后的微指示器 -->
              <circle
                v-if="customPositions[node.id]"
                :cx="CARD_W / 2 - 8"
                :cy="-CARD_H / 2 + 8"
                r="3"
                fill="var(--app-accent, #0078d4)"
              />

              <!-- 左侧协议微图标区 (24x24 Fluent 风格小盒) -->
              <g :transform="`translate(${-CARD_W / 2 + 12}, ${-12})`">
                <rect
                  x="0"
                  y="0"
                  width="24"
                  height="24"
                  rx="4"
                  :class="['node-icon-box', `box-${node.protocol}`]"
                />
                <!-- 内部状态指示小点 -->
                <circle cx="12" cy="12" r="3.5" fill="#ffffff" />
              </g>

              <!-- 右侧文字排版区域 (左对齐，层级分明，不与图标或连线挤压) -->
              <g :transform="`translate(${-CARD_W / 2 + 44}, 0)`">
                <!-- 第一行：主机名 / 域名 (主标题，字号清晰，留足显示空间) -->
                <text
                  y="-5"
                  class="node-title-text"
                  text-anchor="start"
                >
                  {{ node.host.length > 18 ? node.host.slice(0, 17) + '…' : node.host }}
                </text>

                <!-- 第二行：标签微徽标组 (下移充足距离，绝不侵占标题) -->
                <g transform="translate(0, 13)">
                  <!-- 标签 1 (协议) -->
                  <g v-if="node.badges[0]" transform="translate(0, 0)">
                    <rect x="0" y="-8" width="40" height="14" rx="2" class="node-tag-bg" />
                    <text x="20" y="2" text-anchor="middle" class="node-tag-text">{{ node.badges[0] }}</text>
                  </g>
                  <!-- 标签 2 (服务/WAF) -->
                  <g v-if="node.badges[1]" transform="translate(44, 0)">
                    <rect
                      x="0"
                      y="-8"
                      :width="node.badges[1].length > 5 ? 48 : 38"
                      height="14"
                      rx="2"
                      :class="['node-tag-bg', node.badges[1] === 'WAF' ? 'tag-waf' : '']"
                    />
                    <text
                      :x="node.badges[1].length > 5 ? 24 : 19"
                      y="2"
                      text-anchor="middle"
                      class="node-tag-text"
                    >
                      {{ node.badges[1].slice(0, 6) }}
                    </text>
                  </g>
                </g>
              </g>

              <!-- 悬停快捷删除操作按钮 (仅在 hover 时优雅显现于右上角) -->
              <g
                class="node-action-delete"
                :transform="`translate(${CARD_W / 2 - 14}, ${-CARD_H / 2 + 14})`"
                @click.stop="confirmRemoveNode(node.id, node.host)"
              >
                <circle cx="0" cy="0" r="9" class="delete-btn-bg" />
                <path
                  d="M-3 -3 L3 3 M3 -3 L-3 3"
                  stroke="#ffffff"
                  stroke-width="1.6"
                  stroke-linecap="round"
                />
              </g>
            </g>
          </g>
        </g>
      </svg>

      <!-- 鹰眼雷达微型小地图 (Fluent Overlay) -->
      <div v-if="showMinimap && assets.length > 0" class="topology-minimap fluent-overlay-card">
        <div class="minimap-header">
          <span>雷达巡航</span>
          <button class="minimap-close" @click="showMinimap = false">×</button>
        </div>
        <div class="minimap-body">
          <svg viewBox="0 0 200 120" class="minimap-svg">
            <!-- 视口取景框 (置于底层，半透明高亮展示当前视野范围) -->
            <rect
              :x="minimapViewfinder.x"
              :y="minimapViewfinder.y"
              :width="minimapViewfinder.width"
              :height="minimapViewfinder.height"
              class="minimap-viewfinder"
            />
            <!-- 中心宿主小方块 (置于取景框上方) -->
            <rect
              :x="layoutMode === 'orbit' ? 95 : 35"
              y="55"
              width="10"
              height="10"
              rx="2"
              fill="var(--app-accent, #0078d4)"
            />
            <!-- 节点微点 (置于最顶层，带清晰外边框，绝不被任何色块遮挡) -->
            <circle
              v-for="node in layoutData.nodes"
              :key="`mini-${node.id}`"
              :cx="100 + (node.x - cx) * 0.14"
              :cy="60 + (node.y - cy) * 0.14"
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
      >
        <div class="menu-header">
          <span class="menu-host">{{ contextMenu.node.host }}</span>
        </div>
        <div class="menu-item fluent-menu-item" @click="handleNodeClick(contextMenu.node!)">
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
          <span>{{ focusedDomain === contextMenu.node.rootDomain ? '取消聚焦同域' : '仅聚焦同主域资产' }}</span>
        </div>
        <a
          v-if="contextMenu.node.asset.url"
          :href="contextMenu.node.asset.url"
          target="_blank"
          rel="noopener noreferrer"
          class="menu-item fluent-menu-item link-item"
          @click="closeContextMenu"
        >
          <FluentIcon name="globe" :size="14" />
          <span>在新窗口打开</span>
        </a>
        <div class="menu-divider fluent-divider" />
        <div
          class="menu-item fluent-menu-item text-danger"
          @click="confirmRemoveNode(contextMenu.node!.id, contextMenu.node!.host)"
        >
          <FluentIcon name="delete" :size="14" />
          <span>移除该资产节点</span>
        </div>
      </div>
    </div>

    <!-- 资产深度详情抽屉 (Fluent Drawer) -->
    <el-drawer
      v-model="drawerVisible"
      title="资产详情"
      size="420px"
      direction="rtl"
      :append-to-body="true"
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

        <!-- 核心属性列表 -->
        <div class="detail-section">
          <h4 class="section-title">基础与网络信息</h4>
          <div class="detail-prop-row">
            <span class="prop-key">完整 URL:</span>
            <div class="prop-val url-val">
              <span class="url-text" :title="selectedAsset.url">{{ selectedAsset.url || '-' }}</span>
              <el-button
                link
                type="primary"
                size="small"
                @click="copyUrl(selectedAsset.url)"
              >
                <FluentIcon name="copy" :size="13" /> 复制
              </el-button>
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
            <span class="prop-val">{{ selectedAsset.detectedAt || selectedAsset.createdAt }}</span>
          </div>
        </div>

        <!-- 证据 / 指纹详情 -->
        <div v-if="selectedAsset.evidence || selectedAsset.technologies" class="detail-section">
          <h4 class="section-title">指纹与匹配证据</h4>
          <div class="evidence-box">
            <pre class="evidence-pre">{{
              typeof selectedAsset.evidence === 'string'
                ? selectedAsset.evidence
                : JSON.stringify(selectedAsset.evidence || selectedAsset.technologies, null, 2)
            }}</pre>
          </div>
        </div>

        <!-- 底部快捷操作条 -->
        <div class="drawer-actions">
          <el-button
            v-if="selectedAsset.url"
            tag="a"
            :href="selectedAsset.url"
            target="_blank"
            rel="noopener noreferrer"
            type="primary"
            plain
            class="fluent-action-btn"
          >
            在新窗口访问
          </el-button>
          <el-button
            type="danger"
            plain
            class="fluent-action-btn"
            @click="confirmRemoveNode(selectedAsset.id!, parseHost(selectedAsset.url).host)"
          >
            删除此资产节点
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
  min-height: 580px;
  background: var(--app-surface, #ffffff);
  border: 1px solid var(--app-border, #e2e8f0);
  border-radius: var(--fluent-radius-card, 8px);
  overflow: hidden;
  box-shadow: var(--fluent-shadow-4);
  font-family: var(--fluent-font);
}

.asset-topology-container.is-fullscreen {
  position: fixed;
  inset: 0;
  z-index: 2500;
  border-radius: 0;
  border: none;
}

/* 顶部 Fluent CommandBar 控制栏 */
.topology-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 14px;
  background: var(--app-surface-strong, #ffffff);
  border-bottom: 1px solid var(--app-border, #e2e8f0);
  z-index: 10;
  gap: 12px;
  flex-wrap: wrap;
}

.toolbar-left {
  display: flex;
  align-items: center;
}

.stats-pills {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

/* Fluent 胶囊标签 (Pills) */
.stat-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  background: var(--app-surface-soft, #f3f4f6);
  border: 1px solid transparent;
  border-radius: var(--fluent-radius-circular, 9999px);
  font-size: var(--fluent-caption1-size, 12px);
  color: var(--app-muted);
  cursor: pointer;
  transition: all var(--fluent-fast, 150ms ease);
  user-select: none;
}

.stat-pill:hover {
  background: var(--app-accent-soft, #e0f2fe);
  border-color: var(--fluent3-reveal-border, #bae6fd);
  color: var(--app-text);
}

.stat-pill.active {
  background: var(--app-accent-soft-strong, #bae6fd);
  border-color: var(--app-accent, #0078d4);
  color: var(--app-accent, #0078d4);
  font-weight: var(--fluent-weight-semibold, 600);
}

.focused-domain-tag {
  font-size: 11px;
  border-radius: var(--fluent-radius-control, 4px);
}

.stat-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
}

.dot-accent {
  background: var(--app-accent, #0078d4);
  box-shadow: 0 0 6px rgba(0, 120, 212, 0.4);
}

.dot-success {
  background: #107c41;
  box-shadow: 0 0 6px rgba(16, 124, 65, 0.4);
}

.dot-info {
  background: #00b7c3;
  box-shadow: 0 0 6px rgba(0, 183, 195, 0.4);
}

.dot-warning {
  background: #d83b01;
  box-shadow: 0 0 6px rgba(216, 59, 1, 0.4);
}

.stat-label {
  font-weight: var(--fluent-weight-regular, 400);
}

.stat-value {
  font-weight: var(--fluent-weight-semibold, 600);
  color: var(--app-text);
}

.toolbar-center {
  flex: 1;
  max-width: 240px;
}

.topology-search-input :deep(.el-input__wrapper) {
  border-radius: var(--fluent-radius-control, 4px);
}

.toolbar-right {
  display: flex;
  align-items: center;
  gap: 6px;
}

.mode-switch :deep(.el-radio-button__inner) {
  padding: 5px 10px;
  border-radius: var(--fluent-radius-control, 4px);
  font-size: var(--fluent-caption1-size, 12px);
}

.btn-inner {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.divider-v {
  width: 1px;
  height: 18px;
  background: var(--app-border, #e2e8f0);
  margin: 0 4px;
}

/* Fluent 控件组 */
.zoom-controls {
  display: flex;
  align-items: center;
  background: var(--app-surface-soft, #f3f4f6);
  border-radius: var(--fluent-radius-control, 4px);
  border: 1px solid var(--app-border, #e2e8f0);
  padding: 2px 4px;
  gap: 2px;
}

.zoom-level {
  font-size: var(--fluent-caption2-size, 11px);
  font-weight: var(--fluent-weight-semibold, 600);
  color: var(--app-muted);
  min-width: 38px;
  text-align: center;
  user-select: none;
}

/* Fluent Command 按钮规范 */
.fluent-command-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border: none;
  background: transparent;
  border-radius: var(--fluent-radius-control, 4px);
  color: var(--app-text);
  cursor: pointer;
  transition: all var(--fluent-fast, 150ms ease);
}

.fluent-command-btn:hover {
  background: var(--app-accent-soft, #f0fdf4);
  color: var(--app-accent, #0078d4);
}

.fluent-command-btn.active {
  background: var(--app-accent-soft-strong, #bae6fd);
  color: var(--app-accent, #0078d4);
}

.fluent-command-btn.compact {
  width: 22px;
  height: 22px;
}

.sonar-btn.active {
  color: #d83b01;
  background: #fff7ed;
  animation: pulseRotate 1s infinite;
}

@keyframes pulseRotate {
  0% { transform: scale(1); }
  50% { transform: scale(1.15); }
  100% { transform: scale(1); }
}

/* 画布容器 */
.topology-canvas-wrap {
  position: relative;
  flex: 1;
  width: 100%;
  height: 100%;
  overflow: hidden;
  user-select: none;
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
  background: var(--app-surface-soft);
  backdrop-filter: blur(4px);
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

/* 环轨样式 */
.orbit-circle {
  fill: none;
  stroke: var(--app-border, #cbd5e1);
  stroke-width: 1;
  opacity: 0.6;
}

.orbit-circle.dashed {
  stroke-dasharray: 4 4;
}

/* 声呐雷达波纹 */
.sonar-wave {
  fill: none;
  stroke: var(--app-accent, #0078d4);
  stroke-width: 2;
  opacity: 0.8;
  animation: sonarPing 2.2s cubic-bezier(0, 0.2, 0.8, 1) infinite;
  pointer-events: none;
}

.sonar-wave.wave-2 {
  animation-delay: 0.6s;
}

.sonar-wave.wave-3 {
  animation-delay: 1.2s;
}

@keyframes sonarPing {
  0% {
    r: 10px;
    opacity: 0.9;
    stroke-width: 3;
  }
  100% {
    r: 520px;
    opacity: 0;
    stroke-width: 1;
  }
}

/* 连接线样式：严格处于底层，绝不遮盖卡片上的字 */
.edge-base-line {
  fill: none;
  stroke: var(--app-border, #cbd5e1);
  stroke-width: 1.4;
  stroke-linecap: round;
  transition: all var(--fluent-fast);
}

.edge-flow-line {
  fill: none;
  stroke: url(#linkGradient);
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-dasharray: 6 12;
  opacity: 0.5;
  transition: all var(--fluent-fast);
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

.edge-group.is-sonar-active .edge-flow-line {
  stroke: url(#linkHighlight);
  stroke-width: 3;
  opacity: 1;
  animation: cyberFlow 0.8s linear infinite;
}

.edge-group.is-hovered .edge-base-line,
.edge-group.is-selected .edge-base-line {
  stroke: var(--app-accent, #0078d4);
  stroke-width: 2.2;
}

.edge-group.is-hovered .edge-flow-line,
.edge-group.is-selected .edge-flow-line {
  stroke: url(#linkHighlight);
  stroke-width: 2.8;
  opacity: 1;
}

/* 真实物理端点端口 (Connection Sockets)，彻底告别悬空假连 */
.edge-port-dot {
  fill: var(--app-surface-strong, #ffffff);
  stroke: var(--app-border, #cbd5e1);
  stroke-width: 1.4;
  transition: all var(--fluent-fast);
}

.port-target {
  fill: var(--app-surface-strong, #ffffff);
  stroke: var(--app-accent, #0078d4);
}

.edge-group.is-hovered .edge-port-dot,
.edge-group.is-selected .edge-port-dot {
  fill: var(--app-accent, #0078d4);
  stroke: #ffffff;
  stroke-width: 1.5;
}

/* ==================== 中心宿主 Fluent Command Core 卡片 ==================== */
.topology-hub-node {
  cursor: default;
}

.hub-glow-halo {
  fill: none;
  stroke: var(--app-accent, #0078d4);
  stroke-width: 1.5;
  opacity: 0.3;
  animation: hubPulseGlow 3.6s ease-in-out infinite;
  pointer-events: none;
}

@keyframes hubPulseGlow {
  0% { opacity: 0.2; stroke-width: 1.5; }
  50% { opacity: 0.55; stroke-width: 3; }
  100% { opacity: 0.2; stroke-width: 1.5; }
}

.hub-card-bg {
  fill: var(--app-surface-strong, #ffffff);
  stroke: var(--app-accent, #0078d4);
  stroke-width: 1.8;
  transition: all var(--fluent-fast);
}

.topology-hub-node:hover .hub-card-bg {
  stroke: var(--fluent3-reveal-border, #0078d4);
  stroke-width: 2.2;
  filter: drop-shadow(0 6px 20px rgba(0, 120, 212, 0.32));
}

.hub-icon-base {
  fill: var(--app-accent, #0078d4);
}

.hub-title-text {
  fill: var(--app-text, #0f172a);
  font-size: 14px;
  font-weight: var(--fluent-weight-semibold, 600);
  font-family: var(--fluent-font);
  letter-spacing: -0.01em;
  pointer-events: none;
}

.hub-status-dot {
  fill: #107c41; /* Fluent Success Green */
  animation: dotPulse 2s infinite;
}

@keyframes dotPulse {
  0% { opacity: 0.6; }
  50% { opacity: 1; }
  100% { opacity: 0.6; }
}

.hub-subtitle-text {
  fill: var(--app-muted, #64748b);
  font-size: 11px;
  font-weight: var(--fluent-weight-regular, 400);
  font-family: var(--fluent-font);
  pointer-events: none;
}

/* ==================== Fluent 2 资产节点微卡片 ==================== */
.node-card-group {
  cursor: grab;
  transition: opacity var(--fluent-fast);
}

.node-card-group:active {
  cursor: grabbing;
}

.node-card-bg {
  fill: var(--app-surface-strong, #ffffff);
  stroke: var(--app-border, #cbd5e1);
  stroke-width: 1.2;
  transition: all var(--fluent-fast);
}

/* Fluent 3 Reveal 悬停效果 */
.node-card-group:hover .node-card-bg {
  stroke: var(--fluent3-reveal-border, #0078d4);
  stroke-width: 1.6;
  fill: var(--fluent3-reveal-bg, #f8fafc);
  filter: drop-shadow(0 6px 16px rgba(0, 120, 212, 0.16));
}

.node-card-group.is-selected .node-card-bg {
  stroke: var(--app-accent, #0078d4);
  stroke-width: 2;
  fill: var(--app-accent-soft, #eff6ff);
  filter: drop-shadow(0 0 10px rgba(0, 120, 212, 0.3));
}

.node-card-group.is-sonar-pinged .node-card-bg {
  stroke: #00b7c3;
  filter: drop-shadow(0 0 12px rgba(0, 183, 195, 0.5));
}

.node-card-group.is-dimmed {
  opacity: 0.2;
}

/* Fluent 3 Selection Slider (垂直居中 3px 胶囊滑块，严格符合规范) */
.node-selection-slider {
  fill: var(--fluent3-slider-accent, var(--app-accent, #0078d4));
  opacity: 0;
  transform: scaleY(0.4);
  transform-origin: left center;
  transition:
    opacity var(--fluent-fast),
    transform var(--fluent3-slider-ease, 220ms cubic-bezier(0.2, 0.8, 0.2, 1));
}

.node-card-group:hover .node-selection-slider {
  opacity: 0.6;
  transform: scaleY(0.75);
}

.node-card-group.is-selected .node-selection-slider {
  opacity: 1;
  transform: scaleY(1);
}

/* 图标容器小方块 */
.node-icon-box {
  transition: fill var(--fluent-fast);
}

.box-https {
  fill: #107c41;
}

.box-http {
  fill: var(--app-accent, #0078d4);
}

/* 域名标题：清晰字阶，绝不重叠 */
.node-title-text {
  fill: var(--app-text, #0f172a);
  font-size: 12px;
  font-weight: var(--fluent-weight-semibold, 600);
  font-family: var(--fluent-font);
  pointer-events: none;
}

.node-tag-bg {
  fill: var(--app-surface-soft, #f1f5f9);
}

.node-tag-bg.tag-waf {
  fill: #fff4ce; /* Fluent Light Orange */
}

.node-tag-text {
  fill: var(--app-muted, #64748b);
  font-size: 9px;
  font-weight: var(--fluent-weight-semibold, 600);
  font-family: var(--fluent-font);
  pointer-events: none;
}

.node-tag-bg.tag-waf + .node-tag-text {
  fill: #d83b01;
}

/* 快捷删除按钮 */
.node-action-delete {
  opacity: 0;
  transition: opacity var(--fluent-fast);
}

.node-card-group:hover .node-action-delete {
  opacity: 1;
}

.delete-btn-bg {
  fill: #d83b01;
  transition: fill var(--fluent-fast);
}

.node-action-delete:hover .delete-btn-bg {
  fill: #a80000;
  transform: scale(1.15);
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
  box-shadow: var(--fluent-shadow-16);
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
}

.minimap-viewfinder {
  fill: color-mix(in srgb, var(--app-accent, #0078d4) 14%, transparent);
  stroke: var(--app-accent, #0078d4);
  stroke-width: 1.2;
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
  background: var(--app-accent-soft, #f0f7ff);
  border-radius: var(--fluent-radius-card, 8px);
  border: 1px solid var(--app-border, #bfdbfe);
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
  border-left: 3px solid var(--app-accent, #0078d4);
  padding-left: 8px;
}

.detail-prop-row {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: var(--fluent-caption1-size, 12px);
}

.prop-key {
  color: var(--app-muted);
  min-width: 86px;
  flex-shrink: 0;
}

.prop-val {
  color: var(--app-text);
  word-break: break-all;
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
}

.url-text {
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.evidence-box {
  background: var(--app-surface-soft, #0f172a);
  border: 1px solid var(--app-border);
  border-radius: var(--fluent-radius-control, 4px);
  padding: 10px 12px;
  max-height: 200px;
  overflow-y: auto;
}

.evidence-pre {
  margin: 0;
  color: var(--app-text);
  font-size: 11px;
  font-family: "Cascadia Code", "Consolas", monospace;
  white-space: pre-wrap;
  word-break: break-all;
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

.fluent-action-btn {
  border-radius: var(--fluent-radius-control, 4px);
}
</style>
