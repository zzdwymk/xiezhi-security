// 资产拓扑视图设置的本地持久化。
// 全局偏好（布局模式、连接动画、缩略图）与按项目的节点自定义位置分开存储，
// 使用 localStorage 保证刷新与关闭浏览器后依然生效。

type LayoutMode = "orbit" | "tree" | "mindmap";

const PREFS_KEY = "topology.globalPrefs.v1";
const POSITIONS_PREFIX = "topology.nodePositions.v1.project.";

interface TopologyGlobalPrefs {
  layoutMode?: LayoutMode;
  enableFlowAnim: boolean;
  showMinimap: boolean;
}

function safeRead<T>(key: string, fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return fallback;
    return { ...fallback, ...JSON.parse(raw) } as T;
  } catch {
    return fallback;
  }
}

function safeWrite(key: string, value: unknown) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // 存储不可用或已满时静默降级，不阻塞交互。
  }
}

export function loadGlobalPrefs(): TopologyGlobalPrefs {
  return safeRead<TopologyGlobalPrefs>(PREFS_KEY, {
    enableFlowAnim: false,
    showMinimap: false,
  });
}

export function saveGlobalPrefs(prefs: TopologyGlobalPrefs) {
  safeWrite(PREFS_KEY, prefs);
}

export function loadNodePositions(
  projectId: number | string,
): Record<string | number, { x: number; y: number }> {
  return safeRead<Record<string | number, { x: number; y: number }>>(
    `${POSITIONS_PREFIX}${projectId}`,
    {},
  );
}

export function saveNodePositions(
  projectId: number | string,
  positions: Record<string | number, { x: number; y: number }>,
) {
  safeWrite(`${POSITIONS_PREFIX}${projectId}`, positions);
}

export function clearNodePositions(projectId: number | string) {
  try {
    window.localStorage.removeItem(`${POSITIONS_PREFIX}${projectId}`);
  } catch {
    // 忽略不可用的存储。
  }
}