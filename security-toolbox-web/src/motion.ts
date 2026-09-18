/**
 * 界面动画偏好（按区域独立开关）。
 *
 * 每个区域对应一个布尔开关，关闭时在 <html> 上写入对应 data-* 属性，
 * 由 motion.css 依据这些属性把相应动画置为关闭；启动页则由 main 进程把
 * 两个启动相关区域注入 startup.html 根节点。
 *
 * 默认跟随系统“减少动态效果”：无桌面桥时，当系统启用减少动态效果时关闭
 * 全部动画；存在桌面桥时以持久化设置（记录在 desktop-settings.json）为准，
 * 初始值由 main 进程在首次启动时按系统设置写入。
 */
export type MotionArea = keyof MotionAreaFlags;
type Writable<T> = { -readonly [K in keyof T]: T[K] };
export type MutableMotionAreaFlags = Writable<MotionAreaFlags>;

const MOTION_KEY = "security_toolbox_motion_v1";

/** <html> 上用于关闭各区域动画的属性名。 */
const MOTION_ATTRIBUTE_BY_AREA: Record<MotionArea, string> = {
  startProgress: "data-anim-start-progress",
  startPulse: "data-anim-start-pulse",
  loader: "data-anim-loader",
  decorative: "data-anim-decorative",
};

const DEFAULT_FLAGS: MotionAreaFlags = {
  startProgress: true,
  startPulse: true,
  loader: true,
  decorative: true,
};

let activeFlags: MotionAreaFlags = { ...DEFAULT_FLAGS };

function osReducesMotion() {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

function systemBaseline(): MotionAreaFlags {
  const reduce = osReducesMotion();
  return reduce
    ? {
        startProgress: false,
        startPulse: false,
        loader: false,
        decorative: false,
      }
    : { ...DEFAULT_FLAGS };
}

function getStoredFlags(): MotionAreaFlags | null {
  try {
    const raw = localStorage.getItem(MOTION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<MotionAreaFlags>;
    return {
      startProgress: Boolean(parsed.startProgress),
      startPulse: Boolean(parsed.startPulse),
      loader: Boolean(parsed.loader),
      decorative: Boolean(parsed.decorative),
    };
  } catch {
    return null;
  }
}

function applyFlags(flags: MotionAreaFlags) {
  activeFlags = flags;
  const root = document.documentElement;
  for (const area of Object.keys(MOTION_ATTRIBUTE_BY_AREA) as MotionArea[]) {
    root.dataset[attributeKey(area)] = flags[area] ? "on" : "off";
  }
}

function attributeKey(area: MotionArea): string {
  // data-anim-load  -> "animLoad", data-anim-decorative -> "animDecorative" …
  return MOTION_ATTRIBUTE_BY_AREA[area].replace(/^data-/, "").replace(
    /-([a-z0-9])/gi,
    (_match, ch) => String(ch).toUpperCase(),
  );
}

export async function getMotionSettings(): Promise<MotionAreaFlags> {
  const bridge = window.toolboxDesktop;
  if (bridge?.getMotionSettings) {
    try {
      const flags = await bridge.getMotionSettings();
      apply(flags);
      return activeFlags;
    } catch {
      // Fall back to stored/local source
    }
  }
  apply(getStoredFlags() ?? systemBaseline());
  return activeFlags;
}

function normalize(flags: Partial<MotionAreaFlags>): MotionAreaFlags {
  return {
    startProgress: Boolean(flags.startProgress),
    startPulse: Boolean(flags.startPulse),
    loader: Boolean(flags.loader),
    decorative: Boolean(flags.decorative),
  };
}

export async function setMotionSettings(
  flags: Partial<MotionAreaFlags>,
): Promise<MotionAreaFlags> {
  const normalized = normalize(flags);
  try {
    localStorage.setItem(MOTION_KEY, JSON.stringify(normalized));
  } catch {
    // Ignore storage quota or disabled storage
  }

  const bridge = window.toolboxDesktop;
  if (bridge?.setMotionSettings) {
    try {
      const saved = await bridge.setMotionSettings(normalized);
      apply(saved);
      return activeFlags;
    } catch {
      // 桌面保存失败时仍应用本地值
    }
  }
  apply(normalized);
  return activeFlags;
}

function apply(flags: MotionAreaFlags) {
  if (typeof document === "undefined") return;
  applyFlags(flags);
}

export function initializeMotion(): Promise<MotionAreaFlags> {
  // 首帧先用本地/系统基线，避免闪动，再异步读取持久化设置覆盖。
  const baseline =
    typeof window !== "undefined" ? (getStoredFlags() ?? systemBaseline()) : { ...DEFAULT_FLAGS };
  applyFlags(baseline);
  return getMotionSettings().catch(() => baseline);
}