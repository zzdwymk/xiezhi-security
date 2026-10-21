<script setup lang="ts">
import {
  computed,
  markRaw,
  nextTick,
  onBeforeUnmount,
  onMounted,
  ref,
  watch,
} from "vue";
import { useRoute, useRouter } from "vue-router";
import zhCn from "element-plus/es/locale/lang/zh-cn";
import { ElMessage, ElMessageBox, ElNotification } from "element-plus";
import {
  Aim,
  ArrowDown,
  ChatDotRound,
  Connection,
  Delete,
  HomeFilled,
  List,
  Location,
  Plus,
  Setting,
  Share,
  SwitchButton,
  Tickets,
  Tools,
  FolderOpened,
  Warning,
  DataAnalysis,
} from "./components/fluentIcons";
import { useAuthStore } from "./stores/auth";
import { useConversationStore } from "./stores/conversations";
import { conversationStatusBadge } from "./utils/aiStatus";
import { useEngineStore } from "./stores/engine";
import { AUTH_EXPIRED_EVENT, readAuthToken } from "./authToken";
import { endpoints } from "./api";
import { apiFetch, apiUrl, apiBaseUrl } from "./apiClient";
import { startNotificationFeed, type NotificationPage } from "./utils/notificationFeed";
import { createNotificationDelivery } from "./utils/notificationDelivery";
import { notificationRoute, setNotificationDispatcher } from "./utils/notifications";
import { aiToolLabel, displayKnownTestName, displayConversationTitle } from "./utils/aiPresentation";
import { toErrorMessage } from "./utils/errorMessage";
import { useSelectionIndicator } from "./composables/useSelectionIndicator";
import { taskbarProgress } from "./utils/taskbarProgress";

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const conversations = useConversationStore();
// This limits mounted sidebar rows; the existing store still reads full history.
const CONVERSATION_PAGE_SIZE = 8;
const CONVERSATION_PREFETCH_MARGIN = 280;
const visibleConversationLimit = ref(CONVERSATION_PAGE_SIZE);
const loadingMoreConversations = ref(false);
const visibleConversations = computed(() =>
  conversations.items.slice(0, visibleConversationLimit.value),
);
const conversationCount = computed(() => conversations.items.length);
const hasMoreConversations = computed(() =>
  visibleConversations.value.length < conversationCount.value,
);
const engine = useEngineStore();
const sidebarWidth = ref(
  Number(localStorage.getItem("security_toolbox_sidebar_width_v1")) || 260,
);
const resizingSidebar = ref(false);
let resizeStartX = 0;
let resizeStartWidth = 260;

const COLLAPSED_NAVIGATION_GROUPS_KEY =
  "security_toolbox_collapsed_navigation_groups_v1";
const primaryNavigationGroupIds = [
  "ai-workspace",
  "projects-assets",
  "detection-analysis",
  "system-audit",
];

function navigationGroupForPath(path: string) {
  if (path.startsWith("/workflow") || path === "/") return "ai-workspace";
  if (
    path.startsWith("/projects") ||
    path.startsWith("/targets") ||
    path.startsWith("/recon") ||
    path.startsWith("/assets/topology")
  )
    return "projects-assets";
  if (
    path.startsWith("/vulnerabilities") ||
    path.startsWith("/tasks") ||
    path.startsWith("/findings") ||
    path.startsWith("/traffic")
  )
    return "detection-analysis";
  if (
    path.startsWith("/audits") ||
    path.startsWith("/offline-tools") ||
    path.startsWith("/settings")
  )
    return "system-audit";
  return "ai-workspace";
}

function defaultCollapsedNavigationGroups() {
  const activeGroup = navigationGroupForPath(route.path);
  return new Set(
    primaryNavigationGroupIds.filter((groupId) => groupId !== activeGroup),
  );
}

function storedCollapsedNavigationGroups() {
  const saved = localStorage.getItem(COLLAPSED_NAVIGATION_GROUPS_KEY);
  if (saved === null) return defaultCollapsedNavigationGroups();
  try {
    const value = JSON.parse(saved);
    return new Set<string>(
      Array.isArray(value)
        ? value.filter((item) => typeof item === "string")
        : [],
    );
  } catch {
    return defaultCollapsedNavigationGroups();
  }
}

const collapsedNavigationGroups = ref(storedCollapsedNavigationGroups());
let trackPrimaryNavigationLayout = () => {};

function persistCollapsedNavigationGroups(
  groups = collapsedNavigationGroups.value,
) {
  localStorage.setItem(
    COLLAPSED_NAVIGATION_GROUPS_KEY,
    JSON.stringify([...groups]),
  );
}

watch(
  () => route.path,
  (path) => {
    const activeGroup = navigationGroupForPath(path);
    if (!collapsedNavigationGroups.value.has(activeGroup)) return;
    const next = new Set(collapsedNavigationGroups.value);
    next.delete(activeGroup);
    collapsedNavigationGroups.value = next;
    persistCollapsedNavigationGroups(next);
    void nextTick(() => trackPrimaryNavigationLayout());
  },
  { immediate: true },
);

watch(
  sidebarWidth,
  (value) => {
    document.documentElement.style.setProperty(
      "--desktop-sidebar-width",
      `${value}px`,
    );
  },
  { immediate: true },
);

function startSidebarResize(event: PointerEvent) {
  resizingSidebar.value = true;
  resizeStartX = event.clientX;
  resizeStartWidth = sidebarWidth.value;
  window.addEventListener("pointermove", resizeSidebar);
  window.addEventListener("pointerup", stopSidebarResize, { once: true });
  document.body.classList.add("sidebar-resizing");
  (event.currentTarget as HTMLElement)?.setPointerCapture?.(event.pointerId);
}

function resizeSidebar(event: PointerEvent) {
  if (!resizingSidebar.value) return;
  sidebarWidth.value = Math.min(
    420,
    Math.max(210, resizeStartWidth + event.clientX - resizeStartX),
  );
}

function stopSidebarResize() {
  if (!resizingSidebar.value) return;
  resizingSidebar.value = false;
  localStorage.setItem(
    "security_toolbox_sidebar_width_v1",
    String(sidebarWidth.value),
  );
  window.removeEventListener("pointermove", resizeSidebar);
  document.body.classList.remove("sidebar-resizing");
}

function navigationGroupCollapsed(groupId: string) {
  return collapsedNavigationGroups.value.has(groupId);
}

function toggleNavigationGroup(groupId: string) {
  const next = new Set(collapsedNavigationGroups.value);
  if (next.has(groupId)) next.delete(groupId);
  else next.add(groupId);
  collapsedNavigationGroups.value = next;
  persistCollapsedNavigationGroups(next);
  void nextTick(() => trackPrimaryNavigationLayout());
}

const title = computed(() => (route.meta.title as string) || "安全工作台");
const roleName = computed(() =>
  auth.user?.role === "ADMIN" ? "管理员" : "用户",
);
const contextLabel = computed(() =>
  route.path.startsWith("/offline-tools")
    ? "输入仅在本机处理"
    : "仅处理授权目标",
);
const desktopMode = computed(() =>
  Boolean(
    window.toolboxDesktop?.isDesktop ||
      new URLSearchParams(window.location.search).get("desktop") === "1",
  ),
);

const navigationGroups = [
  {
    id: "ai-workspace",
    label: "AI 工作区",
    items: [
      { path: "/", label: "AI 安全助手", icon: markRaw(HomeFilled) },
      { path: "/workflow", label: "红队工作流", icon: markRaw(Share) },
    ],
  },
  {
    id: "projects-assets",
    label: "项目与资产",
    items: [
{ path: "/projects", label: "评估项目", icon: markRaw(FolderOpened) },
      { path: "/targets", label: "授权目标", icon: markRaw(Location) },
      {
        path: "/assets/topology",
        label: "资产拓扑",
        icon: markRaw(DataAnalysis),
      },
    ],
  },
  {
    id: "detection-analysis",
    label: "检测与分析",
    items: [
      { path: "/vulnerabilities", label: "主动检测", icon: markRaw(Aim) },
      { path: "/traffic", label: "流量分析", icon: markRaw(Connection) },
      { path: "/tasks", label: "检测任务", icon: markRaw(List) },
      { path: "/findings", label: "安全发现", icon: markRaw(Warning) },
    ],
  },
  {
    id: "system-audit",
    label: "系统与审计",
    items: [
      { path: "/audits", label: "审计日志", icon: markRaw(Tickets) },
      { path: "/offline-tools", label: "离线工具集", icon: markRaw(Tools) },
    ],
  },
];

const activeNavigation = computed(() => {
  if (route.path === "/") {
    const conversationId = route.query.conversation;
    const conversationOpen =
      typeof conversationId === "string" &&
      conversations.items.some((item) => item.id === conversationId);
    return conversationOpen ? "" : "/";
  }
  if (route.path.startsWith("/workflow")) return "/workflow";
  if (route.path.startsWith("/targets")) return "/targets";
  if (route.path.startsWith("/assets/topology")) return "/assets/topology";
  if (route.path.startsWith("/projects") && route.query.tab === "recon")
    return "/projects";
  if (route.path.startsWith("/recon")) return "/projects";
  if (route.path.startsWith("/projects")) return "/projects";
  if (route.path.startsWith("/traffic")) return "/traffic";
  if (route.path.startsWith("/vulnerabilities")) return "/vulnerabilities";
  if (route.path.startsWith("/tasks")) return "/tasks";
  if (route.path.startsWith("/findings")) return "/findings";
  if (route.path.startsWith("/audits")) return "/audits";
  if (route.path.startsWith("/offline-tools")) return "/offline-tools";
  return "";
});

const primaryNavigation = ref<HTMLElement | null>(null);
const recentNavigation = ref<HTMLElement | null>(null);
const sidebarNavigationScroll = ref<HTMLElement | null>(null);
const workspaceRouteAnimating = ref(false);
let workspaceRouteSequence = 0;
let workspaceRouteAnimationTimer = 0;

const primarySelectionIndicator = useSelectionIndicator({
    container: primaryNavigation,
    activeSelector: ".desktop-v2-nav-item.active",
    dependencies: [activeNavigation, collapsedNavigationGroups],
    scrollContainers: [sidebarNavigationScroll],
    indicatorSelector: ".desktop-v2-nav-indicator",
    hidden: () =>
      Boolean(
        primaryNavigation.value
          ?.querySelector<HTMLElement>(".desktop-v2-nav-item.active")
          ?.closest<HTMLElement>(".desktop-v2-nav-group")
          ?.classList.contains("collapsed"),
      ),
  });
trackPrimaryNavigationLayout =
  primarySelectionIndicator.trackSelectionIndicatorLayout;

useSelectionIndicator({
  container: recentNavigation,
  activeSelector: ".desktop-v2-recent-item.active",
  dependencies: [
    () => route.query.conversation,
    () => visibleConversations.value.map((item) => item.id).join(","),
    collapsedNavigationGroups,
  ],
  indicatorSelector: ".desktop-v2-recent-indicator",
  scrollContainers: [sidebarNavigationScroll, recentNavigation],
  hidden: () => navigationGroupCollapsed("recent-work"),
});

const conversationLoadSentinel = ref<HTMLElement | null>(null);
let conversationPreloadFrame = 0;
let conversationPreloadMounted = false;
let conversationIntersectionObserver: IntersectionObserver | undefined;
let conversationResizeObserver: ResizeObserver | undefined;

function queueConversationPreload() {
  if (!conversationPreloadMounted || conversationPreloadFrame || loadingMoreConversations.value
    || !hasMoreConversations.value || navigationGroupCollapsed("recent-work")) return;
  conversationPreloadFrame = window.requestAnimationFrame(() => {
    conversationPreloadFrame = 0;
    void preloadConversations();
  });
}

async function preloadConversations() {
  const container = recentNavigation.value;
  const sentinel = conversationLoadSentinel.value;
  if (!conversationPreloadMounted || loadingMoreConversations.value || !hasMoreConversations.value
    || navigationGroupCollapsed("recent-work") || !container || !sentinel || container.clientHeight <= 0) return;
  const remaining = sentinel.getBoundingClientRect().top - container.getBoundingClientRect().bottom;
  if (remaining > CONVERSATION_PREFETCH_MARGIN) return;
  loadingMoreConversations.value = true;
  try {
    visibleConversationLimit.value += CONVERSATION_PAGE_SIZE;
    await nextTick();
    await new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
  } finally {
    loadingMoreConversations.value = false;
  }
  // Recheck the new geometry: fill a short first screen plus the preload margin,
  // then stop until the user scrolls closer. Appending never moves focus/scroll.
  queueConversationPreload();
}

function observeConversationPreload() {
  conversationIntersectionObserver?.disconnect();
  conversationResizeObserver?.disconnect();
  const container = recentNavigation.value;
  const sentinel = conversationLoadSentinel.value;
  if (!conversationPreloadMounted || !container || !sentinel) return;
  conversationIntersectionObserver = new IntersectionObserver((entries) => {
    if (entries.some((entry) => entry.isIntersecting)) queueConversationPreload();
  }, { root: container, rootMargin: `0px 0px ${CONVERSATION_PREFETCH_MARGIN}px 0px`, threshold: 0 });
  conversationIntersectionObserver.observe(sentinel);
  conversationResizeObserver = new ResizeObserver(queueConversationPreload);
  conversationResizeObserver.observe(container);
  queueConversationPreload();
}

watch([recentNavigation, conversationLoadSentinel], observeConversationPreload, { flush: "post" });
watch(() => navigationGroupCollapsed("recent-work"), queueConversationPreload, { flush: "post" });
watch(conversationCount, queueConversationPreload, { flush: "post" });
onMounted(() => { conversationPreloadMounted = true; observeConversationPreload(); });
onBeforeUnmount(() => {
  conversationPreloadMounted = false;
  window.cancelAnimationFrame(conversationPreloadFrame);
  conversationIntersectionObserver?.disconnect();
  conversationResizeObserver?.disconnect();
});

watch(
  () => route.path,
  async () => {
    const sequence = ++workspaceRouteSequence;
    window.clearTimeout(workspaceRouteAnimationTimer);
    workspaceRouteAnimating.value = false;
    await nextTick();
    if (sequence !== workspaceRouteSequence) return;
    workspaceRouteAnimating.value = true;
    workspaceRouteAnimationTimer = window.setTimeout(() => {
      if (sequence === workspaceRouteSequence)
        workspaceRouteAnimating.value = false;
    }, 180);
  },
  { immediate: true },
);

function startNewTask() {
  router.push({ path: "/", query: {} });
}

function logout() {
  auth.logout();
  router.replace("/login");
}

function rerunSetup() {
  router.push({ path: "/setup", query: { redirect: route.fullPath } });
}

function openConversation(id: string) {
  const conversation = conversations.items.find((item) => item.id === id);
  const lastAssistant = [...(conversation?.messages || [])]
    .reverse()
    .find((message) => message.role === "assistant");
  if (
    conversation &&
    (lastAssistant?.status === "completed" || lastAssistant?.modelStreamStatus === "completed") &&
    !lastAssistant.completionSeen
  ) {
    conversations.updateMessage(conversation.id, lastAssistant.id, { completionSeen: true });
  }
  router.push({ path: "/", query: { conversation: id } });
}

function conversationStatus(conversation: any): { label: string; type: "running" | "completed" | "failed" } | null {
  const messages = conversation.messages || [];
  if (!messages.length) return null;
  const lastAssistant = [...messages].reverse().find((m: any) => m.role === "assistant");
  if (!lastAssistant) return null;
  // 传入真实的关联任务状态：仅凭消息自身的 stream 状态无法反映“回答已结束但检测任务仍在运行”，
  // 会导致正在进行中的会话在侧边栏没有任何标识。任务状态由 Dashboard 轮询后写入 store。
  const relatedTasks = (lastAssistant.taskIds || [])
    .map((id: number) => conversations.taskStates[id])
    .filter((task: any): task is NonNullable<typeof task> => Boolean(task));
  const badge = conversationStatusBadge(lastAssistant, relatedTasks, Date.now());
  if (badge && badge.type === "completed" && lastAssistant.completionSeen) return null;
  if (badge && badge.type === "running") {
    // 区分“模型仍在作答”与“回答已结束、仅检测任务仍在排队/执行”，让侧边栏标签更准确。
    const modelStreaming =
      lastAssistant.modelStreamStatus === "running" ||
      ["sending", "planning", "running", "answering"].includes(lastAssistant.status);
    const taskActive = relatedTasks.some(
      (task: any) => !["SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "SKIPPED"].includes(task.status),
    );
    if (!modelStreaming && taskActive) return { label: "任务进行中", type: "running" };
  }
  return badge;
}

// 侧边栏会话标识依赖任务实时状态。Dashboard 派发任务后会轮询任务列表并写入 store，
// 但切换到其它路由时 Dashboard 会卸载、轮询停止。这里在应用外壳上做一次轻量补充轮询：
// 仅当存在尚未结束的关联任务时才拉取，保证侧边栏在任何页面都能反映“任务仍在进行中”。
const TASK_STATE_POLL_MS = 10_000;
let taskStatePollTimer: ReturnType<typeof setTimeout> | undefined;
let taskStatePolling = false;

async function refreshTaskStates() {
  if (taskStatePolling) return;
  const hasPending = conversations.items.some((conversation) =>
    (conversation.messages || []).some(
      (message: any) =>
        message.role === "assistant" &&
        (message.taskIds || []).some((id: number) => {
          const status = conversations.taskStates[id]?.status;
          return !status || !["SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "SKIPPED"].includes(status);
        }),
    ),
  );
  if (!hasPending) return;
  taskStatePolling = true;
  try {
    const token = readAuthToken();
    const response = await apiFetch(apiUrl("tasks"), {
      headers: token
        ? { Authorization: `Bearer ${token}`, Accept: "application/json" }
        : { Accept: "application/json" },
    });
    if (response.ok) {
      const list = (await response.json()) as Array<{
        id: number;
        toolCode: string;
        status: string;
        progressMessage?: string;
        errorMessage?: string;
        startedAt?: string;
        finishedAt?: string;
        createdAt: string;
      }>;
      if (Array.isArray(list)) conversations.setTaskStates(list);
    }
  } catch {
    // 任务状态补充轮询失败不打断界面；Dashboard 轮询仍会在会话页纠正。
  } finally {
    taskStatePolling = false;
  }
}

async function removeConversation(id: string) {
  try {
    await ElMessageBox.confirm(
      "删除这段本机对话记录？已经创建的检测任务不会被删除。",
      "删除对话",
      {
        confirmButtonText: "删除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  try {
    try {
      await endpoints.clearAgentSession(id);
    } catch {
      // 后端清理会话记忆尽力而为，不阻断前端本地对话的删除
    }
    conversations.remove(id);
    if (route.query.conversation === id) await router.replace("/");
    ElMessage.success("对话已删除");
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "删除对话失败，请稍后重试"));
  }
}

async function clearRecentConversations() {
  const sessionIds = conversations.items.map((conversation) => conversation.id);
  if (!sessionIds.length) return;
  try {
    await ElMessageBox.confirm(
      "将清空本机保存的全部最近对话，已经创建的检测任务不会被删除。",
      "清空最近对话",
      {
        confirmButtonText: "全部删除",
        cancelButtonText: "取消",
        type: "warning",
      },
    );
  } catch {
    return;
  }
  try {
    await Promise.all(
      sessionIds.map((sessionId) => endpoints.clearAgentSession(sessionId)),
    );
    conversations.clear();
    if (route.path === "/") await router.replace("/");
    ElMessage.success("最近对话已清空");
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "清空对话失败，请稍后重试"));
  }
}

function handleAuthExpired() {
  auth.clear();
}

const nativeTooltipSelector =
  'button[title], a[title], [role="button"][title], input[title], select[title], textarea[title]';
let nativeTooltipObserver: MutationObserver | undefined;

function migrateNativeTooltips(root: ParentNode) {
  root
    .querySelectorAll<HTMLElement>(nativeTooltipSelector)
    .forEach((element) => {
      const value = element.getAttribute("title")?.trim();
      if (!value) return;
      if (!element.getAttribute("aria-label"))
        element.setAttribute("aria-label", value);
      element.setAttribute("data-fluent-tooltip", value);
      element.removeAttribute("title");
    });
}

/* Hover bubbles are mounted on <body> (not on the element) so they are never
   clipped or covered by the overflow-clipped / rounded-corner containers inside
   the workspace — e.g. the left navigation rail that previously hid them. */
const TOOLTIP_SELECTOR = "[data-fluent-tooltip]";
let tooltipEl: HTMLDivElement | null = null;
let tooltipTarget: HTMLElement | null = null;
let tooltipListenersAttached = false;

function ensureTooltipElement(): HTMLDivElement {
  if (tooltipEl) return tooltipEl;
  const el = document.createElement("div");
  el.className = "fluent-hover-tooltip";
  Object.assign(el.style, {
    position: "fixed",
    // Very high so the bubble always renders above every Element Plus overlay /
    // popper / dialog (whose dynamic z-index can exceed 3000 inside nested
    // pop-ups). Re-parenting to <body> on every show keeps it last in DOM order.
    zIndex: "2147483000",
    maxWidth: "min(320px, calc(100vw - 16px))",
    padding: "6px 9px",
    pointerEvents: "none",
    boxSizing: "border-box",
    border: "1px solid var(--app-hover-popup-border)",
    borderRadius: "var(--fluent-radius-control)",
    background: "var(--app-hover-popup-bg)",
    boxShadow: "var(--fluent-overlay-shadow)",
    color: "var(--app-hover-popup-text)",
    fontFamily: "var(--fluent-font)",
    fontSize: "var(--fluent-caption1-size)",
    fontWeight: "var(--fluent-weight-regular)",
    lineHeight: "var(--fluent-caption1-line)",
    whiteSpace: "normal",
    opacity: "0",
    top: "0",
    left: "0",
    transition:
      "opacity var(--fluent-fast), transform var(--fluent-fast)",
  });
  document.body.appendChild(el);
  tooltipEl = el;
  return el;
}

function placeTooltip(target: HTMLElement) {
  if (!tooltipEl) return;
  const rect = target.getBoundingClientRect();
  const el = tooltipEl;
  const vw = window.visualViewport?.width ?? window.innerWidth;
  const vh = window.visualViewport?.height ?? window.innerHeight;
  const w = el.offsetWidth;
  const h = el.offsetHeight;

  // Catalog pane title bubbles open right-aligned off the button; all the
  // others are centered horizontally over the trigger (matching the old CSS).
  const inPaneTitle = Boolean(
    target.closest(".vuln-catalog-pane .pane-title"),
  );
  let left = inPaneTitle
    ? rect.right - w
    : rect.left + rect.width / 2 - w / 2;
  left = Math.max(8, Math.min(left, vw - w - 8));

  let top = rect.bottom + 8;
  const flipUp = top + h > vh - 8 && rect.top - h - 8 >= 8;
  if (flipUp) top = rect.top - h - 8;

  el.style.left = `${Math.round(left)}px`;
  el.style.top = `${Math.round(top)}px`;
  el.style.transform = "translateY(0)";
  el.style.opacity = "1";
}

function showFluentTooltip(target: HTMLElement) {
  const text = target.getAttribute("data-fluent-tooltip")?.trim();
  if (!text) return;
  const el = ensureTooltipElement();
  // Move to the end of <body> so the bubble paints above recently-opened
  // dialogs / dropdowns / popovers (which are also appended to <body>).
  document.body.appendChild(el);
  el.textContent = text;
  tooltipTarget = target;
  placeTooltip(target);
  // Re-measure once text/layout has settled without a frame glitch.
  requestAnimationFrame(() => placeTooltip(target));
}

function hideFluentTooltip() {
  if (tooltipEl) {
    tooltipEl.style.opacity = "0";
    tooltipEl.style.transform = "translateY(-2px)";
  }
  tooltipTarget = null;
}

function handleTooltipReposition() {
  if (tooltipTarget && tooltipEl) placeTooltip(tooltipTarget);
}

function onTooltipEnter(e: Event) {
  const target = (e.target as HTMLElement | null)?.closest<HTMLElement>(
    TOOLTIP_SELECTOR,
  );
  if (!target) return;
  const text = target.getAttribute("data-fluent-tooltip")?.trim();
  if (!text) return;
  if (target === tooltipTarget) return;
  showFluentTooltip(target);
}
function onTooltipLeave(e: Event) {
  const target = e.target as Node | null;
  const related = (e as PointerEvent).relatedTarget as Node | null;
  if (target && related && target.contains(related)) {
    // Moved to a descendant — keep showing.
    return;
  }
  hideFluentTooltip();
}

let stopNotifications: (() => void) | undefined;
let stopNotificationClick: (() => void) | undefined;
let notificationSession = 0;

function openNotificationDestination(value: string) {
  const destination = notificationRoute(value);
  if (!destination) return;
  if (router.currentRoute.value.fullPath === destination) {
    const resolved = router.resolve(destination);
    void router.push({ path: resolved.path, query: { ...resolved.query, _notice: String(Date.now()) } });
  } else void router.push(destination);
}

watch(
  [() => auth.token, () => auth.user?.username, () => route.matched.length > 0 && !route.meta.public],
  ([token, username, inWorkspace]) => {
    stopNotifications?.();
    stopNotifications = undefined;
    const session = ++notificationSession;
    ElNotification.closeAll();
    if (!token || !username || !inWorkspace) return;
    const cursorKey = `security_toolbox_notification_cursor_v1:${apiBaseUrl}:${username}`;
    const deliver = createNotificationDelivery({
      isCurrent: () => session === notificationSession,
      navigate: openNotificationDestination,
      present: (notice, open) => ElNotification({
        title: notice.title, message: notice.body,
        type: notice.outcome, position: "bottom-right", duration: 6000, onClick: open,
      }),
    });
    const unregister = setNotificationDispatcher(notice => deliver([notice]));
    const feed = startNotificationFeed({
      readCursor: () => {
        try {
          const stored = localStorage.getItem(cursorKey);
          const value = stored === null ? NaN : Number(stored);
          return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
        } catch { return undefined; }
      },
      saveCursor: cursor => { try { localStorage.setItem(cursorKey, String(cursor)); } catch { /* session cursor still advances */ } },
      fetchPage: async (after, signal) => {
        const query = new URLSearchParams({ limit: "100" });
        if (after !== undefined) query.set("after", String(after));
        const response = await apiFetch(apiUrl(`/notifications?${query}`), {
          signal, headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
        });
        if (!response.ok) throw new Error(`通知读取失败：${response.status}`);
        return await response.json() as NotificationPage;
      },
      deliver,
    });
    const resume = () => { void feed.poll(); };
    window.addEventListener("online", resume);
    window.addEventListener("focus", resume);
    stopNotifications = () => {
      feed.stop(); unregister();
      window.removeEventListener("online", resume);
      window.removeEventListener("focus", resume);
    };
  },
  { immediate: true },
);

let mouseMoveRaf = 0;
let lastRevealTarget: HTMLElement | null = null;

function onGlobalCursorMove(e: PointerEvent) {
  const clientX = e.clientX;
  const clientY = e.clientY;
  if (mouseMoveRaf) return;
  mouseMoveRaf = window.requestAnimationFrame(() => {
    mouseMoveRaf = 0;
    const x = Math.round(clientX);
    const y = Math.round(clientY);
    document.documentElement.style.setProperty("--fluent-cursor-x", `${x}px`);
    document.documentElement.style.setProperty("--fluent-cursor-y", `${y}px`);

    // Track relative coordinates on interactive target for Fluent Reveal Light Field
    const target = (document.elementFromPoint(x, y) as HTMLElement | null)?.closest?.(
      ".desktop-v2-nav-item, .desktop-v2-nav button, .desktop-v2-recent-item, .settings-row, .settings-list > button, .el-button, .report-card, .severity-legend__item, .severity-bar__seg, .start-action, .catalog-list button, .traffic-row, .quiet-icon-button, .workflow-node, .stat-pill, .el-segmented__item"
    ) as HTMLElement | null;

    if (target) {
      const rect = target.getBoundingClientRect();
      const relX = Math.round(x - rect.left);
      const relY = Math.round(y - rect.top);
      target.style.setProperty("--reveal-x", `${relX}px`);
      target.style.setProperty("--reveal-y", `${relY}px`);
      if (lastRevealTarget && lastRevealTarget !== target) {
        lastRevealTarget.style.removeProperty("--reveal-x");
        lastRevealTarget.style.removeProperty("--reveal-y");
      }
      lastRevealTarget = target;
    } else if (lastRevealTarget) {
      lastRevealTarget.style.removeProperty("--reveal-x");
      lastRevealTarget.style.removeProperty("--reveal-y");
      lastRevealTarget = null;
    }
  });
}

onMounted(() => {
  window.addEventListener("pointermove", onGlobalCursorMove, { passive: true });
  stopNotificationClick = window.toolboxDesktop?.onNotificationClick?.(openNotificationDestination);
  window.addEventListener(AUTH_EXPIRED_EVENT, handleAuthExpired);
  engine.startPolling();
  migrateNativeTooltips(document);
  nativeTooltipObserver = new MutationObserver((records) => {
    for (const record of records) {
      if (
        record.type === "attributes" &&
        record.target instanceof HTMLElement
      ) {
        migrateNativeTooltips(record.target.parentElement || document);
      }
      record.addedNodes.forEach((node) => {
        if (node instanceof HTMLElement) migrateNativeTooltips(node);
      });
    }
  });
  nativeTooltipObserver.observe(document.body, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ["title"],
  });

  if (!tooltipListenersAttached) {
    document.addEventListener("pointerover", onTooltipEnter, true);
    document.addEventListener("pointerout", onTooltipLeave, true);
    document.addEventListener("focusin", onTooltipEnter, true);
    document.addEventListener("focusout", onTooltipLeave, true);
    window.addEventListener("scroll", handleTooltipReposition, true);
    window.addEventListener("resize", handleTooltipReposition);
    window.addEventListener("blur", hideFluentTooltip);
    tooltipListenersAttached = true;
  }

  void refreshTaskStates();
  const scheduleTaskStatePoll = () => {
    taskStatePollTimer = setTimeout(async () => {
      await refreshTaskStates();
      scheduleTaskStatePoll();
    }, TASK_STATE_POLL_MS);
  };
  scheduleTaskStatePoll();
});

onBeforeUnmount(() => {
  window.removeEventListener("pointermove", onGlobalCursorMove);
  if (taskStatePollTimer) clearTimeout(taskStatePollTimer);
  if (mouseMoveRaf) window.cancelAnimationFrame(mouseMoveRaf);
  notificationSession += 1;
  stopNotifications?.();
  stopNotificationClick?.();
  window.removeEventListener(AUTH_EXPIRED_EVENT, handleAuthExpired);
  window.clearTimeout(workspaceRouteAnimationTimer);
  engine.stopPolling();
  taskbarProgress.clearAll();
  nativeTooltipObserver?.disconnect();
  nativeTooltipObserver = undefined;
  tooltipTarget = null;
  tooltipEl?.remove();
  tooltipEl = null;
});
</script>

<template>
  <el-config-provider :locale="zhCn">
    <div
      class="desktop-v2-app-frame"
      :class="{ 'desktop-v2-native-frame': desktopMode }"
    >
    <header
      v-if="desktopMode"
      class="desktop-v2-native-titlebar"
      aria-label="窗口标题栏"
    >
      <span>獬豸授权安全测试平台</span>
    </header>
    <router-view v-if="route.meta.public" />
    <div
      v-else
      class="desktop-v2-shell"
      :style="{ '--sidebar-width': `${sidebarWidth}px` }"
    >
      <aside
        id="desktop-v2-sidebar"
        class="desktop-v2-sidebar"
        :style="{ width: `${sidebarWidth}px` }"
      >
        <div class="desktop-v2-brand">
          <span class="desktop-v2-logo">
            <img src="./assets/xiezhi-mark.png" alt="" aria-hidden="true" />
          </span>
          <span class="desktop-v2-brand-copy">
            <strong>獬豸</strong>
            <small>授权安全测试平台</small>
          </span>
        </div>

        <button type="button" class="desktop-v2-new-task" @click="startNewTask">
          <el-icon><Plus /></el-icon>
          <span>新建对话</span>
        </button>

        <div ref="sidebarNavigationScroll" class="desktop-v2-sidebar-scroll">
          <nav
            id="desktop-v2-primary-navigation"
            ref="primaryNavigation"
            class="desktop-v2-nav"
            aria-label="主导航"
          >
            <span
              class="fluent-selection-indicator desktop-v2-nav-indicator"
              aria-hidden="true"
            />
            <section
              v-for="group in navigationGroups"
              :key="group.id"
              class="desktop-v2-nav-group"
              :class="{ collapsed: navigationGroupCollapsed(group.id) }"
              :aria-labelledby="`nav-group-${group.id}`"
            >
              <button
                :id="`nav-group-${group.id}`"
                type="button"
                class="desktop-v2-nav-group-toggle"
                :aria-controls="`nav-group-items-${group.id}`"
                :aria-expanded="!navigationGroupCollapsed(group.id)"
                @click="toggleNavigationGroup(group.id)"
              >
                <span>{{ group.label }}</span>
                <el-icon><ArrowDown /></el-icon>
              </button>
              <div
                :id="`nav-group-items-${group.id}`"
                class="desktop-v2-nav-group-items"
                :aria-hidden="navigationGroupCollapsed(group.id)"
                :inert="navigationGroupCollapsed(group.id)"
              >
                <div class="desktop-v2-nav-group-items-inner">
                  <button
                    v-for="item in group.items"
                    :key="item.path"
                    type="button"
                    class="desktop-v2-nav-item"
                    :class="{ active: activeNavigation === item.path }"
                    :aria-current="
                      activeNavigation === item.path ? 'page' : undefined
                    "
                    @click="router.push(item.path)"
                  >
                    <el-icon><component :is="item.icon" /></el-icon>
                    <span>{{ item.label }}</span>
                  </button>
                </div>
              </div>
            </section>
          </nav>

          <section
            class="desktop-v2-recents"
            :class="{
              collapsed: navigationGroupCollapsed('recent-work'),
              empty: !conversationCount,
            }"
            aria-label="最近对话区"
          >
            <div class="desktop-v2-recents-head">
              <button
                type="button"
                class="desktop-v2-recents-label desktop-v2-recents-toggle"
                aria-controls="desktop-v2-recents-list"
                :aria-expanded="!navigationGroupCollapsed('recent-work')"
                @click="toggleNavigationGroup('recent-work')"
              >
                <span class="desktop-v2-recents-title">最近对话</span>
                <span
                  v-if="conversationCount"
                  class="desktop-v2-recents-count"
                >
                  {{ conversationCount }}
                </span>
                <el-icon
                  :class="{ collapsed: navigationGroupCollapsed('recent-work') }"
                  ><ArrowDown
                /></el-icon>
              </button>
              <button
                v-if="conversationCount"
                type="button"
                class="desktop-v2-recents-clear is-danger"
                aria-label="清空最近对话"
                @click="clearRecentConversations"
              >
                <el-icon><Delete /></el-icon>
                <span>清空</span>
              </button>
            </div>
            <div
              id="desktop-v2-recents-list"
              ref="recentNavigation"
              class="desktop-v2-recents-list"
              role="region"
              aria-label="对话历史，可滚动自动加载"
              tabindex="0"
              :aria-busy="loadingMoreConversations"
              :data-prefetch-margin="CONVERSATION_PREFETCH_MARGIN"
              :data-page-size="CONVERSATION_PAGE_SIZE"
              @scroll.passive="queueConversationPreload"
              :aria-hidden="navigationGroupCollapsed('recent-work')"
              :inert="navigationGroupCollapsed('recent-work')"
            >
              <span
                class="fluent-selection-indicator desktop-v2-recent-indicator"
                aria-hidden="true"
              />
              <div
                v-if="!conversationCount"
                class="desktop-v2-recent-empty"
              >
                <span class="desktop-v2-recent-empty-icon"
                  ><el-icon><ChatDotRound /></el-icon
                ></span>
                <span>
                  <strong>暂无最近对话</strong>
                  <small>新建对话后会显示在这里</small>
                </span>
              </div>
              <div
                v-for="conversation in visibleConversations"
                :key="conversation.id"
                class="desktop-v2-recent-item"
                :class="{
                  active: route.query.conversation === conversation.id,
                }"
              >
                <button
                  type="button"
                  class="desktop-v2-recent-open"
                  :data-conversation-id="conversation.id"
                  :aria-current="route.query.conversation === conversation.id ? 'page' : undefined"
                  @click="openConversation(conversation.id)"
                >
                  <el-icon><ChatDotRound /></el-icon>
                  <span>
                    <strong>{{ displayConversationTitle(conversation) }}</strong>
                    <small>
                      <span>{{ displayKnownTestName(conversation.targetName) }} · {{ conversations.taskIds(conversation).length }} 个任务</span>
                      <span
                        v-if="conversationStatus(conversation)"
                        class="desktop-v2-conversation-tag"
                        :class="`tag--${conversationStatus(conversation)?.type}`"
                      >
                        <span v-if="conversationStatus(conversation)?.type === 'running'" class="tag-pulse-dot" />
                        {{ conversationStatus(conversation)?.label }}
                      </span>
                    </small>
                  </span>
                </button>
                <el-tooltip
                  content="删除对话"
                  placement="right"
                  :show-after="350"
                >
                  <button
                    type="button"
                    class="desktop-v2-recent-delete is-danger"
                    aria-label="删除对话"
                    @click="removeConversation(conversation.id)"
                  >
                    <el-icon><Delete /></el-icon>
                  </button>
                </el-tooltip>
              </div>
              <div v-if="conversationCount" class="desktop-v2-recents-pagination">
                <p class="desktop-v2-recents-status" role="status" aria-live="polite" aria-atomic="true">
                  <template v-if="loadingMoreConversations">正在加载更多对话…</template>
                  <template v-else-if="hasMoreConversations">已显示 {{ visibleConversations.length }} / {{ conversationCount }} 条对话，继续向下滚动</template>
                  <template v-else>已显示全部 {{ conversationCount }} 条对话</template>
                </p>
                <div
                  v-if="hasMoreConversations"
                  ref="conversationLoadSentinel"
                  class="desktop-v2-recents-sentinel"
                  aria-hidden="true"
                />
              </div>
            </div>
          </section>
        </div>

        <div class="desktop-v2-scope" :class="engine.status">
          <span class="desktop-v2-online-dot" />
          <span>
            <strong>{{
              engine.status === "checking"
                ? "正在检查本地引擎"
                : engine.isOnline
                  ? "本地引擎已连接"
                  : "本地引擎不可用"
            }}</strong>
            <small>{{
              engine.isOnline
                ? "授权边界保护已开启"
                : engine.status === "checking"
                  ? "正在请求健康接口"
                  : "本地健康接口无响应"
            }}</small>
          </span>
        </div>

        <el-dropdown
          trigger="click"
          placement="top-start"
          popper-class="desktop-v2-user-menu"
        >
          <button type="button" class="desktop-v2-user">
            <span class="desktop-v2-avatar">{{
              (auth.user?.username || "U").slice(0, 1).toUpperCase()
            }}</span>
            <span class="desktop-v2-user-copy">
              <strong>{{ auth.user?.username || "用户" }}</strong>
              <small>{{ roleName }}</small>
            </span>
            <el-icon><ArrowDown /></el-icon>
          </button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item disabled>
                当前环境：{{ desktopMode ? "桌面端" : "网页端" }}
              </el-dropdown-item>
              <el-dropdown-item @click="router.push('/settings')">
                <el-icon><Setting /></el-icon>系统设置
              </el-dropdown-item>
              <el-dropdown-item @click="rerunSetup"
                >重新检测系统依赖</el-dropdown-item
              >
              <el-dropdown-item
                divided
                class="desktop-v2-logout-item"
                @click="logout"
              >
                <el-icon><SwitchButton /></el-icon>注销登录
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
        <div
          class="desktop-v2-sidebar-resizer"
          role="separator"
          aria-label="调整导航栏宽度"
          aria-orientation="vertical"
          :aria-valuenow="sidebarWidth"
          tabindex="0"
          @pointerdown="startSidebarResize"
        />
      </aside>

      <section class="desktop-v2-workspace">
        <header class="desktop-v2-topbar">
          <div class="desktop-v2-title">
            <strong>{{ title }}</strong>
          </div>
          <div class="desktop-v2-context">
            <template v-if="desktopMode">
              <span>桌面工作区</span>
              <span class="desktop-v2-context-separator" />
            </template>
            <span>{{ contextLabel }}</span>
          </div>
        </header>

        <main
          class="desktop-v2-content"
          :class="{ 'is-route-entering': workspaceRouteAnimating }"
        >
          <router-view v-slot="{ Component, route: viewRoute }">
            <component :is="Component" :key="viewRoute.path" />
          </router-view>
        </main>
      </section>
    </div>
    </div>
  </el-config-provider>
</template>
