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
import { ElMessage, ElMessageBox } from "element-plus";
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
} from "./components/fluentIcons";
import { useAuthStore } from "./stores/auth";
import { useConversationStore } from "./stores/conversations";
import { useEngineStore } from "./stores/engine";
import { AUTH_EXPIRED_EVENT } from "./authToken";
import { endpoints } from "./api";
import { toErrorMessage } from "./utils/errorMessage";
import { useSelectionIndicator } from "./composables/useSelectionIndicator";

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const conversations = useConversationStore();
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
    path.startsWith("/recon")
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
    ],
  },
  {
    id: "detection-analysis",
    label: "检测与分析",
    items: [
      { path: "/vulnerabilities", label: "主动检测", icon: markRaw(Aim) },
      { path: "/tasks", label: "检测任务", icon: markRaw(List) },
      { path: "/findings", label: "结果中心", icon: markRaw(Warning) },
      { path: "/traffic", label: "流量分析", icon: markRaw(Connection) },
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
      conversations.recent.some((item) => item.id === conversationId);
    return conversationOpen ? "" : "/";
  }
  if (route.path.startsWith("/workflow")) return "/workflow";
  if (route.path.startsWith("/targets")) return "/targets";
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
    () => conversations.recent.map((item) => item.id).join(","),
    collapsedNavigationGroups,
  ],
  indicatorSelector: ".desktop-v2-recent-indicator",
  hidden: () => navigationGroupCollapsed("recent-work"),
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
  localStorage.removeItem("security_toolbox_setup_complete_v2");
  router.push("/setup");
}

function openConversation(id: string) {
  router.push({ path: "/", query: { conversation: id } });
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
    await endpoints.clearAgentSession(id);
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

onMounted(() => {
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
});

onBeforeUnmount(() => {
  window.removeEventListener(AUTH_EXPIRED_EVENT, handleAuthExpired);
  window.clearTimeout(workspaceRouteAnimationTimer);
  engine.stopPolling();
  nativeTooltipObserver?.disconnect();
  nativeTooltipObserver = undefined;
});
</script>

<template>
  <el-config-provider :locale="zhCn">
    <div
      class="desktop-v2-app-frame"
      :class="{ 'desktop-v2-native-frame': desktopMode }"
    >
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
              empty: !conversations.recent.length,
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
                  v-if="conversations.recent.length"
                  class="desktop-v2-recents-count"
                >
                  {{ conversations.recent.length }}
                </span>
                <el-icon
                  :class="{ collapsed: navigationGroupCollapsed('recent-work') }"
                  ><ArrowDown
                /></el-icon>
              </button>
              <button
                v-if="conversations.recent.length"
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
              :aria-hidden="navigationGroupCollapsed('recent-work')"
              :inert="navigationGroupCollapsed('recent-work')"
            >
              <span
                class="fluent-selection-indicator desktop-v2-recent-indicator"
                aria-hidden="true"
              />
              <div
                v-if="!conversations.recent.length"
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
                v-for="conversation in conversations.recent"
                :key="conversation.id"
                class="desktop-v2-recent-item"
                :class="{
                  active: route.query.conversation === conversation.id,
                }"
              >
                <button
                  type="button"
                  class="desktop-v2-recent-open"
                  @click="openConversation(conversation.id)"
                >
                  <el-icon><ChatDotRound /></el-icon>
                  <span>
                    <strong>{{ conversation.title }}</strong>
                    <small
                      >{{ conversation.targetName }} ·
                      {{
                        conversations.taskIds(conversation).length
                      }}
                      个任务</small
                    >
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
