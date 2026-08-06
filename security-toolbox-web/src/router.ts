import {
  createRouter,
  createWebHashHistory,
  createWebHistory,
} from "vue-router";
import { useAuthStore } from "./stores/auth";

const Dashboard = () => import("./views/Dashboard.vue");
const Targets = () => import("./views/Targets.vue");
const Tasks = () => import("./views/Tasks.vue");
const Findings = () => import("./views/Findings.vue");
const DataPage = () => import("./views/DataPage.vue");
const Login = () => import("./views/Login.vue");
const Setup = () => import("./views/Setup.vue");
const Vulnerabilities = () => import("./views/Vulnerabilities.vue");
const Traffic = () => import("./views/Traffic.vue");
const Settings = () => import("./views/Settings.vue");
const OfflineTools = () => import("./views/OfflineTools.vue");
const Projects = () => import("./views/Projects.vue");
const ProjectDetail = () => import("./views/ProjectDetail.vue");
const Recon = () => import("./views/Recon.vue");
const Workflow = () => import("./views/Workflow.vue");

const SETUP_KEY = "security_toolbox_setup_complete_v2";
const desktopMode =
  window.toolboxDesktop?.isDesktop ||
  new URLSearchParams(window.location.search).get("desktop") === "1";
const history = desktopMode ? createWebHashHistory() : createWebHistory();
let desktopInitialNavigation = true;

const router = createRouter({
  history,
  routes: [
    {
      path: "/setup",
      component: Setup,
      meta: { public: true, title: "环境依赖检查" },
    },
    { path: "/login", component: Login, meta: { public: true, title: "登录" } },
    { path: "/", component: Dashboard, meta: { title: "AI 安全助手" } },
    { path: "/workflow", component: Workflow, meta: { title: "红队工作流" } },
    { path: "/traffic", component: Traffic, meta: { title: "流量分析" } },
    { path: "/targets", component: Targets, meta: { title: "授权目标管理" } },
    { path: "/projects", component: Projects, meta: { title: "安全评估项目" } },
    {
      path: "/projects/:id",
      component: ProjectDetail,
      meta: { title: "评估项目详情" },
    },
    { path: "/recon", component: Recon, meta: { title: "信息收集" } },
    {
      path: "/vulnerabilities",
      component: Vulnerabilities,
      meta: { title: "漏洞库与主动检测" },
    },
    { path: "/tasks", component: Tasks, meta: { title: "检测任务" } },
    { path: "/findings", component: Findings, meta: { title: "漏洞结果" } },
    {
      path: "/audits",
      component: DataPage,
      props: { kind: "audits" },
      meta: { title: "审计日志" },
    },
    {
      path: "/offline-tools",
      component: OfflineTools,
      meta: { title: "离线工具集" },
    },
    { path: "/settings", component: Settings, meta: { title: "系统设置" } },
  ],
});

router.beforeEach(async (to) => {
  const auth = useAuthStore();
  // The desktop shell previously reused an encrypted local credential on mount,
  // which made the login screen flash and then entered the workspace without an
  // explicit user action. Start every desktop renderer session signed out.
  if (desktopMode && desktopInitialNavigation) {
    desktopInitialNavigation = false;
    auth.clear();
  }
  if (to.path !== "/setup" && localStorage.getItem(SETUP_KEY) !== "true") {
    return { path: "/setup", query: { redirect: to.fullPath } };
  }
  if (to.meta.public) {
    if (to.path === "/login" && auth.isAuthenticated) return "/";
    return true;
  }
  if (!auth.isAuthenticated)
    return { path: "/login", query: { redirect: to.fullPath } };
  if (!auth.checked && !(await auth.fetchMe())) {
    return { path: "/login", query: { redirect: to.fullPath } };
  }
  return true;
});

export default router;
