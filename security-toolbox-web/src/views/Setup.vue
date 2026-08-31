<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import "../setup.css";
import { useRoute, useRouter } from "vue-router";
import { ElMessage, ElMessageBox } from "element-plus";
import {
  Check,
  Delete,
  Download,
  FolderOpened,
  Refresh,
  Setting,
  Tools,
  Warning,
} from "../components/fluentIcons";
import { endpoints } from "../api";
import { toErrorMessage } from "../utils/errorMessage";
import { taskbarProgress } from "../utils/taskbarProgress";

interface Dependency {
  name: string;
  status?: string;
  installed?: boolean;
  version?: string;
  path?: string;
  required?: boolean;
  category?: string;
  installSupported?: boolean;
  installing?: boolean;
  packageId?: string;
  manualUrl?: string;
  progress?: number;
  progressDeterminate?: boolean;
  installStage?: string;
  downloadedBytes?: number;
  totalBytes?: number;
  resumedBytes?: number;
  processedFiles?: number;
  totalFiles?: number;
  paused?: boolean;
  canPause?: boolean;
  controlling?: boolean;
  uninstalling?: boolean;
  uninstallSupported?: boolean;
  logs?: string[];
  message?: string;
}

const router = useRouter();
const route = useRoute();
const loading = ref(false);
const error = ref("");
const items = ref<Dependency[]>([]);
const developmentMode = ref(import.meta.env.DEV);
const toolsDirectory = ref("程序目录 / tools");
const toolsDirectoryChanging = ref(false);
const downloadSourceStatus = ref<{ configuredMirror: string }>({
  configuredMirror: "",
});
const downloadSourceLoading = ref(false);
const downloadSourceSaving = ref(false);
const downloadSourceMode = ref<"github" | "custom">("github");
const downloadSourceMirror = ref("");
const autoContinue = ref(
  localStorage.getItem("security_toolbox_setup_auto_continue_v1") === "true",
);
const startupCheck = computed(() => route.query.startup === "1");
const desktopDirectorySelectionAvailable = Boolean(
  window.toolboxDesktop?.chooseToolsDirectory &&
    window.toolboxDesktop?.resetToolsDirectory,
);
const desktopMode = Boolean(window.toolboxDesktop);
let removeInstallProgressListener: (() => void) | undefined;
const manualUrls: Record<string, string> = {
  Java: "https://adoptium.net/temurin/releases/?version=17",
  Nmap: "https://nmap.org/download.html#windows",
  Npcap: "https://npcap.com/#download",
  OpenSSL: "https://www.openssl.org/",
  curl: "https://curl.se/windows/",
  Python: "https://www.python.org/downloads/windows/",
  PostgreSQL: "https://www.postgresql.org/download/windows/",
  Nuclei: "https://github.com/projectdiscovery/nuclei/releases",
  Afrog: "https://github.com/zan8in/afrog/releases",
  Xray: "https://github.com/chaitin/xray/releases",
  fscan: "https://github.com/shadow1ng/fscan/releases",
  "ProjectDiscovery httpx":
    "https://github.com/projectdiscovery/httpx/releases",
  "OWASP ZAP": "https://www.zaproxy.org/download/",
};
const missingRequired = computed(() =>
  items.value.filter((item) => item.required !== false && !isReady(item)),
);
const grouped = computed(() => ({
  core: items.value.filter((item) => item.required !== false),
  optional: items.value.filter((item) => item.required === false),
}));

function isReady(item: Dependency) {
  return (
    item.installed === true ||
    ["ready", "installed", "ok", "available"].includes(
      (item.status || "").toLowerCase(),
    )
  );
}

function dependencyPathText(item: Dependency) {
  if (item.path) return item.path;
  if (isReady(item)) {
    return "已在系统环境中就绪";
  }
  return "未检测到安装路径";
}

function dependencyTooltipText(item: Dependency) {
  if (item.path) return item.path;
  if (isReady(item)) {
    return item.message || "已在系统环境中检测通过，登录后可查看详细安装路径";
  }
  return item.message || "未检测到安装路径";
}

async function check(forceRefresh = false) {
  loading.value = true;
  error.value = "";
  items.value = [];
  taskbarProgress.startIndeterminate("setup-detect");
  try {
    if (typeof EventSource !== "undefined") {
      const streamed = await streamDependencies(forceRefresh);
      if (streamed) {
        await decorateItems();
        developmentMode.value = import.meta.env.DEV;
        maybeAutoContinue();
        return true;
      }
    }
    const { data } = await loadDependencies(forceRefresh);
    items.value = Array.isArray(data)
      ? data
      : data.dependencies || data.items || [];
    await decorateItems();
    developmentMode.value = data.developmentMode ?? import.meta.env.DEV;
    maybeAutoContinue();
    return true;
  } catch (checkError) {
    items.value = [];
    const candidate = checkError as {
      response?: { status?: number };
      code?: string;
    };
    error.value =
      candidate.code === "ECONNABORTED"
        ? "本地依赖检测超时，已尝试自动重试，请检查占用较高的工具进程。"
        : candidate.response
          ? `后端依赖检查失败（HTTP ${candidate.response.status || "-"}）。`
          : "无法连接后端依赖检查接口，请确认本地服务已经启动。";
    return false;
  } finally {
    loading.value = false;
    taskbarProgress.stopIndeterminate("setup-detect");
  }
}

function maybeAutoContinue() {
  if (
    startupCheck.value &&
    autoContinue.value &&
    !missingRequired.value.length
  ) {
    proceed();
  }
}

async function decorateItems() {
  if (window.toolboxDesktop) {
    const [directory, installable] = await Promise.all([
      window.toolboxDesktop.getToolsDirectory(),
      window.toolboxDesktop.listInstallableDependencies(),
    ]);
    toolsDirectory.value = directory;
    const packages = new Map(
      installable.map((item) => [item.packageId, item]),
    );
    items.value = items.value.map((item) => {
      const packageId =
        item.name === "Nuclei"
          ? "nuclei"
          : item.name === "ProjectDiscovery httpx"
            ? "httpx"
            : item.name === "Afrog"
              ? "afrog"
: item.name === "Xray"
              ? "xray"
              : item.name === "fscan"
                ? "fscan"
                : undefined;
      return {
        ...item,
        packageId,
        installSupported: Boolean(packageId && packages.has(packageId)),
        uninstallSupported: Boolean(
          item.required === false &&
            packageId &&
            packages.get(packageId)?.uninstallSupported,
        ),
        manualUrl: manualUrls[item.name],
      };
    });
  } else {
    items.value = items.value.map((item) => ({
      ...item,
      manualUrl: manualUrls[item.name],
    }));
  }
}

function upsertDependency(dep: Dependency) {
  const index = items.value.findIndex((item) => item.name === dep.name);
  if (index >= 0) {
    items.value[index] = dep;
  } else {
    items.value.push(dep);
  }
}

async function loadDownloadSource() {
  if (!window.toolboxDesktop?.getToolDownloadSettings) return;
  downloadSourceLoading.value = true;
  try {
    downloadSourceStatus.value =
      await window.toolboxDesktop.getToolDownloadSettings();
    downloadSourceMirror.value =
      downloadSourceStatus.value?.configuredMirror || "";
    downloadSourceMode.value = downloadSourceMirror.value
      ? "custom"
      : "github";
  } catch {
    /* 静默：加载失败时保持默认 GitHub 直连 */
  } finally {
    downloadSourceLoading.value = false;
  }
}

async function saveDownloadSource(mode: "github" | "custom", mirror = "") {
  if (!window.toolboxDesktop?.saveToolDownloadSettings) return;
  downloadSourceSaving.value = true;
  try {
    const mirrorValue =
      mode === "custom" ? (mirror || downloadSourceMirror.value).trim() : "";
    downloadSourceStatus.value =
      await window.toolboxDesktop.saveToolDownloadSettings({
        downloadMirror: mirrorValue,
      });
    downloadSourceMirror.value =
      downloadSourceStatus.value?.configuredMirror || "";
    downloadSourceMode.value = downloadSourceMirror.value
      ? "custom"
      : "github";
  } catch (error: any) {
    ElMessage.error(error?.message || "下载源切换失败");
  } finally {
    downloadSourceSaving.value = false;
  }
}

function openMirrorCustom() {
  downloadSourceMode.value = "custom";
  if (!downloadSourceMirror.value) {
    ElMessage.info("请输入镜像前缀，回车保存；留空请切换回“直连”");
  }
}

function handleDownloadSourceModeChange(value: string | number | boolean) {
  if (value === "github") saveDownloadSource("github");
  else openMirrorCustom();
}

function streamDependencies(forceRefresh: boolean): Promise<boolean> {
  return new Promise((resolve) => {
    let received = 0;
    let source: EventSource;
    let timer: ReturnType<typeof setTimeout>;
    try {
      source = new EventSource(
        `/api/system/dependencies/stream?refresh=${forceRefresh}`,
      );
    } catch {
      resolve(false);
      return;
    }
    const close = (success: boolean) => {
      clearTimeout(timer);
      source.close();
      resolve(success);
    };
    timer = setTimeout(() => close(received > 0), 20_000);
    source.onmessage = (event) => {
      received += 1;
      try {
        upsertDependency(JSON.parse(event.data) as Dependency);
      } catch {
        // 忽略无法解析的事件。
      }
    };
    source.addEventListener("complete", () => close(true));
    source.onerror = () => close(received > 0);
  });
}

async function loadDependencies(forceRefresh = false) {
  const attempts = startupCheck.value ? 3 : 1;
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await endpoints.dependencies(forceRefresh);
    } catch (requestError) {
      lastError = requestError;
      const candidate = requestError as { response?: unknown; code?: string };
      const retryable =
        !candidate.response || candidate.code === "ECONNABORTED";
      if (!retryable || attempt === attempts - 1) break;
      await new Promise((resolve) =>
        window.setTimeout(resolve, 500 * (attempt + 1)),
      );
    }
  }
  throw lastError;
}

async function requestInstall(item: Dependency) {
  if (!item.installSupported || !item.packageId || !window.toolboxDesktop)
    return;
  const dependencyWasReady = isReady(item);
  item.installing = true;
  item.progress = 0;
  item.progressDeterminate = false;
  item.installStage = "preparing";
  item.paused = false;
  item.downloadedBytes = 0;
  item.totalBytes = 0;
  item.resumedBytes = 0;
  item.processedFiles = undefined;
  item.totalFiles = undefined;
  item.logs = ["开始查询官方稳定版本"];
  try {
    const result = await window.toolboxDesktop.installDependency(
      item.packageId,
    );
    if (result.status === "paused" || result.status === "canceled") return;
    const refreshed = await check(true);
    const detected = items.value.find(
      (candidate) => candidate.packageId === item.packageId,
    );
    if (refreshed && detected && isReady(detected)) {
      if (result.status === "up-to-date") {
        ElMessage.info(`${item.name} ${result.version} 已是最新版本`);
      } else {
        ElMessage.success(
          `${item.name} 已${dependencyWasReady ? "更新" : "安装"}到 ${result.version} 并通过检测`,
        );
      }
    } else {
      ElMessage.warning(
        `${item.name} 已写入工具目录，但重新检测尚未确认可用，请再次检测或查看版本输出`,
      );
    }
  } catch (installError: any) {
    const code = String(
      installError?.code || installError?.detail?.code || "",
    ).toUpperCase();
    if (
      installError === "cancel" ||
      installError === "close" ||
      code.includes("DEPENDENCY_DOWNLOAD_CANCELED") ||
      code.includes("DEPENDENCY_DOWNLOAD_PAUSED") ||
      /已取消|已暂停/.test(String(installError?.message || ""))
    ) {
      item.paused = code.includes("DEPENDENCY_DOWNLOAD_PAUSED");
      return;
    }
    ElMessage.error(toErrorMessage(installError, `${item.name} 安装失败`));
  } finally {
    if (!item.paused) item.installing = false;
  }
}

async function controlDownload(item: Dependency, action: "pause" | "cancel") {
  if (!item.packageId || !window.toolboxDesktop?.controlDependencyInstall)
    return;
  item.controlling = true;
  try {
    await window.toolboxDesktop.controlDependencyInstall(
      item.packageId,
      action,
    );
  } catch (controlError: any) {
    ElMessage.error(toErrorMessage(controlError, "下载控制失败"));
  } finally {
    item.controlling = false;
  }
}

async function requestUninstall(item: Dependency) {
  if (
    item.required !== false ||
    !item.packageId ||
    !item.uninstallSupported ||
    !window.toolboxDesktop?.uninstallDependency
  )
    return;
  try {
    await ElMessageBox.confirm(
      `将从当前工具目录卸载 ${item.name}。系统依赖、手动安装版本和已导入的漏洞记录不会被删除。`,
      `卸载 ${item.name}`,
      {
        confirmButtonText: "卸载",
        cancelButtonText: "取消",
        confirmButtonClass: "dependency-uninstall-confirm",
        type: "warning",
      },
    );
    item.uninstalling = true;
    await window.toolboxDesktop.uninstallDependency(item.packageId);
    await check(true);
    ElMessage.success(`${item.name} 已卸载`);
  } catch (uninstallError: any) {
    if (uninstallError !== "cancel" && uninstallError !== "close") {
      ElMessage.error(toErrorMessage(uninstallError, `${item.name} 卸载失败`));
    }
  } finally {
    item.uninstalling = false;
  }
}

function installProgress(item: Dependency) {
  if (item.totalFiles && typeof item.processedFiles === "number") {
    return Math.max(
      0,
      Math.min(100, Math.round((item.processedFiles / item.totalFiles) * 100)),
    );
  }
  if (item.totalBytes && typeof item.downloadedBytes === "number") {
    return Math.max(
      0,
      Math.min(100, Math.round((item.downloadedBytes / item.totalBytes) * 100)),
    );
  }
  return 0;
}

function installProgressIndeterminate(item: Dependency) {
  if (item.paused) return false;
  return (
    item.progressDeterminate !== true ||
    !(
      (item.totalFiles && typeof item.processedFiles === "number") ||
      (item.totalBytes && typeof item.downloadedBytes === "number")
    )
  );
}

function installStageLabel(stage?: string) {
  const labels: Record<string, string> = {
    preparing: "准备下载",
    downloading: "正在下载",
    verifying: "正在校验",
    extracting: "正在解压",
    installing: "正在安装",
    completed: "安装完成",
    failed: "安装失败",
    paused: "下载已暂停，断点文件已保留",
    canceled: "下载已取消，缓存文件已清除",
  };
  return labels[(stage || "").toLowerCase()] || stage || "正在处理";
}

function formatBytes(bytes?: number) {
  if (!bytes || bytes < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const unit = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1,
  );
  const value = bytes / 1024 ** unit;
  return `${value.toFixed(unit === 0 ? 0 : value >= 10 ? 1 : 2)} ${units[unit]}`;
}

function subscribeInstallProgress() {
  const subscribe = window.toolboxDesktop?.onDependencyInstallProgress;
  if (!subscribe) return;
  removeInstallProgressListener = subscribe((event) => {
    const item = items.value.find(
      (candidate) => candidate.packageId === event.packageId,
    );
    if (!item) return;
    item.installing =
      event.installing ??
      (event.stage !== "completed" && event.stage !== "failed");
    item.progress = event.progress;
    item.progressDeterminate = event.progressDeterminate;
    item.installStage = event.installStage || event.stage;
    item.downloadedBytes = event.downloadedBytes;
    item.totalBytes = event.totalBytes;
    item.resumedBytes = event.resumedBytes;
    item.processedFiles = event.processedFiles;
    item.totalFiles = event.totalFiles;
    item.paused = event.paused;
    item.canPause = event.canPause;
    const wasCanceled =
      event.stage === "canceled" ||
      /取消|已取消|canceled/i.test(
        String(event.installStage || event.stage || ""),
      );
    if (wasCanceled) item.installStage = "canceled";
    else if (event.stage === "failed") {
      item.installStage = "failed";
      if (event.installStage) item.message = event.installStage;
    }
    const message = wasCanceled
      ? installStageLabel("canceled")
      : event.stage === "failed"
        ? "安装失败：" + (item.message || "请查看安装日志")
        : installStageLabel(event.installStage || event.stage);
    if (message && item.logs?.[item.logs.length - 1] !== message)
      item.logs = [...(item.logs || []), message].slice(-8);

    if (item.installing && !item.paused) {
      if (
        typeof item.progress === "number" &&
        item.progress >= 0 &&
        item.progress <= 100
      ) {
        taskbarProgress.setProgress(
          `dep-${item.packageId}`,
          item.progress / 100,
        );
      } else {
        taskbarProgress.startIndeterminate(`dep-${item.packageId}`);
      }
    } else {
      taskbarProgress.clearProgress(`dep-${item.packageId}`);
      taskbarProgress.stopIndeterminate(`dep-${item.packageId}`);
    }
  });
}

type DirectoryChangeResult =
  | string
  | {
      changed?: boolean;
      canceled?: boolean;
      toolsDirectory?: string;
      path?: string;
    }
  | null
  | undefined;

function directoryFromResult(result: DirectoryChangeResult) {
  if (typeof result === "string") return result;
  return result?.toolsDirectory || result?.path || "";
}

async function chooseToolsDirectory() {
  const chooser = window.toolboxDesktop?.chooseToolsDirectory;
  if (!chooser) return;
  toolsDirectoryChanging.value = true;
  try {
    const result = await chooser();
    if (typeof result === "object" && result?.canceled) return;
    const selected = directoryFromResult(result);
    if (!selected) return;
    toolsDirectory.value = selected;
    if (typeof result === "object" && result?.changed === false) {
      ElMessage.info("工具安装目录未更改");
      return;
    }
    ElMessage.success("工具安装目录已更新");
    await check();
  } catch (chooseError: any) {
    ElMessage.error(toErrorMessage(chooseError, "选择工具安装目录失败"));
  } finally {
    toolsDirectoryChanging.value = false;
  }
}

async function resetToolsDirectory() {
  const resetter = window.toolboxDesktop?.resetToolsDirectory;
  if (!resetter) return;
  toolsDirectoryChanging.value = true;
  try {
    const result = await resetter();
    const directory = directoryFromResult(result);
    if (directory) toolsDirectory.value = directory;
    if (typeof result === "object" && result?.changed === false) {
      ElMessage.info("当前已是默认工具安装目录");
      return;
    }
    ElMessage.success("已恢复默认工具安装目录");
    await check();
  } catch (resetError: any) {
    ElMessage.error(toErrorMessage(resetError, "恢复默认目录失败"));
  } finally {
    toolsDirectoryChanging.value = false;
  }
}

function proceed() {
  if (missingRequired.value.length && !developmentMode.value) {
    ElMessage.warning("核心依赖尚未满足，暂时不能继续");
    return;
  }
  localStorage.setItem("security_toolbox_setup_complete_v2", "true");
  router.replace(String(route.query.redirect || "/login"));
}

function updateAutoContinue(value: string | number | boolean) {
  autoContinue.value = Boolean(value);
  localStorage.setItem(
    "security_toolbox_setup_auto_continue_v1",
    String(autoContinue.value),
  );
}

onMounted(() => {
  subscribeInstallProgress();
  void check();
  void loadDownloadSource();
});

onUnmounted(() => {
  removeInstallProgressListener?.();
  removeInstallProgressListener = undefined;
  items.value.forEach((item) => {
    if (item.packageId) {
      taskbarProgress.clearProgress(`dep-${item.packageId}`);
      taskbarProgress.stopIndeterminate(`dep-${item.packageId}`);
    }
  });
});
</script>

<template>
  <main class="setup-page">
    <section class="setup-shell">
      <aside class="setup-steps">
        <div class="setup-brand">
          <span class="setup-logo">
            <img src="../assets/xiezhi-mark.png" alt="" aria-hidden="true" />
          </span>
          <span><strong>獬豸</strong><small>授权安全测试平台</small></span>
        </div>
        <div class="setup-side-label">环境配置</div>
        <ol>
          <li class="done">
            <i
              ><el-icon><Check /></el-icon></i
            ><span>环境检查<small>本地服务已连接</small></span>
          </li>
          <li class="active">
            <i>2</i><span>检测依赖<small>确认核心与扩展工具</small></span>
          </li>
          <li>
            <i>3</i><span>完成配置<small>进入安全工作台</small></span>
          </li>
        </ol>
        <div class="setup-download-source" v-if="desktopMode">
          <div class="setup-storage-title">
            <el-icon><Download /></el-icon><b>工具下载源</b>
          </div>
          <div v-if="downloadSourceSaving" class="setup-download-source-line">
            正在保存…
          </div>
          <div v-else class="setup-download-source-line">
            <el-radio-group
              v-model="downloadSourceMode"
              size="small"
              @change="handleDownloadSourceModeChange"
            >
              <el-radio-button label="github">直连</el-radio-button>
              <el-radio-button label="custom">镜像</el-radio-button>
            </el-radio-group>
          </div>
          <template v-if="downloadSourceMode === 'custom'">
            <el-input
              v-model="downloadSourceMirror"
              size="small"
              placeholder="https://ghfast.top/ 或 https://gh-proxy…"
              @keyup.enter="saveDownloadSource('custom')"
            />
            <p class="setup-download-source-hint">
              前缀 + /https://github.com/…；也可在「设置 → 工具下载源」管理。
            </p>
          </template>
          <p
            v-if="downloadSourceMode === 'github'"
            class="setup-download-source-hint"
          >
            直连 GitHub 官方源，或部分网络可能连接超时。
          </p>
        </div>
        <div class="setup-storage">
          <div class="setup-storage-title">
            <el-icon><FolderOpened /></el-icon><b>工具安装目录</b>
          </div>
          <code :title="toolsDirectory">{{ toolsDirectory }}</code>
          <div
            v-if="desktopDirectorySelectionAvailable"
            class="setup-storage-actions"
          >
            <el-button
              size="small"
              :loading="toolsDirectoryChanging"
              @click="chooseToolsDirectory"
              >选择目录</el-button
            >
            <el-button
              size="small"
              :disabled="toolsDirectoryChanging"
              @click="resetToolsDirectory"
              >恢复默认</el-button
            >
          </div>
        </div>
      </aside>

      <section class="setup-content">
        <header class="setup-header">
          <div>
            <span class="setup-eyebrow">系统设置 / 依赖检测</span>
            <h1>检测运行依赖</h1>
            <p>
              确认安全检测引擎与本地工具均可用，缺失项目可在此安装或查看官方来源。
            </p>
          </div>
          <el-button :loading="loading" @click="check(true)"
            ><el-icon><Refresh /></el-icon>重新检测</el-button
          >
        </header>

        <el-alert
          v-if="error"
          :title="error"
          type="error"
          show-icon
          :closable="false"
        />
        <el-alert
          v-else-if="missingRequired.length"
          :title="`缺少 ${missingRequired.length} 项核心依赖，相关检测能力将不可用。`"
          type="warning"
          show-icon
          :closable="false"
        />

        <div v-if="loading && !items.length" class="dependency-loading">
          <el-icon class="is-loading"><Setting /></el-icon
          ><strong>正在检测本地环境</strong><span>这通常只需要几秒钟</span>
        </div>
        <div v-else class="dependency-scroll">
          <div class="dependency-group">
            <div class="dependency-group-head">
              <span class="dependency-group-icon core"
                ><el-icon><Tools /></el-icon
              ></span>
              <div>
                <h3>核心依赖</h3>
                <p>运行平台及主要检测能力所必需</p>
              </div>
              <em
                >{{ grouped.core.filter(isReady).length }} /
                {{ grouped.core.length }} 可用</em
              >
            </div>
            <div
              v-if="!grouped.core.length && !loading"
              class="dependency-empty"
            >
              暂无检查结果
            </div>
            <div
              v-for="item in grouped.core"
              :key="item.name"
              class="dependency-row"
            >
              <span class="dep-status" :class="{ ready: isReady(item) }"
                ><el-icon
                  ><Check v-if="isReady(item)" /><Warning v-else /></el-icon
              ></span>
              <div class="dep-main">
                <b>{{ item.name }}</b>
                <el-tooltip
                  :disabled="!dependencyTooltipText(item)"
                  placement="top-start"
                  :show-after="350"
                  popper-class="dependency-path-tooltip"
                >
                  <template #content
                    ><span class="dependency-path-tooltip-content">{{
                      dependencyTooltipText(item)
                    }}</span></template
                  >
                  <small class="dep-path">{{
                    dependencyPathText(item)
                  }}</small>
                </el-tooltip>
                <div
                  v-if="item.installing || item.paused"
                  class="dep-install-progress"
                >
                  <el-progress
                    :percentage="installProgress(item)"
                    :stroke-width="6"
                    :show-text="false"
                    :indeterminate="installProgressIndeterminate(item)"
                    :duration="1.2"
                  />
                  <span>{{ installStageLabel(item.installStage) }}</span>
                  <span v-if="item.totalFiles"
                    >{{ item.processedFiles || 0 }} /
                    {{ item.totalFiles }} 个文件</span
                  >
                  <span v-else-if="item.totalBytes"
                    >{{ formatBytes(item.downloadedBytes) }} /
                    {{ formatBytes(item.totalBytes)
                    }}<template v-if="item.resumedBytes">
                      · 已续传 {{ formatBytes(item.resumedBytes) }}</template
                    ></span
                  >
                  <span v-else-if="item.downloadedBytes">{{
                    formatBytes(item.downloadedBytes)
                  }}</span>
                  <details v-if="item.logs?.length" class="dep-install-log">
                    <summary>安装日志</summary>
                    <code v-for="line in item.logs" :key="line">{{
                      line
                    }}</code>
                  </details>
                </div>
              </div>
              <el-tooltip
                :disabled="!item.version"
                placement="top"
                :show-after="350"
                popper-class="dependency-path-tooltip"
              >
                <template #content
                  ><span class="dependency-path-tooltip-content">{{
                    item.version
                  }}</span></template
                >
                <span class="dep-version">{{ item.version || "--" }}</span>
              </el-tooltip>
              <el-tag
                :type="isReady(item) ? 'success' : 'danger'"
                size="small"
                >{{ isReady(item) ? "可用" : "缺失" }}</el-tag
              >
              <div class="dep-actions">
                <div
                  v-if="
                    item.installSupported &&
                    !isReady(item) &&
                    (item.canPause || item.paused)
                  "
                  class="dep-install-controls"
                >
                  <el-button
                    type="primary"
                    plain
                    :loading="item.controlling"
                    @click="
                      item.paused
                        ? requestInstall(item)
                        : controlDownload(item, 'pause')
                    "
                    >{{ item.paused ? "继续" : "暂停" }}</el-button
                  >
                  <el-button
                    type="danger"
                    plain
                    :disabled="item.controlling"
                    @click="controlDownload(item, 'cancel')"
                    >取消</el-button
                  >
                </div>
                <el-button
                  v-else-if="item.installSupported && !isReady(item)"
                  type="primary"
                  :loading="item.installing"
                  @click="requestInstall(item)"
                  ><el-icon><Download /></el-icon>下载并安装</el-button
                >
                <div
                  v-else-if="isReady(item) && item.installSupported"
                  class="dep-ready-controls"
                >
                  <el-button
                    plain
                    :loading="item.installing"
                    :disabled="item.uninstalling"
                    @click="requestInstall(item)"
                    ><el-icon><Refresh /></el-icon>检查更新</el-button
                  >
                  <el-tooltip
                    :disabled="!item.uninstallSupported"
                    placement="top"
                    :show-after="350"
                    popper-class="dependency-path-tooltip"
                  >
                    <template #content
                      ><span class="dependency-path-tooltip-content"
                        >卸载可选依赖</span
                      ></template
                    >
                    <el-button
                      v-if="item.uninstallSupported"
                      class="dep-uninstall-button"
                      type="danger"
                      :icon="Delete"
                      :loading="item.uninstalling"
                      :disabled="item.installing"
                      aria-label="卸载可选依赖"
                      @click="requestUninstall(item)"
                      >卸载</el-button
                    >
                  </el-tooltip>
                </div>
                <span v-else-if="isReady(item)" class="dep-action">已就绪</span>
                <a
                  v-else-if="item.manualUrl"
                  class="dep-manual-link"
                  :href="item.manualUrl"
                  target="_blank"
                  rel="noreferrer"
                  >官方安装</a
                >
                <span v-else class="dep-action">暂不支持</span>
              </div>
            </div>
          </div>

          <div class="dependency-group">
            <div class="dependency-group-head">
              <span class="dependency-group-icon"
                ><el-icon><Setting /></el-icon
              ></span>
              <div>
                <h3>可选工具</h3>
                <p>按需启用更多专业检测能力</p>
              </div>
              <em
                >{{ grouped.optional.filter(isReady).length }} /
                {{ grouped.optional.length }} 可用</em
              >
            </div>
            <div
              v-if="!grouped.optional.length && !loading"
              class="dependency-empty"
            >
              未配置可选工具
            </div>
            <div
              v-for="item in grouped.optional"
              :key="item.name"
              class="dependency-row"
            >
              <span class="dep-status" :class="{ ready: isReady(item) }"
                ><el-icon
                  ><Check v-if="isReady(item)" /><Warning v-else /></el-icon
              ></span>
              <div class="dep-main">
                <b>{{ item.name }}</b>
                <el-tooltip
                  :disabled="!dependencyTooltipText(item)"
                  placement="top-start"
                  :show-after="350"
                  popper-class="dependency-path-tooltip"
                >
                  <template #content
                    ><span class="dependency-path-tooltip-content">{{
                      dependencyTooltipText(item)
                    }}</span></template
                  >
                  <small class="dep-path">{{
                    dependencyPathText(item)
                  }}</small>
                </el-tooltip>
                <div
                  v-if="item.installing || item.paused"
                  class="dep-install-progress"
                >
                  <el-progress
                    :percentage="installProgress(item)"
                    :stroke-width="6"
                    :show-text="false"
                    :indeterminate="installProgressIndeterminate(item)"
                    :duration="1.2"
                  />
                  <span>{{ installStageLabel(item.installStage) }}</span>
                  <span v-if="item.totalFiles"
                    >{{ item.processedFiles || 0 }} /
                    {{ item.totalFiles }} 个文件</span
                  >
                  <span v-else-if="item.totalBytes"
                    >{{ formatBytes(item.downloadedBytes) }} /
                    {{ formatBytes(item.totalBytes)
                    }}<template v-if="item.resumedBytes">
                      · 已续传 {{ formatBytes(item.resumedBytes) }}</template
                    ></span
                  >
                  <span v-else-if="item.downloadedBytes">{{
                    formatBytes(item.downloadedBytes)
                  }}</span>
                  <details v-if="item.logs?.length" class="dep-install-log">
                    <summary>安装日志</summary>
                    <code v-for="line in item.logs" :key="line">{{
                      line
                    }}</code>
                  </details>
                </div>
              </div>
              <el-tooltip
                :disabled="!item.version"
                placement="top"
                :show-after="350"
                popper-class="dependency-path-tooltip"
              >
                <template #content
                  ><span class="dependency-path-tooltip-content">{{
                    item.version
                  }}</span></template
                >
                <span class="dep-version">{{ item.version || "--" }}</span>
              </el-tooltip>
              <el-tag :type="isReady(item) ? 'success' : 'info'" size="small">{{
                isReady(item) ? "可用" : "可选"
              }}</el-tag>
              <div class="dep-actions">
                <div
                  v-if="
                    item.installSupported &&
                    !isReady(item) &&
                    (item.canPause || item.paused)
                  "
                  class="dep-install-controls"
                >
                  <el-button
                    type="primary"
                    plain
                    :loading="item.controlling"
                    @click="
                      item.paused
                        ? requestInstall(item)
                        : controlDownload(item, 'pause')
                    "
                    >{{ item.paused ? "继续" : "暂停" }}</el-button
                  >
                  <el-button
                    type="danger"
                    plain
                    :disabled="item.controlling"
                    @click="controlDownload(item, 'cancel')"
                    >取消</el-button
                  >
                </div>
                <el-button
                  v-else-if="item.installSupported && !isReady(item)"
                  type="primary"
                  :loading="item.installing"
                  @click="requestInstall(item)"
                  ><el-icon><Download /></el-icon>下载并安装</el-button
                >
                <div
                  v-else-if="isReady(item) && item.installSupported"
                  class="dep-ready-controls"
                >
                  <el-button
                    plain
                    :loading="item.installing"
                    :disabled="item.uninstalling"
                    @click="requestInstall(item)"
                    ><el-icon><Refresh /></el-icon>检查更新</el-button
                  >
                  <el-tooltip
                    :disabled="!item.uninstallSupported"
                    placement="top"
                    :show-after="350"
                    popper-class="dependency-path-tooltip"
                  >
                    <template #content
                      ><span class="dependency-path-tooltip-content"
                        >卸载可选依赖</span
                      ></template
                    >
                    <el-button
                      v-if="item.uninstallSupported"
                      class="dep-uninstall-button"
                      type="danger"
                      :icon="Delete"
                      :loading="item.uninstalling"
                      :disabled="item.installing"
                      aria-label="卸载可选依赖"
                      @click="requestUninstall(item)"
                      >卸载</el-button
                    >
                  </el-tooltip>
                </div>
                <span v-else-if="isReady(item)" class="dep-action">已就绪</span>
                <a
                  v-else-if="item.manualUrl"
                  class="dep-manual-link"
                  :href="item.manualUrl"
                  target="_blank"
                  rel="noreferrer"
                  >官方安装</a
                >
                <span v-else class="dep-action">暂不支持</span>
              </div>
            </div>
          </div>
        </div>

        <footer>
          <div class="setup-footer-copy">
            <span v-if="developmentMode && missingRequired.length"
              >开发模式允许依赖不完整时继续，部分检测任务可能无法执行。</span
            >
            <span v-else-if="missingRequired.length"
              >请先安装缺失的核心依赖，再重新检测。</span
            >
            <span v-else>核心依赖已满足，可以进入工具箱。</span>
            <el-checkbox
              v-if="desktopMode"
              :model-value="autoContinue"
              @change="updateAutoContinue"
              >下次依赖满足时自动进入</el-checkbox
            >
          </div>
          <el-button
            type="primary"
            :disabled="
              loading ||
              Boolean(error) ||
              Boolean(missingRequired.length && !developmentMode)
            "
            @click="proceed"
            >下一步，进入工具箱</el-button
          >
        </footer>
      </section>
    </section>
  </main>
</template>
