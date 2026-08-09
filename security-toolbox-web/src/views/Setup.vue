<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import "../setup.css";
import { useRoute, useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import {
  Check,
  Download,
  FolderOpened,
  Refresh,
  Setting,
  Tools,
  Warning,
} from "../components/fluentIcons";
import { endpoints } from "../api";
import { toErrorMessage } from "../utils/errorMessage";

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
  logs?: string[];
}

const router = useRouter();
const route = useRoute();
const loading = ref(false);
const error = ref("");
const items = ref<Dependency[]>([]);
const developmentMode = ref(import.meta.env.DEV);
const toolsDirectory = ref("程序目录 / tools");
const toolsDirectoryChanging = ref(false);
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

async function check() {
  loading.value = true;
  error.value = "";
  try {
    const { data } = await loadDependencies();
    items.value = Array.isArray(data)
      ? data
      : data.dependencies || data.items || [];
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
                  : undefined;
        return {
          ...item,
          packageId,
          installSupported: Boolean(packageId && packages.has(packageId)),
          manualUrl: manualUrls[item.name],
        };
      });
    } else {
      items.value = items.value.map((item) => ({
        ...item,
        manualUrl: manualUrls[item.name],
      }));
    }
    developmentMode.value = data.developmentMode ?? import.meta.env.DEV;
    if (
      startupCheck.value &&
      autoContinue.value &&
      !missingRequired.value.length
    ) {
      proceed();
    }
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
  } finally {
    loading.value = false;
  }
}

async function loadDependencies() {
  const attempts = startupCheck.value ? 3 : 1;
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await endpoints.dependencies();
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
    ElMessage.success(`${item.name} ${result.version} 已安装到程序 tools 目录`);
    await check();
  } catch (installError: any) {
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
    const message = event.installStage || event.stage;
    if (message && item.logs?.[item.logs.length - 1] !== message)
      item.logs = [...(item.logs || []), message].slice(-8);
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
});

onUnmounted(() => {
  removeInstallProgressListener?.();
  removeInstallProgressListener = undefined;
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
          <el-button :loading="loading" @click="check"
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
                  :disabled="!item.path"
                  placement="top-start"
                  :show-after="350"
                  popper-class="dependency-path-tooltip"
                >
                  <template #content
                    ><span class="dependency-path-tooltip-content">{{
                      item.path
                    }}</span></template
                  >
                  <small class="dep-path">{{
                    item.path || "未检测到安装路径"
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
              <span class="dep-version">{{ item.version || "--" }}</span>
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
                <el-button
                  v-else-if="isReady(item) && item.installSupported"
                  plain
                  :loading="item.installing"
                  @click="requestInstall(item)"
                  ><el-icon><Refresh /></el-icon>检查更新</el-button
                >
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
                  :disabled="!item.path"
                  placement="top-start"
                  :show-after="350"
                  popper-class="dependency-path-tooltip"
                >
                  <template #content
                    ><span class="dependency-path-tooltip-content">{{
                      item.path
                    }}</span></template
                  >
                  <small class="dep-path">{{
                    item.path || "未检测到安装路径"
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
              <span class="dep-version">{{ item.version || "--" }}</span>
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
                <el-button
                  v-else-if="isReady(item) && item.installSupported"
                  plain
                  :loading="item.installing"
                  @click="requestInstall(item)"
                  ><el-icon><Refresh /></el-icon>检查更新</el-button
                >
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
