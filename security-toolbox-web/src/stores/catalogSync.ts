import { computed, ref } from "vue";
import { defineStore } from "pinia";
import { ElMessage } from "element-plus";
import { taskbarProgress } from "../utils/taskbarProgress";
import {
  endpoints,
  type CatalogSyncProgress,
  type DependencyStatus,
  type HostPluginCatalogSyncResult,
  type ScannerPocCatalogSyncResult,
  type SystemDependenciesResponse,
  type VulnerabilityCatalogStats,
  type VulnerabilityCatalogSyncResult,
} from "../api";
import { toErrorMessage } from "../utils/errorMessage";

export type ScannerSource = "NUCLEI" | "AFROG" | "XRAY" | "HOST";

/** Sources backed by an on-disk catalog with no remote binary to install. */
function isSelfHostedSource(source: ScannerSource) {
  return source === "HOST";
}

export interface CatalogLocalSyncStage {
  message: string;
  percentage: number;
}

type CatalogSyncResult =
  | VulnerabilityCatalogSyncResult
  | ScannerPocCatalogSyncResult
  | HostPluginCatalogSyncResult;

interface LocalUpdateResult {
  localFilesUpdated: boolean;
  catalogFilesUpdated: boolean;
}

const sourceLabels: Record<ScannerSource, string> = {
  NUCLEI: "Nuclei",
  AFROG: "Afrog",
  XRAY: "Xray",
  HOST: "内置主机插件",
};

function dependenciesFrom(data: SystemDependenciesResponse) {
  return data.dependencies || data.items || [];
}

function dependencyReady(item?: DependencyStatus) {
  return (
    item?.installed === true ||
    ["ready", "installed", "ok", "available"].includes(
      (item?.status || "").toLowerCase(),
    )
  );
}

function sourceDependencyReady(
  dependencies: DependencyStatus[],
  source: ScannerSource,
) {
  if (isSelfHostedSource(source)) return true;
  const expected = sourceLabels[source].toLowerCase();
  return dependencyReady(
    dependencies.find((item) => item.name?.toLowerCase() === expected),
  );
}

function catalogCount(stats: VulnerabilityCatalogStats, source: ScannerSource) {
  if (source === "NUCLEI") return Number(stats.nuclei || 0);
  if (source === "AFROG") return Number(stats.afrog || 0);
  if (source === "XRAY") return Number(stats.xray || 0);
  return Number(stats.host || 0);
}

async function importCatalogSource(
  source: ScannerSource,
): Promise<CatalogSyncResult> {
  if (source === "NUCLEI") return (await endpoints.syncNucleiCatalog()).data;
  if (source === "AFROG") return (await endpoints.syncAfrogCatalog()).data;
  if (source === "XRAY") return (await endpoints.syncXrayCatalog()).data;
  return (await endpoints.syncHostCatalog()).data;
}

async function runBounded<T>(
  items: T[],
  concurrency: number,
  worker: (item: T) => Promise<void>,
) {
  let cursor = 0;
  const runners = Array.from(
    { length: Math.min(concurrency, items.length) },
    async () => {
      while (cursor < items.length) {
        const item = items[cursor];
        cursor += 1;
        await worker(item);
      }
    },
  );
  await Promise.all(runners);
}

export const useCatalogSyncStore = defineStore("catalog-sync", () => {
  const running = ref(false);
  const queue = ref<ScannerSource[]>([]);
  const completedSources = ref<ScannerSource[]>([]);
  const localStages = ref<
    Partial<Record<ScannerSource, CatalogLocalSyncStage>>
  >({});
  const backendProgress = ref<
    Partial<Record<ScannerSource, CatalogSyncProgress>>
  >({});
  const failures = ref<Partial<Record<ScannerSource, string>>>({});
  const finishedAt = ref(0);
  const active = computed(
    () =>
      running.value ||
      Object.values(backendProgress.value).some((item) => item?.active),
  );

  let activeTask: Promise<void> | undefined;
  let pollTimer: number | undefined;

  async function refreshProgress() {
    try {
      const { data } = await endpoints.vulnerabilitySyncStatus();
      backendProgress.value = Object.fromEntries(
        data.map((item) => [item.source, item]),
      ) as Partial<Record<ScannerSource, CatalogSyncProgress>>;
    } catch {
      // A temporary progress request failure must not stop the persistent task.
    }
  }

  function stopPollingWhenIdle() {
    const backendActive = Object.values(backendProgress.value).some(
      (item) => item?.active,
    );
    if (!running.value && !backendActive && pollTimer) {
      window.clearInterval(pollTimer);
      pollTimer = undefined;
    }
  }

  function ensureProgressTracking() {
    void refreshProgress();
    if (pollTimer) return;
    pollTimer = window.setInterval(async () => {
      await refreshProgress();
      stopPollingWhenIdle();
    }, 800);
  }

  function markFailed(source: ScannerSource, error: unknown) {
    const message = toErrorMessage(error, `${sourceLabels[source]} 同步失败`);
    failures.value = { ...failures.value, [source]: message };
    const nextStages = { ...localStages.value };
    delete nextStages[source];
    localStages.value = nextStages;
    ElMessage.error(message);
  }

  function markCompleted(source: ScannerSource) {
    if (!completedSources.value.includes(source)) {
      completedSources.value = [...completedSources.value, source];
    }
    const nextStages = { ...localStages.value };
    delete nextStages[source];
    localStages.value = nextStages;
  }

  async function updateLocalSource(
    source: ScannerSource,
  ): Promise<LocalUpdateResult> {
    localStages.value = {
      ...localStages.value,
      [source]: {
        message: `正在检查 ${sourceLabels[source]} 和漏洞目录版本`,
        percentage: 5,
      },
    };
    if (isSelfHostedSource(source)) {
      return { localFilesUpdated: false, catalogFilesUpdated: true };
    }
    if (!window.toolboxDesktop?.installDependency) {
      return { localFilesUpdated: false, catalogFilesUpdated: true };
    }
    const result = await window.toolboxDesktop.installDependency(
      source.toLowerCase(),
      { refreshCatalog: true },
    );
    const localFilesUpdated =
      result.updated === true || result.catalogUpdated === true;
    const catalogFilesUpdated = result.catalogUpdated === true;
    if (localFilesUpdated) {
      ElMessage.success(`${sourceLabels[source]} 本地文件已更新`);
    } else {
      ElMessage.info(`${sourceLabels[source]} 工具与漏洞目录已是最新版本`);
    }
    return { localFilesUpdated, catalogFilesUpdated };
  }

  async function execute(sources: ScannerSource[]) {
    const localResults = new Map<ScannerSource, LocalUpdateResult>();
    const runnableSources: ScannerSource[] = [];
    let initialDependencies: DependencyStatus[];
    try {
      initialDependencies = dependenciesFrom(
        (await endpoints.dependencies()).data,
      );
    } catch (error) {
      sources.forEach((source) => markFailed(source, error));
      return;
    }

    const missing = sources.filter(
      (source) => !sourceDependencyReady(initialDependencies, source),
    );
    if (missing.length) {
      missing.forEach((source) =>
        markFailed(
          source,
          new Error(`请先安装 ${sourceLabels[source]} 后再同步漏洞库`),
        ),
      );
    }

    await Promise.all(
      sources
        .filter((source) => !missing.includes(source))
        .map(async (source) => {
          try {
            localResults.set(source, await updateLocalSource(source));
            runnableSources.push(source);
          } catch (error) {
            markFailed(source, error);
          }
        }),
    );
    if (!runnableSources.length) return;

    if (window.toolboxDesktop) {
      try {
        const refreshed = dependenciesFrom(
          (await endpoints.dependencies(true)).data,
        );
        for (const source of [...runnableSources]) {
          if (sourceDependencyReady(refreshed, source)) continue;
          runnableSources.splice(runnableSources.indexOf(source), 1);
          markFailed(
            source,
            new Error(
              `${sourceLabels[source]} 已安装，但重新检测尚未确认可用`,
            ),
          );
        }
      } catch (error) {
        runnableSources.splice(0).forEach((source) => markFailed(source, error));
      }
    }
    if (!runnableSources.length) return;

    let stats: VulnerabilityCatalogStats | undefined;
    try {
      stats = (await endpoints.vulnerabilityStats()).data;
    } catch {
      // Without stats, importing is safer than incorrectly skipping a stale catalog.
    }

    const imports: ScannerSource[] = [];
    for (const source of runnableSources) {
      const local = localResults.get(source);
      if (
        stats &&
        local?.catalogFilesUpdated === false &&
        catalogCount(stats, source) > 0
      ) {
        markCompleted(source);
        ElMessage.success(`${sourceLabels[source]} 漏洞库已是最新，无需重新导入`);
        continue;
      }
      localStages.value = {
        ...localStages.value,
        [source]: {
          message: "本地文件已准备，正在导入漏洞元数据",
          percentage: 15,
        },
      };
      imports.push(source);
    }

    await runBounded(imports, 2, async (source) => {
      const local = localResults.get(source);
      try {
        const data = await importCatalogSource(source);
        markCompleted(source);
        ElMessage.success(
          `${sourceLabels[source]} 同步完成：新增 ${data.imported}，更新 ${data.updated}`,
        );
      } catch (error) {
        markFailed(
          source,
          local?.localFilesUpdated
            ? new Error(
                `${sourceLabels[source]} 本地文件已更新，但漏洞库导入失败：${toErrorMessage(error, "导入失败")}`,
              )
            : error,
        );
      }
    });
  }

  function start(sources: ScannerSource[]) {
    if (activeTask) return activeTask;
    const uniqueSources = [...new Set(sources)];
    running.value = true;
    queue.value = uniqueSources;
    completedSources.value = [];
    localStages.value = {};
    failures.value = {};
    taskbarProgress.startIndeterminate("catalog-sync");
    ensureProgressTracking();
    activeTask = execute(uniqueSources).finally(async () => {
      running.value = false;
      taskbarProgress.stopIndeterminate("catalog-sync");
      taskbarProgress.clearProgress("catalog-sync");
      finishedAt.value = Date.now();
      await refreshProgress();
      queue.value = [];
      completedSources.value = [];
      localStages.value = {};
      activeTask = undefined;
      stopPollingWhenIdle();
    });
    return activeTask;
  }

  return {
    running,
    active,
    queue,
    completedSources,
    localStages,
    backendProgress,
    failures,
    finishedAt,
    refreshProgress,
    ensureProgressTracking,
    start,
  };
});
