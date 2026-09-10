<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import {
  endpoints,
  safeGet,
  type AssessmentProject,
  type DiscoveredPath,
  type DiscoveryResult,
} from "../api";
import AssetTopology from "../components/AssetTopology.vue";
import FluentIcon from "../components/FluentIcon.vue";
import { toErrorMessage } from "../utils/errorMessage";
import { ElMessage } from "element-plus";

const projects = ref<AssessmentProject[]>([]);
const projectId = ref<number>();
const assets = ref<DiscoveryResult[]>([]);
const loading = ref(false);
const assetsLoading = ref(false);

// Web URL 资产的拓扑节点 id 偏移，避免与 probe_results 自增 id 撞号。
const WEB_PATH_ID_BASE = 10_000_000_000;

const activeProjects = computed(() =>
  projects.value.filter((p) => p.status === "ACTIVE"),
);

const selectedProjectName = computed(() => {
  const found = projects.value.find((p) => p.id === projectId.value);
  return found?.name || "项目中心";
});

async function loadProjects() {
  loading.value = true;
  try {
    const result = await safeGet(endpoints.projects, [] as AssessmentProject[]);
    projects.value = result.data;
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "项目加载失败"));
  } finally {
    loading.value = false;
  }
}

async function loadAssets() {
  const pid = projectId.value;
  if (!pid) {
    assets.value = [];
    return;
  }
  assetsLoading.value = true;
  try {
    const [probeResults, webPaths] = await Promise.all([
      endpoints.projectDiscoveryResults(pid),
      safeGet(() => endpoints.projectDiscoveredPaths(pid), [] as DiscoveredPath[]),
    ]);
    // 资产拓扑 = 主机级探测结果 + Web URL 资产（discovered_paths），两者都带唯一 id 可直接作为拓扑节点。
    assets.value = [...(probeResults.data || []), ...asPathAssets(webPaths.data || [])];
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "资产加载失败"));
  } finally {
    assetsLoading.value = false;
  }
}

// 把 DiscoveredPath 规整为拓扑可直接消费的 DiscoveryResult 形态（保留 id/url/归属）。
// 位移 id 空间，避免与 probe_results 的自增 id 碰撞（两条独立主键）。原始 id 保留在原 id。
function asPathAssets(paths: DiscoveredPath[]): DiscoveryResult[] {
  return paths
    .map((p) => (p.id == null ? null : { p, rawId: p.id as number }))
    .filter((x): x is { p: DiscoveredPath; rawId: number } => x != null)
    .map(({ p, rawId }) => ({
      id: WEB_PATH_ID_BASE + rawId,
      projectId: p.projectId,
      targetId: p.targetId,
      url: p.url || p.path || "",
      _webPath: true,
      _webPathId: rawId,
    }));
}

watch(projectId, loadAssets);
onMounted(async () => {
  await loadProjects();
  if (!projectId.value && activeProjects.value.length) {
    projectId.value = activeProjects.value[0].id;
  }
});
</script>

<template>
  <section class="assets-topology-page">
    <header class="assets-page-header">
      <div class="header-title-box">
        <h1 class="fluent-title">资产拓扑</h1>
      </div>

      <div class="header-actions">
        <el-select
          v-model="projectId"
          :loading="loading"
          placeholder="选择评估项目"
          aria-label="评估项目"
          clearable
          class="project-picker"
        >
          <el-option
            v-for="project in projects"
            :key="project.id"
            :label="project.name"
            :value="project.id"
          />
        </el-select>

        <el-tooltip content="刷新拓扑" placement="bottom">
          <el-button
            :loading="assetsLoading"
            :disabled="!projectId"
            aria-label="刷新拓扑"
            class="refresh-topology-btn"
            @click="loadAssets"
          >
            <FluentIcon v-if="!assetsLoading" name="arrow-clockwise" />
          </el-button>
        </el-tooltip>
      </div>
    </header>

    <div class="topology-wrapper">
      <AssetTopology
        v-if="projectId != null"
        :project-id="projectId"
        :assets="assets"
        :loading="assetsLoading"
        :hub-label="selectedProjectName"
        @change="loadAssets"
      />

      <el-empty
        v-else
        description="未选择评估项目"
        class="empty-project-prompt"
      />
    </div>
  </section>
</template>

<style scoped>
.assets-topology-page {
  display: flex;
  flex-direction: column;
  gap: var(--page-gap, 14px);
  width: 100%;
  height: 100%;
  min-width: 0;
  min-height: 0;
  padding: var(--page-pad-y, 16px) var(--page-pad-x, 20px);
  box-sizing: border-box;
  font-family: var(--fluent-font);
  background: transparent;
  border: 0;
  border-radius: 0;
  box-shadow: none;
}

.assets-page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px 20px;
  flex-shrink: 0;
  flex-wrap: wrap;
}

.header-title-box {
  min-width: 0;
}

.header-title-box .fluent-title {
  margin: 0;
  font-size: var(--page-title-size, 18px);
  font-weight: var(--fluent-weight-semibold, 600);
  color: var(--app-text);
  line-height: 28px;
  letter-spacing: 0;
  overflow-wrap: anywhere;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 288px;
  max-width: 100%;
  min-width: 0;
}

.project-picker {
  flex: 1;
  width: 0;
  min-width: 0;
}

.project-picker :deep(.el-select__wrapper) {
  min-height: 32px;
  height: 32px;
  line-height: 32px;
  border-radius: var(--fluent-radius-control, 4px);
  font-size: 13px;
}

.refresh-topology-btn {
  flex: 0 0 32px;
  width: 32px;
  height: 32px;
  padding: 0;
  border-radius: var(--fluent-radius-control, 4px);
  font-size: 16px;
}

.refresh-topology-btn :deep(.el-icon.is-loading) {
  margin: 0;
}

.topology-wrapper {
  flex: 1;
  min-width: 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
}

.empty-project-prompt {
  margin: auto;
  max-width: 100%;
}

@media (max-width: 640px) {
  .assets-topology-page {
    padding: 12px;
    gap: 12px;
  }

  .header-actions {
    flex: 1 1 240px;
    width: auto;
  }
}
</style>
