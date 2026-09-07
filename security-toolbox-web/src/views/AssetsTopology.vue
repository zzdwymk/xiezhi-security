<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { endpoints, safeGet, type AssessmentProject, type DiscoveryResult } from "../api";
import AssetTopology from "../components/AssetTopology.vue";
import FluentIcon from "../components/FluentIcon.vue";
import { toErrorMessage } from "../utils/errorMessage";
import { ElMessage } from "element-plus";

const projects = ref<AssessmentProject[]>([]);
const projectId = ref<number>();
const assets = ref<DiscoveryResult[]>([]);
const loading = ref(false);
const assetsLoading = ref(false);

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
  if (!projectId.value) {
    assets.value = [];
    return;
  }
  assetsLoading.value = true;
  try {
    assets.value = (await endpoints.projectDiscoveryResults(projectId.value)).data;
  } catch (error) {
    ElMessage.error(toErrorMessage(error, "资产加载失败"));
  } finally {
    assetsLoading.value = false;
  }
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
  <section class="panel assets-topology-page">
    <header class="assets-page-header">
      <div class="header-title-box">
        <h1 class="fluent-title">资产拓扑</h1>
        <p class="fluent-subtitle">以项目为核心透视网络资产测绘、开放服务与爬虫回填的攻击面拓扑分布</p>
      </div>

      <div class="header-actions">
        <el-select
          v-model="projectId"
          :loading="loading"
          placeholder="选择评估项目"
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

        <el-button
          :loading="assetsLoading"
          :disabled="!projectId"
          class="fluent-action-btn"
          @click="loadAssets"
        >
          <FluentIcon name="arrow-sync" :size="14" style="margin-right: 6px;" />
          刷新拓扑
        </el-button>
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
        description="请在上方选择一个评估项目以展示资产拓扑"
        class="empty-project-prompt"
      />
    </div>
  </section>
</template>

<style scoped>
.assets-topology-page {
  display: flex;
  flex-direction: column;
  padding: 16px 20px;
  height: calc(100vh - 100px);
  min-height: 640px;
  box-sizing: border-box;
  font-family: var(--fluent-font);
  background: var(--app-surface);
  border-radius: var(--fluent-radius-card);
  border: 1px solid var(--app-border);
}

.assets-page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 14px;
  flex-shrink: 0;
}

.header-title-box .fluent-title {
  margin: 0;
  font-size: var(--type-section-title, 18px);
  font-weight: var(--fluent-weight-semibold, 600);
  color: var(--app-text);
  letter-spacing: -0.01em;
}

.header-title-box .fluent-subtitle {
  margin: 4px 0 0;
  color: var(--app-muted);
  font-size: var(--fluent-caption1-size, 12px);
  line-height: var(--fluent-caption1-line, 16px);
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 10px;
}

.project-picker {
  width: 240px;
}

.fluent-action-btn {
  border-radius: var(--fluent-radius-control, 4px);
  font-family: var(--fluent-font);
  font-size: var(--fluent-body1-size, 14px);
}

.topology-wrapper {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}

.empty-project-prompt {
  margin: auto;
}
</style>
