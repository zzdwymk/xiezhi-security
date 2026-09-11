<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import {
  endpoints,
  safeGet,
  type AssessmentProject,
  type DiscoveredPath,
  type DiscoveryResult,
  type ProjectFindingRecord,
  type ProjectTarget,
  type Target,
} from "../api";
import AssetTopology from "../components/AssetTopology.vue";
import FluentIcon from "../components/FluentIcon.vue";
import { toErrorMessage } from "../utils/errorMessage";
import { ElMessage } from "element-plus";

const projects = ref<AssessmentProject[]>([]);
const projectId = ref<number | "all">("all");
const assets = ref<DiscoveryResult[]>([]);
const findings = ref<ProjectFindingRecord[]>([]);
const loading = ref(false);
const assetsLoading = ref(false);
const projectsOffline = ref(false);
let assetsRequestId = 0;

// Web URL 资产与目标资产的拓扑节点 id 偏移基数，避免与 probe_results 自增 id 撞号。
const WEB_PATH_ID_BASE = 10_000_000_000;
const TARGET_ASSET_ID_BASE = 5_000_000_000;

type TopologyAsset = DiscoveryResult & {
  _assetKind?: "target" | "probe" | "path";
  _targetLinkId?: number;
  _probeResultId?: number;
  _discoveredPathId?: number;
  _webPath?: boolean;
  _webPathId?: number;
  _isTargetAsset?: boolean;
};

const selectedProjectName = computed(() => {
  if (projectId.value === "all") return "全部项目";
  const found = projects.value.find((p) => p.id === projectId.value);
  return found?.name || "项目中心";
});

async function loadProjects() {
  loading.value = true;
  const result = await safeGet(endpoints.projects, projects.value);
  projectsOffline.value = result.offline;
  if (!result.offline || !projects.value.length) {
    projects.value = result.data || [];
  }
  if (result.offline) {
    ElMessage.warning("项目列表暂时不可用，请稍后重试");
  } else if (
    projectId.value !== "all" &&
    !projects.value.some((project) => project.id === projectId.value)
  ) {
    projectId.value = "all";
  }
  loading.value = false;
}

async function loadAssets() {
  const requestId = ++assetsRequestId;
  const pid = projectId.value;
  const projectIds = pid === "all" ? projects.value.map((p) => p.id) : [pid];
  if (!projectIds.length) {
    assets.value = [];
    findings.value = [];
    assetsLoading.value = false;
    return;
  }
  assetsLoading.value = true;
  try {
    // 授权目标全局读取一次，各项目分别聚合，避免跨项目合并相同 URL。
    const allTargetsRes = await safeGet(endpoints.targets, [] as Target[]);
    const targetsById = new Map((allTargetsRes.data || []).map((t) => [t.id, t]));
    // 报告摘要可能很重；限制并发批次，避免项目数量增加后同时压垮 API。
    const results: Awaited<ReturnType<typeof loadProjectAssets>>[] = [];
    for (let index = 0; index < projectIds.length; index += 4) {
      if (requestId !== assetsRequestId || pid !== projectId.value) return;
      const batch = projectIds.slice(index, index + 4);
      results.push(...(await Promise.all(
        batch.map((id) => loadProjectAssets(id, targetsById)),
      )));
    }
    if (requestId !== assetsRequestId || pid !== projectId.value) return;
    assets.value = results.flatMap((result) => result.assets);
    findings.value = results.flatMap((result) => result.findings);
    if (allTargetsRes.offline || results.some((result) => result.offline)) {
      ElMessage.warning("部分资产或风险数据加载失败，请刷新重试");
    }
  } catch (error) {
    if (requestId === assetsRequestId) {
      ElMessage.error(toErrorMessage(error, "资产加载失败"));
    }
  } finally {
    if (requestId === assetsRequestId) assetsLoading.value = false;
  }
}

async function loadProjectAssets(pid: number, targetsById: Map<number, Target>) {
  const [probeResults, webPaths, summaryResult, projectTargetsRes] =
    await Promise.all([
      safeGet(() => endpoints.projectDiscoveryResults(pid), [] as DiscoveryResult[]),
      safeGet(() => endpoints.projectDiscoveredPaths(pid), [] as DiscoveredPath[]),
      safeGet(() => endpoints.projectReportSummary(pid), null),
      safeGet(() => endpoints.projectTargets(pid), [] as ProjectTarget[]),
    ]);

  const targetAssets: TopologyAsset[] = (projectTargetsRes.data || []).flatMap((pt) => {
    const t = targetsById.get(pt.targetId);
    if (!t) return [];
    const isUrl = String(t.targetType || "").toUpperCase() === "URL";
    const rawVal = String(t.targetValue || "").trim();
    const url = normalizeAssetUrl(rawVal);
    return [{
      // 同一授权目标可关联多个项目，使用项目目标关联 ID 保持节点唯一。
      id: TARGET_ASSET_ID_BASE + pt.id,
      projectId: pid,
      targetId: t.id,
      url,
      targetValue: t.targetValue,
      server: isUrl ? "授权 Web 靶点" : "授权资产主机",
      framework: isUrl ? "URL 资产" : "IP 资产",
      // 授权目标是项目关系的只读占位，不是 recon 发现路径，不能走删除发现结果接口。
      _assetKind: "target",
      _targetLinkId: pt.id,
      _isTargetAsset: true,
    }];
  });

  const probeAssets: TopologyAsset[] = (probeResults.data || []).map((asset) => ({
    ...asset,
    _assetKind: "probe" as const,
    _probeResultId: asset.id,
  }));

  const merged = mergeProjectAssets(pid, [
    ...asPathAssets(webPaths.data || []),
    ...targetAssets,
    ...probeAssets,
  ]);

  return {
    assets: merged,
    findings: (summaryResult.data?.findings || []).map((finding) => ({
      ...finding,
      projectId: pid,
    })),
    offline: [probeResults, webPaths, summaryResult, projectTargetsRes].some(
      (result) => result.offline,
    ),
  };
}

function normalizeAssetUrl(raw: unknown): string {
  const value = String(raw ?? "").trim();
  if (!value) return "";
  const withScheme = /^https?:\/\//i.test(value) ? value : `http://${value}`;
  // WHATWG URL requires IPv6 literals in an authority to be bracketed. The
  // API may return either a bare literal (`2001:db8::1/path`) or a URL with
  // the brackets omitted, so repair the authority before parsing/canonicalizing.
  const match = /^(https?:\/\/)([^/?#]*)([\s\S]*)$/i.exec(withScheme);
  if (!match) return withScheme;
  const [, scheme, authority, suffix] = match;
  if (authority.startsWith("[") || authority.split(":").length < 3) {
    return withScheme;
  }
  const userInfoEnd = authority.lastIndexOf("@");
  const userInfo = userInfoEnd >= 0 ? authority.slice(0, userInfoEnd + 1) : "";
  const host = userInfoEnd >= 0 ? authority.slice(userInfoEnd + 1) : authority;
  return `${scheme}${userInfo}[${host}]${suffix}`;
}

function canonicalAssetUrl(raw: unknown): string {
  const value = normalizeAssetUrl(raw);
  if (!value) return "";
  try {
    const parsed = new URL(value);
    const protocol = parsed.protocol.toLowerCase();
    const rawHostname = parsed.hostname.toLowerCase();
    const hostname = rawHostname.replace(/^\[|\]$/g, "");
    const isDefaultPort =
      (protocol === "http:" && parsed.port === "80") ||
      (protocol === "https:" && parsed.port === "443");
    const port = parsed.port && !isDefaultPort ? `:${parsed.port}` : "";
    const pathname = parsed.pathname === "/" ? "" : parsed.pathname;
    const host = hostname.includes(":") ? `[${hostname}]` : hostname;
    return `${protocol}//${host}${port}${pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return value.replace(/\/+$/, "");
  }
}

function assetPriority(asset: TopologyAsset): number {
  if (asset._isTargetAsset === true) return 1;
  if (asset._webPath === true) return 2;
  // A probe result contains the server/framework/WAF evidence needed by the
  // detail drawer, so it should win over a synthetic target placeholder.
  return 3;
}

function hasAssetValue(value: unknown): boolean {
  if (value == null) return false;
  if (typeof value === "string") return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

const ASSET_DETAIL_KEYS = [
  "targetValue",
  "server",
  "framework",
  "fingerprint",
  "technologies",
  "waf",
  "wafName",
  "confidence",
  "evidence",
  "detectedAt",
  "createdAt",
] as const;

function mergeProjectAssets(
  projectId: number,
  sourceAssets: TopologyAsset[],
): TopologyAsset[] {
  const byUrl = new Map<string, TopologyAsset>();

  for (const source of sourceAssets) {
    const asset = { ...source, projectId };
    const key = canonicalAssetUrl(asset.url);
    if (!key) continue;

    const current = byUrl.get(key);
    if (!current) {
      byUrl.set(key, asset);
      continue;
    }

    const preferred = assetPriority(asset) > assetPriority(current) ? asset : current;
    const supplemental = preferred === asset ? current : asset;
    const preferredKind: "target" | "path" | "probe" =
      preferred._assetKind === "target" || preferred._isTargetAsset === true
        ? "target"
        : preferred._assetKind === "path" || preferred._webPath === true
          ? "path"
          : "probe";
    const supplementalKind: "target" | "path" | "probe" =
      supplemental._assetKind === "target" || supplemental._isTargetAsset === true
        ? "target"
        : supplemental._assetKind === "path" || supplemental._webPath === true
          ? "path"
          : "probe";
    const sameKindSupplemental = supplementalKind === preferredKind;
    const merged: TopologyAsset = {
      ...supplemental,
      ...preferred,
      id: preferred.id ?? supplemental.id,
      projectId,
      targetId: preferred.targetId ?? supplemental.targetId,
      targetValue: preferred.targetValue ?? supplemental.targetValue,
      // Keep source-specific metadata only when the selected record does not
      // already provide it. A real probe result must remain deletable; a
      // synthetic target placeholder must remain protected.
      // Source-specific identifiers must never cross a provenance boundary:
      // otherwise a path selected over an authorization placeholder could
      // incorrectly expose the placeholder's remove action.
      _webPath: preferredKind === "path",
      _webPathId:
        preferredKind === "path"
          ? preferred._webPathId ?? (sameKindSupplemental ? supplemental._webPathId : undefined)
          : undefined,
      _isTargetAsset: preferredKind === "target",
      _assetKind: preferredKind,
      _targetLinkId:
        preferredKind === "target"
          ? preferred._targetLinkId ?? (sameKindSupplemental ? supplemental._targetLinkId : undefined)
          : undefined,
      _probeResultId:
        preferredKind === "probe"
          ? preferred._probeResultId ?? (sameKindSupplemental ? supplemental._probeResultId : undefined)
          : undefined,
      _discoveredPathId:
        preferredKind === "path"
          ? preferred._discoveredPathId ?? (sameKindSupplemental ? supplemental._discoveredPathId : undefined)
          : undefined,
    };
    // Some API records are sparse (for example a probe may only contain a
    // URL while an earlier result has WAF/evidence). Fill only missing values
    // so the preferred record's stronger provenance does not erase details.
    const mergedFields = merged as Record<string, unknown>;
    const supplementalFields = supplemental as Record<string, unknown>;
    for (const key of ASSET_DETAIL_KEYS) {
      if (!hasAssetValue(mergedFields[key]) && hasAssetValue(supplementalFields[key])) {
        mergedFields[key] = supplementalFields[key];
      }
    }
    byUrl.set(key, merged);
  }

  return Array.from(byUrl.values());
}

// 把 DiscoveredPath 规整为拓扑可直接消费的 DiscoveryResult 形态（保留 id/url/归属）。
function asPathAssets(paths: DiscoveredPath[]): TopologyAsset[] {
  return paths
    .map((p) => (p.id == null ? null : { p, rawId: p.id as number }))
    .filter((x): x is { p: DiscoveredPath; rawId: number } => x != null)
    .map(({ p, rawId }) => ({
      id: WEB_PATH_ID_BASE + rawId,
      projectId: p.projectId,
      targetId: p.targetId,
      url: p.url || p.path || "",
      server: "探测发现路径",
      framework: "Web 资源",
      _assetKind: "path",
      _discoveredPathId: rawId,
      _webPath: true,
      _webPathId: rawId,
    }));
}

watch(projectId, () => {
  assets.value = [];
  findings.value = [];
  void loadAssets();
});

async function refreshTopology() {
  await loadProjects();
  await loadAssets();
}

onMounted(async () => {
  await loadProjects();
  await loadAssets();
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
          class="project-picker"
        >
          <el-option label="全部项目" value="all" />
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
            :disabled="loading || assetsLoading"
            aria-label="刷新拓扑"
            class="refresh-topology-btn"
            @click="refreshTopology"
          >
            <FluentIcon v-if="!assetsLoading" name="arrow-clockwise" />
          </el-button>
        </el-tooltip>
      </div>
    </header>

    <div class="topology-wrapper">
      <AssetTopology
        v-if="loading || projects.length"
        :project-id="projectId"
        :assets="assets"
        :findings="findings"
        :loading="loading || assetsLoading"
        :hub-label="selectedProjectName"
        :projects="projects"
        @change="loadAssets"
      />

      <el-empty
        v-else
        :description="projectsOffline ? '项目列表暂时不可用' : '暂无评估项目，请先创建项目'"
        class="empty-project-prompt"
      >
        <el-button v-if="projectsOffline" type="primary" @click="refreshTopology">
          重试
        </el-button>
      </el-empty>
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
