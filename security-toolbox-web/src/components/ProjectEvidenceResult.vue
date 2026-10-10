<script setup lang="ts">
import { computed } from "vue";
import MarkdownBody from "./MarkdownBody.vue";

const props = defineProps<{ data: unknown }>();
const record = computed(() => props.data && typeof props.data === "object" ? props.data as Record<string, unknown> : {});
const query = computed(() => typeof record.value.query === "string" ? record.value.query : "");
const items = computed(() => Array.isArray(record.value.items) ? record.value.items.filter(
  (item): item is { title: string; snippet: string; source: string } => item && typeof item.title === "string" && typeof item.snippet === "string",
) : []);
function sourceLabel(source: string) {
  return ({ project: "项目资料", target: "目标资料", task: "历史任务", finding: "检测发现", recon: "资产信息", probe: "探测记录" } as Record<string, string>)[source] || "相关资料";
}
</script>

<template>
  <section class="project-evidence-result" aria-label="项目资料检索结果">
    <p v-if="query" class="evidence-query"><strong>查询内容</strong><span>{{ query }}</span></p>
    <p v-if="!items.length" class="evidence-empty">没有找到匹配的已有资料，不能据此判断目标不存在风险。</p>
    <article v-for="(item, index) in items" :key="index" class="evidence-item">
      <header><strong>{{ item.title }}</strong><span>{{ sourceLabel(item.source) }}</span></header>
      <MarkdownBody :content="item.snippet" />
    </article>
  </section>
</template>

<style scoped>
.project-evidence-result { min-width: 0; overflow-wrap: anywhere; }
.evidence-query { display: grid; gap: 4px; margin: 0 0 12px; }
.evidence-item { padding: 12px; margin-top: 10px; border: 1px solid var(--app-border); border-radius: 8px; }
.evidence-item header { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px; margin-bottom: 8px; }
.evidence-item header span, .evidence-empty { color: var(--app-muted); font-size: 12px; }
</style>
