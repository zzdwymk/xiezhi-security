<script setup lang="ts">
import { computed, ref, useId } from "vue";
import { renderMarkdown } from "../utils/markdown";
import FluentIcon from "./FluentIcon.vue";

const props = defineProps<{ content: string }>();
const expanded = ref(true);
const regionId = useId();
// Keep the editable source and the outgoing message untouched. Preview uses
// exactly the same safe, unlocalized rendering as a sent user message.
const html = computed(() => renderMarkdown(props.content));
</script>

<template>
  <section v-if="content.trim()" class="composer-preview" :class="{ 'composer-preview--expanded': expanded }" aria-label="输入内容预览">
    <button type="button" class="composer-preview-toggle" :aria-expanded="expanded" :aria-controls="regionId" :aria-label="expanded ? '收起实时预览' : '展开实时预览'" :title="expanded ? '收起实时预览' : '展开实时预览'" @click="expanded = !expanded">
      <span>实时预览</span><FluentIcon :name="expanded ? 'chevron-up' : 'chevron-down'" />
    </button>
    <div v-show="expanded" :id="regionId" class="composer-preview-body markdown-body" tabindex="0" aria-label="Markdown 实时预览，可滚动查看" v-html="html" />
  </section>
</template>

<style scoped>
.composer-preview { min-width: 0; margin: 0 4px 8px; border-top: 1px solid var(--app-border); }
.composer-preview-toggle { display: flex; align-items: center; gap: 6px; min-height: 32px; padding: 3px 0; border: 0; background: transparent; color: var(--app-text-muted); font: inherit; font-size: 12px; cursor: pointer; }
.composer-preview-toggle .fluent-system-icon { width: 14px; height: 14px; }
.composer-preview-body { max-height: min(180px, 24vh); min-width: 0; overflow: auto; overflow-wrap: anywhere; padding: 0 4px 4px; font-size: 14px; line-height: 1.6; color: var(--app-text); }
.composer-preview-body :deep(> :first-child) { margin-top: 0; }
.composer-preview-body :deep(> :last-child) { margin-bottom: 0; }
.composer-preview-body :deep(table) { display: block; max-width: 100%; overflow-x: auto; }
.composer-preview-body :deep(pre) { max-width: 100%; overflow-x: auto; }
.composer-preview-toggle:focus-visible, .composer-preview-body:focus-visible { outline: 2px solid var(--app-accent); outline-offset: 2px; }
/* Query the actual composer width: the sidebar can leave a narrow editor even
   on a wide desktop. References, editing notices and actions keep a full row. */
:global(.chat-page :is(.welcome-composer, .thread-composer):has(.composer-preview)) {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  container: ai-composer / inline-size;
}
:global(:is(.welcome-composer, .thread-composer):has(.composer-preview) > *) {
  grid-column: 1 / -1;
  min-width: 0;
}
:global(.chat-page :is(.welcome-composer, .thread-composer):has(.composer-preview:not(.composer-preview--expanded))) {
  grid-template-columns: minmax(0, 1fr) auto;
}
@container ai-composer (min-width: 580px) {
  .composer-preview-toggle .fluent-system-icon { transform: rotate(90deg); }
  :global(.chat-page :is(.welcome-composer, .thread-composer):has(.composer-preview) > textarea) {
    grid-column: 1;
    width: 100%;
    min-width: 0;
  }
  :global(.chat-page :is(.welcome-composer, .thread-composer) > .composer-preview) {
    grid-column: 2;
    border-top: 0;
    border-left: 1px solid var(--app-border);
    margin: 8px 0;
    padding: 0 12px;
  }
  .composer-preview:not(.composer-preview--expanded) { align-self: start; }
  .composer-preview:not(.composer-preview--expanded) .composer-preview-toggle { white-space: nowrap; }
  :global(.chat-page :is(.welcome-composer, .thread-composer):has(.composer-preview--expanded) > textarea) {
    grid-column: 1;
    width: 100%;
    height: 100%;
    min-height: 144px;
    max-height: none;
    box-sizing: border-box;
    align-self: stretch;
    overflow: auto;
  }
  :global(.chat-page :is(.welcome-composer, .thread-composer) > .composer-preview--expanded) {
    grid-column: 2;
    border-top: 0;
    border-left: 1px solid var(--app-border);
    margin: 8px 0;
    padding: 0 12px;
  }
  .composer-preview--expanded .composer-preview-body { max-height: min(180px, 24vh); }
}
@media (max-height: 650px) { .composer-preview-body { max-height: 100px; } }
</style>
