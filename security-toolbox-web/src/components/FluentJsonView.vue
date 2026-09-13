<script setup lang="ts">
import { computed } from "vue";

const props = withDefaults(
  defineProps<{
    value: unknown;
    depth?: number;
  }>(),
  {
    depth: 0,
  },
);

const isObject = computed(
  () =>
    props.value !== null &&
    typeof props.value === "object" &&
    !Array.isArray(props.value),
);

const isArray = computed(() => Array.isArray(props.value));

const isScalar = computed(
  () =>
    props.value === null ||
    props.value === undefined ||
    typeof props.value !== "object",
);

const entries = computed<Array<[string, unknown]>>(() => {
  if (!isObject.value) return [];
  return Object.entries(props.value as Record<string, unknown>);
});

const list = computed<unknown[]>(() =>
  isArray.value ? (props.value as unknown[]) : [],
);

function scalarText(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return value || "（空）";
  return String(value);
}
</script>

<template>
  <div
    class="fj-block"
    :style="{ '--fj-depth': depth }"
    :aria-level="isScalar ? undefined : depth + 1"
  >
    <span v-if="isScalar" class="fj-scalar-val">{{ scalarText(value) }}</span>

    <template v-else-if="isArray">
      <span v-if="!list.length" class="fj-scalar-val fj-empty">（空数组）</span>
      <div v-for="(item, index) in list" :key="index" class="fj-row">
        <span class="fj-key">[{{ index }}]</span>
        <FluentJsonView :value="item" :depth="depth + 1" />
      </div>
    </template>

    <template v-else-if="isObject">
      <span v-if="!entries.length" class="fj-scalar-val fj-empty"
        >（空对象）</span
      >
      <div v-for="[key, val] in entries" :key="key" class="fj-row">
        <span class="fj-key">{{ key }}</span>
        <FluentJsonView :value="val" :depth="depth + 1" />
      </div>
    </template>
  </div>
</template>

<style scoped>
.fj-block {
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding-left: calc(var(--fj-depth, 0) * 12px);
}
.fj-row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
}
.fj-key {
  flex: none;
  min-width: 132px;
  color: var(--app-muted, #64748b);
  font-family: var(--font-mono, "Cascadia Code", "Consolas", monospace);
  font-size: 11.5px;
  word-break: break-all;
}
.fj-scalar-val {
  color: var(--app-text, #1e293b);
  font-size: 12px;
  line-height: 1.5;
  word-break: break-all;
}
.fj-empty {
  color: var(--app-muted, #64748b);
  font-style: italic;
}
</style>