<script setup lang="ts">
import { computed, type CSSProperties } from "vue";
import {
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
  type Position,
} from "@vue-flow/core";

// A custom edge so the delete affordance can live INSIDE VueFlow's own transformed label
// layer (EdgeLabelRenderer). That layer tracks pan/zoom exactly and is immune to the
// `contain: paint` containing-block bug that pushed the old position:fixed context menu far
// away from the cursor in the desktop build.
const props = defineProps<{
  id: string;
  sourceX: number;
  sourceY: number;
  targetX: number;
  targetY: number;
  sourcePosition: Position;
  targetPosition: Position;
  markerEnd?: string;
  style?: CSSProperties;
  selected?: boolean;
  hovered?: boolean;
}>();

const emit = defineEmits<{ (e: "remove", id: string): void }>();

const path = computed(() =>
  getSmoothStepPath({
    sourceX: props.sourceX,
    sourceY: props.sourceY,
    sourcePosition: props.sourcePosition,
    targetX: props.targetX,
    targetY: props.targetY,
    targetPosition: props.targetPosition,
  }),
);

const showBadge = computed(() => Boolean(props.selected || props.hovered));
</script>

<template>
  <BaseEdge :id="id" :path="path[0]" :marker-end="markerEnd" :style="style" />
  <EdgeLabelRenderer>
    <div
      v-show="showBadge"
      class="wf-edge-badge nodrag nopan"
      :style="{
        transform: `translate(-50%, -50%) translate(${path[1]}px, ${path[2]}px)`,
      }"
    >
      <button
        type="button"
        aria-label="删除连线"
        title="删除连线"
        @click.stop="emit('remove', id)"
      >
        ✕
      </button>
    </div>
  </EdgeLabelRenderer>
</template>

<style scoped>
/* EdgeLabelRenderer's layer is pointer-events:none by default, so the badge must opt back in. */
.wf-edge-badge {
  position: absolute;
  pointer-events: all;
  z-index: 9;
}
.wf-edge-badge button {
  display: grid;
  width: 22px;
  height: 22px;
  place-items: center;
  border: 1px solid var(--app-border-strong);
  border-radius: 999px;
  background: var(--app-surface-strong);
  color: #a4262c;
  cursor: pointer;
  box-shadow: var(--fluent-shadow-4);
  font-size: 12px;
  line-height: 1;
  transition:
    background var(--fluent-fast),
    transform var(--fluent-fast);
}
.wf-edge-badge button:hover,
.wf-edge-badge button:focus-visible {
  outline: none;
  background: color-mix(in srgb, #c8503f 14%, var(--app-surface-strong));
  transform: scale(1.08);
}
</style>
