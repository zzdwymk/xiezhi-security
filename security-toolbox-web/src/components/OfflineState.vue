<script setup lang="ts">
/**
 * 全站统一的空状态 / 离线提示。
 *
 * 视觉规范：
 * - 圆形描边 + 破折号「—」图案，全站唯一空态图案；
 * - 标题 + 一行说明，居中显示；
 * - size="compact" 用于卡片、表格、对话框等局部区块，尺寸更小；
 * - icon 参数已废弃（保留仅为兼容既有调用），不再渲染图标。
 */
withDefaults(
  defineProps<{
    title: string;
    description?: string;
    icon?: string;
    size?: "default" | "compact";
  }>(),
  {
    description: "",
    icon: "",
    size: "default",
  },
);
</script>

<template>
  <div class="empty-state" :class="{ 'is-compact': size === 'compact' }" role="status">
    <span class="empty-mark" aria-hidden="true">—</span>
    <strong>{{ title }}</strong>
    <p v-if="description">{{ description }}</p>
    <slot />
  </div>
</template>
