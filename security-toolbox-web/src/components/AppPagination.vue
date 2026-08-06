<script setup lang="ts">
const page = defineModel<number>("page", { required: true });
const pageSize = defineModel<number>("pageSize", { required: true });

withDefaults(
  defineProps<{
    total: number;
    pageSizes?: number[];
    layout?: string;
  }>(),
  {
    pageSizes: () => [20, 50, 100],
    layout: "total, sizes, prev, pager, next",
  },
);

const emit = defineEmits<{
  currentChange: [page: number];
  sizeChange: [pageSize: number];
}>();
</script>

<template>
  <div v-if="total > 0">
    <el-pagination
      v-model:current-page="page"
      v-model:page-size="pageSize"
      :page-sizes="pageSizes"
      :layout="layout"
      :total="total"
      @current-change="emit('currentChange', $event)"
      @size-change="emit('sizeChange', $event)"
    />
  </div>
</template>
