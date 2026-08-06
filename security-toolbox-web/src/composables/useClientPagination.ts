import { computed, ref, toValue, watch, type MaybeRefOrGetter } from "vue";

export function useClientPagination<T>(
  source: MaybeRefOrGetter<readonly T[]>,
  initialPageSize = 20,
) {
  const page = ref(1);
  const pageSize = ref(initialPageSize);
  const total = computed(() => toValue(source).length);
  const pageCount = computed(() =>
    Math.max(1, Math.ceil(total.value / pageSize.value)),
  );

  const pagedItems = computed(() => {
    const start = (page.value - 1) * pageSize.value;
    return toValue(source).slice(start, start + pageSize.value);
  });

  function resetPage() {
    page.value = 1;
  }

  watch([total, pageSize], () => {
    page.value = Math.min(Math.max(1, page.value), pageCount.value);
  });

  return { page, pageSize, total, pagedItems, resetPage };
}
