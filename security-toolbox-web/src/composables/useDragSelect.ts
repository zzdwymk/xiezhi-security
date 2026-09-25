import {
  computed,
  onBeforeUnmount,
  onMounted,
  ref,
  type ComputedRef,
  type Ref,
} from "vue";
import type { TableInstance } from "element-plus";

export interface MarqueeRect {
  left: number;
  top: number;
  width: number;
  height: number;
  right: number;
  bottom: number;
}

export interface UseDragSelectOptions<T extends object> {
  /** The container section or wrapper element where pointerdown can initiate marquee selection */
  containerRef: Ref<HTMLElement | null | undefined>;
  /** The Element Plus ElTable instance ref */
  tableRef: Ref<TableInstance | null | undefined>;
  /** The current page rows / data array */
  items: Ref<readonly T[]> | ComputedRef<readonly T[]>;
  /** Unique ID extractor for each item */
  getItemId: (item: T) => number | string;
  /** Currently selected items */
  selectedItems: Ref<TargetLike[] | T[]>;
  /** Row selector inside the table tbody (default: 'tbody > tr.el-table__row') */
  rowSelector?: string;
  /** Minimum pixel movement to trigger drag selection (default: 4) */
  dragThreshold?: number;
}

interface TargetLike {
  id?: number | string;
  [key: string]: unknown;
}

const DEFAULT_IGNORE_SELECTOR = [
  "button",
  ".el-button",
  "input",
  "textarea",
  ".el-checkbox",
  ".el-checkbox__inner",
  ".el-checkbox__original",
  ".el-switch",
  ".el-input",
  ".el-select",
  ".el-dropdown",
  ".el-tag",
  ".el-table__header-wrapper",
  "thead",
  "th",
  ".targets-pagination",
  ".el-pagination",
  ".el-dialog",
  ".el-popper",
  ".el-tooltip",
  "a",
  "[role='button']",
  "[role='checkbox']",
].join(", ");

export function useDragSelect<T extends object>({
  containerRef,
  tableRef,
  items,
  getItemId,
  selectedItems,
  rowSelector = "tbody > tr.el-table__row",
  dragThreshold = 4,
}: UseDragSelectOptions<T>) {
  const isDragging = ref(false);
  const marqueeRect = ref<MarqueeRect | null>(null);

  let isPointerDown = false;
  let startX = 0;
  let startY = 0;
  let isCtrl = false;
  let isShift = false;
  let isLongPress = false;
  let longPressTimer: number | undefined;
  let snapshotSelectedIds = new Set<number | string>();
  let autoScrollRaf = 0;
  let lastClientY = 0;
  let anchorRowIndex: number | null = null;

  const marqueeStyle = computed(() => {
    if (!marqueeRect.value || !isDragging.value) {
      return { display: "none" };
    }
    const { left, top, width, height } = marqueeRect.value;
    return {
      position: "fixed" as const,
      left: `${left}px`,
      top: `${top}px`,
      width: `${width}px`,
      height: `${height}px`,
      pointerEvents: "none" as const,
      zIndex: 99999,
    };
  });

  function getTableEl(): HTMLElement | undefined {
    const inst = tableRef.value;
    if (!inst) return undefined;
    return (inst as unknown as { $el?: HTMLElement }).$el || (inst as unknown as HTMLElement);
  }

  function getSelectedIdSet(): Set<number | string> {
    const set = new Set<number | string>();
    for (const item of selectedItems.value) {
      set.add(getItemId(item as T));
    }
    return set;
  }

  function cleanupAutoScroll() {
    if (autoScrollRaf) {
      cancelAnimationFrame(autoScrollRaf);
      autoScrollRaf = 0;
    }
  }

  function onDragStart(e: DragEvent) {
    if (isPointerDown) {
      e.preventDefault();
    }
  }

  function onSelectStart(e: Event) {
    if (isDragging.value) {
      e.preventDefault();
    }
  }

  function cleanupWindowListeners() {
    window.removeEventListener("pointermove", onPointerMove);
    window.removeEventListener("pointerup", onPointerUp);
    window.removeEventListener("pointercancel", onPointerUp);
    window.removeEventListener("keydown", onKeyDown);
    window.removeEventListener("dragstart", onDragStart);
    window.removeEventListener("selectstart", onSelectStart);
    cleanupAutoScroll();
  }

  function resetDragStyles() {
    document.body.style.userSelect = "";
    document.body.style.webkitUserSelect = "";
    document.body.style.cursor = "";
  }

  function rowIndexAtClientY(clientY: number): number | null {
    const tableEl = getTableEl();
    if (!tableEl) return null;

    const rowEls = tableEl.querySelectorAll<HTMLTableRowElement>(rowSelector);
    if (!rowEls.length) return null;

    for (let i = 0; i < rowEls.length; i++) {
      const r = rowEls[i].getBoundingClientRect();
      if (r.top <= clientY && clientY <= r.bottom) return i;
    }
    // Fall back to nearest row inside the scroll container
    const bodyWrapper = tableEl.querySelector<HTMLElement>(".el-table__body-wrapper");
    if (!bodyWrapper) return null;

    const bodyRect = bodyWrapper.getBoundingClientRect();
    if (clientY < bodyRect.top) return 0;
    if (clientY > bodyRect.bottom) return rowEls.length - 1;
    return null;
  }

  function updateIntersections(box: MarqueeRect) {
    void box;
    const tableEl = getTableEl();
    if (!tableEl) return;

    const rowEls = tableEl.querySelectorAll<HTMLTableRowElement>(rowSelector);
    if (!rowEls.length) return;

    const currentSelectedIds = getSelectedIdSet();
    const currentItems = items.value;
    const count = Math.min(currentItems.length, rowEls.length);

    // During auto-scroll the anchor row (where the drag started) is fixed,
    // while the pointer's row index grows/shrinks with scrolling. Selecting by
    // a CONTIGUOUS row-index range between the anchor and the current pointer
    // row keeps newly scrolled-in rows selected even if a frame never happened
    // to intersect them with the marquee box.
    const pointerRowIndex = rowIndexAtClientY(lastClientY);
    if (anchorRowIndex == null || pointerRowIndex == null) return;

    const lo = Math.min(anchorRowIndex, pointerRowIndex);
    const hi = Math.max(anchorRowIndex, pointerRowIndex);

    for (let i = 0; i < count; i++) {
      const item = currentItems[i];
      if (!item) continue;

      const inRange = i >= lo && i <= hi;
      const itemId = getItemId(item);
      const wasInitiallySelected = snapshotSelectedIds.has(itemId);

      let shouldSelect = false;
      if (isCtrl) {
        // Toggle items inside the range, leave others as initial
        shouldSelect = inRange ? !wasInitiallySelected : wasInitiallySelected;
      } else {
        // Standard / Shift drag (append): select everything in the range and
        // never un-select what was already selected (e.g. items scrolled out
        // of the viewport during auto-scroll).
        shouldSelect = wasInitiallySelected || inRange;
      }

      const isCurrentlySelected = currentSelectedIds.has(itemId);
      if (isCurrentlySelected !== shouldSelect) {
        tableRef.value?.toggleRowSelection(item as any, shouldSelect);
      }
    }
  }

  function autoScrollLoop() {
    if (!isDragging.value || !isPointerDown) return;

    const tableEl = getTableEl();
    if (tableEl) {
      const bodyWrapper = tableEl.querySelector<HTMLElement>(".el-table__body-wrapper");
      if (bodyWrapper && bodyWrapper.scrollHeight > bodyWrapper.clientHeight) {
        const rect = bodyWrapper.getBoundingClientRect();
        const edgeZone = 40;
        const maxSpeed = 12;

        if (lastClientY > rect.bottom - edgeZone && lastClientY < rect.bottom + edgeZone) {
          const intensity = Math.min(1, (lastClientY - (rect.bottom - edgeZone)) / edgeZone);
          bodyWrapper.scrollTop += Math.max(2, Math.round(intensity * maxSpeed));
        } else if (lastClientY < rect.top + edgeZone && lastClientY > rect.top - edgeZone) {
          const intensity = Math.min(1, (rect.top + edgeZone - lastClientY) / edgeZone);
          bodyWrapper.scrollTop -= Math.max(2, Math.round(intensity * maxSpeed));
        }
      }
    }

    // Also window vertical scroll if near viewport boundaries
    const viewportHeight = window.innerHeight;
    if (lastClientY > viewportHeight - 35) {
      window.scrollBy(0, 8);
    } else if (lastClientY < 35 && window.scrollY > 0) {
      window.scrollBy(0, -8);
    }

    // Refresh intersections if marquee is active
    if (marqueeRect.value) {
      updateIntersections(marqueeRect.value);
    }

    autoScrollRaf = requestAnimationFrame(autoScrollLoop);
  }

  function onPointerMove(e: PointerEvent) {
    if (!isPointerDown) return;

    lastClientY = e.clientY;
    const dx = e.clientX - startX;
    const dy = e.clientY - startY;
    const dist = Math.hypot(dx, dy);

    if (!isDragging.value) {
      if (dist >= dragThreshold || isLongPress) {
        isDragging.value = true;
        document.body.style.userSelect = "none";
        document.body.style.webkitUserSelect = "none";
        document.body.style.cursor = "default";
        if (!autoScrollRaf) {
          autoScrollRaf = requestAnimationFrame(autoScrollLoop);
        }
      } else {
        return;
      }
    }

    if (e.cancelable) {
      e.preventDefault();
    }

    const left = Math.min(startX, e.clientX);
    const top = Math.min(startY, e.clientY);
    const width = Math.abs(e.clientX - startX);
    const height = Math.abs(e.clientY - startY);
    const right = left + width;
    const bottom = top + height;

    const box: MarqueeRect = { left, top, width, height, right, bottom };
    marqueeRect.value = box;
    updateIntersections(box);
  }

  function onPointerUp(e: PointerEvent) {
    if (!isPointerDown) return;
    isPointerDown = false;

    if (longPressTimer) {
      window.clearTimeout(longPressTimer);
      longPressTimer = undefined;
    }
    isLongPress = false;
    anchorRowIndex = null;

    cleanupWindowListeners();
    resetDragStyles();

    if (isDragging.value) {
      isDragging.value = false;
      marqueeRect.value = null;
    } else {
      // User tapped or clicked without dragging
      const target = e.target as HTMLElement | null;
      const clickedRow = target?.closest(".el-table__row");
      // If clicked on whitespace/background outside any row and without Ctrl/Shift modifiers
      if (!clickedRow && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
        tableRef.value?.clearSelection();
      }
    }
  }

  function onKeyDown(e: KeyboardEvent) {
    if (e.key === "Escape") {
      if (isDragging.value) {
        // Cancel dragging and revert to snapshot
        isDragging.value = false;
        marqueeRect.value = null;
        cleanupWindowListeners();
        resetDragStyles();

        const currentItems = items.value;
        const currentSelectedIds = getSelectedIdSet();
        for (const item of currentItems) {
          const itemId = getItemId(item);
          const wasSelected = snapshotSelectedIds.has(itemId);
          const isSelectedNow = currentSelectedIds.has(itemId);
          if (wasSelected !== isSelectedNow) {
            tableRef.value?.toggleRowSelection(item as any, wasSelected);
          }
        }
      } else if (selectedItems.value.length > 0) {
        tableRef.value?.clearSelection();
      }
    }
  }

  function onContainerPointerDown(e: PointerEvent) {
    // Only respond to main button (left click / single finger touch)
    if (e.button !== 0) return;

    const target = e.target as HTMLElement | null;
    if (!target) return;

    // Ignore interactive controls, headers, buttons, inputs, pagination, etc.
    if (target.closest(DEFAULT_IGNORE_SELECTOR)) {
      return;
    }

    isDragging.value = false;
    marqueeRect.value = null;
    isPointerDown = true;
    startX = e.clientX;
    startY = e.clientY;
    lastClientY = e.clientY;
    isCtrl = e.ctrlKey || e.metaKey;
    isShift = e.shiftKey;
    isLongPress = false;
    snapshotSelectedIds = getSelectedIdSet();
    anchorRowIndex = rowIndexAtClientY(startY);

    // Long press timer (250ms) for touch / long-press drag
    if (longPressTimer) {
      window.clearTimeout(longPressTimer);
    }
    longPressTimer = window.setTimeout(() => {
      if (isPointerDown) {
        isLongPress = true;
      }
    }, 250);

    window.addEventListener("pointermove", onPointerMove, { passive: false });
    window.addEventListener("pointerup", onPointerUp);
    window.addEventListener("pointercancel", onPointerUp);
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("dragstart", onDragStart);
    window.addEventListener("selectstart", onSelectStart);
  }

  function onGlobalKeyDown(e: KeyboardEvent) {
    // Ctrl+A / Cmd+A to select all items on current page
    if ((e.ctrlKey || e.metaKey) && (e.key === "a" || e.key === "A")) {
      const activeEl = document.activeElement;
      if (
        activeEl &&
        (activeEl.tagName === "INPUT" ||
          activeEl.tagName === "TEXTAREA" ||
          activeEl.getAttribute("contenteditable") === "true")
      ) {
        return;
      }

      const container = containerRef.value;
      if (container && (container.contains(activeEl) || container.matches(":hover"))) {
        e.preventDefault();
        const currentItems = items.value;
        const currentSelectedIds = getSelectedIdSet();
        for (const item of currentItems) {
          const itemId = getItemId(item);
          if (!currentSelectedIds.has(itemId)) {
            tableRef.value?.toggleRowSelection(item as any, true);
          }
        }
      }
    }
  }

  function clearSelection() {
    tableRef.value?.clearSelection();
  }

  function selectAll() {
    const currentItems = items.value;
    const currentSelectedIds = getSelectedIdSet();
    for (const item of currentItems) {
      const itemId = getItemId(item);
      if (!currentSelectedIds.has(itemId)) {
        tableRef.value?.toggleRowSelection(item as any, true);
      }
    }
  }

  onMounted(() => {
    window.addEventListener("keydown", onGlobalKeyDown);
  });

  onBeforeUnmount(() => {
    cleanupWindowListeners();
    resetDragStyles();
    window.removeEventListener("keydown", onGlobalKeyDown);
    if (longPressTimer) {
      window.clearTimeout(longPressTimer);
    }
  });

  return {
    isDragging,
    marqueeRect,
    marqueeStyle,
    onContainerPointerDown,
    clearSelection,
    selectAll,
  };
}
