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
  // Pointer-down position converted to content coordinates (adds the scroll
  // offset at press time) so the marquee is rooted in the document, exactly
  // like Windows Explorer. Scrolling then makes the box grow naturally.
  let startContentY = 0;
  let lastClientX = 0;
  let isCtrl = false;
  let isShift = false;
  let isLongPress = false;
  let longPressTimer: number | undefined;
  let snapshotSelectedIds = new Set<number | string>();
  let autoScrollRaf = 0;
  let lastClientY = 0;

  const marqueeStyle = computed(() => {
    if (!marqueeRect.value || !isDragging.value) {
      return { display: "none" };
    }
    const { left, top, width, height } = marqueeRect.value;

    // The logical box is anchored in content space and may extend above/below
    // the scroll viewport (that's how it stretches while scrolling). For
    // painting, clip it to the visible content area so it can never cover the
    // window title bar / app chrome.
    const scroller = getScrollerEl();
    const sr = scroller.getBoundingClientRect();
    const drawLeft = Math.max(left, sr.left);
    const drawTop = Math.max(top, sr.top);
    const drawRight = Math.min(left + width, sr.right);
    const drawBottom = Math.min(top + height, sr.bottom);
    const drawWidth = Math.max(0, drawRight - drawLeft);
    const drawHeight = Math.max(0, drawBottom - drawTop);

    return {
      position: "fixed" as const,
      left: `${drawLeft}px`,
      top: `${drawTop}px`,
      width: `${drawWidth}px`,
      height: `${drawHeight}px`,
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

  function rectsIntersect(a: MarqueeRect, row: DOMRect): boolean {
    return (
      a.left < row.right &&
      a.right > row.left &&
      a.top < row.bottom &&
      a.bottom > row.top
    );
  }

  // The ACTUAL vertical scroll container for the table. In this app that is
  // `.desktop-v2-content` (overflow:auto), not `window.scrollY`. Cached lazily.
  let scrollerEl: HTMLElement | null | undefined;

  function getScrollerEl(): HTMLElement {
    if (scrollerEl) return scrollerEl;
    let el: HTMLElement | null = getTableEl()?.parentElement ?? null;
    let found: HTMLElement | null = null;
    while (el) {
      if (el.classList?.contains("desktop-v2-content")) {
        found = el;
        break;
      }
      const ov = getComputedStyle(el).overflowY;
      if (ov === "auto" || ov === "scroll" || ov === "overlay") {
        found = el;
        break;
      }
      el = el.parentElement;
    }
    scrollerEl =
      found ??
      (document.scrollingElement as HTMLElement | null) ??
      document.documentElement;
    return scrollerEl;
  }

  // Build the marquee in VIEWPORT coordinates. The box is anchored in the
  // scroller's CONTENT coordinates, so when the user scrolls the content the
  // anchored edge moves (and can leave the visible area), stretching the box
  // out exactly like Windows Explorer.
  function updateMarquee(cx: number, cy: number) {
    const scroller = getScrollerEl();
    const rect = scroller.getBoundingClientRect();
    const scrollTop = scroller.scrollTop;

    const contentStart = startContentY; // content coordinate of the press point
    const contentNow = scrollTop + (cy - rect.top);
    const top = Math.min(contentStart, contentNow) - scrollTop + rect.top;
    const bottom = Math.max(contentStart, contentNow) - scrollTop + rect.top;

    const left = Math.min(startX, cx);
    const right = Math.max(startX, cx);

    const box: MarqueeRect = {
      left,
      right,
      top,
      bottom,
      width: right - left,
      height: bottom - top,
    };
    marqueeRect.value = box;
    updateIntersections(box);
  }

  function updateIntersections(box: MarqueeRect) {
    const tableEl = getTableEl();
    if (!tableEl) return;

    const rowEls = tableEl.querySelectorAll<HTMLTableRowElement>(rowSelector);
    if (!rowEls.length) return;

    const currentSelectedIds = getSelectedIdSet();
    const currentItems = items.value;
    const count = Math.min(currentItems.length, rowEls.length);

    for (let i = 0; i < count; i++) {
      const item = currentItems[i];
      if (!item) continue;
      const rowEl = rowEls[i];
      if (!rowEl) continue;

      // Selection is driven purely by whether the row's own band overlaps the
      // marquee box. The box and the row rect are both in viewport/client
      // coordinates, so the highlighted rows always match the visible box.
      const inBox = rectsIntersect(box, rowEl.getBoundingClientRect());

      const itemId = getItemId(item);
      const wasInitiallySelected = snapshotSelectedIds.has(itemId);

      let shouldSelect = false;
      if (isCtrl) {
        // Toggle whatever is covered, leave the rest at its initial state.
        shouldSelect = inBox ? !wasInitiallySelected : wasInitiallySelected;
      } else {
        // The marquee is the single source of truth: a plain drag replaces the
        // selection (rows not covered are un-selected), Shift appends to the
        // pre-drag selection. Because the box is anchored in content space, it
        // moves with the scrolled rows, so scrolling neither re-selects nor
        // un-selects anything by itself.
        shouldSelect = inBox || (isShift && wasInitiallySelected);
      }

      const isCurrentlySelected = currentSelectedIds.has(itemId);
      if (isCurrentlySelected !== shouldSelect) {
        tableRef.value?.toggleRowSelection(item as any, shouldSelect);
      }
    }
  }

  function autoScrollLoop() {
    if (!isDragging.value || !isPointerDown) return;

    // Auto-scroll the REAL scroll container (`.desktop-v2-content`) when the
    // pointer is near its top/bottom edge.
    const scroller = getScrollerEl();
    const edgeZone = 40;
    const maxSpeed = 14;
    const rect = scroller.getBoundingClientRect();

    if (lastClientY > rect.bottom - edgeZone && lastClientY < rect.bottom + edgeZone) {
      const intensity = Math.min(1, (lastClientY - (rect.bottom - edgeZone)) / edgeZone);
      scroller.scrollTop += Math.max(2, Math.round(intensity * maxSpeed));
    } else if (lastClientY < rect.top + edgeZone && lastClientY > rect.top - edgeZone) {
      const intensity = Math.min(1, (rect.top + edgeZone - lastClientY) / edgeZone);
      scroller.scrollTop -= Math.max(2, Math.round(intensity * maxSpeed));
    }

    // Rebuild the box against the (possibly changed) scroll position, so the
    // marquee keeps stretching with the scrolled content like Explorer.
    if (marqueeRect.value) {
      updateMarquee(lastClientX, lastClientY);
    }

    autoScrollRaf = requestAnimationFrame(autoScrollLoop);
  }

  function onPointerMove(e: PointerEvent) {
    if (!isPointerDown) return;

    lastClientY = e.clientY;
    lastClientX = e.clientX;
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

    updateMarquee(e.clientX, e.clientY);
  }

  function onPointerUp(e: PointerEvent) {
    if (!isPointerDown) return;
    isPointerDown = false;

    if (longPressTimer) {
      window.clearTimeout(longPressTimer);
      longPressTimer = undefined;
    }
    isLongPress = false;

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
    lastClientX = e.clientX;
    lastClientY = e.clientY;
    // Anchor the marquee in the scroller's CONTENT coordinates at press time so
    // scrolling makes it grow (Explorer behaviour) instead of staying frozen.
    const scrollerRect = getScrollerEl().getBoundingClientRect();
    startContentY = getScrollerEl().scrollTop + (startY - scrollerRect.top);
    isCtrl = e.ctrlKey || e.metaKey;
    isShift = e.shiftKey;
    isLongPress = false;
    snapshotSelectedIds = getSelectedIdSet();

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
