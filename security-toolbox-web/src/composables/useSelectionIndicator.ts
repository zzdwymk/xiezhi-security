import {
  onBeforeUnmount,
  onMounted,
  watch,
  type Ref,
  type WatchSource,
} from "vue";

type IndicatorOrientation = "vertical" | "horizontal";

interface SelectionIndicatorOptions {
  container: Ref<HTMLElement | null>;
  activeSelector: string;
  indicatorSelector?: string;
  dependencies?: WatchSource[];
  scrollContainers?: Ref<HTMLElement | null>[];
  orientation?: IndicatorOrientation;
  sizeRatio?: number;
  minSize?: number;
  maxSize?: number;
  thickness?: number;
  edgeInset?: number;
  hidden?: () => boolean;
}

const INDICATOR_SELECTOR = ".fluent-selection-indicator";

export function useSelectionIndicator({
  container,
  activeSelector,
  indicatorSelector = INDICATOR_SELECTOR,
  dependencies = [],
  scrollContainers = [],
  orientation = "vertical",
  sizeRatio = 0.56,
  minSize = orientation === "vertical" ? 18 : 24,
  maxSize = orientation === "vertical" ? 24 : Number.POSITIVE_INFINITY,
  thickness = orientation === "vertical" ? 3 : 2,
  edgeInset = orientation === "vertical" ? 0 : 1,
  hidden,
}: SelectionIndicatorOptions) {
  let frame = 0;
  let layoutTrackingFrame = 0;
  let resizeObserver: ResizeObserver | undefined;
  let mounted = false;
  let observedScrollContainers: HTMLElement[] = [];
  let observedActiveItem: HTMLElement | null = null;
  let layoutTrackingIndicator: HTMLElement | null = null;

  function updatePosition() {
    const root = container.value;
    const indicator = root?.querySelector<HTMLElement>(indicatorSelector);
    const activeItem = root?.querySelector<HTMLElement>(activeSelector);
    if (
      !root ||
      !indicator ||
      !activeItem ||
      activeItem.offsetParent === null ||
      hidden?.()
    ) {
      indicator?.style.setProperty("--selection-indicator-opacity", "0");
      return;
    }

    if (resizeObserver && observedActiveItem !== activeItem) {
      if (observedActiveItem) resizeObserver.unobserve(observedActiveItem);
      resizeObserver.observe(activeItem);
      observedActiveItem = activeItem;
    }

    const rootRect = root.getBoundingClientRect();
    const itemRect = activeItem.getBoundingClientRect();
    const itemSize =
      orientation === "vertical" ? itemRect.height : itemRect.width;
    const size = Math.min(maxSize, Math.max(minSize, itemSize * sizeRatio));
    const x =
      itemRect.left -
      rootRect.left +
      root.scrollLeft -
      root.clientLeft +
      (orientation === "horizontal" ? (itemRect.width - size) / 2 : 0);
    const y =
      itemRect.top -
      rootRect.top +
      root.scrollTop -
      root.clientTop +
      (orientation === "vertical"
        ? (itemRect.height - size) / 2
        : itemRect.height - thickness - edgeInset);

    indicator.style.setProperty(
      "--selection-indicator-width",
      `${(orientation === "vertical" ? thickness : size).toFixed(2)}px`,
    );
    indicator.style.setProperty(
      "--selection-indicator-height",
      `${(orientation === "vertical" ? size : thickness).toFixed(2)}px`,
    );
    indicator.style.setProperty("--selection-indicator-x", `${x.toFixed(2)}px`);
    indicator.style.setProperty("--selection-indicator-y", `${y.toFixed(2)}px`);
    indicator.style.setProperty("--selection-indicator-opacity", "1");
  }

  function position() {
    window.cancelAnimationFrame(frame);
    frame = window.requestAnimationFrame(() => {
      updatePosition();
    });
  }

  function trackLayout(duration = 260) {
    window.cancelAnimationFrame(layoutTrackingFrame);
    layoutTrackingIndicator?.classList.remove("is-layout-tracking");
    const root = container.value;
    const indicator = root?.querySelector<HTMLElement>(indicatorSelector);
    const deadline = performance.now() + duration;
    layoutTrackingIndicator = indicator ?? null;
    indicator?.classList.add("is-layout-tracking");

    const followLayout = (time: number) => {
      updatePosition();
      if (time < deadline) {
        layoutTrackingFrame = window.requestAnimationFrame(followLayout);
        return;
      }
      indicator?.classList.remove("is-layout-tracking");
      if (layoutTrackingIndicator === indicator) layoutTrackingIndicator = null;
    };
    layoutTrackingFrame = window.requestAnimationFrame(followLayout);
  }

  function reconnectObservers() {
    if (!mounted) return;
    resizeObserver?.disconnect();
    resizeObserver = new ResizeObserver(position);
    const root = container.value;
    observedActiveItem =
      root?.querySelector<HTMLElement>(activeSelector) ?? null;
    if (root) resizeObserver.observe(root);
    if (observedActiveItem) resizeObserver.observe(observedActiveItem);

    observedScrollContainers.forEach((element) =>
      element.removeEventListener("scroll", position),
    );
    observedScrollContainers = scrollContainers
      .map((item) => item.value)
      .filter((item): item is HTMLElement => Boolean(item));
    observedScrollContainers.forEach((element) =>
      element.addEventListener("scroll", position, { passive: true }),
    );
    position();
  }

  watch([container, ...scrollContainers], reconnectObservers, {
    flush: "post",
  });
  if (dependencies.length) {
    watch(dependencies, position, { flush: "post" });
  }

  onMounted(() => {
    mounted = true;
    window.addEventListener("resize", position);
    reconnectObservers();
  });

  onBeforeUnmount(() => {
    mounted = false;
    window.removeEventListener("resize", position);
    window.cancelAnimationFrame(frame);
    window.cancelAnimationFrame(layoutTrackingFrame);
    layoutTrackingIndicator?.classList.remove("is-layout-tracking");
    layoutTrackingIndicator = null;
    resizeObserver?.disconnect();
    resizeObserver = undefined;
    observedActiveItem = null;
    observedScrollContainers.forEach((element) =>
      element.removeEventListener("scroll", position),
    );
    observedScrollContainers = [];
  });

  return {
    positionSelectionIndicator: position,
    trackSelectionIndicatorLayout: trackLayout,
  };
}
