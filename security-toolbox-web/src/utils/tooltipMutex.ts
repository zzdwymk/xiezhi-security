/* 全局黑框互斥：Element Plus 深色 tooltip（role="tooltip" 的 popper，含
   el-table 溢出提示）与应用自绘的 Fluent 悬浮气泡（见 App.vue 的
   fluent-hover-tooltip）是两套互不知情的系统。消息操作栏这类混合排布的
   按钮行里，先悬停一个再扫过另一个、或在一个黑框亮着时焦点落到另一个
   按钮上，就会出现两个一模一样的黑框。这里的约定是"谁后出现，谁把先
   出现的立即按灭"：
   - Fluent 气泡每次显示前调用 hideOpenElementPlusTooltips()；
   - 本模块监听 popper 可见性，任一 tooltip 亮起时回调
     onForeignTooltipShown()（App.vue 用它收起自己的气泡），并把其余
     tooltip popper 一并按灭。
   Element Plus 用 v-show（直接改 style.display）加 aria-hidden 控制
   popper 可见性，且其 open 状态不变时 Vue 的 v-show updated 钩子是空
   操作，因此这里强改的 display:none 会保留到 EP 自己下一次切换该
   popper，不会被响应式渲染打回。
   选择器与 unified-theme.css / fluent-design-2.css 的深色 tooltip 皮肤
   签名保持一致；下拉、菜单、日期选择、popover 等交互弹层用其他类名或
   role，绝不强关。 */

/* turn-rail-tooltip 与 stats-pill-popover 是应用内受控弹层（visible 由
   状态长持，强关后状态不翻转就一直隐形），因此从按灭清单中排除；它们
   亮起时依然会通过监听回调收起 Fluent 气泡，互斥方向不受影响。 */
export const EP_TOOLTIP_POPPER_SELECTOR =
  '.el-popper[role="tooltip"]:not(.el-select__popper):not(.el-dropdown__popper):not(.el-picker__popper):not(.el-cascader__dropdown):not(.el-autocomplete__popper):not(.el-popover):not(.turn-rail-tooltip):not(.stats-pill-popover)';

export const EP_ANY_POPPER_SELECTOR = ".el-popper";

export function isElementPlusTooltipVisible(el: Element): boolean {
  // 只看 role + 内联 display，不看 aria-hidden：快速扫过时按灭会打断 EP 的
  // 渐隐过渡，其迟到的 afterLeave 可能在重新打开之后才把 aria-hidden 改回
  // true，出现"渲染可见但 aria-hidden=true"的窗口；渐隐中的 popper 内联
  // display 也非 none，正属于应当按灭的对象。
  return (
    el.getAttribute("role") === "tooltip" &&
    (el instanceof HTMLElement ? el.style.display : "") !== "none"
  );
}

/** 按灭当前亮着的所有 Element Plus 深色 tooltip（含正在渐隐的）。 */
export function hideOpenElementPlusTooltips(): void {
  document
    .querySelectorAll<HTMLElement>(EP_TOOLTIP_POPPER_SELECTOR)
    .forEach((el) => {
      if (!isElementPlusTooltipVisible(el)) return;
      el.style.display = "none";
      el.setAttribute("aria-hidden", "true");
    });
}

/**
 * 开始监听 Element Plus popper：任一 tooltip 黑框亮起时回调
 * onForeignTooltipShown（用于收起另一套系统的气泡），并把其余 tooltip
 * 一并按灭。返回停止监听的函数。
 */
export function startElementPlusTooltipMutex(
  onForeignTooltipShown: () => void,
): () => void {
  const observer = new MutationObserver((records) => {
    for (const record of records) {
      const candidates =
        record.type === "childList"
          ? Array.from(record.addedNodes)
          : [record.target];
      for (const node of candidates) {
        if (!(node instanceof Element)) continue;
        if (!node.matches(EP_ANY_POPPER_SELECTOR)) continue;
        if (!isElementPlusTooltipVisible(node)) continue;
        onForeignTooltipShown();
        document
          .querySelectorAll<HTMLElement>(EP_TOOLTIP_POPPER_SELECTOR)
          .forEach((el) => {
            if (el === node || !isElementPlusTooltipVisible(el)) return;
            el.style.display = "none";
            el.setAttribute("aria-hidden", "true");
          });
        return;
      }
    }
  });
  observer.observe(document.body, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ["style", "aria-hidden"],
  });
  return () => observer.disconnect();
}
