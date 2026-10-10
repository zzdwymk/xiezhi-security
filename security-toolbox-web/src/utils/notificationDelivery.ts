import { loadNotificationPreferences, matchingSeverities, notificationRoute, prepareNotifications, type SystemNotice } from "./notifications";
import { severityLabel } from "./aiPresentation";
import { toErrorMessage } from "./errorMessage";

export interface NotificationDeliveryOptions {
  present: (notice: SystemNotice, open: () => void) => void;
  navigate: (route: string) => void;
  isCurrent: () => boolean;
}

/** A single session-scoped dispatcher for native, browser and foreground notices. */
export function createNotificationDelivery(options: NotificationDeliveryOptions) {
  const seen = new Set<string>();
  return async (items: SystemNotice[]) => {
    if (!items.length || !options.isCurrent()) return;
    const preferences = await loadNotificationPreferences();
    if (!options.isCurrent()) return;
    const unique = [...new Map(items.filter(n => !seen.has(n.eventKey)).map(n => [n.eventKey, n])).values()];
    const notices = prepareNotifications(unique, preferences);
    // Reserve all source keys before awaiting IPC; concurrent deliveries cannot duplicate them.
    for (const item of unique) seen.add(item.eventKey);
    while (seen.size > 2000) seen.delete(seen.values().next().value!);
    for (const original of notices) {
      if (!options.isCurrent()) return;
      const levels = matchingSeverities(original, preferences);
      const highlight = preferences.findingNotifications && levels.length > 0;
      const baseBody = original.outcome === "success" ? original.body : toErrorMessage(original.body, "请打开详情查看执行结果。");
      const findingHint = highlight && ["task", "workflow"].includes(original.category)
        ? ` 已保存结果包含${levels.map(severityLabel).join("、")}漏洞。` : "";
      const notice = { ...original,
        title: highlight && original.category === "task" && original.outcome === "success"
          ? `发现${levels.map(severityLabel).join("、")}漏洞` : original.title,
        body: baseBody + findingHint,
      };
      const destination = notificationRoute(notice.route);
      const open = () => { if (destination) options.navigate(destination); };
      const background = document.hidden || !document.hasFocus();
      if (background && window.toolboxDesktop?.showTaskNotification) {
        try {
          const result = await window.toolboxDesktop.showTaskNotification({ ...notice, type: notice.outcome === "success" ? "info" : "error" });
          if (result?.delivered || result?.reason === "duplicate" || result?.reason === "disabled") continue;
        } catch { /* Keep a visible in-app fallback when the native bridge fails. */ }
      } else if (background && "Notification" in window && Notification.permission === "granted") {
        try {
          const notification = new Notification(notice.title, { body: notice.body, tag: notice.eventKey });
          notification.onclick = () => { window.focus(); open(); notification.close(); };
          continue;
        } catch { /* Browser notification support can disappear after permissions change. */ }
      }
      if (options.isCurrent()) options.present(notice, open);
    }
  };
}
