const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
const DEFAULT_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM"];
const BOOLEAN_SETTINGS = [
  "enabled", "taskCompleteNotifications", "taskFailureNotifications",
  "findingNotifications", "workflowCompleteNotifications", "workflowSkipNotifications",
  "approvalNotifications", "scheduleNotifications", "trafficNotifications", "serviceNotifications",
];

function normalizeNotificationSettings(value = {}) {
  const settings = Object.fromEntries(BOOLEAN_SETTINGS.map(key => [key, value[key] !== false]));
  settings.severities = Array.isArray(value.severities)
    ? [...new Set(value.severities.filter(item => SEVERITIES.has(item)))]
    : [...DEFAULT_SEVERITIES];
  return settings;
}

function notificationSettingsFromStorage(value = {}) {
  return normalizeNotificationSettings({
    ...value,
    enabled: value.notificationEnabled,
    findingNotifications: value.findingNotifications ?? value.taskCompleteNotifications,
    severities: value.notificationSeverities,
  });
}

function updateNotificationStorage(previous = {}, patch = {}) {
  const current = notificationSettingsFromStorage(previous);
  const settings = normalizeNotificationSettings({ ...current, ...patch });
  const result = { ...previous, notificationSeverities: settings.severities };
  for (const key of BOOLEAN_SETTINGS) result[key === "enabled" ? "notificationEnabled" : key] = settings[key];
  return result;
}

function safeNotificationRoute(value) {
  if (typeof value !== "string" || value.length > 2048 || /[\\\u0000-\u0020]/.test(value)) return "";
  // Match before URL parsing so encoded paths and URL normalization cannot widen the allowlist.
  const pathname = value.split(/[?#]/, 1)[0];
  return /^\/(?:tasks|workflow|traffic|settings|projects\/[1-9]\d*)$/.test(pathname) ? value : "";
}

function shouldNotify(payload, settings) {
  if (!settings.enabled) return false;
  const category = payload.category || "task";
  const outcome = payload.outcome || (payload.type === "error" ? "error" : "success");
  if (category === "task") {
    const matchingFinding = Array.isArray(payload.severities)
      && payload.severities.some(value => settings.severities.includes(value));
    return (outcome === "success" ? settings.taskCompleteNotifications : settings.taskFailureNotifications)
      || (settings.findingNotifications && matchingFinding);
  }
  if (category === "workflow" && settings.findingNotifications && Array.isArray(payload.severities)
      && payload.severities.some(value => settings.severities.includes(value))) return true;
  const key = {
    workflow: "workflowCompleteNotifications",
    workflow_skip: "workflowSkipNotifications",
    approval: "approvalNotifications",
    schedule: "scheduleNotifications",
    traffic: "trafficNotifications",
    service: "serviceNotifications",
  }[category];
  return Boolean(key && settings[key]);
}

function createNotificationCenter({ Notification, getSettings, getWindow, maxKeys = 1000 }) {
  const deliveredKeys = new Set();
  const activeNotifications = new Set();
  return {
    show(payload = {}) {
      if (!payload || typeof payload !== "object") return { delivered: false, reason: "invalid" };
      if (!shouldNotify(payload, normalizeNotificationSettings(getSettings()))) return { delivered: false, reason: "disabled" };
      const eventKey = typeof payload.eventKey === "string" ? payload.eventKey.slice(0, 300) : "";
      if (eventKey && deliveredKeys.has(eventKey)) return { delivered: false, reason: "duplicate" };
      if (!Notification.isSupported()) return { delivered: false, reason: "unsupported" };
      try {
        const route = safeNotificationRoute(payload.route);
        const notification = new Notification({
          title: typeof payload.title === "string" && payload.title.trim() ? payload.title.slice(0, 150) : "系统通知",
          body: typeof payload.body === "string" ? payload.body.slice(0, 600) : "请打开应用查看详情。",
          silent: false,
        });
        activeNotifications.add(notification);
        notification.on("close", () => activeNotifications.delete(notification));
        notification.on("failed", () => {
          activeNotifications.delete(notification);
          if (eventKey) deliveredKeys.delete(eventKey);
        });
        notification.on("click", () => {
          const target = getWindow();
          if (!target || target.isDestroyed()) return;
          if (target.isMinimized()) target.restore();
          target.show();
          target.focus();
          if (route && !target.webContents.isDestroyed()) target.webContents.send("toolbox:notification-click", route);
        });
        notification.show();
        if (eventKey) {
          deliveredKeys.add(eventKey);
          while (deliveredKeys.size > maxKeys) deliveredKeys.delete(deliveredKeys.values().next().value);
        }
        return { delivered: true };
      } catch {
        return { delivered: false, reason: "failed" };
      }
    },
  };
}

function createServiceExitReporter({ isQuitting, notify }) {
  const intentionallyStopped = new WeakSet();
  return {
    markStopped(child) {
      if (child) intentionallyStopped.add(child);
    },
    watch(child, { service, lifecycleId, label, onUnexpectedExit }) {
      child.once("exit", code => {
        if (isQuitting() || intentionallyStopped.has(child)) return;
        notify({
          eventKey: `service:${service}:${lifecycleId}:exit`,
          category: "service", outcome: "error", type: "error", route: "/settings",
          title: `${label}意外退出`,
          body: `${label}已停止（退出代码 ${code ?? "未知"}），请在设置中检查服务状态。`,
        });
        onUnexpectedExit?.(code);
      });
    },
  };
}

module.exports = {
  createNotificationCenter, normalizeNotificationSettings, notificationSettingsFromStorage,
  updateNotificationStorage, safeNotificationRoute, shouldNotify, createServiceExitReporter,
};
