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

// Node reports a process exit code as a 32-bit value. Windows hands back 0xFFFFFFFF for
// "exited with -1 / killed", which is otherwise displayed as a scary 10-digit 4294967295.
// Show the signed value plus the raw hex so the number stays traceable.
function serviceExitCodeParts(code) {
  if (!Number.isInteger(code)) return undefined;
  const unsigned = code >>> 0;
  const signed = unsigned > 0x7fffffff ? unsigned - 0x100000000 : unsigned;
  const hex = `0x${unsigned.toString(16).toUpperCase().padStart(8, "0")}`;
  return { signed, unsigned, hex };
}

function formatServiceExitCode(code) {
  const parts = serviceExitCodeParts(code);
  if (!parts) return "未知";
  return parts.signed === parts.unsigned
    ? `${parts.signed}（${parts.hex}）`
    : `${parts.signed} / ${parts.unsigned}（${parts.hex}）`;
}

function describeServiceExit(code) {
  const parts = serviceExitCodeParts(code);
  if (!parts) return "进程被外部终止（未取得退出码）";
  switch (parts.unsigned) {
    case 0xffffffff:
      return "服务以错误状态退出（-1），常见于启动失败或运行中被强制终止";
    case 0xc000013a:
      return "服务被 Ctrl+C 或控制台中断";
    case 0xc0000005:
      return "访问冲突（0xC0000005），JVM 或原生组件崩溃";
    case 0xc0000142:
      return "DLL 初始化失败（0xC0000142），通常是安装目录或系统库不完整";
    case 0x40010004:
      return "进程被调试器或系统终止";
    case 0x80000003:
      return "断点异常（0x80000003），进程被调试或强制挂起后终止";
    case 0:
      return "服务正常退出（退出码 0）";
    default:
      return parts.unsigned >= 0x80000000
        ? `以异常码 ${parts.hex} 终止，通常是崩溃或被强制结束`
        : "服务主动退出并报告了错误状态";
  }
}

// Multi-line body: one fact per line, so the exit code, the likely cause and the
// next step never read as one dense run-on sentence in the notification.
function serviceExitBody(label, code) {
  return [
    `${label}已停止。`,
    `退出码：${formatServiceExitCode(code)}`,
    `可能原因：${describeServiceExit(code)}`,
    "下一步：打开 设置 → 运行诊断 → 运行日志 查看详细输出。",
  ].join("\n");
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
          body: serviceExitBody(label, code),
        });
        onUnexpectedExit?.(code);
      });
    },
  };
}

module.exports = {
  createNotificationCenter, normalizeNotificationSettings, notificationSettingsFromStorage,
  updateNotificationStorage, safeNotificationRoute, shouldNotify, createServiceExitReporter,
  formatServiceExitCode, describeServiceExit, serviceExitBody,
};
