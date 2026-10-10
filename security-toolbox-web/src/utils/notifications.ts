import { severityLabel } from "./aiPresentation";

export interface NotificationPreferences {
  enabled: boolean;
  severities: string[];
  taskCompleteNotifications: boolean;
  taskFailureNotifications: boolean;
  findingNotifications: boolean;
  workflowCompleteNotifications: boolean;
  workflowSkipNotifications: boolean;
  approvalNotifications: boolean;
  scheduleNotifications: boolean;
  trafficNotifications: boolean;
  serviceNotifications: boolean;
}

export const DEFAULT_NOTIFICATION_PREFERENCES: NotificationPreferences = {
  enabled: true,
  severities: ["CRITICAL", "HIGH", "MEDIUM"],
  taskCompleteNotifications: true,
  taskFailureNotifications: true,
  findingNotifications: true,
  workflowCompleteNotifications: true,
  workflowSkipNotifications: true,
  approvalNotifications: true,
  scheduleNotifications: true,
  trafficNotifications: true,
  serviceNotifications: true,
};
const PREFERENCES_KEY = "security_toolbox_notifications_v2";
export const NOTIFICATION_SETTINGS_CHANGED = "toolbox-notification-settings-changed";

export function normalizeNotificationPreferences(value: Partial<NotificationPreferences> = {}): NotificationPreferences {
  const result = { ...DEFAULT_NOTIFICATION_PREFERENCES, severities: [...DEFAULT_NOTIFICATION_PREFERENCES.severities] };
  for (const key of Object.keys(result) as (keyof NotificationPreferences)[]) {
    if (key !== "severities" && typeof value[key] === "boolean") result[key] = value[key] as boolean;
  }
  if (Array.isArray(value.severities)) {
    result.severities = [...new Set(value.severities.filter(s => ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(s)))];
  }
  return result;
}

export async function loadNotificationPreferences(): Promise<NotificationPreferences> {
  if (window.toolboxDesktop?.getNotificationSettings) {
    return normalizeNotificationPreferences(await window.toolboxDesktop.getNotificationSettings());
  }
  try { return normalizeNotificationPreferences(JSON.parse(localStorage.getItem(PREFERENCES_KEY) || "{}")); }
  catch { return normalizeNotificationPreferences(); }
}

export async function saveNotificationPreferences(value: Partial<NotificationPreferences>): Promise<NotificationPreferences> {
  const settings = normalizeNotificationPreferences({ ...await loadNotificationPreferences(), ...value });
  const saved = window.toolboxDesktop?.saveNotificationSettings
    ? normalizeNotificationPreferences(await window.toolboxDesktop.saveNotificationSettings(settings))
    : settings;
  if (!window.toolboxDesktop?.saveNotificationSettings) localStorage.setItem(PREFERENCES_KEY, JSON.stringify(saved));
  window.dispatchEvent(new Event(NOTIFICATION_SETTINGS_CHANGED));
  return saved;
}

export interface SystemNotice {
  id?: number;
  eventKey: string;
  category: "task" | "workflow" | "workflow_skip" | "approval" | "schedule" | "traffic" | "service";
  outcome: "success" | "error" | "warning";
  title: string;
  body: string;
  route: string;
  severities?: string[];
  createdAt?: string;
}

export function notificationRoute(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 2048 || /[\\\u0000-\u0020]/.test(value)) return;
  const pathname = value.split(/[?#]/, 1)[0];
  return /^\/(?:tasks|workflow|traffic|settings|projects\/[1-9]\d*)$/.test(pathname || "") ? value : undefined;
}

export function matchingSeverities(notice: SystemNotice, preferences: NotificationPreferences): string[] {
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].filter(s =>
    preferences.severities.includes(s) && notice.severities?.includes(s));
}

export function shouldNotify(notice: SystemNotice, preferences: NotificationPreferences): boolean {
  if (!preferences.enabled) return false;
  switch (notice.category) {
    case "task": return notice.outcome === "success"
      ? preferences.taskCompleteNotifications || (preferences.findingNotifications && matchingSeverities(notice, preferences).length > 0)
      : preferences.taskFailureNotifications || (preferences.findingNotifications && matchingSeverities(notice, preferences).length > 0);
    case "workflow": return preferences.workflowCompleteNotifications || (preferences.findingNotifications && matchingSeverities(notice, preferences).length > 0);
    case "workflow_skip": return preferences.workflowSkipNotifications;
    case "approval": return preferences.approvalNotifications;
    case "schedule": return preferences.scheduleNotifications;
    case "traffic": return preferences.trafficNotifications;
    case "service": return preferences.serviceNotifications;
    default: return false;
  }
}

/** Filter before grouping so disabled events never leak through an aggregate notification. */
export function prepareNotifications(notices: SystemNotice[], preferences: NotificationPreferences): SystemNotice[] {
  const selected = notices.filter(n => n.eventKey && shouldNotify(n, preferences));
  const groups = new Map<string, SystemNotice[]>();
  for (const notice of selected) {
    const key = notice.outcome === "success" && ["task", "workflow", "traffic"].includes(notice.category)
      ? `${notice.category}:${notice.outcome}` : notice.eventKey;
    const group = groups.get(key) || [];
    group.push(notice);
    groups.set(key, group);
  }
  return [...groups.values()].flatMap(group => {
    if (group.length < 4) return group;
    const first = group[0]!;
    const name = { task: "检测任务", workflow: "工作流", traffic: "流量检测" }[first.category as "task" | "workflow" | "traffic"];
    const severities = [...new Set(group.flatMap(n => n.severities || []))];
    const matched = matchingSeverities({ ...first, severities }, preferences);
    return [{ ...first, eventKey: `batch:${first.eventKey}:${group[group.length - 1]!.eventKey}`,
      title: `${group.length} 个${name}已完成`,
      body: `已汇总本批执行结果${preferences.findingNotifications && matched.length ? `，包含${matched.map(severityLabel).join("、")}发现` : ""}。点击查看详情。`,
      route: first.category === "task" ? "/tasks" : first.category === "workflow" ? "/workflow" : "/traffic", severities }];
  });
}

let dispatcher: ((notice: SystemNotice) => Promise<void>) | undefined;
export function setNotificationDispatcher(value: (notice: SystemNotice) => Promise<void>) {
  dispatcher = value;
  return () => { if (dispatcher === value) dispatcher = undefined; };
}

export async function showSystemNotification(notice: SystemNotice) {
  await dispatcher?.(notice);
}

export interface WorkflowSkipNotice { count: number; labels: string[] }
export async function notifyWorkflowSkipped(notice: WorkflowSkipNotice, preferences?: NotificationPreferences) {
  if (preferences && (!preferences.enabled || !preferences.workflowSkipNotifications)) return;
  await showSystemNotification({
    eventKey: `workflow-skip:${Date.now()}:${Math.random().toString(36).slice(2)}`,
    category: "workflow_skip", outcome: "warning", route: "/workflow",
    title: "工作流已跳过不可用节点",
    body: `已跳过 ${notice.count} 个步骤（含受影响的后继步骤）：${notice.labels.filter(Boolean).join("、") || "不可用节点"}。`,
  }).catch(() => { /* Notification failures must not interrupt workflow submission. */ });
}
