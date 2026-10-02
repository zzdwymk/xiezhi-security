import { severityLabel } from "./aiPresentation";

export interface NotificationPreferences {
  severities: string[];
  taskCompleteNotifications: boolean;
  workflowSkipNotifications: boolean;
}

const DEFAULT_PREFERENCES: NotificationPreferences = {
  severities: ["CRITICAL", "HIGH", "MEDIUM"],
  taskCompleteNotifications: true,
  workflowSkipNotifications: true,
};

/**
 * Load the desktop notification preferences through the native bridge.
 * Falls back to safe defaults on browsers / when the bridge is unavailable.
 */
export async function loadNotificationPreferences(): Promise<NotificationPreferences> {
  const bridge = window.toolboxDesktop;
  if (!bridge?.getNotificationSettings) return { ...DEFAULT_PREFERENCES };
  try {
    const settings = await bridge.getNotificationSettings();
    return {
      severities: settings.severities?.length
        ? settings.severities.slice()
        : [...DEFAULT_PREFERENCES.severities],
      taskCompleteNotifications: settings.taskCompleteNotifications !== false,
      workflowSkipNotifications: settings.workflowSkipNotifications !== false,
    };
  } catch {
    return { ...DEFAULT_PREFERENCES };
  }
}

type NotificationType = "info" | "error";

interface ShowNotificationPayload {
  title?: string;
  body?: string;
  type?: NotificationType;
}

/**
 * Fire a desktop operating system notification through the native bridge.
 * No-op on browsers / when the native bridge is unavailable.
 */
export function showSystemNotification(payload: ShowNotificationPayload) {
  try {
    const bridge = window.toolboxDesktop;
    if (!bridge?.showTaskNotification) return;
    void bridge.showTaskNotification({
      title: payload.title,
      body: payload.body,
      type: payload.type ?? "info",
    });
  } catch {
    // ignore native notification failures (non-fatal)
  }
}

const TERMINAL_TASK_STATUSES = new Set([
  "SUCCESS",
  "FAILED",
  "TIMEOUT",
  "REJECTED",
  "CANCELLED",
]);

function severityRank(severity?: string): number {
  const map: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };
  return map[String(severity || "").toUpperCase()] ?? 99;
}

/**
 * Collect the deduplicated severities reported inside a task result JSON.
 */
export function collectResultSeverities(resultJson?: string): string[] {
  if (!resultJson) return [];
  try {
    const parsed: unknown = JSON.parse(resultJson);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      return [];
    const result = parsed as Record<string, unknown>;
    const data =
      result.data && typeof result.data === "object" && !Array.isArray(result.data)
        ? (result.data as Record<string, unknown>)
        : undefined;
    const candidates = [
      result.matches,
      data?.matches,
      result.findings,
      data?.findings,
      data?.items,
      data?.results,
    ];
    const list = candidates.find((value) => Array.isArray(value)) as
      | Array<Record<string, unknown>>
      | undefined;
    if (!list) return [];
    return Array.from(
      new Set(
        list
          .map((item) => (item && typeof item === "object" ? item : {}))
          .map((entry) => {
            const severity =
              (entry as Record<string, unknown>).severity ??
              (entry as Record<string, unknown>).level;
            return typeof severity === "string"
              ? severity.trim().toUpperCase()
              : "";
          })
          .filter(Boolean),
      ),
    );
  } catch {
    return [];
  }
}

function matchedSeverityHint(
  severities: string[],
  preferences: NotificationPreferences,
): string {
  const selected = new Set(preferences.severities);
  const matched = severities
    .filter((s) => selected.has(s))
    .sort((a, b) => severityRank(a) - severityRank(b));
  if (!matched.length) return "";
  return Array.from(new Set(matched)).map((s) => severityLabel(s)).join("/");
}

export interface WorkflowSkipNotice {
  count: number;
  labels: string[];
}

/**
 * Fire a native notification when the user explicitly skips workflow nodes that
 * are unavailable due to missing dependencies. Gated behind the user toggle.
 */
export async function notifyWorkflowSkipped(
  notice: WorkflowSkipNotice,
  preferences: NotificationPreferences,
) {
  if (!preferences.workflowSkipNotifications) return;
  const names = notice.labels.filter(Boolean).join("、");
  showSystemNotification({
    type: "error",
    title: "红队工作流：已跳过不可用节点",
    body: `第 ${notice.count} 个步骤因缺少依赖或不可用被跳过（含依赖它们的后继步骤）：${
      names || "不可用节点"
    }。`,
  });
}

export interface TaskNotificationControl {
  id: number;
  status: string;
  resultJson?: string;
  errorMessage?: string;
}

/**
 * Decide whether a finished task should produce a native notification based on
 * the user's notification preferences, and fire it when appropriate.
 */
export async function notifyTaskCompletion(
  row: TaskNotificationControl,
  preferences: NotificationPreferences,
) {
  const bridge = window.toolboxDesktop;
  if (!bridge?.showTaskNotification) return;
  if (!TERMINAL_TASK_STATUSES.has(row.status)) return;

  if (row.status === "SUCCESS") {
    if (!preferences.taskCompleteNotifications) return;
    const found = new Set(collectResultSeverities(row.resultJson));
    const selected = new Set(preferences.severities);
    if (!(selected.size > 0 && [...selected].some((s) => found.has(s)))) {
      return;
    }
  }

  const success = row.status === "SUCCESS";
  const severityHint = success
    ? matchedSeverityHint(collectResultSeverities(row.resultJson), preferences)
    : "";
  showSystemNotification({
    type: success ? "info" : "error",
    title: success
      ? severityHint
        ? `发现${severityHint}漏洞 · #${row.id}`
        : `任务 #${row.id} 已完成`
      : `任务 #${row.id} ${row.status.toLowerCase()}`,
    body: success
      ? severityHint
        ? `任务发现 ${severityHint} 严重程度漏洞，已生成结果，可在「任务控制中心」查看。`
        : "任务已完成，可在「任务控制中心」查看结果详情。"
      : row.errorMessage ||
        `任务状态为 ${row.status.toLowerCase()}，可在「任务控制中心」查看原因。`,
  });
}