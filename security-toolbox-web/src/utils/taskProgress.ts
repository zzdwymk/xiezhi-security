import type { ProjectTaskRecord } from "../api";

export type TaskProgressLike = Pick<
  ProjectTaskRecord,
  | "status"
  | "progress"
  | "progressDeterminate"
  | "progressCompleted"
  | "progressTotal"
  | "progressMessage"
>;

const FAILURE_STATUSES = new Set([
  "FAILED",
  "TIMEOUT",
  "REJECTED",
  "CANCELLED",
]);

export function taskProgressPercentage(task: TaskProgressLike) {
  if (task.status === "SUCCESS") return 100;
  return Math.max(0, Math.min(100, Number(task.progress) || 0));
}

export function taskProgressIndeterminate(task: TaskProgressLike) {
  return task.status === "RUNNING" && !task.progressDeterminate;
}

export function taskProgressStatus(
  task: TaskProgressLike,
): "success" | "exception" | undefined {
  if (task.status === "SUCCESS") return "success";
  if (FAILURE_STATUSES.has(task.status)) return "exception";
  return undefined;
}

export function taskProgressText(task: TaskProgressLike) {
  if (task.status === "PENDING" || task.status === "QUEUED") return "排队中";
  if (task.status === "BLOCKED") return "等待前置";
  if (task.status === "SKIPPED") return "已跳过";
  if (task.status === "SUCCESS") return "100%";
  if (FAILURE_STATUSES.has(task.status)) {
    return task.status === "TIMEOUT"
      ? "已超时"
      : task.status === "CANCELLED"
        ? "已取消"
        : task.status === "REJECTED"
          ? "已拒绝"
          : "失败";
  }
  if (task.status === "RUNNING" && task.progressDeterminate) {
    const percent = taskProgressPercentage(task);
    const completed = Number(task.progressCompleted);
    const total = Number(task.progressTotal);
    return total > 0 && completed >= 0
      ? `${percent}% · ${completed}/${total}`
      : `${percent}%`;
  }
  return task.progressMessage?.trim() || "执行中";
}
