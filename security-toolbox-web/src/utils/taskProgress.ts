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
  if (!hasReportedProgress(task)) return 0;
  return Math.floor((Number(task.progressCompleted) / Number(task.progressTotal)) * 100);
}

function hasReportedProgress(task: TaskProgressLike) {
  const completed = task.progressCompleted;
  const total = task.progressTotal;
  return task.progressDeterminate === true && typeof completed === "number"
    && typeof total === "number" && Number.isFinite(completed) && Number.isFinite(total)
    && total > 0 && completed >= 0 && completed <= total;
}

export function taskProgressIndeterminate(task: TaskProgressLike) {
  return task.status === "RUNNING" && !hasReportedProgress(task);
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
  if (task.status === "RUNNING" && hasReportedProgress(task)) {
    const percent = taskProgressPercentage(task);
    const completed = Number(task.progressCompleted);
    const total = Number(task.progressTotal);
    return `工具进度 ${percent}% · ${completed}/${total}`;
  }
  return task.progressMessage?.trim() || "执行中";
}
