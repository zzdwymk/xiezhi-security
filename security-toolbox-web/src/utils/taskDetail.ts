export interface TaskDetailSnapshot {
  id: number;
  status: string;
  progressUpdatedAt?: string;
  resultJson?: string;
  requestJson?: string;
  executionLog?: string;
}

const TERMINAL_TASK_STATUSES = new Set([
  "SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "SKIPPED",
]);
export function isTerminalTaskStatus(status?: string) {
  return TERMINAL_TASK_STATUSES.has(String(status || ""));
}

/** A delayed list response must not undo a newer SSE terminal state or erase results. */
export function mergeTaskDetailSnapshot<T extends TaskDetailSnapshot>(current: T | undefined, incoming: T): T {
  if (!current || current.id !== incoming.id) return incoming;
  const currentAt = Date.parse(current.progressUpdatedAt || "");
  const incomingAt = Date.parse(incoming.progressUpdatedAt || "");
  const stale = (isTerminalTaskStatus(current.status) && !isTerminalTaskStatus(incoming.status))
    || (Number.isFinite(currentAt) && Number.isFinite(incomingAt) && currentAt > incomingAt);
  return {
    ...(stale ? incoming : current),
    ...(stale ? current : incoming),
    resultJson: (stale ? current.resultJson : incoming.resultJson) || current.resultJson || incoming.resultJson,
    requestJson: incoming.requestJson || current.requestJson,
    executionLog: (stale ? current.executionLog : incoming.executionLog) || current.executionLog || incoming.executionLog,
  };
}

export function taskDetailEmptyResultText(task: TaskDetailSnapshot) {
  if (task.status === "SUCCESS") return "任务已完成，但暂未读取到结果内容。请刷新详情后查看。";
  if (task.status === "SKIPPED") return "任务已跳过，没有执行结果。请查看终止原因。";
  if (isTerminalTaskStatus(task.status)) return "任务已结束，未返回结果内容。请查看失败原因与执行日志。";
  return "任务尚未结束，执行结果将在完成后更新。";
}

/** One request per selection; a terminal update may supersede an older read.
 * At most one delayed second read handles a terminal SSE frame arriving before commit.
 */
export function createTaskDetailLoader<T extends TaskDetailSnapshot>(options: {
  fetch: (id: number) => Promise<T>;
  apply: (task: T) => void;
  loading: (loading: boolean) => void;
  error: (error?: unknown) => void;
  shouldRetry?: (task: T) => boolean;
  wait?: () => Promise<void>;
}) {
  let generation = 0;
  let active: { id: number; generation: number; promise: Promise<void> } | undefined;
  function invalidate() {
    generation++;
    active = undefined;
    options.loading(false);
  }
  function load(id: number, supersede = false): Promise<void> {
    if (active?.id === id && !supersede) return active.promise;
    const ownGeneration = ++generation;
    options.loading(true);
    options.error();
    const current = () => ownGeneration === generation;
    const promise = Promise.resolve().then(async () => {
      try {
        let task = await options.fetch(id);
        if (!current()) return;
        if (options.shouldRetry?.(task)) {
          await (options.wait?.() || new Promise<void>(resolve => setTimeout(resolve, 250)));
          if (!current()) return;
          task = await options.fetch(id);
        }
        if (current()) {
          if (task.id !== id) throw new Error("任务详情响应与所选任务不一致");
          options.apply(task);
        }
      } catch (error) {
        if (current()) options.error(error);
      } finally {
        if (current()) { active = undefined; options.loading(false); }
      }
    });
    active = { id, generation: ownGeneration, promise };
    return promise;
  }
  return { load, invalidate };
}
