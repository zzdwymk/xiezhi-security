export type TaskbarProgressMode =
  | "none"
  | "normal"
  | "indeterminate"
  | "error"
  | "paused";

interface ProgressItem {
  value: number;
  mode?: "normal" | "paused" | "error";
}

class TaskbarProgressManager {
  private determinateItems = new Map<string, ProgressItem>();
  private indeterminateKeys = new Set<string>();
  private updateTimer: ReturnType<typeof setTimeout> | undefined;
  private lastProgress = -1;
  private lastMode: TaskbarProgressMode = "none";

  /**
   * Set or update a determinate progress value (0 to 1, or 0 to 100)
   */
  public setProgress(
    key: string,
    progress: number,
    mode: "normal" | "paused" | "error" = "normal",
  ) {
    const normalized =
      progress > 1
        ? Math.max(0, Math.min(1, progress / 100))
        : Math.max(0, Math.min(1, progress));
    this.determinateItems.set(key, { value: normalized, mode });
    this.indeterminateKeys.delete(key);
    this.scheduleSync();
  }

  /**
   * Remove a determinate progress item
   */
  public clearProgress(key: string) {
    if (this.determinateItems.delete(key)) {
      this.scheduleSync();
    }
  }

  /**
   * Register an indeterminate activity (animation under taskbar icon)
   */
  public startIndeterminate(key: string) {
    if (!this.indeterminateKeys.has(key)) {
      this.indeterminateKeys.add(key);
      this.scheduleSync();
    }
  }

  /**
   * Stop an indeterminate activity
   */
  public stopIndeterminate(key: string) {
    if (this.indeterminateKeys.delete(key)) {
      this.scheduleSync();
    }
  }

  /**
   * Synchronize a list of tasks with the taskbar progress
   */
  public syncTasks(
    tasks: Array<{
      id: number;
      status: string;
      progress?: number;
      progressDeterminate?: boolean;
    }>,
  ) {
    const runningTaskIds = new Set<string>();
    for (const task of tasks) {
      if (task.status === "RUNNING") {
        const key = `task-${task.id}`;
        runningTaskIds.add(key);
        if (
          task.progressDeterminate &&
          typeof task.progress === "number" &&
          task.progress >= 0
        ) {
          this.setProgress(key, task.progress / 100);
        } else {
          this.startIndeterminate(key);
        }
      }
    }
    for (const key of this.determinateItems.keys()) {
      if (key.startsWith("task-") && !runningTaskIds.has(key)) {
        this.determinateItems.delete(key);
      }
    }
    for (const key of this.indeterminateKeys) {
      if (key.startsWith("task-") && !runningTaskIds.has(key)) {
        this.indeterminateKeys.delete(key);
      }
    }
    this.scheduleSync();
  }

  /**
   * Helper to wrap an asynchronous action with indeterminate taskbar animation
   */
  public async wrapAsync<T>(
    key: string,
    action: Promise<T> | (() => Promise<T>),
  ): Promise<T> {
    this.startIndeterminate(key);
    try {
      const result = typeof action === "function" ? action() : action;
      return await result;
    } finally {
      this.stopIndeterminate(key);
    }
  }

  /**
   * Clear all taskbar progress items and reset taskbar
   */
  public clearAll() {
    this.determinateItems.clear();
    this.indeterminateKeys.clear();
    this.scheduleSync();
  }

  private scheduleSync() {
    if (this.updateTimer) return;
    this.updateTimer = setTimeout(() => {
      this.updateTimer = undefined;
      this.syncNow();
    }, 20);
  }

  private syncNow() {
    let targetProgress = -1;
    let targetMode: TaskbarProgressMode = "none";

    if (this.determinateItems.size > 0) {
      let maxProgress = 0;
      let mode: TaskbarProgressMode = "normal";
      for (const item of this.determinateItems.values()) {
        if (item.value >= maxProgress) {
          maxProgress = item.value;
          mode = item.mode || "normal";
        }
      }
      targetProgress = maxProgress;
      targetMode = mode;
    } else if (this.indeterminateKeys.size > 0) {
      targetProgress = 2;
      targetMode = "indeterminate";
    } else {
      targetProgress = -1;
      targetMode = "none";
    }

    if (targetProgress !== this.lastProgress || targetMode !== this.lastMode) {
      this.lastProgress = targetProgress;
      this.lastMode = targetMode;
      this.sendToNative(targetProgress, targetMode);
    }
  }

  private sendToNative(progress: number, mode: TaskbarProgressMode) {
    try {
      if (
        typeof window !== "undefined" &&
        window.toolboxDesktop?.setProgressBar
      ) {
        void window.toolboxDesktop.setProgressBar(progress, { mode });
      }
    } catch {
      // ignore
    }
  }
}

export const taskbarProgress = new TaskbarProgressManager();
