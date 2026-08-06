package com.bachelor.toolbox.tool;

import java.util.List;

public interface ToolExecutionObserver {
  ToolExecutionObserver NOOP = new ToolExecutionObserver() {};

  default void command(List<String> command) {}

  default void operation(String operation) {}

  /**
   * Reports measurable work performed by a tool. Both values must describe the real unit being
   * processed (ports, requests, templates, files, ...), never an elapsed-time estimate.
   */
  default void progress(long completed, long total, String operation) {}

  /** Reports a native percentage supplied by an external tool. */
  default void progressPercent(double percentage, String operation) {
    if (Double.isFinite(percentage)) {
      progress(Math.round(Math.max(0d, Math.min(100d, percentage))), 100L, operation);
    }
  }

  /**
   * Reports live activity when the external tool cannot expose a truthful total. Clients render
   * this as an indeterminate moving progress bar.
   */
  default void heartbeat(String operation) {}

  default boolean isCancellationRequested() {
    return false;
  }
}
