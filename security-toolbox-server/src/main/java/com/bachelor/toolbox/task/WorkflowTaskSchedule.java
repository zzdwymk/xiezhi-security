package com.bachelor.toolbox.task;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Conservative execution batches layered over an immutable workflow graph. */
public final class WorkflowTaskSchedule {
  private final List<Long> precedingTaskIds = new ArrayList<>();
  private Long lastSerialTaskId;
  private int executionGroup = -1;
  private int previousTopologyGroup = -1;
  private boolean previousWasSerial;

  public static boolean requiresSerialExecution(String risk, boolean approvalRequired) {
    return approvalRequired || !"SAFE".equalsIgnoreCase(risk);
  }

  /**
   * Decide serial vs parallel from both the risk gate and the tool's real target occupancy.
   *
   * <p>Approval or non-SAFE risk still forces serial (unchanged). Beyond that, a tool that sweeps
   * the target (Nmap, crawler, nuclei…) is also a barrier even when its risk label is SAFE, because
   * running a header probe next to a full-port sweep yields misleading timing and can trip rate
   * limits. Light read-only probes are the only tasks allowed to batch.
   */
  public static boolean requiresSerialExecution(
      String risk, boolean approvalRequired, String toolCode) {
    if (requiresSerialExecution(risk, approvalRequired)) return true;
    return ToolConcurrency.isBarrier(toolCode);
  }

  public Scheduled schedule(
      int topologyGroup, String risk, boolean approvalRequired, List<Long> graphDependencies) {
    return schedule(topologyGroup, risk, approvalRequired, graphDependencies, null);
  }

  public Scheduled schedule(
      int topologyGroup, String risk, boolean approvalRequired,
      List<Long> graphDependencies, String toolCode) {
    boolean serial = requiresSerialExecution(risk, approvalRequired, toolCode);
    // A LIGHT task that follows another LIGHT task stays in the same execution group, so the two
    // become parallel siblings; any barrier starts a fresh group.
    if (topologyGroup != previousTopologyGroup || serial || previousWasSerial) executionGroup++;
    previousTopologyGroup = topologyGroup;
    previousWasSerial = serial;
    Set<Long> dependencies = new LinkedHashSet<>(graphDependencies);
    // These are waiting edges only; the saved graph remains unchanged. Serial
    // tasks must wait for all preceding tasks, and later tasks must wait for them.
    if (serial) dependencies.addAll(precedingTaskIds);
    if (lastSerialTaskId != null) dependencies.add(lastSerialTaskId);
    return new Scheduled(executionGroup, List.copyOf(dependencies), serial);
  }

  /** Record runnable tasks only: an explicitly skipped optional node is no barrier. */
  public void taskCreated(Scheduled scheduled, long taskId) {
    precedingTaskIds.add(taskId);
    if (scheduled.serial()) lastSerialTaskId = taskId;
  }

  public record Scheduled(int group, List<Long> dependencyTaskIds, boolean serial) {}
}
