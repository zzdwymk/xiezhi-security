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

  public Scheduled schedule(
      int topologyGroup, String risk, boolean approvalRequired, List<Long> graphDependencies) {
    boolean serial = requiresSerialExecution(risk, approvalRequired);
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
