package com.bachelor.toolbox.task;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Provides a read-only, user-facing view of task concurrency limits. */
@Service
public class TaskControlStatusService {
  private final SecurityTaskRepository tasks;
  private final TaskExecutionControlService control;
  private final int queueCapacity;

  public TaskControlStatusService(
      SecurityTaskRepository tasks,
      TaskExecutionControlService control,
      @Value("${spring.task.execution.pool.queue-capacity:50}") int queueCapacity) {
    this.tasks = tasks;
    this.control = control;
    this.queueCapacity = Math.max(0, queueCapacity);
  }

  public TaskControlStatus snapshot() {
    return new TaskControlStatus(
        control.maxConcurrentTasks(),
        control.availableConcurrentSlots(),
        control.maxConcurrentTasksPerTarget(),
        queueCapacity,
        tasks.countByStatus("PENDING"),
        tasks.countByStatus("RUNNING"));
  }
}
