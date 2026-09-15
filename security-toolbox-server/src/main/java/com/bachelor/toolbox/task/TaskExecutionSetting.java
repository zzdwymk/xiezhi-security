package com.bachelor.toolbox.task;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Persistent, user-editable task-execution policy keyed by a single logical id. */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "task_execution_settings")
public class TaskExecutionSetting {
  /** Fixed single-row id so the settings row is stable. */
  public static final long ID = 1L;

  public static final int DEFAULT_MAX_CONCURRENT_TASKS = 3;
  public static final int MAX_CONCURRENT_LOWER_BOUND = 1;
  public static final int MAX_CONCURRENT_UPPER_BOUND = 32;

  @Id
  @Column(nullable = false)
  private Long id = ID;

  /** Maximum number of tasks that may execute at the same time (global concurrency cap). */
  @Column(nullable = false)
  private int maxConcurrentTasks;
}