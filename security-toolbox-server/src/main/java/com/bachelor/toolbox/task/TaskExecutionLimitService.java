package com.bachelor.toolbox.task;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Persists and applies the user-editable task concurrency limits. */
@Service
public class TaskExecutionLimitService {
  private static final Logger log = LoggerFactory.getLogger(TaskExecutionLimitService.class);

  private final TaskExecutionSettingRepository settings;
  private final TaskExecutionControlService control;

  public TaskExecutionLimitService(
      TaskExecutionSettingRepository settings, TaskExecutionControlService control) {
    this.settings = settings;
    this.control = control;
  }

  /** Applies a previously persisted concurrency limit on service startup. */
  @PostConstruct
  void applyStoredOnStartup() {
    try {
      applyStored();
    } catch (Exception exception) {
      log.warn("启动时应用任务并发设置失败，将使用默认值", exception);
    }
  }

  /** Returns the currently configured global concurrency cap. */
  public int currentMaxConcurrentTasks() {
    return settings
        .findTopByOrderByIdAsc()
        .map(TaskExecutionSetting::getMaxConcurrentTasks)
        .orElse(TaskExecutionSetting.DEFAULT_MAX_CONCURRENT_TASKS);
  }

  /** Applies the stored limit to the runtime executor (idempotent; safe to call on startup). */
  public void applyStored() {
    control.resizeMaxConcurrentTasks(currentMaxConcurrentTasks());
  }

  /** Persists a new limit and applies it immediately. */
  @Transactional
  public int updateMaxConcurrentTasks(int maxConcurrentTasks) {
    int bounded = Math.max(
        TaskExecutionSetting.MAX_CONCURRENT_LOWER_BOUND,
        Math.min(TaskExecutionSetting.MAX_CONCURRENT_UPPER_BOUND, maxConcurrentTasks));
    TaskExecutionSetting persisted =
        settings.findTopByOrderByIdAsc().orElseGet(TaskExecutionSetting::new);
    persisted.setMaxConcurrentTasks(bounded);
    settings.save(persisted);
    control.resizeMaxConcurrentTasks(bounded);
    log.info("已更新任务全局并发上限：maxConcurrentTasks={}", bounded);
    return bounded;
  }
}