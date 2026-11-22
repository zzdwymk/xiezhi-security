package com.bachelor.toolbox.task;

import com.bachelor.toolbox.audit.AuditService;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * 第302轮：启动期任务对账。
 *
 * <p>进程被强制结束（崩溃、关机、任务管理器结束进程）时，正在执行的任务行永远不会被写成
 * FAILED/TIMEOUT，会一直停在 RUNNING/PENDING/PREPARING。R300 只在「清空业务数据」入口做了对账，
 * 任务列表、仪表盘、通知仍显示"执行中"，用户无法判断哪些是僵尸任务。
 *
 * <p>本组件在 {@link ApplicationReadyEvent} 统一对账一次：内存中没有任何 worker 的残留行
 * 一律标记为 FAILED（附可读原因并写审计），使重启后的状态与真实执行情况一致。
 */
@Component
public class TaskStartupReconciler {
  private static final Logger LOG = LoggerFactory.getLogger(TaskStartupReconciler.class);
  private static final List<String> INTERRUPTED_STATUSES =
      List.of("RUNNING", "PENDING", "PREPARING");

  private final SecurityTaskRepository tasks;
  private final TaskExecutionControlService executionControl;
  private final AuditService audit;

  public TaskStartupReconciler(
      SecurityTaskRepository tasks,
      TaskExecutionControlService executionControl,
      AuditService audit) {
    this.tasks = tasks;
    this.executionControl = executionControl;
    this.audit = audit;
  }

  @EventListener(ApplicationReadyEvent.class)
  public void reconcileInterruptedTasks() {
    int healed = 0;
    for (String status : INTERRUPTED_STATUSES) {
      for (SecurityTask task : tasks.findAllByStatusOrderByCreatedAtAsc(status)) {
        if (executionControl != null && executionControl.hasActiveWorker(task.getId())) {
          continue;
        }
        task.setStatus("FAILED");
        task.setErrorMessage("服务重启或异常退出，任务已中断，请重试");
        task.setFinishedAt(Instant.now());
        tasks.save(task);
        audit.record("RECOVER_TASK", "TASK", task.getId(), "startup-reconcile", "SUCCESS");
        healed++;
      }
    }
    if (healed > 0) {
      LOG.warn("启动对账：已将 {} 个残留任务标记为 FAILED", healed);
    }
  }
}
