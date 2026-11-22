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
public class TaskStartupReconciler implements org.springframework.core.Ordered {
  private static final Logger LOG = LoggerFactory.getLogger(TaskStartupReconciler.class);
  private static final List<String> INTERRUPTED_STATUSES =
      List.of("RUNNING", "PENDING", "PREPARING");

  private final SecurityTaskRepository tasks;
  private final TaskExecutionControlService executionControl;
  private final AuditService audit;
  private final com.bachelor.toolbox.notification.NotificationService notifications;

  public TaskStartupReconciler(
      SecurityTaskRepository tasks,
      TaskExecutionControlService executionControl,
      AuditService audit) {
    this(tasks, executionControl, audit, null);
  }

  @org.springframework.beans.factory.annotation.Autowired
  public TaskStartupReconciler(
      SecurityTaskRepository tasks,
      TaskExecutionControlService executionControl,
      AuditService audit,
      @org.springframework.beans.factory.annotation.Autowired(required = false)
          com.bachelor.toolbox.notification.NotificationService notifications) {
    this.tasks = tasks;
    this.executionControl = executionControl;
    this.audit = audit;
    this.notifications = notifications;
  }

  /** Round 307：必须在其它启动期监听器（如扫描调度器）之前完成对账，否则会把刚入队的任务误杀。 */
  @Override
  public int getOrder() {
    return org.springframework.core.Ordered.HIGHEST_PRECEDENCE;
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
        // Round 340：对账结果必须让用户看到，否则只能自己去任务列表里翻出"执行中"变"失败"。
        if (notifications != null) {
          try {
            notifications.publish(
                "task:" + task.getId() + ":startup-failed",
                task.getProjectId(),
                false,
                "task",
                "error",
                "任务因服务重启中断",
                "任务「"
                    + (task.getToolCode() == null ? "未知工具" : task.getToolCode())
                    + "」已标记为失败，请重试。",
                "/tasks?taskId=" + task.getId(),
                List.of("high"));
          } catch (RuntimeException notificationFailure) {
            LOG.warn("启动对账通知发送失败 taskId={}", task.getId(), notificationFailure);
          }
        }
        healed++;
      }
    }
    if (healed > 0) {
      LOG.warn("启动对账：已将 {} 个残留任务标记为 FAILED", healed);
    }
  }
}


