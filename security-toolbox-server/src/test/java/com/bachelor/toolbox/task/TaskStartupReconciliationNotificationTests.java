package com.bachelor.toolbox.task;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.notification.NotificationService;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * 第340轮：启动对账把中断任务标记 FAILED 后，必须给用户发通知。
 *
 * <p>崩溃/强制退出后重启，任务被对账为 FAILED，但用户只能自己去任务列表里发现；通知中心不会出现
 * 任何"任务已中断"的提示。修复后应发布一条可点击跳转的失败通知。
 */
class TaskStartupReconciliationNotificationTests {

  @Test
  void reconciledTasksPublishFailureNotification() {
    SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
    TaskExecutionControlService control = mock(TaskExecutionControlService.class);
    AuditService audit = mock(AuditService.class);
    NotificationService notifications = mock(NotificationService.class);

    SecurityTask stale = new SecurityTask();
    stale.setId(42L);
    stale.setProjectId(7L);
    stale.setTargetId(3L);
    stale.setToolCode("http_headers");
    stale.setStatus("RUNNING");
    stale.setCreatedAt(Instant.now().minusSeconds(3600));
    when(tasks.findAllByStatusOrderByCreatedAtAsc("RUNNING")).thenReturn(List.of(stale));
    when(tasks.findAllByStatusOrderByCreatedAtAsc("PENDING")).thenReturn(List.of());
    when(tasks.findAllByStatusOrderByCreatedAtAsc("PREPARING")).thenReturn(List.of());
    when(control.hasActiveWorker(42L)).thenReturn(false);

    TaskStartupReconciler reconciler =
        new TaskStartupReconciler(tasks, control, audit, notifications);
    reconciler.reconcileInterruptedTasks();

    verify(notifications)
        .publish(
            eq("task:42:startup-failed"),
            eq(7L),
            eq(false),
            anyString(),
            anyString(),
            anyString(),
            anyString(),
            anyString(),
            any());
  }

  @Test
  void noNotificationWhenNothingToReconcile() {
    SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
    TaskExecutionControlService control = mock(TaskExecutionControlService.class);
    AuditService audit = mock(AuditService.class);
    NotificationService notifications = mock(NotificationService.class);
    when(tasks.findAllByStatusOrderByCreatedAtAsc(anyString())).thenReturn(List.of());

    new TaskStartupReconciler(tasks, control, audit, notifications).reconcileInterruptedTasks();

    verify(notifications, never()).publish(any(), any(), anyBoolean(), any(), any(), any(), any(), any(), any());
  }
}
