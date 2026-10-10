package com.bachelor.toolbox.notification;

import com.bachelor.toolbox.task.SecurityTask;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Set;
import org.springframework.stereotype.Service;

@Service
public class TaskNotificationPublisher {
  private static final Set<String> TERMINAL = Set.of("SUCCESS", "FAILED", "TIMEOUT", "REJECTED");
  private final NotificationService notifications;
  @org.springframework.beans.factory.annotation.Autowired
  public TaskNotificationPublisher(NotificationService notifications) {
    this.notifications = notifications;
  }

  public TaskNotificationPublisher(NotificationService notifications, ObjectMapper mapper) {
    this(notifications);
  }

  public void publish(SecurityTask task) {
    if (task.getWorkflowRunId() != null || !TERMINAL.contains(task.getStatus())) return;
    String label = switch (task.getStatus()) {
      case "SUCCESS" -> "已完成";
      case "TIMEOUT" -> "执行超时";
      case "REJECTED" -> "未能进入执行队列";
      default -> "执行失败";
    };
    boolean success = "SUCCESS".equals(task.getStatus());
    String detail = success ? "检测结果已保存" : task.getErrorMessage();
    notifications.publish("task:" + task.getId() + ":" + task.getStatus(), task.getProjectId(),
        false, "task", success ? "success" : "error", "安全任务" + label,
        task.getToolCode() + " · 任务 #" + task.getId() + "：" + (detail == null ? label : detail),
        "/tasks?taskId=" + task.getId(), notifications.findingSeverities(java.util.List.of(task.getId())));
  }
}
