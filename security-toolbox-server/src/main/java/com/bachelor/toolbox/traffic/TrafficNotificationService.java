package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.notification.NotificationService;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/** Traffic operations are administrator-only; notices preserve that audience even for shared targets. */
@Service
public class TrafficNotificationService {
  private static final Logger log = LoggerFactory.getLogger(TrafficNotificationService.class);
  private final NotificationService notifications;
  private final ProjectTargetRepository projectTargets;
  private final ObjectMapper mapper;

  public TrafficNotificationService(NotificationService notifications,
      ProjectTargetRepository projectTargets, ObjectMapper mapper) {
    this.notifications = notifications;
    this.projectTargets = projectTargets;
    this.mapper = mapper;
  }

  String serialize(Object result) {
    try { return mapper.writeValueAsString(result); }
    catch (Exception exception) { log.warn("保存流量结果摘要失败", exception); return null; }
  }

  void publish(String operationId, Long packetId, Long targetId, Long ledgerId,
      String engine, String status, String message, List<String> severities) {
    try {
      // A target may belong to several projects. Do not attribute a global traffic operation
      // to an arbitrary project, or send its captured content to project members.
      List<Long> projects = targetId == null ? List.of() : projectTargets.findByTargetId(targetId)
          .stream().map(link -> link.getProjectId()).distinct().toList();
      Long projectId = projects.size() == 1 ? projects.get(0) : null;
      String outcome = "COMPLETED".equals(status) ? "success"
          : "FAILED".equals(status) || "TIMEOUT".equals(status) ? "error" : "warning";
      String label = "COMPLETED".equals(status) ? "已完成"
          : "TIMEOUT".equals(status) ? "已超时"
          : "CANCELLED".equals(status) ? "已取消" : "FAILED".equals(status) ? "执行失败" : "未全部完成";
      String route = "/traffic?packetId=" + packetId + (ledgerId == null ? "" : "&scanId=" + ledgerId);
      notifications.publish("traffic:" + operationId, projectId, true, "traffic", outcome,
          engine + " 流量测试" + label, message, route, severities);
    } catch (RuntimeException exception) {
      log.warn("发布流量操作通知失败，operationId={}", operationId, exception);
    }
  }

  static String operationId() { return UUID.randomUUID().toString(); }
}
