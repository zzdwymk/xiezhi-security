package com.bachelor.toolbox.settings;

import com.bachelor.toolbox.ai.AiAgentRuntimeClient;
import com.bachelor.toolbox.ai.AiConversationMemoryService;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.traffic.TrafficProxyService;
import com.bachelor.toolbox.traffic.TrafficSessionRepository;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class BusinessDataResetService {
  private static final List<String> ACTIVE_TASK_STATUSES = List.of("BLOCKED", "PENDING", "RUNNING");
  private static final List<String> ACTIVE_TRAFFIC_STATUSES = List.of("STARTING", "RUNNING");
  private static final List<String> BUSINESS_TABLES_IN_DELETE_ORDER =
     List.of(
         "agent_ledger_records",
         "ai_agent_dispatches",
          "ai_conversation_sessions",
          "traffic_suggestions",
          "traffic_packets",
          "traffic_sessions",
          "security_actions",
          "post_scan_paths",
          "findings",
          "scan_schedules",
          "project_approvals",
          "recon_results",
          "probe_results",
          "audit_logs",
          "security_tasks",
          "assessment_project_targets",
          "assessment_projects",
          "authorized_targets");

  private final EntityManager entityManager;
  private final SecurityTaskRepository tasks;
  private final AssessmentProjectRepository projects;
  private final TrafficProxyService trafficProxy;
  private final TrafficSessionRepository trafficSessions;
  private final AiAgentRuntimeClient runtime;
  private final AiConversationMemoryService conversations;
  private final AuditService audit;
  private final BusinessDataOperationGate operationGate;
  private final TransactionTemplate resetTransaction;

  @Autowired
  public BusinessDataResetService(
      EntityManager entityManager,
      SecurityTaskRepository tasks,
      AssessmentProjectRepository projects,
      TrafficProxyService trafficProxy,
      TrafficSessionRepository trafficSessions,
      AiAgentRuntimeClient runtime,
      AiConversationMemoryService conversations,
      AuditService audit,
      BusinessDataOperationGate operationGate,
      PlatformTransactionManager transactionManager) {
    this.entityManager = entityManager;
    this.tasks = tasks;
    this.projects = projects;
    this.trafficProxy = trafficProxy;
    this.trafficSessions = trafficSessions;
    this.runtime = runtime;
    this.conversations = conversations;
    this.audit = audit;
    this.operationGate = operationGate;
    this.resetTransaction = new TransactionTemplate(transactionManager);
    this.resetTransaction.setIsolationLevel(TransactionDefinition.ISOLATION_SERIALIZABLE);
  }

  BusinessDataResetService(
      EntityManager entityManager,
      SecurityTaskRepository tasks,
      AssessmentProjectRepository projects,
      TrafficProxyService trafficProxy,
      TrafficSessionRepository trafficSessions,
      AiAgentRuntimeClient runtime,
      AiConversationMemoryService conversations,
      AuditService audit,
      PlatformTransactionManager transactionManager) {
    this(
        entityManager,
        tasks,
        projects,
        trafficProxy,
        trafficSessions,
        runtime,
        conversations,
        audit,
        new BusinessDataOperationGate(),
        transactionManager);
  }

  public ResetResult clear(String confirmation) {
    if (!"CLEAR".equals(confirmation)) {
      throw new ApiException("请输入 CLEAR 确认清空数据");
    }

    return operationGate.withReset(this::clearExclusively);
  }

  private ResetResult clearExclusively() {
    // TrafficProxyService start/stop/capture mutations synchronize on the service instance.
    // Holding the same monitor prevents a proxy session from starting during the reset.
    synchronized (trafficProxy) {
      assertIdle();
      List<Long> projectIds = projects.findAll().stream().map(project -> project.getId()).toList();
      int runtimeDocumentsDeleted = clearRuntimeIndexes(projectIds);
      ResetResult result =
          resetTransaction.execute(
              ignored -> clearDatabase(projectIds.size(), runtimeDocumentsDeleted));
      if (result == null) throw new IllegalStateException("清空数据事务未返回结果");
      conversations.evictAllLocal();
      return result;
    }
  }

  private void assertIdle() {
    if (trafficProxy.status().running()
        || trafficSessions.countByStatusIn(ACTIVE_TRAFFIC_STATUSES) > 0) {
      throw new ApiException("请先停止正在运行的流量代理");
    }
    if (tasks.countByStatusIn(ACTIVE_TASK_STATUSES) > 0) {
      throw new ApiException("请先取消或等待正在运行的任务结束");
    }
  }

  private int clearRuntimeIndexes(List<Long> projectIds) {
    int deleted = 0;
    for (Long projectId : projectIds) {
      deleted += runtime.clearProjectIndex(projectId);
    }
    return deleted;
  }

  private ResetResult clearDatabase(int projectCount, int runtimeDocumentsDeleted) {
    assertIdle();
    entityManager.flush();
    Map<String, Integer> deletedByTable = new LinkedHashMap<>();
    int total = 0;
    for (String table : BUSINESS_TABLES_IN_DELETE_ORDER) {
      int deleted = entityManager.createNativeQuery("delete from " + table).executeUpdate();
      deletedByTable.put(table, deleted);
      total += deleted;
    }
    entityManager.clear();

    Instant clearedAt = Instant.now();
    audit.recordStructured(
        "CLEAR_BUSINESS_DATA",
        "SYSTEM_DATA",
        null,
        Map.of(
            "deletedRecords", total,
            "deletedProjects", projectCount,
            "runtimeDocumentsDeleted", runtimeDocumentsDeleted,
            "deletedByTable", deletedByTable,
            "preservedData",
                List.of(
                    "app_users",
                    "agent_workflow_spec",
                    "detection_rules",
                    "vulnerability_definitions",
                    "traffic_capture_filters")),
        "SUCCESS");
    return new ResetResult(clearedAt, total, true, projectCount, runtimeDocumentsDeleted);
  }

  public record ResetResult(
      Instant clearedAt,
      int deletedRecords,
      boolean auditLogRetained,
      int clearedProjects,
      int runtimeDocumentsDeleted) {}
}
