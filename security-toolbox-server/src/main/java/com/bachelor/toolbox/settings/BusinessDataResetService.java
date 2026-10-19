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
         "system_notifications",
         "traffic_scan_ledger",
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
          "workflow_runs",
          "security_tasks",
          "assessment_project_targets",
          "assessment_projects",
          "authorized_targets");

  // 物理表名 → 中文业务类别。审计日志只记录业务含义，不暴露数据库 schema：
  // 审计记录可能被导出/截图传播，超出"管理员本人"的信任边界，展示层不应成为 schema 查询接口。
  private static final Map<String, String> TABLE_TO_CATEGORY =
      Map.ofEntries(
          Map.entry("system_notifications", "系统通知"),
          Map.entry("traffic_scan_ledger", "流量扫描台账"),
          Map.entry("agent_ledger_records", "AI 执行台账"),
          Map.entry("ai_agent_dispatches", "AI 任务分发"),
          Map.entry("ai_conversation_sessions", "AI 对话会话"),
          Map.entry("traffic_suggestions", "流量修复建议"),
          Map.entry("traffic_packets", "流量报文"),
          Map.entry("traffic_sessions", "流量会话"),
          Map.entry("security_actions", "安全处置操作"),
          Map.entry("post_scan_paths", "后渗透路径"),
          Map.entry("findings", "漏洞发现"),
          Map.entry("scan_schedules", "扫描计划"),
          Map.entry("project_approvals", "项目审批"),
          Map.entry("recon_results", "信息收集结果"),
          Map.entry("probe_results", "指纹探测结果"),
          Map.entry("audit_logs", "审计日志"),
          Map.entry("workflow_runs", "工作流运行记录"),
          Map.entry("security_tasks", "检测任务"),
          Map.entry("assessment_project_targets", "项目目标关联"),
          Map.entry("assessment_projects", "评估项目"),
          Map.entry("authorized_targets", "授权目标"));

  private static final List<String> PRESERVED_CATEGORIES =
      List.of("用户账号", "AI 工作流定义", "检测规则", "漏洞知识库", "流量捕获过滤器");

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
    if (!"永久清空".equals(confirmation)) {
      throw new ApiException("请输入“永久清空”确认清空数据");
    }

    // Reject known long-running operations before requesting the exclusive lock. A queued fair
    // write lock would otherwise block the cancellation request needed to stop that operation.
    assertIdle();
    return operationGate.withImmediateReset(this::clearExclusively);
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
    // 键为业务类别而非物理表名：审计日志面向查看者只暴露业务语义，不暴露数据库 schema。
    Map<String, Integer> deletedByCategory = new LinkedHashMap<>();
    int total = 0;
    for (String table : BUSINESS_TABLES_IN_DELETE_ORDER) {
      int deleted = entityManager.createNativeQuery("delete from " + table).executeUpdate();
      deletedByCategory.merge(TABLE_TO_CATEGORY.getOrDefault(table, table), deleted, Integer::sum);
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
            "deletedByCategory", deletedByCategory,
            "preservedData", PRESERVED_CATEGORIES),
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
