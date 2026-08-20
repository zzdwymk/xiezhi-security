package com.bachelor.toolbox.task;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
public class TaskService {
  private static final int LIST_LIMIT = 1000;
  private static final Sort LIST_SORT =
      Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"));
  private static final Set<String> RETRYABLE_STATUSES =
      Set.of("FAILED", "TIMEOUT", "REJECTED", "CANCELLED");
  private final SecurityTaskRepository repository;
  private final TargetService targetService;
  private final SecurityToolRegistry registry;
  private final TaskExecutionService executionService;
  private final AuditService auditService;
  private final ObjectMapper objectMapper;
  private final TaskSnapshotService snapshotService;
  private final TaskExecutionControlService executionControl;
  private final AssessmentProjectService projectService;
  private final TaskProgressEventService progressEvents;
  private final ApplicationEventPublisher eventPublisher;

  @Autowired
  public TaskService(
      SecurityTaskRepository repository,
      TargetService targetService,
      SecurityToolRegistry registry,
      TaskExecutionService executionService,
      AuditService auditService,
      ObjectMapper objectMapper,
      TaskSnapshotService snapshotService,
      TaskExecutionControlService executionControl,
      AssessmentProjectService projectService,
      TaskProgressEventService progressEvents,
      ApplicationEventPublisher eventPublisher) {
    this.repository = repository;
    this.targetService = targetService;
    this.registry = registry;
    this.executionService = executionService;
    this.auditService = auditService;
    this.objectMapper = objectMapper;
    this.snapshotService = snapshotService;
    this.executionControl = executionControl;
    this.projectService = projectService;
    this.progressEvents = progressEvents;
    this.eventPublisher = eventPublisher;
  }

  TaskService(
      SecurityTaskRepository repository,
      TargetService targetService,
      SecurityToolRegistry registry,
      TaskExecutionService executionService,
      AuditService auditService,
      ObjectMapper objectMapper,
      TaskSnapshotService snapshotService,
      TaskExecutionControlService executionControl,
      AssessmentProjectService projectService,
      TaskProgressEventService progressEvents) {
    this(
        repository,
        targetService,
        registry,
        executionService,
        auditService,
        objectMapper,
        snapshotService,
        executionControl,
        projectService,
        progressEvents,
        event -> {});
  }

  public List<SecurityTask> list() {
    List<Long> projectIds = projectService.list().stream().map(project -> project.getId()).toList();
    if (projectIds.isEmpty()) {
      return List.of();
    }
    return repository.findAllByProjectIdIn(
        projectIds, PageRequests.bounded(0, LIST_LIMIT, 1, LIST_LIMIT, LIST_SORT));
  }

  public SecurityTask get(Long id) {
    SecurityTask task = repository.findById(id).orElseThrow(() -> new ApiException("任务不存在"));
    if (task.getProjectId() == null) {
      throw new ApiException("任务不属于评估项目");
    }
    projectService.get(task.getProjectId());
    return task;
  }

  public SecurityTask create(CreateTaskRequest request) throws JsonProcessingException {
    return create(request, null, null);
  }

  public SecurityTask create(CreateTaskRequest request, String ruleCode, String vulnerabilityCode)
      throws JsonProcessingException {
    return create(request, ruleCode, vulnerabilityCode, null, null, "CREATE_TASK");
  }

  public SecurityTask createRetest(
      CreateTaskRequest request,
      String ruleCode,
      String vulnerabilityCode,
      Long sourceTaskId,
      Long sourceFindingId)
      throws JsonProcessingException {
    if (sourceTaskId == null || sourceFindingId == null) {
      throw new ApiException("漏洞复测缺少原始任务或漏洞记录");
    }
    return create(
        request,
        ruleCode,
        vulnerabilityCode,
        sourceTaskId,
        sourceFindingId,
        "RETEST_TASK");
  }

  private SecurityTask create(
      CreateTaskRequest request,
      String ruleCode,
      String vulnerabilityCode,
      Long sourceTaskId,
      Long sourceFindingId,
      String auditAction)
      throws JsonProcessingException {
    projectService.validateProjectTarget(request.projectId(), request.targetId());
    var target = targetService.getCurrentlyAuthorized(request.targetId(), request.projectId());
    var tool = registry.require(request.toolCode());
    Map<String, Object> parameters = request.parameters() == null ? Map.of() : request.parameters();
    SecurityTask task = new SecurityTask();
    task.setTargetId(request.targetId());
    task.setProjectId(request.projectId());
    task.setToolCode(request.toolCode());
    task.setRuleCode(ruleCode);
    task.setVulnerabilityCode(vulnerabilityCode);
    task.setSourceTaskId(sourceTaskId);
    task.setSourceFindingId(sourceFindingId);
    task.setStatus("PENDING");
    task.setProgress(0);
    task.setProgressDeterminate(false);
    task.setProgressMessage("等待本地执行资源");
    task.setProgressUpdatedAt(java.time.Instant.now());
    task.setQueueEnteredAt(java.time.Instant.now());
    task.setRequestJson(objectMapper.writeValueAsString(parameters));
    snapshotService.capture(task, target, tool);
    return saveAndExecute(task, auditAction, sourceTaskId);
  }

  /**
   * Persists one workflow-bound task. Only root tasks are queued immediately; successors stay
   * blocked until {@link WorkflowTaskDependencyScheduler} verifies every dependency.
   */
  public SecurityTask createWorkflowTask(
      CreateTaskRequest request,
      String workflowDigest,
      String workflowNodeId,
      String nodeRunId,
      int workflowGroup,
      String effectiveRisk,
      boolean approvalRequired,
      List<Long> dependencyTaskIds)
      throws JsonProcessingException {
    return createWorkflowTask(
        request,
        workflowDigest,
        workflowNodeId,
        nodeRunId,
        workflowGroup,
        effectiveRisk,
        approvalRequired,
        dependencyTaskIds,
        null);
  }

  public SecurityTask createWorkflowTask(
      CreateTaskRequest request,
      String workflowDigest,
      String workflowNodeId,
      String nodeRunId,
      int workflowGroup,
      String effectiveRisk,
      boolean approvalRequired,
      List<Long> dependencyTaskIds,
      Long workflowRunId)
      throws JsonProcessingException {
    if (workflowDigest == null || !workflowDigest.matches("sha256:[0-9a-f]{64}")) {
      throw new ApiException("工作流摘要格式无效");
    }
    if (workflowNodeId == null || !workflowNodeId.matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}")) {
      throw new ApiException("工作流节点 ID 格式无效");
    }
    if (nodeRunId == null || !nodeRunId.matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}")) {
      throw new ApiException("节点运行 ID 格式无效");
    }
    List<Long> dependencies =
        dependencyTaskIds == null ? List.of() : dependencyTaskIds.stream().distinct().toList();
    if (dependencies.stream().anyMatch(id -> id == null || id <= 0)) {
      throw new ApiException("任务依赖 ID 无效");
    }
    projectService.validateProjectTarget(request.projectId(), request.targetId());
    var target = targetService.getCurrentlyAuthorized(request.targetId(), request.projectId());
    var tool = registry.require(request.toolCode());
    for (SecurityTask dependency : repository.findAllById(dependencies)) {
      if (!request.projectId().equals(dependency.getProjectId())
          || !workflowDigest.equals(dependency.getWorkflowDigest())) {
        throw new ApiException("工作流任务依赖越过项目或快照边界");
      }
    }
    if (repository.findAllById(dependencies).size() != dependencies.size()) {
      throw new ApiException("工作流任务依赖不存在");
    }

    SecurityTask task = new SecurityTask();
    task.setTargetId(request.targetId());
    task.setProjectId(request.projectId());
    task.setToolCode(request.toolCode());
    task.setStatus(dependencies.isEmpty() ? "PENDING" : "BLOCKED");
    task.setProgress(0);
    task.setProgressDeterminate(false);
    task.setProgressMessage(dependencies.isEmpty() ? "等待本地执行资源" : "等待前置工作流节点完成");
    task.setProgressUpdatedAt(java.time.Instant.now());
    task.setQueueEnteredAt(java.time.Instant.now());
    task.setRequestJson(
        objectMapper.writeValueAsString(
            request.parameters() == null ? Map.of() : request.parameters()));
    task.setWorkflowDigest(workflowDigest);
    task.setWorkflowRunId(workflowRunId);
    task.setWorkflowNodeId(workflowNodeId);
    task.setNodeRunId(nodeRunId);
    task.setWorkflowGroup(Math.max(0, workflowGroup));
    task.setDependencyTaskIds(objectMapper.writeValueAsString(dependencies));
    task.setEffectiveRisk(effectiveRisk == null ? "SAFE" : effectiveRisk);
    task.setWorkflowApprovalRequired(approvalRequired);
    snapshotService.capture(task, target, tool);
    return saveTask(task, "CREATE_WORKFLOW_TASK", null, dependencies.isEmpty());
  }

  public SecurityTask createSkippedWorkflowTask(
      CreateTaskRequest request,
      String workflowDigest,
      String workflowNodeId,
      String nodeRunId,
      int workflowGroup,
      String effectiveRisk,
      boolean approvalRequired,
      List<Long> dependencyTaskIds,
      Long workflowRunId,
      String reason)
      throws JsonProcessingException {
    projectService.validateProjectTarget(request.projectId(), request.targetId());
    SecurityTask task = new SecurityTask();
    task.setTargetId(request.targetId());
    task.setProjectId(request.projectId());
    task.setToolCode(request.toolCode());
    task.setStatus("SKIPPED");
    task.setProgress(100);
    task.setProgressDeterminate(true);
    task.setProgressMessage(reason);
    task.setProgressUpdatedAt(java.time.Instant.now());
    task.setFinishedAt(java.time.Instant.now());
    task.setTerminationReason("UNAVAILABLE_TOOL");
    task.setErrorMessage(reason);
    task.setRequestJson(
        objectMapper.writeValueAsString(
            request.parameters() == null ? Map.of() : request.parameters()));
    task.setWorkflowDigest(workflowDigest);
    task.setWorkflowRunId(workflowRunId);
    task.setWorkflowNodeId(workflowNodeId);
    task.setNodeRunId(nodeRunId);
    task.setWorkflowGroup(Math.max(0, workflowGroup));
    task.setDependencyTaskIds(
        objectMapper.writeValueAsString(
            dependencyTaskIds == null ? List.of() : dependencyTaskIds.stream().distinct().toList()));
    task.setEffectiveRisk(effectiveRisk == null ? "SAFE" : effectiveRisk);
    task.setWorkflowApprovalRequired(approvalRequired);
    SecurityTask saved = saveTask(task, "SKIP_UNAVAILABLE_WORKFLOW_TASK", null, false);
    publishTerminalAfterCommit(saved.getId());
    return saved;
  }

  public SecurityTask retry(Long id) {
    SecurityTask original = get(id);
    if (!RETRYABLE_STATUSES.contains(original.getStatus())) {
      throw new ApiException("仅失败、被拒绝或已取消的任务可以重试");
    }
    var target =
        targetService.getCurrentlyAuthorized(original.getTargetId(), original.getProjectId());
    projectService.validateProjectTarget(original.getProjectId(), original.getTargetId());
    var tool = registry.require(original.getToolCode());

    SecurityTask retry = new SecurityTask();
    retry.setTargetId(original.getTargetId());
    retry.setProjectId(original.getProjectId());
    retry.setToolCode(original.getToolCode());
    retry.setRuleCode(original.getRuleCode());
    retry.setVulnerabilityCode(original.getVulnerabilityCode());
    retry.setStatus("PENDING");
    retry.setProgress(0);
    retry.setProgressDeterminate(false);
    retry.setProgressMessage("等待本地执行资源");
    retry.setProgressUpdatedAt(java.time.Instant.now());
    retry.setQueueEnteredAt(java.time.Instant.now());
    retry.setRequestJson(original.getRequestJson());
    retry.setSourceTaskId(original.getId());
    snapshotService.capture(retry, target, tool);
    return saveAndExecute(retry, "RETRY_TASK", original.getId());
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public SecurityTask cancel(Long id) {
    SecurityTask task = get(id);
    if (Set.of("SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "SKIPPED")
        .contains(task.getStatus()))
      throw new ApiException("已结束的任务不能取消");
    String previous = task.getStatus();
    // Interrupt the worker and flip status immediately so the control center
    // stops showing RUNNING after cancel is acknowledged.
    executionControl.requestCancellation(id);
    task.setStatus("CANCELLED");
    task.setProgressMessage("PENDING".equals(previous) ? "任务在排队阶段被取消" : "用户取消任务");
    task.setProgressUpdatedAt(java.time.Instant.now());
    task.setTerminationReason("CANCELLED");
    task.setFinishedAt(java.time.Instant.now());
    task.setErrorMessage("用户取消任务");
    repository.save(task);
    progressEvents.publish(task, "用户取消任务");
    publishTerminalAfterCommit(task.getId());
    auditService.record("CANCEL_TASK", "TASK", id, task.getToolCode(), "CANCELLED");
    return task;
  }

  private SecurityTask saveAndExecute(SecurityTask task, String auditAction, Long sourceTaskId) {
    return saveTask(task, auditAction, sourceTaskId, true);
  }

  private SecurityTask saveTask(
      SecurityTask task, String auditAction, Long sourceTaskId, boolean execute) {
    SecurityTask saved = repository.save(task);
    String detail =
        sourceTaskId == null
            ? saved.getToolCode()
            : saved.getToolCode() + "; sourceTaskId=" + sourceTaskId;
    if (saved.getAuthorizationSnapshotHash() == null) {
      auditService.record(auditAction, "TASK", saved.getId(), detail, "ACCEPTED");
    } else {
      auditService.record(
          auditAction,
          "TASK",
          saved.getId(),
          detail,
          "ACCEPTED",
          saved.getId(),
          saved.getAuthorizationSnapshotHash());
    }
    if (!execute) return saved;
    if (TransactionSynchronizationManager.isActualTransactionActive()
        && TransactionSynchronizationManager.isSynchronizationActive()) {
      TransactionSynchronizationManager.registerSynchronization(
          new TransactionSynchronization() {
            @Override
            public void afterCommit() {
              enqueueAfterCommit(saved.getId());
            }
          });
    } else {
      enqueue(saved, true);
    }
    return saved;
  }

  private void enqueueAfterCommit(Long taskId) {
    repository.findById(taskId).ifPresent(task -> enqueue(task, false));
  }

  private void publishTerminalAfterCommit(Long taskId) {
    if (TransactionSynchronizationManager.isActualTransactionActive()
        && TransactionSynchronizationManager.isSynchronizationActive()) {
      TransactionSynchronizationManager.registerSynchronization(
          new TransactionSynchronization() {
            @Override
            public void afterCommit() {
              eventPublisher.publishEvent(new TaskTerminalEvent(taskId));
            }
          });
      return;
    }
    eventPublisher.publishEvent(new TaskTerminalEvent(taskId));
  }

  private void enqueue(SecurityTask task, boolean propagateFailure) {
    try {
      executionService.executeAsync(task.getId());
    } catch (RuntimeException ex) {
      task.setStatus("REJECTED");
      task.setProgressMessage("本地任务队列已满");
      task.setProgressUpdatedAt(java.time.Instant.now());
      task.setErrorMessage("本地任务队列已满，请稍后重试");
      repository.save(task);
      if (propagateFailure) {
        throw new ApiException("本地任务队列已满，请稍后重试");
      }
    }
  }
}
