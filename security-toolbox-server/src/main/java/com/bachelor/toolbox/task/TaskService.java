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
  private com.bachelor.toolbox.notification.TaskNotificationPublisher taskNotifications;

  @org.springframework.beans.factory.annotation.Autowired(required = false)
  public void setTaskNotifications(com.bachelor.toolbox.notification.TaskNotificationPublisher value) {
    taskNotifications = value;
  }
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
  @Autowired private com.bachelor.toolbox.project.ProjectAuthorizationService authorization;
  @Autowired private org.springframework.transaction.PlatformTransactionManager transactionManager;
  @jakarta.persistence.PersistenceContext private jakarta.persistence.EntityManager entityManager;
  /** 与 AiAuthorizationGuard 共用同一组配额配置，保证批量执行与 AI 派发口径一致。 */
  @org.springframework.beans.factory.annotation.Value("${toolbox.ai.agent.max-active-tasks-per-target:4}")
  private int maxActiveTasksPerTarget = 4;

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

  /**
   * AI 计划内带依赖的任务创建入口。
   *
   * <p>AI 直接规划的方案不存在 {@code workflowDigest}/{@code workflowNodeId}，因此用不了
   * {@link #createWorkflowTask}。但"先探测端口、再按探测结果做深入识别"这类步骤必须能建立任务级
   * 依赖：{@code TaskExecutionService#narrowPortsToDependencyResults} 正是靠
   * {@code dependencyTaskIds} 找到前序任务的 {@code openPorts}，把后续工具的扫描范围收敛过去。
   *
   * <p>与 {@link #create(CreateTaskRequest)} 的区别只有一处：<strong>存在依赖时不立即入队</strong>。
   * 依赖任务尚未完成时入队，后续工具只会拿到空结果，等于白跑一次全量扫描。
   *
   * @param dependencyTaskIds 前序任务 ID（同一目标与项目内）；为空时行为等同 {@code create}
   */
  @Transactional(rollbackFor = Exception.class)
  public SecurityTask createDependent(
      CreateTaskRequest request, List<Long> dependencyTaskIds, int workflowGroup)
      throws JsonProcessingException {
    List<Long> dependencies =
        dependencyTaskIds == null
            ? List.of()
            : dependencyTaskIds.stream().distinct().filter(id -> id != null && id > 0).toList();
    if (dependencies.isEmpty()) {
      return create(request);
    }
    projectService.validateProjectTarget(request.projectId(), request.targetId());
    var target = targetService.getCurrentlyAuthorized(request.targetId(), request.projectId());
    var tool = registry.require(request.toolCode());
    List<SecurityTask> dependencyTasks = repository.findAllById(dependencies);
    if (dependencyTasks.size() != dependencies.size()) {
      throw new ApiException("任务依赖不存在");
    }
    for (SecurityTask dependency : dependencyTasks) {
      if (!request.projectId().equals(dependency.getProjectId())
          || !request.targetId().equals(dependency.getTargetId())) {
        throw new ApiException("任务依赖越过项目或目标边界");
      }
    }
    SecurityTask task = new SecurityTask();
    task.setTargetId(request.targetId());
    task.setProjectId(request.projectId());
    task.setToolCode(request.toolCode());
    // BLOCKED 而非 PENDING：PENDING 会被执行器直接取走，在依赖尚未完成时拿到空的 openPorts，
    // 等于白跑一次全量扫描。BLOCKED 由 WorkflowTaskDependencyScheduler 在依赖终态后放行。
    task.setStatus("BLOCKED");
    task.setProgress(0);
    task.setProgressDeterminate(false);
    task.setProgressMessage("等待前置端口探测完成");
    task.setProgressUpdatedAt(java.time.Instant.now());
    task.setQueueEnteredAt(java.time.Instant.now());
    task.setRequestJson(objectMapper.writeValueAsString(
        request.parameters() == null ? Map.of() : request.parameters()));
    task.setWorkflowGroup(Math.max(0, workflowGroup));
    task.setDependencyTaskIds(objectMapper.writeValueAsString(dependencies));
    task.setEffectiveRisk("SAFE");
    snapshotService.capture(task, target, tool);
    // execute=false：等依赖完成后再入队。
    return saveTask(task, "CREATE_DEPENDENT_TASK", null, false);
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
   * 直接按授权项目对项目内目标批量下发同一工具。
   *
   * <p>与单目标入口相比，这里先按项目解析一次目标清单（全部目标或指定子集），再逐目标复用单目标创建流程：
   * 每个目标独立执行项目活跃状态、授权时间窗、目标授权状态和单目标任务配额校验。任一目标失败不会中断其余目标，
   * 最终以逐目标结果的形式返回，从而支持部分成功。单目标入口 {@link #create(CreateTaskRequest)} 保持不变。
   */
  public ProjectBatchTaskResult createBatchForProject(ProjectBatchTaskRequest request) {
    if (request == null || request.projectId() == null) {
      throw new ApiException("项目 ID 不能为空");
    }
    if (request.toolCode() == null || request.toolCode().isBlank()) {
      throw new ApiException("工具代码不能为空");
    }
    // 项目级入口先要求对项目有访问权与可执行授权，避免越权枚举他人项目的目标清单。
    var project = projectService.validateProjectExecution(request.projectId());

    List<com.bachelor.toolbox.project.ProjectTarget> projectLinks =
        projectService.targets(request.projectId());
    List<Long> requestedIds =
        request.allTargets()
            ? projectLinks.stream().map(com.bachelor.toolbox.project.ProjectTarget::getTargetId).toList()
            : request.targetIds().stream().filter(java.util.Objects::nonNull).distinct().toList();
    if (requestedIds.isEmpty()) {
      throw new ApiException("项目内没有可执行的授权目标");
    }
    if (!request.allTargets()) {
      var memberIds =
          projectLinks.stream()
              .map(com.bachelor.toolbox.project.ProjectTarget::getTargetId)
              .collect(java.util.stream.Collectors.toSet());
      for (Long targetId : requestedIds) {
        if (!memberIds.contains(targetId)) {
          throw new ApiException("目标 #" + targetId + " 不属于该评估项目");
        }
      }
    }

    Map<String, Object> parameters =
        request.parameters() == null ? Map.of() : request.parameters();
    List<ProjectBatchTaskResult.Item> items = new java.util.ArrayList<>();
    int succeeded = 0;
    for (Long targetId : requestedIds) {
      String targetName = resolveTargetName(targetId);
      // 单目标配额：与 AI 派发口径一致，未结束任务已达上限的目标跳过，其余目标继续。
      long active =
          repository.countByTargetIdAndStatusIn(
              targetId, List.of("BLOCKED", "PENDING", "RUNNING"));
      if (active + 1 > Math.max(1, maxActiveTasksPerTarget)) {
        items.add(
            ProjectBatchTaskResult.Item.failure(
                targetId,
                targetName,
                "目标任务配额不足（未结束 " + active + " 项，上限 " + Math.max(1, maxActiveTasksPerTarget) + " 项）"));
        continue;
      }
      try {
        SecurityTask created =
            create(
                new CreateTaskRequest(
                    request.projectId(), targetId, request.toolCode(), parameters),
                null,
                null,
                null,
                null,
                "BATCH_CREATE_TASK");
        items.add(ProjectBatchTaskResult.Item.success(targetId, targetName, created.getId()));
        succeeded++;
      } catch (ApiException ex) {
        items.add(ProjectBatchTaskResult.Item.failure(targetId, targetName, ex.getMessage()));
      } catch (Exception ex) {
        items.add(
            ProjectBatchTaskResult.Item.failure(
                targetId, targetName, "任务创建失败：" + ex.getMessage()));
      }
    }
    auditService.record(
        "BATCH_CREATE_TASK",
        "PROJECT",
        project.getId(),
        "tool=" + request.toolCode() + "; targets=" + requestedIds.size(),
        "SUCCESS");
    return new ProjectBatchTaskResult(
        project.getId(),
        request.toolCode(),
        requestedIds.size(),
        succeeded,
        requestedIds.size() - succeeded,
        List.copyOf(items));
  }

  private String resolveTargetName(Long targetId) {
    try {
      var target = targetService.get(targetId);
      String name = target == null ? null : target.getName();
      return name == null || name.isBlank() ? ("目标 #" + targetId) : name;
    } catch (RuntimeException ex) {
      return "目标 #" + targetId;
    }
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
    return retryTask(get(id), null);
  }

  @Transactional(rollbackFor = Exception.class)
  public SecurityTask retry(Long id, String idempotencyKey) {
    if (idempotencyKey == null) return retry(id);
    if (!idempotencyKey.matches("[A-Za-z0-9_-]{1,128}")) {
      throw new ApiException("Idempotency-Key 格式无效，长度应为 1–128 个字母、数字、下划线或连字符");
    }
    String operator = authorization.currentUsername();
    SecurityTask original = get(id);
    // Serialize even the first retry, before a row with this key exists.
    entityManager.lock(original, jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
    entityManager.refresh(original);
    var project = projectService.lockForAgentExecution(original.getProjectId());
    entityManager.refresh(project);
    projectService.get(original.getProjectId());
    var target = targetService.lockForAgentExecution(original.getTargetId());
    entityManager.refresh(target);
    String input = java.util.stream.Stream.of(id.toString(), operator, idempotencyKey)
        .map(value -> value.length() + ":" + value).collect(java.util.stream.Collectors.joining("\n"));
    String key;
    try {
      key = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
          .digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException ex) {
      throw new IllegalStateException("SHA-256 unavailable", ex);
    }
    return retryTask(original, key);
  }

  private SecurityTask retryTask(SecurityTask original, String retryKey) {
    // A failed workflow node is still bound to its reviewed graph and dependencies.
    // Cloning it as a standalone task would silently discard that execution boundary.
    if (original.getWorkflowDigest() != null || original.getWorkflowRunId() != null
        || original.getWorkflowNodeId() != null || Boolean.TRUE.equals(original.getWorkflowApprovalRequired())) {
      throw new ApiException("工作流任务请重新提交原方案并确认执行，不能以普通重试跳过工作流依赖或审批");
    }
    projectService.validateProjectTarget(original.getProjectId(), original.getTargetId());
    var target = targetService.getCurrentlyAuthorized(original.getTargetId(), original.getProjectId());
    var tool = registry.require(original.getToolCode());
    if (retryKey != null) {
      var existing = repository.findByRetryRequestKey(retryKey);
      if (existing.isPresent()) {
        SecurityTask saved = existing.get();
        if (!java.util.Objects.equals(saved.getSourceTaskId(), original.getId())
            || !java.util.Objects.equals(saved.getProjectId(), original.getProjectId())
            || !java.util.Objects.equals(saved.getTargetId(), original.getTargetId())
            || !java.util.Objects.equals(saved.getToolCode(), original.getToolCode())
            || !java.util.Objects.equals(saved.getRuleCode(), original.getRuleCode())
            || !java.util.Objects.equals(saved.getVulnerabilityCode(), original.getVulnerabilityCode())
            || !java.util.Objects.equals(saved.getRequestJson(), original.getRequestJson())) {
          throw new ApiException("同一重试请求的原任务或执行范围已变化，请重新发起重试");
        }
        return saved;
      }
    }
    if (!RETRYABLE_STATUSES.contains(original.getStatus())) {
      throw new ApiException("仅失败、被拒绝或已取消的任务可以重试");
    }

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
    retry.setRetryRequestKey(retryKey);
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
    // afterCommit still has the completed transaction's resources bound to the thread.
    // Persist a queue rejection in a fresh transaction so replay returns its real state.
    var transaction = new org.springframework.transaction.support.TransactionTemplate(transactionManager);
    transaction.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    transaction.executeWithoutResult(status ->
        repository.findById(taskId).ifPresent(task -> enqueue(task, false)));
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
      if (taskNotifications != null) taskNotifications.publish(task);
      publishTerminalAfterCommit(task.getId());
      if (propagateFailure) {
        throw new ApiException("本地任务队列已满，请稍后重试");
      }
    }
  }
}
