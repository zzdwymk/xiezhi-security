package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import com.bachelor.toolbox.task.WorkflowTaskSchedule;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.agent.tool.Tool;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * LangChain4j tool contract for the agent architecture.
 *
 * <p>These tools expose no shell or arbitrary-code surface. Execution re-enters the centralized
 * authorization guard and then uses the existing task dispatcher/TaskService path.
 */
@Component
public class SecurityAgentTools {
  private static final DateTimeFormatter DISPLAY_TIME =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.of("Asia/Shanghai"));
  private final AssessmentProjectService projects;
  private final TargetService targets;
  private final AiAuthorizationGuard guard;
  private final AiTaskDispatchService dispatcher;
  private final AiAgentDispatchRepository dispatches;
  private final ObjectMapper objectMapper;
  private final TaskService taskService;
  private final AuditService auditService;
  private final CrossTurnRecoveryService recoveryService;
  @Autowired(required = false)
  private com.bachelor.toolbox.target.PortRangeParser portRangeParser;

  public SecurityAgentTools(
      AssessmentProjectService projects,
      TargetService targets,
      AiAuthorizationGuard guard,
      AiTaskDispatchService dispatcher,
      AiAgentDispatchRepository dispatches,
      ObjectMapper objectMapper,
      TaskService taskService,
      AuditService auditService,
      CrossTurnRecoveryService recoveryService) {
    this.projects = projects;
    this.targets = targets;
    this.guard = guard;
    this.dispatcher = dispatcher;
    this.dispatches = dispatches;
    this.objectMapper = objectMapper;
    this.taskService = taskService;
    this.auditService = auditService;
    this.recoveryService = recoveryService;
  }

  /**
   * Read project and target metadata for conversation planning. This deliberately validates only
   * the project/target relationship, not the current authorization window: users must be able to
   * ask what an expired project contains and review its historical evidence. Any action plan that
   * reaches execution is re-checked by {@link AiAuthorizationGuard}.
   */
  @Tool("读取当前评估项目、目标和授权记录；允许在授权过期后用于说明和历史结果问答，不执行任何工具")
  public String inspectProjectContext(Long projectId, Long targetId) {
    projects.validateProjectTargetMembership(projectId, targetId);
    AssessmentProject project = projects.get(projectId);
    AuthorizedTarget target = targets.get(targetId);
    return formatScope(project, target);
  }

  @Tool("读取当前评估项目和目标的授权上下文；只返回规划所需的范围信息")
  public String inspectAuthorizedScope(Long projectId, Long targetId) {
    projects.validateProjectTarget(projectId, targetId);
    AssessmentProject project = projects.get(projectId);
    AuthorizedTarget target = targets.getCurrentlyAuthorized(targetId);
    return formatScope(project, target) + "；当前执行授权=有效";
  }

  private String formatScope(AssessmentProject project, AuthorizedTarget target) {
    return "项目="
        + project.getName()
        + "；项目状态="
        + project.getStatus()
        + "；项目授权有效期="
        + display(project.getAuthorizationValidFrom())
        + " 至 "
        + display(project.getAuthorizationExpiresAt())
        + "（"
        + authorizationState(project, target)
        + "）"
        + "；授权声明="
        + safe(project.getAuthorizationStatement())
        + "；目标="
        + target.getName()
        + "("
        + target.getTargetValue()
        + ")"
        + "；目标类型="
        + target.getTargetType()
        + "；允许端口="
        + target.getAllowedPorts()
        + "；目标启用="
        + target.isEnabled()
        + "；目标授权有效期="
        + display(target.getAuthorizationValidFrom())
        + " 至 "
        + display(target.getAuthorizationExpiresAt());
  }

  private String authorizationState(AssessmentProject project, AuthorizedTarget target) {
    Instant now = Instant.now();
    if (!"ACTIVE".equalsIgnoreCase(project.getStatus())) return "项目未激活";
    if (project.getAuthorizationValidFrom() != null
        && now.isBefore(project.getAuthorizationValidFrom())) return "项目授权尚未生效";
    if (project.getAuthorizationExpiresAt() != null
        && !now.isBefore(project.getAuthorizationExpiresAt())) return "项目授权已过期";
    if (!target.isEnabled()) return "目标已停用";
    if (target.getAuthorizationValidFrom() != null
        && now.isBefore(target.getAuthorizationValidFrom())) return "目标授权尚未生效";
    if (target.getAuthorizationExpiresAt() != null
        && !now.isBefore(target.getAuthorizationExpiresAt())) return "目标授权已过期";
    return "可执行校验待确认";
  }

  private String display(Instant value) {
    return value == null ? "未设置" : DISPLAY_TIME.format(value);
  }

  private String safe(String value) {
    return value == null ? "" : value.replaceAll("[\\r\\n]", " ").strip();
  }

  // Internal compatibility entry point, deliberately not exposed as a model tool.
  // New AI requests must persist a plan and use the administrator confirmation path.
  @Transactional
  public AiDispatchResponse executeAuthorizedPlan(
      AiAgentRequest request, AiPlanResponse proposedPlan) throws Exception {
    return executeAuthorizedPlanInTransaction(request, proposedPlan, null, false);
  }

  /**
   * Creates the task batch, dispatch idempotency record and continuation outbox in one database
   * transaction. Runtime checkpoint delivery remains the continuation worker's responsibility
   * after this transaction commits.
   */
  @Transactional
  public AiDispatchResponse executeAuthorizedPlan(
      AiAgentRequest request,
      AiPlanResponse proposedPlan,
      CrossTurnRecoveryService.RecoveryAnchor recoveryAnchor)
      throws Exception {
    if (recoveryAnchor == null) throw new ApiException("Agent 续接锚点不能为空");
    return executeAuthorizedPlanInTransaction(request, proposedPlan, recoveryAnchor, false);
  }

  /** Internal resume path; only the persisted approval service may call this, never a model tool. */
  @Transactional
  AiDispatchResponse executeApprovedPlan(AiAgentRequest request, AiPlanResponse plan,
      CrossTurnRecoveryService.RecoveryAnchor recoveryAnchor) throws Exception {
    return executeAuthorizedPlanInTransaction(request, plan, recoveryAnchor, true);
  }

  private AiDispatchResponse executeAuthorizedPlanInTransaction(
      AiAgentRequest request,
      AiPlanResponse proposedPlan,
      CrossTurnRecoveryService.RecoveryAnchor recoveryAnchor, boolean approvedPlan)
      throws Exception {
    projects.lockForAgentExecution(request.projectId());

    List<Long> targetIdsToExecute;
    if (request.isProjectScoped()) {
      if (request.scopeMode() == AiAgentRequest.ScopeMode.PROJECT_SUBSET) {
        targetIdsToExecute = request.targetIds() == null ? List.of() : request.targetIds().stream().distinct().toList();
        var links = projects.targets(request.projectId()).stream()
            .map(com.bachelor.toolbox.project.ProjectTarget::getTargetId).collect(java.util.stream.Collectors.toSet());
        for (Long tid : targetIdsToExecute) {
          if (!links.contains(tid)) {
            throw new ApiException("目标 #" + tid + " 不属于该评估项目");
          }
        }
      } else { // PROJECT_ALL
        targetIdsToExecute = projects.targets(request.projectId()).stream()
            .map(com.bachelor.toolbox.project.ProjectTarget::getTargetId).distinct().toList();
      }
      if (targetIdsToExecute.isEmpty()) {
        throw new ApiException("项目内没有可执行的授权目标");
      }
    } else {
      targetIdsToExecute = List.of(request.targetId());
    }

    // 避免死锁：按目标 ID 升序加锁
    for (Long tid : targetIdsToExecute.stream().sorted().toList()) {
      targets.lockForAgentExecution(tid);
    }

    String idempotencyKey = idempotencyKey(request);
    String requestDigest = requestDigest(request, proposedPlan);
    AiAgentDispatchRecord existing = dispatches.findById(idempotencyKey).orElse(null);
    Long primaryTargetId = request.targetId() != null ? request.targetId() : targetIdsToExecute.get(0);
    if (existing != null) {
      if (!requestDigest.equals(existing.getRequestDigest())) {
        throw new ApiException("相同 Turn ID 不能用于不同的 AI 执行请求");
      }
      for (Long tid : targetIdsToExecute) {
        projects.validateProjectTarget(request.projectId(), tid);
        targets.getCurrentlyAuthorized(tid);
      }
      AiPlanResponse normalized = prepareForHarness(request, proposedPlan);
      List<Long> taskIds = parseTaskIds(existing.getTaskIds());
      checkpoint(request, recoveryAnchor, taskIds);
      return new AiDispatchResponse(primaryTargetId, inExecutionOrder(normalized), taskIds.size(), taskIds);
    }
    AiAuthorizationGuard.GuardDecision decision = approvedPlan ? guard.evaluateApproved(request, proposedPlan) : guard.evaluate(request, proposedPlan);
    if (!decision.mayExecute()) {
      throw new ApiException("AI 工具调用尚未获得执行确认");
    }
    AiPlanResponse executablePlan =
        prepareForHarness(request, decision.normalizedPlan());
    if (approvedPlan && !executablePlan.steps().equals(proposedPlan.steps())) {
      throw new ApiException("当前校验结果与已批准原计划不一致，请重新申请审批");
    }
    boolean workflowBound = request.workflowDigest() != null && !request.workflowDigest().isBlank();
    List<Long> taskIds = new java.util.ArrayList<>();
    List<AiPlanResponse.PlanStep> orderedSteps =
        executablePlan.steps().stream()
            .sorted(java.util.Comparator.comparingInt(AiPlanResponse.PlanStep::group)
                .thenComparing(SecurityAgentTools::requiresSerialExecution))
            .toList();
    if (!workflowBound) rejectUnsafeParallelGroups(orderedSteps);

    for (Long currentTargetId : targetIdsToExecute) {
      try {
        projects.validateProjectTarget(request.projectId(), currentTargetId);
        targets.getCurrentlyAuthorized(currentTargetId);
      } catch (ApiException e) {
        if (!request.isProjectScoped()) throw e;
        continue;
      }
      java.util.Map<String, Long> taskByNode = new java.util.LinkedHashMap<>();
      WorkflowTaskSchedule schedule = new WorkflowTaskSchedule();
      Long portProbeTaskId = null;
      for (AiPlanResponse.PlanStep step : orderedSteps) {
        List<Long> graphDependencyTaskIds =
            step.dependsOnNodeIds().stream()
                .filter(taskByNode::containsKey)
                .map(taskByNode::get)
                .toList();
        long requiredSelectedDependencies =
            step.dependsOnNodeIds().stream()
                .filter(
                    nodeId ->
                        orderedSteps.stream()
                            .anyMatch(candidate -> nodeId.equals(candidate.workflowNodeId())))
                .count();
        if (graphDependencyTaskIds.size() != requiredSelectedDependencies) {
          throw new ApiException("工作流任务依赖顺序无效");
        }
        List<Long> planDependencies = new java.util.ArrayList<>(graphDependencyTaskIds);
        if (!workflowBound
            && "nmap_service_scan".equals(step.toolCode())
            && consumesOpenPorts(step)
            && portProbeTaskId != null
            && !planDependencies.contains(portProbeTaskId)) {
          planDependencies.add(portProbeTaskId);
        }
        Map<String, Object> stepParameters = step.parameters();
        if (request.isProjectScoped() && portRangeParser != null && Set.of("tcp_ports", "nmap_service_scan", "fscan_scan").contains(step.toolCode())) {
          String reqPorts = java.util.Objects.toString(step.parameters() != null ? step.parameters().get("ports") : null, "").trim();
          if (!reqPorts.isBlank()) {
            try {
              var tgt = targets.get(currentTargetId);
              var allowed = portRangeParser.parse(tgt.getAllowedPorts());
              var requested = portRangeParser.parse(reqPorts);
              var intersection = new java.util.LinkedHashSet<>(requested);
              intersection.retainAll(allowed);
              if (intersection.isEmpty()) {
                continue;
              }
              stepParameters = new java.util.LinkedHashMap<>(step.parameters());
              stepParameters.put("ports", intersection.stream().map(String::valueOf).collect(java.util.stream.Collectors.joining(",")));
            } catch (Exception ignored) {
            }
          }
        }
        WorkflowTaskSchedule.Scheduled scheduled = schedule.schedule(
            step.group(), step.risk(), step.requiresApproval(), planDependencies,
            step.toolCode());
        CreateTaskRequest createRequest =
            new CreateTaskRequest(
                request.projectId(), currentTargetId, step.toolCode(), stepParameters);
        String nodeRunId = workflowBound
            ? (request.isProjectScoped()
                ? (request.nodeRunId() + "." + currentTargetId + "." + step.workflowNodeId())
                : (request.nodeRunId() + "." + step.workflowNodeId()))
            : null;
        SecurityTask task =
            workflowBound
                ? taskService.createWorkflowTask(
                    createRequest,
                    request.workflowDigest(),
                    step.workflowNodeId(),
                    nodeRunId,
                    scheduled.group(),
                    step.risk(),
                    step.requiresApproval(),
                    scheduled.dependencyTaskIds())
                : taskService.createDependent(createRequest, planDependencies, scheduled.group());
        if (workflowBound) {
          task.setSuccessDependencyTaskIds(objectMapper.writeValueAsString(graphDependencyTaskIds));
        } else if (!planDependencies.isEmpty()) {
          task.setSuccessDependencyTaskIds(objectMapper.writeValueAsString(planDependencies));
        }
        taskIds.add(task.getId());
        schedule.taskCreated(scheduled, task.getId());
        if ("tcp_ports".equals(step.toolCode())) portProbeTaskId = task.getId();
        if (step.workflowNodeId() != null) taskByNode.put(step.workflowNodeId(), task.getId());
      }
    }
    if (taskIds.isEmpty() && !orderedSteps.isEmpty()) {
      throw new ApiException("项目范围内所有授权目标均无法通过执行校验或已失效");
    }
    auditService.record(
        "AI_DISPATCH_TASKS",
        "PROJECT",
        request.projectId(),
        "scope=" + (request.isProjectScoped() ? request.scopeMode() : "SINGLE")
            + "; targetIds=" + targetIdsToExecute
            + "; turnId=" + request.turnId() + "; taskIds=" + taskIds,
        "ACCEPTED");
    AiDispatchResponse response =
        new AiDispatchResponse(
            primaryTargetId, inExecutionOrder(executablePlan), taskIds.size(), List.copyOf(taskIds));
    AiAgentDispatchRecord record = new AiAgentDispatchRecord();
    record.setIdempotencyKey(idempotencyKey);
    record.setProjectId(request.projectId());
    record.setTargetId(primaryTargetId);
    record.setRequestDigest(requestDigest);
    record.setTaskIds(
        response.taskIds().stream().map(String::valueOf).collect(java.util.stream.Collectors.joining(",")));
    dispatches.save(record);
    checkpoint(request, recoveryAnchor, response.taskIds());
    return response;
  }

  private AiPlanResponse inExecutionOrder(AiPlanResponse plan) {
    // taskIds are created in scheduling order; return matching plan rows so the UI
    // cannot attach one task's progress to a different approved action.
    return new AiPlanResponse(plan.provider(), plan.model(), plan.summary(), plan.requiresConfirmation(),
        plan.steps().stream().sorted(java.util.Comparator.comparingInt(AiPlanResponse.PlanStep::group)
            .thenComparing(SecurityAgentTools::requiresSerialExecution)).toList());
  }

  private void checkpoint(
      AiAgentRequest request,
      CrossTurnRecoveryService.RecoveryAnchor recoveryAnchor,
      List<Long> taskIds) {
    if (recoveryAnchor == null) return;
    recoveryService.checkpoint(recoveryAnchor.bind(request, taskIds));
  }

  /** 该步骤是否声明了"复用前序端口探测结果"。 */
  private static boolean consumesOpenPorts(AiPlanResponse.PlanStep step) {
    Object raw = step.parameters() == null ? null : step.parameters().get("consumeOpenPorts");
    return Boolean.TRUE.equals(raw) || "true".equalsIgnoreCase(String.valueOf(raw));
  }

  private void rejectUnsafeParallelGroups(List<AiPlanResponse.PlanStep> steps) {    java.util.Map<Integer, List<AiPlanResponse.PlanStep>> byGroup =
        steps.stream().collect(java.util.stream.Collectors.groupingBy(AiPlanResponse.PlanStep::group));
    for (List<AiPlanResponse.PlanStep> group : byGroup.values()) {
      if (group.size() <= 1) continue;
      // Parallel siblings are allowed only when every one of them is a light, read-only probe.
      // A port sweep, crawler, or request-mutating tool in the same group would contend for the
      // target and make results non-reproducible, so it must be planned in its own group.
      boolean allLight =
          group.stream().allMatch(step -> !SecurityAgentTools.isBarrierTool(step));
      if (!allLight) {
        throw new ApiException("同一拓扑层仅允许互不干扰的轻量只读节点并行执行");
      }
    }
  }

  private static boolean isBarrierTool(AiPlanResponse.PlanStep step) {
    return WorkflowTaskSchedule.requiresSerialExecution(
        step.risk(), step.requiresApproval(), step.toolCode());
  }

  private static boolean requiresSerialExecution(AiPlanResponse.PlanStep step) {
    return WorkflowTaskSchedule.requiresSerialExecution(
        step.risk(), step.requiresApproval(), step.toolCode());
  }

  private AiPlanResponse prepareForHarness(AiAgentRequest request, AiPlanResponse plan) {
    if (request.workflowDigest() != null && !request.workflowDigest().isBlank()) {
      return dispatcher.prepareWorkflow(request, plan);
    }
    return dispatcher.prepare(
        new AiPlanRequest(
            request.projectId(),
            request.targetId(),
            request.prompt(),
            request.contextRefs(),
            request.refs(),
            request.mode()),
        plan);
  }

  private String idempotencyKey(AiAgentRequest request) throws Exception {
    String turn = request.turnId();
    if (turn == null || turn.isBlank()) throw new ApiException("AI 执行请求缺少 Turn ID");
    return sha256(
        request.projectId()
            + "\n"
            + turn
            + "\n"
            + java.util.Objects.toString(request.workflowDigest(), ""));
  }

  private String requestDigest(AiAgentRequest request, AiPlanResponse plan) throws Exception {
    java.util.Map<String, Object> digestInput = new java.util.LinkedHashMap<>();
    digestInput.put("projectId", request.projectId());
    digestInput.put("targetId", request.targetId());
    digestInput.put("scopeMode", request.scopeMode() == null ? "SINGLE" : request.scopeMode().name());
    digestInput.put("targetIds", request.targetIds());
    digestInput.put("execute", request.executionRequested());
    digestInput.put("workflowId", request.workflowId());
    digestInput.put("workflowRevision", request.workflowRevision());
    digestInput.put("workflowDigest", request.workflowDigest());
    digestInput.put("outerNodeId", request.outerNodeId());
    digestInput.put("nodeRunId", request.nodeRunId());
    digestInput.put("plan", plan);
    return sha256(objectMapper.writeValueAsString(digestInput));
  }

  private String sha256(String value) throws Exception {
    return java.util.HexFormat.of()
        .formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
  }

  private List<Long> parseTaskIds(String value) {
    if (value == null || value.isBlank()) return List.of();
    return java.util.Arrays.stream(value.split(","))
        .map(String::strip)
        .filter(item -> !item.isBlank())
        .map(Long::valueOf)
        .toList();
  }
}
