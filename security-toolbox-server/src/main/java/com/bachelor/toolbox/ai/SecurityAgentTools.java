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
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.agent.tool.Tool;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
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

  @Tool("执行已经过规划的低风险授权检测；再次校验项目、目标、端口、工具、有效期和资源配额")
  @Transactional
  public AiDispatchResponse executeAuthorizedPlan(
      AiAgentRequest request, AiPlanResponse proposedPlan) throws Exception {
    return executeAuthorizedPlanInTransaction(request, proposedPlan, null);
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
    return executeAuthorizedPlanInTransaction(request, proposedPlan, recoveryAnchor);
  }

  private AiDispatchResponse executeAuthorizedPlanInTransaction(
      AiAgentRequest request,
      AiPlanResponse proposedPlan,
      CrossTurnRecoveryService.RecoveryAnchor recoveryAnchor)
      throws Exception {
    projects.lockForAgentExecution(request.projectId());
    targets.lockForAgentExecution(request.targetId());
    String idempotencyKey = idempotencyKey(request);
    String requestDigest = requestDigest(request, proposedPlan);
    AiAgentDispatchRecord existing = dispatches.findById(idempotencyKey).orElse(null);
    if (existing != null) {
      if (!requestDigest.equals(existing.getRequestDigest())) {
        throw new ApiException("相同 Turn ID 不能用于不同的 AI 执行请求");
      }
      projects.validateProjectTarget(request.projectId(), request.targetId());
      targets.getCurrentlyAuthorized(request.targetId());
      AiPlanResponse normalized = prepareForHarness(request, proposedPlan);
      List<Long> taskIds = parseTaskIds(existing.getTaskIds());
      checkpoint(request, recoveryAnchor, taskIds);
      return new AiDispatchResponse(request.targetId(), normalized, taskIds.size(), taskIds);
    }
    AiAuthorizationGuard.GuardDecision decision = guard.evaluate(request, proposedPlan);
    if (!decision.mayExecute()) {
      throw new ApiException("AI 工具调用尚未获得执行确认");
    }
    AiPlanResponse executablePlan =
        prepareForHarness(request, decision.normalizedPlan());
    boolean workflowBound = request.workflowDigest() != null && !request.workflowDigest().isBlank();
    List<Long> taskIds = new java.util.ArrayList<>();
    java.util.Map<String, Long> taskByNode = new java.util.LinkedHashMap<>();
    List<AiPlanResponse.PlanStep> orderedSteps =
        executablePlan.steps().stream()
            .sorted(java.util.Comparator.comparingInt(AiPlanResponse.PlanStep::group))
            .toList();
    rejectUnsafeParallelGroups(orderedSteps);
    for (AiPlanResponse.PlanStep step : orderedSteps) {
      List<Long> dependencyTaskIds =
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
      if (dependencyTaskIds.size() != requiredSelectedDependencies) {
        throw new ApiException("工作流任务依赖顺序无效");
      }
      CreateTaskRequest createRequest =
          new CreateTaskRequest(
              request.projectId(), request.targetId(), step.toolCode(), step.parameters());
      SecurityTask task =
          workflowBound
              ? taskService.createWorkflowTask(
                  createRequest,
                  request.workflowDigest(),
                  step.workflowNodeId(),
                  request.nodeRunId() + "." + step.workflowNodeId(),
                  step.group(),
                  step.risk(),
                  step.requiresApproval(),
                  dependencyTaskIds)
              : taskService.create(createRequest);
      taskIds.add(task.getId());
      if (step.workflowNodeId() != null) taskByNode.put(step.workflowNodeId(), task.getId());
    }
    auditService.record(
        "AI_DISPATCH_TASKS",
        "PROJECT",
        request.projectId(),
        "targetId=" + request.targetId() + "; turnId=" + request.turnId() + "; taskIds=" + taskIds,
        "ACCEPTED");
    AiDispatchResponse response =
        new AiDispatchResponse(
            request.targetId(), executablePlan, taskIds.size(), List.copyOf(taskIds));
    AiAgentDispatchRecord record = new AiAgentDispatchRecord();
    record.setIdempotencyKey(idempotencyKey);
    record.setProjectId(request.projectId());
    record.setTargetId(request.targetId());
    record.setRequestDigest(requestDigest);
    record.setTaskIds(
        response.taskIds().stream().map(String::valueOf).collect(java.util.stream.Collectors.joining(",")));
    dispatches.save(record);
    checkpoint(request, recoveryAnchor, response.taskIds());
    return response;
  }

  private void checkpoint(
      AiAgentRequest request,
      CrossTurnRecoveryService.RecoveryAnchor recoveryAnchor,
      List<Long> taskIds) {
    if (recoveryAnchor == null) return;
    recoveryService.checkpoint(recoveryAnchor.bind(request, taskIds));
  }

  private void rejectUnsafeParallelGroups(List<AiPlanResponse.PlanStep> steps) {
    java.util.Map<Integer, List<AiPlanResponse.PlanStep>> byGroup =
        steps.stream().collect(java.util.stream.Collectors.groupingBy(AiPlanResponse.PlanStep::group));
    for (List<AiPlanResponse.PlanStep> group : byGroup.values()) {
      if (group.size() > 1
          && group.stream()
              .anyMatch(
                  step -> step.requiresApproval() || !"SAFE".equalsIgnoreCase(step.risk()))) {
        throw new ApiException("同一拓扑层仅允许独立低风险节点并行执行");
      }
    }
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
