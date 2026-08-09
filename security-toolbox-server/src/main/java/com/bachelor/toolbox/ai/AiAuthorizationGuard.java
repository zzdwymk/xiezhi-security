package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Mandatory authorization boundary between Planner and Executor.
 *
 * <p>The reviewer never invokes tools and the executor only receives plans returned by this guard.
 * Existing {@link com.bachelor.toolbox.task.TaskService} validation remains the final enforcement
 * point, so a race such as authorization expiry between planning and execution is rejected again
 * when each task is created.
 */
@Service
public class AiAuthorizationGuard {
  private static final List<String> ACTIVE_STATUSES = List.of("BLOCKED", "PENDING", "RUNNING");

  private final AssessmentProjectService projects;
  private final TargetService targets;
  private final AiTaskDispatchService dispatcher;
  private final SecurityTaskRepository tasks;
  private final int maxProjectTasks;
  private final int maxTargetTasks;

  public AiAuthorizationGuard(
      AssessmentProjectService projects,
      TargetService targets,
      AiTaskDispatchService dispatcher,
      SecurityTaskRepository tasks,
      @Value("${toolbox.ai.agent.max-active-tasks-per-project:20}") int maxProjectTasks,
      @Value("${toolbox.ai.agent.max-active-tasks-per-target:4}") int maxTargetTasks) {
    this.projects = projects;
    this.targets = targets;
    this.dispatcher = dispatcher;
    this.tasks = tasks;
    this.maxProjectTasks = Math.max(1, maxProjectTasks);
    this.maxTargetTasks = Math.max(1, maxTargetTasks);
  }

  public GuardDecision evaluate(AiAgentRequest request, AiPlanResponse proposedPlan) {
    if (request.projectId() == null || request.targetId() == null) {
      throw new ApiException("AI 工具调用必须绑定评估项目和授权目标");
    }

    // A plan preview is not an execution boundary.  It still has to be bound to a real
    // project/target pair, but an expired or paused engagement may be discussed and its
    // historical plan may be reviewed.  The strict status/time-window checks below are
    // intentionally deferred until the caller explicitly requests execution.
    projects.validateProjectTargetMembership(request.projectId(), request.targetId());

    AiPlanRequest scoped =
        new AiPlanRequest(
            request.projectId(),
            request.targetId(),
            request.prompt(),
            request.contextRefs(),
            request.refs(),
            request.mode());
    // Tool allow-list, protocol, parameter and port-subset validation.
    AiPlanResponse normalized = dispatcher.prepare(scoped, proposedPlan);

    long activeProjectTasks =
        tasks.countByProjectIdAndStatusIn(request.projectId(), ACTIVE_STATUSES);
    long activeTargetTasks = tasks.countByTargetIdAndStatusIn(request.targetId(), ACTIVE_STATUSES);
    int requestedTasks = normalized.steps() == null ? 0 : normalized.steps().size();

    if (requestedTasks == 0) {
      return new GuardDecision(
          "ALLOWED",
          "NOT_REQUIRED",
          "计划不包含工具调用",
          normalized,
          activeProjectTasks,
          activeTargetTasks);
    }
    if (!request.executionRequested()) {
      return new GuardDecision(
          "AWAITING_APPROVAL",
          "REQUIRED",
          "计划已按项目登记范围完成规范化；确认执行时将重新校验项目状态、授权有效期和资源配额",
          normalized,
          activeProjectTasks,
          activeTargetTasks);
    }

    // Actual tool execution/task creation is the strict authorization boundary.
    projects.validateProjectTarget(request.projectId(), request.targetId());
    targets.getCurrentlyAuthorized(request.targetId());
    if (activeProjectTasks + requestedTasks > maxProjectTasks) {
      throw new ApiException("项目 AI 任务配额不足，请等待现有任务完成");
    }
    if (activeTargetTasks + requestedTasks > maxTargetTasks) {
      throw new ApiException("目标 AI 任务配额不足，请等待现有任务完成");
    }
    return new GuardDecision(
        "ALLOWED",
        "CONFIRMED_BY_REQUEST",
        "项目、目标、端口、工具和资源配额均已通过校验",
        normalized,
        activeProjectTasks,
        activeTargetTasks);
  }

  public record GuardDecision(
      String status,
      String approvalStatus,
      String reason,
      AiPlanResponse normalizedPlan,
      long activeProjectTasks,
      long activeTargetTasks) {
    public boolean mayExecute() {
      return "ALLOWED".equals(status) && "CONFIRMED_BY_REQUEST".equals(approvalStatus);
    }
  }
}
