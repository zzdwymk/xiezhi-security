package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import dev.langchain4j.agent.tool.Tool;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import org.springframework.stereotype.Component;

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

  public SecurityAgentTools(
      AssessmentProjectService projects,
      TargetService targets,
      AiAuthorizationGuard guard,
      AiTaskDispatchService dispatcher) {
    this.projects = projects;
    this.targets = targets;
    this.guard = guard;
    this.dispatcher = dispatcher;
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
  public AiDispatchResponse executeAuthorizedPlan(
      AiAgentRequest request, AiPlanResponse proposedPlan) throws Exception {
    AiAuthorizationGuard.GuardDecision decision = guard.evaluate(request, proposedPlan);
    if (!decision.mayExecute()) {
      throw new ApiException("AI 工具调用尚未获得执行确认");
    }
    AiPlanRequest scoped =
        new AiPlanRequest(
            request.projectId(),
            request.targetId(),
            request.prompt(),
            request.contextRefs(),
            request.refs(),
            request.mode());
    return dispatcher.dispatchPlanned(scoped, decision.normalizedPlan());
  }
}
