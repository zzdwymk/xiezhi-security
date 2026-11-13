package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectApproval;
import com.bachelor.toolbox.project.ProjectApprovalRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Executes only the exact server-saved plan; this is deliberately not a model tool. */
@Service
public class AiPlanApprovalService {
  private final ProjectApprovalRepository approvals;
  private final ProjectAuthorizationService authorization;
  private final SecurityAgentTools tools;
  private final ObjectMapper mapper;
  private final com.bachelor.toolbox.project.AssessmentProjectService projects;
  private final com.bachelor.toolbox.target.TargetService targets;
  private final PortRangeParser portRangeParser;
  @jakarta.persistence.PersistenceContext
  private jakarta.persistence.EntityManager entityManager;

  public AiPlanApprovalService(ProjectApprovalRepository approvals,
      ProjectAuthorizationService authorization, SecurityAgentTools tools, ObjectMapper mapper,
      com.bachelor.toolbox.project.AssessmentProjectService projects,
      com.bachelor.toolbox.target.TargetService targets,
      PortRangeParser portRangeParser) {
    this.approvals = approvals;
    this.authorization = authorization;
    this.tools = tools;
    this.mapper = mapper;
    this.projects = projects;
    this.targets = targets;
    this.portRangeParser = portRangeParser;
  }

  public static String targetBinding(com.bachelor.toolbox.target.AuthorizedTarget target) {
    return java.util.stream.Stream.of(target.getTargetValue(), target.getTargetType(), target.getAllowedPorts(),
        target.getAuthorizationNote(), target.getAuthorizationValidFrom(), target.getAuthorizationExpiresAt(), target.isEnabled())
        .map(value -> java.util.Objects.toString(value, ""))
        .map(value -> value.length() + ":" + value).collect(java.util.stream.Collectors.joining("\n"));
  }

  public static String projectBinding(com.bachelor.toolbox.project.AssessmentProject project) {
    return java.util.stream.Stream.of(project.getAuthorizationStatement(), project.getAuthorizationValidFrom(),
        project.getAuthorizationExpiresAt(), project.getStatus(), project.getOwner())
        .map(value -> java.util.Objects.toString(value, ""))
        .map(value -> value.length() + ":" + value).collect(java.util.stream.Collectors.joining("\n"));
  }

  @Transactional(rollbackFor = Exception.class)
  public AiDispatchResponse resume(Long projectId, Long approvalId) throws Exception {
    authorization.requireAdmin();
    var actor = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
    if (actor != null && "ai-agent".equals(actor.getName())) throw new ApiException("AI 不能确认执行自己的方案");
    authorization.requireAccess(projectId);
    ProjectApproval approval = approvals.findForUpdate(approvalId, projectId)
        .orElseThrow(() -> new ApiException("项目审批记录不存在"));
    if (!"AI_PLAN_EXECUTION".equals(approval.getAction()) || !"ai-agent".equals(approval.getRequestedBy())
        || !"APPROVED".equals(approval.getStatus())) {
      throw new ApiException("本方案尚未获得管理员批准，未派发任务");
    }
    if (approval.getAiDispatchJson() != null) {
      return mapper.readValue(approval.getAiDispatchJson(), AiDispatchResponse.class);
    }
    if (approval.getAiRequestJson() == null || approval.getAiPlanJson() == null) {
      throw new ApiException("旧审批单未保存完整原计划，不能恢复执行，请重新申请");
    }
    AiAgentRequest stored = mapper.readValue(approval.getAiRequestJson(), AiAgentRequest.class);
    AiPlanResponse plan = mapper.readValue(approval.getAiPlanJson(), AiPlanResponse.class);
    if (!projectId.equals(stored.projectId())) throw new ApiException("审批单与原计划项目不一致");
    var project = projects.lockForAgentExecution(projectId);
    // requireAccess may already have loaded the project before the locks were acquired.
    // Refresh managed state under those locks so a concurrent authorization edit is visible.
    entityManager.refresh(project);
    if (!stored.isProjectScoped()) {
      var target = targets.lockForAgentExecution(stored.targetId());
      entityManager.refresh(target);
      // Approval does not extend an authorization window or authorize a changed engagement.
      // Check live authorization first so expiry remains a precise, actionable API error.
      projects.validateProjectTarget(projectId, stored.targetId());
      targets.getCurrentlyAuthorized(stored.targetId());
      if (approval.getAiTargetBinding() == null || !approval.getAiTargetBinding().equals(targetBinding(target))) {
        throw new ApiException("目标地址或授权范围已变化，原审批不能继续执行，请重新申请");
      }
    } else {
      List<Long> targetIdsToLock;
      if (stored.scopeMode() == AiAgentRequest.ScopeMode.PROJECT_SUBSET) {
        targetIdsToLock = stored.targetIds() == null ? List.of() : stored.targetIds().stream().distinct().toList();
      } else {
        targetIdsToLock = projects.targets(projectId).stream().map(com.bachelor.toolbox.project.ProjectTarget::getTargetId).distinct().toList();
      }
      for (Long tid : targetIdsToLock.stream().sorted().toList()) {
        var target = targets.lockForAgentExecution(tid);
        entityManager.refresh(target);
        projects.validateProjectTarget(projectId, tid);
        targets.getCurrentlyAuthorized(tid);
      }
    }
    if (approval.getAiProjectBinding() == null || !approval.getAiProjectBinding().equals(projectBinding(project))) {
      throw new ApiException("项目授权范围已变化或原审批未保存授权快照，请重新申请");
    }
    // Reuse the original turn identity: even independently duplicated approval tickets
    // cannot create the original turn's task batch twice.
    AiAgentRequest execution = stored.withResolvedExecution(true);
    CrossTurnRecoveryService.RecoveryAnchor recovery = approval.getAiRecoveryJson() == null ? null
        : mapper.readValue(approval.getAiRecoveryJson(), CrossTurnRecoveryService.RecoveryAnchor.class);
    // Round 9 修复：审批与重新执行是两个独立事务，期间目标授权范围/端口/工具可用性可能变化。
    // SecurityAgentTools 内部会重新调用 guard.evaluateApproved 重新校验，但这里在“拿锁之后、真正派发之前”
    // 再做一次快照级重校验，确保管理员看到并批准的正是即将执行的东西，堵住审批 ↔ 执行之间的 TOCTOU 窗口。
    revalidateApprovedPlan(projectId, approval, stored, plan);
    AiDispatchResponse response = tools.executeApprovedPlan(execution, plan, recovery);
    approval.setAiDispatchJson(mapper.writeValueAsString(response));
    approvals.save(approval);
    return response;
  }

  /**
   * 审批快照重校验（TOCTOU 纵深防御）。
   *
   * <p>在项目/目标行锁已持有、真正派发任务之前执行。逐项确认：
   * <ol>
   *   <li>每个步骤的工具仍属可执行白名单、参数结构与白名单键一致（防止工具清单在审批后漂移）；</li>
   *   <li>形如 {@code ports} 的端口参数，其每个端口仍落在目标当前授权端口范围内（防止审批后收窄端口）；
   *   <li>参数中的 URL/host 仍能通过授权校验（防止审批后目标范围变化导致 SSRF 面）。
   * </ol>
   * 任一不符即拒绝——不自动放行、不静默降级。
   */
  void revalidateApprovedPlan(
      Long projectId, ProjectApproval approval, AiAgentRequest stored, AiPlanResponse plan) {
    if (plan == null || plan.steps() == null || plan.steps().isEmpty()) {
      return;
    }
    java.util.Set<Long> targetIds;
    if (!stored.isProjectScoped()) {
      targetIds = java.util.Set.of(stored.targetId());
    } else if (stored.scopeMode() == AiAgentRequest.ScopeMode.PROJECT_SUBSET) {
      targetIds = stored.targetIds() == null ? java.util.Set.of()
          : stored.targetIds().stream().collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
    } else {
      targetIds = projects.targets(projectId).stream()
          .map(com.bachelor.toolbox.project.ProjectTarget::getTargetId)
          .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
    }
    for (AiPlanResponse.PlanStep step : plan.steps()) {
      String toolCode = step.toolCode();
      // ① 工具仍在可执行白名单内（工具清单可能因版本/配置在审批后变更）
      if (!com.bachelor.toolbox.tool.ToolParameterPolicy.isKnownTool(toolCode)
          || com.bachelor.toolbox.tool.ToolParameterPolicy.READ_ONLY_TOOLS.contains(toolCode)) {
        throw new ApiException("审批方案中的工具已不可用或不在可执行白名单内: " + toolCode);
      }
      Map<String, Object> params = step.parameters() == null ? Map.of() : step.parameters();
      // ①' 参数键结构仍符合工具白名单（防止审批后工具参数规格漂移）
      com.bachelor.toolbox.tool.ToolParameterPolicy.validate(toolCode, params);

      // ② 端口类参数必须仍⊆ 当前授权端口（防止审批后收窄）
      Object rawPorts = params.get("ports");
      if (rawPorts != null) {
        String text = String.valueOf(rawPorts).trim();
        if (!text.isBlank()) {
          java.util.Set<Integer> requested;
          try {
            requested = portRangeParser.parse(text);
          } catch (RuntimeException ex) {
            throw new ApiException("审批方案端口参数无法解析，拒绝执行: " + text);
          }
          for (Long tid : targetIds) {
            AuthorizedTarget tgt = targets.getCurrentlyAuthorized(tid);
            java.util.Set<Integer> allowed = portRangeParser.parse(tgt.getAllowedPorts());
            if (!allowed.containsAll(requested)) {
              java.util.Set<Integer> escaped = new java.util.LinkedHashSet<>(requested);
              escaped.removeAll(allowed);
              throw new ApiException("审批后目标授权端口已变化，方案端口越权: " + escaped + "（目标 #" + tid + "）");
            }
          }
        }
      }
    }
  }
}
