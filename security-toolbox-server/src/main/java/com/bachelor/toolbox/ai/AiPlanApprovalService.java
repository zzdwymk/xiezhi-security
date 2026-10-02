package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectApproval;
import com.bachelor.toolbox.project.ProjectApprovalRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.fasterxml.jackson.databind.ObjectMapper;
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
  @jakarta.persistence.PersistenceContext
  private jakarta.persistence.EntityManager entityManager;

  public AiPlanApprovalService(ProjectApprovalRepository approvals,
      ProjectAuthorizationService authorization, SecurityAgentTools tools, ObjectMapper mapper,
      com.bachelor.toolbox.project.AssessmentProjectService projects,
      com.bachelor.toolbox.target.TargetService targets) {
    this.approvals = approvals;
    this.authorization = authorization;
    this.tools = tools;
    this.mapper = mapper;
    this.projects = projects;
    this.targets = targets;
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
    authorization.requireAccess(projectId);
    ProjectApproval approval = approvals.findForUpdate(approvalId, projectId)
        .orElseThrow(() -> new ApiException("项目审批记录不存在"));
    if (!"AI_PLAN_EXECUTION".equals(approval.getAction()) || !"APPROVED".equals(approval.getStatus())) {
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
    var target = targets.lockForAgentExecution(stored.targetId());
    // requireAccess may already have loaded the project before the locks were acquired.
    // Refresh managed state under those locks so a concurrent authorization edit is visible.
    entityManager.refresh(project);
    entityManager.refresh(target);
    // Approval does not extend an authorization window or authorize a changed engagement.
    // Check live authorization first so expiry remains a precise, actionable API error.
    projects.validateProjectTarget(projectId, stored.targetId());
    targets.getCurrentlyAuthorized(stored.targetId());
    if (approval.getAiProjectBinding() == null || !approval.getAiProjectBinding().equals(projectBinding(project))) {
      throw new ApiException("项目授权范围已变化或原审批未保存授权快照，请重新申请");
    }
    if (approval.getAiTargetBinding() == null || !approval.getAiTargetBinding().equals(targetBinding(target))) {
      throw new ApiException("目标地址或授权范围已变化，原审批不能继续执行，请重新申请");
    }
    // Reuse the original turn identity: even independently duplicated approval tickets
    // cannot create the original turn's task batch twice.
    AiAgentRequest execution = stored.withResolvedExecution(true);
    CrossTurnRecoveryService.RecoveryAnchor recovery = approval.getAiRecoveryJson() == null ? null
        : mapper.readValue(approval.getAiRecoveryJson(), CrossTurnRecoveryService.RecoveryAnchor.class);
    AiDispatchResponse response = tools.executeApprovedPlan(execution, plan, recovery);
    approval.setAiDispatchJson(mapper.writeValueAsString(response));
    approvals.save(approval);
    return response;
  }
}
