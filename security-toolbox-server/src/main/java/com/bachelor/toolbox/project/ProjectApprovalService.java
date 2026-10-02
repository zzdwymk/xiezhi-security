package com.bachelor.toolbox.project;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import java.time.Instant;
import java.util.List;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class ProjectApprovalService {
  private static final Sort LIST_SORT =
      Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"));
  private static final String PENDING_STATUS = "PENDING";
  private static final String SYSTEM_OPERATOR = "SYSTEM";

  private final ProjectApprovalRepository repository;
  private final AuditService audit;
  private final ProjectAuthorizationService authorization;
  private final com.bachelor.toolbox.target.TargetService targets;

  @org.springframework.beans.factory.annotation.Autowired
  public ProjectApprovalService(ProjectApprovalRepository repository, AuditService audit,
      ProjectAuthorizationService authorization, com.bachelor.toolbox.target.TargetService targets) {
    this.repository = repository;
    this.audit = audit;
    this.authorization = authorization;
    this.targets = targets;
  }

  public ProjectApprovalService(ProjectApprovalRepository repository, AuditService audit,
      ProjectAuthorizationService authorization) {
    this(repository, audit, authorization, null);
  }

  public List<ProjectApproval> list(Long projectId) {
    authorization.requireAccess(projectId);
    return repository.findByProjectId(projectId, PageRequests.firstPage(LIST_SORT));
  }

  public ProjectApproval request(
      Long projectId, String action, String comment, String authorizationSnapshotHash) {
    authorization.requireManage(projectId);
    ProjectApproval approval =
        createApproval(projectId, action, comment, authorizationSnapshotHash);
    ProjectApproval saved = repository.save(approval);
    recordRequest(saved, approval.getAuthorizationSnapshotHash());
    return saved;
  }

  /**
   * 由 AI Agent 规划服务在识别到需要人工审批的动作时受控提交审批请求。
   * 固定申请主体为系统内置的不可登录服务账号 "ai-agent"，实现人机审批分离。
   */
  private static final int HASH_COLUMN_LENGTH = 64;

  public ProjectApproval requestByAgent(
      Long projectId, String action, String comment, String authorizationSnapshotHash) {
    ProjectApproval approval = new ProjectApproval();
    approval.setProjectId(projectId);
    approval.setAction(action);
    approval.setStatus(PENDING_STATUS);
    approval.setComment(comment);
    approval.setAuthorizationSnapshotHash(normalizeHash(authorizationSnapshotHash));
    approval.setRequestedBy("ai-agent");
    ProjectApproval saved = repository.save(approval);
    recordRequest(saved, approval.getAuthorizationSnapshotHash());
    return saved;
  }

  @org.springframework.transaction.annotation.Transactional(rollbackFor = Exception.class)
  public ProjectApproval requestAiPlan(com.bachelor.toolbox.ai.AiAgentRequest request,
      com.bachelor.toolbox.ai.AiPlanResponse plan,
      com.bachelor.toolbox.ai.CrossTurnRecoveryService.RecoveryAnchor recoveryAnchor) {
    AssessmentProject project = authorization.requireAccess(request.projectId());
    try {
      var mapper = new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules();
      ProjectApproval approval = new ProjectApproval();
      approval.setProjectId(request.projectId());
      approval.setAction("AI_PLAN_EXECUTION");
      approval.setStatus(PENDING_STATUS);
      approval.setRequestedBy("ai-agent");
      String summary = java.util.Objects.toString(plan.summary(), "");
      approval.setComment("AI 请求执行原计划：" + summary.substring(0, Math.min(1800, summary.length())));
      approval.setAuthorizationSnapshotHash(normalizeHash(request.workflowDigest()));
      approval.setAiProjectBinding(com.bachelor.toolbox.ai.AiPlanApprovalService.projectBinding(project));
      if (targets == null) throw new ApiException("审批目标快照服务不可用");
      approval.setAiTargetBinding(com.bachelor.toolbox.ai.AiPlanApprovalService.targetBinding(targets.get(request.targetId())));
      approval.setAiRequestJson(mapper.writeValueAsString(request));
      approval.setAiPlanJson(mapper.writeValueAsString(plan));
      if (recoveryAnchor != null) approval.setAiRecoveryJson(mapper.writeValueAsString(recoveryAnchor));
      ProjectApproval saved = repository.save(approval);
      recordRequest(saved, saved.getAuthorizationSnapshotHash());
      return saved;
    } catch (com.fasterxml.jackson.core.JsonProcessingException ex) {
      throw new ApiException("无法保存待审批原计划，未派发任务");
    }
  }

  /** 写入前规整快照哈希：去除 "sha256:" 前缀并截断到列长限制（64 字符）。 */
  private String normalizeHash(String hash) {
    if (hash == null || hash.isBlank()) {
      return null;
    }
    String value = hash.startsWith("sha256:") ? hash.substring("sha256:".length()) : hash;
    return value.length() > HASH_COLUMN_LENGTH ? value.substring(0, HASH_COLUMN_LENGTH) : value;
  }

  @org.springframework.transaction.annotation.Transactional
  public ProjectApproval decide(Long projectId, Long approvalId, String status, String comment) {
    authorization.requireAdmin();
    if (!"APPROVED".equals(status) && !"REJECTED".equals(status)) throw new ApiException("审批结果只能是 APPROVED 或 REJECTED");
    ProjectApproval approval = repository.findForUpdate(approvalId, projectId)
        .orElseThrow(() -> new ApiException("项目审批记录不存在"));
    if (!PENDING_STATUS.equals(approval.getStatus())) {
      if (status.equals(approval.getStatus())) return approval;
      throw new ApiException("该审批已裁决，不能更改结果，请重新申请");
    }
    applyDecision(approval, status, comment);

    ProjectApproval saved = repository.save(approval);
    recordDecision(saved, approvalId, status);
    return saved;
  }

  private ProjectApproval getApproval(Long projectId, Long approvalId) {
    return repository
        .findByIdAndProjectId(approvalId, projectId)
        .orElseThrow(() -> new ApiException("项目审批记录不存在"));
  }

  private ProjectApproval createApproval(
      Long projectId, String action, String comment, String authorizationSnapshotHash) {
    ProjectApproval approval = new ProjectApproval();
    approval.setProjectId(projectId);
    approval.setAction(action);
    approval.setStatus(PENDING_STATUS);
    approval.setComment(comment);
    approval.setAuthorizationSnapshotHash(normalizeHash(authorizationSnapshotHash));
    approval.setRequestedBy(currentOperator());
    return approval;
  }

  private void applyDecision(ProjectApproval approval, String status, String comment) {
    approval.setStatus(status);
    approval.setComment(comment);
    approval.setApprovedBy(currentOperator());
    approval.setDecidedAt(Instant.now());
  }

  private void recordRequest(ProjectApproval approval, String authorizationSnapshotHash) {
    audit.record(
        "PROJECT_APPROVAL_REQUEST",
        "PROJECT",
        approval.getProjectId(),
        "approvalId=" + approval.getId(),
        "SUCCESS",
        null,
        authorizationSnapshotHash);
  }

  private void recordDecision(ProjectApproval approval, Long approvalId, String status) {
    audit.record(
        "PROJECT_APPROVAL_DECIDE",
        "PROJECT",
        approval.getProjectId(),
        "approvalId=" + approvalId + ";status=" + status,
        "SUCCESS",
        null,
        approval.getAuthorizationSnapshotHash());
  }

  private String currentOperator() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return authentication == null ? SYSTEM_OPERATOR : authentication.getName();
  }
}
