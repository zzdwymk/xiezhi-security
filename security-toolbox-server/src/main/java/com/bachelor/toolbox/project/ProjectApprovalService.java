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
  private com.bachelor.toolbox.notification.NotificationService notifications;

  @org.springframework.beans.factory.annotation.Autowired(required = false)
  public void setNotifications(com.bachelor.toolbox.notification.NotificationService value) {
    notifications = value;
  }
  private static final Sort LIST_SORT =
      Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"));
  private static final String PENDING_STATUS = "PENDING";
  private static final String SYSTEM_OPERATOR = "SYSTEM";

  private final ProjectApprovalRepository repository;
  private final AuditService audit;
  private final ProjectAuthorizationService authorization;
  private final com.bachelor.toolbox.target.TargetService targets;
  @jakarta.persistence.PersistenceContext
  private jakarta.persistence.EntityManager entityManager;

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
    throw new ApiException("手动申请已合并到执行确认，请由 AI 提交方案后由管理员确认执行");
  }

  private static final int HASH_COLUMN_LENGTH = 64;

  @org.springframework.transaction.annotation.Transactional(rollbackFor = Exception.class)
  public ProjectApproval requestAiPlan(com.bachelor.toolbox.ai.AiAgentRequest request,
      com.bachelor.toolbox.ai.AiPlanResponse plan,
      com.bachelor.toolbox.ai.CrossTurnRecoveryService.RecoveryAnchor recoveryAnchor) {
    AssessmentProject project = authorization.requireAccess(request.projectId());
    String applicant = authorization.currentUsername();
    String requestKey = aiRequestKey(request.projectId(), applicant, request.turnId());
    // A project row exists before its first approval. Locking it closes the absent-row race;
    // the unique request key also enforces the invariant for writes outside this service.
    entityManager.lock(project, jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
    entityManager.refresh(project);
    if (!authorization.canAccess(project)) throw new ApiException("无权访问该评估项目");
    if (targets == null) throw new ApiException("审批目标快照服务不可用");
    var target = targets.lockForAgentExecution(request.targetId());
    entityManager.refresh(target);
    try {
      var mapper = new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules();
      String projectBinding = com.bachelor.toolbox.ai.AiPlanApprovalService.projectBinding(project);
      String targetBinding = com.bachelor.toolbox.ai.AiPlanApprovalService.targetBinding(target);
      String requestJson = mapper.writeValueAsString(request);
      String planJson = mapper.writeValueAsString(plan);
      var existing = repository.findByAiRequestKey(requestKey);
      if (existing.isPresent()) {
        ProjectApproval saved = existing.get();
        if (!request.projectId().equals(saved.getProjectId())
            || !applicant.equals(saved.getInitiatedBy())
            || !"AI_PLAN_EXECUTION".equals(saved.getAction())
            || !"ai-agent".equals(saved.getRequestedBy())
            || !projectBinding.equals(saved.getAiProjectBinding())
            || !targetBinding.equals(saved.getAiTargetBinding())
            || !mapper.readTree(requestJson).equals(mapper.readTree(saved.getAiRequestJson()))
            || !mapper.readTree(planJson).equals(mapper.readTree(saved.getAiPlanJson()))) {
          throw new ApiException("相同 Turn ID 的请求、原计划或授权范围已变化，请重新提交新一轮方案");
        }
        return saved;
      }
      ProjectApproval approval = new ProjectApproval();
      approval.setProjectId(request.projectId());
      approval.setAction("AI_PLAN_EXECUTION");
      approval.setStatus(PENDING_STATUS);
      approval.setRequestedBy("ai-agent");
      approval.setInitiatedBy(applicant);
      approval.setAiRequestKey(requestKey);
      String summary = java.util.Objects.toString(plan.summary(), "");
      approval.setComment("AI 请求执行原计划：" + summary.substring(0, Math.min(1800, summary.length())));
      approval.setAuthorizationSnapshotHash(normalizeHash(request.workflowDigest()));
      approval.setAiProjectBinding(projectBinding);
      approval.setAiTargetBinding(targetBinding);
      approval.setAiRequestJson(requestJson);
      approval.setAiPlanJson(planJson);
      if (recoveryAnchor != null) approval.setAiRecoveryJson(mapper.writeValueAsString(recoveryAnchor));
      ProjectApproval saved = repository.save(approval);
      recordRequest(saved, saved.getAuthorizationSnapshotHash());
      if (notifications != null) {
        notifications.publish("approval:" + saved.getId() + ":PENDING", saved.getProjectId(), true,
            "approval", "warning", "AI 执行方案待确认", "项目「" + project.getName() + "」有新的执行方案等待管理员确认",
            "/projects/" + saved.getProjectId() + "?tab=audits&approvalId=" + saved.getId(), List.of());
      }
      return saved;
    } catch (com.fasterxml.jackson.core.JsonProcessingException ex) {
      throw new ApiException("无法保存待审批原计划，未派发任务");
    }
  }

  private static String aiRequestKey(Long projectId, String applicant, String turnId) {
    if (turnId == null || !turnId.matches("[A-Za-z0-9_-]{1,80}")) {
      throw new ApiException("AI 方案必须携带有效的 Turn ID");
    }
    String input = java.util.stream.Stream.of(projectId.toString(), applicant, turnId)
        .map(value -> value.length() + ":" + value)
        .collect(java.util.stream.Collectors.joining("\n"));
    try {
      return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
          .digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException ex) {
      throw new IllegalStateException("SHA-256 unavailable", ex);
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
    authorization.requireAccess(projectId);
    if ("ai-agent".equals(currentOperator())) throw new ApiException("AI 不能确认自己的方案");
    if (!"APPROVED".equals(status) && !"REJECTED".equals(status)) throw new ApiException("审批结果只能是 APPROVED 或 REJECTED");
    ProjectApproval approval = repository.findForUpdate(approvalId, projectId)
        .orElseThrow(() -> new ApiException("项目审批记录不存在"));
    if (!PENDING_STATUS.equals(approval.getStatus())) {
      if (status.equals(approval.getStatus())) return approval;
      throw new ApiException("该审批已裁决，不能更改结果，请重新申请");
    }
    if (!"AI_PLAN_EXECUTION".equals(approval.getAction())
        || !"ai-agent".equals(approval.getRequestedBy())
        || approval.getAiPlanJson() == null || approval.getAiRequestJson() == null) {
      throw new ApiException("历史手动申请不再支持审批，请由 AI 重新提交方案后确认执行");
    }
    applyDecision(approval, status, comment);

    ProjectApproval saved = repository.save(approval);
    recordDecision(saved, approvalId, status);
    return saved;
  }

  public record PlanDetail(Long approvalId, Long projectId, Long targetId, String status,
      com.bachelor.toolbox.ai.AiPlanResponse plan, com.bachelor.toolbox.ai.AiDispatchResponse dispatch) {}

  public PlanDetail planDetail(Long projectId, Long approvalId) {
    authorization.requireAccess(projectId);
    ProjectApproval approval = getApproval(projectId, approvalId);
    if (!"AI_PLAN_EXECUTION".equals(approval.getAction()) || approval.getAiRequestJson() == null
        || approval.getAiPlanJson() == null) throw new ApiException("历史记录没有保存 AI 原方案，请由 AI 重新提交方案");
    try {
      var mapper = new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules();
      var request = mapper.readValue(approval.getAiRequestJson(), com.bachelor.toolbox.ai.AiAgentRequest.class);
      if (!projectId.equals(request.projectId())) throw new ApiException("确认记录与原方案项目不一致");
      var plan = mapper.readValue(approval.getAiPlanJson(), com.bachelor.toolbox.ai.AiPlanResponse.class);
      var dispatch = approval.getAiDispatchJson() == null ? null
          : mapper.readValue(approval.getAiDispatchJson(), com.bachelor.toolbox.ai.AiDispatchResponse.class);
      return new PlanDetail(approvalId, projectId, request.targetId(), approval.getStatus(), plan, dispatch);
    } catch (com.fasterxml.jackson.core.JsonProcessingException ex) {
      throw new ApiException("无法读取已保存的 AI 原方案，请由 AI 重新提交方案");
    }
  }

  private ProjectApproval getApproval(Long projectId, Long approvalId) {
    return repository
        .findByIdAndProjectId(approvalId, projectId)
        .orElseThrow(() -> new ApiException("项目审批记录不存在"));
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
