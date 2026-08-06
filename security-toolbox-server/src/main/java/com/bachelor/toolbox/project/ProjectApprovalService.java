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

  public ProjectApprovalService(
      ProjectApprovalRepository repository,
      AuditService audit,
      ProjectAuthorizationService authorization) {
    this.repository = repository;
    this.audit = audit;
    this.authorization = authorization;
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
    recordRequest(saved, authorizationSnapshotHash);
    return saved;
  }

  public ProjectApproval decide(Long projectId, Long approvalId, String status, String comment) {
    authorization.requireAdmin();
    ProjectApproval approval = getApproval(projectId, approvalId);
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
    approval.setAuthorizationSnapshotHash(authorizationSnapshotHash);
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
