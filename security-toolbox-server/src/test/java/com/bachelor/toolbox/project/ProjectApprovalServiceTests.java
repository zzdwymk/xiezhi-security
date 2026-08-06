package com.bachelor.toolbox.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

class ProjectApprovalServiceTests {
  private final ProjectApprovalRepository repository = mock(ProjectApprovalRepository.class);
  private final AuditService audit = mock(AuditService.class);
  private final AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
  private final ProjectApprovalService service =
      new ProjectApprovalService(repository, audit, new ProjectAuthorizationService(projects));

  @BeforeEach
  void setUp() {
    when(projects.findById(any())).thenReturn(Optional.of(project(3L, "admin")));
    authenticateAsAdmin();
  }

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void listsApprovalsUsingExistingProjectOrder() {
    ProjectApproval approval = new ProjectApproval();
    when(repository.findByProjectId(
            org.mockito.ArgumentMatchers.eq(3L), any(Pageable.class)))
        .thenReturn(List.of(approval));

    assertThat(service.list(3L)).containsExactly(approval);

    ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
    verify(repository).findByProjectId(org.mockito.ArgumentMatchers.eq(3L), pageableCaptor.capture());
    Pageable pageable = pageableCaptor.getValue();
    assertThat(pageable.getPageNumber()).isZero();
    assertThat(pageable.getPageSize()).isLessThanOrEqualTo(1000);
    assertThat(pageable.getSort().getOrderFor("createdAt"))
        .isEqualTo(org.springframework.data.domain.Sort.Order.desc("createdAt"));
    assertThat(pageable.getSort().getOrderFor("id"))
        .isEqualTo(org.springframework.data.domain.Sort.Order.desc("id"));
  }

  @Test
  void rejectsListingApprovalsForAnotherOwnersProjectBeforeQueryingApprovals() {
    authenticateAs("alice", "ROLE_USER");
    when(projects.findById(3L)).thenReturn(Optional.of(project(3L, "bob")));

    assertThatThrownBy(() -> service.list(3L))
        .isInstanceOf(ApiException.class)
        .hasMessage("无权访问该评估项目");
    verify(repository, never()).findByProjectId(any(), any(Pageable.class));
  }

  @Test
  void requestsPendingApprovalAsAdmin() {
    when(repository.save(any(ProjectApproval.class)))
        .thenAnswer(
            invocation -> {
              ProjectApproval approval = invocation.getArgument(0);
              approval.setId(7L);
              return approval;
            });

    ProjectApproval approval = service.request(3L, "SCAN", "申请扫描", "snapshot-hash");

    assertThat(approval.getProjectId()).isEqualTo(3L);
    assertThat(approval.getAction()).isEqualTo("SCAN");
    assertThat(approval.getStatus()).isEqualTo("PENDING");
    assertThat(approval.getComment()).isEqualTo("申请扫描");
    assertThat(approval.getAuthorizationSnapshotHash()).isEqualTo("snapshot-hash");
    assertThat(approval.getRequestedBy()).isEqualTo("admin");
    verify(audit)
        .record(
            "PROJECT_APPROVAL_REQUEST",
            "PROJECT",
            3L,
            "approvalId=7",
            "SUCCESS",
            null,
            "snapshot-hash");
  }

  @Test
  void usesCurrentAuthenticationNameForRequester() {
    authenticateAs("申请人", "ROLE_USER");
    when(projects.findById(3L)).thenReturn(Optional.of(project(3L, "申请人")));
    when(repository.save(any(ProjectApproval.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));

    ProjectApproval approval = service.request(3L, "REPORT", null, null);

    assertThat(approval.getRequestedBy()).isEqualTo("申请人");
  }

  @Test
  void decidesApprovalAndPreservesAuditContract() {
    authenticateAs("审批人", "ROLE_ADMIN");
    ProjectApproval approval = approval(7L, 3L, "snapshot-hash");
    when(repository.findByIdAndProjectId(7L, 3L)).thenReturn(Optional.of(approval));
    when(repository.save(approval)).thenReturn(approval);
    Instant beforeDecision = Instant.now();

    ProjectApproval decided = service.decide(3L, 7L, "REJECTED", "授权材料不足");

    assertThat(decided.getStatus()).isEqualTo("REJECTED");
    assertThat(decided.getComment()).isEqualTo("授权材料不足");
    assertThat(decided.getApprovedBy()).isEqualTo("审批人");
    assertThat(decided.getDecidedAt()).isAfterOrEqualTo(beforeDecision);
    verify(audit)
        .record(
            "PROJECT_APPROVAL_DECIDE",
            "PROJECT",
            3L,
            "approvalId=7;status=REJECTED",
            "SUCCESS",
            null,
            "snapshot-hash");
  }

  @Test
  void reportsMissingApprovalAsStableChineseApiException() {
    when(repository.findByIdAndProjectId(99L, 3L)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.decide(3L, 99L, "APPROVED", null))
        .isInstanceOf(ApiException.class)
        .hasMessage("项目审批记录不存在");
    verify(repository, never()).save(any(ProjectApproval.class));
    verify(audit, never()).record(any(), any(), any(), any(), any(), any(), any());
  }

  @Test
  void rejectsNonAdminDecisionBeforeLoadingApproval() {
    authenticateAs("审核员", "ROLE_USER");

    assertThatThrownBy(() -> service.decide(3L, 7L, "APPROVED", null))
        .isInstanceOf(ApiException.class)
        .hasMessage("仅管理员可以审批项目");
    verify(repository, never()).findByIdAndProjectId(any(), any());
    verify(repository, never()).save(any(ProjectApproval.class));
  }

  @Test
  void rejectsApprovalFromAnotherProject() {
    when(repository.findByIdAndProjectId(8L, 3L)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.decide(3L, 8L, "APPROVED", null))
        .isInstanceOf(ApiException.class)
        .hasMessage("项目审批记录不存在");
    verify(repository, never()).save(any(ProjectApproval.class));
  }

  private void authenticateAsAdmin() {
    authenticateAs("admin", "ROLE_ADMIN");
  }

  private void authenticateAs(String name, String role) {
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(
                name, null, List.of(new SimpleGrantedAuthority(role))));
  }

  private ProjectApproval approval(Long id, Long projectId, String hash) {
    ProjectApproval approval = new ProjectApproval();
    approval.setId(id);
    approval.setProjectId(projectId);
    approval.setAuthorizationSnapshotHash(hash);
    return approval;
  }

  private AssessmentProject project(Long id, String owner) {
    AssessmentProject project = new AssessmentProject();
    project.setId(id);
    project.setOwner(owner);
    return project;
  }
}
