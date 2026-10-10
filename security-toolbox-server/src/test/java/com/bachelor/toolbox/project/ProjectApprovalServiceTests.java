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
  void rejectsManualSubmissionEvenWhenItClaimsAiPlanAction() {
    for (String action : List.of("SCAN", "AI_PLAN_EXECUTION")) {
      assertThatThrownBy(() -> service.request(3L, action, "申请", null))
          .isInstanceOf(ApiException.class).hasMessageContaining("请由 AI 提交方案");
    }
    verify(repository, never()).save(any());
  }

  @Test
  void publicControllerCannotSpoofAiSourceOrSavedPlan() {
    var controller = new ProjectApprovalController(service);
    assertThatThrownBy(() -> controller.request(3L, java.util.Map.of(
        "action", "AI_PLAN_EXECUTION", "requestedBy", "ai-agent", "aiPlanJson", "{}")))
        .isInstanceOf(ApiException.class).hasMessageContaining("请由 AI 提交方案");
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsLegacyManualPendingDecisionWithoutMutation() {
    ProjectApproval approval = approval(7L, 3L, "hash");
    approval.setRequestedBy("admin");
    when(repository.findForUpdate(7L, 3L)).thenReturn(Optional.of(approval));
    assertThatThrownBy(() -> service.decide(3L, 7L, "APPROVED", "确认"))
        .isInstanceOf(ApiException.class).hasMessageContaining("历史手动申请");
    assertThat(approval.getStatus()).isEqualTo("PENDING");
    verify(repository, never()).save(any());
  }

  @Test
  void aiSourceCannotDecideEvenWithErroneouslyGrantedAdminRole() {
    authenticateAs("ai-agent", "ROLE_ADMIN");
    assertThatThrownBy(() -> service.decide(3L, 7L, "APPROVED", null))
        .isInstanceOf(ApiException.class).hasMessageContaining("AI 不能确认");
    verify(repository, never()).findForUpdate(any(), any());
  }

  @Test
  void readsExactSavedPlanAndDispatchWithoutMutation() throws Exception {
    var mapper = new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules();
    var request = new com.bachelor.toolbox.ai.AiAgentRequest(3L, 9L, "session", "private prompt", true,
        null, List.of(), "AUTO", "turn");
    var plan = new com.bachelor.toolbox.ai.AiPlanResponse("provider", "model", "原计划", true,
        List.of(new com.bachelor.toolbox.ai.AiPlanResponse.PlanStep("HTTP_HEADERS", "检查响应头", "授权检查", java.util.Map.of())));
    var dispatch = new com.bachelor.toolbox.ai.AiDispatchResponse(9L, plan, 1, List.of(55L));
    var approval = approval(7L, 3L, "hash");
    approval.setAiRequestJson(mapper.writeValueAsString(request));
    approval.setAiPlanJson(mapper.writeValueAsString(plan));
    approval.setAiDispatchJson(mapper.writeValueAsString(dispatch));
    when(repository.findByIdAndProjectId(7L, 3L)).thenReturn(Optional.of(approval));
    var detail = service.planDetail(3L, 7L);
    assertThat(detail.targetId()).isEqualTo(9L);
    assertThat(detail.plan()).isEqualTo(plan);
    assertThat(detail.dispatch().taskIds()).containsExactly(55L);
    verify(repository, never()).save(any());
  }

  @Test
  void refusesPlanReadBeforeLoadingAnotherOwnersRecord() {
    authenticateAs("alice", "ROLE_USER");
    when(projects.findById(3L)).thenReturn(Optional.of(project(3L, "bob")));
    assertThatThrownBy(() -> service.planDetail(3L, 7L)).hasMessage("无权访问该评估项目");
    verify(repository, never()).findByIdAndProjectId(any(), any());
  }

  @Test
  void decidesApprovalAndPreservesAuditContract() {
    authenticateAs("审批人", "ROLE_ADMIN");
    ProjectApproval approval = approval(7L, 3L, "snapshot-hash");
    when(repository.findForUpdate(7L, 3L)).thenReturn(Optional.of(approval));
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
    when(repository.findForUpdate(99L, 3L)).thenReturn(Optional.empty());

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
    verify(repository, never()).findForUpdate(any(), any());
    verify(repository, never()).save(any(ProjectApproval.class));
  }

  @Test
  void rejectsApprovalFromAnotherProject() {
    when(repository.findForUpdate(8L, 3L)).thenReturn(Optional.empty());

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
    approval.setStatus("PENDING");
    approval.setAction("AI_PLAN_EXECUTION");
    approval.setRequestedBy("ai-agent");
    approval.setAiRequestJson("{}");
    approval.setAiPlanJson("{}");
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
