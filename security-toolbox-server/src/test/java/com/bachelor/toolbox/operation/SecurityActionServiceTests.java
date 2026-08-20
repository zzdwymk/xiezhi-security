package com.bachelor.toolbox.operation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.auth.UserRepository;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;

class SecurityActionServiceTests {
  private final SecurityActionRepository repository = mock(SecurityActionRepository.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final AuditService audit = mock(AuditService.class);
  private final UserRepository users = mock(UserRepository.class);
  private final Authentication applicant = mock(Authentication.class);

  private SecurityActionService service;
  private AssessmentProject project;
  private Instant authorizationTo;

  @BeforeEach
  void setUp() {
    service = new SecurityActionService(repository, projects, audit, users);
    Instant authorizationFrom = Instant.now().minusSeconds(3600);
    authorizationTo = Instant.now().plusSeconds(4 * 3600L);

    project = new AssessmentProject();
    project.setId(1L);
    project.setStatus("ACTIVE");
    project.setAuthorizationValidFrom(authorizationFrom);
    project.setAuthorizationExpiresAt(authorizationTo);

    when(applicant.getName()).thenReturn("alice");
    when(users.count()).thenReturn(1L);
    when(projects.get(1L)).thenReturn(project);
    doNothing().when(projects).validateProjectTarget(1L, 7L);
    when(repository.save(any(SecurityAction.class)))
        .thenAnswer(
            invocation -> {
              SecurityAction action = invocation.getArgument(0);
              if (action.getId() == null) {
                action.setId(42L);
              }
              return action;
            });
  }

  @Test
  void listsActionsAfterCheckingProjectAccess() {
    SecurityAction action = action("PENDING_APPROVAL");
    when(repository.findByProjectId(eq(1L), any(Pageable.class))).thenReturn(List.of(action));

    assertThat(service.list(1L)).containsExactly(action);

    InOrder accessThenQuery = inOrder(projects, repository);
    accessThenQuery.verify(projects).get(1L);
    accessThenQuery.verify(repository).findByProjectId(eq(1L), any(Pageable.class));

    ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
    verify(repository).findByProjectId(eq(1L), pageable.capture());
    assertThat(pageable.getValue().getPageNumber()).isZero();
    assertThat(pageable.getValue().getPageSize()).isEqualTo(1000);
    assertThat(pageable.getValue().getSort().getOrderFor("createdAt").getDirection())
        .isEqualTo(Sort.Direction.DESC);
    assertThat(pageable.getValue().getSort().getOrderFor("id").getDirection())
        .isEqualTo(Sort.Direction.DESC);
    verify(repository, never()).findByProjectIdOrderByCreatedAtDesc(1L);
  }

  @Test
  void rejectsActionOwnedByAnotherProject() {
    SecurityAction action = action("PENDING_APPROVAL");
    action.setProjectId(2L);
    when(repository.findById(42L)).thenReturn(Optional.of(action));

    assertThatThrownBy(() -> service.get(1L, 42L))
        .isInstanceOf(ApiException.class)
        .hasMessage("安全动作不属于当前项目");
  }

  @Test
  void createsOnlyWhenWindowIsInsideProjectAuthorization() {
    Instant start = futureStart();

    SecurityAction created =
        service.create(1L, request(7L, null, start, start.plusSeconds(1800)), applicant);

    assertThat(created.getId()).isEqualTo(42L);
    assertThat(created.getStatus()).isEqualTo("PENDING_APPROVAL");
    assertThat(created.getRequestedBy()).isEqualTo("alice");
    assertThat(created.isNonDestructive()).isTrue();
    assertThat(created.isLateralMovement()).isFalse();

    InOrder persistedThenAudited = inOrder(repository, audit);
    persistedThenAudited.verify(repository).save(created);
    persistedThenAudited
        .verify(audit)
        .record("REQUEST_SECURITY_ACTION", "PROJECT", 1L, "actionId=42", "SUCCESS");
  }

  @Test
  void rejectsWindowOutsideProjectAuthorization() {
    Instant end = authorizationTo.plusSeconds(1);

    assertThatThrownBy(
            () -> service.create(1L, request(7L, null, end.minusSeconds(1800), end), applicant))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("授权有效期");
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsFindingThatIsNotInProject() {
    when(projects.projectFindings(1L)).thenReturn(List.of());
    Instant start = futureStart();

    assertThatThrownBy(
            () -> service.create(1L, request(7L, 99L, start, start.plusSeconds(1800)), applicant))
        .isInstanceOf(ApiException.class)
        .hasMessage("关联漏洞不属于当前项目");
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsFindingForAnotherTarget() {
    Finding finding = new Finding();
    finding.setId(99L);
    finding.setTargetId(8L);
    when(projects.projectFindings(1L)).thenReturn(List.of(finding));
    Instant start = futureStart();

    assertThatThrownBy(
            () -> service.create(1L, request(7L, 99L, start, start.plusSeconds(1800)), applicant))
        .isInstanceOf(ApiException.class)
        .hasMessage("关联漏洞与授权目标不一致");
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsSecretsAndCommandSyntaxInAllUserSuppliedText() {
    Instant start = futureStart();
    SecurityActionDtos.Create secretPurpose =
        new SecurityActionDtos.Create(
            7L,
            null,
            "VULNERABILITY_VALIDATION",
            "验证",
            "token: abc123",
            "MEDIUM",
            true,
            false,
            "服务端验证流程",
            "服务端回滚流程",
            start,
            start.plusSeconds(1800));
    assertThatThrownBy(() -> service.create(1L, secretPurpose, applicant))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("明文凭据");

    SecurityActionDtos.Create commandPlan =
        new SecurityActionDtos.Create(
            7L,
            null,
            "VULNERABILITY_VALIDATION",
            "验证",
            "确认影响",
            "MEDIUM",
            true,
            false,
            "nmap --script vuln",
            "服务端回滚流程",
            start,
            start.plusSeconds(1800));
    assertThatThrownBy(() -> service.create(1L, commandPlan, applicant))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("命令");
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsOversizedPurposeBeforePersistence() {
    Instant start = futureStart();
    SecurityActionDtos.Create request =
        new SecurityActionDtos.Create(
            7L,
            null,
            "VULNERABILITY_VALIDATION",
            "验证",
            "x".repeat(4001),
            "MEDIUM",
            true,
            false,
            "服务端验证流程",
            "服务端回滚流程",
            start,
            start.plusSeconds(1800));

    assertThatThrownBy(() -> service.create(1L, request, applicant))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("长度");
    verify(repository, never()).save(any());
  }

  @Test
  void approvesPendingActionWithIndependentReviewer() {
    SecurityAction action = action("PENDING_APPROVAL");
    Authentication reviewer = mock(Authentication.class);
    when(reviewer.getName()).thenReturn("bob");
    when(repository.findById(42L)).thenReturn(Optional.of(action));
    SecurityActionDtos.Decision request = new SecurityActionDtos.Decision(" approved ", " 已复核 ");

    SecurityAction approved = service.decide(1L, 42L, request, reviewer);

    assertThat(approved.getStatus()).isEqualTo("APPROVED");
    assertThat(approved.getApprovedBy()).isEqualTo("bob");
    assertThat(approved.getApprovedAt()).isNotNull();
    assertThat(approved.getTerminationReason()).isEqualTo("已复核");

    InOrder auditedThenPersisted = inOrder(audit, repository);
    auditedThenPersisted
        .verify(audit)
        .record(
            "DECIDE_SECURITY_ACTION", "PROJECT", 1L, "actionId=42,decision=APPROVED", "SUCCESS");
    auditedThenPersisted.verify(repository).save(action);
  }

  @Test
  void allowsSingleAdministratorToApproveOwnActionWithExplicitConfirmation() {
    SecurityAction action = action("PENDING_APPROVAL");
    org.springframework.security.authentication.UsernamePasswordAuthenticationToken admin =
        new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
            "alice",
            null,
            List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN")));
    when(repository.findById(42L)).thenReturn(Optional.of(action));

    SecurityAction approved =
        service.decide(1L, 42L, new SecurityActionDtos.Decision("APPROVED", "管理员已二次确认"), admin);

    assertThat(approved.getStatus()).isEqualTo("APPROVED");
    assertThat(approved.getApprovedBy()).isEqualTo("alice");
  }

  @Test
  void rejectsApprovalByOriginalApplicant() {
    SecurityAction action = action("PENDING_APPROVAL");
    when(users.count()).thenReturn(2L);
    when(repository.findById(42L)).thenReturn(Optional.of(action));

    assertThatThrownBy(
            () ->
                service.decide(
                    1L, 42L, new SecurityActionDtos.Decision("APPROVED", "复核完成"), applicant))
        .isInstanceOf(ApiException.class)
        .hasMessage("申请人与审批人必须分离");
    verify(repository, never()).save(any());
    verify(audit, never()).record(any(), any(), any(), any(), any());
  }

  @Test
  void startsApprovedActionInsideExecutionWindow() {
    SecurityAction action = action("APPROVED");
    when(repository.findById(42L)).thenReturn(Optional.of(action));

    SecurityAction started = service.start(1L, 42L);

    assertThat(started.getStatus()).isEqualTo("RUNNING");
    assertThat(started.getStartedAt()).isNotNull();
    verify(projects).validateProjectTarget(1L, 7L);

    InOrder auditedThenPersisted = inOrder(audit, repository);
    auditedThenPersisted
        .verify(audit)
        .record("START_SECURITY_ACTION", "PROJECT", 1L, "actionId=42", "SUCCESS");
    auditedThenPersisted.verify(repository).save(action);
  }

  @Test
  void rejectsStartWhenPersistedSafetyBoundaryIsBroken() {
    SecurityAction action = action("APPROVED");
    action.setLateralMovement(true);
    when(repository.findById(42L)).thenReturn(Optional.of(action));

    assertThatThrownBy(() -> service.start(1L, 42L))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("安全边界");
    verify(repository, never()).save(any());
    verify(audit, never()).record(any(), any(), any(), any(), any());
  }

  @Test
  void completesRunningActionAndTrimsEvidence() {
    SecurityAction action = action("RUNNING");
    when(repository.findById(42L)).thenReturn(Optional.of(action));

    SecurityAction completed =
        service.complete(1L, 42L, new SecurityActionDtos.Complete(" 最小必要证据 ", " 正常结束 "));

    assertThat(completed.getStatus()).isEqualTo("COMPLETED");
    assertThat(completed.getEvidence()).isEqualTo("最小必要证据");
    assertThat(completed.getTerminationReason()).isEqualTo("正常结束");
    assertThat(completed.getFinishedAt()).isNotNull();

    InOrder auditedThenPersisted = inOrder(audit, repository);
    auditedThenPersisted
        .verify(audit)
        .record("COMPLETE_SECURITY_ACTION", "PROJECT", 1L, "actionId=42", "SUCCESS");
    auditedThenPersisted.verify(repository).save(action);
  }

  @Test
  void rejectsSensitiveCompletionEvidence() {
    SecurityAction action = action("RUNNING");
    when(repository.findById(42L)).thenReturn(Optional.of(action));

    assertThatThrownBy(
            () ->
                service.complete(
                    1L, 42L, new SecurityActionDtos.Complete("password: hunter2", "已停止")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("明文凭据");
    verify(repository, never()).save(any());
  }

  @Test
  void rollsBackAllowedActionAndPreservesAuditContract() {
    SecurityAction action = action("COMPLETED");
    when(repository.findById(42L)).thenReturn(Optional.of(action));

    SecurityAction rolledBack =
        service.rollback(1L, 42L, new SecurityActionDtos.Rollback(" 清理记录 ", " 验证结束后恢复 "));

    assertThat(rolledBack.getStatus()).isEqualTo("ROLLED_BACK");
    assertThat(rolledBack.getRollbackEvidence()).isEqualTo("清理记录");
    assertThat(rolledBack.getTerminationReason()).isEqualTo("验证结束后恢复");
    assertThat(rolledBack.getFinishedAt()).isNotNull();

    InOrder auditedThenPersisted = inOrder(audit, repository);
    auditedThenPersisted
        .verify(audit)
        .record("ROLLBACK_SECURITY_ACTION", "PROJECT", 1L, "actionId=42", "SUCCESS");
    auditedThenPersisted.verify(repository).save(action);
  }

  @Test
  void rejectsRollbackFromPendingState() {
    SecurityAction action = action("PENDING_APPROVAL");
    when(repository.findById(42L)).thenReturn(Optional.of(action));

    assertThatThrownBy(
            () -> service.rollback(1L, 42L, new SecurityActionDtos.Rollback("无临时状态", "尚未执行")))
        .isInstanceOf(ApiException.class)
        .hasMessage("当前状态不允许回滚");
    verify(repository, never()).save(any());
    verify(audit, never()).record(any(), any(), any(), any(), any());
  }

  private SecurityActionDtos.Create request(
      Long targetId, Long findingId, Instant start, Instant end) {
    return new SecurityActionDtos.Create(
        targetId,
        findingId,
        "VULNERABILITY_VALIDATION",
        "授权漏洞验证",
        "验证已记录漏洞的可达性",
        "MEDIUM",
        true,
        false,
        "仅调用服务端受控验证流程并记录最小必要证据",
        "停止验证流程并清理临时状态",
        start,
        end);
  }

  private Instant futureStart() {
    return Instant.now().plusSeconds(60);
  }

  private SecurityAction action(String status) {
    SecurityAction action = new SecurityAction();
    action.setId(42L);
    action.setProjectId(1L);
    action.setTargetId(7L);
    action.setCategory("VULNERABILITY_VALIDATION");
    action.setTitle("授权漏洞验证");
    action.setPurpose("验证已记录漏洞的可达性");
    action.setRiskLevel("MEDIUM");
    action.setNonDestructive(true);
    action.setLateralMovement(false);
    action.setExecutionPlan("仅调用服务端受控验证流程");
    action.setRollbackPlan("停止验证流程并清理临时状态");
    action.setWindowStart(Instant.now().minusSeconds(60));
    action.setWindowEnd(Instant.now().plusSeconds(1800));
    action.setStatus(status);
    action.setRequestedBy("alice");
    return action;
  }
}
