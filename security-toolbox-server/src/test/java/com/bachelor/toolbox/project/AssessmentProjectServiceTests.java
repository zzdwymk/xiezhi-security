package com.bachelor.toolbox.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditLog;
import com.bachelor.toolbox.audit.AuditLogRepository;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

class AssessmentProjectServiceTests {
  private final AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
  private final ProjectTargetRepository links = mock(ProjectTargetRepository.class);
  private final AuthorizedTargetRepository targets = mock(AuthorizedTargetRepository.class);
  private final AuditService audit = mock(AuditService.class);
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final FindingRepository findings = mock(FindingRepository.class);
  private final AuditLogRepository auditLogs = mock(AuditLogRepository.class);

  private AssessmentProjectService service;

  @BeforeEach
  void setUp() {
    service =
        new AssessmentProjectService(
            projects,
            links,
            targets,
            audit,
            tasks,
            findings,
            auditLogs,
            new ProjectAuthorizationService(projects));
    authenticateAsAdmin();
  }

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void createsDraftProjectWithValidAuthorization() {
    when(projects.save(any(AssessmentProject.class)))
        .thenAnswer(
            invocation -> {
              AssessmentProject project = invocation.getArgument(0);
              project.setId(1L);
              return project;
            });
    Instant now = Instant.now();

    AssessmentProject project =
        service.create(
            new ProjectDtos.Create("项目A", "说明", "已取得书面授权", now, now.plusSeconds(3600), "负责人"));

    assertThat(project.getStatus()).isEqualTo("DRAFT");
    assertThat(project.getId()).isEqualTo(1L);
    assertThat(project.getName()).isEqualTo("项目A");
    assertThat(project.getOwner()).isEqualTo("负责人");
    verify(audit).record("CREATE_PROJECT", "PROJECT", 1L, "项目A", "SUCCESS");
  }

  @Test
  void rejectsInvalidAuthorizationPeriodWithChineseMessage() {
    Instant now = Instant.now();

    assertThatThrownBy(
            () -> service.create(new ProjectDtos.Create("项目A", null, "授权", now, now, "负责人")))
        .isInstanceOf(ApiException.class)
        .hasMessage("授权有效期不合法");
    verify(projects, never()).save(any(AssessmentProject.class));
  }

  @Test
  void reportsMissingProjectInChinese() {
    when(projects.findById(9L)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.get(9L))
        .isInstanceOf(ApiException.class)
        .hasMessage("评估项目不存在");
  }

  @Test
  void updatesOnlyFieldsProvidedByCaller() {
    AssessmentProject project = project("DRAFT");
    project.setName("旧名称");
    project.setDescription("原说明");
    project.setAuthorizationStatement("原授权");
    project.setOwner("原负责人");
    Instant newExpiry = project.getAuthorizationExpiresAt().plusSeconds(600);
    when(projects.findById(1L)).thenReturn(Optional.of(project));
    when(projects.save(project)).thenReturn(project);

    AssessmentProject updated =
        service.update(1L, new ProjectDtos.Update("新名称", null, null, null, newExpiry, null));

    assertThat(updated.getName()).isEqualTo("新名称");
    assertThat(updated.getDescription()).isEqualTo("原说明");
    assertThat(updated.getAuthorizationStatement()).isEqualTo("原授权");
    assertThat(updated.getAuthorizationExpiresAt()).isEqualTo(newExpiry);
    assertThat(updated.getOwner()).isEqualTo("原负责人");
  }

  @Test
  void derivesOwnerFromCurrentUserInsteadOfClientRequest() {
    authenticateAs("alice");
    Instant now = Instant.now();
    when(projects.save(any(AssessmentProject.class)))
        .thenAnswer(
            invocation -> {
              AssessmentProject project = invocation.getArgument(0);
              project.setId(2L);
              return project;
            });

    AssessmentProject created =
        service.create(new ProjectDtos.Create("项目", null, "授权", now, now.plusSeconds(60), "bob"));

    assertThat(created.getOwner()).isEqualTo("alice");
  }

  @Test
  void rejectsAccessToAnotherOwnersProject() {
    authenticateAs("alice");
    AssessmentProject project = project("DRAFT");
    project.setOwner("bob");
    when(projects.findById(1L)).thenReturn(Optional.of(project));

    assertThatThrownBy(() -> service.get(1L))
        .isInstanceOf(ApiException.class)
        .hasMessage("无权访问该评估项目");
  }

  @Test
  void listsOnlyProjectsOwnedByCurrentUser() {
    authenticateAs("alice");
    AssessmentProject own = project("DRAFT");
    own.setOwner("alice");
    when(projects.findByOwner(org.mockito.ArgumentMatchers.eq("alice"), any(Pageable.class)))
        .thenReturn(new PageImpl<>(List.of(own)));

    assertThat(service.list()).containsExactly(own);
    verify(projects, never()).findAll(any(Pageable.class));
  }

  @Test
  void listsProjectsWithBoundedDeterministicPageable() {
    when(projects.findAll(any(Pageable.class))).thenReturn(new PageImpl<>(List.of()));

    service.list();

    ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
    verify(projects).findAll(pageableCaptor.capture());
    Pageable pageable = pageableCaptor.getValue();
    assertThat(pageable.getPageNumber()).isZero();
    assertThat(pageable.getPageSize()).isLessThanOrEqualTo(1000);
    assertThat(pageable.getSort().getOrderFor("createdAt"))
        .isEqualTo(org.springframework.data.domain.Sort.Order.desc("createdAt"));
    assertThat(pageable.getSort().getOrderFor("id"))
        .isEqualTo(org.springframework.data.domain.Sort.Order.desc("id"));
  }

  @Test
  void ordinaryUserCannotChangeProjectOwner() {
    authenticateAs("alice");
    AssessmentProject project = project("DRAFT");
    project.setOwner("alice");
    when(projects.findById(1L)).thenReturn(Optional.of(project));

    assertThatThrownBy(
            () -> service.update(1L, new ProjectDtos.Update(null, null, null, null, null, "bob")))
        .isInstanceOf(ApiException.class)
        .hasMessage("普通用户不能修改项目负责人");
    verify(projects, never()).save(project);
  }

  @Test
  void keepsAllProjectStatusConstantsAccepted() {
    List<String> statuses = List.of("DRAFT", "ACTIVE", "PAUSED", "COMPLETED", "ARCHIVED");
    when(projects.findById(1L)).thenAnswer(invocation -> Optional.of(project("DRAFT")));
    when(projects.save(any(AssessmentProject.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));

    for (String status : statuses) {
      assertThat(service.updateStatus(1L, status).getStatus()).isEqualTo(status);
    }
  }

  @Test
  void rejectsActivatingProjectWhenAuthorizationExpired() {
    AssessmentProject project = project("DRAFT");
    project.setAuthorizationExpiresAt(Instant.now().minusSeconds(60));
    project.setAuthorizationValidFrom(Instant.now().minusSeconds(3600));
    when(projects.findById(1L)).thenReturn(Optional.of(project));

    assertThatThrownBy(() -> service.updateStatus(1L, "ACTIVE"))
        .isInstanceOf(ApiException.class)
        .hasMessage("项目授权已过期或尚未生效");
    verify(projects, never()).save(any(AssessmentProject.class));
  }

  @Test
  void rejectsActivatingProjectWhenAuthorizationNotYetValid() {
    AssessmentProject project = project("DRAFT");
    project.setAuthorizationValidFrom(Instant.now().plusSeconds(60));
    project.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    when(projects.findById(1L)).thenReturn(Optional.of(project));

    assertThatThrownBy(() -> service.updateStatus(1L, "ACTIVE"))
        .isInstanceOf(ApiException.class)
        .hasMessage("项目授权已过期或尚未生效");
    verify(projects, never()).save(any(AssessmentProject.class));
  }

  @Test
  void allowsActivatingProjectWithValidAuthorization() {
    AssessmentProject project = project("DRAFT");
    when(projects.findById(1L)).thenReturn(Optional.of(project));
    when(projects.save(any(AssessmentProject.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));

    assertThat(service.updateStatus(1L, "ACTIVE").getStatus()).isEqualTo("ACTIVE");
    verify(projects).save(any(AssessmentProject.class));
  }

  @Test
  void rejectsUnsupportedProjectStatusBeforeLoadingProject() {
    assertThatThrownBy(() -> service.updateStatus(1L, "UNKNOWN"))
        .isInstanceOf(ApiException.class)
        .hasMessage("不支持的项目状态");
    verify(projects, never()).findById(1L);
  }

  @Test
  void addsAuthorizedTargetAndRecordsAudit() {
    when(projects.findById(1L)).thenReturn(Optional.of(project("DRAFT")));
    when(targets.existsById(2L)).thenReturn(true);
    when(links.findByProjectIdAndTargetId(1L, 2L)).thenReturn(Optional.empty());
    when(links.save(any(ProjectTarget.class))).thenAnswer(invocation -> invocation.getArgument(0));

    ProjectTarget link = service.addTarget(1L, 2L);

    assertThat(link.getProjectId()).isEqualTo(1L);
    assertThat(link.getTargetId()).isEqualTo(2L);
    verify(audit).record("ADD_PROJECT_TARGET", "PROJECT", 1L, "targetId=2", "SUCCESS");
  }

  @Test
  void rejectsMissingAuthorizedTarget() {
    when(projects.findById(1L)).thenReturn(Optional.of(project("DRAFT")));
    when(targets.existsById(2L)).thenReturn(false);

    assertThatThrownBy(() -> service.addTarget(1L, 2L))
        .isInstanceOf(ApiException.class)
        .hasMessage("授权目标不存在");
    verify(links, never()).save(any(ProjectTarget.class));
  }

  @Test
  void rejectsDuplicateProjectTarget() {
    when(projects.findById(1L)).thenReturn(Optional.of(project("DRAFT")));
    when(targets.existsById(2L)).thenReturn(true);
    when(links.findByProjectIdAndTargetId(1L, 2L))
        .thenReturn(Optional.of(new ProjectTarget(1L, 2L)));

    assertThatThrownBy(() -> service.addTarget(1L, 2L))
        .isInstanceOf(ApiException.class)
        .hasMessage("目标已在项目中");
    verify(links, never()).save(any(ProjectTarget.class));
  }

  @Test
  void removesExistingProjectTargetAndRecordsAudit() {
    when(projects.findById(1L)).thenReturn(Optional.of(project("DRAFT")));
    when(links.findByProjectIdAndTargetId(1L, 2L))
        .thenReturn(Optional.of(new ProjectTarget(1L, 2L)));

    service.removeTarget(1L, 2L);

    verify(links).deleteByProjectIdAndTargetId(1L, 2L);
    verify(audit).record("REMOVE_PROJECT_TARGET", "PROJECT", 1L, "targetId=2", "SUCCESS");
  }

  @Test
  void rejectsRemovingTargetOutsideProject() {
    when(projects.findById(1L)).thenReturn(Optional.of(project("DRAFT")));
    when(links.findByProjectIdAndTargetId(1L, 2L)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.removeTarget(1L, 2L))
        .isInstanceOf(ApiException.class)
        .hasMessage("项目未包含该目标");
    verify(links, never()).deleteByProjectIdAndTargetId(1L, 2L);
  }

  @Test
  void validatesActiveAuthorizedProjectTarget() {
    when(projects.findById(1L)).thenReturn(Optional.of(project("ACTIVE")));
    when(links.findByProjectIdAndTargetId(1L, 2L))
        .thenReturn(Optional.of(new ProjectTarget(1L, 2L)));

    assertThatCode(() -> service.validateProjectTarget(1L, 2L)).doesNotThrowAnyException();
  }

  @Test
  void membershipValidationIgnoresStatusAndAuthorizationWindow() {
    AssessmentProject project = project("ARCHIVED");
    project.setAuthorizationExpiresAt(Instant.now().minusSeconds(60));
    when(projects.findById(1L)).thenReturn(Optional.of(project));
    when(links.findByProjectIdAndTargetId(1L, 2L))
        .thenReturn(Optional.of(new ProjectTarget(1L, 2L)));

    assertThatCode(() -> service.validateProjectTargetMembership(1L, 2L))
        .doesNotThrowAnyException();
  }

  @Test
  void rejectsTargetOutsideProject() {
    when(projects.findById(1L)).thenReturn(Optional.of(project("ACTIVE")));
    when(links.findByProjectIdAndTargetId(1L, 2L)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service.validateProjectTarget(1L, 2L))
        .isInstanceOf(ApiException.class)
        .hasMessage("目标不属于该评估项目");
  }

  @Test
  void rejectsNullTargetWithoutRepositoryLookup() {
    when(projects.findById(1L)).thenReturn(Optional.of(project("ACTIVE")));

    assertThatThrownBy(() -> service.validateProjectTarget(1L, null))
        .isInstanceOf(ApiException.class)
        .hasMessage("目标不属于该评估项目");
    verify(links, never()).findByProjectIdAndTargetId(1L, null);
  }

  @Test
  void rejectsInactiveProjectBeforeTargetMembershipCheck() {
    when(projects.findById(1L)).thenReturn(Optional.of(project("DRAFT")));

    assertThatThrownBy(() -> service.validateProjectTarget(1L, 2L))
        .isInstanceOf(ApiException.class)
        .hasMessage("项目未处于进行中状态");
    verify(links, never()).findByProjectIdAndTargetId(1L, 2L);
  }

  @Test
  void rejectsProjectOutsideAuthorizationWindow() {
    AssessmentProject project = project("ACTIVE");
    project.setAuthorizationValidFrom(Instant.now().plusSeconds(60));
    project.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    when(projects.findById(1L)).thenReturn(Optional.of(project));

    assertThatThrownBy(() -> service.validateProjectTarget(1L, 2L))
        .isInstanceOf(ApiException.class)
        .hasMessage("项目授权已过期或尚未生效");
    verify(links, never()).findByProjectIdAndTargetId(1L, 2L);
  }

  @Test
  void summarizesTargetsTasksFindingsRetestsAndAudits() {
    AssessmentProject project = project("ACTIVE");
    SecurityTask originalTask = task(10L, null);
    SecurityTask retestTask = task(11L, 10L);
    Finding vulnerability = finding("HIGH", "nuclei", "CVE-2026-0001");
    Finding information = finding("INFO", "tcp_ports", null);
    when(projects.findById(1L)).thenReturn(Optional.of(project));
    when(tasks.findAllByProjectIdOrderByCreatedAtAsc(1L))
        .thenReturn(List.of(originalTask, retestTask));
    when(findings.findAllByTaskIdInOrderByCreatedAtAsc(List.of(10L, 11L)))
        .thenReturn(List.of(vulnerability, information));
    when(links.countByProjectId(1L)).thenReturn(3L);
    when(auditLogs.countByProjectId(1L, "1")).thenReturn(4L);

    ProjectDtos.Summary summary = service.summary(1L);

    assertThat(summary.project()).isSameAs(project);
    assertThat(summary.targetCount()).isEqualTo(3L);
    assertThat(summary.taskCount()).isEqualTo(2L);
    assertThat(summary.vulnerabilityCount()).isEqualTo(1L);
    assertThat(summary.informationalCount()).isEqualTo(1L);
    assertThat(summary.retestCount()).isEqualTo(1L);
    assertThat(summary.auditCount()).isEqualTo(4L);
  }

  @Test
  void skipsFindingQueryWhenProjectHasNoTasks() {
    when(projects.findById(1L)).thenReturn(Optional.of(project("ACTIVE")));
    when(tasks.findAllByProjectIdOrderByCreatedAtAsc(1L)).thenReturn(List.of());

    ProjectDtos.Summary summary = service.summary(1L);

    assertThat(summary.taskCount()).isZero();
    assertThat(summary.vulnerabilityCount()).isZero();
    assertThat(summary.informationalCount()).isZero();
    verify(findings, never()).findAllByTaskIdInOrderByCreatedAtAsc(any());
  }

  @Test
  void loadsProjectAuditsWithExistingLimitAndOrder() {
    AuditLog log = new AuditLog();
    when(projects.findById(1L)).thenReturn(Optional.of(project("ACTIVE")));
    when(auditLogs.findTop100ByResourceTypeAndResourceIdOrderByCreatedAtDesc("PROJECT", "1"))
        .thenReturn(List.of(log));

    assertThat(service.projectAudits(1L)).containsExactly(log);
  }

  private AssessmentProject project(String status) {
    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    project.setStatus(status);
    project.setAuthorizationValidFrom(Instant.now().minusSeconds(60));
    project.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    return project;
  }

  private SecurityTask task(Long id, Long sourceTaskId) {
    SecurityTask task = new SecurityTask();
    task.setId(id);
    task.setSourceTaskId(sourceTaskId);
    task.setSourceFindingId(sourceTaskId == null ? null : 100L + id);
    return task;
  }

  private Finding finding(String severity, String sourceTool, String vulnerabilityCode) {
    Finding finding = new Finding();
    finding.setSeverity(severity);
    finding.setSourceTool(sourceTool);
    finding.setVulnerabilityCode(vulnerabilityCode);
    return finding;
  }

  private void authenticateAsAdmin() {
    authenticateAs("admin", "ROLE_ADMIN");
  }

  private void authenticateAs(String username) {
    authenticateAs(username, "ROLE_USER");
  }

  private void authenticateAs(String username, String role) {
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(
                username, null, List.of(new SimpleGrantedAuthority(role))));
  }
}
