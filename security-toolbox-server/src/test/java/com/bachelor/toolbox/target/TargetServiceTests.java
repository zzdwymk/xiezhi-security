package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.project.AssessmentProject;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

class TargetServiceTests {
  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void listsTargetsWithBoundedDeterministicPageable() {
    AuthorizedTargetRepository repository = mock(AuthorizedTargetRepository.class);
    AuditService auditService = mock(AuditService.class);
    AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
    ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    List<AuthorizedTarget> targets = List.of(new AuthorizedTarget(), new AuthorizedTarget());
    when(authorization.isAdmin()).thenReturn(true);
    when(repository.findAll(any(Pageable.class))).thenReturn(new PageImpl<>(targets));
    TargetService service =
        new TargetService(
            repository,
            auditService,
            new PortRangeParser(),
            projects,
            projectTargets,
            authorization,
            65535);

    assertThat(service.list()).containsExactlyElementsOf(targets);

    ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
    verify(repository).findAll(pageableCaptor.capture());
    Pageable pageable = pageableCaptor.getValue();
    assertThat(pageable.getPageNumber()).isZero();
    assertThat(pageable.getPageSize()).isLessThanOrEqualTo(1000);
    assertThat(pageable.getSort().getOrderFor("createdAt"))
        .isEqualTo(org.springframework.data.domain.Sort.Order.desc("createdAt"));
    assertThat(pageable.getSort().getOrderFor("id"))
        .isEqualTo(org.springframework.data.domain.Sort.Order.desc("id"));
  }

  @Test
  void ordinaryUserListFiltersByProjectOwnerBeforeApplyingTheGlobalLimit() {
    AuthorizedTargetRepository repository = mock(AuthorizedTargetRepository.class);
    AuditService auditService = mock(AuditService.class);
    AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
    ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    AuthorizedTarget ownTarget = new AuthorizedTarget();
    when(authorization.isAdmin()).thenReturn(false);
    when(authorization.currentUsername()).thenReturn("alice");
    when(repository.findAccessibleByProjectOwner(
            org.mockito.ArgumentMatchers.eq("alice"), any(Pageable.class)))
        .thenReturn(new PageImpl<>(List.of(ownTarget)));
    TargetService service =
        new TargetService(
            repository,
            auditService,
            new PortRangeParser(),
            projects,
            projectTargets,
            authorization,
            65535);

    assertThat(service.list()).containsExactly(ownTarget);

    ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
    verify(repository)
        .findAccessibleByProjectOwner(
            org.mockito.ArgumentMatchers.eq("alice"), pageableCaptor.capture());
    assertThat(pageableCaptor.getValue().getPageSize()).isLessThanOrEqualTo(1000);
    verify(repository, never()).findAll(any(Pageable.class));
    verify(projectTargets, never()).findByTargetId(any());
  }

  @Test
  void storesFullAuthorizationAsCompactRange() {
    AuthorizedTargetRepository repository = mock(AuthorizedTargetRepository.class);
    AuditService auditService = mock(AuditService.class);
    AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
    ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
    when(repository.save(any(AuthorizedTarget.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));
    when(projects.existsById(1L)).thenReturn(true);
    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    project.setOwner("admin");
    when(projects.findById(1L)).thenReturn(Optional.of(project));
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(
                "admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
    TargetService service =
        new TargetService(
            repository,
            auditService,
            new PortRangeParser(),
            projects,
            projectTargets,
            new ProjectAuthorizationService(projects),
            65535);

    AuthorizedTarget saved =
        service.create(
            new TargetRequest(
                "lab",
                "127.0.0.1",
                "IP",
                "written authorization",
                "1-65535",
                true,
                null,
                null,
                1L));

    assertThat(saved.getAllowedPorts()).isEqualTo("1-65535");
  }

  @Test
  void rejectsMalformedDomainBeforePersistingAuthorizationScope() {
    AuthorizedTargetRepository repository = mock(AuthorizedTargetRepository.class);
    AuditService auditService = mock(AuditService.class);
    AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
    ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    project.setOwner("admin");
    when(projects.findById(1L)).thenReturn(Optional.of(project));
    authenticateAsAdmin();
    TargetService service =
        new TargetService(
            repository,
            auditService,
            new PortRangeParser(),
            projects,
            projectTargets,
            new ProjectAuthorizationService(projects),
            65535);

    assertThatThrownBy(
            () ->
                service.create(
                    new TargetRequest(
                        "bad",
                        "not a valid host",
                        "DOMAIN",
                        "written authorization",
                        "80",
                        true,
                        null,
                        null,
                        1L)))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
        .hasMessage("域名格式不正确：请填写不含空格、协议或路径的主机名");
    verify(repository, never()).save(any(AuthorizedTarget.class));
  }

  @Test
  void rejectsCreatingTargetForAnotherOwnersProject() {
    AuthorizedTargetRepository repository = mock(AuthorizedTargetRepository.class);
    AuditService auditService = mock(AuditService.class);
    AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
    ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    project.setOwner("bob");
    when(projects.findById(1L)).thenReturn(Optional.of(project));
    authenticateAs("alice");
    TargetService service =
        new TargetService(
            repository,
            auditService,
            new PortRangeParser(),
            projects,
            projectTargets,
            new ProjectAuthorizationService(projects),
            65535);

    assertThatThrownBy(
            () ->
                service.create(
                    new TargetRequest(
                        "lab",
                        "127.0.0.1",
                        "IP",
                        "written authorization",
                        "80",
                        true,
                        null,
                        null,
                        1L)))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
        .hasMessage("无权访问该评估项目");
    org.mockito.Mockito.verify(repository, org.mockito.Mockito.never())
        .save(any(AuthorizedTarget.class));
  }

  @Test
  void deletesProjectLinksTogetherWithTarget() {
    AuthorizedTargetRepository repository = mock(AuthorizedTargetRepository.class);
    AuditService auditService = mock(AuditService.class);
    AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
    ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setTargetValue("127.0.0.1");
    ProjectTarget first = new ProjectTarget(1L, 7L);
    ProjectTarget second = new ProjectTarget(2L, 7L);
    when(repository.findById(7L)).thenReturn(Optional.of(target));
    when(authorization.isAdmin()).thenReturn(true);
    when(projectTargets.findByTargetId(7L)).thenReturn(List.of(first, second));
    TargetService service =
        new TargetService(
            repository,
            auditService,
            new PortRangeParser(),
            projects,
            projectTargets,
            authorization,
            65535);

    service.delete(7L);

    verify(projectTargets).deleteAll(List.of(first, second));
    verify(repository).delete(target);
    verify(auditService).record("DELETE_TARGET", "TARGET", 7L, "127.0.0.1", "SUCCESS");
  }

  private void authenticateAs(String username) {
    SecurityContextHolder.getContext()
        .setAuthentication(
        new UsernamePasswordAuthenticationToken(
            username, null, List.of(new SimpleGrantedAuthority("ROLE_USER"))));
  }

  private void authenticateAsAdmin() {
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(
                "admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
  }
}
