package com.bachelor.toolbox.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

class ProjectAuthorizationServiceTests {
  private final AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
  private final ProjectAuthorizationService service = new ProjectAuthorizationService(projects);

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void trustedBackgroundScopeCanReuseProjectChecksWithoutInteractiveAuthentication()
      throws Exception {
    AssessmentProject project = project(1L, "alice");
    when(projects.findById(1L)).thenReturn(Optional.of(project));

    AssessmentProject result = service.callWithSystemAccess(() -> service.requireAccess(1L));

    assertThat(result).isSameAs(project);
    assertThat(service.isAdmin()).isFalse();
    assertThatThrownBy(() -> service.requireAccess(1L))
        .isInstanceOf(ApiException.class)
        .hasMessage("请先登录后再继续操作");
  }

  @Test
  void trustedBackgroundScopeIsRestoredAfterFailure() {
    assertThatThrownBy(
            () ->
                service.callWithSystemAccess(
                    () -> {
                      throw new IllegalStateException("测试异常");
                    }))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("测试异常");

    assertThat(service.isAdmin()).isFalse();
    assertThatThrownBy(service::currentUsername)
        .isInstanceOf(ApiException.class)
        .hasMessage("请先登录后再继续操作");
  }

  @Test
  void currentUsernameUsesAuthenticatedUserEntityName() {
    User user = new User();
    user.setUsername("alice");
    user.setRole("USER");
    user.setEnabled(true);
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(
                user, null, List.of(new SimpleGrantedAuthority("ROLE_USER"))));

    assertThat(service.currentUsername()).isEqualTo("alice");
  }

  private AssessmentProject project(Long id, String owner) {
    AssessmentProject project = new AssessmentProject();
    project.setId(id);
    project.setOwner(owner);
    return project;
  }
}
