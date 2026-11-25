package com.bachelor.toolbox.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.ai.AiController;
import com.bachelor.toolbox.ai.AiConversationMemoryService;
import com.bachelor.toolbox.ai.AgentOrchestrator;
import com.bachelor.toolbox.ai.AgentWorkflowSpecService;
import com.bachelor.toolbox.ai.AiAgentRuntimeClient;
import com.bachelor.toolbox.ai.AiAnswerService;
import com.bachelor.toolbox.ai.AiPlanningService;
import com.bachelor.toolbox.ai.AiWorkflowSuggestService;
import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * 第414轮：用真实 ProjectAuthorizationService（不 mock）验证非管理员路径。
 *
 * <p>此前 406/407/412 轮的非管理员结论依赖 mock 授权层；这里把真实 SecurityContext 与真实归属判断接上，
 * 确保“看不到他人项目”“访问他人项目被拒”“列表按归属过滤”是代码事实而非测试假象。
 */
@DisplayName("非管理员归属守卫（Round 414，真实授权逻辑）")
class ProjectAuthorizationRealContextTests {

  @AfterEach
  void clearContext() {
    SecurityContextHolder.clearContext();
  }

  private void loginAs(String username, String role) {
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(
                username, null, List.of(new SimpleGrantedAuthority("ROLE_" + role))));
  }

  private AssessmentProject project(long id, String owner) {
    AssessmentProject project = new AssessmentProject();
    project.setId(id);
    project.setOwner(owner);
    project.setName("项目-" + id);
    return project;
  }

  @Test
  @DisplayName("AU-1 普通用户可访问自有项目，不可访问他人项目")
  void nonAdminCanOnlyAccessOwnProject() {
    AssessmentProjectRepository repository = mock(AssessmentProjectRepository.class);
    when(repository.findById(5L)).thenReturn(Optional.of(project(5L, "auditor2")));
    when(repository.findById(9L)).thenReturn(Optional.of(project(9L, "admin")));
    ProjectAuthorizationService authorization = new ProjectAuthorizationService(repository);
    loginAs("auditor2", "USER");

    assertThat(authorization.isAdmin()).isFalse();
    assertThat(authorization.requireAccess(5L).getId()).isEqualTo(5L);
    assertThatThrownBy(() -> authorization.requireAccess(9L))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("无权访问");
  }

  @Test
  @DisplayName("AU-2 accessibleProjectIds 只返回自有项目")
  void accessibleProjectIdsOnlyOwn() {
    AssessmentProjectRepository repository = mock(AssessmentProjectRepository.class);
    when(repository.findByOwner("auditor2")).thenReturn(List.of(project(5L, "auditor2")));
    ProjectAuthorizationService authorization = new ProjectAuthorizationService(repository);
    loginAs("auditor2", "USER");

    assertThat(authorization.accessibleProjectIds()).containsExactly(5L);
  }

  @Test
  @DisplayName("AU-3 管理员可访问任意项目")
  void adminCanAccessAnyProject() {
    AssessmentProjectRepository repository = mock(AssessmentProjectRepository.class);
    when(repository.findById(9L)).thenReturn(Optional.of(project(9L, "admin")));
    when(repository.findAll()).thenReturn(List.of(project(5L, "auditor2"), project(9L, "admin")));
    ProjectAuthorizationService authorization = new ProjectAuthorizationService(repository);
    loginAs("admin", "ADMIN");

    assertThat(authorization.isAdmin()).isTrue();
    assertThat(authorization.requireAccess(9L).getId()).isEqualTo(9L);
    assertThat(authorization.accessibleProjectIds()).containsExactlyInAnyOrder(5L, 9L);
  }

  @Test
  @DisplayName("AU-4 非管理员列表看不到他人项目的会话线程（真实授权 + 真实过滤）")
  void conversationListFiltersOtherOwnersThreadsWithRealAuthorization() {
    AssessmentProjectRepository repository = mock(AssessmentProjectRepository.class);
    when(repository.findByOwner("auditor2")).thenReturn(List.of(project(5L, "auditor2")));
    ProjectAuthorizationService authorization = new ProjectAuthorizationService(repository);
    AiConversationMemoryService memory = mock(AiConversationMemoryService.class);
    Map<String, Object> mine = new LinkedHashMap<>(Map.of("id", "mine", "projectId", 5L));
    Map<String, Object> others = new LinkedHashMap<>(Map.of("id", "others", "projectId", 9L));
    when(memory.listAllPersistedThreads()).thenReturn(List.of(mine, others));
    AiController controller = new AiController(
        mock(AiPlanningService.class),
        mock(AiAnswerService.class),
        mock(AgentOrchestrator.class),
        mock(AiAgentRuntimeClient.class),
        mock(AgentWorkflowSpecService.class),
        mock(AiWorkflowSuggestService.class),
        new ObjectMapper(),
        authorization,
        mock(AssessmentProjectService.class),
        memory);
    loginAs("auditor2", "USER");

    assertThat(controller.listConversations())
        .extracting(item -> item.get("id"))
        .containsExactly("mine");
  }
}
