package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** AI 会话列表按项目归属过滤（防跨用户对话泄露）——Round 37。 */
@DisplayName("AI 会话列表归属过滤（Round 37）")
class AiConversationListAccessTests {

  private Map<String, Object> thread(long projectId, String id) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("id", id);
    m.put("projectId", projectId);
    m.put("messages", List.of());
    return m;
  }

  private AiController controller(ProjectAuthorizationService auth, AiConversationMemoryService mem) {
    return new AiController(
        mock(AiPlanningService.class),
        mock(AiAnswerService.class),
        mock(AgentOrchestrator.class),
        mock(AiAgentRuntimeClient.class),
        mock(AgentWorkflowSpecService.class),
        mock(AiWorkflowSuggestService.class),
        new ObjectMapper(),
        auth,
        mock(AssessmentProjectService.class),
        mem);
  }

  @Test
  @DisplayName("CL-1 非管理员只见本项目对话线程")
  void filtersToAccessibleProjects() {
    ProjectAuthorizationService auth = mock(ProjectAuthorizationService.class);
    AiConversationMemoryService mem = mock(AiConversationMemoryService.class);
    when(auth.isAdmin()).thenReturn(false);
    when(auth.accessibleProjectIds()).thenReturn(List.of(5L));
    when(mem.listAllPersistedThreads())
        .thenReturn(List.of(thread(5L, "mine"), thread(9L, "other")));

    var result = controller(auth, mem).listConversations();
    assertThat(result).extracting(m -> m.get("id")).containsExactly("mine");
  }

  @Test
  @DisplayName("CL-2 管理员可见全部对话线程")
  void adminSeesAll() {
    ProjectAuthorizationService auth = mock(ProjectAuthorizationService.class);
    AiConversationMemoryService mem = mock(AiConversationMemoryService.class);
    when(auth.isAdmin()).thenReturn(true);
    when(mem.listAllPersistedThreads())
        .thenReturn(List.of(thread(5L, "a"), thread(9L, "b")));

    var result = controller(auth, mem).listConversations();
    assertThat(result).hasSize(2);
  }

  @Test
  @DisplayName("CL-5 非管理员不显示无项目归属(null)孤立线程")
  void nonAdminHidesOrphanThreads() {
    ProjectAuthorizationService auth = mock(ProjectAuthorizationService.class);
    AiConversationMemoryService mem = mock(AiConversationMemoryService.class);
    when(auth.isAdmin()).thenReturn(false);
    when(auth.accessibleProjectIds()).thenReturn(List.of(5L));
    Map<String, Object> orphan = new LinkedHashMap<>();
    orphan.put("id", "orphan"); // 无 projectId
    orphan.put("messages", List.of());
    when(mem.listAllPersistedThreads()).thenReturn(List.of(thread(5L, "mine"), orphan));

    var result = controller(auth, mem).listConversations();
    assertThat(result).extracting(m -> m.get("id")).containsExactly("mine");
  }

  @Test
  @DisplayName("CL-3 保存到他人项目会话 → 拒绝")
  void saveRejectsOtherProjectThread() {
    ProjectAuthorizationService auth = mock(ProjectAuthorizationService.class);
    AiConversationMemoryService mem = mock(AiConversationMemoryService.class);
    when(mem.scope("s1"))
        .thenReturn(new AiConversationMemoryService.SessionScope(9L, null));
    org.mockito.Mockito.doThrow(new com.bachelor.toolbox.common.ApiException("无权访问"))
        .when(auth).requireAccess(9L);
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> controller(auth, mem).saveConversation("s1", new java.util.LinkedHashMap<>(Map.of("projectId", 9))))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class);
  }

  @Test
  @DisplayName("CL-6 新建会话不声明项目 → 拒绝且不落库")
  void saveRejectsNewSessionWithoutProject() {
    ProjectAuthorizationService auth = mock(ProjectAuthorizationService.class);
    AiConversationMemoryService mem = mock(AiConversationMemoryService.class);
    when(mem.scope("new")).thenReturn(null);

    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> controller(auth, mem).saveConversation("new", new LinkedHashMap<>()))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
        .hasMessageContaining("评估项目");
    org.mockito.Mockito.verify(mem, org.mockito.Mockito.never())
        .saveClientThread(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
  }

  @Test
  @DisplayName("CL-7 新建会话声明可访问项目 → 允许保存")
  void saveAllowsNewSessionWithAccessibleProject() {
    ProjectAuthorizationService auth = mock(ProjectAuthorizationService.class);
    AiConversationMemoryService mem = mock(AiConversationMemoryService.class);
    when(mem.scope("new5")).thenReturn(null);

    controller(auth, mem).saveConversation(
        "new5", new java.util.LinkedHashMap<>(Map.of("projectId", 5)));

    org.mockito.Mockito.verify(mem)
        .saveClientThread(org.mockito.ArgumentMatchers.eq("new5"), org.mockito.ArgumentMatchers.any());
  }

  @Test
  @DisplayName("CL-8 存量孤立线程更新仍放行（兼容既有数据，不外泄给他人）")
  void saveAllowsLegacyOrphanUpdate() {
    ProjectAuthorizationService auth = mock(ProjectAuthorizationService.class);
    AiConversationMemoryService mem = mock(AiConversationMemoryService.class);
    when(mem.scope("legacy"))
        .thenReturn(new AiConversationMemoryService.SessionScope(null, null));

    controller(auth, mem).saveConversation("legacy", new LinkedHashMap<>());

    org.mockito.Mockito.verify(mem)
        .saveClientThread(org.mockito.ArgumentMatchers.eq("legacy"), org.mockito.ArgumentMatchers.any());
  }

  @Test
  @DisplayName("CL-9 客户端省略 id → 落库前补 sessionId 作为主键")
  void saveFillsMissingIdWithSessionId() {
    ProjectAuthorizationService auth = mock(ProjectAuthorizationService.class);
    AiConversationMemoryService mem = mock(AiConversationMemoryService.class);
    when(mem.scope("no-id")).thenReturn(null);

    controller(auth, mem).saveConversation(
        "no-id", new java.util.LinkedHashMap<>(Map.of("projectId", 5)));

    org.mockito.ArgumentCaptor<Map<String, Object>> captor =
        org.mockito.ArgumentCaptor.forClass(Map.class);
    org.mockito.Mockito.verify(mem)
        .saveClientThread(org.mockito.ArgumentMatchers.eq("no-id"), captor.capture());
    assertThat(captor.getValue()).containsEntry("id", "no-id");
  }

  @Test
  @DisplayName("CL-10 客户端自带 id → 原值保留，不被覆盖")
  void saveKeepsClientSuppliedId() {
    ProjectAuthorizationService auth = mock(ProjectAuthorizationService.class);
    AiConversationMemoryService mem = mock(AiConversationMemoryService.class);
    when(mem.scope("has-id")).thenReturn(null);
    Map<String, Object> payload = new LinkedHashMap<>(Map.of("projectId", 5, "id", "client-thread-1"));

    controller(auth, mem).saveConversation("has-id", payload);

    org.mockito.ArgumentCaptor<Map<String, Object>> captor =
        org.mockito.ArgumentCaptor.forClass(Map.class);
    org.mockito.Mockito.verify(mem)
        .saveClientThread(org.mockito.ArgumentMatchers.eq("has-id"), captor.capture());
    assertThat(captor.getValue()).containsEntry("id", "client-thread-1");
  }

  @Test
  @DisplayName("CL-4 删除他人项目会话 → 拒绝")
  void deleteRejectsOtherProjectThread() {
    ProjectAuthorizationService auth = mock(ProjectAuthorizationService.class);
    AiConversationMemoryService mem = mock(AiConversationMemoryService.class);
    when(mem.scope("s2"))
        .thenReturn(new AiConversationMemoryService.SessionScope(9L, null));
    org.mockito.Mockito.doThrow(new com.bachelor.toolbox.common.ApiException("无权访问"))
        .when(auth).requireAccess(9L);
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () -> controller(auth, mem).deleteConversation("s2"))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class);
  }
}
