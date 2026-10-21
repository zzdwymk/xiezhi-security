package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class AiPlanningQuotaTests {
  private static final List<String> ACTIVE = List.of("BLOCKED", "PENDING", "RUNNING");
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final AiAgentRequest request = new AiAgentRequest(
      7L, 9L, "quota-test", "quota-test", false, null, List.of(), "standard", "quota-turn");

  @Test
  void defaultEmptyTargetAdvertisesFourActionsInsteadOfTwenty() {
    assertThat(quota(20, 4, 0, 0)).isEqualTo(Map.of("maxActions", 4, "usedActions", 0));
    verify(tasks).countByProjectIdAndStatusIn(7L, ACTIVE);
    verify(tasks).countByTargetIdAndStatusIn(9L, ACTIVE);
  }

  @Test
  void targetOccupancyReducesThePlanningBudget() {
    assertThat(quota(20, 4, 10, 3)).isEqualTo(Map.of("maxActions", 4, "usedActions", 3));
  }

  @Test
  void projectOccupancyCanBeTheTighterLimit() {
    assertThat(quota(20, 4, 19, 0)).isEqualTo(Map.of("maxActions", 4, "usedActions", 3));
  }

  @Test
  void aSmallerProjectLimitAlsoAppliesToAnEmptyTarget() {
    assertThat(quota(2, 4, 0, 0)).isEqualTo(Map.of("maxActions", 2, "usedActions", 0));
  }

  @Test
  void dispatchBatchLimitAppliesEvenWhenBothConfiguredQuotasAreLarger() {
    assertThat(quota(20, 12, 2, 2)).isEqualTo(Map.of("maxActions", 8, "usedActions", 0));
  }

  @Test
  void usageBeyondEitherLimitClampsRemainingCapacityToZero() {
    assertThat(quota(20, 4, 21, 0)).isEqualTo(Map.of("maxActions", 4, "usedActions", 4));
    assertThat(quota(20, 4, 10, 5)).isEqualTo(Map.of("maxActions", 4, "usedActions", 4));
  }

  @Test
  void exactRemainingCapacityIsNotConfusedWithTheSmallerAbsoluteLimit() {
    assertThat(quota(20, 4, 18, 1)).isEqualTo(Map.of("maxActions", 4, "usedActions", 2));
  }

  @Test
  void runtimeRequestActuallyCarriesTheCombinedQuotaSnapshot() throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    AtomicReference<JsonNode> captured = new AtomicReference<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/agent/stream", exchange -> {
      captured.set(mapper.readTree(exchange.getRequestBody()));
      exchange.sendResponseHeaders(400, -1);
      exchange.close();
    });
    server.start();
    try {
      AssessmentProjectService projects = mock(AssessmentProjectService.class);
      TargetService targets = mock(TargetService.class);
      AssessmentProject project = new AssessmentProject();
      project.setStatus("ACTIVE");
      AuthorizedTarget target = new AuthorizedTarget();
      target.setId(9L);
      target.setTargetValue("127.0.0.1");
      target.setAllowedPorts("80,443");
      when(projects.get(7L)).thenReturn(project);
      when(targets.getCurrentlyAuthorized(9L)).thenReturn(target);
      when(tasks.countByProjectIdAndStatusIn(7L, ACTIVE)).thenReturn(19L);
      when(tasks.countByTargetIdAndStatusIn(9L, ACTIVE)).thenReturn(0L);
      int port = server.getAddress().getPort();
      AiAgentRuntimeClient client = new AiAgentRuntimeClient(mapper, projects, targets, tasks,
          mock(AgentWorkflowSpecService.class), true, "http://127.0.0.1:" + port, port,
          "test-token", "test-signing-secret", 30, 20, 4, 3, null);
      AiAgentRequest bound = new AiAgentRequest(7L, 9L, "quota-test", "quota-test", false,
          null, List.of(), "standard", "quota-turn", "quota-workflow", 1L,
          "sha256:" + "a".repeat(64), "quota-node", "quota-node-run");

      assertThatThrownBy(() -> client.plan(bound, "quota-test", null))
          .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
      assertThat(captured.get()).isNotNull();
      assertThat(captured.get().at("/authorization/quota/maxActions").intValue()).isEqualTo(4);
      assertThat(captured.get().at("/authorization/quota/usedActions").intValue()).isEqualTo(3);
      try (var state = client.withConversationState(Map.of("projectId", 7L, "targetId", 9L,
          "planAvailable", true, "approvalRequired", true))) {
        assertThatThrownBy(() -> client.plan(bound, "contextual follow-up", null))
            .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
        assertThat(captured.get().at("/conversationState/planAvailable").booleanValue()).isTrue();
        try (var wrongScope = client.withConversationState(Map.of("projectId", 7L, "targetId", 99L))) {
          assertThatThrownBy(() -> client.plan(bound, "wrong target", null))
              .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class).hasMessageContaining("会话状态");
        }
        assertThatThrownBy(() -> client.plan(bound, "restored parent state", null))
            .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
        assertThat(captured.get().at("/conversationState/targetId").longValue()).isEqualTo(9L);
      }
      assertThatThrownBy(() -> client.plan(bound, "independent next turn", null))
          .isInstanceOf(AiAgentRuntimeClient.RuntimeProtocolException.class);
      assertThat(captured.get().has("conversationState")).isFalse();
    } finally {
      server.stop(0);
    }
  }

  private Map<String, Integer> quota(int projectLimit, int targetLimit,
      long projectUsed, long targetUsed) {
    when(tasks.countByProjectIdAndStatusIn(7L, ACTIVE)).thenReturn(projectUsed);
    when(tasks.countByTargetIdAndStatusIn(9L, ACTIVE)).thenReturn(targetUsed);
    AiAgentRuntimeClient client = new AiAgentRuntimeClient(new ObjectMapper(),
        mock(AssessmentProjectService.class), mock(TargetService.class), tasks,
        mock(AgentWorkflowSpecService.class), false, "http://127.0.0.1:8090", 8090,
        "", "", 30, projectLimit, targetLimit, 3, null);
    return client.planningQuota(request);
  }
}
