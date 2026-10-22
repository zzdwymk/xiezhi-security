package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The chat reads this endpoint to say what it is waiting on, so it must be scoped and safe. */
class AiSessionStatusControllerTests {
  private AiPlanningService service;
  private AiAnswerService answerService;
  private AgentOrchestrator agentOrchestrator;
  private AiAgentRuntimeClient runtimeClient;
  private AgentWorkflowSpecService workflowSpecs;
  private AiWorkflowSuggestService workflowSuggestService;
  private ProjectAuthorizationService authorization;
  private AssessmentProjectService projects;
  private AiConversationMemoryService memoryService;
  private CrossTurnRecoveryService recoveryService;
  private AiController controller;

  @BeforeEach
  void setUp() {
    service = mock(AiPlanningService.class);
    answerService = mock(AiAnswerService.class);
    agentOrchestrator = mock(AgentOrchestrator.class);
    runtimeClient = mock(AiAgentRuntimeClient.class);
    workflowSpecs = mock(AgentWorkflowSpecService.class);
    workflowSuggestService = mock(AiWorkflowSuggestService.class);
    authorization = mock(ProjectAuthorizationService.class);
    projects = mock(AssessmentProjectService.class);
    memoryService = mock(AiConversationMemoryService.class);
    recoveryService = mock(CrossTurnRecoveryService.class);
    controller =
        new AiController(
            service,
            answerService,
            agentOrchestrator,
            runtimeClient,
            workflowSpecs,
            workflowSuggestService,
            new ObjectMapper(),
            authorization,
            projects,
            memoryService);
    controller.setRecoveryService(recoveryService);
  }

  @Test
  void statusRequiresProjectAccessBeforeExposingPendingWork() {
    when(memoryService.scope("conversation-1"))
        .thenReturn(new AiConversationMemoryService.SessionScope(7L, 11L));
    when(recoveryService.statusForSession("conversation-1"))
        .thenReturn(
            Map.of(
                "phase",
                "waiting_tasks",
                "tasks",
                List.of(Map.of("id", 31, "toolCode", "tcp_ports", "status", "RUNNING"))));

    Map<String, Object> status = controller.sessionStatus("conversation-1");

    verify(authorization).requireAccess(7L);
    assertThat(status).containsEntry("sessionId", "conversation-1");
    assertThat(status).containsEntry("phase", "waiting_tasks");
    assertThat(status.get("tasks")).isInstanceOf(List.class);
    assertThat((List<?>) status.get("tasks")).hasSize(1);
  }

  @Test
  void statusRefusesASessionOutsideTheCallersProjects() {
    when(memoryService.scope("conversation-1"))
        .thenReturn(new AiConversationMemoryService.SessionScope(7L, 11L));
    org.mockito.Mockito.doThrow(new ApiException("无权访问该项目"))
        .when(authorization)
        .requireAccess(7L);

    assertThatThrownBy(() -> controller.sessionStatus("conversation-1"))
        .isInstanceOf(ApiException.class);

    verifyNoInteractions(recoveryService);
  }

  @Test
  void statusStaysReadableWhenRecoveryIsNotConfigured() {
    // No recovery service wired (optional dependency): the endpoint still answers
    // instead of failing the whole chat view.
    AiController withoutRecovery =
        new AiController(
            service,
            answerService,
            agentOrchestrator,
            runtimeClient,
            workflowSpecs,
            workflowSuggestService,
            new ObjectMapper(),
            authorization,
            projects,
            memoryService);
    when(memoryService.scope("conversation-1")).thenReturn(null);

    Map<String, Object> status = withoutRecovery.sessionStatus("conversation-1");

    assertThat(status).containsEntry("sessionId", "conversation-1").containsEntry("phase", "idle");
  }

  @Test
  void statusReturnsTheBackendPhaseForACompletedSession() {
    when(memoryService.scope("conversation-1"))
        .thenReturn(new AiConversationMemoryService.SessionScope(7L, 11L));
    when(recoveryService.statusForSession("conversation-1")).thenReturn(Map.of("phase", "idle"));

    assertThat(controller.sessionStatus("conversation-1"))
        .containsEntry("phase", "idle")
        .containsEntry("sessionId", "conversation-1");
  }
}
