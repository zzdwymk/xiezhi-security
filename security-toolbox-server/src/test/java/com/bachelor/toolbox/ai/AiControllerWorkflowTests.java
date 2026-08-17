package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AiControllerWorkflowTests {
  private AgentOrchestrator orchestrator;
  private AgentWorkflowSpecService workflowSpecs;
  private AiController controller;

  @BeforeEach
  void setUp() {
    orchestrator = mock(AgentOrchestrator.class);
    workflowSpecs = mock(AgentWorkflowSpecService.class);
    controller =
        new AiController(
            mock(AiPlanningService.class),
            mock(AiAnswerService.class),
            orchestrator,
            mock(AiAgentRuntimeClient.class),
            workflowSpecs,
            mock(AiWorkflowSuggestService.class),
            new ObjectMapper().findAndRegisterModules(),
            mock(ProjectAuthorizationService.class),
            mock(AssessmentProjectService.class));
  }

  @Test
  void workflowEndpointsRequireAndForwardProjectScope() {
    Map<String, Object> response = Map.of("scopeId", 101L, "revision", 1L);
    when(workflowSpecs.read(101L)).thenReturn(response);
    when(workflowSpecs.save(eq(101L), any())).thenReturn(response);

    assertEquals(response, controller.getWorkflow(101L));
    assertEquals(response, controller.saveWorkflow(101L, Map.of("steps", List.of())));

    verify(workflowSpecs).read(101L);
    verify(workflowSpecs).save(101L, Map.of("steps", List.of()));
  }

  @Test
  void clearAgentSessionReturnsTheOrchestratorResult() {
    when(orchestrator.clearSession("session-1")).thenReturn(false);

    assertEquals(
        Map.of("sessionId", "session-1", "cleared", false),
        controller.clearAgentSession("session-1"));

    verify(orchestrator).clearSession("session-1");
  }

  @Test
  void agentTurnRunsWithOneFrozenWorkflowRevision() {
    String digest = "sha256:" + "a".repeat(64);
    AgentWorkflowSpecService.WorkflowSnapshot snapshot =
        new AgentWorkflowSpecService.WorkflowSnapshot(
            "workflow-101",
            101L,
            7L,
            digest,
            "alice",
            Instant.parse("2026-08-08T00:00:00Z"),
            Map.of("version", 1, "steps", List.of()),
            List.of());
    AiAgentRequest request =
        new AiAgentRequest(
            101L,
            12L,
            "session-1",
            "检查目标",
            false,
            null,
            List.of(),
            "agent",
            "turn-1",
            "workflow-101",
            7L,
            digest);
    when(workflowSpecs.freezeSnapshot(101L, "workflow-101", 7L, digest)).thenReturn(snapshot);
    doCallRealMethod()
        .when(workflowSpecs)
        .withSnapshot(
            eq(snapshot), org.mockito.ArgumentMatchers.<Supplier<AiAgentResponse>>any());
    when(orchestrator.run(any(AiAgentRequest.class))).thenReturn(null);

    controller.agent(request);

    ArgumentCaptor<AiAgentRequest> captured = ArgumentCaptor.forClass(AiAgentRequest.class);
    verify(orchestrator).run(captured.capture());
    assertEquals("workflow-101", captured.getValue().workflowId());
    assertEquals(7L, captured.getValue().workflowRevision());
    assertEquals(digest, captured.getValue().workflowDigest());
    verify(workflowSpecs)
        .withSnapshot(
            eq(snapshot), org.mockito.ArgumentMatchers.<Supplier<AiAgentResponse>>any());
  }

  @Test
  void everyStreamEventCarriesTheFrozenWorkflowIdentity() throws Exception {
    String digest = "sha256:" + "b".repeat(64);
    AgentWorkflowSpecService.WorkflowSnapshot snapshot =
        new AgentWorkflowSpecService.WorkflowSnapshot(
            "workflow-stream",
            101L,
            3L,
            digest,
            "alice",
            Instant.parse("2026-08-08T00:00:00Z"),
            Map.of("version", 1, "steps", List.of()),
            List.of());
    AiAgentRequest request =
        new AiAgentRequest(
            101L,
            12L,
            "session-stream",
            "检查目标",
            false,
            null,
            List.of(),
            "agent",
            "turn-stream");
    when(workflowSpecs.freezeSnapshot(101L, null, null, null)).thenReturn(snapshot);
    doCallRealMethod()
        .when(workflowSpecs)
        .withSnapshot(eq(snapshot), any(Runnable.class));
    doCallRealMethod()
        .when(workflowSpecs)
        .withSnapshot(
            eq(snapshot), org.mockito.ArgumentMatchers.<Supplier<AiAgentResponse>>any());
    when(orchestrator.run(any(AiAgentRequest.class), any()))
        .thenAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              Consumer<AiAgentEvent> sink = invocation.getArgument(1);
              sink.accept(
                  new AiAgentEvent(
                      1,
                      2,
                      "run-1",
                      1,
                      "policy-1",
                      "state",
                      AgentPhase.ENGAGEMENT,
                      "RUNNING",
                      "running",
                      Instant.parse("2026-08-08T00:00:01Z"),
                      Map.of()));
              return null;
            });

    var response = controller.agentStream(request);
    assertNotNull(response.getBody());
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    response.getBody().writeTo(output);
    @SuppressWarnings("unchecked")
    Map<String, Object> event =
        new ObjectMapper().readValue(output.toString(StandardCharsets.UTF_8).strip(), Map.class);
    @SuppressWarnings("unchecked")
    Map<String, Object> data = (Map<String, Object>) event.get("data");
    assertEquals("workflow-stream", data.get("workflowId"));
    assertEquals(3, data.get("workflowRevision"));
    assertEquals(digest, data.get("workflowDigest"));
  }
}
