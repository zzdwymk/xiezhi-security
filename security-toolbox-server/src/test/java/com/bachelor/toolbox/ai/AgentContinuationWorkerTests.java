package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AgentContinuationWorkerTests {
  private CrossTurnRecoveryService recovery;
  private SecurityTaskRepository tasks;
  private AiAgentRuntimeClient runtime;
  private AgentOrchestrator orchestrator;
  private AgentContinuationExecutionService executions;
  private AgentContinuationWorker worker;

  @BeforeEach
  void setUp() {
    recovery = mock(CrossTurnRecoveryService.class);
    tasks = mock(SecurityTaskRepository.class);
    runtime = mock(AiAgentRuntimeClient.class);
    orchestrator = mock(AgentOrchestrator.class);
    executions = mock(AgentContinuationExecutionService.class);
    ProjectAuthorizationService authorization =
        new ProjectAuthorizationService(mock(AssessmentProjectRepository.class));
    AgentWorkflowSpecService workflows =
        new AgentWorkflowSpecService(
            mock(AgentWorkflowSpecRepository.class), new ObjectMapper(), authorization);
    worker =
        new AgentContinuationWorker(
            recovery,
            tasks,
            runtime,
            orchestrator,
            executions,
            workflows,
            authorization,
            true);
  }

  @Test
  void crashFenceIsSafelyClosedWithoutCallingOrchestratorAgain() {
    CrossTurnRecoveryService.ContinuationClaim claim = claim();
    arrangeReady(claim);
    when(executions.prepare(claim))
        .thenReturn(
            new AgentContinuationExecutionService.Preparation(
                AgentContinuationExecutionService.Preparation.Kind.SKIP,
                null,
                AgentContinuationExecution.STARTED));

    worker.drain();

    verify(executions)
        .skip(claim, "IN_DOUBT", "PREVIOUS_EXECUTION_" + AgentContinuationExecution.STARTED);
    verify(orchestrator, never()).run(any(AiAgentRequest.class));
  }

  @Test
  void executesOneReadOnlyTurnWithStableValidContinuationTurnId() {
    CrossTurnRecoveryService.ContinuationClaim claim = claim();
    arrangeReady(claim);
    when(executions.prepare(claim))
        .thenReturn(
            new AgentContinuationExecutionService.Preparation(
                AgentContinuationExecutionService.Preparation.Kind.EXECUTE,
                null,
                AgentContinuationExecution.STARTED));
    AiAgentResponse response = response();
    when(orchestrator.run(any(AiAgentRequest.class))).thenReturn(response);
    when(executions.execute(any(), any()))
        .thenAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              Supplier<AiAgentResponse> operation = invocation.getArgument(1);
              return operation.get();
            });

    worker.drain();

    ArgumentCaptor<AiAgentRequest> request = ArgumentCaptor.forClass(AiAgentRequest.class);
    verify(orchestrator).run(request.capture());
    assertThat(request.getValue().turnId()).matches("resume-[0-9a-f]{48}");
    assertThat(request.getValue().executionRequested()).isFalse();
    assertThat(request.getValue().workflowDigest()).isEqualTo(claim.workflowDigest());
  }

  private void arrangeReady(CrossTurnRecoveryService.ContinuationClaim claim) {
    when(recovery.candidateIds()).thenReturn(List.of(claim.tombstoneId()));
    when(recovery.claim(claim.tombstoneId())).thenReturn(claim);
    SecurityTask task = new SecurityTask();
    task.setId(31L);
    task.setProjectId(7L);
    task.setTargetId(11L);
    task.setStatus("SUCCESS");
    task.setResultJson("{\"status\":\"ok\"}");
    when(tasks.findById(31L)).thenReturn(java.util.Optional.of(task));
    when(runtime.resumeContinuation(any(), anyLong()))
        .thenReturn(Map.of("status", "CONTINUATION_READY"));
  }

  private static CrossTurnRecoveryService.ContinuationClaim claim() {
    String workflowDigest = "sha256:" + "a".repeat(64);
    AgentWorkflowSpecService.WorkflowSnapshot snapshot =
        new AgentWorkflowSpecService.WorkflowSnapshot(
            "workflow-1",
            7L,
            3L,
            workflowDigest,
            "admin",
            Instant.now(),
            Map.of("version", 1, "steps", List.of()),
            List.of());
    return new CrossTurnRecoveryService.ContinuationClaim(
        5L,
        7L,
        11L,
        "runtime-run-1",
        "node-run-1",
        "conversation-1",
        "turn-1",
        "workflow-1",
        3L,
        workflowDigest,
        "ledger-agent",
        AiAgentRuntimeClient.POLICY_REVISION,
        9L,
        "sha256:" + "b".repeat(64),
        "sha256:" + "c".repeat(64),
        List.of(31L),
        1,
        snapshot);
  }

  private static AiAgentResponse response() {
    return new AiAgentResponse(
        "conversation-1",
        7L,
        11L,
        "summary",
        new AiPlanResponse("runtime", "model", "summary", false, List.of()),
        "NOT_APPLICABLE",
        "NOT_REQUIRED",
        false,
        List.of(),
        new AiAgentResponse.AgentReview("NOT_REQUIRED", "done", false, List.of()),
        2,
        Instant.now());
  }
}
