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
            mock(AgentWorkflowSpecRepository.class), new ObjectMapper(), authorization, 24);
    worker =
        new AgentContinuationWorker(
            recovery,
            tasks,
            runtime,
            orchestrator,
            executions,
            workflows,
            authorization,
            true,
            3);
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

  /**
   * The continuation turn must be allowed to *propose* a next step, otherwise the whole loop is a
   * dead end (tasks finish, the model summarises, nothing can ever follow up). Guarding still
   * happens downstream, so the prompt only has to avoid two things: forbidding proposals, and
   * inviting endless work.
   */
  @Test
  void continuationPromptAsksForNextStepProposalInsteadOfForbiddingAction() {
    CrossTurnRecoveryService.ContinuationClaim claim = claim();
    arrangeReady(claim);
    when(executions.prepare(claim))
        .thenReturn(
            new AgentContinuationExecutionService.Preparation(
                AgentContinuationExecutionService.Preparation.Kind.EXECUTE,
                null,
                AgentContinuationExecution.STARTED));
    when(orchestrator.run(any(AiAgentRequest.class))).thenReturn(response());
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
    String prompt = request.getValue().prompt();
    // It must invite a proposal...
    assertThat(prompt).contains("提出下一步检测动作");
    // ...while making clear the proposal needs administrator confirmation.
    assertThat(prompt).contains("管理员在执行确认中逐次批准");
    // The old blanket prohibition must be gone.
    assertThat(prompt).doesNotContain("不要创建任务、执行工具或提出未授权动作");
    // And it must explicitly offer the option to stop.
    assertThat(prompt).contains("结束");
    // Continuation re-evaluates by default instead of assuming the round is done,
    // so a first scan of a fresh target does not silently end the loop.
    assertThat(prompt).contains("重新评估");
    assertThat(prompt).contains("是否需要继续由结果本身决定");
  }

  /** The round budget stays a hard stop even with the wider default. */
  @Test
  void widerRoundBudgetStillForbidsActionsAtItsLastRound() {
    AgentContinuationWorker wider =
        new AgentContinuationWorker(
            recovery,
            tasks,
            runtime,
            orchestrator,
            executions,
            new AgentWorkflowSpecService(
                mock(AgentWorkflowSpecRepository.class),
                new ObjectMapper(),
                new ProjectAuthorizationService(mock(AssessmentProjectRepository.class)),
                24),
            new ProjectAuthorizationService(mock(AssessmentProjectRepository.class)),
            true,
            5);
    CrossTurnRecoveryService.ContinuationClaim claim = claimAtAttempt(4, 5);
    arrangeReady(claim);
    when(executions.prepare(claim))
        .thenReturn(
            new AgentContinuationExecutionService.Preparation(
                AgentContinuationExecutionService.Preparation.Kind.EXECUTE,
                null,
                AgentContinuationExecution.STARTED));
    when(orchestrator.run(any(AiAgentRequest.class))).thenReturn(response());
    when(executions.execute(any(), any()))
        .thenAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              Supplier<AiAgentResponse> operation = invocation.getArgument(1);
              return operation.get();
            });

    wider.drain();

    ArgumentCaptor<AiAgentRequest> request = ArgumentCaptor.forClass(AiAgentRequest.class);
    verify(orchestrator).run(request.capture());
    String prompt = request.getValue().prompt();
    // attempt=4 is the fifth round, so the widened budget must now say stop.
    assertThat(prompt).contains("已达到允许的最大轮次");
    assertThat(prompt).contains("禁止再提出任何新的检测动作");
  }

  /** At the round budget the prompt must forbid new work, so a loop can never run forever. */
  @Test
  void finalAllowedRoundForbidsFurtherActions() {
    CrossTurnRecoveryService.ContinuationClaim claim = claimAtAttempt(2, 3);
    arrangeReady(claim);
    when(executions.prepare(claim))
        .thenReturn(
            new AgentContinuationExecutionService.Preparation(
                AgentContinuationExecutionService.Preparation.Kind.EXECUTE,
                null,
                AgentContinuationExecution.STARTED));
    when(orchestrator.run(any(AiAgentRequest.class))).thenReturn(response());
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
    String prompt = request.getValue().prompt();
    assertThat(prompt).contains("已达到允许的最大轮次");
    assertThat(prompt).contains("禁止再提出任何新的检测动作");
    assertThat(prompt).doesNotContain("提出下一步检测动作");
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
    return claimAtAttempt(1, 3);
  }

  private static CrossTurnRecoveryService.ContinuationClaim claimAtAttempt(
      int attempt, int maxRounds) {
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
        attempt,
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
