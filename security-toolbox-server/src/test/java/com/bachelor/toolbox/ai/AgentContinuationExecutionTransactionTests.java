package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@DataJpaTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:continuation-execution;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop"
    })
@Import({
  AgentContinuationExecutionService.class,
  AgentContinuationExecutionTransactionTests.Configuration.class
})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AgentContinuationExecutionTransactionTests {
  @Autowired private AgentContinuationExecutionService service;
  @Autowired private AgentContinuationExecutionRepository executions;
  @Autowired private AiConversationSessionRepository sessions;
  @MockBean private CrossTurnRecoveryService recovery;

  @BeforeEach
  void clear() {
    sessions.deleteAllInBatch();
    executions.deleteAllInBatch();
  }

  @Test
  void prepareCommitsFenceAndSecondPreparationDoesNotExecuteAgain() {
    CrossTurnRecoveryService.ContinuationClaim claim = claim();

    assertThat(service.prepare(claim).kind())
        .isEqualTo(AgentContinuationExecutionService.Preparation.Kind.EXECUTE);

    AgentContinuationExecution stored = executions.findByTombstoneId(5L).orElseThrow();
    assertThat(stored.getStatus()).isEqualTo(AgentContinuationExecution.STARTED);
    assertThat(stored.getContinuationTurnId()).matches("resume-[0-9a-f]{48}");
    assertThat(service.prepare(claim).kind())
        .isEqualTo(AgentContinuationExecutionService.Preparation.Kind.SKIP);
  }

  @Test
  void successfulExecutionCommitsBusinessWriteResultAndCompletionTogether() {
    CrossTurnRecoveryService.ContinuationClaim claim = claim();
    service.prepare(claim);

    AiAgentResponse response =
        service.execute(
            claim,
            () -> {
              sessions.saveAndFlush(session("continuation-session"));
              return response();
            });

    AgentContinuationExecution stored = executions.findByTombstoneId(5L).orElseThrow();
    assertThat(response.message()).isEqualTo("summary");
    assertThat(stored.getStatus()).isEqualTo(AgentContinuationExecution.COMPLETED);
    assertThat(stored.getResponseDigest()).matches("sha256:[0-9a-f]{64}");
    assertThat(sessions.findById("continuation-session")).isPresent();
    verify(recovery).markContinued(5L);
  }

  @Test
  void failedExecutionRollsBackBusinessWriteAndLeavesCrashFenceForSafeSkip() {
    CrossTurnRecoveryService.ContinuationClaim claim = claim();
    service.prepare(claim);

    assertThatThrownBy(
            () ->
                service.execute(
                    claim,
                    () -> {
                      sessions.saveAndFlush(session("rolled-back-session"));
                      throw new IllegalStateException("simulated crash");
                    }))
        .isInstanceOf(IllegalStateException.class);

    assertThat(sessions.findById("rolled-back-session")).isEmpty();
    assertThat(executions.findByTombstoneId(5L).orElseThrow().getStatus())
        .isEqualTo(AgentContinuationExecution.STARTED);
    assertThat(service.prepare(claim).kind())
        .isEqualTo(AgentContinuationExecutionService.Preparation.Kind.SKIP);

    service.skip(claim, "IN_DOUBT", "PROCESS_CRASHED_AFTER_START");
    assertThat(executions.findByTombstoneId(5L).orElseThrow().getStatus())
        .isEqualTo(AgentContinuationExecution.ABANDONED);
    verify(recovery).markSkipped(5L, "PROCESS_CRASHED_AFTER_START");
  }

  @Test
  void completedResponseIsReusedWithoutCallingOperationAgain() {
    CrossTurnRecoveryService.ContinuationClaim claim = claim();
    service.prepare(claim);
    service.execute(claim, AgentContinuationExecutionTransactionTests::response);

    AgentContinuationExecutionService.Preparation replay = service.prepare(claim);
    assertThat(replay.kind())
        .isEqualTo(AgentContinuationExecutionService.Preparation.Kind.COMPLETED);
    assertThat(replay.response().message()).isEqualTo("summary");
    assertThat(service.reuse(claim).message()).isEqualTo("summary");
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

  private static AiConversationSessionRecord session(String id) {
    AiConversationSessionRecord record = new AiConversationSessionRecord();
    record.setId(id);
    record.setProjectId(7L);
    record.setTargetId(11L);
    record.setTurnsJson("[]");
    record.setLastAccess(Instant.now());
    return record;
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
        Instant.parse("2026-08-11T00:00:00Z"));
  }

  @TestConfiguration
  static class Configuration {
    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper().findAndRegisterModules();
    }
  }
}
