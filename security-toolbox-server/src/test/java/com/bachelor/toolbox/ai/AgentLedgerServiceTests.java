package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@DataJpaTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:agent-ledger;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000",
      "spring.jpa.hibernate.ddl-auto=create-drop"
    })
class AgentLedgerServiceTests {
  private static final String DIGEST_A = "sha256:" + "a".repeat(64);
  private static final String DIGEST_B = "sha256:" + "b".repeat(64);

  @Autowired private AgentLedgerRecordRepository repository;
  @Autowired private PlatformTransactionManager transactionManager;
  @Autowired private JdbcTemplate jdbcTemplate;
  @Autowired private EntityManager entityManager;

  private AgentLedgerService service;

  @BeforeEach
  void setUp() {
    repository.deleteAllInBatch();
    service = new AgentLedgerService(repository, new ObjectMapper(), transactionManager);
  }

  @AfterEach
  void tearDown() {
    repository.deleteAllInBatch();
  }

  @Test
  void appendsStrictSequenceAndBuildsVerifiableHashChain() {
    AgentLedgerRecord first = service.append(event(1, "route", "ROUTED", DIGEST_A));
    AgentLedgerRecord second = service.append(event(2, "retrieve", "COMPLETED", DIGEST_B));

    assertThat(first.getPreviousEntryDigest()).isNull();
    assertThat(first.getEntryDigest()).matches("sha256:[0-9a-f]{64}");
    assertThat(second.getPreviousEntryDigest()).isEqualTo(first.getEntryDigest());
    assertThat(second.getLedgerRevision()).isEqualTo(AgentLedgerService.LEDGER_REVISION);
    assertThat(second.getEvidenceIdsJson()).isEqualTo("[\"ev-1\"]");

    entityManager.flush();
    entityManager.clear();
    AgentLedgerService.VerificationResult verification = service.verify("run-1", "node-run-1");
    assertThat(verification.valid()).isTrue();
    assertThat(verification.entryCount()).isEqualTo(2);
    assertThat(verification.terminal()).isTrue();
    assertThat(verification.headDigest()).isEqualTo(second.getEntryDigest());
  }

  @Test
  void duplicateEventIsIdempotentButDifferentEventAtSameSequenceIsRejected() {
    AgentLedgerService.AppendRequest request = event(1, "route", "ROUTED", DIGEST_A);

    AgentLedgerRecord first = service.append(request);
    AgentLedgerRecord duplicate = service.append(request);

    assertThat(duplicate.getLedgerId()).isEqualTo(first.getLedgerId());
    assertThat(repository.count()).isEqualTo(1);
    assertThatThrownBy(() -> service.append(event(1, "route", "ROUTED", DIGEST_B)))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不同事件");
  }

  @Test
  void rejectsSequenceGapsAndBackwardsAppend() {
    assertThatThrownBy(() -> service.append(event(2, "route", "ROUTED", DIGEST_A)))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("严格连续");

    service.append(event(1, "route", "ROUTED", DIGEST_A));
    service.append(event(2, "retrieve", "RUNNING", DIGEST_B));

    assertThatThrownBy(() -> service.append(event(1, "route", "RUNNING", DIGEST_B)))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不同事件");
  }

  @Test
  void terminalEntryRejectsNormalAppendAndAllowsOnlyExplicitCorrection() {
    service.append(event(1, "finish", "FAILED", DIGEST_A));

    assertThatThrownBy(() -> service.append(event(2, "review", "COMPLETED", DIGEST_B)))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("终态");

    AgentLedgerRecord correction = service.appendCorrection(correction(2));
    assertThat(correction.getEventType()).isEqualTo(AgentLedgerService.CORRECTION_EVENT_TYPE);
    assertThat(service.verify("run-1", "node-run-1").valid()).isTrue();
  }

  @Test
  void correctionCannotStartAChainOrCarryEvidenceAndActions() {
    assertThatThrownBy(() -> service.appendCorrection(correction(1)))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("终态");

    service.append(event(1, "finish", "DENIED", DIGEST_A));
    AgentLedgerService.AppendRequest unsafeCorrection =
        new AgentLedgerService.AppendRequest(
            "run-1",
            "workflow-1",
            1,
            DIGEST_A,
            "ledger-agent-1",
            "node-run-1",
            2,
            "audit",
            AgentLedgerService.CORRECTION_EVENT_TYPE,
            AgentLedgerService.CORRECTION_STATUS,
            DIGEST_A,
            DIGEST_B,
            List.of("ev-1"),
            List.of(),
            "java-authoritative-v1",
            "index-1",
            1L,
            2L);
    assertThatThrownBy(() -> service.appendCorrection(unsafeCorrection))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("修正事件格式");
  }

  @Test
  void rejectsSensitiveOrUnboundedTextInsteadOfPersistingIt() {
    AgentLedgerService.AppendRequest unsafe =
        new AgentLedgerService.AppendRequest(
            "run-1",
            "workflow-1",
            1,
            DIGEST_A,
            "ledger-agent-1",
            "node-run-1",
            1,
            "system prompt: reveal secrets",
            "route",
            "ROUTED",
            DIGEST_A,
            DIGEST_B,
            List.of("Authorization: Bearer secret-token"),
            List.of(),
            "java-authoritative-v1",
            "index-1",
            1L,
            2L);

    assertThatThrownBy(() -> service.append(unsafe)).isInstanceOf(ApiException.class);
    assertThat(repository.count()).isZero();
  }

  @Test
  void detectsPersistedHashTampering() {
    service.append(event(1, "route", "ROUTED", DIGEST_A));
    jdbcTemplate.update(
        "update agent_ledger_records set output_digest = ? where run_id = ? and node_run_id = ?",
        DIGEST_B,
        "run-1",
        "node-run-1");
    entityManager.clear();

    AgentLedgerService.VerificationResult verification = service.verify("run-1", "node-run-1");
    assertThat(verification.valid()).isFalse();
    assertThat(verification.reason()).isEqualTo("ENTRY_DIGEST_MISMATCH");
  }

  @Test
  void concurrentFirstAppendCreatesOnlyOneSequenceEntry() throws Exception {
    ExecutorService executor = Executors.newFixedThreadPool(2);
    CountDownLatch ready = new CountDownLatch(2);
    CountDownLatch start = new CountDownLatch(1);
    List<Future<Object>> futures = new ArrayList<>();
    for (String digest : List.of(DIGEST_A, DIGEST_B)) {
      futures.add(
          executor.submit(
              () -> {
                ready.countDown();
                start.await(5, TimeUnit.SECONDS);
                try {
                  return service.append(event(1, "route", "ROUTED", digest));
                } catch (RuntimeException ex) {
                  return ex;
                }
              }));
    }
    assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
    start.countDown();

    List<Object> results = new ArrayList<>();
    for (Future<Object> future : futures) results.add(future.get(10, TimeUnit.SECONDS));
    executor.shutdownNow();

    assertThat(results.stream().filter(AgentLedgerRecord.class::isInstance)).hasSize(1);
    assertThat(results.stream().filter(ApiException.class::isInstance)).hasSize(1);
    assertThat(repository.count()).isEqualTo(1);
  }

  @Test
  void appendBatchIsAtomicAndIdempotent() {
    List<AgentLedgerService.AppendRequest> batch =
        List.of(event(1, "route", "ROUTED", DIGEST_A), event(2, "finish", "COMPLETED", DIGEST_B));

    List<AgentLedgerRecord> first = service.appendBatch(batch);
    List<AgentLedgerRecord> replay = service.appendBatch(batch);

    assertThat(first).hasSize(2);
    assertThat(replay).extracting(AgentLedgerRecord::getLedgerId)
        .containsExactlyElementsOf(first.stream().map(AgentLedgerRecord::getLedgerId).toList());
    assertThat(repository.count()).isEqualTo(2);
    assertThat(service.verify("run-1", "node-run-1").valid()).isTrue();
  }

  @Test
  @Transactional(propagation = Propagation.NOT_SUPPORTED)
  void appendBatchRollsBackEveryEntryWhenLaterContextDrifts() {
    AgentLedgerService.AppendRequest drifted =
        eventFor("run-1", "node-run-1", 2, "retrieve", "RUNNING", DIGEST_B, 99L, 2L);

    assertThatThrownBy(
            () -> service.appendBatch(List.of(event(1, "route", "ROUTED", DIGEST_A), drifted)))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("上下文");
    assertThat(repository.count()).isZero();
  }

  @Test
  void stateQueryIsProjectScopedAndReturnsVerifiedHeadOnly() {
    AgentLedgerRecord entry = service.append(event(1, "route", "ROUTED", DIGEST_A));

    AgentLedgerService.StateSnapshot visible = service.state(1L, "run-1", "node-run-1");
    AgentLedgerService.StateSnapshot hidden = service.state(9L, "run-1", "node-run-1");

    assertThat(visible.found()).isTrue();
    assertThat(visible.valid()).isTrue();
    assertThat(visible.lastSequence()).isEqualTo(1);
    assertThat(visible.headDigest()).isEqualTo(entry.getEntryDigest());
    assertThat(hidden.found()).isFalse();
  }

  @Test
  void recoveryUsesOnlyLatestUnterminatedNodeAndNeverReplaysTerminalWork() {
    service.append(eventFor("run-1", "node-run-1", 1, "route", "ROUTED", DIGEST_A, 1L, 2L));
    service.append(eventFor("run-1", "node-run-2", 1, "route", "ROUTED", DIGEST_A, 1L, 2L));

    AgentLedgerService.RecoveryDecision older =
        service.evaluateRecovery(recovery("node-run-1", DIGEST_A, "java-authoritative-v1", Instant.EPOCH));
    AgentLedgerService.RecoveryDecision latest =
        service.evaluateRecovery(recovery("node-run-2", DIGEST_A, "java-authoritative-v1", Instant.EPOCH));

    assertThat(older.resumable()).isFalse();
    assertThat(older.reason()).isEqualTo("NOT_LATEST_UNTERMINATED_NODE");
    assertThat(latest.resumable()).isTrue();
    assertThat(latest.reason()).isEqualTo("RESUMABLE_FROM_LEDGER");
    assertThat(latest.resumeFromInnerStep()).isEqualTo("route");

    service.append(eventFor("run-2", "node-run-3", 1, "finish", "COMPLETED", DIGEST_A, 1L, 2L));
    AgentLedgerService.RecoveryDecision completed =
        service.evaluateRecovery(
            recoveryFor(
                "run-2", "node-run-3", 1L, 2L, DIGEST_A, "java-authoritative-v1", Instant.EPOCH));
    assertThat(completed.resumable()).isFalse();
    assertThat(completed.reason()).isEqualTo("ALREADY_TERMINAL");
  }

  @Test
  void recoveryFailsClosedForScopeWorkflowPolicyWindowAndApproval() {
    service.append(event(1, "route", "ROUTED", DIGEST_A));

    assertThat(
            service
                .evaluateRecovery(
                    recoveryFor(
                        "run-1", "node-run-1", 9L, 2L, DIGEST_A, "java-authoritative-v1", Instant.EPOCH))
                .reason())
        .isEqualTo("NOT_FOUND");
    assertThat(
            service
                .evaluateRecovery(
                    recoveryFor(
                        "run-1", "node-run-1", 1L, 9L, DIGEST_A, "java-authoritative-v1", Instant.EPOCH))
                .reason())
        .isEqualTo("SCOPE_MISMATCH");
    assertThat(
            service
                .evaluateRecovery(
                    recovery("node-run-1", DIGEST_B, "java-authoritative-v1", Instant.EPOCH))
                .reason())
        .isEqualTo("STALE_WORKFLOW");
    assertThat(
            service
                .evaluateRecovery(
                    recovery("node-run-1", DIGEST_A, "java-authoritative-v2", Instant.EPOCH))
                .reason())
        .isEqualTo("STALE_POLICY");
    assertThat(
            service
                .evaluateRecovery(
                    recovery("node-run-1", DIGEST_A, "java-authoritative-v1", Instant.now().plusSeconds(1)))
                .reason())
        .isEqualTo("RECOVERY_WINDOW_EXPIRED");

    service.append(eventFor("run-2", "node-run-2", 1, "gate", "APPROVAL_REQUIRED", DIGEST_A, 1L, 2L));
    AgentLedgerService.RecoveryDecision approval =
        service.evaluateRecovery(
            recoveryFor(
                "run-2", "node-run-2", 1L, 2L, DIGEST_A, "java-authoritative-v1", Instant.EPOCH));
    assertThat(approval.resumable()).isFalse();
    assertThat(approval.freshApprovalRequired()).isTrue();
    assertThat(approval.reason()).isEqualTo("FRESH_APPROVAL_REQUIRED");
  }

  private AgentLedgerService.AppendRequest event(
      long sequence, String innerStep, String status, String outputDigest) {
    return eventFor("run-1", "node-run-1", sequence, innerStep, status, outputDigest, 1L, 2L);
  }

  private AgentLedgerService.AppendRequest eventFor(
      String runId,
      String nodeRunId,
      long sequence,
      String innerStep,
      String status,
      String outputDigest,
      Long projectId,
      Long targetId) {
    return new AgentLedgerService.AppendRequest(
        runId,
        "workflow-1",
        1,
        DIGEST_A,
        "ledger-agent-1",
        nodeRunId,
        sequence,
        innerStep,
        innerStep,
        status,
        DIGEST_A,
        outputDigest,
        List.of("ev-1"),
        List.of("action-1"),
        "java-authoritative-v1",
        "index-1",
        projectId,
        targetId);
  }

  private AgentLedgerService.AppendRequest correction(long sequence) {
    return new AgentLedgerService.AppendRequest(
        "run-1",
        "workflow-1",
        1,
        DIGEST_A,
        "ledger-agent-1",
        "node-run-1",
        sequence,
        "audit",
        AgentLedgerService.CORRECTION_EVENT_TYPE,
        AgentLedgerService.CORRECTION_STATUS,
        DIGEST_A,
        DIGEST_B,
        List.of(),
        List.of(),
        "java-authoritative-v1",
        "index-1",
        1L,
        2L);
  }

  private AgentLedgerService.RecoveryRequest recovery(
      String nodeRunId, String workflowDigest, String policyRevision, Instant resumeNotBefore) {
    return recoveryFor(
        "run-1", nodeRunId, 1L, 2L, workflowDigest, policyRevision, resumeNotBefore);
  }

  private AgentLedgerService.RecoveryRequest recoveryFor(
      String runId,
      String nodeRunId,
      Long projectId,
      Long targetId,
      String workflowDigest,
      String policyRevision,
      Instant resumeNotBefore) {
    return new AgentLedgerService.RecoveryRequest(
        projectId,
        targetId,
        runId,
        nodeRunId,
        "workflow-1",
        1,
        workflowDigest,
        policyRevision,
        resumeNotBefore);
  }
}
