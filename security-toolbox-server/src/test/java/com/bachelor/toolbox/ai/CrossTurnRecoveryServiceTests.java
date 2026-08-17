package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class CrossTurnRecoveryServiceTests {
  private static final String WORKFLOW_DIGEST = "sha256:" + "a".repeat(64);
  private static final String LEDGER_DIGEST = "sha256:" + "b".repeat(64);

  private ConversationTombstoneRepository tombstones;
  private AgentLedgerService ledger;
  private AssessmentProjectService projects;
  private TargetService targets;
  private AgentWorkflowSpecService workflows;
  private SecurityTaskRepository tasks;
  private AuditService audit;
  private CrossTurnRecoveryService service;

  @BeforeEach
  void setUp() {
    tombstones = mock(ConversationTombstoneRepository.class);
    ledger = mock(AgentLedgerService.class);
    projects = mock(AssessmentProjectService.class);
    targets = mock(TargetService.class);
    workflows = mock(AgentWorkflowSpecService.class);
    tasks = mock(SecurityTaskRepository.class);
    audit = mock(AuditService.class);
    service =
        new CrossTurnRecoveryService(
            tombstones,
            ledger,
            projects,
            targets,
            workflows,
            tasks,
            new ObjectMapper(),
            audit,
            900,
            300);
  }

  @Test
  void checkpointPersistsFiniteAnchorWithoutCouplingCommitToRuntimeAvailability() {
    SecurityTask task = task(31L, "PENDING");
    when(ledger.state(7L, "runtime-run-1", "node-run-1")).thenReturn(ledgerState());
    when(tasks.findAllById(List.of(31L))).thenReturn(List.of(task));
    when(tombstones.findByRunIdAndNodeRunId("runtime-run-1", "node-run-1"))
        .thenReturn(Optional.empty());
    when(tombstones.findByProjectIdAndTargetIdAndTurnIdAndWorkflowDigest(
            7L, 11L, "turn-1", WORKFLOW_DIGEST))
        .thenReturn(Optional.empty());
    when(tombstones.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

    service.checkpoint(checkpoint());

    ArgumentCaptor<ConversationTombstone> stored =
        ArgumentCaptor.forClass(ConversationTombstone.class);
    verify(tombstones).save(stored.capture());
    assertThat(stored.getValue().getStatus()).isEqualTo(ConversationTombstone.WAITING_TASKS);
    assertThat(stored.getValue().getPendingTaskIdsJson()).isEqualTo("[31]");
    assertThat(stored.getValue().getRequestDigest()).matches("sha256:[0-9a-f]{64}");
    assertThat(stored.getValue().getLedgerSequence()).isEqualTo(9L);
    assertThat(stored.getValue().getLedgerHeadDigest()).isEqualTo(LEDGER_DIGEST);
  }

  @Test
  void claimWaitsUntilEveryTaskIsTerminal() {
    ConversationTombstone tombstone = tombstone();
    when(tombstones.findLockedById(5L)).thenReturn(Optional.of(tombstone));
    when(tasks.findAllById(List.of(31L))).thenReturn(List.of(task(31L, "RUNNING")));

    assertThat(service.claim(5L)).isNull();

    assertThat(tombstone.getStatus()).isEqualTo(ConversationTombstone.WAITING_TASKS);
    verify(workflows, never()).freezeSnapshot(any());
  }

  @Test
  void claimRevalidatesWorkflowAndExactLedgerAnchorBeforeProcessing() {
    ConversationTombstone tombstone = tombstone();
    AgentWorkflowSpecService.WorkflowSnapshot snapshot =
        new AgentWorkflowSpecService.WorkflowSnapshot(
            "workflow-1",
            7L,
            3L,
            WORKFLOW_DIGEST,
            "admin",
            Instant.now(),
            Map.of("version", 1, "steps", List.of()),
            List.of());
    when(tombstones.findLockedById(5L)).thenReturn(Optional.of(tombstone));
    when(tasks.findAllById(List.of(31L))).thenReturn(List.of(task(31L, "SUCCESS")));
    when(workflows.freezeSnapshot(7L)).thenReturn(snapshot);
    when(ledger.state(7L, "runtime-run-1", "node-run-1")).thenReturn(ledgerState());
    when(tombstones.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

    CrossTurnRecoveryService.ContinuationClaim claim = service.claim(5L);

    assertThat(claim).isNotNull();
    assertThat(claim.taskIds()).containsExactly(31L);
    assertThat(claim.ledgerSequence()).isEqualTo(9L);
    assertThat(tombstone.getStatus()).isEqualTo(ConversationTombstone.PROCESSING);
    assertThat(tombstone.getAttempt()).isEqualTo(1);
    verify(projects).validateProjectTarget(7L, 11L);
    verify(targets).getCurrentlyAuthorized(11L, 7L);
  }

  @Test
  void claimRejectsCheckpointCreatedWithAnOlderPolicyRevision() {
    ConversationTombstone tombstone = tombstone();
    tombstone.setPolicyRevision("java-authoritative-v0");
    AgentWorkflowSpecService.WorkflowSnapshot snapshot =
        new AgentWorkflowSpecService.WorkflowSnapshot(
            "workflow-1",
            7L,
            3L,
            WORKFLOW_DIGEST,
            "admin",
            Instant.now(),
            Map.of("version", 1, "steps", List.of()),
            List.of());
    when(tombstones.findLockedById(5L)).thenReturn(Optional.of(tombstone));
    when(tasks.findAllById(List.of(31L))).thenReturn(List.of(task(31L, "SUCCESS")));
    when(workflows.freezeSnapshot(7L)).thenReturn(snapshot);
    when(tombstones.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

    assertThat(service.claim(5L)).isNull();
    assertThat(tombstone.getStatus()).isEqualTo(ConversationTombstone.STALE);
    assertThat(tombstone.getLastError()).isEqualTo("STALE_POLICY");
  }

  private CrossTurnRecoveryService.CheckpointRequest checkpoint() {
    return new CrossTurnRecoveryService.CheckpointRequest(
        7L,
        11L,
        "runtime-run-1",
        "node-run-1",
        "conversation-1",
        "turn-1",
        "workflow-1",
        3L,
        WORKFLOW_DIGEST,
        "ledger-agent",
        AiAgentRuntimeClient.POLICY_REVISION,
        9L,
        LEDGER_DIGEST,
        List.of(31L));
  }

  private ConversationTombstone tombstone() {
    ConversationTombstone value = new ConversationTombstone();
    value.setId(5L);
    value.setProjectId(7L);
    value.setTargetId(11L);
    value.setRunId("runtime-run-1");
    value.setNodeRunId("node-run-1");
    value.setSessionId("conversation-1");
    value.setTurnId("turn-1");
    value.setWorkflowId("workflow-1");
    value.setWorkflowRevision(3L);
    value.setWorkflowDigest(WORKFLOW_DIGEST);
    value.setOuterNodeId("ledger-agent");
    value.setPolicyRevision(AiAgentRuntimeClient.POLICY_REVISION);
    value.setLedgerSequence(9L);
    value.setLedgerHeadDigest(LEDGER_DIGEST);
    value.setRequestDigest("sha256:" + "c".repeat(64));
    value.setPendingTaskIdsJson("[31]");
    value.setStatus(ConversationTombstone.WAITING_TASKS);
    value.setCreatedAt(Instant.now());
    value.setUpdatedAt(Instant.now());
    value.setNextAttemptAt(Instant.now().minusSeconds(1));
    return value;
  }

  private SecurityTask task(Long id, String status) {
    SecurityTask value = new SecurityTask();
    value.setId(id);
    value.setProjectId(7L);
    value.setTargetId(11L);
    value.setStatus(status);
    return value;
  }

  private AgentLedgerService.StateSnapshot ledgerState() {
    return new AgentLedgerService.StateSnapshot(
        true,
        true,
        true,
        "OK",
        "runtime-run-1",
        "node-run-1",
        "ledger-agent",
        "COMPLETED",
        "finish",
        9L,
        9L,
        LEDGER_DIGEST,
        "workflow-1",
        3L,
        WORKFLOW_DIGEST,
        AiAgentRuntimeClient.POLICY_REVISION,
        Instant.now().minusSeconds(30),
        Instant.now());
  }
}
