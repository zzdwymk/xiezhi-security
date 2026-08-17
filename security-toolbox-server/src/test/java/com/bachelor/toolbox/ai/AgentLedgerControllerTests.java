package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.TargetService;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AgentLedgerControllerTests {
  private static final String DIGEST = "sha256:" + "a".repeat(64);

  private AgentLedgerService ledger;
  private ProjectAuthorizationService authorization;
  private AssessmentProjectService projects;
  private TargetService targets;
  private AgentWorkflowSpecService workflows;
  private CrossTurnRecoveryService recoveryService;
  private AgentLedgerController controller;

  @BeforeEach
  void setUp() {
    ledger = mock(AgentLedgerService.class);
    authorization = mock(ProjectAuthorizationService.class);
    projects = mock(AssessmentProjectService.class);
    targets = mock(TargetService.class);
    workflows = mock(AgentWorkflowSpecService.class);
    recoveryService = mock(CrossTurnRecoveryService.class);
    controller =
        new AgentLedgerController(ledger, authorization, projects, targets, workflows, recoveryService, 900);
  }

  @Test
  void stateRequiresProjectAccessAndUsesScopedLookup() {
    AgentLedgerService.StateSnapshot expected =
        new AgentLedgerService.StateSnapshot(
            false,
            true,
            false,
            "NOT_FOUND",
            "run-1",
            "node-1",
            null,
            null,
            null,
            0,
            0,
            null,
            null,
            0,
            null,
            null,
            null,
            null);
    when(ledger.state(1L, "run-1", "node-1")).thenReturn(expected);

    assertThat(controller.state("run-1", "node-1", 1L)).isSameAs(expected);

    verify(authorization).requireAccess(1L);
    verify(ledger).state(1L, "run-1", "node-1");
  }

  @Test
  void recoveryUsesServerWorkflowAndRevalidatesBothAuthorizationWindows() {
    when(workflows.read(1L))
        .thenReturn(
            Map.of(
                "workflowId", "workflow-1",
                "revision", 7L,
                "specDigest", DIGEST));
    AgentLedgerService.RecoveryDecision expected =
        new AgentLedgerService.RecoveryDecision(
            false, "STALE_WORKFLOW", "STALE_WORKFLOW", 0, 2, DIGEST, null, false);
    when(ledger.evaluateRecovery(any())).thenReturn(expected);

    assertThat(
            controller.recoveryCheck(
                "run-1", "node-1", new AgentLedgerController.RecoveryCheckRequest(1L, 2L)))
        .isSameAs(expected);

    verify(projects).validateProjectTarget(1L, 2L);
    verify(targets).getCurrentlyAuthorized(2L, 1L);
    ArgumentCaptor<AgentLedgerService.RecoveryRequest> captor =
        ArgumentCaptor.forClass(AgentLedgerService.RecoveryRequest.class);
    verify(ledger).evaluateRecovery(captor.capture());
    AgentLedgerService.RecoveryRequest request = captor.getValue();
    assertThat(request.workflowId()).isEqualTo("workflow-1");
    assertThat(request.workflowRevision()).isEqualTo(7);
    assertThat(request.workflowDigest()).isEqualTo(DIGEST);
    assertThat(request.policyRevision()).isEqualTo(AiAgentRuntimeClient.POLICY_REVISION);
    assertThat(request.resumeNotBefore()).isBefore(Instant.now());
  }
}
