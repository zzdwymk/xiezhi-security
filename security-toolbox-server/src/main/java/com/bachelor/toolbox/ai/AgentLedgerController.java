package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.TargetService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Read-only inspection and fail-closed recovery eligibility for persisted Agent ledger chains. */
@RestController
@RequestMapping("/api/ai/agent/ledger")
public class AgentLedgerController {
  private final AgentLedgerService ledger;
  private final ProjectAuthorizationService authorization;
  private final AssessmentProjectService projects;
  private final TargetService targets;
  private final AgentWorkflowSpecService workflows;
  private final long recoveryWindowSeconds;

  @Autowired
  public AgentLedgerController(
      AgentLedgerService ledger,
      ProjectAuthorizationService authorization,
      AssessmentProjectService projects,
      TargetService targets,
      AgentWorkflowSpecService workflows,
      @Value("${toolbox.ai.ledger.recovery-window-seconds:900}") long recoveryWindowSeconds) {
    this.ledger = ledger;
    this.authorization = authorization;
    this.projects = projects;
    this.targets = targets;
    this.workflows = workflows;
    this.recoveryWindowSeconds = Math.max(1, Math.min(recoveryWindowSeconds, 86_400));
  }

  /** Source compatibility for callers compiled against the removed console-only recovery draft. */
  public AgentLedgerController(
      AgentLedgerService ledger,
      ProjectAuthorizationService authorization,
      AssessmentProjectService projects,
      TargetService targets,
      AgentWorkflowSpecService workflows,
      CrossTurnRecoveryService ignoredRecoveryService,
      long recoveryWindowSeconds) {
    this(ledger, authorization, projects, targets, workflows, recoveryWindowSeconds);
  }

  @GetMapping("/{runId}/nodes/{nodeRunId}")
  public AgentLedgerService.StateSnapshot state(
      @PathVariable String runId,
      @PathVariable String nodeRunId,
      @RequestParam @Positive Long projectId) {
    authorization.requireAccess(projectId);
    return ledger.state(projectId, runId, nodeRunId);
  }

  /**
   * Returns eligibility only. A positive result is a verified ledger checkpoint, not permission to
   * execute a task or restore arbitrary Python memory.
   */
  @PostMapping("/{runId}/nodes/{nodeRunId}/recovery-check")
  public AgentLedgerService.RecoveryDecision recoveryCheck(
      @PathVariable String runId,
      @PathVariable String nodeRunId,
      @Valid @RequestBody RecoveryCheckRequest request) {
    projects.validateProjectTarget(request.projectId(), request.targetId());
    targets.getCurrentlyAuthorized(request.targetId(), request.projectId());
    Map<String, Object> currentWorkflow = workflows.read(request.projectId());
    String workflowId = requiredText(currentWorkflow, "workflowId");
    long workflowRevision = requiredPositiveLong(currentWorkflow, "revision");
    String workflowDigest = requiredText(currentWorkflow, "specDigest");
    return ledger.evaluateRecovery(
        new AgentLedgerService.RecoveryRequest(
            request.projectId(),
            request.targetId(),
            runId,
            nodeRunId,
            workflowId,
            workflowRevision,
            workflowDigest,
            AiAgentRuntimeClient.POLICY_REVISION,
            Instant.now().minusSeconds(recoveryWindowSeconds)));
  }

  private String requiredText(Map<String, Object> values, String field) {
    String value = Objects.toString(values.get(field), "").strip();
    if (value.isEmpty()) throw new ApiException("当前工作流快照不完整，不能恢复 Agent 节点");
    return value;
  }

  private long requiredPositiveLong(Map<String, Object> values, String field) {
    Object raw = values.get(field);
    try {
      long value = raw instanceof Number number ? number.longValue() : Long.parseLong(String.valueOf(raw));
      if (value > 0) return value;
    } catch (RuntimeException ignored) {
      // Fall through to the same fail-closed response.
    }
    throw new ApiException("当前工作流快照不完整，不能恢复 Agent 节点");
  }

  public record RecoveryCheckRequest(
      @NotNull @Positive Long projectId, @NotNull @Positive Long targetId) {}

}
