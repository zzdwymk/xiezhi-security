package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.task.TaskTerminalEvent;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Completes an Agent turn after its already-created tasks reach terminal states.
 *
 * <p>The continuation is intentionally read-only: it rehydrates task context from Java and calls
 * the orchestrator with {@code execute=false}; it can never create a second batch of scans.
 */
@Service
public class AgentContinuationWorker {
  private final CrossTurnRecoveryService recovery;
  private final SecurityTaskRepository tasks;
  private final AiAgentRuntimeClient runtime;
  private final AgentOrchestrator orchestrator;
  private final AgentContinuationExecutionService executions;
  private final AgentWorkflowSpecService workflows;
  private final ProjectAuthorizationService authorization;
  private final boolean enabled;

  public AgentContinuationWorker(
      CrossTurnRecoveryService recovery,
      SecurityTaskRepository tasks,
      AiAgentRuntimeClient runtime,
      AgentOrchestrator orchestrator,
      AgentContinuationExecutionService executions,
      AgentWorkflowSpecService workflows,
      ProjectAuthorizationService authorization,
      @Value("${toolbox.ai.agent.continuation-enabled:true}") boolean enabled) {
    this.recovery = recovery;
    this.tasks = tasks;
    this.runtime = runtime;
    this.orchestrator = orchestrator;
    this.executions = executions;
    this.workflows = workflows;
    this.authorization = authorization;
    this.enabled = enabled;
  }

  @EventListener
  @Async
  public void onTaskTerminal(TaskTerminalEvent ignored) {
    drain();
  }

  @EventListener(ApplicationReadyEvent.class)
  public void recoverAfterRestart() {
    drain();
  }

  @Scheduled(fixedDelayString = "${toolbox.ai.agent.continuation-poll-ms:15000}")
  public void poll() {
    drain();
  }

  synchronized void drain() {
    if (!enabled) return;
    for (Long id : recovery.candidateIds()) {
      CrossTurnRecoveryService.ContinuationClaim claim;
      try {
        claim = recovery.claim(id);
      } catch (RuntimeException ignored) {
        continue;
      }
      if (claim == null) continue;
      try {
        // Java outbox persistence is independent from Runtime availability. Delivery is retried
        // here after the row has been committed, and the Python write is idempotent.
        runtime.checkpointContinuation(recovery.checkpointBody(claim), claim.projectId());
        String status = "WAITING_TASKS";
        for (Map<String, Object> callback : callbackBodies(claim)) {
          Map<String, Object> result = runtime.resumeContinuation(callback, claim.projectId());
          status = Objects.toString(result.get("status"), "");
        }
        if ("WAITING_TASKS".equals(status)) {
          recovery.markFailure(claim.tombstoneId(), "RUNTIME_WAITING_TASKS");
          continue;
        }
        if (!"CONTINUATION_READY".equals(status)
            && !"ALREADY_CONTINUED".equals(status)
            && !"RUNTIME_DISABLED".equals(status)) {
          throw new ApiException("AI Runtime 拒绝续接：" + status);
        }
        if ("ALREADY_CONTINUED".equals(status) || "RUNTIME_DISABLED".equals(status)) {
          executions.skip(claim, status, "RUNTIME_" + status);
          continue;
        }
        AgentContinuationExecutionService.Preparation preparation = executions.prepare(claim);
        if (preparation.kind()
            == AgentContinuationExecutionService.Preparation.Kind.COMPLETED) {
          executions.reuse(claim);
          continue;
        }
        if (preparation.kind() == AgentContinuationExecutionService.Preparation.Kind.SKIP) {
          executions.skip(claim, "IN_DOUBT", "PREVIOUS_EXECUTION_" + preparation.status());
          continue;
        }
        try {
          executions.execute(claim, () -> runReadOnlyContinuation(claim));
        } catch (RuntimeException ex) {
          // The durable STARTED fence means a model call may already have happened. Close the
          // turn without retrying it; all Java message/audit writes were rolled back with execute.
          executions.skip(claim, "IN_DOUBT", ex.getMessage());
        }
      } catch (RuntimeException ex) {
        recovery.markFailure(claim.tombstoneId(), ex.getMessage());
      }
    }
  }

  private AiAgentResponse runReadOnlyContinuation(CrossTurnRecoveryService.ContinuationClaim claim) {
    List<Long> ids = claim.taskIds();
    String prompt =
        "原 Agent 回合创建的受控任务已经全部进入终态。请仅读取服务端任务、Finding 和审计上下文，"
            + "总结结果、失败原因和后续人工处置建议；不要创建任务、执行工具或提出未授权动作。任务 ID："
            + ids.stream().map(String::valueOf).collect(java.util.stream.Collectors.joining(","));
    AiPlanRequest.ContextRefs refs =
        new AiPlanRequest.ContextRefs(claim.targetId(), ids, List.of(), List.of(), List.of(), List.of());
    String turnId = continuationTurnId(claim, ids);
    AiAgentRequest request =
        new AiAgentRequest(
                claim.projectId(),
                claim.targetId(),
                claim.sessionId(),
                prompt,
                false,
                refs,
                List.of(),
                "review",
                turnId,
                claim.workflowId(),
                claim.workflowRevision(),
                claim.workflowDigest(),
                claim.outerNodeId(),
                "resume-" + turnId)
            .withWorkflowSnapshot(claim.workflowSnapshot());
    return workflows.withSnapshot(
        claim.workflowSnapshot(),
        () -> {
          try {
            return authorization.callWithSystemAccess(() -> orchestrator.run(request));
          } catch (Exception ex) {
            throw new ApiException("Agent 续接回合执行失败");
          }
        });
  }

  private List<Map<String, Object>> callbackBodies(
      CrossTurnRecoveryService.ContinuationClaim claim) {
    List<Map<String, Object>> callbacks = new ArrayList<>();
    for (Long id : claim.taskIds()) {
      SecurityTask task = tasks.findById(id).orElseThrow(() -> new ApiException("续接任务不存在"));
      String resultDigest = digest(task.getResultJson());
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("projectId", claim.projectId());
      body.put("targetId", claim.targetId());
      body.put("conversationId", claim.sessionId());
      body.put("runId", claim.runId());
      body.put("nodeRunId", claim.nodeRunId());
      body.put("workflowId", claim.workflowId());
      body.put("workflowRevision", claim.workflowRevision());
      body.put("workflowDigest", claim.workflowDigest());
      body.put("outerNodeId", claim.outerNodeId());
      body.put("policyRevision", claim.policyRevision());
      body.put("requestDigest", claim.requestDigest());
      body.put("stateVersion", claim.ledgerSequence());
      body.put("ledgerDigest", claim.ledgerHeadDigest());
      body.put("taskId", id);
      body.put("taskStatus", task.getStatus());
      body.put("resultDigest", resultDigest);
      body.put("callbackId", "cb-" + digest(claim.runId() + ":" + id + ":" + task.getStatus() + ":" + resultDigest).substring(7, 39));
      callbacks.add(body);
    }
    return callbacks;
  }

  private String continuationTurnId(
      CrossTurnRecoveryService.ContinuationClaim claim, List<Long> taskIds) {
    return "resume-" + digest(claim.runId() + ":" + claim.nodeRunId() + ":" + taskIds).substring(7, 55);
  }

  private String digest(String value) {
    try {
      return "sha256:"
          + java.util.HexFormat.of()
              .formatHex(MessageDigest.getInstance("SHA-256").digest(Objects.toString(value, "").getBytes(StandardCharsets.UTF_8)));
    } catch (Exception ex) {
      throw new IllegalStateException("续接摘要失败", ex);
    }
  }

}
