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
  private final int maxContinuationRounds;

  public AgentContinuationWorker(
      CrossTurnRecoveryService recovery,
      SecurityTaskRepository tasks,
      AiAgentRuntimeClient runtime,
      AgentOrchestrator orchestrator,
      AgentContinuationExecutionService executions,
      AgentWorkflowSpecService workflows,
      ProjectAuthorizationService authorization,
      @Value("${toolbox.ai.agent.continuation-enabled:true}") boolean enabled,
      @Value("${toolbox.ai.agent.max-continuation-rounds:5}") int maxContinuationRounds) {
    this.recovery = recovery;
    this.tasks = tasks;
    this.runtime = runtime;
    this.orchestrator = orchestrator;
    this.executions = executions;
    this.workflows = workflows;
    this.authorization = authorization;
    this.enabled = enabled;
    this.maxContinuationRounds = Math.max(1, Math.min(maxContinuationRounds, 10));
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
        // claim() re-validates project membership and target authorization. Those checks read the
        // current principal, and this runs on a timer/event thread with no HTTP user — so it must
        // run under system access or every continuation would fail with "please sign in".
        claim = authorization.callWithSystemAccess(() -> recovery.claim(id));
      } catch (Exception ignored) {
        continue;
      }
      if (claim == null) continue;
      try {
        // Checkpoint delivery and resumption likewise go through the authorized HTTP client and
        // the same membership checks, so they stay inside system access as well.
        String status;
        try {
          status =
              authorization.callWithSystemAccess(
                  () -> {
                    runtime.checkpointContinuation(
                        recovery.checkpointBody(claim), claim.projectId());
                    String delivered = "WAITING_TASKS";
                    for (Map<String, Object> callback : callbackBodies(claim)) {
                      Map<String, Object> result =
                          runtime.resumeContinuation(callback, claim.projectId());
                      delivered = Objects.toString(result.get("status"), "");
                    }
                    return delivered;
                  });
        } catch (Exception ex) {
          throw ex instanceof RuntimeException runtime ? runtime : new ApiException(ex.getMessage());
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
    String prompt = continuationPrompt(claim, ids);
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

  /**
   * Builds the prompt for one continuation turn.
   *
   * <h2>Why this text is the difference between "summary" and "loop"</h2>
   *
   * <p>This method used to forbid any action outright ("不要创建任务、执行工具或提出未授权动作"),
   * which made the whole continuation pipeline a dead end: tasks finished, the model summarised,
   * and nothing could ever follow up. The result was a single-shot platform whose "agent" could
   * never act on what it had just learned.
   *
   * <p>It now asks for a *next step proposal* instead — but a proposal only. The safety property
   * does not come from the model declining to act; it comes from the fact that anything it
   * proposes still has to pass the four-layer gate, get judged, and be confirmed by an
   * administrator before a single packet is sent. Removing the prohibition does not remove any
   * guard, it only stops the pipeline from stalling.
   *
   * <p>Two hard stops remain: the round budget (see {@link #maxContinuationRounds}) and the
   * explicit instruction that a completed assessment must end rather than invent more work.
   */
  private String continuationPrompt(
      CrossTurnRecoveryService.ContinuationClaim claim, List<Long> ids) {
    String taskList =
        ids.stream().map(String::valueOf).collect(java.util.stream.Collectors.joining(","));
    int round = claim.attempt() + 1;
    if (round >= maxContinuationRounds) {
      return "原 Agent 回合创建的受控任务已经全部进入终态。本轮是自动续接的第 "
          + round
          + " 轮，已达到允许的最大轮次，禁止再提出任何新的检测动作。"
          + "请读取服务端任务、Finding 和审计上下文，输出最终总结与后续人工处置建议。任务 ID："
          + taskList;
    }
    return "原 Agent 回合创建的受控任务已经全部进入终态。请先读取服务端任务结果、Finding 与审计上下文，"
        + "以这些真实结果为基础重新评估当前目标的安全状况。"
        + "如果结果中还有值得继续核实的问题，"
        + "请按当前工作流可用的工具提出下一步检测动作，并说明这一步依据的是哪一条已有证据；"
        + "如果结果已经足够支撑结论、或继续检测不会带来新信息，再给出总结并结束。"
        + "是否需要继续由结果本身决定，不要因为「已经扫过一轮」就默认收尾。"
        + "说明：你提出的任何动作都不会直接执行，会先经过授权与参数护栏校验、语义风险判定，"
        + "并由管理员在执行确认中逐次批准；未被批准的动作不会产生任何任务。任务 ID："
        + taskList;
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
