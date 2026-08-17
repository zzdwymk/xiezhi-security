package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Coordinates durable continuation execution with the Java conversation/audit transaction.
 *
 * <p>Preparation uses a separate transaction so the execution fence survives a JVM crash. The
 * actual orchestrator call then runs in one transaction with the response receipt and tombstone
 * completion. Database side effects therefore commit together, while an in-flight crash is
 * treated as an unknown result and safely skipped on recovery.
 */
@Service
public class AgentContinuationExecutionService {
  private static final int MAX_RESPONSE_CHARS = 100_000;

  private final AgentContinuationExecutionRepository executions;
  private final CrossTurnRecoveryService recovery;
  private final ObjectMapper objectMapper;

  public AgentContinuationExecutionService(
      AgentContinuationExecutionRepository executions,
      CrossTurnRecoveryService recovery,
      ObjectMapper objectMapper) {
    this.executions = executions;
    this.recovery = recovery;
    this.objectMapper = objectMapper;
  }

  /** Acquire the deterministic turn once, committing the fence before model invocation. */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public Preparation prepare(CrossTurnRecoveryService.ContinuationClaim claim) {
    AgentContinuationExecution existing =
        executions.findLockedByTombstoneId(claim.tombstoneId()).orElse(null);
    if (existing != null) {
      validateIdentity(existing, claim);
      if (AgentContinuationExecution.COMPLETED.equals(existing.getStatus())) {
        return Preparation.completed(readResponse(existing));
      }
      return Preparation.skip(existing.getStatus());
    }
    AgentContinuationExecution created = new AgentContinuationExecution();
    created.setTombstoneId(claim.tombstoneId());
    created.setContinuationTurnId(continuationTurnId(claim));
    created.setRequestDigest(claim.requestDigest());
    created.setStatus(AgentContinuationExecution.STARTED);
    executions.saveAndFlush(created);
    return Preparation.execute();
  }

  /** Execute and commit response, conversation messages, audit, and tombstone completion together. */
  @Transactional
  public AiAgentResponse execute(
      CrossTurnRecoveryService.ContinuationClaim claim, Supplier<AiAgentResponse> operation) {
    AgentContinuationExecution execution =
        executions.findLockedByTombstoneId(claim.tombstoneId()).orElseThrow(
            () -> new ApiException("Agent 续接执行记录不存在"));
    validateIdentity(execution, claim);
    if (AgentContinuationExecution.COMPLETED.equals(execution.getStatus())) {
      return readResponse(execution);
    }
    if (!AgentContinuationExecution.STARTED.equals(execution.getStatus())) {
      throw new ApiException("Agent 续接执行已安全跳过");
    }
    AiAgentResponse response = Objects.requireNonNull(operation.get(), "续接未返回结果");
    String json = serialize(response);
    execution.setResponseJson(json);
    execution.setResponseDigest(digest(json));
    execution.setStatus(AgentContinuationExecution.COMPLETED);
    execution.setCompletedAt(Instant.now());
    execution.setReason(null);
    executions.save(execution);
    // Joins this transaction; the completion audit and tombstone state are committed atomically.
    recovery.markContinued(claim.tombstoneId());
    return response;
  }

  /** Reuse a committed result and repair a tombstone that was not observed as completed. */
  @Transactional
  public AiAgentResponse reuse(CrossTurnRecoveryService.ContinuationClaim claim) {
    AgentContinuationExecution execution =
        executions.findLockedByTombstoneId(claim.tombstoneId()).orElseThrow(
            () -> new ApiException("Agent 续接执行记录不存在"));
    validateIdentity(execution, claim);
    if (!AgentContinuationExecution.COMPLETED.equals(execution.getStatus())) {
      throw new ApiException("Agent 续接尚无可复用结果");
    }
    AiAgentResponse response = readResponse(execution);
    recovery.markContinued(claim.tombstoneId());
    return response;
  }

  /** Safely close an in-doubt or runtime-already-completed turn without invoking the model. */
  @Transactional
  public void skip(
      CrossTurnRecoveryService.ContinuationClaim claim, String status, String reason) {
    AgentContinuationExecution execution =
        executions.findLockedByTombstoneId(claim.tombstoneId()).orElse(null);
    if (execution == null) {
      execution = new AgentContinuationExecution();
      execution.setTombstoneId(claim.tombstoneId());
      execution.setContinuationTurnId(continuationTurnId(claim));
      execution.setRequestDigest(claim.requestDigest());
    } else {
      validateIdentity(execution, claim);
    }
    if (!AgentContinuationExecution.COMPLETED.equals(execution.getStatus())) {
      execution.setStatus(
          "IN_DOUBT".equals(status)
              ? AgentContinuationExecution.ABANDONED
              : AgentContinuationExecution.SKIPPED);
      execution.setReason(safeReason(reason));
      executions.save(execution);
    }
    recovery.markSkipped(claim.tombstoneId(), safeReason(reason));
  }

  private void validateIdentity(
      AgentContinuationExecution execution, CrossTurnRecoveryService.ContinuationClaim claim) {
    if (!Objects.equals(execution.getTombstoneId(), claim.tombstoneId())
        || !Objects.equals(execution.getContinuationTurnId(), continuationTurnId(claim))
        || !Objects.equals(execution.getRequestDigest(), claim.requestDigest())) {
      throw new ApiException("Agent 续接执行记录身份不一致");
    }
  }

  private AiAgentResponse readResponse(AgentContinuationExecution execution) {
    if (execution.getResponseJson() == null || execution.getResponseDigest() == null
        || !Objects.equals(execution.getResponseDigest(), digest(execution.getResponseJson()))) {
      throw new ApiException("Agent 续接结果记录损坏");
    }
    try {
      return objectMapper.readValue(execution.getResponseJson(), AiAgentResponse.class);
    } catch (Exception ex) {
      throw new ApiException("Agent 续接结果记录无法读取");
    }
  }

  private String serialize(AiAgentResponse response) {
    try {
      String value = objectMapper.writeValueAsString(response);
      if (value.length() > MAX_RESPONSE_CHARS) throw new ApiException("Agent 续接结果过大");
      return value;
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException("Agent 续接结果无法保存");
    }
  }

  private String continuationTurnId(CrossTurnRecoveryService.ContinuationClaim claim) {
    String seed = claim.runId() + ":" + claim.nodeRunId() + ":" + claim.taskIds();
    return "resume-" + digest(seed).substring(7, 55);
  }

  private String digest(String value) {
    try {
      return "sha256:"
          + java.util.HexFormat.of().formatHex(
              MessageDigest.getInstance("SHA-256")
                  .digest(Objects.toString(value, "").getBytes(StandardCharsets.UTF_8)));
    } catch (Exception ex) {
      throw new IllegalStateException("续接执行摘要失败", ex);
    }
  }

  private String safeReason(String reason) {
    String value = Objects.toString(reason, "UNKNOWN");
    return value.length() <= 500 ? value : value.substring(0, 500);
  }

  public record Preparation(Kind kind, AiAgentResponse response, String status) {
    static Preparation execute() { return new Preparation(Kind.EXECUTE, null, AgentContinuationExecution.STARTED); }
    static Preparation completed(AiAgentResponse response) { return new Preparation(Kind.COMPLETED, response, AgentContinuationExecution.COMPLETED); }
    static Preparation skip(String status) { return new Preparation(Kind.SKIP, null, status); }
    public enum Kind { EXECUTE, COMPLETED, SKIP }
  }
}
