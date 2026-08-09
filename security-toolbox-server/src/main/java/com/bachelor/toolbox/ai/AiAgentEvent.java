package com.bachelor.toolbox.ai;

import java.time.Instant;
import java.util.Map;

public record AiAgentEvent(
    long sequence,
    int contractVersion,
    String runId,
    long stateVersion,
    String policyRevision,
    String workflowDigest,
    String outerNodeId,
    String nodeRunId,
    String innerStep,
    long ledgerSequence,
    String ledgerEntryDigest,
    String terminationReason,
    String type,
    AgentPhase phase,
    String status,
    String message,
    Instant timestamp,
    Map<String, Object> data) {
  public AiAgentEvent {
    workflowDigest = text(workflowDigest);
    outerNodeId = text(outerNodeId);
    nodeRunId = text(nodeRunId);
    innerStep = text(innerStep);
    ledgerEntryDigest = text(ledgerEntryDigest);
    terminationReason = text(terminationReason);
    data = data == null ? Map.of() : Map.copyOf(data);
  }

  /**
   * Compatibility constructor for Java orchestration events and older controller adapters.
   *
   * <p>Known v3 fields are recovered from {@code data}; this also preserves them when an adapter
   * enriches and rebuilds an event without yet using the expanded canonical constructor.
   */
  public AiAgentEvent(
      long sequence,
      int contractVersion,
      String runId,
      long stateVersion,
      String policyRevision,
      String type,
      AgentPhase phase,
      String status,
      String message,
      Instant timestamp,
      Map<String, Object> data) {
    this(
        sequence,
        contractVersion,
        runId,
        stateVersion,
        policyRevision,
        text(data, "workflowDigest"),
        text(data, "outerNodeId"),
        text(data, "nodeRunId"),
        text(data, "innerStep"),
        number(data, "ledgerSequence"),
        text(data, "ledgerEntryDigest"),
        text(data, "terminationReason"),
        type,
        phase,
        status,
        message,
        timestamp,
        data);
  }

  private static String text(Map<String, Object> data, String key) {
    return data == null ? "" : text(data.get(key));
  }

  private static String text(Object value) {
    return value instanceof String text ? text : "";
  }

  private static long number(Map<String, Object> data, String key) {
    if (data == null) return 0L;
    Object value = data.get(key);
    return value instanceof Number number ? number.longValue() : 0L;
  }
}
