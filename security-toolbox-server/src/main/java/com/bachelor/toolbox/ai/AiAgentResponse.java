package com.bachelor.toolbox.ai;

import java.time.Instant;
import java.util.List;

public record AiAgentResponse(
    String sessionId,
    Long projectId,
    Long targetId,
    String message,
    AiPlanResponse plan,
    String guardStatus,
    String approvalStatus,
    boolean executed,
    List<Long> taskIds,
    AgentReview review,
    int memoryMessages,
    Instant completedAt) {
  public record AgentReview(
      String status, String summary, boolean retryAllowed, List<Long> verifiedTaskIds) {}
}
