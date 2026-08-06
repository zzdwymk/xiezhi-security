package com.bachelor.toolbox.postscan;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record PostScanPathResponse(
    Long id,
    Long targetId,
    Long projectId,
    List<Long> findingIds,    String provider,
    String model,
    String summary,
    String analysis,
    String status,
    Instant expiresAt,
    boolean requiresConfirmation,
    List<PathHypothesis> paths,
    List<RecommendedStep> steps,
    List<Long> taskIds) {
  public record PathHypothesis(
      String id,
      String title,
      String riskLevel,
      String confidence,
      String goal,
      List<String> prerequisites,
      String evidenceBasis,
      List<String> limitations,
      List<String> stopConditions) {}

  public record RecommendedStep(
      String id,
      String title,
      String phase,
      String riskLevel,
      String reason,
      List<String> prerequisites,
      String expectedEvidence,
      String impact,
      boolean automated,
      String toolCode,
      Map<String, Object> parameters,
      String blockedReason) {}
}
