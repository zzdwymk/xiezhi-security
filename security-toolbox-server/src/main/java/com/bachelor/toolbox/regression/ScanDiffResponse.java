package com.bachelor.toolbox.regression;

import java.time.Instant;
import java.util.List;

public record ScanDiffResponse(
    Long baselineTaskId,
    Long currentTaskId,
    Long targetId,
    Instant generatedAt,
    Summary summary,
    List<Item> items) {
  public record Summary(
      int baselineCount,
      int currentCount,
      int added,
      int persistent,
      int resolved,
      int severityChanged) {}

  public record Item(
      String changeType,
      String fingerprint,
      Long baselineFindingId,
      Long currentFindingId,
      String title,
      String previousSeverity,
      String currentSeverity,
      String ruleCode,
      String vulnerabilityCode) {}
}
