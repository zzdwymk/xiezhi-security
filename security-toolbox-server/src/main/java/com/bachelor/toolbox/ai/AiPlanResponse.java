package com.bachelor.toolbox.ai;

import java.util.List;
import java.util.Map;

public record AiPlanResponse(
    String provider,
    String model,
    String summary,
    boolean requiresConfirmation,
    List<PlanStep> steps) {
  public record PlanStep(
      String toolCode, String title, String reason, Map<String, Object> parameters) {}
}
