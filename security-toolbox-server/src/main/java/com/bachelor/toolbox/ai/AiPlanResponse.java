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
      String toolCode,
      String title,
      String reason,
      Map<String, Object> parameters,
      String workflowNodeId,
      int group,
      List<String> dependsOnNodeIds,
      String risk,
      boolean requiresApproval,
      List<String> evidenceRefs) {
    public PlanStep {
      parameters = parameters == null ? Map.of() : Map.copyOf(parameters);
      dependsOnNodeIds = dependsOnNodeIds == null ? List.of() : List.copyOf(dependsOnNodeIds);
      risk = risk == null || risk.isBlank() ? "SAFE" : risk;
      evidenceRefs = evidenceRefs == null ? List.of() : List.copyOf(evidenceRefs);
    }

    /** Compatibility constructor for Java planner and existing non-workflow callers. */
    public PlanStep(
        String toolCode, String title, String reason, Map<String, Object> parameters) {
      this(toolCode, title, reason, parameters, null, 0, List.of(), "SAFE", false, List.of());
    }
  }
}
