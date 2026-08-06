package com.bachelor.toolbox.ai;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;

public record AiPlanRequest(
    Long projectId,
    @NotNull(message = "目标 ID 不能为空") Long targetId,
    @NotBlank(message = "提示内容不能为空") String prompt,
    ContextRefs contextRefs,
    List<ContextRef> refs,
    String mode) {
  public AiPlanRequest(Long targetId, String prompt) {
    this(null, targetId, prompt, null, null, null);
  }

  public AiPlanRequest(Long targetId, String prompt, ContextRefs contextRefs) {
    this(null, targetId, prompt, contextRefs, null, null);
  }

  /** Compatibility constructor for callers that predate project-scoped agent execution. */
  public AiPlanRequest(
      Long targetId, String prompt, ContextRefs contextRefs, List<ContextRef> refs, String mode) {
    this(null, targetId, prompt, contextRefs, refs, mode);
  }

  public record ContextRefs(
      Long targetId,
      List<Long> taskIds,
      List<Long> findingIds,
      List<Long> vulnerabilityIds,
      List<Long> auditIds,
      List<Long> trafficIds) {}

  public record ContextRef(String type, Long id, Long targetId, String title) {}
}
