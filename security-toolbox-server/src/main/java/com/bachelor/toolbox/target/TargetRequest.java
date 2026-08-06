package com.bachelor.toolbox.target;

import jakarta.validation.constraints.NotBlank;
import java.time.Instant;

public record TargetRequest(
    @NotBlank(message = "目标名称不能为空") String name,
    @NotBlank(message = "目标地址不能为空") String targetValue,
    @NotBlank(message = "目标类型不能为空") String targetType,
    @NotBlank(message = "授权记录不能为空") String authorizationNote,
    String allowedPorts,
    Boolean enabled,
    Instant authorizationValidFrom,
    Instant authorizationExpiresAt,
    Long projectId) {
  public TargetRequest(
      String name,
      String targetValue,
      String targetType,
      String authorizationNote,
      String allowedPorts,
      Boolean enabled) {
    this(name, targetValue, targetType, authorizationNote, allowedPorts, enabled, null, null, null);
  }
}
