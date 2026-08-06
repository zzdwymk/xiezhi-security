package com.bachelor.toolbox.task;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Map;

public record CreateTaskRequest(
    @NotNull(message = "项目 ID 不能为空") Long projectId,
    @NotNull(message = "目标 ID 不能为空") Long targetId,
    @NotBlank(message = "工具代码不能为空") String toolCode,
    Map<String, Object> parameters) {
  /** Compatibility constructor for internal callers; project is resolved later when available. */
  public CreateTaskRequest(Long targetId, String toolCode, Map<String, Object> parameters) {
    this(null, targetId, toolCode, parameters);
  }
}
