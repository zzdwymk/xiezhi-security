package com.bachelor.toolbox.task;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.Map;

public record CreateTaskRequest(
    @NotNull(message = "项目 ID 不能为空") Long projectId,
    @NotNull(message = "目标 ID 不能为空") Long targetId,
    @NotBlank(message = "工具代码不能为空")
        // Round 248：SecurityTask.toolCode 列宽 50，先校验避免超长值进入服务/DB。
        @Size(max = 50, message = "工具代码不能超过 50 个字符")
        String toolCode,
    Map<String, Object> parameters) {
  /** Compatibility constructor for internal callers; project is resolved later when available. */
  public CreateTaskRequest(Long targetId, String toolCode, Map<String, Object> parameters) {
    this(null, targetId, toolCode, parameters);
  }
}
