package com.bachelor.toolbox.schedule;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Map;

public record CreateScheduleRequest(
    @NotNull(message = "项目 ID 不能为空") Long projectId,
    @NotNull(message = "目标 ID 不能为空") Long targetId,
    @NotBlank(message = "工具代码不能为空") String toolCode,
    Map<String, Object> parameters,
    String cronExpression,
    @Min(value = 60, message = "执行间隔不得少于 60 秒") Long intervalSeconds,
    Boolean enabled) {}
