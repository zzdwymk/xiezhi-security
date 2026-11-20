package com.bachelor.toolbox.schedule;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.Map;

public record CreateScheduleRequest(
    @NotNull(message = "项目 ID 不能为空") Long projectId,
    @NotNull(message = "目标 ID 不能为空") Long targetId,
    @NotBlank(message = "工具代码不能为空")
        // Round 247：ScanSchedule.toolCode 列宽 50，先校验避免超长值进入服务/DB。
        @Size(max = 50, message = "工具代码不能超过 50 个字符")
        String toolCode,
    Map<String, Object> parameters,
    // Round 247：ScanSchedule.cronExpression 列宽 120，先校验避免超长表达式写入失败。
    @Size(max = 120, message = "Cron 表达式不能超过 120 个字符") String cronExpression,
    @Min(value = 60, message = "执行间隔不得少于 60 秒") Long intervalSeconds,
    Boolean enabled) {}
