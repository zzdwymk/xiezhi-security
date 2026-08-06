package com.bachelor.toolbox.ai;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;

public record AiAnswerRequest(
    @NotNull(message = "项目 ID 不能为空") Long projectId,
    @NotNull(message = "目标 ID 不能为空") Long targetId,
    @NotBlank(message = "提示内容不能为空") @Size(max = 4000, message = "提示内容长度不得超过 4000 个字符")
        String prompt,    @NotEmpty(message = "任务 ID 列表不能为空") @Size(max = 20, message = "任务 ID 数量不得超过 20 个")
        List<@NotNull(message = "任务 ID 不能为空") Long> taskIds) {}
