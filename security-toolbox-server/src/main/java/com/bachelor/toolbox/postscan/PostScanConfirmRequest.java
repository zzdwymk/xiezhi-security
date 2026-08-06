package com.bachelor.toolbox.postscan;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;

public record PostScanConfirmRequest(
    @NotNull(message = "确认状态不能为空") Boolean acknowledged,
    @Size(max = 4, message = "所选步骤数量不得超过 4 个") List<String> selectedStepIds) {}
