package com.bachelor.toolbox.postscan;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;

public record PostScanPathRequest(
    @NotNull(message = "项目 ID 不能为空") Long projectId,
    @NotNull(message = "目标 ID 不能为空") Long targetId,
    @NotEmpty(message = "发现项 ID 列表不能为空") @Size(max = 20, message = "发现项 ID 数量不得超过 20 个")
        List<@NotNull(message = "发现项 ID 不能为空") Long> findingIds,
    @Size(max = 1000, message = "分析目标长度不得超过 1000 个字符") String objective) {}