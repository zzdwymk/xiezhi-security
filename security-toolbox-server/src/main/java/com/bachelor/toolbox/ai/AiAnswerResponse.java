package com.bachelor.toolbox.ai;

import java.util.List;
import java.util.Map;

public record AiAnswerResponse(
    Long targetId,
    List<Long> taskIds,
    String provider,
    String model,
    String answer,
    int taskCount,
    int successCount,
    int failedCount,
    int findingCount,
    Map<String, Long> severityCounts) {}
