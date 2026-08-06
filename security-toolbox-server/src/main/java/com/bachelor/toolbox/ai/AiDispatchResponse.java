package com.bachelor.toolbox.ai;

import java.util.List;

public record AiDispatchResponse(
    Long targetId, AiPlanResponse plan, int taskCount, List<Long> taskIds) {}
