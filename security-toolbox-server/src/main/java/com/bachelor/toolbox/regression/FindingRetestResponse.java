package com.bachelor.toolbox.regression;

import java.time.Instant;

public record FindingRetestResponse(
    Long findingId,
    Long baselineTaskId,
    Long retestTaskId,
    Long targetId,
    String ruleCode,
    String vulnerabilityCode,
    String status,
    Instant requestedAt) {}
