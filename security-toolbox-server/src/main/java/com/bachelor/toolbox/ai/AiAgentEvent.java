package com.bachelor.toolbox.ai;

import java.time.Instant;
import java.util.Map;

public record AiAgentEvent(
    long sequence,
    String type,
    AgentPhase phase,
    String status,
    String message,
    Instant timestamp,
    Map<String, Object> data) {}
