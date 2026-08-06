package com.bachelor.toolbox.tool;

import java.util.List;
import java.util.Map;

public record ToolExecutionResult(
    String summary, Map<String, Object> data, List<FindingDraft> findings) {}
