package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.target.AuthorizedTarget;
import java.util.Map;

public interface SecurityTool {
  String code();

  String displayName();

  String description();

  ToolExecutionResult execute(AuthorizedTarget target, Map<String, Object> parameters)
      throws Exception;

  default ToolExecutionResult execute(
      AuthorizedTarget target, Map<String, Object> parameters, ToolExecutionObserver observer)
      throws Exception {
    return execute(target, parameters);
  }
}
