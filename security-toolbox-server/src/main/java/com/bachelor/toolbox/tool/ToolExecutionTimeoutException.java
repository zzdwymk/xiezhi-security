package com.bachelor.toolbox.tool;

import java.util.Objects;
import java.util.concurrent.TimeoutException;

/** A timed-out execution whose scope-validated observations may still be retained. */
public final class ToolExecutionTimeoutException extends TimeoutException {
  private final ToolExecutionResult partialResult;

  public ToolExecutionTimeoutException(String message, ToolExecutionResult partialResult) {
    super(message);
    this.partialResult = Objects.requireNonNull(partialResult);
  }

  public ToolExecutionResult partialResult() {
    return partialResult;
  }
}
