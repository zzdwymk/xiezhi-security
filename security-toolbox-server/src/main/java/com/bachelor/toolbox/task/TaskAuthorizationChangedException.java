package com.bachelor.toolbox.task;

import com.bachelor.toolbox.common.ApiException;

final class TaskAuthorizationChangedException extends ApiException {
  TaskAuthorizationChangedException(String message) {
    super(message);
  }

  TaskAuthorizationChangedException(String message, Throwable cause) {
    super(message);
    initCause(cause);
  }
}
