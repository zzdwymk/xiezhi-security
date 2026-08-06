package com.bachelor.toolbox.common;

import java.time.Instant;

public record ApiErrorResponse(Instant timestamp, int status, String message) {
  public static ApiErrorResponse of(int status, String message) {
    return new ApiErrorResponse(Instant.now(), status, message);
  }
}
