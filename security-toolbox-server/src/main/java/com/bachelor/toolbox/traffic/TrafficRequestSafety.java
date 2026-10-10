package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import java.time.Instant;

/** Checks made at the point of an active operation, never when capturing or reading traffic. */
final class TrafficRequestSafety {
  private TrafficRequestSafety() {}

  static void validateAuthorization(AuthorizedTarget target) {
    if (target == null) throw new ApiException("授权目标不存在");
    if (!target.isEnabled()) throw new ApiException("授权目标已停用");
    Instant now = Instant.now();
    if (target.getAuthorizationValidFrom() != null && now.isBefore(target.getAuthorizationValidFrom())) {
      throw new ApiException("目标授权尚未生效");
    }
    if (target.getAuthorizationExpiresAt() != null && !now.isBefore(target.getAuthorizationExpiresAt())) {
      throw new ApiException("目标授权已过期");
    }
  }

}
