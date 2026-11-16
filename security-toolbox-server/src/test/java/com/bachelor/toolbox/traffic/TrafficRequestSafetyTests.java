package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class TrafficRequestSafetyTests {
  private AuthorizedTarget enabledTarget() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setEnabled(true);
    return target;
  }

  @Test
  void rejectsMissingAndDisabledTargets() {
    assertThatThrownBy(() -> TrafficRequestSafety.validateAuthorization(null))
        .isInstanceOf(ApiException.class).hasMessage("授权目标不存在");
    AuthorizedTarget target = enabledTarget();
    target.setEnabled(false);
    assertThatThrownBy(() -> TrafficRequestSafety.validateAuthorization(target))
        .isInstanceOf(ApiException.class).hasMessage("授权目标已停用");
  }

  @Test
  void rejectsFutureAuthorization() {
    AuthorizedTarget target = enabledTarget();
    target.setAuthorizationValidFrom(Instant.now().plusSeconds(3600));
    assertThatThrownBy(() -> TrafficRequestSafety.validateAuthorization(target))
        .isInstanceOf(ApiException.class).hasMessage("目标授权尚未生效");
  }

  @Test
  void rejectsExpiredAuthorization() {
    AuthorizedTarget target = enabledTarget();
    target.setAuthorizationExpiresAt(Instant.now().minusSeconds(3600));
    assertThatThrownBy(() -> TrafficRequestSafety.validateAuthorization(target))
        .isInstanceOf(ApiException.class).hasMessage("目标授权已过期");
  }

  @Test
  void acceptsCurrentWindow() {
    AuthorizedTarget target = enabledTarget();
    target.setAuthorizationValidFrom(Instant.now().minusSeconds(3600));
    target.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    assertThatCode(() -> TrafficRequestSafety.validateAuthorization(target)).doesNotThrowAnyException();
  }

  @Test
  void preservesOptionalTargetTimeBounds() {
    assertThatCode(() -> TrafficRequestSafety.validateAuthorization(enabledTarget()))
        .doesNotThrowAnyException();
  }
}
