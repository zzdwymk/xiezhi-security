package com.bachelor.toolbox.project;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * 第303轮：项目授权时间窗的边界语义。
 *
 * <p>目标级校验用的是 {@code !now.isBefore(expiresAt)}（到期时刻即拒绝），而项目级原先用
 * {@code now.isAfter(expiresAt)}，恰好等于到期时刻时**仍然放行**。两处语义不一致，且项目侧偏松：
 * 在授权到期的那一刻仍会放行任务。安全边界应当"到期即失效"。
 */
class ProjectAuthorizationWindowBoundaryTests {
  @Test
  void exactlyAtExpiryInstantIsRejected() {
    AssessmentProjectService service =
        new AssessmentProjectService(
            null, null, null, null, null, null, null, null);
    AssessmentProject project = new AssessmentProject();
    Instant expiry = Instant.parse("2026-06-01T00:00:00Z");
    project.setStatus("ACTIVE");
    project.setAuthorizationValidFrom(Instant.parse("2026-01-01T00:00:00Z"));
    project.setAuthorizationExpiresAt(expiry);

    assertThatThrownBy(() -> service.validateAuthorizationWindow(project, expiry))
        .as("授权到期时刻本身必须视为已过期（与目标级语义一致）")
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("项目授权已过期");
  }

  @Test
  void oneSecondBeforeExpiryIsStillValid() {
    AssessmentProjectService service =
        new AssessmentProjectService(
            null, null, null, null, null, null, null, null);
    AssessmentProject project = new AssessmentProject();
    Instant expiry = Instant.parse("2026-06-01T00:00:00Z");
    project.setStatus("ACTIVE");
    project.setAuthorizationValidFrom(Instant.parse("2026-01-01T00:00:00Z"));
    project.setAuthorizationExpiresAt(expiry);

    assertThatCode(() -> service.validateAuthorizationWindow(project, expiry.minusSeconds(1)))
        .doesNotThrowAnyException();
  }
}
