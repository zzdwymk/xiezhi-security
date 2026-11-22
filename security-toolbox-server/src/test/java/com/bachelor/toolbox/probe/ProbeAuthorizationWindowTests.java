package com.bachelor.toolbox.probe;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProject;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * 第305轮：探测入口的项目授权窗口边界（R304 修复的回归锁定）。
 *
 * <p>R304 前探测用 {@code now.isAfter(expiresAt)}，到期时刻仍放行；现统一为右开区间。本测试锁定
 * 「到期前 1 秒可探测、恰好到期即拒绝」，并把该分支纳入可回归验证（此前只有代码审查）。
 */
class ProbeAuthorizationWindowTests {
  private ProbeService service() {
    return new ProbeService(null, null, null, null, null, null, null);
  }

  private AssessmentProject projectExpiringAt(Instant expiry) {
    AssessmentProject project = new AssessmentProject();
    project.setStatus("ACTIVE");
    project.setAuthorizationValidFrom(expiry.minusSeconds(3600));
    project.setAuthorizationExpiresAt(expiry);
    return project;
  }

  @Test
  void projectExpiringInTheFutureAllowsProbe() {
    assertThatCode(() -> service().validateProjectAuthorization(projectExpiringAt(Instant.now().plusSeconds(60))))
        .doesNotThrowAnyException();
  }

  @Test
  void alreadyExpiredProjectIsRejected() {
    assertThatThrownBy(() -> service().validateProjectAuthorization(projectExpiringAt(Instant.now().minusSeconds(1))))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("项目授权已过期");
  }
}
