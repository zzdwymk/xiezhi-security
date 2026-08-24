package com.bachelor.toolbox.auth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** 登录失败节流：连续失败达到阈值后锁定，成功后清零。 */
class LoginAttemptServiceTests {
  private final LoginAttemptService service = new LoginAttemptService(3, 300);

  @Test
  void 初始状态不锁定() {
    assertThat(service.isBlocked("admin", "127.0.0.1")).isFalse();
  }

  @Test
  void 未达阈值时不锁定() {
    service.recordFailure("admin", "127.0.0.1");
    service.recordFailure("admin", "127.0.0.1");

    assertThat(service.isBlocked("admin", "127.0.0.1")).isFalse();
  }

  @Test
  void 达到阈值后进入锁定并给出剩余时间() {
    for (int i = 0; i < 3; i++) {
      service.recordFailure("admin", "127.0.0.1");
    }

    assertThat(service.isBlocked("admin", "127.0.0.1")).isTrue();
    assertThat(service.remainingLockSeconds("admin", "127.0.0.1")).isPositive();
  }

  @Test
  void 登录成功后计数清零() {
    service.recordFailure("admin", "127.0.0.1");
    service.recordFailure("admin", "127.0.0.1");
    service.recordSuccess("admin", "127.0.0.1");
    service.recordFailure("admin", "127.0.0.1");

    // 清零后重新计数，单次失败不应触发锁定
    assertThat(service.isBlocked("admin", "127.0.0.1")).isFalse();
  }

  @Test
  void 锁定按用户名与来源地址分别计数() {
    for (int i = 0; i < 3; i++) {
      service.recordFailure("admin", "127.0.0.1");
    }

    assertThat(service.isBlocked("admin", "127.0.0.1")).isTrue();
    // 同一账号、不同来源不受影响
    assertThat(service.isBlocked("admin", "10.0.0.5")).isFalse();
    // 同一来源、不同账号不受影响
    assertThat(service.isBlocked("other", "127.0.0.1")).isFalse();
  }

  @Test
  void 用户名大小写与空白不影响计数归并() {
    service.recordFailure("Admin", "127.0.0.1");
    service.recordFailure(" admin ", "127.0.0.1");
    service.recordFailure("ADMIN", "127.0.0.1");

    assertThat(service.isBlocked("admin", "127.0.0.1")).isTrue();
  }
}
