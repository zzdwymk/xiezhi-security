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

  @Test
  void 海量不同用户名不会导致条目无界增长内存耗尽() {
    // 模拟攻击者用海量不同用户名各失败一次（不达阈值、不再重试）；
    // 若无容量上限，条目会持续增长至 OOM。修复后条目数必须被上限约束。
    int distinct = LoginAttemptService.MAX_ENTRIES * 3 + 137;
    for (int i = 0; i < distinct; i++) {
      service.recordFailure("victim-" + i, "127.0.0.1");
    }
    assertThat(service.size())
        .as("登录尝试记录必须被容量上限约束，杜绝内存耗尽")
        .isLessThanOrEqualTo(LoginAttemptService.MAX_ENTRIES);
  }

  @Test
  void 容量控制不影响正常锁定语义() {
    // 灌满大量无关条目后，对目标账号的节流仍然生效。
    for (int i = 0; i < LoginAttemptService.MAX_ENTRIES + 500; i++) {
      service.recordFailure("noise-" + i, "127.0.0.1");
    }
    for (int i = 0; i < 3; i++) {
      service.recordFailure("realadmin", "127.0.0.1");
    }
    assertThat(service.isBlocked("realadmin", "127.0.0.1")).isTrue();
  }
}
