package com.bachelor.toolbox.postscan;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * 第305轮：后续路径到期判断的边界与空值。
 *
 * <p>R304 把「到期时刻仍可执行」修正为右开区间；本轮补两点：① 到期时刻必须判为已过期（回归锁定）；
 * ② {@code expiresAt} 列允许为空，null 必须按"已过期"处理，否则历史数据会在执行时抛 NPE（500）。
 */
class PostScanPathExpiryTests {
  private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");

  @Test
  void exactlyAtExpiryIsExpired() {
    assertThat(PostScanPathService.isExpired(NOW, NOW)).isTrue();
  }

  @Test
  void oneSecondBeforeExpiryIsNotExpired() {
    assertThat(PostScanPathService.isExpired(NOW, NOW.minusSeconds(1))).isFalse();
  }

  @Test
  void nullExpiryIsTreatedAsExpired() {
    assertThat(PostScanPathService.isExpired(null, NOW))
        .as("历史数据 expiresAt 为空时必须 fail-closed，而不是抛 NPE")
        .isTrue();
  }
}
