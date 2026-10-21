package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class HttpProbeTimeoutsTests {

  @Test
  void defaultsWidenConnectWindowBeyondTheOldFiveSeconds() {
    // 原先硬编码 5 秒，慢目标/假死服务会在连接阶段被判 TIMEOUT。
    assertThat(HttpProbeTimeouts.DEFAULT_CONNECT_TIMEOUT_SECONDS)
        .isGreaterThan(5)
        .isEqualTo(10);
    assertThat(HttpProbeTimeouts.connectTimeout(0))
        .isEqualTo(Duration.ofSeconds(HttpProbeTimeouts.DEFAULT_CONNECT_TIMEOUT_SECONDS));
  }

  @Test
  void nonPositiveConfigurationFallsBackToDefaultsInsteadOfImmediateTimeout() {
    // 配置成 0 / 负数绝不能变成「立即超时」。
    assertThat(HttpProbeTimeouts.connectTimeout(-1)).isEqualTo(Duration.ofSeconds(10));
    assertThat(HttpProbeTimeouts.requestTimeout(-5, Duration.ofSeconds(10)))
        .isEqualTo(Duration.ofSeconds(20));
  }

  @Test
  void requestTimeoutNeverShorterThanConnectTimeout() {
    // 请求层若先于连接层触发，日志就无法区分「连不上」与「连上了但不回包」。
    Duration connect = Duration.ofSeconds(10);

    assertThat(HttpProbeTimeouts.requestTimeout(5, connect))
        .as("配置的请求超时短于连接超时时，必须被抬到连接超时")
        .isEqualTo(connect);
    assertThat(HttpProbeTimeouts.requestTimeout(30, connect)).isEqualTo(Duration.ofSeconds(30));
  }

  @Test
  void honoursExplicitConfiguration() {
    assertThat(HttpProbeTimeouts.connectTimeout(15)).isEqualTo(Duration.ofSeconds(15));
    assertThat(HttpProbeTimeouts.requestTimeout(45, Duration.ofSeconds(15)))
        .isEqualTo(Duration.ofSeconds(45));
  }
}
