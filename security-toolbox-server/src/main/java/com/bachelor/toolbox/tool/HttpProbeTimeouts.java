package com.bachelor.toolbox.tool;

import java.time.Duration;

/**
 * HTTP 探测类工具的连接/响应超时取值。
 *
 * <p>背景：{@code http_headers} 与 {@code http_security_check} 本质是「对授权目标发一次 GET」。
 * 原先把 {@code connectTimeout} 硬编码为 5 秒、{@code HttpRequest.timeout} 硬编码为 10 秒，
 * 目标 Web 服务假死或反代后端挂起时，会在 5 秒左右抛出 {@code HttpTimeoutException}，
 * 被任务层归类为 {@code TIMEOUT}，用户只看到「已超时」，既改不了也看不出是连接阶段还是响应阶段超时。
 *
 * <p>这里把两者都做成可配置，并且**保证请求超时不小于连接超时**：
 * 若 {@code requestTimeout < connectTimeout}，请求层会先于连接层触发，配置就成了误导。
 */
public final class HttpProbeTimeouts {

  /** 连接超时默认值（秒）。家用/内网慢目标或握手挂起时，5 秒偏紧。 */
  public static final int DEFAULT_CONNECT_TIMEOUT_SECONDS = 10;

  /** 单次 HTTP 响应超时默认值（秒）。 */
  public static final int DEFAULT_REQUEST_TIMEOUT_SECONDS = 20;

  private HttpProbeTimeouts() {}

  /** 约束到合法区间：非正数回落到默认值，避免配置成 0 导致「立即超时」。 */
  public static Duration connectTimeout(int configuredSeconds) {
    return Duration.ofSeconds(
        configuredSeconds > 0 ? configuredSeconds : DEFAULT_CONNECT_TIMEOUT_SECONDS);
  }

  /**
   * 单次请求超时。始终不短于连接超时，避免请求层抢在连接层之前触发，
   * 使日志和终止原因无法区分「连不上」与「连上了但不回包」。
   */
  public static Duration requestTimeout(int configuredSeconds, Duration connectTimeout) {
    Duration requested =
        Duration.ofSeconds(
            configuredSeconds > 0 ? configuredSeconds : DEFAULT_REQUEST_TIMEOUT_SECONDS);
    return requested.compareTo(connectTimeout) < 0 ? connectTimeout : requested;
  }
}
