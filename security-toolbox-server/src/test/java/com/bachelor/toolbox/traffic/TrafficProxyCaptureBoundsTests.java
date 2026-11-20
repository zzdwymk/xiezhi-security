package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Round 251：代理抓包字段必须匹配 TrafficPacket 列宽。 */
class TrafficProxyCaptureBoundsTests {
  @Test
  void boundsHostPathAndContentType() {
    assertThat(TrafficProxyService.bounded("h".repeat(300), 253)).hasSize(253);
    assertThat(TrafficProxyService.bounded("p".repeat(3000), 2048)).hasSize(2048);
    assertThat(TrafficProxyService.bounded("c".repeat(300), 200)).hasSize(200);
    assertThat(TrafficProxyService.bounded("s".repeat(120), 100)).hasSize(100);
    assertThat(TrafficProxyService.bounded(null, 253)).isNull();
  }
}
