package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

/**
 * 第354轮：代理路径聚合必须按 targetId 隔离。
 *
 * <p>原查询只按 host 过滤：同一 host 被两个项目的目标使用时，项目 B 的资产同步会把项目 A
 * 抓到的路径也聚合进来（跨项目数据泄漏）。修复后按 targetId 过滤。
 */
@DataJpaTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:traffic-endpoint-scope;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop"
    })
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class TrafficPacketEndpointScopeTests {

  @Autowired private TrafficPacketRepository packets;

  @Test
  void endpointsAreScopedByTargetId() {
    packets.save(packet(1L, 11L, "/a"));
    packets.save(packet(1L, 11L, "/b"));
    packets.save(packet(2L, 11L, "/c"));

    var toTarget1 = packets.findDistinctEndpointsByTargetIdAndHost(1L, "192.168.222.157");
    var toTarget2 = packets.findDistinctEndpointsByTargetIdAndHost(2L, "192.168.222.157");

    assertThat(toTarget1).hasSize(2);
    assertThat(toTarget2).hasSize(1);
    assertThat(toTarget1.stream().map(row -> row[3])).doesNotContain("/c");
  }

  private static TrafficPacket packet(long targetId, long sessionId, String path) {
    TrafficPacket packet = new TrafficPacket();
    packet.setSessionId(sessionId);
    packet.setTargetId(targetId);
    packet.setProtocol("HTTP");
    packet.setMethod("GET");
    packet.setScheme("http");
    packet.setHost("192.168.222.157");
    packet.setPort(80);
    packet.setPath(path);
    packet.setStatusCode(200);
    packet.setRequestBytes(1);
    packet.setResponseBytes(1);
    packet.setDurationMs(1L);
    packet.setCreatedAt(Instant.now());
    return packet;
  }
}
