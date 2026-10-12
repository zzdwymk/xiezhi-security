package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.PlatformTransactionManager;

@ExtendWith(MockitoExtension.class)
class TrafficProxyQueryTests {
  @Mock private TrafficSessionRepository sessions;
  @Mock private TrafficPacketRepository packets;
  @Mock private TrafficSuggestionRepository suggestions;
  @Mock private TrafficAnalysisService analysis;
  @Mock private TargetService targets;
  @Mock private TargetPolicyService policy;
  @Mock private TrafficCaptureFilterService filters;
  @Mock private AuditService audit;
  @Mock private MitmCertificateAuthority certificateAuthority;
  @Mock private TrafficAssetSyncService assetSync;
  @Mock private PlatformTransactionManager transactionManager;

  @Test
  void startsCaptureWithoutLoadingOrValidatingALegacyTarget() throws Exception {
    when(sessions.save(any(TrafficSession.class))).thenAnswer(invocation -> {
      TrafficSession session = invocation.getArgument(0);
      session.setId(90L);
      return session;
    });
    int port = availablePort();
    assertThat(port).isGreaterThan(0);
    TrafficProxyService proxy = service();
    try {
      var status = proxy.start(new TrafficDtos.StartRequest(999999L, port, "AUTO_SAFE"));
      assertThat(status.running()).isTrue();
      assertThat(status.targetId()).isNull();
      assertThat(status.handlingMode()).isEqualTo("ASK");
      org.mockito.Mockito.verifyNoInteractions(targets, policy, analysis);
    } finally { proxy.stop(); }
  }

  @Test
  void queriesOnlyTheMostRecentTwoHundredStoredPackets() {
    TrafficPacket packet = packet(1L);
    when(packets.findAll(any(Pageable.class))).thenReturn(new PageImpl<>(List.of(packet)));

    assertThat(service().packets()).containsExactly(packet);

    ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
    verify(packets).findAll(pageable.capture());
    assertThat(pageable.getValue().getPageNumber()).isZero();
    assertThat(pageable.getValue().getPageSize()).isEqualTo(200);
    assertThat(pageable.getValue().getSort().getOrderFor("createdAt").isDescending()).isTrue();
    assertThat(pageable.getValue().getSort().getOrderFor("id").isDescending()).isTrue();
  }

  @Test
  void preservesHistoryAcrossProxyStartRecordingPauseResumeAndStop() throws Exception {
    TrafficPacket history = packet(1L);
    when(packets.findAll(any(Pageable.class))).thenReturn(new PageImpl<>(List.of(history)));
    when(sessions.save(any(TrafficSession.class))).thenAnswer(invocation -> {
      TrafficSession session = invocation.getArgument(0);
      session.setId(9L);
      return session;
    });
    int port = availablePort();
    assertThat(port).isGreaterThan(0);
    TrafficProxyService service = service();
    assertThat(service.packets()).containsExactly(history);
    try {
      assertThat(service.start(new TrafficDtos.StartRequest(null, port, "ASK")).running()).isTrue();
      assertThat(service.packets()).containsExactly(history);
      assertThat(service.setCapturing(true).capturing()).isTrue();
      assertThat(service.packets()).containsExactly(history);
      assertThat(service.setCapturing(false).capturing()).isFalse();
      assertThat(service.packets()).containsExactly(history);
      assertThat(service.setCapturing(true).capturing()).isTrue();
      assertThat(service.packets()).containsExactly(history);
    } finally {
      service.stop();
    }
    assertThat(service.packets()).containsExactly(history);
    verify(packets, org.mockito.Mockito.times(6)).findAll(any(Pageable.class));
    org.mockito.Mockito.verifyNoMoreInteractions(packets);
  }

  private TrafficPacket packet(Long sessionId) {
    TrafficPacket packet = new TrafficPacket();
    packet.setSessionId(sessionId);
    packet.setCreatedAt(Instant.now());
    return packet;
  }

  /**
   * 在固定区间 19080-19120 内挑一个空闲端口。
   *
   * <p>与 {@code TrafficProxyLifecycleTests#availablePort()} 同源（该区间是
   * {@code TrafficProxyService.start} 的产品约束，测试不能改用端口 0）。两点缓解：
   *
   * <ul>
   *   <li>探测时带 {@code setReuseAddress(true)}，与 {@code LocalTrafficProxy.start} 的绑定方式
   *       对齐，避免把 {@code TIME_WAIT} 误判为占用；
   *   <li>从随机起点扫描，避免多个测试类总是争抢 19080 这一个端口。
   * </ul>
   *
   * <p>"探测后 close 再绑定"的 TOCTOU 窗口被缩小但未消除——已在注释中如实记录，未假装解决。
   */
  private static int availablePort() {
    int span = 19120 - 19080 + 1;
    int offset = java.util.concurrent.ThreadLocalRandom.current().nextInt(span);
    for (int attempt = 0; attempt < span; attempt++) {
      int port = 19080 + ((offset + attempt) % span);
      java.net.ServerSocket socket = null;
      try {
        socket = new java.net.ServerSocket();
        socket.setReuseAddress(true);
        socket.bind(
            new java.net.InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), port), 1);
        return port;
      } catch (java.io.IOException occupied) {
        // 该端口已被占用，试下一个。
      } finally {
        if (socket != null) {
          try { socket.close(); } catch (java.io.IOException ignored) { }
        }
      }
    }
    throw new IllegalStateException("No free test proxy port");
  }

  private TrafficProxyService service() {
    return new TrafficProxyService(
        sessions,
        packets,
        suggestions,
        analysis,
        targets,
        policy,
        filters,
        audit,
        certificateAuthority,
        assetSync,
        transactionManager);
  }
}
