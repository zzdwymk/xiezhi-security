package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;

@ExtendWith(MockitoExtension.class)
class TrafficProxyLifecycleTests {
  @Mock TrafficSessionRepository sessions;
  @Mock TrafficPacketRepository packets;
  @Mock TrafficSuggestionRepository suggestions;
  @Mock TrafficAnalysisService analysis;
  @Mock TargetService targets;
  @Mock TargetPolicyService policy;
  @Mock TrafficCaptureFilterService filters;
  @Mock AuditService audit;
  @Mock MitmCertificateAuthority certificateAuthority;
  @Mock TrafficAssetSyncService assetSync;
  @Mock PlatformTransactionManager transactionManager;
  private TrafficProxyService service;

  @BeforeEach
  void prepare() {
    service = new TrafficProxyService(sessions, packets, suggestions, analysis, targets,
        policy, filters, audit, certificateAuthority, assetSync, transactionManager);
  }

  private void persistSessions() {
    AtomicLong ids = new AtomicLong();
    when(sessions.save(any(TrafficSession.class))).thenAnswer(invocation -> {
      TrafficSession session = invocation.getArgument(0);
      if (session.getId() == null) session.setId(ids.incrementAndGet());
      return session;
    });
  }

  @Test
  void startupAuditFailureClosesListenerAndAllowsImmediateRetry() throws Exception {
    persistSessions();
    int port = availablePort();
    doThrow(new IllegalStateException("audit unavailable")).when(audit)
        .record(eq("START_TRAFFIC_PROXY"), anyString(), any(), anyString(), anyString());
    assertThatThrownBy(() -> service.start(request(port))).isInstanceOf(ApiException.class);
    assertStoppedAndPortReleased(port);
    doNothing().when(audit).record(eq("START_TRAFFIC_PROXY"), anyString(), any(), anyString(), anyString());
    try {
      assertThat(service.start(request(port)).running()).isTrue();
    } finally { service.stop(); }
  }

  @Test
  void startupDatabaseFailureStillClosesListenerWhenFailureStatusCannotBeSaved() throws Exception {
    AtomicLong saves = new AtomicLong();
    doAnswer(invocation -> {
      if (saves.incrementAndGet() > 1) throw new IllegalStateException("database unavailable");
      TrafficSession session = invocation.getArgument(0);
      session.setId(1L);
      return session;
    }).when(sessions).save(any(TrafficSession.class));
    int port = availablePort();
    assertThatThrownBy(() -> service.start(request(port))).isInstanceOf(ApiException.class);
    assertStoppedAndPortReleased(port);
    assertThat(saves.get()).isEqualTo(3);
  }

  @Test
  void stoppedProxyCallbacksCannotWriteIntoTheNextRecordingRun() throws Exception {
    persistSessions();
    int port = availablePort();
    service.start(request(port));
    Consumer<LocalTrafficProxy.Capture> previousCapture = callback();
    service.stop();
    try {
      service.start(request(port));
      service.setCapturing(true);
      previousCapture.accept(capture());
      verifyNoInteractions(packets, filters, transactionManager, assetSync);
      TrafficSession current = (TrafficSession) ReflectionTestUtils.getField(service, "current");
      when(sessions.findById(current.getId())).thenReturn(Optional.of(current));
      when(packets.save(any(TrafficPacket.class))).thenAnswer(invocation -> invocation.getArgument(0));
      callback().accept(capture());
      verify(packets).save(any(TrafficPacket.class));
      assertThat(service.status().capturedCount()).isEqualTo(1);
    } finally { service.stop(); }
  }

  @Test
  void failedStopPersistenceCannotLeaveCurrentSessionOrOpenListener() throws Exception {
    persistSessions();
    int port = availablePort();
    service.start(request(port));
    service.setCapturing(true);
    Consumer<LocalTrafficProxy.Capture> previousCapture = callback();
    doThrow(new IllegalStateException("database unavailable")).when(sessions).save(any(TrafficSession.class));
    assertThatThrownBy(service::stop).isInstanceOf(IllegalStateException.class);
    assertStoppedAndPortReleased(port);
    previousCapture.accept(capture());
    verifyNoInteractions(packets, filters, transactionManager, assetSync);
  }

  private void assertStoppedAndPortReleased(int port) throws Exception {
    assertThat(service.status().running()).isFalse();
    assertThat(service.status().capturing()).isFalse();
    assertThat(service.status().capturedCount()).isZero();
    assertThat(ReflectionTestUtils.getField(service, "current")).isNull();
    try (ServerSocket listener = new ServerSocket(port, 1, InetAddress.getLoopbackAddress())) {
      assertThat(listener.isBound()).isTrue();
    }
  }

  @SuppressWarnings("unchecked")
  private Consumer<LocalTrafficProxy.Capture> callback() {
    Object proxy = ReflectionTestUtils.getField(service, "proxy");
    return (Consumer<LocalTrafficProxy.Capture>) ReflectionTestUtils.getField(proxy, "capture");
  }

  private static TrafficDtos.StartRequest request(int port) { return new TrafficDtos.StartRequest(999L, port, "ASK"); }
  private static LocalTrafficProxy.Capture capture() {
    return new LocalTrafficProxy.Capture("HTTP", "GET", "http", "example.test", 80, "/", 200,
        "", "", "", "", 0, 0, 1, "CAPTURED", "text/plain", null);
  }

  private static int availablePort() throws Exception {
    for (int port = 19080; port <= 19120; port++) {
      try (ServerSocket socket = new ServerSocket(port, 1, InetAddress.getLoopbackAddress())) { return port; }
      catch (java.io.IOException occupied) { }
    }
    throw new IllegalStateException("No free test proxy port");
  }
}
