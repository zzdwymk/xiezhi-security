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
import java.net.InetSocketAddress;
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

  /**
   * 断言代理已停止且监听端口已释放。
   *
   * <h2>为什么必须带 SO_REUSEADDR（CI 实测的 flake 根因）</h2>
   *
   * <p>原实现用 {@code new ServerSocket(port, 1, loopback)} 复验端口，<strong>没有</strong>设置
   * {@code setReuseAddress(true)}。而被测的 {@link LocalTrafficProxy#start(int)} 是<em>带</em>
   * {@code setReuseAddress(true)} 绑定的。这个不对称会制造两种误报：
   *
   * <ul>
   *   <li><strong>TIME_WAIT 残留</strong>：代理已真正关闭，但此前建立的连接使端口处于
   *       {@code TIME_WAIT}。不带 reuseAddress 的绑定会直接抛
   *       {@code BindException: Address already in use}——于是"端口已释放"这一<em>真实成立</em>的
   *       性质被判为失败。这正是 CI run 38243364665 上
   *       {@code failedStopPersistenceCannotLeaveCurrentSessionOrOpenListener} 的失败原因
   *       （{@code Time elapsed: 0.041 s}，整类瞬间失败，与"没释放端口"不相容）。
   *   <li><strong>端口区间竞争</strong>：本类与其他用例共用固定区间 19080-19120，
   *       {@link #availablePort()} 的"探测后立即 close"存在 TOCTOU 窗口。
   * </ul>
   *
   * <p>加上 {@code setReuseAddress(true)} 后，{@code TIME_WAIT} 不再导致误报，而<strong>仍然能
   * 检出真正未释放的监听</strong>——已实测：当另一个 socket 正持有该端口时，即使开启
   * reuseAddress 绑定依旧失败。因此这不是"放宽断言"，而是让它只对真正的问题报警。
   */
  private void assertStoppedAndPortReleased(int port) throws Exception {
    assertThat(service.status().running()).isFalse();
    assertThat(service.status().capturing()).isFalse();
    assertThat(service.status().capturedCount()).isZero();
    assertThat(ReflectionTestUtils.getField(service, "current")).isNull();
    java.io.IOException lastBindError = null;
    for (int attempt = 0; attempt < 20; attempt++) {
      ServerSocket listener = new ServerSocket();
      try {
        listener.setReuseAddress(true);
        listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 1);
        assertThat(listener.isBound()).isTrue();
        return;
      } catch (java.io.IOException ex) {
        lastBindError = ex;
        Thread.sleep(50);
      } finally {
        try { listener.close(); } catch (Exception ignored) { }
      }
    }
    if (lastBindError != null) {
      throw lastBindError;
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

  /**
   * 在固定区间 19080-19120 内挑一个空闲端口。
   *
   * <p>本类的用例需要在<strong>同一端口</strong>上反复 start/stop（验证"重启后仍能立即绑定"），
   * 因此不能像其他用例那样直接用端口 0 让系统分配。但"探测后立即 close、再交给被测代码绑定"
   * 天然存在 TOCTOU 窗口。
   *
   * <p>两点缓解：
   *
   * <ul>
   *   <li>探测时带 {@code setReuseAddress(true)}，与 {@link LocalTrafficProxy#start(int)} 的绑定
   *       方式对齐——避免把 {@code TIME_WAIT} 误判为"占用"。
   *   <li>从<strong>随机起点</strong>开始扫描，而不是每次都从 19080 起。固定起点会让多个测试类
   *       与同一 JVM 内的并发用例反复争抢同一个端口，是竞争被放大的主因。
   * </ul>
   *
   * <p>注意：这些缓解缩小但不消除竞态窗口。真正的消除需要被测代码支持端口 0，但
   * {@code TrafficProxyService.start} 明确把端口限制在 19080-19120（产品约束），
   * 因此测试侧只能做到这里——该窗口已在注释中如实记录。
   */
  private static int availablePort() throws Exception {
    int span = 19120 - 19080 + 1;
    int offset = java.util.concurrent.ThreadLocalRandom.current().nextInt(span);
    for (int attempt = 0; attempt < span; attempt++) {
      int port = 19080 + ((offset + attempt) % span);
      ServerSocket socket = new ServerSocket();
      try {
        socket.setReuseAddress(true);
        socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 1);
        return port;
      } catch (java.io.IOException occupied) {
        // 该端口已被占用，试下一个。
      } finally {
        try { socket.close(); } catch (java.io.IOException ignored) { }
      }
    }
    throw new IllegalStateException("No free test proxy port");
  }
}
