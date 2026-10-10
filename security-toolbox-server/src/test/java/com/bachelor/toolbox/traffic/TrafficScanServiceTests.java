package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SqlmapScanTool;
import com.bachelor.toolbox.tool.FindingDraft;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import com.bachelor.toolbox.tool.XrayScanTool;
import com.bachelor.toolbox.tool.zap.ZapDaemon;
import com.bachelor.toolbox.tool.zap.ZapDaemonSupplier;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

class TrafficScanServiceTests {
  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final TargetService targets = mock(TargetService.class);
  private final AuthorizedTargetRepository targetRepository = mock(AuthorizedTargetRepository.class);
  private final ZapDaemonSupplier supplier = mock(ZapDaemonSupplier.class);
  private final DependencyDetectionService dependencies = mock(DependencyDetectionService.class);
  private final ZapDaemon daemon = mock(ZapDaemon.class);
  private final AuditService audit = mock(AuditService.class);
  private final TrafficScanLedgerService ledger = mock(TrafficScanLedgerService.class);
  private final XrayScanTool xray = mock(XrayScanTool.class);
  private final SqlmapScanTool sqlmap = mock(SqlmapScanTool.class);
  private final AtomicInteger requests = new AtomicInteger();
  private HttpServer fixture;
  private TrafficPacket packet;
  private AuthorizedTarget target;

  @BeforeEach
  void setUp() throws Exception {
    fixture = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    fixture.createContext("/", exchange -> {
      requests.incrementAndGet();
      // No payload processing: this controlled endpoint only counts incoming requests.
      exchange.sendResponseHeaders(200, -1);
      exchange.close();
    });
    fixture.start();
    target = new AuthorizedTarget(); target.setId(2L); target.setTargetValue("127.0.0.1");
    target.setAllowedPorts(String.valueOf(fixture.getAddress().getPort()));
    packet = new TrafficPacket(); packet.setId(1L); packet.setTargetId(2L);
    packet.setHost("127.0.0.1"); packet.setScheme("http"); packet.setMethod("GET");
    packet.setPort(fixture.getAddress().getPort()); packet.setPath("/page?id=1");
    when(packets.findById(1L)).thenReturn(Optional.of(packet));
    when(targets.get(2L)).thenReturn(target);
    when(supplier.create()).thenReturn(daemon);
    when(dependencies.detect(false)).thenReturn(new SystemDependenciesResponse("win", "x64", "H2",
        List.of(new SystemDependenciesResponse.DependencyStatus("OWASP ZAP", "AVAILABLE", "2.17.0", "/zap", false, "PROXY_SCANNER", "ready", null, null))));
    when(daemon.startActiveScan(any(), anyString(), anyString(), anyBoolean())).thenReturn("7");
    when(daemon.activeScanProgress("7")).thenReturn(100);
    when(daemon.alerts()).thenReturn(List.of());
    HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    doAnswer(invocation -> {
      URI uri = invocation.getArgument(0);
      client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(2)).GET().build(),
          HttpResponse.BodyHandlers.discarding());
      return null;
    }).when(daemon).accessUrl(any());
  }

  @AfterEach
  void tearDown() { fixture.stop(0); }

  @Test
  void disconnectedStreamStillCompletesAndNotifiesOnce() {
    TrafficNotificationService notifications = mock(TrafficNotificationService.class);
    TrafficScanService service = service(Duration.ofSeconds(1));
    service.setNotifications(notifications);
    TrafficScanService.ZapScanListener disconnected = new TrafficScanService.ZapScanListener() {
      @Override public void onStart(String url) { throw new IllegalStateException("client disconnected"); }
    };
    var result = service.zapScan(1L, new TrafficScanService.ZapScanRequest("MEDIUM", null), disconnected);
    assertThat(result.status()).isEqualTo("COMPLETED");
    assertThat(requests.get()).isEqualTo(1);
    verify(notifications).publish(anyString(), eq(1L), eq(2L), org.mockito.ArgumentMatchers.isNull(),
        eq("ZAP"), eq("COMPLETED"), anyString(), eq(List.of()));
  }

  @Test
  void rejectedScanHasOneFailureNoticeWithoutExecutingEngine() {
    TrafficNotificationService notifications = mock(TrafficNotificationService.class);
    TrafficScanService service = service(Duration.ofSeconds(1));
    service.setNotifications(notifications);
    assertThatThrownBy(() -> service.zapScan(1L, new TrafficScanService.ZapScanRequest("INVALID", null)))
        .isInstanceOf(ApiException.class);
    verifyNoInteractions(supplier, daemon);
    verify(notifications).publish(anyString(), eq(1L), eq(2L), org.mockito.ArgumentMatchers.isNull(),
        eq("ZAP"), eq("FAILED"), anyString(), eq(List.of()));
  }

  @Test
  void timedOutScanProducesTimeoutNotice() throws Exception {
    when(daemon.activeScanProgress("7")).thenThrow(new TimeoutException("fixture timeout"));
    TrafficNotificationService notifications = mock(TrafficNotificationService.class);
    TrafficScanService service = service(Duration.ofSeconds(1));
    service.setNotifications(notifications);
    assertThat(service.zapScan(1L, new TrafficScanService.ZapScanRequest("MEDIUM", null)).status())
        .isEqualTo("TIMEOUT");
    verify(notifications).publish(anyString(), eq(1L), eq(2L), org.mockito.ArgumentMatchers.isNull(),
        eq("ZAP"), eq("TIMEOUT"), anyString(), eq(List.of()));
  }

  private TrafficScanService service(Duration timeout) {
    PortRangeParser ports = new PortRangeParser();
    return new TrafficScanService(packets, targets, new TargetPolicyService(false, ports), targetRepository,
        supplier, dependencies, xray, sqlmap, audit, ledger, ports, timeout);
  }

  private TrafficScanService.TargetedScanResult run() {
    return service(Duration.ofSeconds(2)).zapScan(1L, new TrafficScanService.ZapScanRequest("LOW", "Default Policy"));
  }

  @Test
  void zapBudgetUsesTheSameConfiguredTimeoutAsTaskScans() {
    try (var context = new org.springframework.context.annotation.AnnotationConfigApplicationContext()) {
      org.springframework.boot.test.util.TestPropertyValues.of("toolbox.execution.zap-scan-timeout-seconds=120")
          .applyTo(context);
      context.registerBean(TrafficPacketRepository.class, () -> packets);
      context.registerBean(TargetService.class, () -> targets);
      context.registerBean(TargetPolicyService.class, () -> new TargetPolicyService(false, new PortRangeParser()));
      context.registerBean(AuthorizedTargetRepository.class, () -> targetRepository);
      context.registerBean(ZapDaemonSupplier.class, () -> supplier);
      context.registerBean(DependencyDetectionService.class, () -> dependencies);
      context.registerBean(XrayScanTool.class, () -> xray);
      context.registerBean(SqlmapScanTool.class, () -> sqlmap);
      context.registerBean(AuditService.class, () -> audit);
      context.registerBean(TrafficScanLedgerService.class, () -> ledger);
      context.registerBean(PortRangeParser.class, PortRangeParser::new);
      context.register(TrafficScanService.class);
      context.refresh();
      assertThat(context.getBean(TrafficScanService.class).zapScanStreamTimeoutMillis())
          .isEqualTo(Duration.ofSeconds(120).plusMinutes(5).toMillis());
    }
  }

  @Test
  void unchangedTwentySixPercentContinuesUntilTheEngineActuallyFinishes() throws Exception {
    when(daemon.activeScanProgress("7")).thenReturn(26, 26, 100);
    when(daemon.activeScanActivity("7")).thenReturn(new ZapDaemon.ScanActivity(123L, List.of("SQL Injection"), "RUNNING"));
    var listener = mock(TrafficScanService.ZapScanListener.class);
    var result = service(Duration.ofSeconds(5)).zapScan(1L, null, listener);
    assertThat(result.status()).isEqualTo("COMPLETED");
    verify(daemon, org.mockito.Mockito.times(3)).activeScanProgress("7");
    verify(listener).onStatus(org.mockito.ArgumentMatchers.contains("当前检查尚未结束"));
    verify(daemon).activeScanActivity("7");
    verify(listener, org.mockito.Mockito.times(2)).onStatus(org.mockito.ArgumentMatchers.contains("已发送 123 次请求 · 当前检查：SQL Injection"));
    verify(daemon, never()).stopActiveScan(anyString());
  }

  @Test
  void realTimeoutReportsLastProgressWithoutClaimingCompletion() throws Exception {
    when(daemon.activeScanProgress("7")).thenReturn(26);
    var result = service(Duration.ofMillis(150)).zapScan(1L, null);
    assertThat(result.status()).isEqualTo("TIMEOUT");
    assertThat(result.message()).contains("最后进度 26%", "检测未完成");
    verify(daemon).stopActiveScan("7");
  }

  private void assertRecorded(String status, String auditResult) {
    ArgumentCaptor<TrafficScanLedger> captured = ArgumentCaptor.forClass(TrafficScanLedger.class);
    verify(ledger).record(captured.capture());
    assertThat(captured.getValue().getStatus()).isEqualTo(status);
    assertThat(captured.getValue().getEngine()).isEqualTo("ZAP");
    assertThat(captured.getValue().getTargetId()).isEqualTo(target.getId());
    verify(audit).record(eq("TRAFFIC_ZAP_SCAN"), eq("TRAFFIC_PACKET"), eq(1L),
        eq("status=" + status + ",hits=" + captured.getValue().getHitCount()), eq(auditResult));
  }

  @Test
  void zeroAlertsCompleteNormallyWithOnlyTheSelectedSeedRequest() throws Exception {
    TrafficScanService.TargetedScanResult result = run();
    assertThat(result.status()).isEqualTo("COMPLETED");
    assertThat(result.engine()).isEqualTo("ZAP_ACTIVE");
    assertThat(result.hits()).isEmpty(); assertThat(result.probes()).isEmpty();
    assertThat(result.message()).contains("0 项授权范围内告警").doesNotContain("高危注入漏洞");
    assertThat(requests.get()).isEqualTo(1);
    URI uri = URI.create("http://127.0.0.1:" + packet.getPort() + "/page?id=1");
    InOrder order = inOrder(daemon);
    order.verify(daemon).includeInScope(uri);
    order.verify(daemon).accessUrl(uri);
    order.verify(daemon).startActiveScan(uri, "Default Policy", "LOW", false);
    verify(daemon).close(); assertRecorded("COMPLETED", "SUCCESS");
  }

  @Test
  void zapFailureDoesNotSendHeuristicProbesToTheLocalFixture() throws Exception {
    when(daemon.startActiveScan(any(), anyString(), anyString(), anyBoolean()))
        .thenThrow(new ApiException("ZAP scan failed"));
    TrafficScanService.TargetedScanResult result = run();
    assertThat(result.status()).isEqualTo("FAILED"); assertThat(result.engine()).isEqualTo("ZAP_ACTIVE");
    assertThat(result.probes()).isEmpty(); assertThat(requests.get()).isEqualTo(1);
    verify(daemon, never()).alerts(); verify(daemon).kill(); assertRecorded("FAILED", "FAILURE");
  }

  @Test
  void unavailableZapDoesNotSilentlyUseAnotherEngine() {
    when(dependencies.detect(false)).thenReturn(new SystemDependenciesResponse("win", "x64", "H2", List.of()));
    TrafficScanService.TargetedScanResult result = run();
    assertThat(result.status()).isEqualTo("FAILED"); assertThat(requests.get()).isZero();
    verifyNoInteractions(supplier, daemon); assertRecorded("FAILED", "FAILURE");
  }

  @Test
  void shortInjectedDeadlineReturnsTimeoutWithoutWaitingFortyFiveSeconds() throws Exception {
    when(daemon.activeScanProgress("7")).thenReturn(12);
    long started = System.nanoTime();
    TrafficScanService.TargetedScanResult result = service(Duration.ofMillis(5)).zapScan(1L, null);
    assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(3));
    assertThat(result.status()).isEqualTo("TIMEOUT"); assertThat(result.message()).contains("未完成");
    verify(daemon).stopActiveScan("7"); verify(daemon).kill(); verify(daemon, never()).alerts();
    assertThat(requests.get()).isEqualTo(1); assertRecorded("TIMEOUT", "FAILURE");
  }

  @Test
  void daemonHttpTimeoutIsRecordedAsTimeoutWithoutFallback() throws Exception {
    when(daemon.activeScanProgress("7")).thenThrow(new java.net.http.HttpTimeoutException("timed out"));
    assertThat(run().status()).isEqualTo("TIMEOUT");
    verify(daemon).stopActiveScan("7"); verify(daemon, never()).alerts();
    assertThat(requests.get()).isEqualTo(1); assertRecorded("TIMEOUT", "FAILURE");
  }

  @Test
  void interruptedScanIsCancelledAndPreservesThreadInterruption() throws Exception {
    when(daemon.activeScanProgress("7")).thenThrow(new InterruptedException("cancelled"));
    try {
      assertThat(run().status()).isEqualTo("CANCELLED");
      assertThat(Thread.currentThread().isInterrupted()).isTrue();
      verify(daemon).stopActiveScan("7"); verify(daemon).kill(); verify(daemon, never()).alerts();
      assertThat(requests.get()).isEqualTo(1); assertRecorded("CANCELLED", "FAILURE");
    } finally { Thread.interrupted(); }
  }

  @ParameterizedTest
  @NullAndEmptySource
  void missingScanIdCannotCompleteOrReadAlerts(String id) throws Exception {
    when(daemon.startActiveScan(any(), anyString(), anyString(), anyBoolean())).thenReturn(id);
    assertThat(run().status()).isEqualTo("FAILED");
    verify(daemon, never()).alerts(); assertThat(requests.get()).isEqualTo(1);
    assertRecorded("FAILED", "FAILURE");
  }

  @ParameterizedTest
  @ValueSource(ints = {-1, 101})
  void invalidProgressFailsInsteadOfLookingComplete(int progress) throws Exception {
    when(daemon.activeScanProgress("7")).thenReturn(progress);
    assertThat(run().status()).isEqualTo("FAILED"); verify(daemon).stopActiveScan("7");
    verify(daemon, never()).alerts(); assertRecorded("FAILED", "FAILURE");
  }

  @Test
  void missingAlertResponseFailsInsteadOfReportingZeroFindings() throws Exception {
    when(daemon.alerts()).thenReturn(null);
    assertThat(run().status()).isEqualTo("FAILED"); assertThat(requests.get()).isEqualTo(1);
    assertRecorded("FAILED", "FAILURE");
  }

  @Test
  void activeScanDoesNotCompleteBeforeQueuedResponsesAreChecked() throws Exception {
    when(daemon.passiveScanRemaining()).thenReturn(1L, 0L);
    assertThat(run().status()).isEqualTo("COMPLETED");
    InOrder order = inOrder(daemon);
    order.verify(daemon).activeScanProgress("7");
    order.verify(daemon, org.mockito.Mockito.times(2)).passiveScanRemaining();
    order.verify(daemon).alerts();
  }

  @Test
  void responseQueueTimeoutIsNotNoFindings() throws Exception {
    when(daemon.passiveScanRemaining()).thenReturn(1L);
    var result = service(Duration.ofMillis(100)).zapScan(1L, null);
    assertThat(result.status()).isEqualTo("TIMEOUT");
    assertThat(result.message()).contains("响应分析超过等待上限");
    verify(daemon, never()).alerts();
    assertRecorded("TIMEOUT", "FAILURE");
  }

  @Test
  void invalidResponseQueueStateFailsInsteadOfCompleting() throws Exception {
    when(daemon.passiveScanRemaining()).thenReturn(-1L);
    assertThat(run().status()).isEqualTo("FAILED");
    verify(daemon, never()).alerts();
    assertRecorded("FAILED", "FAILURE");
  }

  @Test
  void onlyExactAuthorizedHostAndPortAlertsAreIncluded() throws Exception {
    String base = "http://127.0.0.1:" + packet.getPort();
    when(daemon.alerts()).thenReturn(List.of(
        new ZapDaemon.ZapAlert(base + "/page", "Accepted", "LOW", "HIGH", "CWE-16", "d", 1),
        new ZapDaemon.ZapAlert("http://127.0.0.10:" + packet.getPort(), "Other host", "HIGH", "HIGH", "CWE-79", "d", 1),
        new ZapDaemon.ZapAlert("http://127.0.0.1:1/", "Other port", "HIGH", "HIGH", "CWE-79", "d", 1)));
    TrafficScanService.TargetedScanResult result = run();
    assertThat(result.hits()).extracting(TrafficScanService.TargetedScanHit::title).containsExactly("Accepted");
    assertRecorded("COMPLETED", "SUCCESS");
  }

  @ParameterizedTest
  @ValueSource(strings = {"host", "port", "disabled"})
  void directPacketTargetBindingMustRemainEnabledAndMatchExactHostPort(String invalid) {
    if ("host".equals(invalid)) target.setTargetValue("127.0.0.10");
    if ("port".equals(invalid)) target.setAllowedPorts("1");
    if ("disabled".equals(invalid)) target.setEnabled(false);
    assertThatThrownBy(this::run).isInstanceOf(ApiException.class).hasMessageContaining("授权范围");
    verifyNoInteractions(supplier, daemon); assertThat(requests.get()).isZero();
  }

  @Test
  void unboundPacketCannotUseSubstringHostOrUnauthorizedPortFallback() {
    packet.setTargetId(0L); target.setTargetValue("127.0.0.10");
    when(targetRepository.findAll()).thenReturn(List.of(target));
    assertThatThrownBy(this::run).isInstanceOf(ApiException.class);
    target.setTargetValue("127.0.0.1"); target.setAllowedPorts("1");
    assertThatThrownBy(this::run).isInstanceOf(ApiException.class).hasMessageContaining("端口");
    verifyNoInteractions(supplier, daemon); assertThat(requests.get()).isZero();
  }

  @Test
  void matchingUnboundPacketRecordsTheActualAuthorizedTargetId() {
    packet.setTargetId(0L); when(targetRepository.findAll()).thenReturn(List.of(target));
    assertThat(run().status()).isEqualTo("COMPLETED"); assertRecorded("COMPLETED", "SUCCESS");
  }

  @ParameterizedTest
  @CsvSource({"https,80,https://127.0.0.1:80", "http,443,http://127.0.0.1:443",
      "https,443,https://127.0.0.1", "http,80,http://127.0.0.1"})
  void urlPreservesPortsAccordingToItsScheme(String scheme, int port, String origin) throws Exception {
    packet.setScheme(scheme); packet.setPort(port); target.setAllowedPorts(String.valueOf(port));
    doNothing().when(daemon).accessUrl(any());
    assertThat(run().status()).isEqualTo("COMPLETED");
    verify(daemon).accessUrl(URI.create(origin + "/page?id=1"));
    assertThat(requests.get()).isZero();
  }

  @Test
  void malformedPacketPathCannotOverrideHostOrIntroduceFragment() {
    packet.setPath("//127.0.0.2/override");
    assertThatThrownBy(this::run).isInstanceOf(ApiException.class);
    packet.setPath("/page#fragment");
    assertThatThrownBy(this::run).isInstanceOf(ApiException.class);
    verifyNoInteractions(supplier, daemon);
  }

  @ParameterizedTest
  @ValueSource(strings = {"XRAY", "SQLMAP"})
  void scannerFailureProducesFailedTerminalEventAndLedger(String engine) throws Exception {
    when(xray.execute(any(), any(), any(), any())).thenThrow(new ApiException("无法连接目标，检测未完成"));
    when(sqlmap.execute(any(), any(), any(), any())).thenThrow(new ApiException("无法连接目标，检测未完成"));
    var listener = mock(TrafficScanService.ZapScanListener.class);
    var result = runScanner(engine, listener);
    assertThat(result.status()).isEqualTo("FAILED");
    assertThat(result.message()).contains("无法连接目标");
    verify(listener).onComplete(result);
    assertScannerRecorded(engine, "FAILED", "FAILURE");
  }

  @ParameterizedTest
  @ValueSource(strings = {"XRAY", "SQLMAP"})
  void missingOrPartialToolResultNeverMeansNoVulnerabilities(String engine) throws Exception {
    when(xray.execute(any(), any(), any(), any())).thenReturn(null);
    when(sqlmap.execute(any(), any(), any(), any())).thenReturn(new ToolExecutionResult("partial", Map.of("partial", true), List.of()));
    var result = runScanner(engine, TrafficScanService.ZapScanListener.NOOP);
    assertThat(result.status()).isEqualTo("FAILED");
    assertThat(result.message()).contains("未返回完整");
    assertScannerRecorded(engine, "FAILED", "FAILURE");
  }

  @ParameterizedTest
  @ValueSource(strings = {"XRAY", "SQLMAP"})
  void validEmptyScannerResultCanComplete(String engine) throws Exception {
    var empty = new ToolExecutionResult("complete", Map.of("matchCount", 0, "executionVerified", true, "vulnerable", false), List.of());
    when(xray.execute(any(), any(), any(), any())).thenReturn(empty);
    when(sqlmap.execute(any(), any(), any(), any())).thenReturn(empty);
    assertThat(runScanner(engine, TrafficScanService.ZapScanListener.NOOP).status()).isEqualTo("COMPLETED");
    assertScannerRecorded(engine, "COMPLETED", "SUCCESS");
  }

  @Test
  void xrayPartialLiveFindingSurvivesTimeoutWithoutSuccessfulVerdict() throws Exception {
    when(xray.execute(any(), any(), any(), any())).thenAnswer(invocation -> {
      Consumer<FindingDraft> finding = invocation.getArgument(3);
      finding.accept(new FindingDraft("Potential issue", "LOW", "d", "e", "r", "poc-1"));
      throw new TimeoutException("deadline");
    });
    var listener = mock(TrafficScanService.ZapScanListener.class);
    var result = runScanner("XRAY", listener);
    assertThat(result.status()).isEqualTo("TIMEOUT");
    assertThat(result.hits()).hasSize(1);
    verify(listener).onComplete(result);
    assertScannerRecorded("XRAY", "TIMEOUT", "FAILURE");
  }

  @Test
  void xrayUsesFinalFindingsEvenWithoutLiveCallback() throws Exception {
    var finding = new FindingDraft("Potential issue", "LOW", "d", "e", "r", "poc-1");
    when(xray.execute(any(), any(), any(), any())).thenReturn(new ToolExecutionResult("complete", Map.of("executionVerified", true), List.of(finding)));
    var result = runScanner("XRAY", TrafficScanService.ZapScanListener.NOOP);
    assertThat(result.status()).isEqualTo("COMPLETED");
    assertThat(result.hits()).hasSize(1);
    assertThat(result.message()).contains("1 项潜在漏洞");
  }

  @ParameterizedTest
  @ValueSource(strings = {"XRAY", "SQLMAP"})
  void resultWithoutVerifiedExecutionOrConclusionCannotComplete(String engine) throws Exception {
    var unverified = new ToolExecutionResult("complete", Map.of("matchCount", 0), List.of());
    when(xray.execute(any(), any(), any(), any())).thenReturn(unverified);
    when(sqlmap.execute(any(), any(), any(), any())).thenReturn(unverified);
    assertThat(runScanner(engine, TrafficScanService.ZapScanListener.NOOP).status()).isEqualTo("FAILED");
    assertScannerRecorded(engine, "FAILED", "FAILURE");
  }

  private TrafficScanService.TargetedScanResult runScanner(String engine, TrafficScanService.ZapScanListener listener) {
    var scans = service(Duration.ofSeconds(2));
    return "XRAY".equals(engine) ? scans.xrayScan(1L, null, listener) : scans.sqlmapScan(1L, null, listener);
  }

  private void assertScannerRecorded(String engine, String status, String auditResult) {
    var captured = ArgumentCaptor.forClass(TrafficScanLedger.class);
    verify(ledger).record(captured.capture());
    var entry = captured.getValue();
    assertThat(entry.getStatus()).isEqualTo(status);
    assertThat(entry.getEngine()).isEqualTo(engine);
    verify(audit).record(eq("TRAFFIC_" + engine + "_SCAN"), eq("TRAFFIC_PACKET"), eq(1L),
        eq("status=" + status + ",hits=" + entry.getHitCount()), eq(auditResult));
  }
}
