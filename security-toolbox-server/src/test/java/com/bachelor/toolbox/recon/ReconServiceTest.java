package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class ReconServiceTest {
  @Mock private ReconResultRepository results;
  @Mock private AssessmentProjectService projects;
  @Mock private AuthorizedTargetRepository targets;

  @Test
  void reportsMissingTargetIdentifierInChinese() {
    ReconRequest request =
        new ReconRequest(null, false, false, false, List.of(), false, "PASSIVE", false);

    assertThatThrownBy(() -> service(false).collect(1L, request))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("目标 ID 不能为空");
  }

  @Test
  void reportsMissingTargetInChinese() {
    ReconRequest request = requestFor(7L);
    when(targets.findById(7L)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service(false).collect(1L, request))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("未找到目标");

    verify(projects).validateProjectTarget(1L, 7L);
    verifyNoInteractions(results);
  }

  @Test
  void reportsMissingProjectBeforeQueryingHistory() {
    when(projects.get(99L)).thenThrow(new IllegalArgumentException("评估项目不存在"));

    assertThatThrownBy(() -> service(false).history(99L))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("评估项目不存在");

    verifyNoInteractions(results);
  }

  @Test
  void delegatesHistoryToDescendingRepositoryQueries() {
    ReconResult projectResult = new ReconResult();
    ReconResult targetResult = new ReconResult();
    when(results.findByProjectIdOrderByCollectedAtDescIdDesc(eq(1L), any()))
        .thenReturn(List.of(projectResult));
    when(results.findByProjectIdAndTargetIdOrderByCollectedAtDescIdDesc(
            eq(1L), eq(7L), any()))
        .thenReturn(List.of(targetResult));

    assertThat(service(false).history(1L)).containsExactly(projectResult);
    assertThat(service(false).history(1L, 7L)).containsExactly(targetResult);

    verify(projects).get(1L);
    verify(projects).validateProjectTargetMembership(1L, 7L);
    verify(results)
        .findByProjectIdOrderByCollectedAtDescIdDesc(
            eq(1L),
            argThat(page -> page.getPageNumber() == 0 && page.getPageSize() == 1_000));
    verify(results)
        .findByProjectIdAndTargetIdOrderByCollectedAtDescIdDesc(
            eq(1L),
            eq(7L),
            argThat(page -> page.getPageNumber() == 0 && page.getPageSize() == 1_000));
  }

  @Test
  void rejectsNullTargetInIcpBatch() {
    assertThatThrownBy(
            () ->
                service(false)
                    .icpBatch(
                        1L, new ReconService.IcpBatchRequest(java.util.Arrays.asList((Long) null))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("目标 ID 不能为空");

    verifyNoInteractions(projects, targets, results);
  }

  @Test
  void reportsDeletedIcpTargetAsUnavailable() {
    when(targets.findById(7L)).thenReturn(Optional.empty());

    ReconService.IcpResult result =
        service(false).icpBatch(1L, new ReconService.IcpBatchRequest(List.of(7L))).get(0);

    assertThat(result.targetId()).isEqualTo(7L);
    assertThat(result.status()).isEqualTo("UNAVAILABLE");
    assertThat(result.reason()).isEqualTo("授权目标不存在或已删除");
    assertThat(result.data()).isEmpty();
    verify(projects).validateProjectTarget(1L, 7L);
  }

  @Test
  void retainsReconResultJsonDefaultsAndTimestampCallback() {
    ReconResult result = new ReconResult();

    result.prePersist();

    assertThat(result.getDnsRecords()).isEqualTo("{}");
    assertThat(result.getIpInformation()).isEqualTo("{}");
    assertThat(result.getTlsInformation()).isEqualTo("{}");
    assertThat(result.getHttpInformation()).isEqualTo("{}");
    assertThat(result.getSubdomains()).isEqualTo("[]");
    assertThat(result.getNetworkInformation()).isEqualTo("{}");
    assertThat(result.getRegistrationInformation()).isEqualTo("{}");
    assertThat(result.getGeolocationInformation()).isEqualTo("{}");
    assertThat(result.getSourceEvidence()).isEqualTo("[]");
    assertThat(result.getCollectedAt()).isNotNull();
  }

  @Test
  void usesDeclaredHttpPortAndKeepsPartialResultWhenThatServiceStops() throws Exception {
    AtomicReference<String> upgrade = new AtomicReference<>();
    AtomicReference<String> http2Settings = new AtomicReference<>();
    HttpServer server = startHttpServer(upgrade, http2Settings);
    int port = server.getAddress().getPort();
    AuthorizedTarget target = authorizedTarget("http://127.0.0.1:" + port, String.valueOf(port));
    stubSavedTarget(target);

    ReconRequest request =
        new ReconRequest(target.getId(), true, false, false, List.of(), false, "PASSIVE", false);

    try {
      ReconResult available = service(false).collect(1L, request);
      assertThat(available.getHttpInformation())
          .contains("\"status\":200")
          .contains(":" + port + "/")
          .contains("Recon test");
      assertThat(upgrade.get()).isNull();
      assertThat(http2Settings.get()).isNull();
    } finally {
      server.stop(0);
    }

    ReconResult partial = service(false).collect(1L, request);
    assertThat(partial.getHttpInformation())
        .contains("\"status\":\"UNAVAILABLE\"")
        .contains("连接被拒绝");
    assertThat(partial.getSourceEvidence()).contains("\"source\":\"HTTP\"");
  }

  @Test
  void recordsRequestButNeverPerformsNetworkNeighbourProbe() {
    AuthorizedTarget target = authorizedTarget("127.0.0.1", "80,443");
    stubSavedTarget(target);
    ReconRequest request =
        new ReconRequest(target.getId(), false, false, false, List.of(), true, "ACTIVE", true);

    ReconResult result = service(false).collect(1L, request);

    assertThat(result.isActiveNetworkProbe()).isFalse();
    assertThat(result.getNetworkInformation())
        .contains("\"neighbourProbeRequested\":true")
        .contains("\"neighbourProbePerformed\":false")
        .contains("不会访问相邻主机");
  }

  @Test
  void rejectsNonHttpsIcpSourceWithoutSendingARequest() {
    AuthorizedTarget target = authorizedTarget("example.com", "443");
    when(targets.findById(target.getId())).thenReturn(Optional.of(target));
    ReconService service = service(false);
    ReflectionTestUtils.setField(service, "icpApiUrl", "http://127.0.0.1/query");

    ReconService.IcpResult result =
        service.icpBatch(1L, new ReconService.IcpBatchRequest(List.of(target.getId()))).get(0);

    assertThat(result.status()).isEqualTo("UNAVAILABLE");
    assertThat(result.reason()).isEqualTo("ICP 数据源必须使用 HTTPS");
    assertThat(result.data()).isEmpty();
  }

  @Test
  void hidesUnexpectedExternalSourceErrorDetails() {
    Logger logger = (Logger) LoggerFactory.getLogger(ReconService.class);
    Level originalLevel = logger.getLevel();
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    logger.setLevel(Level.DEBUG);

    try {
      String message =
          ReflectionTestUtils.invokeMethod(
              service(false),
              "safeError",
              new IllegalStateException("jdbc:postgresql://private-host/secret"));

      assertThat(message)
          .isEqualTo("外部数据源请求失败，请稍后重试")
          .doesNotContain("postgresql", "private-host", "secret");
      assertThat(appender.list)
          .anySatisfy(
              event -> {
                assertThat(event.getFormattedMessage()).isEqualTo("信息收集数据源请求失败");
                assertThat(event.getThrowableProxy().getMessage())
                    .contains("jdbc:postgresql://private-host/secret");
              });
    } finally {
      logger.detachAppender(appender);
      logger.setLevel(originalLevel);
      appender.stop();
    }
  }

  @Test
  void passiveResponseCacheExpiresEntriesAndEvictsTheLeastRecentlyUsedEntry() {
    ReconService.PassiveResponseCache cache = new ReconService.PassiveResponseCache(2);
    cache.put("first", "one", 100L, 0L);
    cache.put("second", "two", 100L, 0L);

    assertThat(cache.get("first", 1L)).isEqualTo("one");
    cache.put("third", "three", 100L, 1L);

    assertThat(cache.get("second", 1L)).isNull();
    assertThat(cache.get("first", 1L)).isEqualTo("one");
    assertThat(cache.get("third", 100L)).isNull();
    assertThat(cache.size()).isEqualTo(1);
  }

  @Test
  void passiveResponseCacheStaysWithinCapacityDuringConcurrentAccess() throws Exception {
    ReconService.PassiveResponseCache cache = new ReconService.PassiveResponseCache(16);
    ExecutorService workers = Executors.newFixedThreadPool(8);
    List<Future<?>> results = new ArrayList<>();
    try {
      for (int index = 0; index < 1_000; index++) {
        int item = index;
        results.add(
            workers.submit(
                () -> {
                  String key = "key-" + item;
                  cache.put(key, "value-" + item, Long.MAX_VALUE, item);
                  cache.get(key, item);
                }));
      }
      for (Future<?> result : results) result.get(10, TimeUnit.SECONDS);
    } finally {
      workers.shutdown();
      assertThat(workers.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
    }

    assertThat(cache.size()).isLessThanOrEqualTo(16);
  }

  private HttpServer startHttpServer(
      AtomicReference<String> upgrade, AtomicReference<String> http2Settings) throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          upgrade.set(exchange.getRequestHeaders().getFirst("Upgrade"));
          http2Settings.set(exchange.getRequestHeaders().getFirst("HTTP2-Settings"));
          byte[] body = "<title>Recon test</title>".getBytes(StandardCharsets.UTF_8);
          exchange.getResponseHeaders().add("Server", "recon-test");
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.start();
    return server;
  }

  private void stubSavedTarget(AuthorizedTarget target) {
    when(targets.findById(target.getId())).thenReturn(Optional.of(target));
    when(results.save(any(ReconResult.class))).thenAnswer(invocation -> invocation.getArgument(0));
  }

  private AuthorizedTarget authorizedTarget(String value, String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setTargetValue(value);
    target.setAllowedPorts(allowedPorts);
    return target;
  }

  private ReconRequest requestFor(Long targetId) {
    return new ReconRequest(targetId, false, false, false, List.of(), false, "PASSIVE", false);
  }

  private ReconService service(boolean passiveSourcesEnabled) {
    ReconService service = new ReconService(results, projects, targets, new ObjectMapper());
    ReflectionTestUtils.setField(service, "passiveSourcesEnabled", passiveSourcesEnabled);
    return service;
  }
}
