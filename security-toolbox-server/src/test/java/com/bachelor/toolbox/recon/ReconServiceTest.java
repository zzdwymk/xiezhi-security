package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.traffic.TrafficPacketRepository;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
import com.bachelor.toolbox.target.TargetService;
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
  @Mock private TargetService targetService;
  @Mock private IcpBrowserCaptureStore icpBrowserCaptures;

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

  @Test
  void minesInjectableParameterAndRegistersCandidateForSqlmap() throws Exception {
    // 模拟 sqli-labs Less-2：/Less-2 目录 301 到 /Less-2/；带单引号触发 MySQL 报错回显，
    // 合法值不报错。/safe 端点对任何取值都不报错，用于校验不会误报。
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          byte[] body =
              ("<html><a href=\"Less-2\">Less-2</a> <a href=\"safe\">safe</a></html>")
                  .getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.createContext(
        "/Less-2",
        exchange -> {
          String path = exchange.getRequestURI().getPath();
          String rawQuery = exchange.getRequestURI().getRawQuery();
          if (!path.endsWith("/")) {
            exchange
                .getResponseHeaders()
                .add("Location", "/Less-2/" + (rawQuery != null ? "?" + rawQuery : ""));
            exchange.sendResponseHeaders(301, -1);
            exchange.close();
            return;
          }
          String query = exchange.getRequestURI().getQuery();
          boolean quoted = query != null && query.contains("'");
          byte[] body =
              (quoted
                      ? "<b>You have an error in your SQL syntax; check the manual that"
                          + " corresponds to your MySQL server version</b>"
                      : "<div>Your Login name:Dumb Your Password:xxx</div>")
                  .getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.createContext(
        "/safe",
        exchange -> {
          byte[] body = "<div>static content, no database here</div>".getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.start();
    int port = server.getAddress().getPort();

    DiscoveredPathService discoveredPaths = mock(DiscoveredPathService.class);
    // 站点爬取先把 /Less-2、/safe 登记进已发现集合（record 返回 true 才会并入本次快照）。
    when(discoveredPaths.record(any(), any(), any(), any(), any(), any(), any())).thenReturn(true);
    AuthorizedTarget target = authorizedTarget("http://127.0.0.1:" + port, String.valueOf(port));
    stubSavedTarget(target);
    ReconService service = serviceWith(discoveredPaths);

    // enumeratePaths=false, crawlSite=true → 爬取根页发现 /Less-2、/safe，随后参数探测。
    ReconRequest request =
        new ReconRequest(
            target.getId(), false, false, false, List.of(), false, List.of(), true, false, false,
            "ACTIVE", false);

    try {
      service.collect(1L, request);
    } finally {
      server.stop(0);
    }

    // 命中：以带合法值的 URL 登记 /Less-2/?id=1，来源 ACTIVE_ENUM，附「疑似可注入」备注。
    verify(discoveredPaths)
        .record(
            eq(target),
            eq(1L),
            argThat(url -> url != null && url.contains("/Less-2/") && url.contains("id=1")),
            eq("ACTIVE_ENUM"),
            any(),
            any(),
            argThat(note -> note != null && note.contains("疑似可注入")));
    // 不误报：任何非 /Less-2/ 端点都不应被标记为疑似可注入。
    verify(discoveredPaths, never())
        .record(
            any(),
            any(),
            argThat(url -> url != null && !url.contains("/Less-2/")),
            eq("ACTIVE_ENUM"),
            any(),
            any(),
            argThat(note -> note != null && note.contains("疑似可注入")));
  }

  @Test
  void prioritizesScriptEndpointsSoInjectableIsFoundEvenBeyondTheEndpointCap() throws Exception {
    // 站点先列出一批「看起来静态」的目录，再列出一个 product.php?id= 的可注入脚本端点。
    // 端点上限设为 3；若按发现顺序截断会漏掉 product.php，按可注入可能性排序则应优先探测到。
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    StringBuilder links = new StringBuilder("<html>");
    for (int i = 1; i <= 8; i++) links.append("<a href=\"dir").append(i).append("\">d</a>");
    links.append("<a href=\"product.php?id=1\">p</a></html>");
    server.createContext(
        "/",
        exchange -> {
          byte[] body = links.toString().getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    // 静态目录：任何取值都不报错
    for (int i = 1; i <= 8; i++) {
      server.createContext(
          "/dir" + i,
          exchange -> {
            byte[] body = "<div>plain listing</div>".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
          });
    }
    // 可注入脚本端点：注入单引号触发报错
    server.createContext(
        "/product.php",
        exchange -> {
          String query = exchange.getRequestURI().getQuery();
          boolean quoted = query != null && query.contains("'");
          byte[] body =
              (quoted
                      ? "<b>You have an error in your SQL syntax near ''' at line 1</b>"
                      : "<div>product #1</div>")
                  .getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.start();
    int port = server.getAddress().getPort();

    DiscoveredPathService discoveredPaths = mock(DiscoveredPathService.class);
    when(discoveredPaths.record(any(), any(), any(), any(), any(), any(), any())).thenReturn(true);
    AuthorizedTarget target = authorizedTarget("http://127.0.0.1:" + port, String.valueOf(port));
    stubSavedTarget(target);
    ReconService service = serviceWith(discoveredPaths, 3);

    ReconRequest request =
        new ReconRequest(
            target.getId(), false, false, false, List.of(), false, List.of(), true, false, false,
            "ACTIVE", false);
    try {
      service.collect(1L, request);
    } finally {
      server.stop(0);
    }

    // 尽管 product.php 在发现顺序里排最后、端点上限只有 3，仍应因脚本后缀优先而被探测并命中。
    verify(discoveredPaths)
        .record(
            eq(target),
            eq(1L),
            argThat(url -> url != null && url.contains("/product.php") && url.contains("id=1")),
            eq("ACTIVE_ENUM"),
            any(),
            any(),
            argThat(note -> note != null && note.contains("疑似可注入")));
  }

  private ReconService serviceWith(DiscoveredPathService discoveredPaths) {
    return serviceWith(discoveredPaths, 16);
  }

  private ReconService serviceWith(DiscoveredPathService discoveredPaths, int maxEndpoints) {
    ReconService service =
        new ReconService(
            results, projects, targets, targetService, new ObjectMapper(), icpBrowserCaptures,
            discoveredPaths, mock(TrafficPacketRepository.class));
    ReflectionTestUtils.setField(service, "passiveSourcesEnabled", false);
    ReflectionTestUtils.setField(service, "paramProbeEnabled", true);
    ReflectionTestUtils.setField(service, "paramProbeMaxEndpoints", maxEndpoints);
    ReflectionTestUtils.setField(service, "paramProbeMaxFindings", 8);
    return service;
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
    ReconService service =
        new ReconService(
            results, projects, targets, targetService, new ObjectMapper(), icpBrowserCaptures,
            mock(DiscoveredPathService.class), mock(TrafficPacketRepository.class));
    ReflectionTestUtils.setField(service, "passiveSourcesEnabled", passiveSourcesEnabled);
    return service;
  }
}
