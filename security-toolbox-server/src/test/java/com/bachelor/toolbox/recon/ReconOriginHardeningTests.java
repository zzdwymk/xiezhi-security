package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.traffic.TrafficPacketRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * 第360轮：recon 出站 origin 残余收紧（R359 复核确认的四个边界）。
 *
 * <ol>
 *   <li>URL 携带 {@code user:pass@} userinfo 时不得发出请求（登记层早已拒绝，出站层此前放行）；</li>
 *   <li>显式 {@code :0} 端口不得按默认 80/443 授权判断（应视为非法）；</li>
 *   <li>{@code sameAuthorizedOrigin} 必须比对 scheme（http↔https 跨协议重定向不放行）；</li>
 *   <li>{@code mineProbe} 首次发送前必须有入口范围守卫（此前仅依赖候选来源约定）。</li>
 * </ol>
 */
class ReconOriginHardeningTests {

  private static ReconService service() {
    ReconService service =
        new ReconService(
            mock(ReconResultRepository.class),
            mock(AssessmentProjectService.class),
            mock(AuthorizedTargetRepository.class),
            mock(TargetService.class),
            new ObjectMapper(),
            mock(IcpBrowserCaptureStore.class),
            mock(DiscoveredPathService.class),
            mock(TrafficPacketRepository.class),
            mock(SubdomainDictionaryService.class),
            mock(PathDictionaryService.class),
            new com.bachelor.toolbox.target.PortRangeParser());
    ReflectionTestUtils.setField(service, "passiveSourcesEnabled", false);
    return service;
  }

  private static AuthorizedTarget target(String value, String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(1L);
    target.setTargetValue(value);
    target.setAllowedPorts(allowedPorts);
    target.setEnabled(true);
    return target;
  }

  private static HttpServer countingServer(AtomicInteger hits) throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          hits.incrementAndGet();
          byte[] body = "ok".getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.start();
    return server;
  }

  @Test
  void probePathRejectsUserInfoUrlsWithoutSending() throws Exception {
    AtomicInteger hits = new AtomicInteger();
    HttpServer server = countingServer(hits);
    try {
      int port = server.getAddress().getPort();
      String url = "http://user:pass@127.0.0.1:" + port + "/";
      Method probe =
          ReconService.class.getDeclaredMethod(
              "probePath", HttpClient.class, String.class, AuthorizedTarget.class);
      probe.setAccessible(true);
      Object result =
          probe.invoke(service(), HttpClient.newHttpClient(), url, target(url, String.valueOf(port)));
      assertThat(result).as("携带 userinfo 的 URL 必须在入口拒绝").isNull();
      assertThat(hits.get()).as("userinfo 请求不得发出").isEqualTo(0);
    } finally {
      server.stop(0);
    }
  }

  @Test
  void withinAuthorizedScopeRejectsExplicitZeroPort() throws Exception {
    Method scope =
        ReconService.class.getDeclaredMethod(
            "withinAuthorizedScope", String.class, AuthorizedTarget.class);
    scope.setAccessible(true);
    Object result =
        scope.invoke(service(), "http://127.0.0.1:0/", target("http://127.0.0.1/", "80"));
    assertThat(result)
        .as("显式 :0 是非法端口，不能按默认 80/443 授权判断")
        .isEqualTo(false);
  }

  @Test
  void sameAuthorizedOriginRequiresSchemeEquality() throws Exception {
    Method origin =
        ReconService.class.getDeclaredMethod(
            "sameAuthorizedOrigin", URI.class, String.class, int.class, String.class);
    origin.setAccessible(true);
    ReconService service = service();
    URI httpsUri = URI.create("https://127.0.0.1:61678/");
    Object result = origin.invoke(service, httpsUri, "127.0.0.1", 61678, "http");
    assertThat(result)
        .as("http 授权基址不得放行 https 同端口 URI（origin 必须含 scheme）")
        .isEqualTo(false);
    Object sameScheme =
        origin.invoke(service, URI.create("http://127.0.0.1:61678/"), "127.0.0.1", 61678, "http");
    assertThat(sameScheme).as("同 scheme/host/port 应放行").isEqualTo(true);
  }

  @Test
  void mineProbeEntryGuardBlocksUnauthorizedPortBeforeFirstSend() throws Exception {
    AtomicInteger forbiddenHits = new AtomicInteger();
    HttpServer forbidden = countingServer(forbiddenHits);
    HttpServer authorized = countingServer(new AtomicInteger());
    try {
      int forbiddenPort = forbidden.getAddress().getPort();
      int authorizedPort = authorized.getAddress().getPort();
      Method probe =
          ReconService.class.getDeclaredMethod(
              "mineProbe", HttpClient.class, String.class, String.class, int.class, String.class);
      probe.setAccessible(true);
      Object result =
          probe.invoke(
              service(),
              HttpClient.newHttpClient(),
              "http://127.0.0.1:" + forbiddenPort + "/page-c",
              "127.0.0.1",
              authorizedPort,
              "http");
      assertThat(result).as("未授权端口的参数探测必须返回 null").isNull();
      assertThat(forbiddenHits.get()).as("未授权端口不得收到任何请求").isEqualTo(0);
    } finally {
      forbidden.stop(0);
      authorized.stop(0);
    }
  }
}