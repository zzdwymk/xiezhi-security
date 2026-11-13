package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.traffic.TrafficPacketRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * SSRF-经重定向回归——Round 12。
 * ...
 */
@DisplayName("参数探测 SSRF-经重定向防护（Round 12）")
class ReconRedirectSsrfTest {
  private HttpServer authorized;
  private HttpServer internal;

  @AfterEach
  void tearDown() {
    if (authorized != null) authorized.stop(0);
    if (internal != null) internal.stop(0);
  }

  private ReconService newService() {
    return new ReconService(
        mock(ReconResultRepository.class),
        mock(AssessmentProjectService.class),
        mock(AuthorizedTargetRepository.class),
        mock(TargetService.class),
        new ObjectMapper(),
        mock(IcpBrowserCaptureStore.class),
        mock(DiscoveredPathService.class),
        mock(TrafficPacketRepository.class),
        mock(SubdomainDictionaryService.class),
        mock(PathDictionaryService.class));
  }

  private Object invokeMineProbe(ReconService svc, String url, String targetHost, int targetPort) throws Exception {
    Method m = ReconService.class.getDeclaredMethod(
        "mineProbe", java.net.http.HttpClient.class, String.class, String.class, int.class);
    m.setAccessible(true);
    Object client = ReflectionTestUtils.getField(svc, "paramProbeClient");
    return m.invoke(svc, client, url, targetHost, targetPort);
  }

  @Test
  @DisplayName("SSRF-1 跨主机 302 → 不跟随、内网服务器零请求、结果 null")
  void crossHostRedirectIsNotFollowed() throws Exception {
    AtomicBoolean internalHit = new AtomicBoolean(false);
    internal = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    int internalPort = internal.getAddress().getPort();
    internal.createContext("/secret", ex -> {
      internalHit.set(true);
      byte[] b = "INTERNAL-SECRET".getBytes(StandardCharsets.UTF_8);
      ex.sendResponseHeaders(200, b.length);
      ex.getResponseBody().write(b);
      ex.close();
    });
    internal.start();

    authorized = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    int authPort = authorized.getAddress().getPort();
    authorized.createContext("/p", ex -> {
      ex.getResponseHeaders().add("Location", "http://127.0.0.1:" + internalPort + "/secret");
      ex.sendResponseHeaders(302, -1);
      ex.close();
    });
    authorized.start();

    ReconService svc = newService();
    String url = "http://127.0.0.1:" + authPort + "/p?id=1'";
    Object resp = invokeMineProbe(svc, url, "127.0.0.1", authPort);

    // 结果应为 null（跨主机被丢弃）
    assertThat(resp).isNull();
    // 关键：内网目标从未被真实请求
    assertThat(internalHit.get())
        .as("跨主机重定向绝不能被真实请求（SSRF）")
        .isFalse();
  }

  @Test
  @DisplayName("SSRF-2 同源 301 → 手工跟随成功（目录补齐不被误伤）")
  void sameHostRedirectIsFollowedOnce() throws Exception {
    authorized = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    int authPort = authorized.getAddress().getPort();
    authorized.createContext("/dir", ex -> {
      String path = ex.getRequestURI().getPath();
      if (!path.endsWith("/")) {
        ex.getResponseHeaders().add("Location", "/dir/");
        ex.sendResponseHeaders(301, -1);
        ex.close();
        return;
      }
      byte[] b = "OK-SAMEHOST".getBytes(StandardCharsets.UTF_8);
      ex.sendResponseHeaders(200, b.length);
      ex.getResponseBody().write(b);
      ex.close();
    });
    authorized.start();

    ReconService svc = newService();
    Object resp = invokeMineProbe(svc, "http://127.0.0.1:" + authPort + "/dir?id=1", "127.0.0.1", authPort);

    assertThat(resp).isNotNull();
    Object status = ReflectionTestUtils.invokeGetterMethod(resp, "status");
    assertThat(status).isEqualTo(200);
  }
}
