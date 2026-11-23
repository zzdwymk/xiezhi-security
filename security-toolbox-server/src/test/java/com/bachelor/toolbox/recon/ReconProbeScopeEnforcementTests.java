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
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * 第357轮：授权范围校验下沉到 probePath / fetchBody 内部。
 *
 * <p>R355 只在 {@code resolveLink} 校验端口，{@code probePath} 本身不校验；任何新增调用点忘记校验就会
 * 越界出站。本轮把 host + 授权端口校验放进这两个方法入口，并用「未授权端口不得产生任何请求」验证。
 */
class ReconProbeScopeEnforcementTests {

  private static ReconService service() {
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
        mock(PathDictionaryService.class),
        new com.bachelor.toolbox.target.PortRangeParser());
  }

  private static AuthorizedTarget target(String value, String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(1L);
    target.setTargetValue(value);
    target.setAllowedPorts(allowedPorts);
    target.setEnabled(true);
    return target;
  }

  @Test
  void probeToUnauthorizedPortSendsNoRequest() throws Exception {
    AtomicInteger hits = new AtomicInteger();
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
    try {
      int port = server.getAddress().getPort();
      String url = "http://127.0.0.1:" + port + "/";
      Method probe =
          ReconService.class.getDeclaredMethod(
              "probePath", HttpClient.class, String.class, AuthorizedTarget.class);
      probe.setAccessible(true);
      ReconService service = service();
      HttpClient client = HttpClient.newHttpClient();

      // 授权端口 = 该端口：应当真实探测并拿到 200
      Object allowed = probe.invoke(service, client, url, target(url, String.valueOf(port)));
      assertThat(allowed).as("授权端口应放行").isNotNull();
      assertThat(hits.get()).isEqualTo(1);

      // 授权端口只写 80：必须被入口拦截，绝不发出请求
      Object blocked = probe.invoke(service, client, url, target(url, "80"));
      assertThat(blocked).as("未授权端口必须在入口返回 null").isNull();
      assertThat(hits.get()).as("被拦截时不得产生任何请求").isEqualTo(1);
    } finally {
      server.stop(0);
    }
  }

  @Test
  void fetchBodyToForeignHostSendsNoRequest() throws Exception {
    Method fetch =
        ReconService.class.getDeclaredMethod(
            "fetchBody", HttpClient.class, String.class, AuthorizedTarget.class);
    fetch.setAccessible(true);
    Object result =
        fetch.invoke(service(), HttpClient.newHttpClient(), "http://evil.example.com/", target("http://127.0.0.1/", "80"));
    assertThat(result).as("跨 host 抓取必须被入口拦截").isNull();
  }
}
