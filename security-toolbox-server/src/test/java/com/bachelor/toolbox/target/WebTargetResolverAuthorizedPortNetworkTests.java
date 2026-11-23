package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * 第370轮：WebTargetResolver 授权端口不变量的真实网络验证。
 *
 * <p>使用真实 {@link TargetPolicyService}、真实 {@link HttpClient} 与两个真实回环 HTTP 服务（无 mock）：
 * 授权范围只含端口 A，但前置端口扫描结果同时包含未授权端口 B。要求解析器对 B **零出站**，
 * 且只返回 A 的基址——这是「发现端口来自前置扫描也必须逐端口复核授权」的核心不变量。
 */
class WebTargetResolverAuthorizedPortNetworkTests {
  private final PortRangeParser ports = new PortRangeParser();
  private final WebTargetResolver resolver = new WebTargetResolver(
      new TargetPolicyService(false, ports), ports, null, HttpClient.newHttpClient());
  private HttpServer authorizedServer;
  private HttpServer unauthorizedServer;
  private final AtomicInteger authorizedHits = new AtomicInteger();
  private final AtomicInteger unauthorizedHits = new AtomicInteger();

  private static HttpServer server(AtomicInteger hits) throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", exchange -> {
      hits.incrementAndGet();
      exchange.sendResponseHeaders(200, -1);
      exchange.close();
    });
    server.start();
    return server;
  }

  @BeforeEach
  void startServers() throws Exception {
    authorizedServer = server(authorizedHits);
    unauthorizedServer = server(unauthorizedHits);
  }

  @AfterEach
  void stopServers() {
    if (authorizedServer != null) authorizedServer.stop(0);
    if (unauthorizedServer != null) unauthorizedServer.stop(0);
  }

  private AuthorizedTarget target(String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(371L);
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAllowedPorts(allowedPorts);
    target.setEnabled(true);
    return target;
  }

  private static Map<String, Object> discovered(int port) {
    return Map.of("port", port, "protocol", "tcp", "service", "http");
  }

  @Test
  void discoveredUnauthorizedPortReceivesNoRequestAndIsNotResolved() {
    int authorizedPort = authorizedServer.getAddress().getPort();
    int unauthorizedPort = unauthorizedServer.getAddress().getPort();

    List<URI> resolved = resolver.resolve(
        target(String.valueOf(authorizedPort)),
        List.of(discovered(authorizedPort), discovered(unauthorizedPort)));

    assertThat(resolved).as("只应解析出授权端口的基址").hasSize(1);
    assertThat(resolved.get(0).getPort() == -1 ? 80 : resolved.get(0).getPort())
        .isEqualTo(authorizedPort);
    assertThat(authorizedHits.get()).as("授权端口必须被真实探测").isGreaterThan(0);
    assertThat(unauthorizedHits.get()).as("未授权端口不得收到任何请求").isZero();
  }

  @Test
  void defaultWebPortsAreOnlyProbedWhenExplicitlyAuthorized() {
    // 授权范围只有随机端口；默认 80/443 未授权，不得被探测（真实回环上通常无服务，
    // 这里断言的是「解析结果不含未授权端口」这一可观察行为）。
    int authorizedPort = authorizedServer.getAddress().getPort();
    List<URI> resolved = resolver.resolve(target(String.valueOf(authorizedPort)), List.of());

    assertThat(resolved).hasSize(1);
    assertThat(resolved.get(0).getPort() == -1 ? 80 : resolved.get(0).getPort())
        .isEqualTo(authorizedPort);
  }

  @Test
  void joinRejectsAbsoluteUrlPointingToAnotherPort() {
    URI base = URI.create("http://127.0.0.1:" + authorizedServer.getAddress().getPort() + "/");
    org.assertj.core.api.Assertions
        .assertThatThrownBy(() -> resolver.join(base, "http://127.0.0.1:9/other"))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
        .hasMessageContaining("不允许指向授权目标之外的主机或端口");
    org.assertj.core.api.Assertions
        .assertThat(resolver.join(base, "/same-host")).hasPort(authorizedServer.getAddress().getPort());
  }
}
