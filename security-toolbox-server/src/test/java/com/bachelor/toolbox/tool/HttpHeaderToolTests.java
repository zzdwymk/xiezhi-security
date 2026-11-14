package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class HttpHeaderToolTests {
  @Test
  void usesHttp11ForAuthorizedLocalDevelopmentServer() throws Exception {
    AtomicReference<String> upgrade = new AtomicReference<>();
    AtomicReference<String> http2Settings = new AtomicReference<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          upgrade.set(exchange.getRequestHeaders().getFirst("Upgrade"));
          http2Settings.set(exchange.getRequestHeaders().getFirst("HTTP2-Settings"));
          exchange.getResponseHeaders().add("Server", "local-header-test");
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    server.start();

    try {
      int port = server.getAddress().getPort();
      AuthorizedTarget target = new AuthorizedTarget();
      target.setEnabled(true);
      target.setTargetValue("http://127.0.0.1:" + port);
      target.setAllowedPorts(String.valueOf(port));
      HttpHeaderTool tool =
          new HttpHeaderTool(new TargetPolicyService(false, new PortRangeParser()));

      ToolExecutionResult result = tool.execute(target, Map.of());

      assertThat(result.data()).containsEntry("status", 200);
      assertThat(upgrade.get()).isNull();
      assertThat(http2Settings.get()).isNull();
    } finally {
      server.stop(0);
    }
  }

  @Test
  void resolverJoinRejectsAbsolutePathPointingOutsideAuthorizedTarget() throws Exception {
    // Round 67：与 HttpSecurityCheckTool.join 同一纵深防御——绝对 URL 路径仅允许与授权目标同 host+port。
    var method =
        HttpHeaderTool.class.getDeclaredMethod("resolverJoin", java.net.URI.class, String.class);
    method.setAccessible(true);
    var tool = new HttpHeaderTool(new com.bachelor.toolbox.target.TargetPolicyService(false, new com.bachelor.toolbox.target.PortRangeParser()));
    var base = java.net.URI.create("http://192.168.222.158:80/");
    var same =
        (java.net.URI)
            method.invoke(tool, base, "http://192.168.222.158:80/login?id=1");
    org.assertj.core.api.Assertions.assertThat(same.getHost()).isEqualTo("192.168.222.158");
    assertThatThrownBy(
            () -> method.invoke(tool, base, "http://169.254.169.254/latest/meta-data/"))
        .isInstanceOf(java.lang.reflect.InvocationTargetException.class)
        .hasCauseInstanceOf(com.bachelor.toolbox.common.ApiException.class);
    assertThatThrownBy(
            () -> method.invoke(tool, base, "http://192.168.222.158:8080/"))
        .isInstanceOf(java.lang.reflect.InvocationTargetException.class)
        .hasCauseInstanceOf(com.bachelor.toolbox.common.ApiException.class);
  }
}