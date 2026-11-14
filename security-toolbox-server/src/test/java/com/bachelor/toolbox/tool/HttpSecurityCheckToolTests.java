package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class HttpSecurityCheckToolTests {
  private final HttpSecurityCheckTool tool =
      new HttpSecurityCheckTool(mock(TargetPolicyService.class));

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
          exchange.getResponseHeaders().add("Server", "local-security-test");
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
      HttpSecurityCheckTool networkTool =
          new HttpSecurityCheckTool(new TargetPolicyService(false, new PortRangeParser()));

      ToolExecutionResult result =
          networkTool.execute(target, Map.of("check", "disclosure"));

      assertThat(result.data()).containsEntry("status", 200);
      assertThat(upgrade.get()).isNull();
      assertThat(http2Settings.get()).isNull();
    } finally {
      server.stop(0);
    }
  }

  @Test
  void detectsMissingAttributesWithoutExposingCookieValue() {
    HttpHeaders headers =
        headers(
            Map.of("Set-Cookie", List.of("JSESSIONID=super-secret-value; Path=/; SameSite=Lax")));

    List<FindingDraft> findings = tool.analyzeCookies(URI.create("https://127.0.0.1"), headers);

    assertThat(findings).hasSize(1);
    assertThat(findings.get(0).title()).contains("JSESSIONID");
    assertThat(findings.get(0).evidence())
        .contains("Secure", "HttpOnly")
        .doesNotContain("super-secret-value");
  }

  @Test
  void acceptsCompactCookieAttributeSyntax() {
    HttpHeaders headers =
        headers(Map.of("Set-Cookie", List.of("auth_token=value;Secure;HttpOnly;SameSite=Strict")));

    assertThat(tool.analyzeCookies(URI.create("https://127.0.0.1"), headers)).isEmpty();
  }

  @Test
  void detectsReflectedCredentialedCorsOrigin() {
    HttpHeaders headers =
        headers(
            Map.of(
                "Access-Control-Allow-Origin", List.of("https://security-toolbox.invalid"),
                "Access-Control-Allow-Credentials", List.of("true")));

    List<FindingDraft> findings = tool.analyzeCors(headers, "https://security-toolbox.invalid");

    assertThat(findings)
        .singleElement()
        .satisfies(
            finding -> {
              assertThat(finding.severity()).isEqualTo("HIGH");
              assertThat(finding.title()).contains("CORS");
            });
  }

  @Test
  void detectsDangerousAdvertisedMethods() {
    HttpHeaders headers = headers(Map.of("Allow", List.of("GET, POST, TRACE, CONNECT")));

    List<FindingDraft> findings = tool.analyzeMethods(headers);

    assertThat(findings)
        .singleElement()
        .satisfies(
            finding -> {
              assertThat(finding.severity()).isEqualTo("HIGH");
              assertThat(finding.evidence()).contains("TRACE", "CONNECT");
            });
  }

  @Test
  void detectsTechnologyDisclosureHeaders() {
    HttpHeaders headers =
        headers(
            Map.of(
                "Server", List.of("nginx/1.24.0"),
                "X-Powered-By", List.of("Express")));

    List<FindingDraft> findings = tool.analyzeDisclosure(headers);

    assertThat(findings)
        .singleElement()
        .satisfies(finding -> assertThat(finding.evidence()).contains("nginx/1.24.0", "Express"));
  }

  private HttpHeaders headers(Map<String, List<String>> values) {
    return HttpHeaders.of(values, (name, value) -> true);
  }

  @Test
  void joinRejectsAbsolutePathPointingOutsideAuthorizedTarget() throws Exception {
    // Round 63：path 为绝对 URL 时仅允许与授权目标同 host+port（防潜在 SSRF 纵深防御）。
    var method =
        HttpSecurityCheckTool.class.getDeclaredMethod("join", java.net.URI.class, String.class);
    method.setAccessible(true);
    var base = java.net.URI.create("http://192.168.222.158:80/");
    // 同目标绝对 URL → 通过
    var same =
        (java.net.URI)
            method.invoke(tool, base, "http://192.168.222.158:80/login?id=1");
    org.assertj.core.api.Assertions.assertThat(same.getHost()).isEqualTo("192.168.222.158");
    // 跨目标绝对 URL → ApiException（fail-closed）
    assertThatThrownBy(
            () -> method.invoke(tool, base, "http://169.254.169.254/latest/meta-data/"))
        .isInstanceOf(java.lang.reflect.InvocationTargetException.class)
        .hasCauseInstanceOf(com.bachelor.toolbox.common.ApiException.class);
    // 同目标不同端口 → 拒
    assertThatThrownBy(
            () -> method.invoke(tool, base, "http://192.168.222.158:8080/"))
        .isInstanceOf(java.lang.reflect.InvocationTargetException.class)
        .hasCauseInstanceOf(com.bachelor.toolbox.common.ApiException.class);
  }
}