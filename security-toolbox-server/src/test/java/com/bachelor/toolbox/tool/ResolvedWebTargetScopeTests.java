package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.WebTargetResolver;
import com.sun.net.httpserver.HttpServer;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Round 398: cached framework metadata is never an authorization credential. */
class ResolvedWebTargetScopeTests {
  private static TargetPolicyService policy() {
    return new TargetPolicyService(false, new PortRangeParser());
  }

  private static AuthorizedTarget target(String host, String ports) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setTargetValue(host);
    target.setAllowedPorts(ports);
    target.setEnabled(true);
    return target;
  }

  private static SecurityTool httpTool(String code) {
    return "http_headers".equals(code)
        ? new HttpHeaderTool(policy()) : new HttpSecurityCheckTool(policy());
  }

  private static Map<String, Object> parameters(String code, List<String> bases) {
    Map<String, Object> parameters = new LinkedHashMap<>();
    parameters.put(WebTargetResolver.PARAM_RESOLVED_BASES, bases);
    if ("http_security_check".equals(code)) parameters.put("check", "disclosure");
    return parameters;
  }

  private static HttpServer fixture(AtomicInteger hits) throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", exchange -> {
      hits.incrementAndGet();
      exchange.sendResponseHeaders(200, -1);
      exchange.close();
    });
    server.start();
    return server;
  }

  @ParameterizedTest
  @ValueSource(strings = {"http_headers", "http_security_check"})
  void rejectsForeignResolvedHostBeforeAnyHttpRequest(String code) throws Exception {
    AtomicInteger hits = new AtomicInteger();
    HttpServer server = fixture(hits);
    try {
      String base = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
      assertThatThrownBy(() -> httpTool(code).execute(
          target("192.168.222.155", "443"), parameters(code, List.of(base))))
          .isInstanceOf(ApiException.class).hasMessageContaining("授权目标");
      assertThat(hits).hasValue(0);
    } finally { server.stop(0); }
  }

  @ParameterizedTest
  @ValueSource(strings = {"http_headers", "http_security_check"})
  void rejectsUnauthorizedResolvedPortBeforeAnyHttpRequest(String code) throws Exception {
    AtomicInteger hits = new AtomicInteger();
    HttpServer server = fixture(hits);
    try {
      String base = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
      assertThatThrownBy(() -> httpTool(code).execute(
          target("127.0.0.1", "443"), parameters(code, List.of(base))))
          .isInstanceOf(ApiException.class).hasMessageContaining("授权端口");
      assertThat(hits).hasValue(0);
    } finally { server.stop(0); }
  }

  @ParameterizedTest
  @ValueSource(strings = {"http_headers", "http_security_check"})
  void validatesAllResolvedBasesBeforeFirstHttpRequest(String code) throws Exception {
    AtomicInteger hits = new AtomicInteger();
    HttpServer server = fixture(hits);
    try {
      int port = server.getAddress().getPort();
      List<String> bases = List.of("http://127.0.0.1:" + port + "/", "http://127.0.0.1:0/");
      assertThatThrownBy(() -> httpTool(code).execute(
          target("127.0.0.1", String.valueOf(port)), parameters(code, bases)))
          .isInstanceOf(ApiException.class).hasMessageContaining("端口");
      assertThat(hits).hasValue(0);
    } finally { server.stop(0); }
  }

  @ParameterizedTest
  @ValueSource(strings = {"http_headers", "http_security_check"})
  void preservesAuthorizedNonDefaultResolvedPort(String code) throws Exception {
    AtomicInteger hits = new AtomicInteger();
    HttpServer server = fixture(hits);
    try {
      int port = server.getAddress().getPort();
      String base = "http://127.0.0.1:" + port + "/";
      ToolExecutionResult result = httpTool(code).execute(
          target("127.0.0.1", String.valueOf(port)), parameters(code, List.of(base)));
      assertThat(result.data()).containsEntry("status", 200);
      assertThat(hits).hasValue(1);
    } finally { server.stop(0); }
  }

  @ParameterizedTest
  @ValueSource(strings = {"http_headers", "http_security_check"})
  void rejectsDisabledTargetEvenWhenResolvedBasesExist(String code) throws Exception {
    AtomicInteger hits = new AtomicInteger();
    HttpServer server = fixture(hits);
    try {
      int port = server.getAddress().getPort();
      AuthorizedTarget target = target("127.0.0.1", String.valueOf(port));
      target.setEnabled(false);
      assertThatThrownBy(() -> httpTool(code).execute(target,
          parameters(code, List.of("http://127.0.0.1:" + port + "/"))))
          .isInstanceOf(ApiException.class).hasMessageContaining("停用");
      assertThat(hits).hasValue(0);
    } finally { server.stop(0); }
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "https://127.0.0.1/", "https://192.168.222.155:8443/",
      "https://user@192.168.222.155/", "https://192.168.222.155/#fragment",
      "https://192.168.222.155:0/"})
  void tlsResolutionRejectsUntrustedFinalUriWithoutOpeningSocket(String base) throws Exception {
    TlsConfigurationTool tool = new TlsConfigurationTool(policy());
    Method resolve = TlsConfigurationTool.class.getDeclaredMethod(
        "resolveBase", AuthorizedTarget.class, Map.class);
    resolve.setAccessible(true);
    assertThatThrownBy(() -> resolve.invoke(tool, target("192.168.222.155", "443"),
        Map.of(WebTargetResolver.PARAM_RESOLVED_BASES, List.of(base))))
        .isInstanceOf(java.lang.reflect.InvocationTargetException.class)
        .hasCauseInstanceOf(ApiException.class);
  }

  @Test
  void tlsResolutionPreservesAuthorizedAlternatePortWithoutOpeningSocket() throws Exception {
    TlsConfigurationTool tool = new TlsConfigurationTool(policy());
    Method resolve = TlsConfigurationTool.class.getDeclaredMethod(
        "resolveBase", AuthorizedTarget.class, Map.class);
    resolve.setAccessible(true);
    URI uri = (URI) resolve.invoke(tool, target("192.168.222.155", "8443"),
        Map.of(WebTargetResolver.PARAM_RESOLVED_BASES, List.of("https://192.168.222.155:8443/")));
    assertThat(uri).isEqualTo(URI.create("https://192.168.222.155:8443/"));
  }
}
