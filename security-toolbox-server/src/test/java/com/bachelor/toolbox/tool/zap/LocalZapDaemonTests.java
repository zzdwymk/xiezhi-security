package com.bachelor.toolbox.tool.zap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.LinkedHashMap;
import java.net.URLDecoder;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * P0 integration test: drives {@link LocalZapDaemon} against an embedded stub of the ZAP JSON REST
 * API. This proves the REST call + JSON parsing contract end-to-end without requiring a real ZAP
 * install on the build machine.
 */
class LocalZapDaemonTests {
  private HttpServer server;
  private int port;
  private LocalZapDaemon daemon;
  private ExecutorService executor;

  @BeforeEach
  void setUp() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    executor = java.util.concurrent.Executors.newSingleThreadExecutor();
    server.setExecutor(executor);
    server.start();
    port = server.getAddress().getPort();
    daemon = new LocalZapDaemon("ignored", "127.0.0.1", port, Duration.ofSeconds(1));
  }

  @AfterEach
  void tearDown() {
    server.stop(0);
    executor.shutdownNow();
  }

  private void route(String pathPrefix, String body) {
    server.createContext(pathPrefix, exchange -> {
      byte[] payload = body.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, payload.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(payload);
      }
    });
  }

  @Test
  void readsVersionAndRunsSpider() throws Exception {
    route("/json/core/view/version", "{\"version\":\"2.15.0\"}");
    route("/json/spider/action/scan", "{\"scan\":\"7\"}");
    route("/json/spider/view/status", "{\"status\":\"42\"}");
    route("/json/spider/action/stop", "{\"result\":\"SUCCESS\"}");

    assertThat(daemon.isReady()).isTrue();
    String id = daemon.startSpider(URI.create("http://127.0.0.1:80"));
    assertThat(id).isEqualTo("7");
    assertThat(daemon.spiderProgress(id)).isEqualTo(42);
    daemon.stopSpider(id);
  }

  @Test
  void runsActiveScanAndReadsProgress() throws Exception {
    route("/json/ascan/action/scan", "{\"scan\":\"3\"}");
    route("/json/ascan/view/status", "{\"status\":\"88\"}");
    route("/json/ascan/action/stop", "{\"result\":\"SUCCESS\"}");

    String id = daemon.startActiveScan(URI.create("http://127.0.0.1:80"));
    assertThat(id).isEqualTo("3");
    assertThat(daemon.activeScanProgress(id)).isEqualTo(88);
  }

  @Test
  void parsesAlertsIntoNormalizedRecords() throws Exception {
    route(
        "/json/core/view/alerts",
        """
        {"alerts":[{"url":"http://127.0.0.1:80/","alert":"XSS","risk":"High","confidence":"Medium","cweid":"79","description":"reflected"},{"url":"http://127.0.0.1:80/","alert":"Info","risk":"Informational","cweid":"-1","description":"x"}]}
        """);

    List<ZapDaemon.ZapAlert> alerts = daemon.alerts();

    assertThat(alerts).hasSize(2);
    assertThat(alerts.get(0).risk()).isEqualTo("HIGH");
    assertThat(alerts.get(0).cweId()).isEqualTo("CWE-79");
    assertThat(alerts.get(1).risk()).isEqualTo("INFO");
  }

  private Map<String, String> publicParameters(com.sun.net.httpserver.HttpExchange exchange) {
    Map<String, String> result = new LinkedHashMap<>();
    for (String item : exchange.getRequestURI().getRawQuery().split("&")) {
      String[] pair = item.split("=", 2);
      if (List.of("url", "followRedirects", "recurse", "scanPolicyName", "id", "attackStrength").contains(pair[0])) {
        result.put(pair[0], URLDecoder.decode(pair.length > 1 ? pair[1] : "", StandardCharsets.UTF_8));
      }
    }
    return result;
  }

  private void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) { out.write(bytes); }
  }

  @Test
  void seedsSitesTreeWithoutRedirectsAndAppliesActualStrengthBeforeSingleUrlScan() throws Exception {
    AtomicBoolean seeded = new AtomicBoolean();
    List<String> calls = new ArrayList<>();
    List<Map<String, String>> settings = new ArrayList<>();
    URI target = URI.create("http://192.0.2.1/");
    server.createContext("/json/core/action/accessUrl", exchange -> {
      assertThat(publicParameters(exchange)).containsExactlyInAnyOrderEntriesOf(Map.of("url", target.toString(), "followRedirects", "false"));
      seeded.set(true); calls.add("access"); respond(exchange, 200, "{\"accessUrl\":[]}");
    });
    route("/json/ascan/view/scanners", "{\"scanners\":[{\"id\":\"1\",\"enabled\":true},{\"id\":\"2\",\"enabled\":false}]}");
    server.createContext("/json/ascan/action/setScannerAttackStrength", exchange -> {
      settings.add(publicParameters(exchange)); calls.add("strength"); respond(exchange, 200, "{\"Result\":\"OK\"}");
    });
    server.createContext("/json/ascan/action/scan", exchange -> {
      if (!seeded.get()) { respond(exchange, 400, "{\"code\":\"url_not_found\",\"message\":\"URL Not Found\"}"); return; }
      assertThat(publicParameters(exchange)).containsEntry("url", target.toString()).containsEntry("recurse", "false").containsEntry("scanPolicyName", "Default Policy");
      calls.add("scan"); respond(exchange, 200, "{\"scan\":\"850\"}");
    });

    assertThatThrownBy(() -> daemon.startActiveScan(target)).hasMessageContaining("ascan/action/scan").hasMessageContaining("URL_NOT_FOUND");
    daemon.accessUrl(target);
    assertThat(daemon.startActiveScan(target, "Default Policy", "LOW", false)).isEqualTo("850");
    assertThat(calls).containsExactly("access", "strength", "strength", "scan");
    assertThat(settings).containsExactly(
        Map.of("id", "1", "attackStrength", "LOW", "scanPolicyName", "Default Policy"),
        Map.of("id", "2", "attackStrength", "LOW", "scanPolicyName", "Default Policy"));
  }

  @Test
  void preservesOriginalApiErrorWithoutReturningEmptyIdOrExposingResponseMessage() throws Exception {
    server.createContext("/json/ascan/action/scan", exchange ->
        respond(exchange, 400, "{\"code\":\"url_not_found\",\"message\":\"password=secret&apikey=private\"}"));
    assertThatThrownBy(() -> daemon.startActiveScan(URI.create("http://192.0.2.1/")))
        .hasMessageContaining("ascan/action/scan").hasMessageContaining("HTTP 400").hasMessageContaining("URL_NOT_FOUND")
        .hasMessageNotContaining("secret").hasMessageNotContaining("private").hasMessageNotContaining("apikey");
  }

  @Test
  void refusesSuccessResponseWithNoScanId() throws Exception {
    route("/json/ascan/action/scan", "{}");
    assertThatThrownBy(() -> daemon.startActiveScan(URI.create("http://192.0.2.1/")))
        .hasMessageContaining("扫描未启动");
  }
}
