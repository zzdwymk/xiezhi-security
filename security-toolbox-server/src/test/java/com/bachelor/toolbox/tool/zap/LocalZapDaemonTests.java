package com.bachelor.toolbox.tool.zap;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
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

  @BeforeEach
  void setUp() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(java.util.concurrent.Executors.newSingleThreadExecutor());
    server.start();
    port = server.getAddress().getPort();
    daemon = new LocalZapDaemon("ignored", "127.0.0.1", port, Duration.ofSeconds(1));
  }

  @AfterEach
  void tearDown() {
    server.stop(0);
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
}