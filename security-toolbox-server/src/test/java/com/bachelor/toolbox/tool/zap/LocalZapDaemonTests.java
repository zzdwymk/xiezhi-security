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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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
  void readsRealActivityForSelectedScanAndOnlyCurrentlyRunningRules() {
    route("/json/ascan/view/scans", """
        {"scans":[{"id":"1","state":"RUNNING","reqCount":"999"},
          {"id":"3","state":"RUNNING","reqCount":"42","progress":"26"}]}
        """);
    route("/json/ascan/view/scanProgress", """
        {"scanProgress":["127.0.0.1:8080",{"HostProcess":[
          {"Plugin":["SQL Injection - MySQL (Time Based)","40019","release","26%","40000","12","0"]},
          {"Plugin":["Finished rule","1","release","Complete","100","3","0"]},
          {"Plugin":["Waiting rule","2","release","Pending","0","0","0"]}]}]}
        """);

    ZapDaemon.ScanActivity activity = daemon.activeScanActivity("3");

    assertThat(activity.requestCount()).isEqualTo(42);
    assertThat(activity.state()).isEqualTo("RUNNING");
    assertThat(activity.runningRules()).containsExactly("SQL Injection - MySQL (Time Based)");
  }

  @Test
  void missingOptionalDiagnosticsDoNotInvalidateAuthoritativeProgress() throws Exception {
    route("/json/ascan/view/status", "{\"status\":\"26\"}");
    route("/json/ascan/view/scans", "{\"code\":\"BAD_VIEW\"}");
    route("/json/ascan/view/scanProgress", "{\"scanProgress\":[{\"HostProcess\":[{\"Plugin\":[]}]}]}");

    assertThat(daemon.activeScanActivity("3")).isNull();
    assertThat(daemon.activeScanProgress("3")).isEqualTo(26);
  }

  @Test
  void unavailableDetailedRulesStillPreserveActualRequestCount() {
    route("/json/ascan/view/scans", "{\"scans\":[{\"id\":\"3\",\"reqCount\":\"42\",\"state\":\"RUNNING\"}]}");
    route("/json/ascan/view/scanProgress", "{\"code\":\"BAD_VIEW\"}");

    ZapDaemon.ScanActivity activity = daemon.activeScanActivity("3");

    assertThat(activity.requestCount()).isEqualTo(42);
    assertThat(activity.runningRules()).isEmpty();
  }

  @Test
  void interruptedDiagnosticsRestoreCancellationSignal() {
    Thread.currentThread().interrupt();
    try {
      assertThat(daemon.activeScanActivity("3")).isNull();
      assertThat(Thread.currentThread().isInterrupted()).isTrue();
    } finally {
      Thread.interrupted();
    }
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
      seeded.set(true); calls.add("access");
      respond(exchange, 200, "{\"accessUrl\":[{\"responseHeader\":\"HTTP/1.1 200 OK\\r\\n\\r\\n\"}]}");
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

  @ParameterizedTest
  @ValueSource(strings = {"{}", "{\"accessUrl\":[]}", "{\"accessUrl\":[{}]}",
      "{\"accessUrl\":[{\"responseHeader\":\"\"}]}",
      "{\"accessUrl\":[{\"responseHeader\":\"connection refused\"}]}"})
  void successfulApiWithoutTargetResponseIsIncomplete(String body) {
    route("/json/core/action/accessUrl", body);
    assertThatThrownBy(() -> daemon.accessUrl(URI.create("http://192.0.2.1/")))
        .hasMessageContaining("未收到目标网站的有效响应").hasMessageContaining("未完成");
  }

  @ParameterizedTest
  @ValueSource(strings = {"{}", "{\"status\":\"\"}", "{\"status\":\"NaN\"}",
      "{\"status\":\"Infinity\"}", "{\"status\":101}", "{\"status\":-1}"})
  void invalidProgressCannotBecomeCompletion(String body) {
    route("/json/ascan/view/status", body);
    assertThatThrownBy(() -> daemon.activeScanProgress("1")).hasMessageContaining("有效的检测进度");
  }

  private ZapDaemon.FuzzSpec fuzzSpec(String method) {
    URI target = URI.create("https://192.0.2.1:8443/form?keep=one&id=old");
    return new ZapDaemon.FuzzSpec(target, target.toString(), method,
        "POST".equals(method) ? "keep=one&id=old" : "", " a&b=✓ ", "id");
  }

  private String fuzzResponse(String request) throws Exception {
    return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(
        Map.of("sendRequest", List.of(Map.of("id", "4", "requestHeader", request,
            "responseHeader", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))));
  }

  @ParameterizedTest
  @ValueSource(strings = {"GET", "POST"})
  void usesActualCoreApiWithOneLiteralRequestAndNeverFollowsRedirects(String method) throws Exception {
    java.util.concurrent.atomic.AtomicInteger sends = new java.util.concurrent.atomic.AtomicInteger();
    server.createContext("/json/core/action/sendRequest", exchange -> {
      Map<String, String> form = new LinkedHashMap<>();
      String raw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
      for (String item : raw.split("&")) {
        String[] pair = item.split("=", 2);
        form.put(pair[0], URLDecoder.decode(pair.length > 1 ? pair[1] : "", StandardCharsets.UTF_8));
      }
      assertThat(exchange.getRequestMethod()).isEqualTo("POST");
      assertThat(form).containsEntry("followRedirects", "false");
      assertThat(form.keySet()).containsExactlyInAnyOrder("apikey", "request", "followRedirects");
      String request = form.get("request");
      assertThat(request).startsWith(method + " https://192.0.2.1:8443/form?");
      assertThat(request).contains("keep=one&id=+a%26b%3D%E2%9C%93+");
      if ("POST".equals(method)) {
        String body = request.split("\r\n\r\n", 2)[1];
        assertThat(request).contains("Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n");
        assertThat(request).contains("Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n");
      } else {
        assertThat(request).doesNotContain("Content-Length:").endsWith("\r\n\r\n");
      }
      sends.incrementAndGet();
      respond(exchange, 200, fuzzResponseUnchecked(request));
    });
    route("/json/pscan/view/recordsToScan", "{\"recordsToScan\":\"0\"}");
    String receipt = daemon.startFuzz(fuzzSpec(method));
    assertThat(receipt).startsWith("request-");
    assertThat(daemon.fuzzStatus(receipt)).isEqualTo("stopped;id=" + receipt + ";requests=1");
    assertThat(sends.get()).isEqualTo(1);
  }

  private String fuzzResponseUnchecked(String request) throws IOException {
    try { return fuzzResponse(request); }
    catch (Exception ex) { throw new IOException(ex); }
  }

  @ParameterizedTest
  @ValueSource(strings = {"{}", "{\"sendRequest\":[]}", "{\"sendRequest\":[{}]}",
      "{\"sendRequest\":[{\"requestHeader\":\"POST / HTTP/1.1\",\"responseHeader\":\"\"}]}",
      "{\"code\":\"BAD_ACTION\",\"message\":\"private-secret\"}"})
  void refusesMissingOrIncompleteSendResponseInsteadOfCreatingReceipt(String response) throws Exception {
    route("/json/core/action/sendRequest", response);
    assertThatThrownBy(() -> daemon.startFuzz(fuzzSpec("POST")))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class).hasMessageNotContaining("private-secret");
  }

  @Test
  void sendRequestHttpFailureIsNotHiddenBySuccessfulLookingJson() throws Exception {
    String body = fuzzResponse("POST https://192.0.2.1:8443/form HTTP/1.1\r\n");
    server.createContext("/json/core/action/sendRequest", exchange -> respond(exchange, 503, body));
    assertThatThrownBy(() -> daemon.startFuzz(fuzzSpec("POST")))
        .hasMessageContaining("HTTP 503").hasMessageContaining("core/action/sendRequest");
  }

  @ParameterizedTest
  @ValueSource(strings = {"{}", "{\"recordsToScan\":\"\"}", "{\"recordsToScan\":\"stopped\"}",
      "{\"recordsToScan\":-1}", "{\"code\":\"BAD_VIEW\",\"message\":\"private-secret\"}"})
  void invalidPassiveStatusCannotBeReportedAsStopped(String status) throws Exception {
    route("/json/core/action/sendRequest", fuzzResponse("POST https://192.0.2.1:8443/form HTTP/1.1\r\n"));
    route("/json/pscan/view/recordsToScan", status);
    String receipt = daemon.startFuzz(fuzzSpec("POST"));
    assertThatThrownBy(() -> daemon.fuzzStatus(receipt))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class).hasMessageNotContaining("private-secret");
  }

  @Test
  void pendingPassiveQueueIsRunningAndUnknownReceiptIsRejected() throws Exception {
    route("/json/core/action/sendRequest", fuzzResponse("POST https://192.0.2.1:8443/form HTTP/1.1\r\n"));
    route("/json/pscan/view/recordsToScan", "{\"recordsToScan\":\"1\"}");
    String receipt = daemon.startFuzz(fuzzSpec("POST"));
    assertThat(daemon.fuzzStatus(receipt)).startsWith("running;");
    assertThatThrownBy(() -> daemon.fuzzStatus("unknown")).hasMessageContaining("不存在");
  }

  @ParameterizedTest
  @ValueSource(strings = {"{}", "{\"alerts\":[{}]}", "{\"alerts\":[null]}"})
  void missingAlertsResponseCannotMasqueradeAsNoFindings(String response) throws Exception {
    route("/json/core/view/alerts", response);
    assertThatThrownBy(() -> daemon.alerts()).hasMessageContaining("不完整");
  }
}
