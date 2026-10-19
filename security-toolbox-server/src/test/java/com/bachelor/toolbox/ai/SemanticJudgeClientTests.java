package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link SemanticJudgeClient}: every failure path must produce a blocking verdict.
 *
 * <p>The invariant under test is the one that matters operationally: a judge that is slow, broken,
 * returning rubbish or missing entirely must never look like a judge that approved the plan.
 */
class SemanticJudgeClientTests {
  private HttpServer server;
  private int port;
  private final ConcurrentLinkedQueue<String> requests = new ConcurrentLinkedQueue<>();
  /** Response the fake judge service will return (status, body). */
  private volatile int responseStatus = 200;
  private volatile String responseBody = "{}";
  private volatile long responseDelayMillis = 0;

  @BeforeEach
  void startServer() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(4));
    server.createContext("/agent/judge/evaluate", this::handle);
    server.start();
    port = server.getAddress().getPort();
  }

  @AfterEach
  void stopServer() {
    if (server != null) {
      server.stop(0);
    }
  }

  private void handle(HttpExchange exchange) throws java.io.IOException {
    requests.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
    if (responseDelayMillis > 0) {
      try {
        Thread.sleep(responseDelayMillis);
      } catch (InterruptedException ex) {
        Thread.currentThread().interrupt();
      }
    }
    byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(responseStatus, bytes.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(bytes);
    }
    exchange.close();
  }

  private SemanticJudgeClient client(int timeoutSeconds) {
    return new SemanticJudgeClient(
        new ObjectMapper(),
        "http://127.0.0.1:" + port,
        port,
        "",
        true,
        timeoutSeconds);
  }

  private static AiPlanResponse.PlanStep step(String toolCode, String nodeId) {
    return new AiPlanResponse.PlanStep(
        toolCode,
        "步骤 " + nodeId,
        "依据证据 " + nodeId,
        Map.of(),
        nodeId,
        0,
        List.of(),
        "CAUTION",
        true,
        List.of());
  }

  private static String cleanVerdict(String behaviour, String risk, boolean allow, double confidence) {
    return "{\"allow\":"
        + allow
        + ",\"behaviour\":\""
        + behaviour
        + "\",\"risk\":\""
        + risk
        + "\",\"confidence\":"
        + confidence
        + ",\"summary\":\"判定摘要\",\"degraded\":false,\"degradedReason\":\"\"}";
  }

  // ------------------------------------------------------------------ happy path

  @Test
  void parsesAVerdictFromTheRuntime() {
    responseBody = cleanVerdict("目录与资产枚举", "CAUTION", false, 0.92);

    Map<String, Object> verdict = client(8).judgeOne(step("dir_scan", "dir-scan"), 42L);

    assertThat(verdict).containsEntry("allow", false);
    assertThat(verdict).containsEntry("behaviour", "目录与资产枚举");
    assertThat(verdict).containsEntry("risk", "CAUTION");
    assertThat(verdict).containsEntry("degraded", false);
    // The request must carry the tool code so the judge sees what is being proposed.
    assertThat(requests).hasSize(1);
    assertThat(requests.peek()).contains("dir_scan").contains("dir-scan");
  }

  @Test
  void planDocumentAggregatesWorstRiskAndRequiresReview() {
    responseBody = cleanVerdict("SQL注入探测", "HIGH", false, 0.88);

    Map<String, Object> document =
        client(8)
            .judgePlan(
                List.of(step("sqlmap_scan", "sqlmap"), step("dir_scan", "dir-scan")), 42L);

    assertThat(document).containsEntry("worstRisk", "HIGH");
    assertThat(document).containsEntry("requiresHumanReview", true);
    assertThat(document).containsEntry("degraded", false);
    assertThat((List<?>) document.get("steps")).hasSize(2);
  }

  @Test
  void fullyClearedPlanDoesNotRequireReview() {
    responseBody = cleanVerdict("常规安全探测", "SAFE", true, 0.97);

    Map<String, Object> document =
        client(8).judgePlan(List.of(step("http_headers", "headers")), 42L);

    assertThat(document).containsEntry("worstRisk", "SAFE");
    assertThat(document).containsEntry("requiresHumanReview", false);
    assertThat(document).containsEntry("degraded", false);
  }

  // ------------------------------------------------------------------ fail-closed paths

  @Test
  void httpErrorProducesDegradedBlockingVerdict() {
    responseStatus = 500;
    responseBody = "{\"detail\":\"boom\"}";

    Map<String, Object> verdict = client(8).judgeOne(step("http_headers", "headers"), 42L);

    assertThat(verdict).containsEntry("allow", false);
    assertThat(verdict).containsEntry("risk", "CRITICAL");
    assertThat(verdict).containsEntry("degraded", true);
    assertThat(String.valueOf(verdict.get("degradedReason"))).contains("judge_http_500");
  }

  @Test
  void timeoutProducesDegradedBlockingVerdict() {
    responseDelayMillis = 3000;
    responseBody = cleanVerdict("常规安全探测", "SAFE", true, 0.99);

    Map<String, Object> verdict = client(1).judgeOne(step("http_headers", "headers"), 42L);

    assertThat(verdict).containsEntry("allow", false);
    assertThat(verdict).containsEntry("degraded", true);
    assertThat(verdict).containsEntry("risk", "CRITICAL");
  }

  @Test
  void unparseableBodyProducesDegradedBlockingVerdict() {
    responseBody = "this is not json at all";

    Map<String, Object> verdict = client(8).judgeOne(step("dir_scan", "dir-scan"), 42L);

    assertThat(verdict).containsEntry("allow", false);
    assertThat(verdict).containsEntry("degraded", true);
  }

  @Test
  void unreachableJudgeProducesDegradedBlockingVerdict() {
    // Point at a closed port: the call must fail into the degraded verdict, not throw.
    SemanticJudgeClient unreachable =
        new SemanticJudgeClient(new ObjectMapper(), "http://127.0.0.1:1", 1, "", true, 2);

    Map<String, Object> verdict = unreachable.judgeOne(step("dir_scan", "dir-scan"), 42L);

    assertThat(verdict).containsEntry("allow", false);
    assertThat(verdict).containsEntry("risk", "CRITICAL");
    assertThat(verdict).containsEntry("degraded", true);
  }

  @Test
  void disabledJudgeProducesDegradedDocumentWithoutCallingOut() {
    SemanticJudgeClient disabled =
        new SemanticJudgeClient(
            new ObjectMapper(), "http://127.0.0.1:" + port, port, "", false, 8);

    Map<String, Object> document =
        disabled.judgePlan(List.of(step("dir_scan", "dir-scan")), 42L);

    assertThat(document).containsEntry("degraded", true);
    assertThat(document).containsEntry("requiresHumanReview", true);
    assertThat(document).containsEntry("worstRisk", "CRITICAL");
    // Nothing was sent: a disabled judge must not leak plan data to the provider.
    assertThat(requests).isEmpty();
  }

  @Test
  void emptyPlanIsNotDegraded() {
    Map<String, Object> document = client(8).judgePlan(List.of(), 42L);

    assertThat(document).containsEntry("degraded", false);
    assertThat(document).containsEntry("requiresHumanReview", false);
    assertThat((List<?>) document.get("steps")).isEmpty();
  }

  @Test
  void planWithOnlyDegradedStepsRequiresReview() {
    responseStatus = 503;

    Map<String, Object> document =
        client(8).judgePlan(List.of(step("dir_scan", "dir-scan")), 42L);

    assertThat(document).containsEntry("degraded", true);
    assertThat(document).containsEntry("requiresHumanReview", true);
    assertThat(document).containsEntry("worstRisk", "CRITICAL");
  }

  // ------------------------------------------------------------------ helpers and bounds

  @Test
  void sendsTheRuntimeTokenUnderTheHeaderNameTheRuntimeExpects() throws Exception {
    responseBody = cleanVerdict("常规安全探测", "SAFE", true, 0.95);
    ConcurrentLinkedQueue<String> tokens = new ConcurrentLinkedQueue<>();
    // A separate server: HttpServer refuses to replace an existing context on the same path.
    HttpServer tokenServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    tokenServer.createContext(
        "/agent/judge/evaluate",
        exchange -> {
          String token = exchange.getRequestHeaders().getFirst("X-AI-Runtime-Token");
          tokens.add(token == null ? "" : token);
          exchange.getRequestBody().readAllBytes();
          byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, bytes.length);
          try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
          }
          exchange.close();
        });
    tokenServer.start();
    try {
      int tokenPort = tokenServer.getAddress().getPort();
      SemanticJudgeClient withToken =
          new SemanticJudgeClient(
              new ObjectMapper(),
              "http://127.0.0.1:" + tokenPort,
              tokenPort,
              "judge-e2e-token",
              true,
              8);
      withToken.judgeOne(step("http_headers", "headers"), 42L);
    } finally {
      tokenServer.stop(0);
    }

    // A wrong header name makes every judge call fail authentication, which would silently
    // degrade every plan to "judge unavailable" — the feature would look like a permanent block.
    assertThat(tokens).containsExactly("judge-e2e-token");
  }

  @Test
  void stricterRiskOrderingIsNotAlphabetical() {
    assertThat(SemanticJudgeClient.stricter("SAFE", "CAUTION")).isEqualTo("CAUTION");
    assertThat(SemanticJudgeClient.stricter("CRITICAL", "SAFE")).isEqualTo("CRITICAL");
    // Unknown values must not be treated as SAFE.
    assertThat(SemanticJudgeClient.stricter("SAFE", "BANANA")).isEqualTo("CRITICAL");
  }

  @Test
  void judgesAtMostSixteenStepsPerPlan() {
    responseBody = cleanVerdict("常规安全探测", "SAFE", true, 0.95);
    List<AiPlanResponse.PlanStep> many = new ArrayList<>();
    for (int index = 0; index < 25; index++) {
      many.add(step("http_headers", "node-" + index));
    }

    Map<String, Object> document = client(8).judgePlan(many, 42L);

    assertThat((List<?>) document.get("steps")).hasSize(16);
    assertThat(requests).hasSize(16);
  }

  @Test
  void rejectsNonLoopbackBaseUrl() {
    try {
      new SemanticJudgeClient(
          new ObjectMapper(), "http://10.0.0.5:8090", 8090, "", true, 8);
      throw new AssertionError("expected loopback validation to reject a remote judge host");
    } catch (IllegalArgumentException ex) {
      assertThat(ex.getMessage()).contains("回环");
    }
  }

  @Test
  void defaultsToLoopbackWhenBaseUrlIsBlank() {
    SemanticJudgeClient client =
        new SemanticJudgeClient(new ObjectMapper(), "", port, "", true, 8);

    assertThat(client.available()).isTrue();
  }
}
