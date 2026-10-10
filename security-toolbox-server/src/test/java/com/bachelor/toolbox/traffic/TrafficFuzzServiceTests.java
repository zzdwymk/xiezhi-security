package com.bachelor.toolbox.traffic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.any;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.tool.zap.ZapDaemon;
import com.bachelor.toolbox.tool.zap.ZapDaemonSupplier;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class TrafficFuzzServiceTests {
  private static final long PACKET_ID = 41L;
  private static final String MARKER = "\u00a7name\u00a7";

  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final AuditService audit = mock(AuditService.class);
  private final TargetService replayTargets = mock(TargetService.class);
  private final TrafficReplayService replay = new TrafficReplayService(packets, audit, replayTargets,
      new TargetPolicyService(false, new PortRangeParser()));
  private final TrafficFuzzService service = new TrafficFuzzService(replay);

  private LocalEchoServer server;

  @AfterEach
  void closeServer() throws Exception {
    if (server != null) server.close();
  }

  @Test
  void substitutesPlaceholderInBodyAndFlagsChangedResponses() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    List<String> payloads =
        List.of("plain", "<b>reflected</b>", "admin", "../../etc/passwd");

    TrafficFuzzService.FuzzResponse response =
        service.fuzz(
            PACKET_ID,
            new TrafficFuzzService.FuzzRequest(
                7L,
                "POST",
                "http://127.0.0.1:" + server.port() + "/submit",
                "Content-Type: application/x-www-form-urlencoded",
                "q=" + MARKER,
                payloads));

    assertEquals(payloads.size(), response.payloadCount());
    TrafficFuzzService.FuzzHit baseline = response.results().get(0);
    assertEquals("<<baseline>>", baseline.payload());
    assertFalse(baseline.changed());

    TrafficFuzzService.FuzzHit plain = response.results().get(1);
    assertTrue(plain.changed(), "不同响应应与基线判为变更");

    TrafficFuzzService.FuzzHit reflected = response.results().get(2);
    assertTrue(reflected.payload().contains("reflected"));
    assertTrue(reflected.changed(), "反射型 payload 响应应判为变更");
  }

  @Test
  void rejectsRequestWithoutPlaceholder() throws Exception {
    server = LocalEchoServer.started();
    TrafficFuzzService.FuzzRequest request =
        new TrafficFuzzService.FuzzRequest(
            null,
            "GET",
            "http://127.0.0.1:" + server.port() + "/none",
            "",
            "",
            List.of("aa", "bb"));

    assertThrows(ApiException.class, () -> service.fuzz(PACKET_ID, request));
  }

  @Test
  void keepsNonNameLongAndRepeatedBindingsInTheActualRequestSnapshot() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    String origin = "http://127.0.0.1:" + server.port();
    String full = "A".repeat(257);
    var response = service.fuzz(PACKET_ID, new TrafficFuzzService.FuzzRequest(7L, "POST",
        origin + "/§id§?repeat=§id§", "X-Value: §id§", "q=§id§\r\nlast=§id§",
        Map.of("id", List.of(full)), null, "LOOP", "SNIPER"));

    assertEquals(2, server.requests.size());
    assertEquals(origin + "/?repeat=", response.results().get(0).request().url());
    var hit = response.results().get(1);
    assertEquals(48, hit.payload().length(), "The UI label remains an abbreviated label");
    assertEquals("POST", hit.request().method());
    assertEquals(origin + "/" + full + "?repeat=" + full, hit.request().url());
    assertEquals("X-Value: " + full, hit.request().headers());
    assertEquals("q=" + full + "\r\nlast=" + full, hit.request().body());
    assertTrue(server.requests.get(1).startsWith("POST /" + full + "?repeat=" + full + " HTTP/1.1\r\n"));
    assertTrue(server.requests.get(1).contains("\r\nX-Value: " + full + "\r\n"));
    assertTrue(server.requests.get(1).endsWith("\r\n\r\n" + hit.request().body()));
  }

  @Test
  void storesEachSniperCandidateWithoutParsingItsMultiVariableDisplayLabel() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    String origin = "http://127.0.0.1:" + server.port();
    var response = service.fuzz(PACKET_ID, new TrafficFuzzService.FuzzRequest(7L, "POST",
        origin + "/§name§?id=§id§", "X-Pair: §name§|§id§", "name=§name§&id=§id§",
        Map.of("name", List.of("A"), "id", List.of("A")), List.of("A"), "LOOP", "SNIPER"));
    assertEquals(3, response.results().size());
    assertEquals(3, server.requests.size());
    assertEquals("name=A · id=id", response.results().get(1).payload());
    assertEquals("name=name · id=A", response.results().get(2).payload());
    var first = response.results().get(1).request();
    var second = response.results().get(2).request();
    assertEquals(new TrafficFuzzService.FuzzReplayRequest("POST", origin + "/A?id=id", "X-Pair: A|id", "name=A&id=id"), first);
    assertEquals(new TrafficFuzzService.FuzzReplayRequest("POST", origin + "/name?id=A", "X-Pair: name|A", "name=name&id=A"), second);
    assertTrue(server.requests.get(1).startsWith("POST /A?id=id HTTP/1.1\r\n"));
    assertTrue(server.requests.get(1).endsWith("\r\n\r\n" + first.body()));
    assertTrue(server.requests.get(2).startsWith("POST /name?id=A HTTP/1.1\r\n"));
    assertTrue(server.requests.get(2).endsWith("\r\n\r\n" + second.body()));
  }

  @Test
  void oldSerializedHitsRemainReadableAndNewSnapshotsSurviveRoundTrip() throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    var old = mapper.readValue("{\"payload\":\"old-label\",\"statusCode\":200,\"reason\":\"OK\","
        + "\"durationMs\":1,\"responseBytes\":2,\"digestPrefix\":\"abcd\",\"effectiveStatus\":200,\"changed\":true}", TrafficFuzzService.FuzzHit.class);
    assertNull(old.request());
    assertEquals("old-label", old.payload());
    var snapshot = new TrafficFuzzService.FuzzReplayRequest("POST", "http://192.168.136.132/A?id=id",
        "X-Value: " + "A".repeat(257), "one\r\ntwo");
    var current = new TrafficFuzzService.FuzzHit("short display", 200, "OK", 1, 2, "abcd", 200, true, snapshot);
    assertEquals(current, mapper.readValue(mapper.writeValueAsString(current), TrafficFuzzService.FuzzHit.class));
  }

  @Test
  void allLoopCombinationModesKeepTheirOwnActualRequests() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    String origin = "http://127.0.0.1:" + server.port();
    Map<String, List<String>> expected = Map.of(
        "BATTERING_RAM", List.of("1|1", "2|2"),
        "PITCHFORK", List.of("1|A", "2|B"),
        "PITCHFORK_LONGEST", List.of("1|A", "2|B"),
        "CLUSTER_BOMB", List.of("1|A", "1|B", "2|A", "2|B"));
    for (String mode : List.of("BATTERING_RAM", "PITCHFORK", "PITCHFORK_LONGEST", "CLUSTER_BOMB")) {
      int offset = server.requests.size();
      var response = service.fuzz(PACKET_ID, new TrafficFuzzService.FuzzRequest(7L, "POST",
          origin + "/§x§?y=§y§", "X-Pair: §x§|§y§", "x=§x§&y=§y§",
          Map.of("x", List.of("1", "2"), "y", List.of("A", "B")), null, "LOOP", mode));
      assertEquals(1 + expected.get(mode).size(), response.results().size());
      for (int i = 0; i < expected.get(mode).size(); i++) {
        String[] pair = expected.get(mode).get(i).split("\\|");
        var snapshot = response.results().get(i + 1).request();
        String target = "/" + pair[0] + "?y=" + pair[1];
        assertEquals(origin + target, snapshot.url(), mode);
        assertEquals("X-Pair: " + pair[0] + "|" + pair[1], snapshot.headers(), mode);
        assertEquals("x=" + pair[0] + "&y=" + pair[1], snapshot.body(), mode);
        assertTrue(server.requests.get(offset + i + 1).startsWith("POST " + target + " HTTP/1.1\r\n"), mode);
        assertTrue(server.requests.get(offset + i + 1).endsWith("\r\n\r\n" + snapshot.body()), mode);
      }
    }
  }

  @Test
  void everyMultiDictionaryAliasRejectsEmptyParticipatingGroupsBeforeAnyEngineWork() {
    TrafficReplayService replaySpy = mock(TrafficReplayService.class);
    ZapDaemonSupplier supplier = mock(ZapDaemonSupplier.class);
    DependencyDetectionService detection = mock(DependencyDetectionService.class);
    TrafficFuzzService checked = new TrafficFuzzService(replaySpy, supplier, detection);
    List<List<String>> invalidGroups = java.util.Arrays.asList(null, List.of(), List.of(""),
        List.of(" \t\r\n"), List.of("\u00A0\u3000\uFEFF"),
        java.util.Arrays.asList((String) null), java.util.Arrays.asList(null, " \t"));
    for (String mode : List.of("PITCHFORK", "SHORTEST", "PITCHFORK_LONGEST", "LONGEST",
        "CLUSTER_BOMB", "CLUSTERBOMB", "CARTESIAN", " longest ")) {
      for (String engine : List.of("LOOP", "AUTO", "ZAP")) {
        for (List<String> invalid : invalidGroups) {
          Map<String, List<String>> groups = new java.util.LinkedHashMap<>();
          groups.put("x", invalid);
          groups.put("y", List.of("1"));
          var request = new TrafficFuzzService.FuzzRequest(7L, "GET",
              "http://192.168.136.132/?x=§x§&y=§y§", "", "", groups, List.of("legacy"), engine, mode);
          ApiException failure = assertThrows(ApiException.class, () -> checked.fuzz(PACKET_ID, request),
              mode + "/" + engine + "/" + invalid);
          assertEquals("多字典模式的每个占位符都需要至少一行非空载荷：§x§", failure.getMessage());
        }
        var omitted = new TrafficFuzzService.FuzzRequest(7L, "GET",
            "http://192.168.136.132/?x=§x§&y=§y§", "", "", Map.of("y", List.of("1")), null, engine, mode);
        assertEquals("多字典模式的每个占位符都需要至少一行非空载荷：§x§",
            assertThrows(ApiException.class, () -> checked.fuzz(PACKET_ID, omitted)).getMessage());
      }
    }
    verifyNoInteractions(replaySpy, supplier, detection);
  }

  @Test
  void multiDictionaryMissingMapCannotBorrowLegacyPayloadsAndReportsEveryMissingVariable() {
    TrafficReplayService replaySpy = mock(TrafficReplayService.class);
    ZapDaemonSupplier supplier = mock(ZapDaemonSupplier.class);
    DependencyDetectionService detection = mock(DependencyDetectionService.class);
    TrafficFuzzService checked = new TrafficFuzzService(replaySpy, supplier, detection);
    for (String mode : List.of("PITCHFORK", "SHORTEST", "PITCHFORK_LONGEST", "LONGEST",
        "CLUSTER_BOMB", "CLUSTERBOMB", "CARTESIAN")) {
      for (Map<String, List<String>> groups : java.util.Arrays.<Map<String, List<String>>>asList(null, Map.of())) {
        var request = new TrafficFuzzService.FuzzRequest(7L, "GET",
            "http://192.168.136.132/?q=§name§", "", "", groups, List.of("legacy"), "AUTO", mode);
        assertEquals("多字典模式的每个占位符都需要至少一行非空载荷：§name§",
            assertThrows(ApiException.class, () -> checked.fuzz(PACKET_ID, request)).getMessage());
      }
      var bothEmpty = new TrafficFuzzService.FuzzRequest(7L, "GET",
          "http://192.168.136.132/?x=§x§&y=§y§", "X-Again: §x§", "", Map.of(), null, "LOOP", mode);
      assertEquals("多字典模式的每个占位符都需要至少一行非空载荷：§x§、§y§",
          assertThrows(ApiException.class, () -> checked.fuzz(PACKET_ID, bothEmpty)).getMessage());
    }
    verifyNoInteractions(replaySpy, supplier, detection);
  }

  @Test
  void validMultiDictionariesTrimLikeTheUiPreserveDuplicatesAndKeepEachActualRequest() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    String origin = "http://127.0.0.1:" + server.port();
    List<String> shortest = List.of("A|1", "A|2");
    List<String> longest = List.of("A|1", "A|2", "B|2");
    List<String> cartesian = List.of("A|1", "A|2", "A|1", "A|2", "B|1", "B|2");
    Map<String, List<String>> expectations = Map.of("PITCHFORK", shortest, "SHORTEST", shortest,
        "PITCHFORK_LONGEST", longest, "LONGEST", longest, "CLUSTER_BOMB", cartesian,
        "CLUSTERBOMB", cartesian, "CARTESIAN", cartesian);
    for (var entry : expectations.entrySet()) {
      int offset = server.requests.size();
      var response = service.fuzz(PACKET_ID, new TrafficFuzzService.FuzzRequest(7L, "POST",
          origin + "/§x§?y=§y§", "X-Pair: §x§|§y§", "x=§x§&y=§y§",
          Map.of("x", java.util.Arrays.asList(" A ", null, "", "\u00A0\uFEFF", "A", "\u00A0B\uFEFF"),
              "y", List.of(" 1 ", "\t2\u3000")), null, "LOOP", entry.getKey()));
      assertEquals(entry.getValue().size(), response.payloadCount(), entry.getKey());
      assertEquals(entry.getValue().size() + 1, response.completedRequests(), entry.getKey());
      for (int i = 0; i < entry.getValue().size(); i++) {
        String[] pair = entry.getValue().get(i).split("\\|");
        String target = "/" + pair[0] + "?y=" + pair[1];
        var snapshot = response.results().get(i + 1).request();
        assertEquals(origin + target, snapshot.url(), entry.getKey());
        assertEquals("X-Pair: " + pair[0] + "|" + pair[1], snapshot.headers(), entry.getKey());
        assertEquals("x=" + pair[0] + "&y=" + pair[1], snapshot.body(), entry.getKey());
        assertTrue(server.requests.get(offset + i + 1).startsWith("POST " + target + " HTTP/1.1\r\n"), entry.getKey());
        assertTrue(server.requests.get(offset + i + 1).endsWith("\r\n\r\n" + snapshot.body()), entry.getKey());
      }
    }
  }

  @Test
  void singleDictionaryModesStillKeepLiteralWhitespaceAndLegacyPayloads() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    String origin = "http://127.0.0.1:" + server.port();
    for (String mode : List.of("SNIPER", "BATTERING_RAM", "BATTERINGRAM", "RAM")) {
      int offset = server.requests.size();
      var response = service.fuzz(PACKET_ID, new TrafficFuzzService.FuzzRequest(7L, "POST",
          origin + "/submit", "Content-Type: text/plain", "q=§name§",
          null, List.of(" ", " A "), "LOOP", mode));
      assertEquals(2, response.payloadCount(), mode);
      assertEquals("q= ", response.results().get(1).request().body(), mode);
      assertEquals("q= A ", response.results().get(2).request().body(), mode);
      assertTrue(server.requests.get(offset + 1).endsWith("\r\n\r\nq= "), mode);
      assertTrue(server.requests.get(offset + 2).endsWith("\r\n\r\nq= A "), mode);
    }
  }

  @Test
  void fallsBackToLoopWhenZapUnavailable() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    DependencyDetectionService detection = mock(DependencyDetectionService.class);
    when(detection.detect(false)).thenReturn(zapUnavailable());
    TrafficFuzzService withZap =
        new TrafficFuzzService(replay, () -> new StubZapDaemon(true), detection);

    TrafficFuzzService.FuzzResponse response =
        withZap.fuzz(
            PACKET_ID,
            new TrafficFuzzService.FuzzRequest(
                7L,
                "GET",
                "http://127.0.0.1:" + server.port() + "/f?q=" + MARKER,
                "",
                "",
                List.of("boom")));

    assertEquals("LOOP", response.engine());
    assertTrue(response.results().stream().anyMatch(hit -> "boom".equals(hit.payload())));
    assertTrue(response.results().stream().allMatch(hit -> hit.request() != null));
    assertEquals("http://127.0.0.1:" + server.port() + "/f?q=boom", response.results().get(1).request().url());
  }

  @Test
  void zapSendsEveryCandidateExactlyOnceAndZeroAlertsIsCompleted() throws Exception {
    server = LocalEchoServer.started();
    ZapDaemon daemon = fixtureDaemon();
    TrafficFuzzService withZap = authorizedZap(replay, daemon, server.port());
    var response = withZap.fuzz(PACKET_ID, zapRequest("GET", "http://127.0.0.1:" + server.port()
        + "/x?q=prefix-" + MARKER + "&keep=1", "", "", List.of("one & two", "<literal>", " "), "ZAP"));
    assertEquals("ZAP", response.engine());
    assertEquals("COMPLETED", response.status());
    assertEquals(3, response.payloadCount());
    assertEquals(3, response.completedRequests());
    assertTrue(response.results().isEmpty());
    assertTrue(response.message().contains("不包含响应基线比较"));
    assertEquals(3, server.requests.size());
    assertTrue(server.requests.get(0).contains("q=prefix-one+%26+two&keep=1"));
    assertTrue(server.requests.get(1).contains("q=prefix-%3Cliteral%3E&keep=1"));
    assertTrue(server.requests.get(2).contains("q=prefix-+&keep=1"));
  }

  @Test
  void zapPostKeepsUnselectedFieldsAndEncodesOneLiteralValue() throws Exception {
    server = LocalEchoServer.started();
    var withZap = authorizedZap(replay, fixtureDaemon(), server.port());
    var response = withZap.fuzz(PACKET_ID, zapRequest("POST", "http://127.0.0.1:" + server.port()
        + "/submit", "Content-Type: application/x-www-form-urlencoded", "q=" + MARKER + "&keep=1",
        List.of("literal&admin=true"), "ZAP"));
    assertEquals("COMPLETED", response.status());
    assertEquals(1, server.requests.size());
    assertTrue(server.requests.get(0).endsWith("q=literal%26admin%3Dtrue&keep=1"));
  }

  @Test
  void autoFallbackExplainsUnsupportedHeadersBeforeAnyZapRequest() throws Exception {
    server = LocalEchoServer.started();
    ZapDaemon daemon = mock(ZapDaemon.class);
    var withZap = authorizedZap(replay, daemon, server.port());
    var response = withZap.fuzz(PACKET_ID, zapRequest("POST", "http://127.0.0.1:" + server.port()
        + "/submit", "X-Preserve: keep", "q=" + MARKER, List.of("value"), "AUTO"));
    assertEquals("LOOP", response.engine());
    assertTrue(response.message().contains("请求头 x-preserve"));
    assertEquals(2, response.completedRequests());
    assertEquals(2, server.requests.size());
    verifyNoInteractions(daemon);
  }

  @Test
  void explicitZapRejectsUnsupportedShapesAndEmptyCandidatesBeforeSending() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    var withZap = authorizedZap(mock(TrafficReplayService.class), daemon, 8080);
    String url = "http://127.0.0.1:8080/?q=" + MARKER;
    assertThrows(ApiException.class, () -> withZap.fuzz(PACKET_ID,
        zapRequest("GET", url, "X-Keep: value", "", List.of("candidate"), "ZAP")));
    assertThrows(ApiException.class, () -> withZap.fuzz(PACKET_ID,
        zapRequest("GET", url + "&other=" + MARKER, "", "", List.of("candidate"), "ZAP")));
    assertThrows(ApiException.class, () -> withZap.fuzz(PACKET_ID,
        zapRequest("GET", url, "", "", List.of(), "ZAP")));
    verifyNoInteractions(daemon);
  }

  @Test
  void zapCannotBypassSourceHostPortOrTargetBinding() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    TrafficReplayService loop = mock(TrafficReplayService.class);
    var withZap = authorizedZap(loop, daemon, 8080);
    for (String url : List.of("http://127.0.0.2:8080/?q=", "http://127.0.0.1:8081/?q=")) {
      assertThrows(ApiException.class, () -> withZap.fuzz(PACKET_ID,
          zapRequest("GET", url + MARKER, "", "", List.of("value"), "AUTO")));
    }
    assertThrows(ApiException.class, () -> withZap.fuzz(PACKET_ID,
        new TrafficFuzzService.FuzzRequest(99L, "GET", "http://127.0.0.1:8080/?q=" + MARKER,
            "", "", null, List.of("value"), "ZAP", "SNIPER")));
    verifyNoInteractions(daemon, loop);
  }

  @Test
  void zapFailureAfterSendStopsWithoutAutoReplayOrFalseSuccess() throws Exception {
    for (String state : List.of("bad-status", "running", "http-timeout")) {
      ZapDaemon daemon = mock(ZapDaemon.class);
      when(daemon.startFuzz(any())).thenReturn("receipt");
      if (state.equals("running")) when(daemon.fuzzStatus(any())).thenThrow(new java.util.concurrent.TimeoutException("deadline"));
      else if (state.equals("http-timeout")) when(daemon.fuzzStatus(any())).thenThrow(new java.net.http.HttpTimeoutException("deadline"));
      else when(daemon.fuzzStatus(any())).thenReturn(state);
      TrafficReplayService loop = mock(TrafficReplayService.class);
      var withZap = authorizedZap(loop, daemon, 8080);
      var response = withZap.fuzz(PACKET_ID, zapRequest("GET", "http://127.0.0.1:8080/?q=" + MARKER,
          "", "", List.of("first", "second"), "AUTO"));
      assertEquals("ZAP", response.engine());
      assertEquals(state.equals("bad-status") ? "FAILED" : "TIMEOUT", response.status());
      assertEquals(0, response.completedRequests());
      verify(daemon, times(1)).startFuzz(any());
      verify(daemon).kill();
      verifyNoInteractions(loop);
    }
  }

  @Test
  void zapRejectsEmptyReceiptAndMissingAlertResultWithoutReplay() throws Exception {
    for (boolean emptyReceipt : List.of(true, false)) {
      ZapDaemon daemon = mock(ZapDaemon.class);
      when(daemon.startFuzz(any())).thenReturn(emptyReceipt ? "" : "receipt");
      when(daemon.fuzzStatus(any())).thenReturn("stopped");
      when(daemon.alerts()).thenReturn(null);
      TrafficReplayService loop = mock(TrafficReplayService.class);
      var withZap = authorizedZap(loop, daemon, 8080);
      var response = withZap.fuzz(PACKET_ID, zapRequest("GET", "http://127.0.0.1:8080/?q=" + MARKER,
          "", "", List.of("first"), "AUTO"));
      assertEquals("FAILED", response.status());
      verifyNoInteractions(loop);
    }
  }

  @Test
  void zapCandidateBudgetRemainsTwoHundredRequestsWithoutBaseline() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    when(daemon.startFuzz(any())).thenReturn("receipt");
    when(daemon.fuzzStatus(any())).thenReturn("stopped");
    when(daemon.alerts()).thenReturn(List.of());
    var withZap = authorizedZap(mock(TrafficReplayService.class), daemon, 8080);
    var response = withZap.fuzz(PACKET_ID, zapRequest("GET", "http://127.0.0.1:8080/?q=" + MARKER,
        "", "", java.util.stream.IntStream.range(0, 210).mapToObj(Integer::toString).toList(), "ZAP"));
    assertEquals(200, response.completedRequests());
    verify(daemon, times(200)).startFuzz(any());
  }

  @Test
  void expiredZapDeadlineNeverReadsAlertsOrClaimsCompletion() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    assertThrows(java.util.concurrent.TimeoutException.class,
        () -> service.awaitZapCompletion(daemon, "receipt", System.nanoTime() - 1));
    verifyNoInteractions(daemon);
  }

  @Test
  void validatesEveryCandidateAndFieldUniquenessBeforeAnyRequest() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    var withZap = authorizedZap(mock(TrafficReplayService.class), daemon, 8080);
    assertThrows(ApiException.class, () -> withZap.fuzz(PACKET_ID, zapRequest("GET",
        "http://127.0.0.1:8080/?q=" + MARKER, "", "", List.of("valid", "x".repeat(1001)), "ZAP")));
    assertThrows(ApiException.class, () -> withZap.fuzz(PACKET_ID, zapRequest("GET",
        "http://127.0.0.1:8080/?q=" + MARKER + "&%71=duplicate", "", "", List.of("valid"), "ZAP")));
    verifyNoInteractions(daemon);
  }

  @Test
  void autoStartupFailureFallsBackOnceWithReasonAndExplicitZapFails() throws Exception {
    server = LocalEchoServer.started();
    ZapDaemon daemon = mock(ZapDaemon.class);
    doThrow(new ApiException("fixture startup failure")).when(daemon).start();
    var withZap = authorizedZap(replay, daemon, server.port());
    String url = "http://127.0.0.1:" + server.port() + "/submit";
    var response = withZap.fuzz(PACKET_ID, zapRequest("POST", url, "", "q=" + MARKER, List.of("value"), "AUTO"));
    assertEquals("LOOP", response.engine());
    assertTrue(response.message().contains("fixture startup failure"));
    assertEquals(2, server.requests.size());
    assertThrows(ApiException.class, () -> withZap.fuzz(PACKET_ID,
        zapRequest("POST", url, "", "q=" + MARKER, List.of("value"), "ZAP")));
    assertEquals(2, server.requests.size());
    verify(daemon, never()).startFuzz(any());
  }

  @Test
  void zapCancellationKeepsInterruptAndNeverAutoReplays() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    when(daemon.startFuzz(any())).thenThrow(new InterruptedException("fixture cancelled"));
    TrafficReplayService loop = mock(TrafficReplayService.class);
    var withZap = authorizedZap(loop, daemon, 8080);
    try {
      var response = withZap.fuzz(PACKET_ID, zapRequest("GET", "http://127.0.0.1:8080/?q=" + MARKER,
          "", "", List.of("first", "second"), "AUTO"));
      assertEquals("CANCELLED", response.status());
      assertTrue(Thread.currentThread().isInterrupted());
      verify(daemon, times(1)).startFuzz(any());
      verify(daemon).kill();
      verifyNoInteractions(loop);
    } finally { Thread.interrupted(); }
  }

  @Test
  void zapReturnsOnlyInScopePassiveAlertsWithRequestCountSeparateFromAlertCount() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    when(daemon.startFuzz(any())).thenReturn("receipt");
    when(daemon.fuzzStatus(any())).thenReturn("stopped");
    when(daemon.alerts()).thenReturn(List.of(
        new ZapDaemon.ZapAlert("http://127.0.0.1:8080/?q=value", "Scoped alert", "MEDIUM", "LOW", "1", "detail", 1),
        new ZapDaemon.ZapAlert("http://127.0.0.2:8080/?q=value", "Other host", "HIGH", "LOW", "1", "detail", 2),
        new ZapDaemon.ZapAlert("http://127.0.0.1:22/?q=value", "Other port", "HIGH", "LOW", "1", "detail", 3)));
    var withZap = authorizedZap(mock(TrafficReplayService.class), daemon, 8080);
    var response = withZap.fuzz(PACKET_ID, zapRequest("GET", "http://127.0.0.1:8080/?q=" + MARKER,
        "", "", List.of("first", "second"), "ZAP"));
    assertEquals("COMPLETED", response.status());
    assertEquals(2, response.completedRequests());
    assertEquals(1, response.results().size());
    assertEquals("Scoped alert", response.results().get(0).payload());
    assertNull(response.results().get(0).request(), "A passive alert has no uniquely attributable request; never invent one from its label");
  }

  private TrafficFuzzService.FuzzRequest zapRequest(String method, String url, String headers,
      String body, List<String> payloads, String engine) {
    return new TrafficFuzzService.FuzzRequest(7L, method, url, headers, body, null, payloads, engine, "SNIPER");
  }

  private TrafficFuzzService authorizedZap(TrafficReplayService loop, ZapDaemon daemon, int port) {
    arrangeSource(7L, port);
    TargetService targets = mock(TargetService.class);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L); target.setEnabled(true); target.setTargetType("URL");
    target.setTargetValue("http://127.0.0.1:" + port); target.setAllowedPorts(Integer.toString(port));
    when(targets.get(7L)).thenReturn(target);
    DependencyDetectionService detection = mock(DependencyDetectionService.class);
    when(detection.detect(false)).thenReturn(zapAvailable());
    return new TrafficFuzzService(loop, () -> daemon, detection, packets, targets,
        new TargetPolicyService(false, new PortRangeParser()));
  }

  private ZapDaemon fixtureDaemon() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    when(daemon.startFuzz(any())).thenAnswer(invocation -> {
      ZapDaemon.FuzzSpec spec = invocation.getArgument(0);
      try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), server.port())) {
        socket.setSoTimeout(3000);
        socket.getOutputStream().write(spec.requestMessage().getBytes(StandardCharsets.UTF_8));
        socket.getOutputStream().flush();
        String response = new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(response.startsWith("HTTP/1.1 200"));
      }
      return "receipt";
    });
    when(daemon.fuzzStatus(any())).thenReturn("stopped");
    when(daemon.alerts()).thenReturn(List.of());
    return daemon;
  }

  @Test
  void cartesianCombinesMultipleVariables() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    Map<String, List<String>> multi =
        Map.of("user", List.of("a", "b"), "pass", List.of("x", "y"));
    TrafficFuzzService.FuzzResponse response =
        service.fuzz(
            PACKET_ID,
            new TrafficFuzzService.FuzzRequest(
                7L,
                "POST",
                "http://127.0.0.1:" + server.port() + "/login",
                "",
                "u=\u00a7user\u00a7&p=\u00a7pass\u00a7",
                multi,
                null,
                null,
                "CARTESIAN"));

    assertEquals(4, response.payloadCount()); // 2x2 全组合
    List<String> labels =
        response.results().subList(1, response.results().size()).stream()
            .map(TrafficFuzzService.FuzzHit::payload)
            .toList();
    assertTrue(labels.contains("user=a · pass=x"));
    assertTrue(labels.contains("user=a · pass=y"));
    assertTrue(labels.contains("user=b · pass=x"));
    assertTrue(labels.contains("user=b · pass=y"));
  }

  @Test
  void longestAlignmentRepeatsShortListLastValue() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    Map<String, List<String>> multi =
        Map.of("id", List.of("1", "2", "3"), "k", List.of("only"));
    TrafficFuzzService.FuzzResponse response =
        service.fuzz(
            PACKET_ID,
            new TrafficFuzzService.FuzzRequest(
                7L,
                "GET",
                "http://127.0.0.1:" + server.port() + "/" + "\u00a7id\u00a7" + "?k=" + "\u00a7k\u00a7",
                "",
                "",
                multi,
                null,
                null,
                "LONGEST"));

    assertEquals(3, response.payloadCount()); // 最长列表 = 3
    List<String> labels = response.results().subList(1, response.results().size()).stream()
        .map(TrafficFuzzService.FuzzHit::payload)
        .toList();
    // 最后一轮 id=3 复用 k 的最后值 only
    assertTrue(labels.contains("id=3 · k=only"));
    assertTrue(labels.contains("id=1 · k=only"));
  }

  @Test
  void shortestAlignmentStopsAtShortestList() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    Map<String, List<String>> multi =
        Map.of("id", List.of("1", "2", "3"), "k", List.of("only"));
    TrafficFuzzService.FuzzResponse response =
        service.fuzz(
            PACKET_ID,
            new TrafficFuzzService.FuzzRequest(
                7L,
                "GET",
                "http://127.0.0.1:" + server.port() + "/uniq/" + "\u00a7id\u00a7" + "?k=" + "\u00a7k\u00a7",
                "",
                "",
                multi,
                null,
                null,
                "SHORTEST"));

    assertEquals(1, response.payloadCount()); // 仅最短列表长度
  }

  @Test
  void sniperIteratesEachVariableWithBaseValues() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    Map<String, List<String>> multi = Map.of("user", List.of("admin", "root"));
    TrafficFuzzService.FuzzResponse response =
        service.fuzz(
            PACKET_ID,
            new TrafficFuzzService.FuzzRequest(
                7L,
                "POST",
                "http://127.0.0.1:" + server.port() + "/login",
                "",
                "u=\u00a7user\u00a7&p=\u00a7pass\u00a7",
                multi,
                null,
                null,
                "SNIPER"));

    // 2 个变量位置 x 2 个通用 payload = 4 次请求
    assertEquals(4, response.payloadCount());
    List<String> labels = response.results().subList(1, response.results().size()).stream()
        .map(TrafficFuzzService.FuzzHit::payload)
        .toList();
    assertTrue(labels.contains("user=admin · pass=pass"));
    assertTrue(labels.contains("user=root · pass=pass"));
    assertTrue(labels.contains("user=user · pass=admin"));
    assertTrue(labels.contains("user=user · pass=root"));
  }

  @Test
  void batteringRamInjectsSamePayloadToAllVariables() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    Map<String, List<String>> multi = Map.of("user", List.of("alpha", "beta"));
    TrafficFuzzService.FuzzResponse response =
        service.fuzz(
            PACKET_ID,
            new TrafficFuzzService.FuzzRequest(
                7L,
                "POST",
                "http://127.0.0.1:" + server.port() + "/dual",
                "",
                "field1=\u00a7user\u00a7&field2=\u00a7pass\u00a7",
                multi,
                null,
                null,
                "BATTERING_RAM"));

    // 所有变量在单次迭代中注入相同的值
    assertEquals(2, response.payloadCount());
    List<String> labels = response.results().subList(1, response.results().size()).stream()
        .map(TrafficFuzzService.FuzzHit::payload)
        .toList();
    assertTrue(labels.contains("user=alpha · pass=alpha"));
    assertTrue(labels.contains("user=beta · pass=beta"));
  }

  @Test
  void pitchforkAndClusterBombAliasesWork() throws Exception {
    server = LocalEchoServer.started();
    arrangeSource(0L, server.port());
    Map<String, List<String>> multi =
        Map.of("a", List.of("1", "2"), "b", List.of("x", "y"));

    TrafficFuzzService.FuzzResponse pitchforkResp =
        service.fuzz(
            PACKET_ID,
            new TrafficFuzzService.FuzzRequest(
                7L,
                "GET",
                "http://127.0.0.1:" + server.port() + "/?a=\u00a7a\u00a7&b=\u00a7b\u00a7",
                "",
                "",
                multi,
                null,
                null,
                "PITCHFORK"));
    assertEquals(2, pitchforkResp.payloadCount());

    TrafficFuzzService.FuzzResponse clusterBombResp =
        service.fuzz(
            PACKET_ID,
            new TrafficFuzzService.FuzzRequest(
                7L,
                "GET",
                "http://127.0.0.1:" + server.port() + "/?a=\u00a7a\u00a7&b=\u00a7b\u00a7",
                "",
                "",
                multi,
                null,
                null,
                "CLUSTER_BOMB"));
    assertEquals(4, clusterBombResp.payloadCount());
  }

  private SystemDependenciesResponse zapUnavailable() {
    return new SystemDependenciesResponse(
        "win32",
        "x64",
        "h2",
        List.of(
            new SystemDependenciesResponse.DependencyStatus(
                "OWASP ZAP", "MISSING", "-", "", false, "PROXY_SCANNER", "", null, null)));
  }

  private SystemDependenciesResponse zapAvailable() {
    return new SystemDependenciesResponse(
        "win32",
        "x64",
        "h2",
        List.of(
            new SystemDependenciesResponse.DependencyStatus(
                "OWASP ZAP", "AVAILABLE", "2.17.0", "/zap", false, "PROXY_SCANNER", "ready", null, null)));
  }

  private static final class StubZapDaemon implements ZapDaemon {
    private final boolean ready;

    private StubZapDaemon(boolean ready) {
      this.ready = ready;
    }

    @Override
    public boolean isReady() {
      return ready;
    }

    @Override
    public void start() {}

    @Override
    public void includeInScope(URI target) {}

    @Override
    public String startSpider(URI target) {
      return "";
    }

    @Override
    public int spiderProgress(String taskId) {
      return 100;
    }

    @Override
    public void stopSpider(String taskId) {}

    @Override
    public String startActiveScan(URI target) {
      return "";
    }

    @Override
    public String startActiveScan(URI target, String scanPolicyName) {
      return startActiveScan(target);
    }

    @Override
    public int activeScanProgress(String scanId) {
      return 100;
    }

    @Override
    public void stopActiveScan(String scanId) {}

    @Override
    public String startFuzz(FuzzSpec spec) {
      return "1";
    }

    @Override
    public String fuzzStatus(String fuzzId) {
      return "stopped;number=1";
    }

    @Override
    public List<ZapDaemon.ZapAlert> alerts() {
      return List.of(new ZapDaemon.ZapAlert("http://127.0.0.1:8080/x", "SQLi", "HIGH", "MEDIUM",
          "CWE-89", "reflected", 1));
    }

    @Override
    public void kill() {}

    @Override
    public void close() {}
  }

  private void arrangeSource(Long targetId, int port) {
    TrafficPacket packet = new TrafficPacket();
    packet.setId(PACKET_ID);
    packet.setTargetId(targetId);
    packet.setHost("127.0.0.1");
    packet.setPort(port);
    when(packets.findById(PACKET_ID)).thenReturn(Optional.of(packet));
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setTargetValue("127.0.0.1");
    target.setAllowedPorts(String.valueOf(port));
    when(replayTargets.get(7L)).thenReturn(target);
  }

  private static final class LocalEchoServer implements AutoCloseable {
    private final List<String> requests = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final ServerSocket socket;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();

    private LocalEchoServer() throws IOException {
      socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
      worker.submit(this::serve);
    }

    private static LocalEchoServer started() throws IOException {
      return new LocalEchoServer();
    }

    private int port() {
      return socket.getLocalPort();
    }

    private void serve() {
      while (!socket.isClosed()) {
        try (Socket client = socket.accept()) {
          client.setSoTimeout(5_000);
          byte[] rawHeader = readHeader(client.getInputStream());
          String headers = new String(rawHeader, StandardCharsets.ISO_8859_1);
          int length = contentLength(headers);
          String body =
              new String(client.getInputStream().readNBytes(length), StandardCharsets.UTF_8);
          requests.add(headers + body);
          byte[] payload = ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                  + body.getBytes(StandardCharsets.UTF_8).length
                  + "\r\nConnection: close\r\n\r\n"
                  + body)
              .getBytes(StandardCharsets.UTF_8);
          OutputStream output = client.getOutputStream();
          output.write(payload);
          output.flush();
        } catch (Exception ignored) {
          // server keeps looping until closed
        }
      }
    }

    private int contentLength(String headers) {
      for (String line : headers.split("\r\n")) {
        if (line.regionMatches(true, 0, "Content-Length:", 0, "Content-Length:".length())) {
          return Integer.parseInt(line.substring("Content-Length:".length()).trim());
        }
      }
      return 0;
    }

    private byte[] readHeader(InputStream input) throws IOException {
      ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      int state = 0;
      int value;
      while ((value = input.read()) != -1) {
        bytes.write(value);
        state =
            state == 0 && value == '\r'
                ? 1
                : state == 1 && value == '\n'
                    ? 2
                    : state == 2 && value == '\r' ? 3 : state == 3 && value == '\n' ? 4 : 0;
        if (state == 4) return bytes.toByteArray();
      }
      throw new IOException("request headers ended early");
    }

    @Override
    public void close() throws Exception {
      socket.close();
      worker.shutdownNow();
      worker.awaitTermination(5, TimeUnit.SECONDS);
    }
  }
}
