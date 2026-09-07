package com.bachelor.toolbox.traffic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse;
import com.bachelor.toolbox.tool.zap.ZapDaemon;
import com.bachelor.toolbox.tool.zap.ZapDaemonSupplier;
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
  private final TrafficReplayService replay = new TrafficReplayService(packets, audit);
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
                null,
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
                null,
                "GET",
                "http://127.0.0.1:" + server.port() + "/f?q=" + MARKER,
                "",
                "",
                List.of("boom")));

    assertEquals("LOOP", response.engine());
    assertTrue(response.results().stream().anyMatch(hit -> "boom".equals(hit.payload())));
  }

  @Test
  void usesZapEngineWhenAvailable() {
    DependencyDetectionService detection = mock(DependencyDetectionService.class);
    when(detection.detect(false)).thenReturn(zapAvailable());
    TrafficFuzzService withZap =
        new TrafficFuzzService(null, () -> new StubZapDaemon(true), detection);

    TrafficFuzzService.FuzzResponse response =
        withZap.fuzz(
            PACKET_ID,
            new TrafficFuzzService.FuzzRequest(
                null,
                "GET",
                "http://127.0.0.1:8080/x?q=" + MARKER,
                "",
                "",
                List.of()));

    assertEquals("ZAP", response.engine());
    assertTrue(response.results().stream().anyMatch(hit -> hit.changed()));
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
                null,
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
                null,
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
                null,
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
                null,
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
                null,
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
                null,
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
                null,
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
  }

  private static final class LocalEchoServer implements AutoCloseable {
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