package com.bachelor.toolbox.traffic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class TrafficReplayServiceTests {
  private static final long PACKET_ID = 41L;
  private static final long TARGET_ID = 73L;

  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final TargetService targets = mock(TargetService.class);
  private final AuditService audit = mock(AuditService.class);
  private final TargetPolicyService policy = new TargetPolicyService(false, new PortRangeParser());
  private final TrafficReplayService service = new TrafficReplayService(packets, audit);

  private LocalHttpServer server;

  @AfterEach
  void closeServer() throws Exception {
    if (server != null) server.close();
  }

  @Test
  void replaysGenericPacketToMatchingTargetAndReadsFixedLengthGetResponse() throws Exception {
    server = LocalHttpServer.fixed("fixed-ok");
    arrangeSourceAndTarget(0L, TARGET_ID, server.port());

    TrafficReplayService.ReplayResponse response =
        service.replay(
            PACKET_ID,
            request(
                TARGET_ID,
                "GET",
                url(server.port(), "/hello?name=replay"),
                "GET /old HTTP/1.1\r\nAccept: text/plain\r\n",
                null));

    ReceivedRequest received = server.received();
    assertEquals("GET", received.method());
    assertEquals("/hello?name=replay", received.path());
    assertEquals("", received.body());
    assertEquals("127.0.0.1:" + server.port(), received.header("Host"));
    assertEquals("close", received.header("Connection"));
    assertEquals("text/plain", received.header("Accept"));

    assertEquals(200, response.statusCode());
    assertEquals("fixed-ok", response.responseBody());
    assertEquals("TEXT", response.bodyEncoding());
    assertEquals(8, response.responseBytes());
    assertFalse(response.truncated());
    verify(audit)
        .record(
            "REPLAY_TRAFFIC_PACKET",
            "TRAFFIC_PACKET",
            PACKET_ID,
            "replayOnly,method=GET,host=127.0.0.1,port=" + server.port() + ",status=200",
            "SUCCESS");
  }

  @Test
  void replaysPostBodyAndReadsChunkedResponseWhileRegeneratingFramingHeaders() throws Exception {
    server = LocalHttpServer.chunked("chunk-ed");
    arrangeSourceAndTarget(TARGET_ID, TARGET_ID, server.port());
    String body = "{\"value\":42}";

    TrafficReplayService.ReplayResponse response =
        service.replay(
            PACKET_ID,
            request(
                TARGET_ID,
                "POST",
                url(server.port(), "/submit"),
                "Host: 127.0.0.1:"
                    + server.port()
                    + "\r\n"
                    + "Content-Type: application/json\r\n"
                    + "Content-Length: 999\r\n"
                    + "Connection: keep-alive\r\n",
                body));

    ReceivedRequest received = server.received();
    assertEquals("POST", received.method());
    assertEquals("/submit", received.path());
    assertEquals(body, received.body());
    assertEquals(
        String.valueOf(body.getBytes(StandardCharsets.UTF_8).length),
        received.header("Content-Length"));
    assertEquals("close", received.header("Connection"));
    assertEquals("application/json", received.header("Content-Type"));

    assertEquals(201, response.statusCode());
    assertEquals("Created", response.reasonPhrase());
    assertEquals("chunk-ed", response.responseBody());
    assertEquals(8, response.responseBytes());
    assertFalse(response.truncated());
  }

  @Test
  void rejectsSwitchingAnAlreadyBoundPacketToAnotherTarget() {
    TrafficPacket source = sourcePacket(22L, "127.0.0.1", 8080);
    when(packets.findById(PACKET_ID)).thenReturn(Optional.of(source));

    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                service.replay(PACKET_ID, request(23L, "GET", "http://127.0.0.1:8080/", "", null)));

    assertTrue(error.getMessage().contains("不允许切换"));
    verifyNoInteractions(targets);
  }

  @Test
  void rejectsUrlHostOutsideSourceAndAuthorizedTarget() {
    arrangeSourceAndTarget(0L, TARGET_ID, 8080);

    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                service.replay(
                    PACKET_ID,
                    request(TARGET_ID, "GET", "http://localhost:8080/outside", "", null)));

    assertTrue(error.getMessage().contains("主机必须与源流量及授权目标一致"));
  }

  @Test
  void allowsReplayToAnotherPortOnTheSameCapturedHost() throws Exception {
    server = LocalHttpServer.fixed("port-ok");
    arrangeSourceAndTarget(0L, TARGET_ID, 8080);

    TrafficReplayService.ReplayResponse response =
        service.replay(
            PACKET_ID, request(TARGET_ID, "GET", url(server.port(), "/another-port"), "", null));

    assertEquals(200, response.statusCode());
    assertEquals("port-ok", response.responseBody());
  }

  @Test
  void allowsRedactedTextAsARegularLiteralValue() throws Exception {
    server = LocalHttpServer.fixed("ok");
    arrangeSourceAndTarget(0L, TARGET_ID, server.port());

    service.replay(
        PACKET_ID,
        request(
            TARGET_ID,
            "POST",
            url(server.port(), "/literal"),
            "Authorization: [REDACTED]",
            "token=[redacted]"));

    ReceivedRequest received = server.received();
    assertEquals("[REDACTED]", received.header("Authorization"));
    assertEquals("token=[redacted]", received.body());
  }

  @Test
  void rejectsMismatchedHostHeaderAndTransferEncoding() {
    arrangeSourceAndTarget(0L, TARGET_ID, 8080);

    ApiException hostError =
        assertThrows(
            ApiException.class,
            () ->
                service.replay(
                    PACKET_ID,
                    request(
                        TARGET_ID, "GET", "http://127.0.0.1:8080/", "Host: localhost:8080", null)));
    ApiException transferError =
        assertThrows(
            ApiException.class,
            () ->
                service.replay(
                    PACKET_ID,
                    request(
                        TARGET_ID,
                        "POST",
                        "http://127.0.0.1:8080/",
                        "Transfer-Encoding: chunked",
                        "hello")));

    assertTrue(hostError.getMessage().contains("Host 请求头必须与发包 URL 一致"));
    assertTrue(transferError.getMessage().contains("不支持请求头 Transfer-Encoding"));
  }

  @Test
  void hidesNetworkFailureDetailsFromTheResponse() {
    String unavailableHost = "unavailable.invalid";
    when(packets.findById(PACKET_ID))
        .thenReturn(Optional.of(sourcePacket(0L, unavailableHost, 80)));

    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                service.replay(
                    PACKET_ID,
                    request(TARGET_ID, "GET", "http://" + unavailableHost + "/", "", null)));

    assertEquals("发包失败，请检查目标连接与服务日志", error.getMessage());
    assertFalse(error.getMessage().contains(unavailableHost));
  }

  @Test
  void exposesReplayEndpointAndSerializesTheServiceResponse() throws Exception {
    TrafficProxyService proxy = mock(TrafficProxyService.class);
    TrafficAnalysisService analysis = mock(TrafficAnalysisService.class);
    TrafficReplayService replay = mock(TrafficReplayService.class);
    TrafficProxyController controller =
        new TrafficProxyController(
            proxy,
            analysis,
            replay,
            mock(TrafficCaptureFilterService.class),
            mock(TrafficAiChatService.class));
    MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    when(replay.replay(
            org.mockito.ArgumentMatchers.eq(PACKET_ID), org.mockito.ArgumentMatchers.any()))
        .thenReturn(
            new TrafficReplayService.ReplayResponse(
                PACKET_ID,
                "HTTP/1.1",
                "GET",
                "http://127.0.0.1:8080/",
                200,
                "OK",
                "Content-Type: text/plain",
                "ok",
                "TEXT",
                "text/plain",
                2,
                3,
                false));

    mockMvc
        .perform(
            post("/api/traffic/packets/{id}/replay", PACKET_ID)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"targetId\":73,\"method\":\"GET\","
                        + "\"url\":\"http://127.0.0.1:8080/\",\"headers\":\"\",\"body\":\"\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sourcePacketId").value(PACKET_ID))
        .andExpect(jsonPath("$.statusCode").value(200))
        .andExpect(jsonPath("$.responseBody").value("ok"));
  }

  @Test
  void truncatesOversizedFixedLengthResponsePreviewButReportsDeclaredResponseBytes()
      throws Exception {
    int previewLimit = 4 * 1024 * 1024;
    String oversized = "x".repeat(previewLimit + 17);
    server = LocalHttpServer.fixed(oversized);
    arrangeSourceAndTarget(0L, TARGET_ID, server.port());

    TrafficReplayService.ReplayResponse response =
        service.replay(
            PACKET_ID, request(TARGET_ID, "GET", url(server.port(), "/large"), "", null));

    assertTrue(response.truncated());
    assertEquals(previewLimit + 17L, response.responseBytes());
    assertEquals(previewLimit, response.responseBody().length());
  }

  private void arrangeSourceAndTarget(Long sourceTargetId, Long selectedTargetId, int allowedPort) {
    when(packets.findById(PACKET_ID))
        .thenReturn(Optional.of(sourcePacket(sourceTargetId, "127.0.0.1", allowedPort)));
    when(targets.get(selectedTargetId))
        .thenReturn(target(selectedTargetId, "127.0.0.1", allowedPort));
  }

  private TrafficPacket sourcePacket(Long targetId, String host, int port) {
    TrafficPacket packet = new TrafficPacket();
    packet.setId(PACKET_ID);
    packet.setTargetId(targetId);
    packet.setHost(host);
    packet.setPort(port);
    return packet;
  }

  private AuthorizedTarget target(Long id, String host, int allowedPort) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(id);
    target.setName("local-test");
    target.setTargetValue(host);
    target.setTargetType("IP");
    target.setAuthorizationNote("local test authorization");
    target.setAllowedPorts(String.valueOf(allowedPort));
    target.setEnabled(true);
    return target;
  }

  private TrafficReplayService.ReplayRequest request(
      Long targetId, String method, String url, String headers, String body) {
    return new TrafficReplayService.ReplayRequest(targetId, method, url, headers, body);
  }

  private String url(int port, String path) {
    return "http://127.0.0.1:" + port + path;
  }

  private static final class LocalHttpServer implements AutoCloseable {
    private final ServerSocket socket;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final CompletableFuture<ReceivedRequest> request = new CompletableFuture<>();
    private final byte[] response;

    private LocalHttpServer(byte[] response) throws IOException {
      this.response = response;
      this.socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
      worker.submit(this::serve);
    }

    private static LocalHttpServer fixed(String body) throws IOException {
      byte[] encoded = body.getBytes(StandardCharsets.UTF_8);
      return new LocalHttpServer(
          ("HTTP/1.1 200 OK\r\n"
                  + "Content-Type: text/plain; charset=utf-8\r\n"
                  + "Content-Length: "
                  + encoded.length
                  + "\r\n"
                  + "Connection: close\r\n\r\n"
                  + body)
              .getBytes(StandardCharsets.UTF_8));
    }

    private static LocalHttpServer chunked(String body) throws IOException {
      byte[] encoded = body.getBytes(StandardCharsets.UTF_8);
      String chunks =
          Integer.toHexString(5)
              + "\r\n"
              + body.substring(0, 5)
              + "\r\n"
              + Integer.toHexString(encoded.length - 5)
              + "\r\n"
              + body.substring(5)
              + "\r\n"
              + "0\r\nX-Test-Trailer: complete\r\n\r\n";
      return new LocalHttpServer(
          ("HTTP/1.1 201 Created\r\n"
                  + "Content-Type: text/plain\r\n"
                  + "Transfer-Encoding: chunked\r\n"
                  + "Connection: close\r\n\r\n"
                  + chunks)
              .getBytes(StandardCharsets.UTF_8));
    }

    private int port() {
      return socket.getLocalPort();
    }

    private ReceivedRequest received() throws Exception {
      return request.get(5, TimeUnit.SECONDS);
    }

    private void serve() {
      try (Socket client = socket.accept()) {
        client.setSoTimeout(5_000);
        byte[] rawHeader = readHeader(client.getInputStream());
        String headers = new String(rawHeader, StandardCharsets.ISO_8859_1);
        String[] requestLine = headers.split("\r\n", 2)[0].split(" ", 3);
        int length = contentLength(headers);
        String body =
            new String(client.getInputStream().readNBytes(length), StandardCharsets.UTF_8);
        request.complete(new ReceivedRequest(requestLine[0], requestLine[1], headers, body));
        OutputStream output = client.getOutputStream();
        output.write(response);
        output.flush();
      } catch (Exception ex) {
        request.completeExceptionally(ex);
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

  private record ReceivedRequest(String method, String path, String rawHeaders, String body) {
    private String header(String name) {
      for (String line : rawHeaders.split("\r\n")) {
        int separator = line.indexOf(':');
        if (separator > 0 && line.substring(0, separator).equalsIgnoreCase(name)) {
          return line.substring(separator + 1).trim();
        }
      }
      return null;
    }
  }
}
