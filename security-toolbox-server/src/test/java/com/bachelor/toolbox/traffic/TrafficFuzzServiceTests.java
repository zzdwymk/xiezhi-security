package com.bachelor.toolbox.traffic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
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