package com.bachelor.toolbox.traffic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.ResourceLock;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ResourceLock("javax.net.ssl.SSLContext.default")
class LocalTrafficProxyHttp2Tests {
  private static final String PASSWORD = "http2-proxy-integration-test-password";
  private static final String CLIENT_ERROR_MESSAGE = "代理请求处理失败，请稍后重试";
  private static final Duration TIMEOUT = Duration.ofSeconds(10);

  @TempDir static Path temporaryDirectory;

  private SSLContext originalDefaultContext;
  private MitmCertificateAuthority certificateAuthority;
  private LocalHttpsServer upstream;
  private LocalTrafficProxy proxy;
  private BlockingQueue<LocalTrafficProxy.Capture> captures;
  private int proxyPort;
  private SSLContext clientTlsContext;

  @BeforeAll
  void createCertificateAuthorityAndUpstream() throws Exception {
    originalDefaultContext = SSLContext.getDefault();
    Path caStore = temporaryDirectory.resolve("traffic-http2-mitm-ca.p12");
    certificateAuthority = new MitmCertificateAuthority(true, caStore.toString(), PASSWORD);
    X509Certificate root = loadRootCertificate(caStore);
    clientTlsContext = contextTrusting(root);
    SSLContext.setDefault(clientTlsContext);
    upstream = new LocalHttpsServer(certificateAuthority.serverContext("127.0.0.1"));
  }

  @AfterAll
  void restoreDefaultTlsContext() throws Exception {
    if (upstream != null) upstream.close();
    if (originalDefaultContext != null) SSLContext.setDefault(originalDefaultContext);
  }

  @BeforeEach
  void startProxy() throws Exception {
    captures = new LinkedBlockingQueue<>();
    proxyPort = reservePort();
    proxy =
        new LocalTrafficProxy(
            null,
            new TargetPolicyService(false, new PortRangeParser()),
            certificateAuthority,
            captures::add);
    proxy.start(proxyPort);
  }

  @AfterEach
  void stopProxy() {
    if (proxy != null) proxy.close();
  }

  @Test
  void decryptsConcurrentHttp2GetsAndPostThroughConnect() throws Exception {
    HttpClient client = http2Client();

    String postBody = "{\"token\":\"local-only\",\"value\":42}";
    List<HttpRequest> requests =
        List.of(
            request("/parallel-a").GET().build(),
            request("/parallel-b?value=2").GET().build(),
            request("/submit")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(postBody))
                .build());

    List<CompletableFuture<HttpResponse<String>>> pending =
        requests.stream()
            .map(request -> client.sendAsync(request, HttpResponse.BodyHandlers.ofString()))
            .toList();
    CompletableFuture.allOf(pending.toArray(CompletableFuture[]::new)).get(15, TimeUnit.SECONDS);
    List<HttpResponse<String>> responses = pending.stream().map(CompletableFuture::join).toList();

    for (HttpResponse<String> response : responses) {
      assertEquals(200, response.statusCode());
      assertEquals(HttpClient.Version.HTTP_2, response.version());
    }
    assertTrue(responses.get(0).body().contains("/parallel-a"));
    assertTrue(responses.get(1).body().contains("/parallel-b?value=2"));
    assertTrue(responses.get(2).body().contains("/submit"));
    assertTrue(responses.get(2).body().contains("local-only"));

    List<LocalTrafficProxy.Capture> received = awaitCaptures(3);
    assertEquals(3, received.size());
    for (LocalTrafficProxy.Capture capture : received) {
      assertEquals("HTTP/2", capture.protocol());
      assertEquals("DECRYPTED", capture.captureState());
      assertEquals(200, capture.statusCode());
      assertEquals("127.0.0.1", capture.host());
      assertEquals(upstream.port(), capture.port());
    }
    LocalTrafficProxy.Capture post =
        received.stream()
            .filter(capture -> "POST".equals(capture.method()))
            .findFirst()
            .orElseThrow();
    assertEquals("/submit", post.path());
    assertEquals(postBody, post.requestBody());
    assertEquals(postBody.getBytes(StandardCharsets.UTF_8).length, post.requestBytes());
    assertEquals(1, upstream.countRequestsForPath("/parallel-a"));
    assertEquals(1, upstream.countRequestsForPath("/parallel-b?value=2"));
    assertEquals(1, upstream.countRequestsForPath("/submit"));
  }

  @Test
  void relaysLargeFixedAndChunkedResponsesThroughHttp2FlowControl() throws Exception {
    HttpClient client = http2Client();
    byte[] expected = largeBody();

    HttpResponse<byte[]> fixed =
        client.send(request("/large-fixed").GET().build(), HttpResponse.BodyHandlers.ofByteArray());
    HttpResponse<byte[]> chunked =
        client.send(
            request("/large-chunked").GET().build(), HttpResponse.BodyHandlers.ofByteArray());

    assertEquals(200, fixed.statusCode());
    assertEquals(HttpClient.Version.HTTP_2, fixed.version());
    assertTrue(java.util.Arrays.equals(expected, fixed.body()));
    assertEquals(200, chunked.statusCode());
    assertEquals(HttpClient.Version.HTTP_2, chunked.version());
    assertTrue(java.util.Arrays.equals(expected, chunked.body()));

    List<LocalTrafficProxy.Capture> received = awaitCaptures(2);
    assertEquals(2, received.size());
    for (String path : List.of("/large-fixed", "/large-chunked")) {
      LocalTrafficProxy.Capture capture =
          received.stream()
              .filter(candidate -> path.equals(candidate.path()))
              .findFirst()
              .orElseThrow();
      assertEquals("HTTP/2", capture.protocol());
      assertEquals("DECRYPTED_TRUNCATED", capture.captureState());
      assertEquals(expected.length, capture.responseBytes());
      assertEquals(200, capture.statusCode());
      assertEquals(64 * 1024, capture.responseBody().getBytes(StandardCharsets.UTF_8).length);
    }
  }

  @Test
  void hidesUpstreamFailureDetailsInHttp2ErrorResponse() throws Exception {
    HttpResponse<String> response =
        http2Client()
            .send(
                request("/invalid-content-length").GET().build(),
                HttpResponse.BodyHandlers.ofString());

    assertEquals(502, response.statusCode());
    assertEquals(HttpClient.Version.HTTP_2, response.version());
    assertEquals(CLIENT_ERROR_MESSAGE, response.body());
    assertFalse(response.body().contains("Content-Length"));

    LocalTrafficProxy.Capture capture = awaitCaptures(1).get(0);
    assertEquals("DECRYPT_FAILED", capture.captureState());
    assertEquals("上游返回了无效的响应长度", capture.errorMessage());
    assertEquals(1, upstream.countRequestsForPath("/invalid-content-length"));
  }

  @Test
  void recordsAUsefulCauseWhenUpstreamClosesWithoutAResponse() throws Exception {
    HttpResponse<String> response =
        http2Client()
            .send(request("/close-without-response").GET().build(), HttpResponse.BodyHandlers.ofString());

    assertEquals(502, response.statusCode());
    assertEquals(CLIENT_ERROR_MESSAGE, response.body());

    LocalTrafficProxy.Capture capture = awaitCaptures(1).get(0);
    assertEquals("DECRYPT_FAILED", capture.captureState());
    assertEquals(
        "上游 HTTPS 服务未返回响应，可能不支持 HTTP/1.1 或已关闭连接", capture.errorMessage());
  }

  private HttpClient http2Client() {
    return HttpClient.newBuilder()
        .sslContext(clientTlsContext)
        .proxy(ProxySelector.of(new InetSocketAddress(InetAddress.getLoopbackAddress(), proxyPort)))
        .version(HttpClient.Version.HTTP_2)
        .connectTimeout(TIMEOUT)
        .build();
  }

  private static byte[] largeBody() {
    byte[] body = new byte[320 * 1024];
    byte[] pattern = "0123456789abcdefghijklmnopqrstuvwxyz\n".getBytes(StandardCharsets.UTF_8);
    for (int offset = 0; offset < body.length; offset++) {
      body[offset] = pattern[offset % pattern.length];
    }
    return body;
  }

  private HttpRequest.Builder request(String path) {
    return HttpRequest.newBuilder(URI.create("https://127.0.0.1:" + upstream.port() + path))
        .timeout(TIMEOUT);
  }

  private List<LocalTrafficProxy.Capture> awaitCaptures(int count) throws Exception {
    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    List<LocalTrafficProxy.Capture> result = new ArrayList<>();
    while (result.size() < count && System.nanoTime() < deadline) {
      long remaining = Math.max(1, deadline - System.nanoTime());
      LocalTrafficProxy.Capture capture = captures.poll(remaining, TimeUnit.NANOSECONDS);
      if (capture == null) break;
      if ("HTTP/2".equals(capture.protocol())) result.add(capture);
    }
    return result;
  }

  private X509Certificate loadRootCertificate(Path storePath) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (InputStream input = Files.newInputStream(storePath)) {
      store.load(input, PASSWORD.toCharArray());
    }
    return (X509Certificate) store.getCertificate("traffic-mitm-root");
  }

  private SSLContext contextTrusting(X509Certificate certificate) throws Exception {
    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("trusted-test-ca", certificate);
    TrustManagerFactory trustManagers =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagers.init(trustStore);
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, trustManagers.getTrustManagers(), null);
    return context;
  }

  private int reservePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      return socket.getLocalPort();
    }
  }

  private static byte[] readHeader(InputStream input) throws IOException {
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
      if (state == 4) break;
    }
    return bytes.toByteArray();
  }

  private static final class LocalHttpsServer implements AutoCloseable {
    private final SSLServerSocket server;
    private final ExecutorService acceptor = Executors.newSingleThreadExecutor();
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private final BlockingQueue<ReceivedRequest> requests = new LinkedBlockingQueue<>();
    private volatile boolean running = true;

    private LocalHttpsServer(SSLContext context) throws Exception {
      server =
          (SSLServerSocket)
              context
                  .getServerSocketFactory()
                  .createServerSocket(0, 20, InetAddress.getLoopbackAddress());
      acceptor.submit(this::acceptLoop);
    }

    private int port() {
      return server.getLocalPort();
    }

    private int countRequestsForPath(String path) {
      return (int) requests.stream().filter(request -> path.equals(request.path())).count();
    }

    private void acceptLoop() {
      while (running) {
        try {
          SSLSocket socket = (SSLSocket) server.accept();
          workers.submit(() -> handleSafely(socket));
        } catch (Exception ignored) {
          // Closing the server socket wakes the accept loop.
        }
      }
    }

    private void handleSafely(SSLSocket socket) {
      try (socket) {
        socket.setUseClientMode(false);
        socket.setSoTimeout(10_000);
        socket.startHandshake();
        byte[] rawHeaders = readHeader(socket.getInputStream());
        if (rawHeaders.length == 0) return;
        String headers = new String(rawHeaders, StandardCharsets.ISO_8859_1);
        String[] requestLine = headers.split("\r\n", 2)[0].split(" ", 3);
        int contentLength = contentLength(headers);
        String body =
            new String(socket.getInputStream().readNBytes(contentLength), StandardCharsets.UTF_8);
        ReceivedRequest request = new ReceivedRequest(requestLine[0], requestLine[1], body);
        requests.add(request);

        if (request.path().equals("/invalid-content-length")) {
          OutputStream output = socket.getOutputStream();
          output.write(
              ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                      + "Content-Length: SECRET_INTERNAL_DETAIL\r\nConnection: close\r\n\r\n")
                  .getBytes(StandardCharsets.ISO_8859_1));
          output.flush();
          return;
        }

        if (request.path().equals("/close-without-response")) return;

        if (request.path().equals("/large-fixed") || request.path().equals("/large-chunked")) {
          writeLargeResponse(socket.getOutputStream(), request.path().equals("/large-chunked"));
          return;
        }

        String responseBody =
            "{\"method\":\""
                + request.method()
                + "\",\"path\":\""
                + request.path()
                + "\",\"body\":\""
                + jsonEscape(request.body())
                + "\"}";
        byte[] encoded = responseBody.getBytes(StandardCharsets.UTF_8);
        OutputStream output = socket.getOutputStream();
        output.write(
            ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + encoded.length
                    + "\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
        output.write(encoded);
        output.flush();
      } catch (Exception ignored) {
        // Tests assert successful requests through received-request and capture queues.
      }
    }

    private void writeLargeResponse(OutputStream output, boolean chunked) throws IOException {
      byte[] body = largeBody();
      if (!chunked) {
        output.write(
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "
                    + body.length
                    + "\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
        output.write(body);
      } else {
        output.write(
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                    + "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
        int offset = 0;
        while (offset < body.length) {
          int length = Math.min(7_919, body.length - offset);
          output.write(
              (Integer.toHexString(length) + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
          output.write(body, offset, length);
          output.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
          offset += length;
        }
        output.write("0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
      }
      output.flush();
    }

    private int contentLength(String headers) {
      for (String line : headers.split("\r\n")) {
        if (line.regionMatches(true, 0, "Content-Length:", 0, "Content-Length:".length())) {
          return Integer.parseInt(line.substring("Content-Length:".length()).trim());
        }
      }
      return 0;
    }

    private String jsonEscape(String value) {
      return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Override
    public void close() throws Exception {
      running = false;
      server.close();
      acceptor.shutdownNow();
      workers.shutdownNow();
      acceptor.awaitTermination(5, TimeUnit.SECONDS);
      workers.awaitTermination(5, TimeUnit.SECONDS);
    }
  }

  private record ReceivedRequest(String method, String path, String body) {}
}
