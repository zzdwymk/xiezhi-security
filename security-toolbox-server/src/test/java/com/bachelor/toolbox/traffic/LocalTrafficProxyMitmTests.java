package com.bachelor.toolbox.traffic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
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
class LocalTrafficProxyMitmTests {
  private static final String PASSWORD = "proxy-integration-test-password";
  private static final String CLIENT_ERROR_MESSAGE = "代理请求处理失败，请稍后重试";
  private static final Duration CAPTURE_TIMEOUT = Duration.ofSeconds(5);

  @TempDir static Path temporaryDirectory;

  private SSLContext originalDefaultContext;
  private MitmCertificateAuthority certificateAuthority;
  private LocalHttpsServer upstream;
  private LocalTrafficProxy proxy;
  private BlockingQueue<LocalTrafficProxy.Capture> captures;
  private int proxyPort;

  @BeforeAll
  void createCertificateAuthorityAndTrustItForUpstreamTls() throws Exception {
    originalDefaultContext = SSLContext.getDefault();
    Path caStore = temporaryDirectory.resolve("traffic-mitm-ca.p12");
    certificateAuthority = new MitmCertificateAuthority(true, caStore.toString(), PASSWORD);
    X509Certificate root = loadRootCertificate(caStore);
    SSLContext.setDefault(contextTrusting(root));
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
  void decryptsAndCapturesHttpsGetAndPost() throws Exception {
    String getResponse =
        exchange(
            contextTrusting(loadRootCertificate(temporaryDirectory.resolve("traffic-mitm-ca.p12"))),
            "GET /hello?name=mitm HTTP/1.1\r\n"
                + hostHeader()
                + "\r\n"
                + "Accept: application/json\r\nConnection: close\r\n\r\n");

    assertTrue(getResponse.startsWith("HTTP/1.1 200"));
    assertTrue(
        getResponse.endsWith("{\"method\":\"GET\",\"path\":\"/hello?name=mitm\",\"body\":\"\"}"));
    LocalTrafficProxy.Capture getCapture = awaitCapture("GET");
    assertEquals("HTTPS", getCapture.protocol());
    assertEquals("DECRYPTED", getCapture.captureState());
    assertEquals("/hello?name=mitm", getCapture.path());
    assertEquals(200, getCapture.statusCode());
    assertEquals("", getCapture.requestBody());

    String requestBody = "{\"token\":\"local-only\",\"value\":42}";
    String postResponse =
        exchange(
            contextTrusting(loadRootCertificate(temporaryDirectory.resolve("traffic-mitm-ca.p12"))),
            "POST /submit HTTP/1.1\r\n"
                + hostHeader()
                + "\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: "
                + requestBody.getBytes(StandardCharsets.UTF_8).length
                + "\r\n"
                + "Connection: close\r\n\r\n"
                + requestBody);

    assertTrue(postResponse.startsWith("HTTP/1.1 200"));
    assertTrue(postResponse.contains("\"path\":\"/submit\""));
    LocalTrafficProxy.Capture postCapture = awaitCapture("POST");
    assertEquals("HTTPS", postCapture.protocol());
    assertEquals("DECRYPTED", postCapture.captureState());
    assertEquals("/submit", postCapture.path());
    assertEquals(requestBody, postCapture.requestBody());
    assertEquals(requestBody.getBytes(StandardCharsets.UTF_8).length, postCapture.requestBytes());
    assertTrue(postCapture.responseBody().contains("\"method\":\"POST\""));
  }

  @Test
  void clientThatDoesNotTrustTheLocalCaCannotCompleteTlsHandshake() throws Exception {
    try (Socket tunnel = openConnectTunnel()) {
      SSLContext untrusted = contextWithEmptyTrustStore();
      try (SSLSocket tls = wrapClient(tunnel, untrusted)) {
        assertThrows(SSLException.class, tls::startHandshake);
      }
    }

    LocalTrafficProxy.Capture capture = awaitCapture("CONNECT");
    assertEquals("TLS_CLIENT_REJECTED", capture.captureState());
    assertEquals("https", capture.scheme());
    assertEquals(CLIENT_ERROR_MESSAGE, capture.errorMessage());
  }

  @Test
  void rejectsADecryptedHostThatDiffersFromTheConnectAuthority() throws Exception {
    SSLContext clientContext =
        contextTrusting(loadRootCertificate(temporaryDirectory.resolve("traffic-mitm-ca.p12")));
    String response =
        exchange(
            clientContext,
            "GET /outside-boundary HTTP/1.1\r\n"
                + "Host: localhost:"
                + upstream.port()
                + "\r\n"
                + "Connection: close\r\n\r\n");

    assertTrue(response.startsWith("HTTP/1.1 403 \r\n"), response);
    assertEquals(CLIENT_ERROR_MESSAGE, responseBody(response));
    assertFalse(response.contains("Proxy Error"), response);
    assertFalse(response.contains("Host 必须与 CONNECT 目标一致"), response);
    LocalTrafficProxy.Capture capture = awaitCapture("GET");
    assertEquals("HTTPS", capture.protocol());
    assertEquals("UNSUPPORTED", capture.captureState());
    assertEquals(CLIENT_ERROR_MESSAGE, capture.errorMessage());
    assertEquals("127.0.0.1", capture.host());
    assertEquals(upstream.port(), capture.port());
    assertEquals(0, upstream.countRequestsForPath("/outside-boundary"));
  }

  @Test
  void hidesInternalExceptionDetailsInPlainHttpErrorResponse() throws Exception {
    String internalDetail = "SECRET_INTERNAL_DETAIL";
    String response =
        plainExchange(
            "GET http://127.0.0.1/%"
                + internalDetail
                + " HTTP/1.1\r\n"
                + "Host: 127.0.0.1\r\nConnection: close\r\n\r\n");

    assertTrue(response.startsWith("HTTP/1.1 502 \r\n"), response);
    assertEquals(CLIENT_ERROR_MESSAGE, responseBody(response));
    assertFalse(response.contains(internalDetail), response);
    assertFalse(response.contains("Proxy Error"), response);
  }

  private String exchange(SSLContext clientContext, String request) throws Exception {
    try (Socket tunnel = openConnectTunnel();
        SSLSocket tls = wrapClient(tunnel, clientContext)) {
      tls.startHandshake();
      tls.getOutputStream().write(request.getBytes(StandardCharsets.UTF_8));
      tls.getOutputStream().flush();
      return new String(tls.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private String plainExchange(String request) throws Exception {
    try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), proxyPort)) {
      socket.setSoTimeout(5_000);
      socket.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
      socket.getOutputStream().flush();
      return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private String responseBody(String response) {
    int separator = response.indexOf("\r\n\r\n");
    assertTrue(separator >= 0, response);
    return response.substring(separator + 4);
  }

  private Socket openConnectTunnel() throws Exception {
    Socket socket = new Socket(InetAddress.getLoopbackAddress(), proxyPort);
    socket.setSoTimeout(5_000);
    OutputStream output = socket.getOutputStream();
    output.write(
        ("CONNECT 127.0.0.1:"
                + upstream.port()
                + " HTTP/1.1\r\n"
                + "Host: 127.0.0.1:"
                + upstream.port()
                + "\r\n"
                + "Proxy-Connection: keep-alive\r\n\r\n")
            .getBytes(StandardCharsets.ISO_8859_1));
    output.flush();
    String response = new String(readHeader(socket.getInputStream()), StandardCharsets.ISO_8859_1);
    assertTrue(response.startsWith("HTTP/1.1 200 Connection Established"), response);
    return socket;
  }

  private SSLSocket wrapClient(Socket tunnel, SSLContext context) throws Exception {
    SSLSocket tls =
        (SSLSocket)
            context.getSocketFactory().createSocket(tunnel, "127.0.0.1", upstream.port(), true);
    tls.setUseClientMode(true);
    tls.setSoTimeout(5_000);
    SSLParameters parameters = tls.getSSLParameters();
    parameters.setEndpointIdentificationAlgorithm("HTTPS");
    parameters.setApplicationProtocols(new String[] {"http/1.1"});
    tls.setSSLParameters(parameters);
    return tls;
  }

  private String hostHeader() {
    return "Host: 127.0.0.1:" + upstream.port();
  }

  private LocalTrafficProxy.Capture awaitCapture(String method) throws Exception {
    long deadline = System.nanoTime() + CAPTURE_TIMEOUT.toNanos();
    LocalTrafficProxy.Capture capture;
    while ((capture =
            captures.poll(
                Math.max(1, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())),
                TimeUnit.MILLISECONDS))
        != null) {
      if (method.equals(capture.method())) return capture;
      if (System.nanoTime() >= deadline) break;
    }
    throw new AssertionError("Timed out waiting for capture method " + method);
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
    return contextWithTrustStore(trustStore);
  }

  private SSLContext contextWithEmptyTrustStore() throws Exception {
    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    return contextWithTrustStore(trustStore);
  }

  private SSLContext contextWithTrustStore(KeyStore trustStore) throws Exception {
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
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final BlockingQueue<ReceivedRequest> requests = new LinkedBlockingQueue<>();
    private volatile boolean running = true;

    private LocalHttpsServer(SSLContext context) throws Exception {
      server =
          (SSLServerSocket)
              context
                  .getServerSocketFactory()
                  .createServerSocket(0, 20, InetAddress.getLoopbackAddress());
      worker.submit(this::acceptLoop);
    }

    private int port() {
      return server.getLocalPort();
    }

    private int countRequestsForPath(String path) {
      return (int) requests.stream().filter(request -> path.equals(request.path())).count();
    }

    private void acceptLoop() {
      while (running) {
        try (SSLSocket socket = (SSLSocket) server.accept()) {
          socket.setUseClientMode(false);
          socket.setSoTimeout(5_000);
          socket.startHandshake();
          handle(socket);
        } catch (Exception ignored) {
          // Rejected client handshakes and proxy-side early closes are expected in negative tests.
        }
      }
    }

    private void handle(SSLSocket socket) throws Exception {
      byte[] rawHeaders = readHeader(socket.getInputStream());
      if (rawHeaders.length == 0) return;
      String headers = new String(rawHeaders, StandardCharsets.ISO_8859_1);
      String firstLine = headers.split("\r\n", 2)[0];
      String[] requestLine = firstLine.split(" ", 3);
      int contentLength = contentLength(headers);
      String body =
          new String(socket.getInputStream().readNBytes(contentLength), StandardCharsets.UTF_8);
      ReceivedRequest request = new ReceivedRequest(requestLine[0], requestLine[1], body);
      requests.add(request);

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
      worker.shutdownNow();
      worker.awaitTermination(5, TimeUnit.SECONDS);
    }
  }

  private record ReceivedRequest(String method, String path, String body) {}
}
