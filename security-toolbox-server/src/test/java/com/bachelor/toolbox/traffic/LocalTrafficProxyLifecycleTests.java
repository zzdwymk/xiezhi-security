package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.test.util.ReflectionTestUtils;

@Timeout(10)
class LocalTrafficProxyLifecycleTests {
  @Test
  void closesBothSidesOfAnHttpRequestWaitingForUpstreamResponse() throws Exception {
    try (ServerSocket server = upstream(); LocalTrafficProxy proxy = proxy(false);
        Socket client = client(proxy)) {
      send(client, "GET http://127.0.0.1:" + server.getLocalPort() + "/slow HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
      try (Socket accepted = server.accept()) {
        accepted.setSoTimeout(2000);
        assertThat(readHeader(accepted.getInputStream())).contains("/slow");
        proxy.close();
        assertClosed(client);
        assertClosed(accepted);
      }
    }
  }

  @Test
  void closesClientAndUpstreamDuringUpstreamTlsHandshake() throws Exception {
    try (ServerSocket server = upstream(); LocalTrafficProxy proxy = proxy(true);
        Socket client = client(proxy)) {
      send(client, "CONNECT 127.0.0.1:" + server.getLocalPort() + " HTTP/1.1\r\nHost: localhost\r\n\r\n");
      try (Socket accepted = server.accept()) {
        accepted.setSoTimeout(2000);
        // The upstream intentionally never answers the TLS ClientHello.
        assertThat(accepted.getInputStream().read()).isEqualTo(22);
        proxy.close();
        assertClosed(client);
        assertClosed(accepted);
      }
    }
  }

  @Test
  void closesEstablishedConnectTunnel() throws Exception {
    try (ServerSocket server = upstream(); LocalTrafficProxy proxy = proxy(false);
        Socket client = client(proxy)) {
      send(client, "CONNECT 127.0.0.1:" + server.getLocalPort() + " HTTP/1.1\r\nHost: localhost\r\n\r\n");
      try (Socket accepted = server.accept()) {
        accepted.setSoTimeout(2000);
        assertThat(readHeader(client.getInputStream())).startsWith("HTTP/1.1 200");
        send(client, "ping");
        assertThat(new String(accepted.getInputStream().readNBytes(4), StandardCharsets.UTF_8)).isEqualTo("ping");
        proxy.close();
        assertClosed(client);
        assertClosed(accepted);
      }
    }
  }

  @Test
  void concurrentAcceptAndCloseDoNotLeaveAcceptedSocketsOpen() throws Exception {
    var clients = new ConcurrentLinkedQueue<Socket>();
    var executor = Executors.newFixedThreadPool(4);
    CountDownLatch connected = new CountDownLatch(8);
    try (LocalTrafficProxy proxy = proxy(false)) {
      int port = port(proxy);
      var attempts = new java.util.ArrayList<java.util.concurrent.Future<?>>();
      for (int thread = 0; thread < 4; thread++) {
        attempts.add(executor.submit(() -> {
          for (int attempt = 0; attempt < 12; attempt++) {
            try {
              Socket socket = new Socket(InetAddress.getLoopbackAddress(), port);
              clients.add(socket);
              connected.countDown();
            } catch (IOException closedListener) {
              // Connections racing with stop may be refused; accepted connections must be closed.
            }
          }
        }));
      }
      assertThat(connected.await(2, TimeUnit.SECONDS)).isTrue();
      proxy.close();
      for (var attempt : attempts) attempt.get(2, TimeUnit.SECONDS);
      assertThat(clients.size()).isGreaterThanOrEqualTo(8);
      for (Socket socket : clients) assertClosed(socket);
      assertThat(executor.isShutdown()).isFalse();
    } finally {
      for (Socket socket : clients) socket.close();
      executor.shutdownNow();
    }
  }

  private static LocalTrafficProxy proxy(boolean mitm) throws Exception {
    MitmCertificateAuthority certificate = mock(MitmCertificateAuthority.class);
    when(certificate.enabled()).thenReturn(mitm);
    LocalTrafficProxy proxy = new LocalTrafficProxy(null, null, certificate, capture -> {});
    proxy.start(0);
    return proxy;
  }

  private static ServerSocket upstream() throws IOException {
    ServerSocket server = new ServerSocket(0, 20, InetAddress.getLoopbackAddress());
    server.setSoTimeout(2000);
    return server;
  }

  private static int port(LocalTrafficProxy proxy) {
    return ((ServerSocket) ReflectionTestUtils.getField(proxy, "server")).getLocalPort();
  }

  private static Socket client(LocalTrafficProxy proxy) throws IOException {
    Socket socket = new Socket(InetAddress.getLoopbackAddress(), port(proxy));
    socket.setSoTimeout(2000);
    return socket;
  }

  private static void send(Socket socket, String text) throws IOException {
    socket.getOutputStream().write(text.getBytes(StandardCharsets.ISO_8859_1));
    socket.getOutputStream().flush();
  }

  private static String readHeader(InputStream input) throws IOException {
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    int value;
    while ((value = input.read()) >= 0) {
      data.write(value);
      if (data.size() >= 4 && data.toString(StandardCharsets.ISO_8859_1).endsWith("\r\n\r\n")) break;
      if (data.size() > 65536) fail("Unexpectedly large test request");
    }
    return data.toString(StandardCharsets.ISO_8859_1);
  }

  private static void assertClosed(Socket socket) throws IOException {
    socket.setSoTimeout(2000);
    try {
      while (socket.getInputStream().read() >= 0) { }
    } catch (SocketException reset) {
      // Both orderly EOF and reset mean the transport really closed. A read timeout fails.
    }
  }
}
