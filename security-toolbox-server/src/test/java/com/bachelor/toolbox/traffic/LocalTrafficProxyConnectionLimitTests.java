package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
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
import java.util.concurrent.Semaphore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * 抓包代理并发连接上限——Round 27。
 *
 * <p>原 cached 线程池每条连接新建线程，无并发上限。修复用信号量对同时处理连接数封顶，
 * 超出即关闭新连接。本测试锁定关键正确性：连接处理完毕后<b>许可必须释放</b>（不泄漏），
 * 否则上限会被逐渐耗尽导致代理最终拒绝一切连接。
 */
@Timeout(15)
class LocalTrafficProxyConnectionLimitTests {

  @Test
  void permitIsReleasedAfterEachRequestCompletes() throws Exception {
    try (ServerSocket upstream = upstream();
        LocalTrafficProxy proxy = proxy();
        Socket client = client(proxy)) {
      Semaphore permits = (Semaphore) ReflectionTestUtils.getField(proxy, "connectionPermits");
      int total = permits.availablePermits();

      send(client,
          "GET http://127.0.0.1:" + upstream.getLocalPort()
              + "/ok HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
      try (Socket accepted = upstream.accept()) {
        accepted.setSoTimeout(2000);
        readHeader(accepted.getInputStream());
        accepted.getOutputStream().write(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"
                .getBytes(StandardCharsets.ISO_8859_1));
        accepted.getOutputStream().flush();
      }
      // 关闭客户端，促使代理处理循环结束
      try {
        client.close();
      } catch (IOException ignored) {
      }
      // 给 handle 的 finally 释放许可留时间
      long deadline = System.currentTimeMillis() + 5000;
      while (permits.availablePermits() < total && System.currentTimeMillis() < deadline) {
        Thread.sleep(50);
      }
      assertThat(permits.availablePermits())
          .as("连接处理完毕后许可必须归还，避免上限被逐渐耗尽")
          .isEqualTo(total);
    }
  }

  @Test
  void concurrencyCapIsBounded() throws Exception {
    try (LocalTrafficProxy proxy = proxy()) {
      Semaphore permits = (Semaphore) ReflectionTestUtils.getField(proxy, "connectionPermits");
      // 上限有限且为正（cached 池已改为受信号量约束的并发连接数）
      assertThat(permits.availablePermits()).isPositive().isLessThanOrEqualTo(128);
    }
  }

  private static LocalTrafficProxy proxy() throws Exception {
    MitmCertificateAuthority certificate = mock(MitmCertificateAuthority.class);
    when(certificate.enabled()).thenReturn(false);
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
      if (data.size() > 65536) throw new IOException("too large");
    }
    return data.toString(StandardCharsets.ISO_8859_1);
  }
}
