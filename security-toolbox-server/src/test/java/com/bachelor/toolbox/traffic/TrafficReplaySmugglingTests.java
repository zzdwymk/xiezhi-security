package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 请求走私（HTTP Request Smuggling）边界——Round 9 对抗测试。
 *
 * <p>目标：确认发包器不会把可能引发 CL.TE / TE.CL 走私的请求头透传到目标。
 * 每个用例外起一个本地 HTTP 服务器，并记录它实际收到的原始报文——
 * 未走私的请求必须<strong>不</strong>把 Transfer-Encoding / 客户端 Content-Length 透传过去。
 */
class TrafficReplaySmugglingTests {
  private static final long PACKET_ID = 41L;
  private static final long TARGET_ID = 73L;

  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final TargetService targets = mock(TargetService.class);
  private final AuditService audit = mock(AuditService.class);
  private final TargetPolicyService policy = new TargetPolicyService(false, new PortRangeParser());
  private final TrafficReplayService service =
      new TrafficReplayService(packets, audit, targets, policy);

  private LocalServer server;

  @AfterEach
  void close() throws Exception {
    if (server != null) server.close();
  }

  private void arrange(int port) {
    TrafficPacket source = new TrafficPacket();
    source.setId(PACKET_ID);
    source.setHost("127.0.0.1");
    source.setPort(port);
    when(packets.findById(PACKET_ID)).thenReturn(Optional.of(source));
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(TARGET_ID);
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAllowedPorts(String.valueOf(port));
    target.setEnabled(true);
    when(targets.get(TARGET_ID)).thenReturn(target);
  }

  private TrafficReplayService.ReplayRequest req(String method, int port, String headers, String body) {
    return new TrafficReplayService.ReplayRequest(
        TARGET_ID, method, "http://127.0.0.1:" + port + "/", headers, body);
  }

  private ApiException expectRejected(String headers, String fragment) {
    server = null;
    // 用一个极短超时的端口来确保即便走到连接也快速失败；走私判定在连接前。
    arrange(1);
    return (ApiException)
        assertThatThrownBy(() -> service.replay(PACKET_ID, req("POST", 1, headers, "x=1")))
            .isInstanceOf(ApiException.class)
            .hasMessageContaining(fragment)
            .actual();
  }

  @Test
  @DisplayName("SMUG-1 标准 Transfer-Encoding: chunked → 拒绝")
  void rejectsStandardTransferEncoding() {
    expectRejected("Transfer-Encoding: chunked\r\n", "Transfer-Encoding");
  }

  @Test
  @DisplayName("SMUG-2 大小写变体 → 拒绝（小写/全大写都不能绕过 TE 判定）")
  void rejectsCaseVariants() {
    expectRejected("Transfer-Encoding: Chunked\r\n", "Transfer-Encoding");
    expectRejected("TRANSFER-ENCODING: chunked\r\n", "Transfer-Encoding");
  }

  @Test
  @DisplayName("SMUG-2b 下划线变体 Transfer_Encoding 不被当作可透传头（在连接前被拒或被框架再生）")
  void underscoreVariantCannotSmuggle() {
    // 下划线是非标准写法；无论被解析为普通头还是被拒，都不得作为 Transfer-Encoding 透传到目标。
    server = null;
    arrange(1);
    assertThatThrownBy(() -> service.replay(PACKET_ID, req("POST", 1,
        "Transfer_Encoding: chunked\r\n", "x=1")))
        .isInstanceOf(ApiException.class);
  }

  @Test
  @DisplayName("SMUG-3 TE 与 CL 同时出现（CL.TE 经典走私）→ 拒绝")
  void rejectsBothTransferEncodingAndContentLength() {
    expectRejected("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n", "Transfer-Encoding");
  }

  @Test
  @DisplayName("SMUG-4 客户端手动指定 Content-Length → 拒绝")
  void rejectsClientSuppliedContentLength() {
    expectRejected("Content-Length: 999\r\n", "Content-Length");
  }

  @Test
  @DisplayName("SMUG-5 重复 Host 头 → 拒绝（防解析不一致）")
  void rejectsDuplicateHostHeader() {
    // 第一个 Host 经 validateHostHeader 校验通过后被 continue 消耗；第二个进入重复名检测。
    expectRejected("Host: 127.0.0.1:1\r\nHost: 127.0.0.1:1\r\n", "请求头不能重复");
  }

  @Test
  @DisplayName("SMUG-6 重复 Content-Length → 拒绝")
  void rejectsDuplicateContentLength() {
    expectRejected("Content-Length: 1\r\nContent-Length: 2\r\n", "Content-Length");
  }

  @Test
  @DisplayName("SMUG-7 折行请求头（obs-fold）→ 拒绝")
  void rejectsObsFold() {
    expectRejected("X-Test: a\r\n\tb\r\n", "折行");
  }

  @Test
  @DisplayName("SMUG-8 头值含控制字符 → 拒绝")
  void rejectsControlCharInHeaderValue() {
    expectRejected("X-Evil: a\u000b b\r\n", "非法字符");
  }

  @Test
  @DisplayName("SMUG-9 普通合法头被透传，且框架头被严格再生（不发 Transfer-Encoding/客户端CL）")
  void normalHeadersForwardedAndFramingRegenerated() throws Exception {
    server = new LocalServer();
    arrange(server.port());
    service.replay(PACKET_ID, req("POST", server.port(),
        "User-Agent: tester\r\nAccept: */*\r\n", "hello"));
    String raw = server.rawRequest();
    assertThat(raw).contains("User-Agent: tester");
    assertThat(raw.toLowerCase()).doesNotContain("transfer-encoding");
    // 只允许发包器自己追加的一条 Content-Length: 5（请求体 "hello" 长度）
    long clCount = raw.toLowerCase().split("content-length:", -1).length - 1;
    assertThat(clCount).isEqualTo(1);
    assertThat(raw).containsIgnoringCase("Content-Length: 5");
  }

  // ---------------------------------------------------------------- 本地服务器
  private static final class LocalServer implements AutoCloseable {
    private final ServerSocket socket;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private volatile String raw = "";

    LocalServer() throws IOException {
      socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
      worker.submit(this::serve);
    }

    int port() { return socket.getLocalPort(); }
    String rawRequest() throws Exception {
      worker.shutdown();
      worker.awaitTermination(5, TimeUnit.SECONDS);
      return raw;
    }

    private void serve() {
      try (Socket client = socket.accept()) {
        InputStream in = client.getInputStream();
        byte[] buf = new byte[8192];
        int n = in.read(buf);
        raw = n > 0 ? new String(buf, 0, n, StandardCharsets.ISO_8859_1) : "";
        byte[] body = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".getBytes(StandardCharsets.ISO_8859_1);
        OutputStream out = client.getOutputStream();
        out.write(body);
        out.flush();
      } catch (IOException ignored) {
      }
    }

    @Override
    public void close() throws Exception {
      socket.close();
      worker.shutdownNow();
      worker.awaitTermination(5, TimeUnit.SECONDS);
    }
  }
}
