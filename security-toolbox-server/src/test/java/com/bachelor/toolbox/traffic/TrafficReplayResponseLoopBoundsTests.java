package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
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
 * 发包器响应读取循环的防无界上限——Round 45。
 *
 * <p>背景：{@code readFinalResponseHead} 的 1xx 跳过循环与 chunked trailer 行循环均无迭代上限；
 * SO_TIMEOUT 只在空闲时触发，恶意/异常目标持续发送数据即可造成无界循环（线程挂起/CPU 放大）。
 * 修复后 1xx 连续次数 ≤8、trailer 行数 ≤64，超限中止并返回发包失败。
 */
@DisplayName("发包器响应循环防无界（Round 45）")
class TrafficReplayResponseLoopBoundsTests {
  private static final long PACKET_ID = 41L;
  private static final long TARGET_ID = 73L;

  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final TargetService targets = mock(TargetService.class);
  private final AuditService audit = mock(AuditService.class);
  private final TargetPolicyService policy = new TargetPolicyService(false, new PortRangeParser());
  private final TrafficReplayService service =
      new TrafficReplayService(packets, audit, targets, policy);

  private LoopServer server;

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

  private TrafficReplayService.ReplayRequest req(int port) {
    return new TrafficReplayService.ReplayRequest(
        TARGET_ID, "GET", "http://127.0.0.1:" + port + "/", "", "");
  }

  @Test
  @DisplayName("RL-1 目标连发超过 8 个 1xx → 中止（发包失败），不再等待最终响应")
  void endlessInformationalResponsesAbort() throws Exception {
    StringBuilder raw = new StringBuilder();
    for (int i = 0; i < 12; i++) {
      raw.append("HTTP/1.1 100 Continue\r\nHeader-X: ").append(i).append("\r\n\r\n");
    }
    raw.append("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    server = new LoopServer(raw.toString());
    arrange(server.port());
    assertThatThrownBy(() -> service.replay(PACKET_ID, req(server.port())))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
        .hasMessageContaining("发包失败");
  }

  @Test
  @DisplayName("RL-2 chunked 响应 trailer 行数 >64 → 中止")
  void excessiveChunkTrailersAbort() throws Exception {
    StringBuilder raw = new StringBuilder("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n");
    for (int i = 0; i < 100; i++) {
      raw.append("X-Trailer-").append(i).append(": v\r\n");
    }
    raw.append("\r\n");
    server = new LoopServer(raw.toString());
    arrange(server.port());
    assertThatThrownBy(() -> service.replay(PACKET_ID, req(server.port())))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
        .hasMessageContaining("发包失败");
  }

  @Test
  @DisplayName("RL-3 正常 1xx(≤8) + 最终响应 → 正常完成（不误伤）")
  void boundedInformationalResponsesStillComplete() throws Exception {
    StringBuilder raw = new StringBuilder();
    for (int i = 0; i < 3; i++) {
      raw.append("HTTP/1.1 100 Continue\r\n\r\n");
    }
    raw.append("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    server = new LoopServer(raw.toString());
    arrange(server.port());
    var response = service.replay(PACKET_ID, req(server.port()));
    org.assertj.core.api.Assertions.assertThat(response.statusCode()).isEqualTo(200);
    // 响应体以 base64 返回（"ok" -> "b2s="）
    org.assertj.core.api.Assertions.assertThat(response.responseBody()).contains("b2s=");
  }

  /** 单连接 fixture：读取一次请求后回放配置好的原始响应字节。 */
  private static final class LoopServer implements AutoCloseable {
    private final ServerSocket socket;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final byte[] response;

    LoopServer(String response) throws IOException {
      this.response = response.getBytes(StandardCharsets.ISO_8859_1);
      socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
      worker.submit(this::serve);
    }

    int port() {
      return socket.getLocalPort();
    }

    private void serve() {
      try (Socket client = socket.accept()) {
        InputStream in = client.getInputStream();
        byte[] buf = new byte[8192];
        // 排空请求（读到 EOF 或读完一次请求即可），随后一次性写响应。
        in.read(buf);
        OutputStream out = client.getOutputStream();
        out.write(response);
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
