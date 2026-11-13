package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 抓包代理会话报文保留上限——Round 23。
 *
 * <p>原 {@code persistCapture} 每次捕获都无条件落库、无保留上限：代理长时间运行对活跃目标持续
 * 累积报文行（含请求/响应体快照）最终耗尽磁盘。修复后每会话最多保留 MAX_PACKETS_PER_SESSION 条，
 * 超出淘汰最旧（未标记）。本类以反射锁定 {@code evictBeyondRetention} 的淘汰行为。
 */
@DisplayName("抓包代理会话保留上限（Round 23）")
class TrafficProxyRetentionTests {
  private final TrafficSessionRepository sessions = mock(TrafficSessionRepository.class);
  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final TrafficSuggestionRepository suggestions = mock(TrafficSuggestionRepository.class);

  private TrafficProxyService service() {
    return new TrafficProxyService(
        sessions,
        packets,
        suggestions,
        mock(TrafficAnalysisService.class),
        mock(com.bachelor.toolbox.target.TargetService.class),
        mock(com.bachelor.toolbox.target.TargetPolicyService.class),
        mock(TrafficCaptureFilterService.class),
        mock(com.bachelor.toolbox.audit.AuditService.class),
        mock(MitmCertificateAuthority.class),
        mock(TrafficAssetSyncService.class),
        mock(org.springframework.transaction.PlatformTransactionManager.class));
  }

  private long invokeEvict(TrafficProxyService svc, Long sessionId) throws Exception {
    Method m = TrafficProxyService.class.getDeclaredMethod("evictBeyondRetention", Long.class);
    m.setAccessible(true);
    return (long) m.invoke(svc, sessionId);
  }

  private static TrafficPacket packet(long id, boolean marked) {
    TrafficPacket p = new TrafficPacket();
    p.setId(id);
    p.setMarked(marked);
    return p;
  }

  @Test
  @DisplayName("RET-1 会话报文数未超上限 → 不淘汰")
  void underCapNoEviction() throws Exception {
    TrafficProxyService svc = service();
    when(packets.countBySessionId(1L)).thenReturn(100L);
    assertThat(invokeEvict(svc, 1L)).isZero();
    verify(packets, never()).deleteAllInBatch(any());
  }

  @Test
  @DisplayName("RET-2 超上限 → 淘汰最旧未标记报文")
  void overCapEvictsOldestUnmarked() throws Exception {
    TrafficProxyService svc = service();
    when(packets.countBySessionId(1L)).thenReturn(5_010L); // 超 MAX 5000 共 10 条
    // 返回最旧的 10 条，其中 2 条 marked（不淘汰）
    List<TrafficPacket> oldest =
        List.of(packet(1L, false), packet(2L, false), packet(3L, true), packet(4L, false),
            packet(5L, false), packet(6L, true), packet(7L, false), packet(8L, false),
            packet(9L, false), packet(10L, false));
    when(packets.findAllBySessionIdOrderByIdAsc(eq(1L), any())).thenReturn(oldest);

    long evicted = invokeEvict(svc, 1L);
    // 10 条中最旧里有 8 条未标记 → 淘汰 8
    assertThat(evicted).isEqualTo(8);
    verify(packets).deleteAllInBatch(any());
    verify(packets).flush();
  }
}
