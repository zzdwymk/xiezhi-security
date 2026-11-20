package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * Round 226：流量扫描 SSE 端点必须限制同时运行的流式扫描数量。
 *
 * <p>修复前 `TrafficProxyController.SCAN_STREAM_EXECUTOR` 是无界 cached thread pool，
 * 每个 `/packets/{id}/zap-scan/stream` 请求都会提交一个可能持续数分钟的扫描任务；大量请求会
 * 无界创建线程。这里用可控阻塞的扫描服务验证并发上限。
 */
class TrafficProxyStreamConcurrencyTests {

  @Test
  void 并发流式扫描超过预算时快速拒绝() throws Exception {
    TrafficScanService scanService = mock(TrafficScanService.class);
    when(scanService.zapScanStreamTimeoutMillis()).thenReturn(60_000L);
    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    when(scanService.zapScan(anyLong(), any(), any()))
        .thenAnswer(
            ignored -> {
              entered.countDown();
              release.await(10, TimeUnit.SECONDS);
              return null;
            });

    ExecutorService executor = Executors.newFixedThreadPool(4);
    try {
      TrafficProxyController controller =
          new TrafficProxyController(
              mock(TrafficProxyService.class),
              mock(TrafficAnalysisService.class),
              mock(TrafficReplayService.class),
              mock(TrafficCaptureFilterService.class),
              mock(TrafficAiChatService.class),
              mock(TrafficFuzzService.class),
              scanService,
              mock(TrafficScanLedgerService.class),
              mock(TrafficAssetSyncService.class),
              executor);

      // 前四个请求占用全部流式扫描名额。
      for (int i = 0; i < 4; i++) {
        assertThat(controller.zapScanStream(1L, null)).isNotNull();
      }
      assertThat(entered.await(5, TimeUnit.SECONDS)).as("扫描任务已启动").isTrue();

      assertThatThrownBy(() -> controller.zapScanStream(1L, null))
          .isInstanceOf(ApiException.class)
          .hasMessageContaining("并发流式扫描");
    } finally {
      release.countDown();
      executor.shutdownNow();
    }
  }
}
