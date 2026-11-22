package com.bachelor.toolbox.msf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.dependency.ExecutableLocator;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * 第313轮：MSF 选项读取必须有全局并发上限。
 *
 * <p>按模块分锁（R312）解决了跨模块阻塞，但**不同模块**仍可同时各自启动一个 {@code msfconsole}
 * （实测每个约 59 秒）。大量不同模块的并发请求会同时拉起大量重量级进程。这里用信号量把同时进行的
 * 读取限制为固定数量。
 */
class MsfModuleOptionProcessLimitTests {

  private static final class CountingService extends MsfModuleOptionService {
    private final AtomicInteger active = new AtomicInteger();
    private final AtomicInteger maxActive = new AtomicInteger();

    CountingService() {
      super(mock(ExecutableLocator.class), new ObjectMapper(), "msfconsole", 5, 2);
    }

    @Override
    List<ModuleOption> loadOptions(String module) {
      int now = active.incrementAndGet();
      maxActive.accumulateAndGet(now, Math::max);
      try {
        Thread.sleep(250);
      } catch (InterruptedException ex) {
        Thread.currentThread().interrupt();
      } finally {
        active.decrementAndGet();
      }
      return List.of(new ModuleOption("TARGETURI", "string", false, "/", "目标路径"));
    }
  }

  @Test
  void concurrentModuleReadsAreCapped() throws Exception {
    CountingService service = new CountingService();
    ExecutorService pool = Executors.newFixedThreadPool(6);
    try {
      List<Future<List<MsfModuleOptionService.ModuleOption>>> futures = new ArrayList<>();
      for (int i = 0; i < 6; i++) {
        String module = "auxiliary/scanner/probe/limit_probe_" + i;
        futures.add(pool.submit(() -> service.options(module)));
      }
      for (Future<List<MsfModuleOptionService.ModuleOption>> future : futures) {
        assertThat(future.get(15, TimeUnit.SECONDS)).hasSize(1);
      }
      assertThat(service.maxActive.get())
          .as("同时进行的 msfconsole 读取不得超过配置的并发上限 2")
          .isLessThanOrEqualTo(2);
    } finally {
      pool.shutdownNow();
    }
  }
}
