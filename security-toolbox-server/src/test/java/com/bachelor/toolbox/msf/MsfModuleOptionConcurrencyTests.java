package com.bachelor.toolbox.msf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.dependency.ExecutableLocator;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * 第312轮：不同模块的选项读取必须能并发进行。
 *
 * <p>R311 引入缓存时用了整类 {@code synchronized}：只要一个模块的 {@code msfconsole} 还在启动
 * （实测可达数十秒），其它模块的读取都会被串行阻塞。按模块加锁后，不同模块互不影响。
 */
class MsfModuleOptionConcurrencyTests {

  private static final class BlockingService extends MsfModuleOptionService {
    private final CountDownLatch slowStarted = new CountDownLatch(1);
    private final CountDownLatch releaseSlow = new CountDownLatch(1);

    BlockingService() {
      super(mock(ExecutableLocator.class), new ObjectMapper(), "msfconsole", 5);
    }

    @Override
    List<ModuleOption> loadOptions(String module) {
      if (module.contains("slow")) {
        slowStarted.countDown();
        try {
          releaseSlow.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
          Thread.currentThread().interrupt();
        }
      }
      return List.of(new ModuleOption("TARGETURI", "string", false, "/", "目标路径"));
    }
  }

  @Test
  void differentModulesDoNotBlockEachOther() throws Exception {
    BlockingService service = new BlockingService();
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      Future<List<MsfModuleOptionService.ModuleOption>> slow =
          pool.submit(() -> service.options("auxiliary/scanner/http/slow_probe"));
      assertThat(service.slowStarted.await(2, TimeUnit.SECONDS)).isTrue();

      Future<List<MsfModuleOptionService.ModuleOption>> fast =
          pool.submit(() -> service.options("auxiliary/scanner/http/fast_probe"));

      // 慢模块仍被卡住时，另一个模块必须能完成（修复前会被整类锁阻塞）
      assertThat(fast.get(2, TimeUnit.SECONDS))
          .as("不同模块的选项读取不得互相阻塞")
          .hasSize(1);

      service.releaseSlow.countDown();
      assertThat(slow.get(5, TimeUnit.SECONDS)).hasSize(1);
    } finally {
      service.releaseSlow.countDown();
      pool.shutdownNow();
    }
  }
}
