package com.bachelor.toolbox.dependency;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;

/**
 * Round 225：流式依赖检测是未登录的本地 SSE 入口，必须限制同时运行的检测批次，
 * 防止并发请求各自创建 12 线程池与外部命令进程造成资源耗尽。
 */
class DependencyDetectionStreamConcurrencyTests {

  @Test
  void 并发流式依赖检测只允许一个批次运行() throws Exception {
    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    AtomicInteger locatorCalls = new AtomicInteger();
    ExecutableLocator locator =
        candidates -> {
          if (locatorCalls.incrementAndGet() == 1) entered.countDown();
          try {
            release.await(10, TimeUnit.SECONDS);
          } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
          }
          return Optional.empty();
        };
    Environment environment = mock(Environment.class);
    when(environment.getProperty("spring.datasource.url", "")).thenReturn("jdbc:h2:test");
    DependencyDetectionService service =
        new DependencyDetectionService(
            locator,
            mock(CommandRunner.class),
            new NmapExecutableResolver(locator, "nmap"),
            environment,
            mock(ToolDirectoryHasher.class));

    CountDownLatch firstComplete = new CountDownLatch(1);
    service.detectStreaming(false, manifests -> {}, status -> {}, all -> firstComplete.countDown());
    assertThat(entered.await(5, TimeUnit.SECONDS)).as("首批检测已启动").isTrue();

    // 第二批必须快速失败，不能创建第二个执行器。
    assertThatThrownBy(
            () -> service.detectStreaming(false, manifests -> {}, status -> {}, all -> {}))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("正在进行");

    release.countDown();
    assertThat(firstComplete.await(10, TimeUnit.SECONDS)).as("首批检测正常完成").isTrue();

    // 首批完成后必须释放单飞名额，后续检测可以正常开始并完成。
    CountDownLatch secondComplete = new CountDownLatch(1);
    service.detectStreaming(false, manifests -> {}, status -> {}, all -> secondComplete.countDown());
    assertThat(secondComplete.await(10, TimeUnit.SECONDS)).as("后续检测可以重新开始").isTrue();
  }
}
