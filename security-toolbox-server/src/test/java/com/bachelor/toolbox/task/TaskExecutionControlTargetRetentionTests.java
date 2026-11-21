package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** Round 276：按 target 限流器必须随许可归还而回收，不能在长跑进程里无界增长。 */
class TaskExecutionControlTargetRetentionTests {

  @Test
  void releasesTargetEntryOnceAllPermitsReturn() {
    var control = new TaskExecutionControlService(8, 2);
    try (var permit = control.acquire(1L, 42L)) {
      assertThat(permit).isNotNull();
      assertThat(control.trackedTargets()).isEqualTo(1);
    }
    assertThat(control.trackedTargets()).isZero();
  }

  @Test
  void keepsTargetEntryWhileAnyPermitIsStillHeld() {
    var control = new TaskExecutionControlService(8, 2);
    var first = control.acquire(1L, 42L);
    var second = control.acquire(2L, 42L);
    first.close();
    // One permit is still out, so the limiter must stay (otherwise the cap would be bypassed).
    assertThat(control.trackedTargets()).isEqualTo(1);
    second.close();
    assertThat(control.trackedTargets()).isZero();
  }

  @Test
  void manyDistinctTargetsDoNotAccumulate() {
    var control = new TaskExecutionControlService(8, 1);
    for (long targetId = 1; targetId <= 200; targetId++) {
      control.acquire(targetId, targetId).close();
    }
    assertThat(control.trackedTargets()).isZero();
  }

  @Test
  void perTargetCapStillHoldsAcrossConcurrentAcquireAndRelease() throws Exception {
    var control = new TaskExecutionControlService(16, 1);
    var concurrent = new AtomicInteger();
    var peak = new AtomicInteger();
    var failures = new ArrayList<Throwable>();
    int workers = 8;
    var ready = new CountDownLatch(workers);
    ExecutorService pool = Executors.newFixedThreadPool(workers);
    try {
      List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < workers; i++) {
        long taskId = i + 1;
        futures.add(
            pool.submit(
                () -> {
                  ready.countDown();
                  try (var ignored = control.acquire(taskId, 7L)) {
                    int now = concurrent.incrementAndGet();
                    peak.accumulateAndGet(now, Math::max);
                    Thread.sleep(5);
                    concurrent.decrementAndGet();
                  } catch (Throwable error) {
                    synchronized (failures) {
                      failures.add(error);
                    }
                  }
                  return null;
                }));
      }
      ready.await(5, TimeUnit.SECONDS);
      for (var future : futures) future.get(20, TimeUnit.SECONDS);
    } finally {
      pool.shutdownNow();
    }

    assertThat(failures).isEmpty();
    // perTargetLimit=1：无论回收如何与并发交错，同一 target 的并发数不得超过 1。
    assertThat(peak.get()).isEqualTo(1);
    assertThat(control.trackedTargets()).isZero();
  }

  @Test
  void cancelledWaitStillReturnsBothPermits() throws Exception {
    var control = new TaskExecutionControlService(8, 1);
    control.requestCancellation(9L);
    assertThatThrownBy(() -> control.acquire(9L, 3L))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("已取消");
    assertThat(control.trackedTargets()).isZero();
    // 全局配额未泄漏：仍能拿到全部 8 个许可。
    for (int i = 0; i < 8; i++) control.acquire(100L + i, 100L + i).close();
  }
}
