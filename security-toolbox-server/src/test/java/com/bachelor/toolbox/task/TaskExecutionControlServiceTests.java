package com.bachelor.toolbox.task;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.bachelor.toolbox.common.ApiException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class TaskExecutionControlServiceTests {
  @Test
  void interruptedTargetWaitReturnsGlobalPermit() throws Exception {
    TaskExecutionControlService control = new TaskExecutionControlService(2, 1);
    TaskExecutionControlService.Permit first = control.acquire(1L, 9L);
    CountDownLatch started = new CountDownLatch(1);
    Thread waiter =
        new Thread(
            () -> {
              started.countDown();
              assertThrows(ApiException.class, () -> control.acquire(2L, 9L));
            });
    waiter.start();
    assertEquals(true, started.await(1, TimeUnit.SECONDS));
    // The second worker has acquired a global slot and is blocked on the
    // per-target quota. Interrupting it must release that global slot.
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
    while (control.availableConcurrentSlots() != 0 && System.nanoTime() < deadline) {
      Thread.yield();
    }
    waiter.interrupt();
    waiter.join(1_000);
    assertEquals(false, waiter.isAlive());
    assertEquals(1, control.availableConcurrentSlots());
    first.close();
    assertEquals(2, control.availableConcurrentSlots());
  }

  @Test
  void exposesConfiguredConcurrencyPolicy() {
    TaskExecutionControlService control = new TaskExecutionControlService(4, 2);

    assertEquals(4, control.maxConcurrentTasks());
    assertEquals(4, control.availableConcurrentSlots());
    assertEquals(2, control.maxConcurrentTasksPerTarget());
  }
}
