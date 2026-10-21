package com.bachelor.toolbox.task;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import com.bachelor.toolbox.common.ApiException;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;

class TaskExecutionControlServiceTests {
  /** Scheme-B default: the per-target cap must allow light probes to overlap on one target. */
  @Test
  void defaultPerTargetCapLetsLightProbesOverlapOnTheSameTarget() throws Exception {
    // Mirrors the shipped defaults (global 3, per-target 3).
    TaskExecutionControlService control = new TaskExecutionControlService(3, 3);
    TaskExecutionControlService.Permit first = control.acquire(1L, 9L);
    // A second task on the same target must acquire immediately rather than block.
    TaskExecutionControlService.Permit second =
        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> control.acquire(2L, 9L));
    try { first.close(); } catch (Exception ignored) {}
    try { second.close(); } catch (Exception ignored) {}
  }

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

  @Test
  void shrinkingBusyThreeToOneRepaysDebtBeforeAnotherTaskCanStart() throws Exception {
    var control = new TaskExecutionControlService(3, 3);
    var first = control.acquire(1L, 1L);
    var second = control.acquire(2L, 1L);
    var third = control.acquire(3L, 1L);
    var executor = Executors.newSingleThreadExecutor();
    try {
      control.resizeMaxConcurrentTasks(1);
      assertEquals(1, control.maxConcurrentTasks());
      assertEquals(0, control.availableConcurrentSlots());
      var waiting = executor.submit(() -> control.acquire(4L, 1L));
      assertThrows(TimeoutException.class, () -> waiting.get(100, TimeUnit.MILLISECONDS));
      first.close();
      assertEquals(0, control.availableConcurrentSlots());
      assertThrows(TimeoutException.class, () -> waiting.get(100, TimeUnit.MILLISECONDS));
      second.close();
      assertEquals(0, control.availableConcurrentSlots());
      assertThrows(TimeoutException.class, () -> waiting.get(100, TimeUnit.MILLISECONDS));
      third.close();
      var fourth = waiting.get(1, TimeUnit.SECONDS);
      assertEquals(0, control.availableConcurrentSlots());
      fourth.close();
      assertEquals(1, control.availableConcurrentSlots());
    } finally {
      first.close(); second.close(); third.close();
      executor.shutdownNow();
      assertEquals(true, executor.awaitTermination(1, TimeUnit.SECONDS));
    }
  }

  @Test
  void repeatedChangesWhileBusyCannotInflateTheLimit() {
    var control = new TaskExecutionControlService(3, 3);
    var first = control.acquire(1L, 1L);
    var second = control.acquire(2L, 1L);
    var third = control.acquire(3L, 1L);
    for (int i = 0; i < 20; i++) {
      control.resizeMaxConcurrentTasks(1);
      control.resizeMaxConcurrentTasks(4);
      control.resizeMaxConcurrentTasks(2);
    }
    assertEquals(2, control.maxConcurrentTasks());
    assertEquals(0, control.availableConcurrentSlots());
    first.close();
    assertEquals(0, control.availableConcurrentSlots());
    second.close();
    assertEquals(1, control.availableConcurrentSlots());
    third.close();
    assertEquals(2, control.availableConcurrentSlots());
    control.resizeMaxConcurrentTasks(1);
    assertEquals(1, control.availableConcurrentSlots());
  }

  @Test
  void increasingWhileBusyMakesOnlyTheAddedSlotsAvailable() {
    var control = new TaskExecutionControlService(1, 4);
    var first = control.acquire(1L, 1L);
    control.resizeMaxConcurrentTasks(3);
    assertEquals(2, control.availableConcurrentSlots());
    var second = control.acquire(2L, 1L);
    var third = control.acquire(3L, 1L);
    assertEquals(0, control.availableConcurrentSlots());
    first.close(); second.close(); third.close();
    assertEquals(3, control.availableConcurrentSlots());
  }

  @Test
  void concurrentAndRepeatedCloseReleaseEachPermitOnlyOnce() throws Exception {
    var control = new TaskExecutionControlService(2, 1);
    var permit = control.acquire(1L, 1L);
    var executor = Executors.newFixedThreadPool(8);
    var start = new CountDownLatch(1);
    try {
      var futures = new java.util.ArrayList<java.util.concurrent.Future<?>>();
      for (int i = 0; i < 16; i++) {
        futures.add(executor.submit(() -> {
          try { start.await(); } catch (InterruptedException ex) { throw new AssertionError(ex); }
          permit.close();
        }));
      }
      start.countDown();
      for (var future : futures) future.get(1, TimeUnit.SECONDS);
      permit.close();
      assertEquals(2, control.availableConcurrentSlots());
      var next = control.acquire(2L, 1L);
      assertEquals(1, control.availableConcurrentSlots());
      next.close();
      assertEquals(2, control.availableConcurrentSlots());
    } finally {
      start.countDown();
      executor.shutdownNow();
      assertEquals(true, executor.awaitTermination(1, TimeUnit.SECONDS));
    }
  }

  @Test
  void interruptedTargetWaitRepaysReducedGlobalQuota() throws Exception {
    var control = new TaskExecutionControlService(2, 1);
    var first = control.acquire(1L, 9L);
    var executor = Executors.newSingleThreadExecutor();
    try {
      var waiting = executor.submit(() -> control.acquire(2L, 9L));
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
      while (control.availableConcurrentSlots() != 0 && System.nanoTime() < deadline) Thread.yield();
      assertEquals(0, control.availableConcurrentSlots());
      control.resizeMaxConcurrentTasks(1);
      waiting.cancel(true);
      executor.shutdown();
      assertEquals(true, executor.awaitTermination(1, TimeUnit.SECONDS));
      assertEquals(0, control.availableConcurrentSlots());
      first.close();
      assertEquals(1, control.availableConcurrentSlots());
    } finally {
      first.close();
      executor.shutdownNow();
    }
  }
}
