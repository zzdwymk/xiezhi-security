package com.bachelor.toolbox.settings;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class BusinessDataOperationGateTests {
  @Test
  void resetWaitsForAnActiveMutationAndBlocksNewMutations() throws Exception {
    BusinessDataOperationGate gate = new BusinessDataOperationGate();
    CountDownLatch firstMutationEntered = new CountDownLatch(1);
    CountDownLatch releaseFirstMutation = new CountDownLatch(1);
    CountDownLatch resetEntered = new CountDownLatch(1);
    CountDownLatch releaseReset = new CountDownLatch(1);
    CountDownLatch secondMutationEntered = new CountDownLatch(1);

    ExecutorService executor = Executors.newFixedThreadPool(3);
    try {
      var firstMutation =
          executor.submit(
              () ->
                  gate.withMutation(
                      () -> {
                        firstMutationEntered.countDown();
                        await(releaseFirstMutation);
                      }));
      assertThat(firstMutationEntered.await(1, TimeUnit.SECONDS)).isTrue();

      var reset =
          executor.submit(
              () ->
                  gate.withReset(
                      () -> {
                        resetEntered.countDown();
                        await(releaseReset);
                        return null;
                      }));
      assertThat(resetEntered.await(100, TimeUnit.MILLISECONDS)).isFalse();

      releaseFirstMutation.countDown();
      assertThat(resetEntered.await(1, TimeUnit.SECONDS)).isTrue();

      var secondMutation =
          executor.submit(
              () -> gate.withMutation(secondMutationEntered::countDown));
      assertThat(secondMutationEntered.await(100, TimeUnit.MILLISECONDS)).isFalse();

      releaseReset.countDown();
      assertThat(secondMutationEntered.await(1, TimeUnit.SECONDS)).isTrue();
      firstMutation.get(1, TimeUnit.SECONDS);
      reset.get(1, TimeUnit.SECONDS);
      secondMutation.get(1, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
    }
  }

  private static void await(CountDownLatch latch) {
    try {
      assertThat(latch.await(2, TimeUnit.SECONDS)).isTrue();
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw new AssertionError(exception);
    }
  }
}
