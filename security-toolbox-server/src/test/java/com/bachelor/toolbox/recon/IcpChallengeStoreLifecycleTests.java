package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class IcpChallengeStoreLifecycleTests {
  private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");
  private static final class TestClock extends Clock {
    volatile Instant now = START;
    final ConcurrentLinkedQueue<Instant> sequence = new ConcurrentLinkedQueue<>();
    public ZoneId getZone() { return ZoneOffset.UTC; }
    public Clock withZone(ZoneId zone) { return this; }
    public Instant instant() { Instant next = sequence.poll(); if (next != null) now = next; return now; }
  }

  @Test
  void expiresAtTheDeadlineRatherThanOneTickLater() {
    TestClock clock = new TestClock();
    IcpChallengeStore store = new IcpChallengeStore(clock);
    String id = store.register(mock(MiitIcpClient.PendingCaptcha.class));
    clock.now = START.plusSeconds(600);
    assertThat(store.take(id)).isNull();
  }

  @Test
  void rechecksExpiryAfterPurgeBeforeReturningTheRemovedEntry() {
    TestClock clock = new TestClock();
    IcpChallengeStore store = new IcpChallengeStore(clock);
    String id = store.register(mock(MiitIcpClient.PendingCaptcha.class));
    clock.sequence.add(START.plusSeconds(600).minusNanos(1));
    clock.sequence.add(START.plusSeconds(600).plusNanos(1));
    assertThat(store.take(id)).isNull();
  }

  @Test
  void concurrentConsumersReceiveTheChallengeOnlyOnce() throws Exception {
    IcpChallengeStore store = new IcpChallengeStore(new TestClock());
    var pending = mock(MiitIcpClient.PendingCaptcha.class);
    String id = store.register(pending);
    var pool = Executors.newFixedThreadPool(8);
    try {
      List<Future<MiitIcpClient.PendingCaptcha>> results = new ArrayList<>();
      for (int i=0; i<32; i++) results.add(pool.submit(() -> store.take(id)));
      int hits = 0;
      for (var future : results) if (future.get(5, TimeUnit.SECONDS) == pending) hits++;
      assertThat(hits).isEqualTo(1);
    } finally { pool.shutdownNow(); }
  }

  @Test
  void concurrentRegistrationRespectsEntryCountCapacity() throws Exception {
    IcpChallengeStore store = new IcpChallengeStore(new TestClock());
    var pending = mock(MiitIcpClient.PendingCaptcha.class);
    var pool = Executors.newFixedThreadPool(8);
    try {
      List<Future<String>> results = new ArrayList<>();
      for (int i=0; i<600; i++) results.add(pool.submit(() -> store.register(pending)));
      for (var future : results) future.get(10, TimeUnit.SECONDS);
      var field = IcpChallengeStore.class.getDeclaredField("store");
      field.setAccessible(true);
      assertThat(((java.util.Map<?,?>) field.get(store)).size()).isEqualTo(500);
    } finally { pool.shutdownNow(); }
  }
}
