package com.bachelor.toolbox.recon;
import static org.assertj.core.api.Assertions.assertThat;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
class IcpCaptureExpiryTests {
  private static final Instant START=Instant.parse("2026-01-01T00:00:00Z");
  private static class TestClock extends Clock {
    Instant now=START; final Queue<Instant> sequence=new ArrayDeque<>();
    public ZoneId getZone(){return ZoneOffset.UTC;}
    public Clock withZone(ZoneId zone){return this;}
    public Instant instant(){if(!sequence.isEmpty())now=sequence.remove();return now;}
  }
  @Test void exactDeadlineIsExpired() {
    var clock=new TestClock();var store=new IcpBrowserCaptureStore(clock);
    store.store(1L,2L,"example.test",List.of(Map.of("owner","QA")));
    clock.now=START.plusSeconds(86400);
    assertThat(store.take(1L,2L)).isNull();
  }
  @Test void crossingDeadlineAfterPurgeCannotReturnExpiredCapture() {
    var clock=new TestClock();var store=new IcpBrowserCaptureStore(clock);
    store.store(1L,2L,"example.test",List.of(Map.of("owner","QA")));
    clock.sequence.add(START.plusSeconds(86400).minusNanos(1));
    clock.sequence.add(START.plusSeconds(86400));
    assertThat(store.take(1L,2L)).isNull();
  }
  @Test void beforeDeadlineReadsRemainRepeatableAndClearStillWorks() {
    var clock=new TestClock();var store=new IcpBrowserCaptureStore(clock);
    store.store(1L,2L,"example.test",List.of(Map.of("owner","QA")));
    clock.now=START.plusSeconds(86400).minusNanos(1);
    assertThat(store.take(1L,2L)).isNotNull();assertThat(store.take(1L,2L)).isNotNull();
    store.clear(1L,2L);assertThat(store.take(1L,2L)).isNull();
  }
}
