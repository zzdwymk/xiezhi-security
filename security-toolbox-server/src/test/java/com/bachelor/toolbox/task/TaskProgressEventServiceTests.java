package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.AbstractSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

class TaskProgressEventServiceTests {
  @Test
  void createsStreamForRunningTaskAndAcceptsProgressEvents() {
    TaskProgressEventService service = new TaskProgressEventService();
    SecurityTask task = new SecurityTask();
    task.setId(7L);
    task.setStatus("RUNNING");
    task.setProgress(40);

    SseEmitter emitter = service.subscribe(task);
    service.publish(task, "执行命令：nmap --version");

    assertThat(emitter).isNotNull();
    assertThat(emitter.getTimeout()).isEqualTo(30L * 60L * 1000L);
  }

  @Test
  void createsCompletedSnapshotStreamForTerminalTask() {
    TaskProgressEventService service = new TaskProgressEventService();
    SecurityTask task = new SecurityTask();
    task.setId(8L);
    task.setStatus("SUCCESS");
    task.setProgress(100);

    assertThat(service.subscribe(task)).isNotNull();
  }

  @Test
  void removesTaskSubscriberWhenSendingFailsWithoutRetainingADeadEmitter() {
    TaskProgressEventService service =
        new TaskProgressEventService(timeout -> new FailingSseEmitter(timeout, 2));
    SecurityTask task = runningTask(9L);

    SseEmitter emitter = service.subscribe(task);
    service.publish(task, "progress");

    Map<Long, Set<SseEmitter>> subscribers = subscribers(service);
    assertThat(subscribers).isEmpty();
    assertThat(TaskProgressEventService.class.getDeclaredFields())
        .noneMatch(field -> field.getName().equals("dead"));
  }

  @Test
  void removesAllTaskSubscriberWhenSendingFails() {
    TaskProgressEventService service =
        new TaskProgressEventService(timeout -> new FailingSseEmitter(timeout, 2));

    SseEmitter emitter = service.subscribeAll();
    service.publish(runningTask(10L), "progress");

    assertThat(allTaskSubscribers(service)).doesNotContain(emitter);
  }

  @Test
  void keepsReconnectSubscribedWhileLastOldSubscriberIsBeingRemoved() throws Exception {
    AtomicInteger emitterCount = new AtomicInteger();
    CountDownLatch reconnectEmitterCreated = new CountDownLatch(1);
    TaskProgressEventService service =
        new TaskProgressEventService(
            timeout -> {
              if (emitterCount.incrementAndGet() == 1) return new FailingSseEmitter(timeout, 2);
              reconnectEmitterCreated.countDown();
              return new FailingSseEmitter(timeout, Integer.MAX_VALUE);
            });
    SecurityTask task = runningTask(11L);
    SseEmitter oldEmitter = service.subscribe(task);
    BlockingRemoveSet blockingSet = new BlockingRemoveSet(oldEmitter);
    subscribers(service).put(task.getId(), blockingSet);
    ExecutorService workers = Executors.newFixedThreadPool(2);

    try {
      Future<?> cleanup = workers.submit(() -> service.publish(task, "disconnect"));
      assertThat(blockingSet.removeStarted.await(5, TimeUnit.SECONDS)).isTrue();

      Future<SseEmitter> reconnect = workers.submit(() -> service.subscribe(task));
      assertThat(reconnectEmitterCreated.await(5, TimeUnit.SECONDS)).isTrue();
      assertThat(reconnect.isDone()).isFalse();

      blockingSet.allowRemove.countDown();
      cleanup.get(5, TimeUnit.SECONDS);
      SseEmitter newEmitter = reconnect.get(5, TimeUnit.SECONDS);

      assertThat(subscribers(service).get(task.getId())).containsExactly(newEmitter);
    } finally {
      blockingSet.allowRemove.countDown();
      workers.shutdownNow();
      assertThat(workers.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
    }
  }

  private SecurityTask runningTask(long id) {
    SecurityTask task = new SecurityTask();
    task.setId(id);
    task.setStatus("RUNNING");
    task.setProgress(1);
    return task;
  }

  @SuppressWarnings("unchecked")
  private Map<Long, Set<SseEmitter>> subscribers(TaskProgressEventService service) {
    return (Map<Long, Set<SseEmitter>>) ReflectionTestUtils.getField(service, "subscribers");
  }

  @SuppressWarnings("unchecked")
  private Set<SseEmitter> allTaskSubscribers(TaskProgressEventService service) {
    return (Set<SseEmitter>) ReflectionTestUtils.getField(service, "allTaskSubscribers");
  }

  private static final class FailingSseEmitter extends SseEmitter {
    private final int failOnSend;
    private int sends;

    private FailingSseEmitter(Long timeout, int failOnSend) {
      super(timeout);
      this.failOnSend = failOnSend;
    }

    @Override
    public synchronized void send(SseEventBuilder builder) throws IOException {
      if (++sends >= failOnSend) throw new IOException("closed");
    }
  }

  private static final class BlockingRemoveSet extends AbstractSet<SseEmitter> {
    private final Set<SseEmitter> delegate = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final CountDownLatch removeStarted = new CountDownLatch(1);
    private final CountDownLatch allowRemove = new CountDownLatch(1);

    private BlockingRemoveSet(SseEmitter emitter) {
      delegate.add(emitter);
    }

    @Override
    public Iterator<SseEmitter> iterator() {
      return delegate.iterator();
    }

    @Override
    public int size() {
      return delegate.size();
    }

    @Override
    public boolean add(SseEmitter emitter) {
      return delegate.add(emitter);
    }

    @Override
    public boolean remove(Object emitter) {
      boolean removed = delegate.remove(emitter);
      removeStarted.countDown();
      try {
        if (!allowRemove.await(5, TimeUnit.SECONDS)) throw new AssertionError("remove timed out");
      } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
        throw new AssertionError("remove interrupted", exception);
      }
      return removed;
    }
  }
}
