package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.lang.reflect.Field;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class AiConversationMemoryServiceTests {
  @Test
  void rejectsReusingSessionAcrossProjectsOrTargets() {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);

    AiConversationMemoryService.SessionHandle handle = memory.open("scoped-session", 1L, 2L);
    memory.addUser(handle.id(), "remember me");

    assertThat(handle.projectId()).isEqualTo(1L);
    assertThat(handle.targetId()).isEqualTo(2L);
    assertThatThrownBy(() -> memory.open(handle.id(), 9L, 2L))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("已绑定其他项目或目标");
    assertThatThrownBy(() -> memory.open(handle.id(), 1L, 9L))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("已绑定其他项目或目标");
    assertThat(memory.transcript(handle.id())).contains("remember me");
  }

  @Test
  void evictsExpiredSessionAndAllowsIdToBeRebound() throws ReflectiveOperationException {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 5);
    memory.open("expired-session", 1L, 2L);
    memory.addUser("expired-session", "old context");
    setLastAccess(memory, "expired-session", Instant.now().minus(6, ChronoUnit.MINUTES));

    memory.open("eviction-trigger", 1L, 2L);

    assertThatThrownBy(() -> memory.transcript("expired-session"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不存在或已过期");
    AiConversationMemoryService.SessionHandle rebound =
        memory.open("expired-session", 3L, 4L);
    assertThat(rebound.projectId()).isEqualTo(3L);
    assertThat(rebound.targetId()).isEqualTo(4L);
    assertThat(memory.transcript(rebound.id())).isEmpty();
  }

  @Test
  void evictsLeastRecentlyUsedSessionAtCapacity() throws ReflectiveOperationException {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 10, 120);
    for (int index = 0; index < 10; index++) {
      memory.open("session-" + index, 1L, 2L);
    }
    setLastAccess(memory, "session-3", Instant.now().minus(1, ChronoUnit.MINUTES));

    memory.open("session-10", 1L, 2L);

    assertThatThrownBy(() -> memory.transcript("session-3"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不存在或已过期");
    assertThat(memory.transcript("session-0")).isEmpty();
    assertThat(memory.transcript("session-10")).isEmpty();
  }

  @Test
  void boundsConversationByConfiguredMessageCapacity() {
    AiConversationMemoryService memory = new AiConversationMemoryService(4, 20, 120);
    memory.open("bounded-session", 1L, 2L);

    memory.addUser("bounded-session", "message-1");
    memory.addAssistant("bounded-session", "message-2");
    memory.addUser("bounded-session", "message-3");
    memory.addAssistant("bounded-session", "message-4");
    memory.addUser("bounded-session", "message-5");
    memory.addAssistant("bounded-session", "message-6");

    assertThat(memory.messageCount("bounded-session")).isEqualTo(4);
    assertThat(memory.recentChatMessages("bounded-session"))
        .extracting(message -> message.get("content"))
        .containsExactly("message-3", "message-4", "message-5", "message-6");
    assertThat(memory.transcript("bounded-session"))
        .doesNotContain("message-1", "message-2")
        .contains("message-3", "message-4", "message-5", "message-6");
  }

  @Test
  void clearReturnsScopeRemovesContextAndPermitsCleanReopen() {
    AiConversationMemoryService memory = new AiConversationMemoryService(20, 20, 120);
    memory.open("clear-session", 1L, 2L);
    memory.addUser("clear-session", "question");
    memory.addAssistant("clear-session", "answer");

    AiConversationMemoryService.SessionScope scope = memory.clear("clear-session");

    assertThat(scope.projectId()).isEqualTo(1L);
    assertThat(scope.targetId()).isEqualTo(2L);
    assertThatThrownBy(() -> memory.transcript("clear-session"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不存在或已过期");
    assertThat(memory.clear("clear-session")).isNull();
    assertThat(memory.clear(null)).isNull();

    memory.open("clear-session", 8L, 9L);
    assertThat(memory.transcript("clear-session")).isEmpty();
  }

  @Test
  void restoresScopedConversationAfterServiceRestart() {
    RepositoryFixture fixture = new RepositoryFixture();
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiConversationMemoryService first = fixture.service(runtime);
    first.open("restart-session", 11L, 22L);
    first.addUser("restart-session", "persisted question");
    first.addAssistant("restart-session", "persisted answer");

    AiConversationMemoryService restarted = fixture.service(runtime);
    AiConversationMemoryService.SessionHandle restored =
        restarted.open("restart-session", 11L, 22L);

    assertThat(restored.projectId()).isEqualTo(11L);
    assertThat(restored.targetId()).isEqualTo(22L);
    assertThat(restarted.recentChatMessages(restored.id()))
        .extracting(message -> message.get("content"))
        .containsExactly("persisted question", "persisted answer");
    assertThatThrownBy(() -> restarted.open("restart-session", 99L, 22L))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("已绑定其他项目或目标");
    verify(runtime, never()).clearConversationMemories(any(Long.class), any(String.class));
  }

  @Test
  void expiredPersistedConversationIsDeletedAndTombstonedAfterRestart() {
    RepositoryFixture fixture = new RepositoryFixture();
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiConversationMemoryService first = fixture.service(runtime);
    first.open("expired-persisted", 31L, 32L);
    first.addUser("expired-persisted", "stale context");
    fixture.records.get("expired-persisted").setLastAccess(Instant.now().minus(6, ChronoUnit.MINUTES));

    AiConversationMemoryService restarted = fixture.service(runtime);
    restarted.open("fresh-session", 31L, 32L);

    assertThat(fixture.records).doesNotContainKey("expired-persisted");
    verify(runtime).clearConversationMemories(31L, "expired-persisted");
    AiConversationMemoryService.SessionHandle rebound =
        restarted.open("expired-persisted", 41L, 42L);
    assertThat(restarted.transcript(rebound.id())).isEmpty();
  }

  @Test
  void ttlEvictionWaitsForInFlightWriteAndKeepsTheRefreshedConversation() throws Exception {
    RepositoryFixture fixture = new RepositoryFixture();
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiConversationMemoryService memory = fixture.service(runtime, 20, 5);
    AiConversationMemoryService.SessionHandle handle = memory.open("ttl-race", 51L, 52L);
    memory.addUser(handle.id(), "existing context");
    Instant stale = Instant.now().minus(6, ChronoUnit.MINUTES);
    setLastAccess(memory, handle.id(), stale);
    fixture.records.get(handle.id()).setLastAccess(stale);

    CountDownLatch writerHasLock = new CountDownLatch(1);
    CountDownLatch releaseWriter = new CountDownLatch(1);
    AtomicReference<Thread> evictionThread = new AtomicReference<>();
    ExecutorService workers = Executors.newFixedThreadPool(2);
    try {
      Future<?> writer =
          workers.submit(
              () -> {
                synchronized (handle.monitor()) {
                  writerHasLock.countDown();
                  await(releaseWriter);
                  memory.addUser(handle.id(), "concurrent refresh");
                }
              });
      assertThat(writerHasLock.await(2, TimeUnit.SECONDS)).isTrue();
      Future<?> eviction =
          workers.submit(
              () -> {
                evictionThread.set(Thread.currentThread());
                memory.open("ttl-trigger", 51L, 52L);
              });

      awaitState(evictionThread, Thread.State.BLOCKED);
      releaseWriter.countDown();
      writer.get(2, TimeUnit.SECONDS);
      eviction.get(2, TimeUnit.SECONDS);

      assertThat(memory.transcript(handle.id())).contains("existing context", "concurrent refresh");
      assertThat(fixture.records).containsKey(handle.id());
      verify(runtime, never()).clearConversationMemories(51L, handle.id());
    } finally {
      releaseWriter.countDown();
      workers.shutdownNow();
    }
  }

  @Test
  void lruEvictionRechecksAfterInFlightWriteAndTombstonesTheActualOldestSession()
      throws Exception {
    RepositoryFixture fixture = new RepositoryFixture();
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiConversationMemoryService memory = fixture.service(runtime, 10, 120);
    AiConversationMemoryService.SessionHandle candidate = null;
    for (int index = 0; index < 10; index++) {
      AiConversationMemoryService.SessionHandle opened =
          memory.open("lru-session-" + index, 61L, 62L);
      if (index == 3) candidate = opened;
    }
    assertThat(candidate).isNotNull();
    AiConversationMemoryService.SessionHandle heldCandidate = candidate;
    Instant initiallyOldest = Instant.now().minus(1, ChronoUnit.MINUTES);
    setLastAccess(memory, heldCandidate.id(), initiallyOldest);
    fixture.records.get(heldCandidate.id()).setLastAccess(initiallyOldest);
    Instant nextOldest = Instant.now().minus(30, ChronoUnit.SECONDS);
    setLastAccess(memory, "lru-session-0", nextOldest);
    fixture.records.get("lru-session-0").setLastAccess(nextOldest);

    RepositoryFixture.SaveBlock blockedSave = fixture.blockNextSave(heldCandidate.id());
    AtomicReference<Thread> evictionThread = new AtomicReference<>();
    ExecutorService workers = Executors.newFixedThreadPool(2);
    try {
      Future<?> writer =
          workers.submit(() -> memory.addUser(heldCandidate.id(), "recent write"));
      assertThat(blockedSave.started.await(2, TimeUnit.SECONDS)).isTrue();
      Future<?> eviction =
          workers.submit(
              () -> {
                evictionThread.set(Thread.currentThread());
                memory.open("lru-session-10", 61L, 62L);
              });

      awaitState(evictionThread, Thread.State.BLOCKED);
      blockedSave.release.countDown();
      writer.get(2, TimeUnit.SECONDS);
      eviction.get(2, TimeUnit.SECONDS);

      assertThat(memory.transcript(heldCandidate.id())).contains("recent write");
      assertThat(fixture.records).containsKey(heldCandidate.id());
      assertThat(fixture.records).doesNotContainKey("lru-session-0");
      verify(runtime).clearConversationMemories(61L, "lru-session-0");
      verify(runtime, never()).clearConversationMemories(61L, heldCandidate.id());
    } finally {
      blockedSave.release.countDown();
      workers.shutdownNow();
    }
  }

  private void await(CountDownLatch latch) {
    try {
      if (!latch.await(2, TimeUnit.SECONDS)) throw new AssertionError("timed out waiting for latch");
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new AssertionError("interrupted while waiting for latch", ex);
    }
  }

  private void awaitState(AtomicReference<Thread> threadRef, Thread.State expected)
      throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
    Thread thread;
    do {
      thread = threadRef.get();
      if (thread != null && thread.getState() == expected) return;
      Thread.sleep(5);
    } while (System.nanoTime() < deadline);
    assertThat(thread).isNotNull();
    assertThat(thread.getState()).isEqualTo(expected);
  }

  @SuppressWarnings("unchecked")
  private void setLastAccess(
      AiConversationMemoryService memory, String sessionId, Instant lastAccess)
      throws ReflectiveOperationException {
    Field sessionsField = AiConversationMemoryService.class.getDeclaredField("sessions");
    sessionsField.setAccessible(true);
    Map<String, Object> sessions = (Map<String, Object>) sessionsField.get(memory);
    Object session = sessions.get(sessionId);
    assertThat(session).as("session %s", sessionId).isNotNull();

    Field lastAccessField = session.getClass().getDeclaredField("lastAccess");
    lastAccessField.setAccessible(true);
    lastAccessField.set(session, lastAccess);
  }

  private static final class RepositoryFixture {
    private final Map<String, AiConversationSessionRecord> records = new ConcurrentHashMap<>();
    private final AiConversationSessionRepository repository =
        mock(AiConversationSessionRepository.class);
    private final AtomicReference<SaveBlock> nextSaveBlock = new AtomicReference<>();

    private RepositoryFixture() {
      when(repository.findById(any(String.class)))
          .thenAnswer(invocation -> Optional.ofNullable(records.get(invocation.getArgument(0))));
      when(repository.save(any(AiConversationSessionRecord.class)))
          .thenAnswer(
              invocation -> {
                AiConversationSessionRecord record = invocation.getArgument(0);
                SaveBlock block = nextSaveBlock.get();
                if (block != null
                    && block.sessionId.equals(record.getId())
                    && nextSaveBlock.compareAndSet(block, null)) {
                  block.started.countDown();
                  try {
                    if (!block.release.await(2, TimeUnit.SECONDS)) {
                      throw new AssertionError("timed out waiting to release repository save");
                    }
                  } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError("repository save interrupted", ex);
                  }
                }
                records.put(record.getId(), record);
                return record;
              });
      when(repository.findByLastAccessBefore(any(Instant.class)))
          .thenAnswer(
              invocation -> {
                Instant threshold = invocation.getArgument(0);
                return records.values().stream()
                    .filter(record -> record.getLastAccess().isBefore(threshold))
                    .toList();
              });
      when(repository.count()).thenAnswer(ignored -> (long) records.size());
      when(repository.findFirstByOrderByLastAccessAsc())
          .thenAnswer(
              ignored ->
                  records.values().stream()
                      .min(Comparator.comparing(AiConversationSessionRecord::getLastAccess)));
      doAnswer(
              invocation -> {
                AiConversationSessionRecord record = invocation.getArgument(0);
                records.remove(record.getId());
                return null;
              })
          .when(repository)
          .delete(any(AiConversationSessionRecord.class));
    }

    private SaveBlock blockNextSave(String sessionId) {
      SaveBlock block = new SaveBlock(sessionId);
      assertThat(nextSaveBlock.compareAndSet(null, block)).isTrue();
      return block;
    }

    private AiConversationMemoryService service(AiAgentRuntimeClient runtime) {
      return service(runtime, 20, 5);
    }

    private AiConversationMemoryService service(
        AiAgentRuntimeClient runtime, int maxSessions, long ttlMinutes) {
      return new AiConversationMemoryService(
          20, maxSessions, ttlMinutes, repository, new ObjectMapper(), runtime);
    }

    private static final class SaveBlock {
      private final String sessionId;
      private final CountDownLatch started = new CountDownLatch(1);
      private final CountDownLatch release = new CountDownLatch(1);

      private SaveBlock(String sessionId) {
        this.sessionId = sessionId;
      }
    }
  }
}
