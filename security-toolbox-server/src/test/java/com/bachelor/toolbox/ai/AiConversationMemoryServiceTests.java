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
  void clearDoesNotHoldSessionLockWhileClearingRuntimeMemory() throws Exception {
    // 回归：clear() 曾在 lifecycleMonitor/session.monitor 内同步调用 AI Runtime 的
    // 索引清理接口（读超时 10 秒以上）。慢调用会长时间占锁，使 DELETE 会话请求
    // 挂起到浏览器放弃（桌面表现为 net::ERR_ABORTED、会话数不减少）。
    // 这里用一个"卡住"的 runtime 调用来证明：清理运行时记忆期间，同一会话的其他
    // 操作不会被阻塞，且 clear 最终仍返回正确作用域。
    RepositoryFixture fixture = new RepositoryFixture();
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    CountDownLatch runtimeEntered = new CountDownLatch(1);
    CountDownLatch releaseRuntime = new CountDownLatch(1);
    doAnswer(
            invocation -> {
              runtimeEntered.countDown();
              await(releaseRuntime);
              return 1;
            })
        .when(runtime)
        .clearConversationMemories(any(Long.class), any(String.class));
    AiConversationMemoryService memory = fixture.service(runtime);
    memory.open("lock-scope", 71L, 72L);
    memory.addUser("lock-scope", "context");

    ExecutorService workers = Executors.newFixedThreadPool(2);
    try {
      Future<AiConversationMemoryService.SessionScope> clearing =
          workers.submit(() -> memory.clear("lock-scope"));
      assertThat(runtimeEntered.await(5, TimeUnit.SECONDS))
          .as("clear 应进入运行时记忆清理")
          .isTrue();

      // 运行时清理仍在进行时，新的会话操作必须能立刻完成（锁未被占住）。
      Future<AiConversationMemoryService.SessionHandle> opening =
          workers.submit(() -> memory.open("other-session", 71L, 72L));
      AiConversationMemoryService.SessionHandle handle = opening.get(5, TimeUnit.SECONDS);
      assertThat(handle).isNotNull();
      assertThat(handle.projectId()).isEqualTo(71L);

      releaseRuntime.countDown();
      AiConversationMemoryService.SessionScope scope = clearing.get(5, TimeUnit.SECONDS);
      assertThat(scope.projectId()).isEqualTo(71L);
      assertThat(scope.targetId()).isEqualTo(72L);
      verify(runtime).clearConversationMemories(71L, "lock-scope");
    } finally {
      releaseRuntime.countDown();
      workers.shutdownNow();
    }
  }

  @Test
  void evictionDoesNotHoldLocksWhileClearingRuntimeMemory() throws Exception {
    // 回归：evictExpired() 由 open() 在每一轮对话中调用，而 open() 持有
    // lifecycleMonitor。若在其中同步调用 AI Runtime 的清理接口，一次慢调用就会
    // 占住这个全局锁，阻塞所有会话的对话。
    RepositoryFixture fixture = new RepositoryFixture();
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    CountDownLatch runtimeEntered = new CountDownLatch(1);
    CountDownLatch releaseRuntime = new CountDownLatch(1);
    doAnswer(
            invocation -> {
              runtimeEntered.countDown();
              await(releaseRuntime);
              return 1;
            })
        .when(runtime)
        .clearConversationMemories(any(Long.class), any(String.class));
    AiConversationMemoryService memory = fixture.service(runtime, 20, 5);
    AiConversationMemoryService.SessionHandle stale = memory.open("evict-slow", 81L, 82L);
    Instant expired = Instant.now().minus(6, ChronoUnit.MINUTES);
    setLastAccess(memory, stale.id(), expired);
    fixture.records.get(stale.id()).setLastAccess(expired);

    // 只让第一次运行时清理卡住：后续调用直接返回，避免测试自身互相等待。
    java.util.concurrent.atomic.AtomicBoolean firstCall =
        new java.util.concurrent.atomic.AtomicBoolean(true);
    doAnswer(
            invocation -> {
              if (firstCall.compareAndSet(true, false)) {
                runtimeEntered.countDown();
                awaitLong(releaseRuntime, 20);
              }
              return 1;
            })
        .when(runtime)
        .clearConversationMemories(any(Long.class), any(String.class));

    ExecutorService workers = Executors.newFixedThreadPool(3);
    try {
      Future<AiConversationMemoryService.SessionHandle> opening =
          workers.submit(() -> memory.open("evict-trigger", 91L, 92L));
      assertThat(runtimeEntered.await(5, TimeUnit.SECONDS))
          .as("淘汰过期会话时应发起运行时清理")
          .isTrue();

      // 运行时清理仍在进行时，另一个会话必须能立刻打开（全局锁未被占住）。
      // 注意 await() 内部等待上限为 2 秒，因此这里必须尽快放行运行时调用。
      Future<AiConversationMemoryService.SessionHandle> other =
          workers.submit(() -> memory.open("evict-other", 93L, 94L));
      assertThat(other.get(5, TimeUnit.SECONDS)).isNotNull();
      releaseRuntime.countDown();
      assertThat(opening.get(5, TimeUnit.SECONDS)).isNotNull();
    } finally {
      releaseRuntime.countDown();
      workers.shutdownNow();
    }
  }

  @Test
  void failedPersistDoesNotLeaveHalfCreatedSessionBehind() {
    // 回归：open() 曾先用 computeIfAbsent 把 Session 登记进 sessions，再调用 persist()。
    // 若 persist 失败，这个空会话会残留；重试时因"已存在"而跳过 loadPersisted，
    // 历史会被空列表覆盖，造成静默的上下文丢失。
    RepositoryFixture fixture = new RepositoryFixture();
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiConversationMemoryService memory = fixture.service(runtime);
    memory.open("persist-fail", 101L, 102L);
    memory.addUser("persist-fail", "重要上下文");
    memory.addAssistant("persist-fail", "重要回答");
    assertThat(fixture.records.get("persist-fail").getTurnsJson()).contains("重要上下文");

    // 另开一个会话，并让它的首次落库失败。
    fixture.failNextSave.set(true);
    assertThatThrownBy(() -> memory.open("half-created", 103L, 104L))
        .isInstanceOf(ApiException.class);

    // 失败后不能残留内存会话：重新打开必须是全新的空会话，而不是"半成品"。
    AiConversationMemoryService.SessionHandle reopened = memory.open("half-created", 103L, 104L);
    assertThat(reopened.projectId()).isEqualTo(103L);
    assertThat(memory.transcript(reopened.id())).isEmpty();
    assertThat(fixture.records).containsKey("half-created");
  }

  @Test
  void transcriptDropsWholeTurnInsteadOfSlicingItMidway() {
    // 回归：历史超长时曾把当前这一行"截半"追加，半句话会被当作有效历史
    // 拼进规划提示词发给模型。现在应当整轮丢弃并显式标注已截断。
    AiConversationMemoryService memory = new AiConversationMemoryService(200, 20, 120);
    memory.open("long-history", 1L, 2L);
    String longTurn = "A".repeat(3800);
    for (int i = 0; i < 4; i++) {
      memory.addUser("long-history", longTurn + "-" + i);
      memory.addAssistant("long-history", longTurn + "-" + i);
    }

    String transcript = memory.transcript("long-history");

    assertThat(transcript).contains("历史较长，较早的内容已省略");
    // 不能以半行结尾：每条完整记录的结尾都是换行后被 strip 掉的完整句子，
    // 因此不允许出现"被截断的 3800 字长句"这种中间态。
    assertThat(transcript.length()).isLessThanOrEqualTo(8000 + 40);
    for (String line : transcript.split("\n")) {
      if (line.startsWith("用户：") || line.startsWith("助手：")) {
        String body = line.substring(3);
        assertThat(body.endsWith("历史较长，较早的内容已省略"))
            .as("每一行都必须是完整记录或省略标记")
            .isFalse();
        assertThat(body).matches(".*-\\d$");
      }
    }
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

  /** 与 await 相同，但等待上限更长，供需要跨多步验证的并发用例使用。 */
  private void awaitLong(CountDownLatch latch, long seconds) {
    try {
      if (!latch.await(seconds, TimeUnit.SECONDS))
        throw new AssertionError("timed out waiting for latch");
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
    /** 置为 true 时下一次 save 直接抛错，用于验证"落库失败不留下半成品会话"。 */
    final java.util.concurrent.atomic.AtomicBoolean failNextSave =
        new java.util.concurrent.atomic.AtomicBoolean(false);

    private RepositoryFixture() {
      when(repository.findById(any(String.class)))
          .thenAnswer(invocation -> Optional.ofNullable(records.get(invocation.getArgument(0))));
      when(repository.save(any(AiConversationSessionRecord.class)))
          .thenAnswer(
              invocation -> {
                AiConversationSessionRecord record = invocation.getArgument(0);
                if (failNextSave.compareAndSet(true, false)) {
                  throw new IllegalStateException("simulated repository failure");
                }
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
