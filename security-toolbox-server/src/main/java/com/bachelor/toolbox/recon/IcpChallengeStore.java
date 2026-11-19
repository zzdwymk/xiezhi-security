package com.bachelor.toolbox.recon;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Short-lived in-memory store for manual MIIT point-challenge sessions. A pending challenge holds
 * the opaque auth token, the secret key and the client uid on the server side so they are never
 * exposed to the browser; only the operator's clicked coordinates are submitted back later.
 */
@Component
public class IcpChallengeStore {

  private static final Duration TTL = Duration.ofMinutes(10);
  /**
   * 硬上限（Round 29，纵深防御）：即便攻击者/操作者在 TTL 窗口内反复调用 /captcha 触发 register，
   * 也保证内存中未消费挑战条目数封顶，避免无界增长（每条目持有 MIIT token/密钥/图片字节）。
   * 超出时按注册时间最早优先淘汰（近似 LRU，按插入序驱逐）。
   */
  private static final int MAX_ENTRIES = 500;

  private final ConcurrentHashMap<String, Entry> store = new ConcurrentHashMap<>();
  private final Clock clock;

  public IcpChallengeStore() { this(Clock.systemUTC()); }

  IcpChallengeStore(Clock clock) { this.clock = java.util.Objects.requireNonNull(clock); }

  public synchronized String register(MiitIcpClient.PendingCaptcha pending) {
    purge();
    if (store.size() >= MAX_ENTRIES) {
      evictOldest();
    }
    String id = UUID.randomUUID().toString();
    Instant now = clock.instant();
    store.put(id, new Entry(pending, now, now.plus(TTL)));
    return id;
  }

  /** 淘汰注册时间最早的一条（条目数已达上限时调用）。 */
  private void evictOldest() {
    String oldestKey = null;
    Instant oldest = null;
    for (var e : store.entrySet()) {
      Instant at = e.getValue().registeredAt();
      if (oldest == null || at.isBefore(oldest)) {
        oldest = at;
        oldestKey = e.getKey();
      }
    }
    if (oldestKey != null) {
      store.remove(oldestKey);
    }
  }

  /**
   * Removes and returns the pending challenge for the given id, or {@code null} if it is unknown
   * or has expired. A challenge can be consumed only once.
   */
  public MiitIcpClient.PendingCaptcha take(String challengeId) {
    if (challengeId == null) {
      return null;
    }
    purge();
    Entry entry = store.remove(challengeId);
    // purge and remove are separate operations; time can cross the deadline
    // between them. Validate the entry again at the actual consumption boundary.
    return entry == null || !entry.expiresAt().isAfter(clock.instant()) ? null : entry.pending();
  }

  private void purge() {
    Instant now = clock.instant();
    store.entrySet().removeIf(e -> !e.getValue().expiresAt().isAfter(now));
  }

  private record Entry(MiitIcpClient.PendingCaptcha pending, Instant registeredAt, Instant expiresAt) {}
}