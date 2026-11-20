package com.bachelor.toolbox.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * 登录失败节流。
 *
 * <p>后端仅监听回环地址并不等于免疫爆破——本机任意进程都可以反复尝试登录。
 * 此处按「用户名 + 来源地址」计数，连续失败达到阈值后进入锁定窗口，
 * 锁定期间即使密码正确也直接拒绝，从而把离线爆破的速率压到不可用。
 *
 * <p>状态保存在内存中：本系统为单机桌面部署，重启即清空是可接受的取舍，
 * 不引入额外存储依赖。
 *
 * <h2>容量上限（Round 14 修复：内存耗尽 DoS）</h2>
 *
 * <p>条目以「用户名@来源地址」为键；对每个<strong>新用户名</strong>的首次失败都会新增一条记录。
 * 若攻击者（或本机任意进程）用海量不同用户名发起失败登录，而条目无上限且仅"锁定过期后惰性删除"，
 * 未达阈值、也不再重试的条目会<strong>永久驻留</strong> → 内存持续增长直至 OOM。
 * 因此这里强制容量上限 {@value #MAX_ENTRIES}：每次写入前先清理"已过期"条目，
 * 仍超上限则按最近访问时间淘汰最旧条目（LRU），保证内存有界、不影响正常节流语义。
 */
@Service
public class LoginAttemptService {
  /** 条目容量上限，防止海量用户名把内存撑爆。 */
  static final int MAX_ENTRIES = 10_000;

  private final int maxAttempts;
  private final Duration lockDuration;
  private final Map<String, Attempt> attempts = new ConcurrentHashMap<>();

  public LoginAttemptService(
      @Value("${toolbox.security.login.max-attempts:5}") int maxAttempts,
      @Value("${toolbox.security.login.lock-seconds:300}") long lockSeconds) {
    this.maxAttempts = Math.max(1, maxAttempts);
    this.lockDuration = Duration.ofSeconds(Math.max(1, lockSeconds));
  }

  /**
   * 在密码校验前原子认领一个尝试名额。
   *
   * <p>原实现由调用方先 {@link #isBlocked} 再校验密码、最后 {@link #recordFailure}。这三步不在同一
   * 临界区，并发请求会在任何失败被记录之前全部通过 {@code isBlocked}，从而把失败阈值放大到并发数
   * （实测 120 个并发请求中有 114 个进入密码校验，而阈值只有 5）。这里把"检查是否锁定 + 占用名额"
   * 合并为一个同步操作：失败次数与在途尝试次数之和达到阈值后直接拒绝，未完成的尝试通过
   * {@link #recordFailure} 或 {@link #cancelAttempt} 释放名额。
   *
   * @return true 表示可以继续做凭据校验；false 表示已被限流或锁定，调用方不得再查库/校验密码
   */
  public synchronized boolean beginAttempt(String username, String clientAddress) {
    String attemptKey = key(username, clientAddress);
    Instant now = Instant.now();
    Attempt attempt = attempts.get(attemptKey);
    if (attempt != null && attempt.lockedUntil != null) {
      if (now.isAfter(attempt.lockedUntil)) {
        attempts.remove(attemptKey, attempt);
        attempt = null;
      } else {
        attempt.touch();
        return false;
      }
    }
    if (attempt == null) {
      evictIfNeeded();
      if (attempts.size() >= MAX_ENTRIES) {
        return false;
      }
      attempt = attempts.computeIfAbsent(attemptKey, ignored -> new Attempt());
    }
    attempt.touch();
    // synchronized 保证 failures 与 inFlight 的组合判断和自增对所有登录线程是原子的。
    if (attempt.failures.get() + attempt.inFlight.get() >= maxAttempts) {
      return false;
    }
    attempt.inFlight.incrementAndGet();
    return true;
  }

  /** 当前是否处于锁定窗口内 */
  public synchronized boolean isBlocked(String username, String clientAddress) {
    Attempt attempt = attempts.get(key(username, clientAddress));
    if (attempt == null) {
      evictIfNeeded();
      // All remaining entries may be actively locked. Fail closed for a new key rather
      // than evicting another account's lock or creating untracked authentication attempts.
      return attempts.size() >= MAX_ENTRIES;
    }
    attempt.touch();
    if (attempt.lockedUntil == null) {
      return false;
    }
    if (Instant.now().isAfter(attempt.lockedUntil)) {
      // 锁定窗口已过，清除记录，重新开始计数
      attempts.remove(key(username, clientAddress));
      return false;
    }
    return true;
  }

  /** 剩余锁定秒数，用于提示用户 */
  public long remainingLockSeconds(String username, String clientAddress) {
    Attempt attempt = attempts.get(key(username, clientAddress));
    if (attempt == null || attempt.lockedUntil == null) {
      return 0;
    }
    long seconds = Duration.between(Instant.now(), attempt.lockedUntil).toSeconds();
    return Math.max(0, seconds);
  }

  /** 记录一次失败；达到阈值后进入锁定 */
  public synchronized void recordFailure(String username, String clientAddress) {
    String attemptKey = key(username, clientAddress);
    Attempt attempt = attempts.get(attemptKey);
    if (attempt == null) {
      evictIfNeeded();
      if (attempts.size() >= MAX_ENTRIES) return;
      attempt = attempts.computeIfAbsent(attemptKey, ignored -> new Attempt());
    }
    attempt.touch();
    // beginAttempt 已认领名额时先归还；直接调用 recordFailure 的旧调用方没有认领，inFlight==0。
    if (attempt.inFlight.get() > 0) {
      attempt.inFlight.decrementAndGet();
    }
    int failures = attempt.failures.incrementAndGet();
    if (failures >= maxAttempts) {
      attempt.lockedUntil = Instant.now().plus(lockDuration);
    }
  }

  /**
   * 凭据校验过程发生非失败类异常时归还名额，不增加失败次数。
   *
   * <p>例如数据库暂时不可用；若不归还，认领的名额会被永久占用并逐步收紧节流窗口。
   */
  public synchronized void cancelAttempt(String username, String clientAddress) {
    String attemptKey = key(username, clientAddress);
    Attempt attempt = attempts.get(attemptKey);
    if (attempt == null) {
      return;
    }
    if (attempt.inFlight.get() > 0) {
      attempt.inFlight.decrementAndGet();
    }
    attempt.touch();
    if (attempt.failures.get() == 0 && attempt.inFlight.get() == 0) {
      attempts.remove(attemptKey, attempt);
    }
  }

  /** 登录成功后清除计数 */
  public synchronized void recordSuccess(String username, String clientAddress) {
    attempts.remove(key(username, clientAddress));
  }

  /** 当前条目数（供测试与运维观测）。 */
  int size() {
    return attempts.size();
  }

  /**
   * 容量控制：在服务监视器内调用，先移除过期锁，再淘汰未锁定的最旧条目。
   * 活跃锁不能因用户名轮换被删除；若全为活跃锁，则新键在 isBlocked 中被拒绝。
   */
  private void evictIfNeeded() {
    if (attempts.size() < MAX_ENTRIES) {
      return;
    }
    Instant now = Instant.now();
    // ① 清理已过期（锁定窗口已过）的条目
    attempts.entrySet().removeIf(entry -> {
      Instant lockedUntil = entry.getValue().lockedUntil;
      return lockedUntil != null && now.isAfter(lockedUntil);
    });
    // Active lockouts are security state, not expendable cache entries.
    while (attempts.size() >= MAX_ENTRIES) {
      String oldestUnlocked = attempts.entrySet().stream()
          .filter(entry -> entry.getValue().lockedUntil == null)
          .filter(entry -> entry.getValue().inFlight.get() == 0)
          .min(Comparator.comparingLong(entry -> entry.getValue().lastTouchedNanos))
          .map(Map.Entry::getKey)
          .orElse(null);
      if (oldestUnlocked == null) return;
      attempts.remove(oldestUnlocked);
    }
  }

  private String key(String username, String clientAddress) {
    return (username == null ? "" : username.trim().toLowerCase())
        + "@"
        + (clientAddress == null ? "" : clientAddress);
  }

  private static final class Attempt {
    private final AtomicInteger failures = new AtomicInteger();
    /** 已通过 beginAttempt 认领、但尚未以成功/失败结束的在途凭据校验数。 */
    private final AtomicInteger inFlight = new AtomicInteger();
    private volatile Instant lockedUntil;
    /** 最近一次访问的单调纳秒时间，用于 LRU 淘汰。 */
    private volatile long lastTouchedNanos = System.nanoTime();

    private void touch() {
      lastTouchedNanos = System.nanoTime();
    }
  }
}
