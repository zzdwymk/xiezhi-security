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

  /** 当前是否处于锁定窗口内 */
  public boolean isBlocked(String username, String clientAddress) {
    Attempt attempt = attempts.get(key(username, clientAddress));
    if (attempt == null) {
      return false;
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
  public void recordFailure(String username, String clientAddress) {
    evictIfNeeded();
    Attempt attempt =
        attempts.computeIfAbsent(key(username, clientAddress), ignored -> new Attempt());
    attempt.touch();
    int failures = attempt.failures.incrementAndGet();
    if (failures >= maxAttempts) {
      attempt.lockedUntil = Instant.now().plus(lockDuration);
    }
  }

  /** 登录成功后清除计数 */
  public void recordSuccess(String username, String clientAddress) {
    attempts.remove(key(username, clientAddress));
  }

  /** 当前条目数（供测试与运维观测）。 */
  int size() {
    return attempts.size();
  }

  /**
   * 容量控制：先移除已过锁定窗口的陈旧条目；若仍超过上限，按最近访问时间淘汰最旧的一条，
   * 直到回落到上限以内。锁外调用，竞态下最多短暂多出少量条目，随后会被下一次写入收敛。
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
    // ② 仍超上限则按最近访问时间淘汰最旧
    while (attempts.size() >= MAX_ENTRIES) {
      attempts.entrySet().stream()
          .min(Comparator.comparingLong(entry -> entry.getValue().lastTouchedNanos))
          .map(Map.Entry::getKey)
          .ifPresent(attempts::remove);
    }
  }

  private String key(String username, String clientAddress) {
    return (username == null ? "" : username.trim().toLowerCase())
        + "@"
        + (clientAddress == null ? "" : clientAddress);
  }

  private static final class Attempt {
    private final AtomicInteger failures = new AtomicInteger();
    private volatile Instant lockedUntil;
    /** 最近一次访问的单调纳秒时间，用于 LRU 淘汰。 */
    private volatile long lastTouchedNanos = System.nanoTime();

    private void touch() {
      lastTouchedNanos = System.nanoTime();
    }
  }
}
