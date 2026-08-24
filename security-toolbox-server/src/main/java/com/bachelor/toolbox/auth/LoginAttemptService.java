package com.bachelor.toolbox.auth;

import java.time.Duration;
import java.time.Instant;
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
 */
@Service
public class LoginAttemptService {
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
    Attempt attempt =
        attempts.computeIfAbsent(key(username, clientAddress), ignored -> new Attempt());
    int failures = attempt.failures.incrementAndGet();
    if (failures >= maxAttempts) {
      attempt.lockedUntil = Instant.now().plus(lockDuration);
    }
  }

  /** 登录成功后清除计数 */
  public void recordSuccess(String username, String clientAddress) {
    attempts.remove(key(username, clientAddress));
  }

  private String key(String username, String clientAddress) {
    return (username == null ? "" : username.trim().toLowerCase())
        + "@"
        + (clientAddress == null ? "" : clientAddress);
  }

  private static final class Attempt {
    private final AtomicInteger failures = new AtomicInteger();
    private volatile Instant lockedUntil;
  }
}
