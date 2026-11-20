package com.bachelor.toolbox.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Round 223 并发/竞态回归：登录失败节流的"检查-校验-记录"必须是一个原子准入过程。
 *
 * <p>修复前的公开接口只有 {@code isBlocked()} 与 {@code recordFailure()}。并发线程可以在任何失败被
 * 记录之前全部通过检查；随后才各写一次失败。在线实测 120 个并发错误口令请求中有 114 个进入密码校验，
 * 而配置阈值仅为 5。本测试直接锁定修复后的 {@code beginAttempt()} 准入语义。
 */
class LoginAttemptServiceConcurrencyTests {

  @Test
  void 并发认领尝试名额时不得突破失败阈值() throws Exception {
    LoginAttemptService service = new LoginAttemptService(5, 300);
    int callers = 128;
    ExecutorService pool = Executors.newFixedThreadPool(callers);
    CountDownLatch start = new CountDownLatch(1);
    List<Future<Boolean>> futures = new ArrayList<>();
    try {
      for (int i = 0; i < callers; i++) {
        futures.add(
            pool.submit(
                () -> {
                  start.await();
                  return service.beginAttempt("race-user", "127.0.0.1");
                }));
      }
      start.countDown();
      int admitted = 0;
      for (Future<Boolean> future : futures) {
        if (Boolean.TRUE.equals(future.get(10, TimeUnit.SECONDS))) {
          admitted++;
        }
      }
      assertThat(admitted)
          .as("并发准入必须被失败阈值约束，不能按线程数放大")
          .isEqualTo(5);
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void 并发登录流程最多只有阈值数量的请求进入密码校验() throws Exception {
    LoginAttemptService service = new LoginAttemptService(5, 300);
    int callers = 120;
    ExecutorService pool = Executors.newFixedThreadPool(callers);
    CountDownLatch start = new CountDownLatch(1);
    AtomicInteger credentialChecks = new AtomicInteger();
    List<Future<?>> futures = new ArrayList<>();
    try {
      for (int i = 0; i < callers; i++) {
        futures.add(
            pool.submit(
                () -> {
                  start.await();
                  if (service.beginAttempt("race-user-2", "127.0.0.1")) {
                    // 模拟 BCrypt/DB 查询耗时，放大原实现的竞态窗口。
                    credentialChecks.incrementAndGet();
                    Thread.sleep(20);
                    service.recordFailure("race-user-2", "127.0.0.1");
                  }
                  return null;
                }));
      }
      start.countDown();
      for (Future<?> future : futures) {
        future.get(10, TimeUnit.SECONDS);
      }
      assertThat(credentialChecks.get())
          .as("进入密码校验的并发请求数必须不超过失败阈值")
          .isLessThanOrEqualTo(5);
      assertThat(service.isBlocked("race-user-2", "127.0.0.1")).isTrue();
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void 取消认领会归还在途名额() {
    LoginAttemptService service = new LoginAttemptService(1, 300);

    assertThat(service.beginAttempt("admin", "127.0.0.1")).isTrue();
    assertThat(service.beginAttempt("admin", "127.0.0.1")).isFalse();

    service.cancelAttempt("admin", "127.0.0.1");

    assertThat(service.beginAttempt("admin", "127.0.0.1")).isTrue();
  }

  @Test
  void 成功登录会清除失败与在途名额() {
    LoginAttemptService service = new LoginAttemptService(2, 300);

    assertThat(service.beginAttempt("admin", "127.0.0.1")).isTrue();
    service.recordFailure("admin", "127.0.0.1");
    assertThat(service.beginAttempt("admin", "127.0.0.1")).isTrue();
    service.recordSuccess("admin", "127.0.0.1");

    assertThat(service.beginAttempt("admin", "127.0.0.1")).isTrue();
    assertThat(service.beginAttempt("admin", "127.0.0.1")).isTrue();
    assertThat(service.beginAttempt("admin", "127.0.0.1")).isFalse();
    service.cancelAttempt("admin", "127.0.0.1");
    service.cancelAttempt("admin", "127.0.0.1");
  }

  @Test
  void 旧调用方直接记录失败仍保持锁定语义() {
    LoginAttemptService service = new LoginAttemptService(3, 300);

    service.recordFailure("legacy", "127.0.0.1");
    service.recordFailure("legacy", "127.0.0.1");
    assertThat(service.isBlocked("legacy", "127.0.0.1")).isFalse();

    service.recordFailure("legacy", "127.0.0.1");
    assertThat(service.isBlocked("legacy", "127.0.0.1")).isTrue();
    assertThat(service.beginAttempt("legacy", "127.0.0.1")).isFalse();
  }
}
