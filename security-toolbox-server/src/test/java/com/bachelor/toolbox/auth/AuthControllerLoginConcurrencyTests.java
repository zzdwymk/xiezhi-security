package com.bachelor.toolbox.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Round 223：从真实 Controller 业务入口验证登录节流的并发准入。
 *
 * <p>只允许阈值数量的并发请求进入用户查询与密码比对；其余请求必须直接收到限流错误。
 */
class AuthControllerLoginConcurrencyTests {

  @Test
  void 并发登录只允许阈值内的请求查询用户与校验密码() throws Exception {
    LoginAttemptService attempts = new LoginAttemptService(5, 300);
    UserRepository users = mock(UserRepository.class);
    AtomicInteger lookups = new AtomicInteger();
    when(users.findByUsername(anyString()))
        .thenAnswer(
            ignored -> {
              lookups.incrementAndGet();
              return Optional.empty();
            });
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");

    AuthController controller =
        new AuthController(
            users,
            mock(PasswordEncoder.class),
            mock(JwtService.class),
            attempts,
            mock(AuditService.class));

    int callers = 80;
    ExecutorService pool = Executors.newFixedThreadPool(callers);
    CountDownLatch start = new CountDownLatch(1);
    List<Future<?>> futures = new ArrayList<>();
    try {
      for (int i = 0; i < callers; i++) {
        futures.add(
            pool.submit(
                () -> {
                  start.await();
                  try {
                    controller.login(
                        new LoginRequest("controller-race-user", "wrong-password"), request);
                  } catch (RuntimeException expected) {
                    // 预期为 BadCredentialsException（前 5 次）或 ApiException（限流）。
                  }
                  return null;
                }));
      }
      start.countDown();
      for (Future<?> future : futures) {
        future.get(10, TimeUnit.SECONDS);
      }
    } finally {
      pool.shutdownNow();
    }

    assertThat(lookups.get())
        .as("并发请求中只有阈值内的请求可以进入用户查询/密码校验")
        .isEqualTo(5);
  }

  @Test
  void 并发请求最多执行阈值次密码比对() throws Exception {
    LoginAttemptService attempts = new LoginAttemptService(5, 300);
    User user = new User();
    user.setId(1L);
    user.setUsername("slow-bcrypt-user");
    user.setPasswordHash("$2a$10$not-a-real-hash");
    user.setRole("ADMIN");
    user.setEnabled(true);

    UserRepository users = mock(UserRepository.class);
    when(users.findByUsername(anyString())).thenReturn(Optional.of(user));
    AtomicInteger passwordChecks = new AtomicInteger();
    PasswordEncoder encoder = mock(PasswordEncoder.class);
    when(encoder.matches(anyString(), anyString()))
        .thenAnswer(
            ignored -> {
              passwordChecks.incrementAndGet();
              // 模拟 BCrypt 的耗时，放大"先检查后记录失败"的竞态窗口。
              Thread.sleep(25);
              return false;
            });

    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    AuthController controller =
        new AuthController(users, encoder, mock(JwtService.class), attempts, mock(AuditService.class));

    int callers = 80;
    ExecutorService pool = Executors.newFixedThreadPool(callers);
    CountDownLatch start = new CountDownLatch(1);
    List<Future<?>> futures = new ArrayList<>();
    try {
      for (int i = 0; i < callers; i++) {
        futures.add(
            pool.submit(
                () -> {
                  start.await();
                  try {
                    controller.login(
                        new LoginRequest("slow-bcrypt-user", "wrong-password"), request);
                  } catch (RuntimeException expected) {
                    // 预期为 BadCredentialsException（前 5 次）或 ApiException（限流）。
                  }
                  return null;
                }));
      }
      start.countDown();
      for (Future<?> future : futures) {
        future.get(15, TimeUnit.SECONDS);
      }
    } finally {
      pool.shutdownNow();
    }

    assertThat(passwordChecks.get())
        .as("并发请求最多只能执行失败阈值次密码比对")
        .isEqualTo(5);
  }
}
