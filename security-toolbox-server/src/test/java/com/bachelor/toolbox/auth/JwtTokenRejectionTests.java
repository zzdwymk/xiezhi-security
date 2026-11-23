package com.bachelor.toolbox.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * 第380轮：JWT 认证的拒绝面回归（单元层）。
 *
 * <p>审计 {@link JwtService} / {@link JwtAuthenticationFilter} / {@link LoginAttemptService} 未发现
 * 可复现缺陷（密钥强度、算法绑定、ver 版本、禁用用户、角色取库均已硬化并有既有测试）。本轮补充
 * 两条此前未被显式锁定的**拒绝**不变量：
 *
 * <ol>
 *   <li>{@code alg=none} 的无签名伪造令牌必须被拒绝（经典算法混淆/绕过手法）；
 *   <li>过期令牌必须被拒绝（exp 校验不能被绕过）。
 * </ol>
 */
@DisplayName("JWT 拒绝面回归（第380轮）")
class JwtTokenRejectionTests {

  private static final String SECRET = "r380-very-long-desktop-secret-value-0123456789";

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  @Test
  @DisplayName("alg=none 的无签名令牌不能被任何过滤器视为已认证")
  void algNoneTokenIsRejected() throws Exception {
    // {"alg":"none"} . {"sub":"admin","role":"ADMIN","ver":0,"exp":<far future>} . (空签名)
    String payload =
        "{\"sub\":\"admin\",\"role\":\"ADMIN\",\"ver\":0,\"exp\":4102444800}";
    String forged =
        java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8))
            + "."
            + java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8))
            + ".";

    JwtService jwtService = new JwtService(SECRET, 60, false);
    assertThatThrownBy(() -> jwtService.parse(forged)).isInstanceOf(JwtException.class);

    // 过滤器层同样不得认证
    UserRepository users = mock(UserRepository.class);
    when(users.findByUsername(any())).thenReturn(Optional.of(new User()));
    JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtService, users);
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader("Authorization")).thenReturn("Bearer " + forged);
    filter.doFilterInternal(request, mock(HttpServletResponse.class), mock(FilterChain.class));
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  @Test
  @DisplayName("过期令牌必须被拒绝")
  void expiredTokenIsRejected() {
    // minutes=0 → exp 等于签发时刻，解析时即已过期
    JwtService jwtService = new JwtService(SECRET, 0, false);
    User user = new User();
    user.setUsername("admin");
    user.setRole("ADMIN");
    user.setEnabled(true);
    String token = jwtService.createToken(user);

    assertThatThrownBy(() -> jwtService.parse(token)).isInstanceOf(JwtException.class);
  }

  @Test
  @DisplayName("签名被篡改的令牌必须被拒绝（有效令牌仍可用作对照）")
  void tamperedSignatureIsRejected() {
    JwtService jwtService = new JwtService(SECRET, 60, false);
    User user = new User();
    user.setUsername("admin");
    user.setRole("ADMIN");
    user.setEnabled(true);
    String token = jwtService.createToken(user);
    assertThat(jwtService.parse(token).getSubject()).isEqualTo("admin");

    String tampered = token.substring(0, token.length() - 2) + (token.endsWith("A") ? "BB" : "AA");
    assertThatThrownBy(() -> jwtService.parse(tampered)).isInstanceOf(JwtException.class);
  }
}
