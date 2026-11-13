package com.bachelor.toolbox.auth;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Set;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 登录凭据长度上限校验——Round 32。
 *
 * <p>背景：{@code LoginRequest} 原仅 {@code @NotBlank}，无 {@code @Size}。超大用户名/密码
 * （Round 25 已限 32MB 请求体，仍可容纳数千万字符）会进入 {@code findByUsername} 的 DB 查询、
 * BCrypt 比对与 LoginAttemptService 限流键，造成内存/DB 放大。本测试锁定超长凭据在参数校验阶段被拒。
 */
@DisplayName("登录凭据长度上限（Round 32）")
class LoginRequestValidationTests {
  private static ValidatorFactory factory;
  private static Validator validator;

  @BeforeAll
  static void setUp() {
    factory = Validation.buildDefaultValidatorFactory();
    validator = factory.getValidator();
  }

  @AfterAll
  static void tearDown() {
    if (factory != null) factory.close();
  }

  private static Set<ConstraintViolation<LoginRequest>> validate(String u, String p) {
    return validator.validate(new LoginRequest(u, p));
  }

  @Test
  @DisplayName("LR-1 超长用户名(>100) → 校验失败")
  void rejectsLongUsername() {
    assertThat(validate("a".repeat(101), "pw")).isNotEmpty();
  }

  @Test
  @DisplayName("LR-2 超长密码(>128) → 校验失败")
  void rejectsLongPassword() {
    assertThat(validate("admin", "p".repeat(129))).isNotEmpty();
  }

  @Test
  @DisplayName("LR-3 正常凭据 → 通过")
  void allowsNormalCredentials() {
    assertThat(validate("admin", "StrongPass123")).isEmpty();
  }
}
