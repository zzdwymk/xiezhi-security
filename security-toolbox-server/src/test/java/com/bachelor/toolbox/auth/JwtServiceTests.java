package com.bachelor.toolbox.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class JwtServiceTests {
  @Test
  void rejectsFixedDevelopmentSecretWithoutExplicitOptIn() {
    assertThatThrownBy(() -> new JwtService(JwtService.DEVELOPMENT_SECRET, 120, false))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("默认 JWT 密钥已禁用，请将 JWT_SECRET 设置为高强度密钥");
  }

  @Test
  void allowsFixedDevelopmentSecretOnlyWithExplicitOptIn() {
    JwtService service = new JwtService(JwtService.DEVELOPMENT_SECRET, 120, true);
    assertThat(service.expirationSeconds()).isEqualTo(7200);
  }

  @Test
  void acceptsHighEntropyDesktopSecret() {
    JwtService service =
        new JwtService(
            "BbYwWVmT-3Z8I0j2hD-zmeNbRhVSNHUaoPgvYQBX3WRjm_i6-sg3BElBdlqsuNuG", 30, false);
    assertThat(service.expirationSeconds()).isEqualTo(1800);
  }

  @Test
  void rejectsSecretShorterThan32Bytes() {
    assertThatThrownBy(() -> new JwtService("short-secret", 120, false))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("JWT_SECRET 的 UTF-8 编码长度不得少于 32 字节");
  }
}
