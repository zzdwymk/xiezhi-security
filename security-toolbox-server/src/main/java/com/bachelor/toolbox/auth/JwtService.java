package com.bachelor.toolbox.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
  static final String DEVELOPMENT_SECRET = "development-only-jwt-secret-change-me-32-bytes";

  private final SecretKey key;
  private final long expirationSeconds;

  public JwtService(
      @Value("${toolbox.auth.jwt-secret}") String secret,
      @Value("${toolbox.auth.jwt-expiration-minutes}") long minutes,
      @Value("${toolbox.auth.allow-insecure-development-credentials:false}")
          boolean allowInsecureDevelopmentCredentials) {
    if (DEVELOPMENT_SECRET.equals(secret) && !allowInsecureDevelopmentCredentials) {
      throw new IllegalArgumentException("默认 JWT 密钥已禁用，请将 JWT_SECRET 设置为高强度密钥");
    }
    if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
      throw new IllegalArgumentException("JWT_SECRET 的 UTF-8 编码长度不得少于 32 字节");
    }
    key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    expirationSeconds = minutes * 60;
  }

  public String createToken(User user) {
    Instant now = Instant.now();
    return Jwts.builder()
        .subject(user.getUsername())
        .claim("role", user.getRole())
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusSeconds(expirationSeconds)))
        .signWith(key)
        .compact();
  }

  public Claims parse(String token) {
    return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
  }

  public long expirationSeconds() {
    return expirationSeconds;
  }
}
