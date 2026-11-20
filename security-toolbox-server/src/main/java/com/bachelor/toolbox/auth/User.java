package com.bachelor.toolbox.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
@Table(name = "app_users")
@Getter
@Setter
@NoArgsConstructor
public class User implements UserDetails {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true, length = 64)
  private String username;

  @com.fasterxml.jackson.annotation.JsonIgnore
  @Column(nullable = false)
  private String passwordHash;

  @Column(nullable = false, length = 32)
  private String role;

  @Column(nullable = false)
  private boolean enabled = true;

  /**
   * 令牌版本号。修改密码/重置密码时递增，旧 JWT 的 {@code ver} 声明会因此不再匹配。
   *
   * <p>使用可空包装类型是为了兼容旧数据库：新增列时既有行可为 NULL，读取时按 0 处理。
   */
  @com.fasterxml.jackson.annotation.JsonIgnore
  @Column
  private Long tokenVersion = 0L;

  @Column(nullable = false, updatable = false)
  private Instant createdAt = Instant.now();

  @com.fasterxml.jackson.annotation.JsonIgnore
  @Override
  public String getPassword() {
    return passwordHash;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    if (role == null || role.isBlank()) return List.of();
    return List.of(new SimpleGrantedAuthority("ROLE_" + role));
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }
}
