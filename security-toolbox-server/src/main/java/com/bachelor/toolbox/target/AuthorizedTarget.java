package com.bachelor.toolbox.target;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "authorized_targets")
public class AuthorizedTarget {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 100)
  private String name;

  @Column(nullable = false, length = 500)
  private String targetValue;

  @Column(nullable = false, length = 20)
  private String targetType;

  @Column(nullable = false, length = 2000)
  private String authorizationNote;

  @Column(nullable = false, length = 200)
  private String allowedPorts = "80,443,3000,8080";

  @Column(nullable = false)
  private boolean enabled = true;

  private Instant authorizationValidFrom;

  private Instant authorizationExpiresAt;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @PrePersist
  void prePersist() {
    createdAt = Instant.now();
  }
}
