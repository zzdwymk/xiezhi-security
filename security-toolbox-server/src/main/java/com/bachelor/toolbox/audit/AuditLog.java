package com.bachelor.toolbox.audit;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "audit_logs")
public class AuditLog {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 100)
  private String action;

  @Column(nullable = false, length = 50)
  private String resourceType;

  private String resourceId;

  @Column(length = 100)
  private String operator;

  @Column(length = 100)
  private String operatorRoles;

  @Column(length = 64)
  private String sourceIp;

  @Column(length = 36)
  private String requestId;

  private Long relatedTaskId;

  @Column(length = 64)
  private String authorizationSnapshotHash;

  @Lob private String detail;

  @Column(nullable = false, length = 30)
  private String result;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @PrePersist
  void prePersist() {
    createdAt = Instant.now();
  }
}
