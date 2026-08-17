package com.bachelor.toolbox.ai;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Durable execution receipt for one read-only continuation turn.
 *
 * <p>The receipt is intentionally separate from the tombstone lifecycle. The tombstone tells us
 * whether task callbacks are ready; this row tells us whether the deterministic continuation turn
 * has already produced a response. A committed {@code STARTED} row is an execution fence: after a
 * process crash the worker must not call the model again because the outcome is unknown.
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(
    name = "ai_continuation_executions",
    uniqueConstraints = {
      @UniqueConstraint(name = "uk_continuation_execution_tombstone", columnNames = "tombstoneId"),
      @UniqueConstraint(name = "uk_continuation_execution_turn", columnNames = "continuationTurnId")
    },
    indexes = {
      @Index(name = "idx_continuation_execution_status", columnList = "status,updatedAt")
    })
public class AgentContinuationExecution {
  public static final String STARTED = "STARTED";
  public static final String COMPLETED = "COMPLETED";
  public static final String SKIPPED = "SKIPPED";
  public static final String ABANDONED = "ABANDONED";

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true)
  private Long tombstoneId;

  @Column(nullable = false, length = 80, unique = true)
  private String continuationTurnId;

  @Column(nullable = false, length = 71)
  private String requestDigest;

  @Column(nullable = false, length = 20)
  private String status;

  @Lob private String responseJson;

  @Column(length = 71)
  private String responseDigest;

  @Column(length = 500)
  private String reason;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @Column(nullable = false)
  private Instant updatedAt;

  private Instant completedAt;

  @jakarta.persistence.Version private long version;

  @PrePersist
  void prePersist() {
    Instant now = Instant.now();
    createdAt = now;
    updatedAt = now;
  }

  @PreUpdate
  void preUpdate() {
    updatedAt = Instant.now();
  }
}
