package com.bachelor.toolbox.task;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "security_tasks")
public class SecurityTask {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long targetId;

  @Column(nullable = false)
  private Long projectId;

  @Column(nullable = false, length = 50)
  private String toolCode;

  @Column(length = 64)
  private String ruleCode;

  @Column(length = 64)
  private String vulnerabilityCode;

  @Column(nullable = false, length = 30)
  private String status;

  @Column(nullable = false)
  private int progress;

  /**
   * Nullable for backward compatibility with databases created before live progress metadata
   * existed.
   */
  private Boolean progressDeterminate;

  private Long progressCompleted;
  private Long progressTotal;

  @Column(length = 500)
  private String progressMessage;

  private Instant progressUpdatedAt;

  @Lob private String requestJson;

  @Lob private String resultJson;

  @Lob private String executionLog;

  @Lob private String targetSnapshotJson;

  @Column(length = 200)
  private String allowedPortsSnapshot;

  @Lob private String authorizationStatementSnapshot;
  private Instant authorizationValidFromSnapshot;
  private Instant authorizationExpiresAtSnapshot;

  @Column(length = 500)
  private String toolVersionSnapshot;

  @Column(length = 64)
  private String ruleVersionSnapshot;

  @Column(length = 64)
  private String nucleiTemplateHashSnapshot;

  private Instant snapshotCapturedAt;

  @Column(length = 16)
  private String snapshotSchemaVersion;

  @Column(length = 64)
  private String authorizationSnapshotHash;

  private Long sourceTaskId;

  @Column(length = 32)
  private String terminationReason;

  private Instant timeoutAt;
  private Instant queueEnteredAt;
  private Instant queueStartedAt;

  @Column(length = 2000)
  private String errorMessage;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  private Instant startedAt;
  private Instant finishedAt;

  @PrePersist
  void prePersist() {
    createdAt = Instant.now();
  }
}
