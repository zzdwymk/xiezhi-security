package com.bachelor.toolbox.ai;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Internal outbox for a read-only Agent continuation after asynchronous tasks finish.
 *
 * <p>This is deliberately not a user-facing Ledger console and contains no prompt, evidence
 * body, model reasoning, credentials, or bearer recovery token. It stores only the immutable
 * identity and Ledger anchor needed to revalidate a continuation.
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(
    name = "ai_conversation_tombstones",
    uniqueConstraints = {
      @UniqueConstraint(
          name = "uk_tombstone_runtime_node", columnNames = {"runId", "nodeRunId"}),
      @UniqueConstraint(
          name = "uk_tombstone_turn_workflow",
          columnNames = {"projectId", "targetId", "turnId", "workflowDigest"})
    },
    indexes = {
      @Index(name = "idx_tombstone_scope_status", columnList = "projectId,targetId,status"),
      @Index(name = "idx_tombstone_status_due", columnList = "status,nextAttemptAt")
    })
public class ConversationTombstone {
  public static final String WAITING_TASKS = "WAITING_TASKS";
  public static final String PROCESSING = "PROCESSING";
  public static final String CONTINUED = "CONTINUED";
  public static final String SKIPPED = "SKIPPED";
  public static final String STALE = "STALE";
  public static final String FAILED = "FAILED";

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long projectId;

  @Column(nullable = false)
  private Long targetId;

  @Column(nullable = false, length = 80)
  private String runId;

  @Column(nullable = false, length = 160)
  private String nodeRunId;

  @Column(nullable = false, length = 64)
  private String sessionId;

  @Column(nullable = false, length = 80)
  private String turnId;

  @Column(nullable = false, length = 120)
  private String workflowId;

  @Column(nullable = false)
  private long workflowRevision;

  @Column(nullable = false, length = 71)
  private String workflowDigest;

  @Column(nullable = false, length = 80)
  private String outerNodeId;

  @Column(nullable = false, length = 80)
  private String policyRevision;

  @Column(nullable = false)
  private long ledgerSequence;

  @Column(nullable = false, length = 71)
  private String ledgerHeadDigest;

  @Column(nullable = false, length = 71)
  private String requestDigest;

  @Column(nullable = false, length = 1200)
  private String pendingTaskIdsJson;

  @Column(nullable = false, length = 32)
  private String status;

  @Column(nullable = false)
  private int attempt;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @Column(nullable = false)
  private Instant updatedAt;

  private Instant nextAttemptAt;
  private Instant processingStartedAt;
  private Instant continuedAt;

  @Column(length = 500)
  private String lastError;

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
