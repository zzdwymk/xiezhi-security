package com.bachelor.toolbox.operation;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "security_actions")
public class SecurityAction {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long projectId;

  @Column(nullable = false)
  private Long targetId;

  private Long findingId;

  @Column(nullable = false, length = 40)
  private String category;

  @Column(nullable = false, length = 200)
  private String title;

  @Column(nullable = false, length = 4000)
  private String purpose;

  @Column(nullable = false, length = 30)
  private String riskLevel;

  @Column(nullable = false)
  private boolean nonDestructive = true;

  @Column(nullable = false)
  private boolean lateralMovement = false;

  @Column(nullable = false, length = 4000)
  private String executionPlan;

  @Column(nullable = false, length = 4000)
  private String rollbackPlan;

  @Column(nullable = false)
  private Instant windowStart;

  @Column(nullable = false)
  private Instant windowEnd;

  @Column(nullable = false, length = 30)
  private String status = "PENDING_APPROVAL";

  @Column(nullable = false, length = 100)
  private String requestedBy;

  private String approvedBy;
  private Instant approvedAt;
  private Instant startedAt;
  private Instant finishedAt;

  @Column(length = 4000)
  private String terminationReason;

  @Column(length = 8000)
  private String evidence;

  @Column(length = 4000)
  private String rollbackEvidence;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @PrePersist
  void created() {
    createdAt = Instant.now();
  }
}
