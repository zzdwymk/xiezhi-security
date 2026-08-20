package com.bachelor.toolbox.task;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
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
@Table(
    name = "workflow_runs",
    indexes = {
      @Index(name = "idx_workflow_runs_project_created", columnList = "project_id, created_at"),
      @Index(name = "idx_workflow_runs_status", columnList = "status, id")
    })
public class WorkflowRun {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long projectId;

  @Column(nullable = false)
  private Long targetId;

  @Column(nullable = false, length = 36)
  private String workflowId;

  @Column(nullable = false)
  private Long workflowRevision;

  @Column(nullable = false, length = 71)
  private String workflowDigest;

  @Lob
  @Column(nullable = false)
  private String specJson;

  @Column(nullable = false, length = 24)
  private String status;

  @Column(nullable = false)
  private int progress;

  @Column(length = 1000)
  private String message;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  private Instant startedAt;
  private Instant finishedAt;
  private Instant clearedAt;

  @PrePersist
  void init() {
    createdAt = Instant.now();
  }
}
