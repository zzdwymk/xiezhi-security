package com.bachelor.toolbox.project;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(
    name = "assessment_project_targets",
    uniqueConstraints = @UniqueConstraint(columnNames = {"projectId", "targetId"}))
public class ProjectTarget {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long projectId;

  @Column(nullable = false)
  private Long targetId;

  @Column(nullable = false, updatable = false)
  private Instant addedAt;

  public ProjectTarget(Long projectId, Long targetId) {
    this.projectId = projectId;
    this.targetId = targetId;
  }

  @PrePersist
  void prePersist() {
    addedAt = Instant.now();
  }
}
