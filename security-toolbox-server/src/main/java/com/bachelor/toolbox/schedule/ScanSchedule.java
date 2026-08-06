package com.bachelor.toolbox.schedule;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
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
@Table(name = "scan_schedules")
public class ScanSchedule {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long targetId;

  @Column(nullable = false)
  private Long projectId;

  @Column(nullable = false, length = 50)
  private String toolCode;

  @Lob private String parametersJson;

  @Column(length = 120)
  private String cronExpression;

  private Long intervalSeconds;

  @Column(nullable = false)
  private boolean enabled = true;

  private Instant nextRunAt;
  private Instant lastRunAt;
  private Long lastTaskId;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @PrePersist
  void init() {
    createdAt = Instant.now();
  }
}
