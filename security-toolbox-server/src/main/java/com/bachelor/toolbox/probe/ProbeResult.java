package com.bachelor.toolbox.probe;

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
@Table(name = "probe_results")
public class ProbeResult {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long projectId;

  @Column(nullable = false)
  private Long targetId;

  private String url;

  @Column(length = 2000)
  private String technologies;

  private String server;
  private String framework;
  private String waf;

  @Column(length = 5000)
  private String evidence;

  @Column(nullable = false)
  private Instant detectedAt;

  @PrePersist
  void prePersist() {
    detectedAt = Instant.now();
  }
}
