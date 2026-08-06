package com.bachelor.toolbox.postscan;

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
@Table(name = "post_scan_paths")
public class PostScanPath {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long targetId;

  @Column(name = "project_id")
  private Long projectId;

  @Lob
  @Column(nullable = false)
  private String sourceFindingIdsJson;
  @Lob
  @Column(nullable = false)
  private String documentJson;

  @Column(nullable = false, length = 64)
  private String authorizationSnapshot;

  @Column(nullable = false, length = 32)
  private String status = "DRAFT";

  @Column(nullable = false, length = 40)
  private String provider;

  @Column(length = 120)
  private String model;

  @Column(nullable = false, length = 2000)
  private String summary;

  @Column(nullable = false)
  private Instant expiresAt;

  @Lob private String taskIdsJson;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  private Instant confirmedAt;

  @PrePersist
  void prePersist() {
    createdAt = Instant.now();
  }
}
