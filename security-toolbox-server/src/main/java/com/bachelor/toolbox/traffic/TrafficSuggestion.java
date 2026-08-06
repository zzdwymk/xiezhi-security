package com.bachelor.toolbox.traffic;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "traffic_suggestions")
public class TrafficSuggestion {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true)
  private Long packetId;

  @Column(nullable = false)
  private Long targetId;

  @Column(nullable = false, length = 20)
  private String source = "LOCAL_RULE";

  @Column(nullable = false, length = 16)
  private String severity = "INFO";

  @Column(nullable = false, length = 300)
  private String title;

  @Lob private String summary;
  @Lob private String reason;

  @Column(nullable = false)
  private double confidence;

  @Column(nullable = false, length = 64)
  private String actionType;

  @Column(length = 64)
  private String toolCode;

  @Column(nullable = false)
  private boolean requiresConfirmation = true;

  @Column(nullable = false, length = 20)
  private String status = "PENDING";

  private Long taskId;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  private Instant decidedAt;

  @PrePersist
  void prePersist() {
    createdAt = Instant.now();
  }
}
