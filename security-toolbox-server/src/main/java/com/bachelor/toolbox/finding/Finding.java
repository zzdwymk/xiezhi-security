package com.bachelor.toolbox.finding;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "findings")
public class Finding {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long taskId;

  @Column(nullable = false)
  private Long targetId;

  /** Derived from the source task for client-side project binding; not persisted. */
  @Transient private Long projectId;
  @Column(nullable = false, length = 300)
  private String title;

  @Column(nullable = false, length = 20)
  private String severity;

  @Column(nullable = false, length = 50)
  private String sourceTool;

  @Column(length = 64)
  private String ruleCode;

  @Column(length = 64)
  private String vulnerabilityCode;

  @Column(nullable = false, length = 30)
  private String status = "OPEN";

  @Lob private String description;

  @Lob private String evidence;

  @Lob private String remediation;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @PrePersist
  void prePersist() {
    createdAt = Instant.now();
  }
}
