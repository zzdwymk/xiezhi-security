package com.bachelor.toolbox.ai;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
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
@Table(name = "ai_agent_dispatches")
public class AiAgentDispatchRecord {
  @Id
  @Column(length = 64)
  private String idempotencyKey;

  @Column(nullable = false)
  private Long projectId;

  @Column(nullable = false)
  private Long targetId;

  @Column(nullable = false, length = 64)
  private String requestDigest;

  @Column(nullable = false, length = 1000)
  private String taskIds;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @PrePersist
  void prePersist() {
    createdAt = Instant.now();
  }
}
