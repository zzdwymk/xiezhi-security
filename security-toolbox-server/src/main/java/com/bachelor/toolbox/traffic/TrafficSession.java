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
@Table(name = "traffic_sessions")
public class TrafficSession {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long targetId;

  @Column(nullable = false, length = 100)
  private String name;

  @Column(nullable = false, length = 20)
  private String status;

  @Column(nullable = false)
  private int listenPort;

  @Column(nullable = false, length = 20)
  private String handlingMode;

  @Column(nullable = false)
  private long packetCount;

  @Column(nullable = false)
  private long findingCount;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  private Instant startedAt;
  private Instant stoppedAt;

  @Column(length = 2000)
  private String errorMessage;

  @PrePersist
  void prePersist() {
    createdAt = Instant.now();
  }
}
