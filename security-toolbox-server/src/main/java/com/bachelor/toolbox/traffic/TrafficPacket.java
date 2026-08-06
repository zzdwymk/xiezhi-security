package com.bachelor.toolbox.traffic;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "traffic_packets")
public class TrafficPacket {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long sessionId;

  @Column(nullable = false)
  private Long targetId;

  @Column(nullable = false, length = 16)
  private String protocol;

  @Column(nullable = false, length = 16)
  private String method;

  @Column(nullable = false, length = 10)
  private String scheme;

  @Column(nullable = false, length = 253)
  private String host;

  @Column(nullable = false)
  private int port;

  @Column(length = 2048)
  private String path;

  private Integer statusCode;

  @Column(length = 200)
  private String contentType;

  @Column(nullable = false)
  private long requestBytes;

  @Column(nullable = false)
  private long responseBytes;

  private Long durationMs;

  @Column(nullable = false, length = 16)
  private String riskLevel = "NONE";

  @Column(nullable = false, length = 20)
  private String aiStatus = "ANALYZING";

  @Column(nullable = false, length = 20)
  private String captureState = "CAPTURED";

  @Column(nullable = false, columnDefinition = "boolean default false")
  private boolean marked = false;

  @JsonIgnore @Lob private String requestHeaders;
  @JsonIgnore @Lob private String requestBody;
  @JsonIgnore @Lob private String responseHeaders;
  @JsonIgnore @Lob private String responseBody;

  @Column(length = 2000)
  private String errorMessage;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @PrePersist
  void prePersist() {
    createdAt = Instant.now();
  }
}
