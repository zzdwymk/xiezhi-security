package com.bachelor.toolbox.traffic;

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

/** 流量定向扫描执行台账：统一记录 ZAP / Xray / sqlmap 三引擎在流量复核时的每次执行。 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "traffic_scan_ledger")
public class TrafficScanLedger {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 16)
  private String engine;

  @Column(nullable = false)
  private Long packetId;

  @Column(nullable = false)
  private Long targetId;

  @Column(nullable = false, length = 253)
  private String host;

  private Integer port;

  @Column(length = 2048)
  private String url;

  @Column(nullable = false)
  private int hitCount;

  @Column(nullable = false, length = 16)
  private String status = "COMPLETED";

  @Column(length = 2000)
  private String message;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  @PrePersist
  void prePersist() {
    createdAt = Instant.now();
  }
}