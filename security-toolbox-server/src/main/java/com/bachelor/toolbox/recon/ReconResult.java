package com.bachelor.toolbox.recon;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
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
@Table(
    name = "recon_results",
    indexes = {
      @Index(name = "idx_recon_project", columnList = "projectId"),
      @Index(name = "idx_recon_target", columnList = "targetId")
    })
public class ReconResult {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long projectId;

  @Column(nullable = false)
  private Long targetId;

  @Column(nullable = false, length = 253)
  private String rootDomain;

  @Lob
  @Column(nullable = false)
  private String dnsRecords = "{}";

  @Lob
  @Column(nullable = false)
  private String ipInformation = "{}";

  @Lob
  @Column(nullable = false)
  private String tlsInformation = "{}";

  @Lob
  @Column(nullable = false)
  private String httpInformation = "{}";

  @Lob
  @Column(nullable = false)
  private String subdomains = "[]";

  // 可空：允许 ddl-auto 向已存在的 recon_results 表增量添加该列（NOT NULL 列无法直接加到有数据的表）。
  @Lob private String webPaths = "[]";

  @Lob
  @Column(nullable = false)
  private String networkInformation = "{}";

  @Lob
  @Column(nullable = false)
  private String registrationInformation = "{}";

  @Lob
  @Column(nullable = false)
  private String geolocationInformation = "{}";

  @Lob
  @Column(nullable = false)
  private String sourceEvidence = "[]";

  @Column(nullable = false)
  private boolean activeNetworkProbe;

  @Column(nullable = false, updatable = false)
  private Instant collectedAt;

  @PrePersist
  void prePersist() {
    collectedAt = Instant.now();
  }
}
