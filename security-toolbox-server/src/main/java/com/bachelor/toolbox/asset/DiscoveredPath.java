package com.bachelor.toolbox.asset;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * 某个授权目标下发现的一条 Web 子路径 / 资产 URL。按 (projectId, targetId) 归属目标，
 * 只在授权 host:端口 范围内收集。来源可为主动目录枚举、站点爬取、响应链接提取、代理会话或 ZAP 爬虫。
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(
    name = "discovered_paths",
    indexes = {
      @Index(name = "idx_discovered_project_target", columnList = "projectId,targetId")
    })
public class DiscoveredPath {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false)
  private Long projectId;

  @Column(nullable = false)
  private Long targetId;

  /** 完整 URL，例如 http://192.168.136.132/Less-2/?id=1 */
  @Column(nullable = false, length = 2048)
  private String url;

  /** 相对路径（含查询串），例如 /Less-2/?id=1 */
  @Column(length = 2048)
  private String path;

  @Column(length = 16)
  private String method = "GET";

  /** ACTIVE_ENUM | CRAWL | PASSIVE_LINK | PROXY | ZAP_SPIDER */
  @Column(length = 20)
  private String source;

  private Integer statusCode;

  private Long responseBytes;

  @Column(length = 500)
  private String note;

  @Column(nullable = false)
  private Instant discoveredAt;

  public DiscoveredPath(
      Long projectId,
      Long targetId,
      String url,
      String path,
      String method,
      String source,
      Integer statusCode,
      Long responseBytes,
      String note) {
    this.projectId = projectId;
    this.targetId = targetId;
    this.url = url;
    this.path = path;
    this.method = method == null ? "GET" : method;
    this.source = source;
    this.statusCode = statusCode;
    this.responseBytes = responseBytes;
    this.note = note;
  }

  @PrePersist
  void prePersist() {
    discoveredAt = Instant.now();
  }
}
