package com.bachelor.toolbox.project;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "assessment_projects")
public class AssessmentProject {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 150)
  private String name;

  @Column(length = 2000)
  private String description;

  @Column(nullable = false, length = 4000)
  private String authorizationStatement;

  @Column(nullable = false)
  private Instant authorizationValidFrom;

  @Column(nullable = false)
  private Instant authorizationExpiresAt;

  @Column(nullable = false, length = 30)
  private String status = "DRAFT";

  @Column(nullable = false, length = 100)
  private String owner;

  @Column(nullable = false, updatable = false)
  private Instant createdAt;

  /**
   * Round 288：乐观锁版本号。项目的授权声明与授权时间窗是整套任务的授权来源，
   * 而 update() 是「读—改—写」且原先没有版本校验：两个运维并发编辑同一项目时，
   * 后提交者会用旧快照覆盖前者刚收窄的授权时间窗。列定义带 DEFAULT 0，保证既有库可原地升级。
   */
  @jakarta.persistence.Version
  @Column(nullable = false, columnDefinition = "BIGINT DEFAULT 0")
  private long version;

  private Instant updatedAt;

  @PrePersist
  void prePersist() {
    createdAt = Instant.now();
    updatedAt = createdAt;
  }

  @PreUpdate
  void preUpdate() {
    updatedAt = Instant.now();
  }
}
