package com.bachelor.toolbox.ai;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;

/** One immutable revision of a project-scoped, visually-composed workflow. */
@Entity
@Table(
    name = "agent_workflow_spec",
    uniqueConstraints = {
      @UniqueConstraint(
          name = "uk_agent_workflow_scope_revision",
          columnNames = {"scope_id", "revision"}),
      @UniqueConstraint(
          name = "uk_agent_workflow_id_revision",
          columnNames = {"workflow_id", "revision"})
    })
public class AgentWorkflowSpec {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(name = "workflow_id", nullable = false, updatable = false, length = 64)
  private String workflowId;

  @Column(name = "scope_id", nullable = false, updatable = false)
  private Long scopeId;

  @Column(nullable = false, updatable = false)
  private Long revision;

  @Column(name = "spec_digest", nullable = false, updatable = false, length = 71)
  private String specDigest;

  @Column(nullable = false, updatable = false, columnDefinition = "text")
  private String specJson;

  @Column(nullable = false, updatable = false, length = 100)
  private String updatedBy;

  @Column(nullable = false, updatable = false)
  private Instant updatedAt;

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getWorkflowId() {
    return workflowId;
  }

  public void setWorkflowId(String workflowId) {
    this.workflowId = workflowId;
  }

  public Long getScopeId() {
    return scopeId;
  }

  public void setScopeId(Long scopeId) {
    this.scopeId = scopeId;
  }

  public Long getRevision() {
    return revision;
  }

  public void setRevision(Long revision) {
    this.revision = revision;
  }

  public String getSpecDigest() {
    return specDigest;
  }

  public void setSpecDigest(String specDigest) {
    this.specDigest = specDigest;
  }

  public String getSpecJson() {
    return specJson;
  }

  public void setSpecJson(String specJson) {
    this.specJson = specJson;
  }

  public String getUpdatedBy() {
    return updatedBy;
  }

  public void setUpdatedBy(String updatedBy) {
    this.updatedBy = updatedBy;
  }

  public Instant getUpdatedAt() {
    return updatedAt;
  }

  public void setUpdatedAt(Instant updatedAt) {
    this.updatedAt = updatedAt;
  }
}
