package com.bachelor.toolbox.ai;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/** Single-row store for the visually-composed agent workflow spec (JSON). */
@Entity
@Table(name = "agent_workflow_spec")
public class AgentWorkflowSpec {
  @Id private Long id = 1L;

  @Column(columnDefinition = "text")
  private String specJson;

  private Instant updatedAt;

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getSpecJson() {
    return specJson;
  }

  public void setSpecJson(String specJson) {
    this.specJson = specJson;
  }

  public Instant getUpdatedAt() {
    return updatedAt;
  }

  public void setUpdatedAt(Instant updatedAt) {
    this.updatedAt = updatedAt;
  }
}
