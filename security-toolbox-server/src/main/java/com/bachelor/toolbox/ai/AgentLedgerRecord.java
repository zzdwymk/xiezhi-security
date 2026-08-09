package com.bachelor.toolbox.ai;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** Append-only, finite public facts for one outer workflow node execution. */
@Getter
@NoArgsConstructor
@Entity
@Table(
    name = "agent_ledger_records",
    uniqueConstraints =
        @UniqueConstraint(
            name = "uk_agent_ledger_run_node_sequence",
            columnNames = {"run_id", "node_run_id", "sequence"}),
    indexes = {
      @Index(
          name = "idx_agent_ledger_run_node_sequence",
          columnList = "run_id,node_run_id,sequence"),
      @Index(
          name = "idx_agent_ledger_project_run_node",
          columnList = "project_id,run_id,node_run_id"),
      @Index(name = "idx_agent_ledger_workflow", columnList = "workflow_id,workflow_revision")
    })
public class AgentLedgerRecord {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Column(name = "ledger_id")
  private Long ledgerId;

  @Column(name = "run_id", nullable = false, length = 80, updatable = false)
  private String runId;

  @Column(name = "project_id", nullable = false, updatable = false)
  private Long projectId;

  @Column(name = "target_id", nullable = false, updatable = false)
  private Long targetId;

  @Column(name = "workflow_id", nullable = false, length = 80, updatable = false)
  private String workflowId;

  @Column(name = "workflow_revision", nullable = false, updatable = false)
  private long workflowRevision;

  @Column(name = "workflow_digest", nullable = false, length = 71, updatable = false)
  private String workflowDigest;

  @Column(name = "outer_node_id", nullable = false, length = 64, updatable = false)
  private String outerNodeId;

  @Column(name = "node_run_id", nullable = false, length = 80, updatable = false)
  private String nodeRunId;

  @Column(name = "sequence", nullable = false, updatable = false)
  private long sequence;

  @Column(name = "inner_step", nullable = false, length = 64, updatable = false)
  private String innerStep;

  @Column(name = "event_type", nullable = false, length = 64, updatable = false)
  private String eventType;

  @Column(name = "status", nullable = false, length = 32, updatable = false)
  private String status;

  @Column(name = "input_digest", nullable = false, length = 71, updatable = false)
  private String inputDigest;

  @Column(name = "output_digest", nullable = false, length = 71, updatable = false)
  private String outputDigest;

  @Column(name = "evidence_ids_json", nullable = false, length = 4000, updatable = false)
  private String evidenceIdsJson;

  @Column(name = "action_ids_json", nullable = false, length = 4000, updatable = false)
  private String actionIdsJson;

  @Column(name = "policy_revision", nullable = false, length = 80, updatable = false)
  private String policyRevision;

  @Column(name = "index_revision", nullable = false, length = 100, updatable = false)
  private String indexRevision;

  @Column(name = "ledger_revision", nullable = false, length = 32, updatable = false)
  private String ledgerRevision;

  @Column(name = "previous_entry_digest", length = 71, updatable = false)
  private String previousEntryDigest;

  @Column(name = "entry_digest", nullable = false, unique = true, length = 71, updatable = false)
  private String entryDigest;

  @Column(name = "created_at", nullable = false, updatable = false)
  private Instant createdAt;

  AgentLedgerRecord(
      AgentLedgerService.AppendRequest request,
      String evidenceIdsJson,
      String actionIdsJson,
      String ledgerRevision,
      String previousEntryDigest,
      String entryDigest,
      Instant createdAt) {
    this.runId = request.runId();
    this.projectId = request.projectId();
    this.targetId = request.targetId();
    this.workflowId = request.workflowId();
    this.workflowRevision = request.workflowRevision();
    this.workflowDigest = request.workflowDigest();
    this.outerNodeId = request.outerNodeId();
    this.nodeRunId = request.nodeRunId();
    this.sequence = request.sequence();
    this.innerStep = request.innerStep();
    this.eventType = request.eventType();
    this.status = request.status();
    this.inputDigest = request.inputDigest();
    this.outputDigest = request.outputDigest();
    this.evidenceIdsJson = evidenceIdsJson;
    this.actionIdsJson = actionIdsJson;
    this.policyRevision = request.policyRevision();
    this.indexRevision = request.indexRevision();
    this.ledgerRevision = ledgerRevision;
    this.previousEntryDigest = previousEntryDigest;
    this.entryDigest = entryDigest;
    this.createdAt = createdAt;
  }
}
