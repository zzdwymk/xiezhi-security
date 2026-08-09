package com.bachelor.toolbox.ai;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AgentLedgerRecordRepository extends JpaRepository<AgentLedgerRecord, Long> {
  Optional<AgentLedgerRecord> findByRunIdAndNodeRunIdAndSequence(
      String runId, String nodeRunId, long sequence);

  Optional<AgentLedgerRecord> findFirstByRunIdAndNodeRunIdOrderBySequenceDesc(
      String runId, String nodeRunId);

  List<AgentLedgerRecord> findByRunIdAndNodeRunIdOrderBySequenceAsc(
      String runId, String nodeRunId);

  List<AgentLedgerRecord> findByProjectIdAndRunIdAndNodeRunIdOrderBySequenceAsc(
      Long projectId, String runId, String nodeRunId);

  List<AgentLedgerRecord> findByProjectIdAndRunIdOrderByCreatedAtAscLedgerIdAsc(
      Long projectId, String runId);

  boolean existsByRunIdAndNodeRunIdAndStatusIn(
      String runId, String nodeRunId, Collection<String> statuses);
}
