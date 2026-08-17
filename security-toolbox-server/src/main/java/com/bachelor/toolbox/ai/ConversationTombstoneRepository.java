package com.bachelor.toolbox.ai;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;

public interface ConversationTombstoneRepository extends JpaRepository<ConversationTombstone, Long> {
  Optional<ConversationTombstone> findByRunIdAndNodeRunId(String runId, String nodeRunId);

  Optional<ConversationTombstone> findByProjectIdAndTargetIdAndTurnIdAndWorkflowDigest(
      Long projectId, Long targetId, String turnId, String workflowDigest);

  List<ConversationTombstone> findTop100ByStatusInAndNextAttemptAtLessThanEqualOrderByCreatedAtAsc(
      Collection<String> statuses, Instant now);

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select t from ConversationTombstone t where t.id = :id")
  Optional<ConversationTombstone> findLockedById(@Param("id") Long id);
}
