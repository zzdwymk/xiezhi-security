package com.bachelor.toolbox.ai;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;

public interface AgentContinuationExecutionRepository
    extends JpaRepository<AgentContinuationExecution, Long> {
  Optional<AgentContinuationExecution> findByTombstoneId(Long tombstoneId);

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select e from AgentContinuationExecution e where e.tombstoneId = :tombstoneId")
  Optional<AgentContinuationExecution> findLockedByTombstoneId(
      @Param("tombstoneId") Long tombstoneId);
}
