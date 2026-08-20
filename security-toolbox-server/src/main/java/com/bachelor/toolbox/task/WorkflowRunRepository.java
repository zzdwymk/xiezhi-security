package com.bachelor.toolbox.task;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface WorkflowRunRepository extends JpaRepository<WorkflowRun, Long> {
  List<WorkflowRun> findAllByProjectIdAndClearedAtIsNullOrderByCreatedAtDesc(
      Long projectId, Pageable pageable);

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select run from WorkflowRun run where run.id = :id")
  Optional<WorkflowRun> findByIdForUpdate(@Param("id") Long id);
}
