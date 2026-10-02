package com.bachelor.toolbox.task;

import java.util.Collection;
import java.time.Instant;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface SecurityTaskRepository extends JpaRepository<SecurityTask, Long> {
  @Modifying(clearAutomatically = true, flushAutomatically = true)
  @Transactional
  @Query("""
      update SecurityTask task set task.status = 'PENDING',
        task.progressMessage = :message, task.progressUpdatedAt = :now
      where task.id = :id and task.status = 'BLOCKED'
        and (task.workflowRunId is null or exists
          (select run.id from WorkflowRun run
           where run.id = task.workflowRunId and run.status = 'RUNNING'))
      """)
  int activateBlockedWorkflowTask(
      @Param("id") Long id, @Param("message") String message, @Param("now") Instant now);

  List<SecurityTask> findAllByOrderByCreatedAtDesc();

  List<SecurityTask> findAllByProjectIdInOrderByCreatedAtDesc(Collection<Long> projectIds);

  List<SecurityTask> findAllByProjectIdIn(Collection<Long> projectIds, Pageable pageable);

  List<SecurityTask> findAllByTargetIdOrderByCreatedAtAsc(Long targetId);

  List<SecurityTask> findAllByProjectIdOrderByCreatedAtAsc(Long projectId);

  List<SecurityTask> findAllByProjectId(Long projectId, Pageable pageable);

  List<SecurityTask> findAllByWorkflowRunIdOrderByCreatedAtAsc(Long workflowRunId);

  List<SecurityTask> findAllByStatusOrderByCreatedAtAsc(String status);

  long countByStatus(String status);

  long countByStatusIn(Collection<String> statuses);

  boolean existsByTargetIdAndStatusIn(Long targetId, List<String> statuses);

  long countByTargetIdAndStatusIn(Long targetId, List<String> statuses);

  long countByProjectIdAndStatusIn(Long projectId, List<String> statuses);
}
