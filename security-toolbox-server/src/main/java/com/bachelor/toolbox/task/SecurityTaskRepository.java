package com.bachelor.toolbox.task;

import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityTaskRepository extends JpaRepository<SecurityTask, Long> {
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
