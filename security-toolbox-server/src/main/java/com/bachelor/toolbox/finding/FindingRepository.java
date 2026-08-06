package com.bachelor.toolbox.finding;

import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface FindingRepository
    extends JpaRepository<Finding, Long>, JpaSpecificationExecutor<Finding> {
  List<Finding> findAllByOrderByCreatedAtDesc();

  List<Finding> findTop100ByOrderByCreatedAtDesc();

  List<Finding> findAllByTaskIdOrderByCreatedAtAsc(Long taskId);

  long countByTaskId(Long taskId);

  List<Finding> findAllByTaskIdInOrderByCreatedAtAsc(List<Long> taskIds);

  List<Finding> findAllByTaskIdIn(List<Long> taskIds, Pageable pageable);

  List<Finding> findAllByTargetIdOrderByCreatedAtAsc(Long targetId);

  long countBySeverityIn(List<String> severities);

  long deleteBySourceToolInAndTitleStartingWithAndVulnerabilityCodeIsNull(
      Collection<String> sourceTools, String titlePrefix);
}
