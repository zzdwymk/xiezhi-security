package com.bachelor.toolbox.finding;

import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface FindingRepository
    extends JpaRepository<Finding, Long>, JpaSpecificationExecutor<Finding> {
  List<Finding> findAllByOrderByCreatedAtDesc();

  List<Finding> findTop100ByOrderByCreatedAtDesc();

  List<Finding> findAllByTaskIdOrderByCreatedAtAsc(Long taskId);

  long countByTaskId(Long taskId);

  @Query("select distinct f.severity from Finding f where f.taskId in :taskIds")
  List<String> findDistinctSeveritiesByTaskIds(@Param("taskIds") List<Long> taskIds);

  List<Finding> findAllByTaskIdInOrderByCreatedAtAsc(List<Long> taskIds);

  List<Finding> findAllByTaskIdIn(List<Long> taskIds, Pageable pageable);

  List<Finding> findAllByTargetIdOrderByCreatedAtAsc(Long targetId);

  long countBySeverityIn(List<String> severities);

  long deleteBySourceToolInAndTitleStartingWithAndVulnerabilityCodeIsNull(
      Collection<String> sourceTools, String titlePrefix);
}
