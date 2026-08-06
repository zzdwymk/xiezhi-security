package com.bachelor.toolbox.schedule;

import java.time.Instant;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ScanScheduleRepository extends JpaRepository<ScanSchedule, Long> {
  Page<ScanSchedule> findAll(Pageable pageable);

  @Query(
      """
      select schedule
      from ScanSchedule schedule, AssessmentProject project
      where schedule.projectId = project.id
        and project.owner = :owner
      """)
  Page<ScanSchedule> findAccessibleByProjectOwner(
      @Param("owner") String owner, Pageable pageable);

  List<ScanSchedule> findByEnabledTrueAndNextRunAtLessThanEqual(
      Instant now, Pageable pageable);
}
