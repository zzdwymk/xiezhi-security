package com.bachelor.toolbox.project;

import java.util.List;
import java.util.Optional;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AssessmentProjectRepository extends JpaRepository<AssessmentProject, Long> {
  List<AssessmentProject> findByOwner(String owner);

  Page<AssessmentProject> findByOwner(String owner, Pageable pageable);

  @Lock(LockModeType.PESSIMISTIC_WRITE)
  @Query("select project from AssessmentProject project where project.id = :id")
  Optional<AssessmentProject> findByIdForUpdate(@Param("id") Long id);
}
