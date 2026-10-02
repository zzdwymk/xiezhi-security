package com.bachelor.toolbox.project;

import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProjectApprovalRepository extends JpaRepository<ProjectApproval, Long> {
  List<ProjectApproval> findByProjectIdOrderByCreatedAtDesc(Long projectId);

  List<ProjectApproval> findByProjectId(Long projectId, Pageable pageable);

  @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
  @org.springframework.data.jpa.repository.Query("select a from ProjectApproval a where a.id = :id and a.projectId = :projectId")
  Optional<ProjectApproval> findForUpdate(@org.springframework.data.repository.query.Param("id") Long id,
      @org.springframework.data.repository.query.Param("projectId") Long projectId);

  Optional<ProjectApproval> findByIdAndProjectId(Long id, Long projectId);
}
