package com.bachelor.toolbox.project;

import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProjectApprovalRepository extends JpaRepository<ProjectApproval, Long> {
  List<ProjectApproval> findByProjectIdOrderByCreatedAtDesc(Long projectId);

  List<ProjectApproval> findByProjectId(Long projectId, Pageable pageable);

  Optional<ProjectApproval> findByIdAndProjectId(Long id, Long projectId);
}
