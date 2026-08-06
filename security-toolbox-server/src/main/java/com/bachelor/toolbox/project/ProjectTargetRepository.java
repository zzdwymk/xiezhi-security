package com.bachelor.toolbox.project;

import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProjectTargetRepository extends JpaRepository<ProjectTarget, Long> {
  List<ProjectTarget> findByProjectId(Long projectId);

  List<ProjectTarget> findByProjectId(Long projectId, Pageable pageable);

  List<ProjectTarget> findByTargetId(Long targetId);

  Optional<ProjectTarget> findByProjectIdAndTargetId(Long projectId, Long targetId);

  void deleteByProjectIdAndTargetId(Long projectId, Long targetId);

  long countByProjectId(Long projectId);
}
