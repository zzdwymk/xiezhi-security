package com.bachelor.toolbox.operation;

import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityActionRepository extends JpaRepository<SecurityAction, Long> {
  List<SecurityAction> findByProjectIdOrderByCreatedAtDesc(Long projectId);

  List<SecurityAction> findByProjectId(Long projectId, Pageable pageable);
}
