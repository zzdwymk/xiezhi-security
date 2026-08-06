package com.bachelor.toolbox.recon;

import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ReconResultRepository extends JpaRepository<ReconResult, Long> {
  List<ReconResult> findByProjectIdOrderByCollectedAtDesc(Long projectId);

  List<ReconResult> findByProjectIdOrderByCollectedAtDescIdDesc(
      Long projectId, Pageable pageable);

  List<ReconResult> findByProjectIdAndTargetIdOrderByCollectedAtDesc(Long projectId, Long targetId);

  List<ReconResult> findByProjectIdAndTargetIdOrderByCollectedAtDescIdDesc(
      Long projectId, Long targetId, Pageable pageable);
}
