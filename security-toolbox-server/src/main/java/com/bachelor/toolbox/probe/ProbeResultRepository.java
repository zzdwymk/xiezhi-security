package com.bachelor.toolbox.probe;

import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProbeResultRepository extends JpaRepository<ProbeResult, Long> {
  List<ProbeResult> findByProjectIdAndTargetIdOrderByDetectedAtDesc(Long projectId, Long targetId);

  List<ProbeResult> findByProjectIdAndTargetIdOrderByDetectedAtDescIdDesc(
      Long projectId, Long targetId, Pageable pageable);

  List<ProbeResult> findByProjectIdOrderByDetectedAtDesc(Long projectId);

  List<ProbeResult> findByProjectIdOrderByDetectedAtDescIdDesc(
      Long projectId, Pageable pageable);
}
