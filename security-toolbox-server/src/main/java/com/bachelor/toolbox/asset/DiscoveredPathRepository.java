package com.bachelor.toolbox.asset;

import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DiscoveredPathRepository extends JpaRepository<DiscoveredPath, Long> {
  List<DiscoveredPath> findByProjectIdAndTargetIdOrderByDiscoveredAtDescIdDesc(
      Long projectId, Long targetId);

  List<DiscoveredPath> findByProjectIdAndTargetIdOrderByDiscoveredAtDescIdDesc(
      Long projectId, Long targetId, Pageable pageable);

  boolean existsByProjectIdAndTargetIdAndUrl(Long projectId, Long targetId, String url);

  long countByProjectIdAndTargetId(Long projectId, Long targetId);

  List<DiscoveredPath> findByTargetIdOrderByDiscoveredAtDescIdDesc(Long targetId);
}
