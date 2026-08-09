package com.bachelor.toolbox.traffic;

import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TrafficSessionRepository extends JpaRepository<TrafficSession, Long> {
  List<TrafficSession> findAllByOrderByCreatedAtDesc();

  List<TrafficSession> findByIdGreaterThanOrderByIdAsc(Long id, Pageable pageable);

  long countByStatusIn(Collection<String> statuses);
}
