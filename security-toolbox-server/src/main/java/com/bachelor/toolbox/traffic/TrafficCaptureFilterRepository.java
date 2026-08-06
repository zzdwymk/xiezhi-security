package com.bachelor.toolbox.traffic;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TrafficCaptureFilterRepository extends JpaRepository<TrafficCaptureFilter, Long> {
  List<TrafficCaptureFilter> findAllByOrderByCreatedAtAsc();
}
