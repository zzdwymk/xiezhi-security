package com.bachelor.toolbox.traffic;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TrafficScanLedgerRepository
    extends JpaRepository<TrafficScanLedger, Long> {
  Page<TrafficScanLedger> findAllByOrderByCreatedAtDesc(Pageable pageable);

  Page<TrafficScanLedger> findByEngineOrderByCreatedAtDesc(String engine, Pageable pageable);

  List<TrafficScanLedger> findTop50ByOrderByCreatedAtDesc();
}