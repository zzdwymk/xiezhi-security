package com.bachelor.toolbox.traffic;

import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TrafficScanLedgerRepository
    extends JpaRepository<TrafficScanLedger, Long> {
  Page<TrafficScanLedger> findAllByOrderByCreatedAtDesc(Pageable pageable);

  Page<TrafficScanLedger> findByEngineOrderByCreatedAtDesc(String engine, Pageable pageable);

  @org.springframework.data.jpa.repository.Query("select s from TrafficScanLedger s where s.hitCount > 0 and s.engine <> 'FUZZ' and (:engine is null or s.engine = :engine)")
  Page<TrafficScanLedger> findFindingSources(@org.springframework.data.repository.query.Param("engine") String engine, Pageable pageable);

  List<TrafficScanLedger> findTop50ByOrderByCreatedAtDesc();

  List<TrafficScanLedger> findByStatus(String status);
}
