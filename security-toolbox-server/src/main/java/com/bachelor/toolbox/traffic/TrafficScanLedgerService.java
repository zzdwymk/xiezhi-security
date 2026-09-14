package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import java.util.List;
import java.util.Locale;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

/** 运行时「扫描执行台账」：记录与查询 ZAP / Xray / sqlmap 的每次流量定向扫描。 */
@Service
public class TrafficScanLedgerService {
  private static final int MAX_LIST_SIZE = 50;

  private final TrafficScanLedgerRepository repository;

  public TrafficScanLedgerService(TrafficScanLedgerRepository repository) {
    this.repository = repository;
  }

  public TrafficScanLedger record(TrafficScanLedger entry) {
    return repository.save(entry);
  }

  public Page<TrafficScanLedger> list(int page, int size, String engine) {
    var pageable =
        PageRequests.bounded(
            page, size, 1, MAX_LIST_SIZE, Sort.by(Sort.Order.desc("createdAt")));
    if (engine != null && !engine.isBlank()) {
      String normalized = engine.trim().toUpperCase(Locale.ROOT);
      if (!List.of("ZAP", "XRAY", "SQLMAP").contains(normalized)) {
        throw new ApiException("未知扫描引擎: " + engine);
      }
      return repository.findByEngineOrderByCreatedAtDesc(normalized, pageable);
    }
    return repository.findAllByOrderByCreatedAtDesc(pageable);
  }

  public List<TrafficScanLedger> recent() {
    return repository.findTop50ByOrderByCreatedAtDesc();
  }
}