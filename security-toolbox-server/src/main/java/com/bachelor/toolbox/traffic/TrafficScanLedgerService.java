package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
  private ProjectAuthorizationService authorization;

  @org.springframework.beans.factory.annotation.Autowired(required = false)
  public void setAuthorization(ProjectAuthorizationService authorization) {
    this.authorization = authorization;
  }

  public TrafficScanLedgerService(TrafficScanLedgerRepository repository) {
    this.repository = repository;
  }

  public TrafficScanLedger record(TrafficScanLedger entry) {
    boundSummary(entry);
    if (!"RUNNING".equals(entry.getStatus())) entry.setFinishedAt(java.time.Instant.now());
    return repository.save(entry);
  }

  /** Commit the operation before the scanner can send its first request. */
  public void begin(TrafficScanLedger entry) {
    boundSummary(entry);
    entry.setStatus("RUNNING");
    entry.setStartedAt(java.time.Instant.now());
    TrafficScanLedger saved = repository.saveAndFlush(entry);
    entry.setId(saved.getId());
  }

  public void progress(TrafficScanLedger entry) {
    boundSummary(entry);
    repository.save(entry);
  }

  private void boundSummary(TrafficScanLedger entry) {
    // Keep full diagnostics in resultJson; list summaries must fit their database columns.
    if (entry.getMessage() != null && entry.getMessage().length() > 2000)
      entry.setMessage(entry.getMessage().substring(0, 2000));
    if (entry.getUrl() != null && entry.getUrl().length() > 2048)
      entry.setUrl(entry.getUrl().substring(0, 2048));
  }

  /** A stopped local engine cannot resume the old in-memory scanner workers. */
  @org.springframework.context.event.EventListener(org.springframework.boot.context.event.ApplicationReadyEvent.class)
  public void recoverInterruptedScans() {
    for (TrafficScanLedger entry : repository.findByStatus("RUNNING")) {
      entry.setStatus("FAILED");
      entry.setMessage("本地引擎重启，流量检测已中断；已保存的告警可查看，本次检测未完成。");
      try {
        var mapper = new ObjectMapper();
        var result = entry.getResultJson() == null ? mapper.createObjectNode()
            : (com.fasterxml.jackson.databind.node.ObjectNode) mapper.readTree(entry.getResultJson());
        result.put("status", entry.getStatus());
        result.put("message", entry.getMessage());
        entry.setResultJson(mapper.writeValueAsString(result));
      } catch (Exception ignored) { /* The authoritative entry still records the interruption. */ }
      record(entry);
    }
  }

  public Detail detail(Long id) {
    // Stored results can contain raw captured traffic. They share the admin audience of the operation.
    requireAdmin();
    TrafficScanLedger entry = repository.findById(id).orElseThrow(() -> new ApiException("流量测试记录不存在"));
    JsonNode result = null;
    try {
      if (entry.getResultJson() != null) result = new ObjectMapper().readTree(entry.getResultJson());
    } catch (Exception exception) { throw new ApiException("流量测试结果无法读取"); }
    return new Detail(entry, result);
  }

  public record Detail(TrafficScanLedger entry, JsonNode result) {}

  public Page<TrafficScanLedger> list(int page, int size, String engine) {
    return list(page, size, engine, false);
  }

  public Page<TrafficScanLedger> list(int page, int size, String engine, boolean findingsOnly) {
    requireAdmin();
    var pageable =
        PageRequests.bounded(
            page, size, 1, MAX_LIST_SIZE, Sort.by(Sort.Order.desc("createdAt")));
    if (engine != null && !engine.isBlank()) {
      String normalized = engine.trim().toUpperCase(Locale.ROOT);
      if (!List.of("ZAP", "XRAY", "SQLMAP", "FUZZ").contains(normalized)) {
        throw new ApiException("未知扫描引擎: " + engine);
      }
      if (findingsOnly) return repository.findFindingSources(normalized, pageable);
      return repository.findByEngineOrderByCreatedAtDesc(normalized, pageable);
    }
    if (findingsOnly) return repository.findFindingSources(null, pageable);
    return repository.findAllByOrderByCreatedAtDesc(pageable);
  }

  public List<TrafficScanLedger> recent() {
    requireAdmin();
    return repository.findTop50ByOrderByCreatedAtDesc();
  }

  private void requireAdmin() {
    if (authorization == null) throw new ApiException("无法确认流量结果访问权限");
    authorization.requireAdmin();
  }
}
