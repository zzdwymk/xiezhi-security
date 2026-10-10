package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/** One submitted selection is one operation, including when its HTTP client leaves the page. */
@Service
public class TrafficFuzzBatchService {
  private static final Logger log = LoggerFactory.getLogger(TrafficFuzzBatchService.class);
  private static final int MAX_PACKETS = 200; // Same bound as the traffic workspace's recent packet list.
  private final TrafficFuzzService fuzz;
  private final TrafficPacketRepository packets;
  private final TrafficScanLedgerService ledger;
  private final TrafficNotificationService notifications;
  private final ProjectAuthorizationService authorization;

  public TrafficFuzzBatchService(TrafficFuzzService fuzz, TrafficPacketRepository packets,
      TrafficScanLedgerService ledger, TrafficNotificationService notifications,
      ProjectAuthorizationService authorization) {
    this.fuzz = fuzz;
    this.packets = packets;
    this.ledger = ledger;
    this.notifications = notifications;
    this.authorization = authorization;
  }

  public record Request(@NotEmpty @Size(max = MAX_PACKETS) List<@NotNull @Positive Long> packetIds,
      @NotNull @Valid TrafficFuzzService.FuzzRequest request) {}
  public record Result(String batchId, String status, String message,
      Map<Long, TrafficFuzzService.FuzzResponse> results) {}

  public Result run(Request request) {
    authorization.requireAdmin();
    if (request == null || request.request() == null || request.packetIds() == null
        || request.packetIds().isEmpty() || request.packetIds().size() > MAX_PACKETS
        || request.packetIds().stream().anyMatch(id -> id == null || id <= 0)) {
      throw new ApiException("请选择 1 至 200 条流量记录");
    }
    String operationId = TrafficNotificationService.operationId();
    List<Long> ids = request.packetIds().stream().distinct().toList();
    Long firstId = ids.get(0);
    Map<Long, TrafficFuzzService.FuzzResponse> results = new LinkedHashMap<>();
    String status = "COMPLETED";
    String failure = "";
    TrafficPacket first = null;
    try {
      // Validate every selected packet before sending any fuzz request. Existing fuzz/replay
      // services separately enforce the selected target's host, port and authorization scope.
      for (Long id : ids) {
        TrafficPacket packet = packets.findById(id).orElseThrow(() -> new ApiException("流量记录不存在"));
        if (first == null) first = packet;
      }
      for (Long id : ids) {
        TrafficFuzzService.FuzzResponse response = fuzz.fuzz(id, request.request());
        results.put(id, response);
        if (!"COMPLETED".equals(response.status())) {
          status = response.status() == null ? "PARTIAL" : response.status();
          failure = response.message();
          break;
        }
      }
    } catch (RuntimeException exception) {
      status = failureStatus(exception);
      failure = exception instanceof ApiException ? exception.getMessage() : "执行中断，请查看流量测试记录";
      log.warn("批量流量测试未完成，batchId={}", operationId, exception);
    }
    int completed = results.values().stream().mapToInt(TrafficFuzzService.FuzzResponse::completedRequests).sum();
    String message = "选择 " + ids.size() + " 条流量记录，已返回 " + results.size()
        + " 条记录结果，确认完成 " + completed + " 次请求。"
        + ("COMPLETED".equals(status) ? "响应变化需人工复核，不代表已确认漏洞。" : "未全部完成：" + failure);
    Result result = new Result(operationId, status, message, Map.copyOf(results));
    Long ledgerId = null;
    if (first != null) {
      try {
        TrafficScanLedger entry = new TrafficScanLedger();
        entry.setEngine("FUZZ");
        entry.setPacketId(firstId);
        entry.setTargetId(request.request().targetId() == null ? 0L : request.request().targetId());
        entry.setHost(first.getHost() == null ? "" : first.getHost());
        entry.setPort(first.getPort());
        entry.setStatus(status);
        entry.setMessage(message);
        entry.setHitCount(0); // Response changes and passive alerts are not confirmed vulnerabilities.
        entry.setResultJson(notifications.serialize(result));
        TrafficScanLedger saved = ledger.record(entry);
        ledgerId = saved == null ? null : saved.getId();
      } catch (RuntimeException exception) { log.warn("保存批量流量测试结果失败", exception); }
    }
    notifications.publish(operationId, firstId, request.request().targetId(), ledgerId,
        "Fuzz 批量", status, message, List.of());
    return result;
  }

  private static String failureStatus(Throwable error) {
    for (Throwable cause = error; cause != null; cause = cause.getCause()) {
      if (cause instanceof java.util.concurrent.TimeoutException
          || cause instanceof java.net.http.HttpTimeoutException
          || cause instanceof java.net.SocketTimeoutException) return "TIMEOUT";
      if (cause instanceof java.util.concurrent.CancellationException
          || cause instanceof InterruptedException) return "CANCELLED";
    }
    return "FAILED";
  }
}
