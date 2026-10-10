package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.target.WebTargetResolver;
import com.bachelor.toolbox.tool.SqlmapScanTool;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import com.bachelor.toolbox.tool.XrayScanTool;
import com.bachelor.toolbox.tool.zap.ZapDaemon;
import com.bachelor.toolbox.tool.zap.ZapDaemonSupplier;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TrafficScanService {
  private static final Logger LOGGER = LoggerFactory.getLogger(TrafficScanService.class);

  public record TargetedScanHit(
      String title,
      String severity,
      String description,
      String parameter,
      String evidence,
      String solution) {}

  public record TargetedScanProbe(
      String name,
      String method,
      String target,
      String payload,
      Integer statusCode,
      String responseSnippet,
      boolean triggered,
      String note) {}

  public record TargetedScanResult(
      Long packetId,
      String engine,
      String status,
      List<TargetedScanHit> hits,
      List<TargetedScanProbe> probes,
      String message,
      Long scanId) {
    public TargetedScanResult(Long packetId, String engine, String status,
        List<TargetedScanHit> hits, List<TargetedScanProbe> probes, String message) {
      this(packetId, engine, status, hits, probes, message, null);
    }
  }

  public record ZapScanRequest(String strength, String policy, Long targetId) {
    public ZapScanRequest(String strength, String policy) { this(strength, policy, null); }
  }
  public record XrayScanRequest(List<String> pocCodes, boolean allPocs, Long targetId) {
    public XrayScanRequest(List<String> pocCodes, boolean allPocs) { this(pocCodes, allPocs, null); }
  }

  public record SqlmapScanRequest(Integer level, Integer risk, String technique, String data, Long targetId) {
    public SqlmapScanRequest(Integer level, Integer risk, String technique, String data) {
      this(level, risk, technique, data, null);
    }
  }

  /** 实时回调：扫描过程中逐条推送探针与命中，便于前端流式展示测试数据。 */
  public interface ZapScanListener {
    default void onRecord(Long scanId) {}

    default void onStart(String targetUrl) {}

    default void onStatus(String message) {}

    default void onProbe(TargetedScanProbe probe) {}

    default void onHit(TargetedScanHit hit) {}

    default void onComplete(TargetedScanResult result) {}

    ZapScanListener NOOP = new ZapScanListener() {};
  }

  private final TrafficPacketRepository packets;
  private final TargetService targets;
  private final TargetPolicyService policy;
  private final AuthorizedTargetRepository targetRepository;
  private final ZapDaemonSupplier zapDaemonSupplier;
  private final DependencyDetectionService dependencies;
  private final XrayScanTool xrayTool;
  private final SqlmapScanTool sqlmapTool;
  private final AuditService audit;
  private final TrafficScanLedgerService scanLedger;
  private final PortRangeParser portRangeParser;
  private final Duration zapScanTimeout;
  private final com.fasterxml.jackson.databind.ObjectMapper resultMapper = new com.fasterxml.jackson.databind.ObjectMapper();
  private TrafficNotificationService notifications;

  @Autowired(required = false)
  public void setNotifications(TrafficNotificationService notifications) {
    this.notifications = notifications;
  }

  public TrafficScanService(
      TrafficPacketRepository packets,
      TargetService targets,
      TargetPolicyService policy,
      AuthorizedTargetRepository targetRepository,
      @Autowired(required = false) ZapDaemonSupplier zapDaemonSupplier,
      DependencyDetectionService dependencies,
      XrayScanTool xrayTool,
      SqlmapScanTool sqlmapTool,
      AuditService audit,
      TrafficScanLedgerService scanLedger,
      PortRangeParser portRangeParser) {
    this(packets, targets, policy, targetRepository, zapDaemonSupplier, dependencies, xrayTool,
        sqlmapTool, audit, scanLedger, portRangeParser, Duration.ofMinutes(30));
  }

  @Autowired
  public TrafficScanService(TrafficPacketRepository packets, TargetService targets, TargetPolicyService policy,
      AuthorizedTargetRepository targetRepository, @Autowired(required = false) ZapDaemonSupplier zapDaemonSupplier,
      DependencyDetectionService dependencies, XrayScanTool xrayTool, SqlmapScanTool sqlmapTool,
      AuditService audit, TrafficScanLedgerService scanLedger, PortRangeParser portRangeParser,
      @Value("${toolbox.execution.zap-scan-timeout-seconds:1800}") long zapScanTimeoutSeconds) {
    this(packets, targets, policy, targetRepository, zapDaemonSupplier, dependencies, xrayTool,
        sqlmapTool, audit, scanLedger, portRangeParser, Duration.ofSeconds(zapScanTimeoutSeconds));
  }

  TrafficScanService(TrafficPacketRepository packets, TargetService targets, TargetPolicyService policy,
      AuthorizedTargetRepository targetRepository, ZapDaemonSupplier zapDaemonSupplier,
      DependencyDetectionService dependencies, XrayScanTool xrayTool, SqlmapScanTool sqlmapTool,
      AuditService audit, TrafficScanLedgerService scanLedger, PortRangeParser portRangeParser,
      Duration zapScanTimeout) {
    this.packets = packets;
    this.targets = targets;
    this.policy = policy;
    this.targetRepository = targetRepository;
    this.zapDaemonSupplier = zapDaemonSupplier;
    this.dependencies = dependencies;
    this.xrayTool = xrayTool;
    this.sqlmapTool = sqlmapTool;
    this.audit = audit;
    this.scanLedger = scanLedger;
    this.portRangeParser = portRangeParser;
    if (zapScanTimeout == null || zapScanTimeout.isZero() || zapScanTimeout.isNegative()) {
      throw new IllegalArgumentException("ZAP 检测超时时间必须大于零");
    }
    this.zapScanTimeout = zapScanTimeout;
  }

  public long zapScanStreamTimeoutMillis() {
    // Include daemon startup, API setup and cleanup in the transport budget.
    return zapScanTimeout.plusMinutes(5).toMillis();
  }

  public TargetedScanResult zapScan(Long packetId, ZapScanRequest request) {
    return zapScan(packetId, request, ZapScanListener.NOOP);
  }

  public TargetedScanResult zapScan(
      Long packetId, ZapScanRequest request, ZapScanListener listener) {
    return runNotifiedScan(packetId, request == null ? null : request.targetId(), "ZAP",
        listener, (packet, target, safeListener) -> zapScanInternal(packet, target, request, safeListener));
  }

  private TargetedScanResult zapScanInternal(TrafficPacket packet, AuthorizedTarget target,
      ZapScanRequest request, ZapScanListener listener) {
    Long packetId = packet.getId();
    URI uri = validatedPacketUri(packet, target);
    String targetUrl = uri.toString();
    String strength = request == null || request.strength() == null ? "MEDIUM"
        : request.strength().trim().toUpperCase(Locale.ROOT);
    if (!Set.of("LOW", "MEDIUM", "HIGH", "INSANE").contains(strength)) {
      throw new ApiException("ZAP 扫描强度仅支持 LOW、MEDIUM、HIGH 或 INSANE");
    }
    String policyName = request == null || request.policy() == null || request.policy().isBlank()
        ? "Default Policy" : request.policy().trim();
    if (policyName.length() > 100 || policyName.chars().anyMatch(Character::isISOControl)) {
      throw new ApiException("ZAP 扫描策略名称不正确");
    }
    List<TargetedScanHit> hits = new ArrayList<>();
    List<TargetedScanProbe> probes = new ArrayList<>();
    String status = "COMPLETED";
    String message;
    int lastProgress = 0;
    listener.onStart(targetUrl);
    try {
      if (zapDaemonSupplier == null || !zapAvailable()) throw new ApiException("OWASP ZAP 引擎不可用，检测未执行");
      try (ZapDaemon daemon = zapDaemonSupplier.create()) {
        String ascanId = null;
        try {
          listener.onStatus("正在启动 OWASP ZAP 引擎并纳入扫描范围...");
          daemon.start();
          daemon.includeInScope(uri);
          daemon.accessUrl(uri); // The daemon contract explicitly forbids redirect following here.
          listener.onStatus("正在对选定地址执行 ZAP 主动扫描（强度 " + strength + "，不递归）...");
          ascanId = daemon.startActiveScan(uri, policyName, strength, false);
          if (ascanId == null || ascanId.isBlank()) throw new ApiException("ZAP 未返回扫描编号，检测未启动");
          long started = System.nanoTime();
          long deadline = started + zapScanTimeout.toNanos();
          int previousProgress = -1;
          long nextActivityRead = started;
          ZapDaemon.ScanActivity activity = null;
          while (true) {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedException("ZAP 检测已取消");
            if (System.nanoTime() >= deadline) throw new TimeoutException("ZAP 定向检测超时，检测未完成");
            int progress = daemon.activeScanProgress(ascanId);
            lastProgress = progress;
            if (progress < 0 || progress > 100) throw new ApiException("ZAP 返回非法扫描进度，检测未完成");
            if (System.nanoTime() >= deadline) throw new TimeoutException("ZAP 定向检测超时，检测未完成");
            if (progress == 100) break;
            if (System.nanoTime() >= nextActivityRead) {
              activity = daemon.activeScanActivity(ascanId);
              nextActivityRead = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            }
            if (Thread.currentThread().isInterrupted()) throw new InterruptedException("ZAP 检测已取消");
            if (System.nanoTime() >= deadline) throw new TimeoutException("ZAP 定向检测超时，检测未完成");
            long elapsed = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - started);
            listener.onStatus("ZAP 主动扫描进度 " + progress + "% · 已用 " + elapsed
                + " 秒，本次最多等待 " + zapScanTimeout.toSeconds() + " 秒"
                + zapActivityDescription(activity)
                + (progress == previousProgress ? "。当前检查尚未结束，进度可能暂时不变。" : ""));
            previousProgress = progress;
            long remainingMillis = Math.max(1, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()));
            Thread.sleep(Math.min(600, remainingMillis));
          }
          while (true) {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedException("ZAP 检测已取消");
            if (System.nanoTime() >= deadline) throw new TimeoutException("ZAP 定向检测超时，检测未完成");
            long remaining = daemon.passiveScanRemaining();
            if (remaining < 0) throw new ApiException("ZAP 返回了无效的响应检查进度，检测未完成");
            if (System.nanoTime() >= deadline) throw new TimeoutException("ZAP 定向检测超时，检测未完成");
            if (remaining == 0) break;
            listener.onStatus("ZAP 正在检查网站响应，剩余 " + remaining + " 条");
            long remainingMillis = Math.max(1, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()));
            Thread.sleep(Math.min(600, remainingMillis));
          }
          List<ZapDaemon.ZapAlert> alerts = daemon.alerts();
          if (alerts == null) throw new ApiException("ZAP 未返回有效告警结果，检测未完成");
          for (ZapDaemon.ZapAlert alert : alerts) {
            if (alert != null && alertMatchesTarget(alert.url(), uri)) {
              TargetedScanHit hit =
                  new TargetedScanHit(
                      alert.name(),
                      alert.risk(),
                      alert.description(),
                      alert.url(),
                      "CWE: " + alert.cweId() + "; Confidence=" + alert.confidence(),
                      "请依据 OWASP 风险指南并结合业务上下文进行针对性修复与复测。");
              hits.add(hit);
              listener.onHit(hit);
              TargetedScanProbe probe =
                  new TargetedScanProbe(
                      alert.name(),
                      "", // Alert API does not supply the actual request method.
                      alert.url(),
                      "",
                      null,
                      "",
                      true,
                      "ZAP 主动扫描告警: risk="
                          + alert.risk()
                          + ", confidence="
                          + alert.confidence()
                          + ", CWE="
                          + alert.cweId());
              probes.add(probe);
              listener.onProbe(probe);
            }
          }
        } catch (Exception ex) {
          if (ascanId != null && !ascanId.isBlank()) {
            try { daemon.stopActiveScan(ascanId); } catch (Exception cleanup) { ex.addSuppressed(cleanup); }
          }
          try { daemon.kill(); } catch (Exception cleanup) { ex.addSuppressed(cleanup); }
          throw ex;
        }
      }
      message = "ZAP 定向检测完成，返回 " + hits.size() + " 项授权范围内告警";
    } catch (TimeoutException | java.net.http.HttpTimeoutException ex) {
      status = "TIMEOUT";
      message = ex instanceof java.net.http.HttpTimeoutException
          ? "等待 ZAP 引擎响应超时，检测未完成。请检查引擎运行状态后重试。"
          : lastProgress == 100
          ? "ZAP 主动扫描已结束，但响应分析超过等待上限（" + zapScanTimeout.toSeconds()
              + " 秒），检测未完整完成。请检查引擎负载或调整等待时长后重试。"
          : "ZAP 检测达到等待上限（" + zapScanTimeout.toSeconds() + " 秒），最后进度 "
              + lastProgress + "%，检测未完成。可降低检测强度或调整等待时长后重试。";
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      status = "CANCELLED";
      message = "ZAP 定向检测已取消，检测未完成";
    } catch (Exception ex) {
      status = "FAILED";
      message = ex instanceof ApiException ? ex.getMessage() : "ZAP 引擎执行失败，检测未完成";
      LOGGER.warn("ZAP 定向检测未完成，流量 ID={}，异常类型={}", packetId, ex.getClass().getSimpleName());
    }
    audit.record("TRAFFIC_ZAP_SCAN", "TRAFFIC_PACKET", packetId,
        "status=" + status + ",hits=" + hits.size(), "COMPLETED".equals(status) ? "SUCCESS" : "FAILURE");
    TargetedScanResult result = new TargetedScanResult(packetId, "ZAP_ACTIVE", status, hits, probes, message);
    return result;
  }

  private String zapActivityDescription(ZapDaemon.ScanActivity activity) {
    if (activity == null) return "";
    StringBuilder text = new StringBuilder();
    if (activity.requestCount() != null) text.append(" · 已发送 ").append(activity.requestCount()).append(" 次请求");
    if (activity.runningRules() != null && !activity.runningRules().isEmpty()) {
      text.append(" · 当前检查：").append(String.join("、", activity.runningRules().stream().limit(3).toList()));
    }
    if ("PAUSED".equalsIgnoreCase(activity.state())) text.append(" · 引擎报告扫描已暂停");
    return text.toString();
  }

  public TargetedScanResult xrayScan(Long packetId, XrayScanRequest request) {
    return xrayScan(packetId, request, ZapScanListener.NOOP);
  }

  public TargetedScanResult xrayScan(
      Long packetId, XrayScanRequest request, ZapScanListener listener) {
    return runNotifiedScan(packetId, request == null ? null : request.targetId(), "XRAY",
        listener, (packet, target, safeListener) -> xrayScanInternal(packet, target, request, safeListener));
  }

  private TargetedScanResult xrayScanInternal(TrafficPacket packet, AuthorizedTarget target,
      XrayScanRequest request, ZapScanListener listener) {
    Long packetId = packet.getId();
    validatedPacketUri(packet, target);

    List<TargetedScanHit> hits = java.util.Collections.synchronizedList(new ArrayList<>());
    String status = "COMPLETED";
    String message;
    listener.onStart(buildUrl(packet));
    listener.onStatus("正在执行 Xray 靶向 PoC 探测...");
    try {
      Map<String, Object> params = new java.util.HashMap<>();
      String url = buildUrl(packet);
      if (url != null && !url.isBlank()) {
        params.put(WebTargetResolver.PARAM_RESOLVED_BASES, List.of(url));
      }
      if (request != null && request.allPocs()) {
        params.put("allPocs", true);
      } else if (request != null && request.pocCodes() != null && !request.pocCodes().isEmpty()) {
        params.put("pocCodes", request.pocCodes());
      } else {
        params.put("allPocs", true);
      }

      ToolExecutionResult toolResult = xrayTool.execute(
          target,
          params,
          observerFor(listener),
          draft -> {
            TargetedScanHit hit =
                new TargetedScanHit(
                    draft.title(),
                    draft.severity(),
                    draft.description(),
                    draft.vulnerabilityCode(),
                    draft.evidence(),
                    draft.remediation());
            hits.add(hit);
            listener.onHit(hit);
          });
      assertCompleteResult(toolResult, "Xray");
      // The final result is authoritative even if a live callback was not delivered.
      for (var draft : toolResult.findings()) {
        TargetedScanHit hit = new TargetedScanHit(draft.title(), draft.severity(), draft.description(),
            draft.vulnerabilityCode(), draft.evidence(), draft.remediation());
        if (!hits.contains(hit)) {
          hits.add(hit);
          listener.onHit(hit);
        }
      }
      message = hits.isEmpty() ? "Xray 检测完成，本次未发现所检查的漏洞"
          : "Xray 检测完成，发现 " + hits.size() + " 项潜在漏洞";
    } catch (Exception ex) {
      LOGGER.warn("Xray 靶向测试未完成，流量 ID={}", packetId, ex);
      status = failureStatus(ex);
      message = failureMessage("Xray", status, ex);
    }

    audit.record("TRAFFIC_XRAY_SCAN", "TRAFFIC_PACKET", packetId,
        "status=" + status + ",hits=" + hits.size(), "COMPLETED".equals(status) ? "SUCCESS" : "FAILURE");
    TargetedScanResult result =
        new TargetedScanResult(
            packetId,
            "XRAY_POC",
            status,
            List.copyOf(hits),
            List.of(),
            message);
    return result;
  }

  public TargetedScanResult sqlmapScan(Long packetId, SqlmapScanRequest request) {
    return sqlmapScan(packetId, request, ZapScanListener.NOOP);
  }

  /**
   * 使用 sqlmap 对一条流量记录做 SQL 注入复核。将流量里的完整 URL（含查询参数）与可选的
   * 表单请求体（POST --data）交回受控的 sqlmap 子进程，并把 sqlmap 的逐行过程与注入命中通过
   * {@code listener} 实时转发，实现执行过程透明。默认仅探测（--batch、不导出数据），
   * 检测强度 level/risk/technique 由调用方在授权范围内显式指定。
   */
  public TargetedScanResult sqlmapScan(
      Long packetId, SqlmapScanRequest request, ZapScanListener listener) {
    return runNotifiedScan(packetId, request == null ? null : request.targetId(), "SQLMAP",
        listener, (packet, target, safeListener) -> sqlmapScanInternal(packet, target, request, safeListener));
  }

  private TargetedScanResult sqlmapScanInternal(TrafficPacket packet, AuthorizedTarget target,
      SqlmapScanRequest request, ZapScanListener listener) {
    Long packetId = packet.getId();
    validatedPacketUri(packet, target);

    String url = buildUrl(packet);
    List<TargetedScanHit> hits = new ArrayList<>();
    List<TargetedScanProbe> probes = new ArrayList<>();
    listener.onStart(url);

    Map<String, Object> params = new java.util.HashMap<>();
    params.put(WebTargetResolver.PARAM_RESOLVED_BASES, List.of(url));
    if (request != null) {
      if (request.level() != null) params.put("level", request.level());
      if (request.risk() != null) params.put("risk", request.risk());
      if (request.technique() != null && !request.technique().isBlank()) {
        params.put("technique", request.technique());
      }
      if (request.data() != null && !request.data().isBlank()) {
        params.put("data", request.data());
      }
    }

    ToolExecutionObserver observer = observerFor(listener);
    String status = "COMPLETED";
    String message;
    try {
      ToolExecutionResult toolResult =
          sqlmapTool.execute(
              target,
              params,
              observer,
              line -> listener.onStatus(line));
      assertCompleteResult(toolResult, "sqlmap");
      for (com.bachelor.toolbox.tool.FindingDraft finding : toolResult.findings()) {
        TargetedScanHit hit =
            new TargetedScanHit(
                finding.title(),
                finding.severity(),
                finding.description(),
                finding.vulnerabilityCode(),
                finding.evidence(),
                finding.remediation());
        hits.add(hit);
        listener.onHit(hit);
      }
      message = hits.isEmpty() ? "sqlmap 检测完成，本次未确认 SQL 注入"
          : "sqlmap 检测完成，确认 " + hits.size() + " 处 SQL 注入";
    } catch (Exception ex) {
      LOGGER.warn("sqlmap 复核未完成，流量 ID={}", packetId, ex);
      status = failureStatus(ex);
      message = failureMessage("sqlmap", status, ex);
    }

    audit.record("TRAFFIC_SQLMAP_SCAN", "TRAFFIC_PACKET", packetId,
        "status=" + status + ",hits=" + hits.size(), "COMPLETED".equals(status) ? "SUCCESS" : "FAILURE");
    TargetedScanResult result =
        new TargetedScanResult(
            packetId,
            "SQLMAP",
            status,
            hits,
            probes,
            message);
    return result;
  }

  private void assertCompleteResult(ToolExecutionResult result, String engine) {
    if (result == null || result.data() == null || result.findings() == null
        || Boolean.TRUE.equals(result.data().get("partial"))
        || Boolean.FALSE.equals(result.data().get("scanCompleted"))
        || ("Xray".equals(engine) && !Boolean.TRUE.equals(result.data().get("executionVerified")))
        || ("sqlmap".equals(engine) && !(result.data().get("vulnerable") instanceof Boolean))) {
      throw new ApiException(engine + " 未返回完整的检测结果，无法判断是否存在漏洞");
    }
  }

  private String failureStatus(Exception ex) {
    if (ex instanceof InterruptedException || ex instanceof java.util.concurrent.CancellationException) {
      if (ex instanceof InterruptedException) Thread.currentThread().interrupt();
      return "CANCELLED";
    }
    return ex instanceof TimeoutException || ex instanceof java.net.SocketTimeoutException
        || ex instanceof java.net.http.HttpTimeoutException ? "TIMEOUT" : "FAILED";
  }

  private String failureMessage(String engine, String status, Exception ex) {
    if ("CANCELLED".equals(status)) return engine + " 检测已取消，本次检测未完成";
    if ("TIMEOUT".equals(status)) return engine + " 检测超时，本次检测未完成";
    return ex instanceof ApiException && ex.getMessage() != null && !ex.getMessage().isBlank()
        ? ex.getMessage() : engine + " 执行失败，本次检测未完成，请检查目标和检测引擎后重试";
  }

  @FunctionalInterface
  private interface ScanAction {
    TargetedScanResult run(TrafficPacket packet, AuthorizedTarget target, ZapScanListener listener);
  }

  private TargetedScanResult runNotifiedScan(Long packetId, Long requestedTargetId, String engine,
      ZapScanListener listener, ScanAction action) {
    String operationId = TrafficNotificationService.operationId();
    TrafficPacket packet = null;
    AuthorizedTarget target = null;
    TargetedScanResult result;
    RuntimeException failure = null;
    ZapScanListener safeListener = disconnectSafeListener(listener);
    TrafficScanLedger entry = null;
    try {
      packet = packets.findById(packetId).orElseThrow(() -> new ApiException("流量记录不存在"));
      entry = scanEntry(packet, engine);
      entry.setStatus("RUNNING");
      entry.setMessage("正在校验授权目标并准备检测");
      try { scanLedger.begin(entry); }
      catch (RuntimeException persistenceFailure) {
        entry = null;
        throw new ApiException("无法创建流量检测记录，本次检测未启动，请检查本地数据库后重试");
      }
      safeListener.onRecord(entry.getId());
      target = resolveTarget(packet, requestedTargetId);
      entry.setTargetId(target.getId());
      result = action.run(packet, target, recordingListener(entry, safeListener));
    } catch (RuntimeException exception) {
      failure = exception;
      String status = failureStatus(exception);
      result = new TargetedScanResult(packetId, engine, status, List.of(), List.of(),
          failureMessage(engine, status, exception));
    }
    Long ledgerId = recordScan(entry, target, result);
    result = new TargetedScanResult(result.packetId(), result.engine(), result.status(),
        result.hits(), result.probes(), result.message(), ledgerId);
    if (notifications != null) notifications.publish(operationId, packetId,
        target == null ? null : target.getId(), ledgerId, engine, result.status(),
        result.message(), result.hits().stream().map(TargetedScanHit::severity).toList());
    if (failure != null) throw failure;
    safeListener.onComplete(result);
    return result;
  }

  /** The client may leave this page; losing its stream must not abort the server operation. */
  private static ZapScanListener disconnectSafeListener(ZapScanListener delegate) {
    return new ZapScanListener() {
      private boolean connected = true;
      private void send(Runnable action) {
        if (!connected) return;
        try { action.run(); } catch (RuntimeException disconnected) { connected = false; }
      }
      public void onRecord(Long scanId) { if (scanId != null) send(() -> delegate.onRecord(scanId)); }
      public void onStart(String url) { send(() -> delegate.onStart(url)); }
      public void onStatus(String message) { send(() -> delegate.onStatus(message)); }
      public void onProbe(TargetedScanProbe probe) { send(() -> delegate.onProbe(probe)); }
      public void onHit(TargetedScanHit hit) { send(() -> delegate.onHit(hit)); }
      public void onComplete(TargetedScanResult result) { send(() -> delegate.onComplete(result)); }
    };
  }

  /** Persist the authoritative final result before publishing the link to it. */
  private Long recordScan(TrafficScanLedger entry, AuthorizedTarget target, TargetedScanResult result) {
    if (entry == null) return null;
    synchronized (entry) {
      try {
      entry.setTargetId(target == null ? 0L : target.getId());
      entry.setHitCount(result.hits().size());
      entry.setStatus(result.status());
      entry.setMessage(result.message());
      entry.setResultJson(resultMapper.writeValueAsString(new TargetedScanResult(result.packetId(),
          result.engine(), result.status(), result.hits(), result.probes(), result.message(), entry.getId())));
      TrafficScanLedger saved = scanLedger.record(entry);
      return saved == null ? null : saved.getId();
      } catch (Exception ex) {
        LOGGER.error("保存流量检测结果失败，记录 ID={}", entry.getId(), ex);
        throw new ApiException("流量检测结果保存失败，请检查本地数据库；不能将本次操作视为已成功归档");
      }
    }
  }

  private TrafficScanLedger scanEntry(TrafficPacket packet, String engine) {
    TrafficScanLedger entry = new TrafficScanLedger();
    entry.setEngine(engine);
    entry.setPacketId(packet.getId());
    entry.setTargetId(0L);
    entry.setHost(packet.getHost() == null ? "" : packet.getHost());
    entry.setPort(packet.getPort());
    try { entry.setUrl(buildUrl(packet)); } catch (ApiException invalidUrl) { /* Keep rejected attempts too. */ }
    return entry;
  }

  /** Persist progress independently of the browser connection, including partial evidence. */
  private ZapScanListener recordingListener(TrafficScanLedger entry, ZapScanListener delegate) {
    return new ZapScanListener() {
      private final List<TargetedScanHit> hits = new ArrayList<>();
      private final List<TargetedScanProbe> probes = new ArrayList<>();
      private void update(String message, TargetedScanHit hit, TargetedScanProbe probe, Runnable delivery) {
        // Scanner output and heartbeat workers may call concurrently, or arrive after completion.
        synchronized (entry) {
          if (!"RUNNING".equals(entry.getStatus())) return;
          if (hit != null) hits.add(hit);
          if (probe != null) probes.add(probe);
          if (message != null) entry.setMessage(message);
          entry.setHitCount(hits.size());
          try {
            entry.setResultJson(resultMapper.writeValueAsString(new TargetedScanResult(entry.getPacketId(),
                entry.getEngine(), "RUNNING", hits, probes, entry.getMessage(), entry.getId())));
            scanLedger.progress(entry);
          } catch (Exception exception) {
            throw new ApiException("流量检测进度保存失败，请检查本地数据库");
          }
          delivery.run();
        }
      }
      public void onStart(String url) { update("正在对 " + url + " 执行检测", null, null, () -> delegate.onStart(url)); }
      public void onStatus(String message) { update(message, null, null, () -> delegate.onStatus(message)); }
      public void onHit(TargetedScanHit hit) { update(null, hit, null, () -> delegate.onHit(hit)); }
      public void onProbe(TargetedScanProbe probe) { update(null, null, probe, () -> delegate.onProbe(probe)); }
    };
  }

  /** 把底层工具的可观察过程（命令/操作/心跳/进度）桥接为面向用户的实时状态推送，实现执行过程透明。 */
  private static ToolExecutionObserver observerFor(ZapScanListener listener) {
    return new ToolExecutionObserver() {
      @Override
      public void command(List<String> command) {
        listener.onStatus("执行命令: " + String.join(" ", command));
      }

      @Override
      public void operation(String operation) {
        if (operation != null && !operation.isBlank()) {
          listener.onStatus(operation);
        }
      }

      @Override
      public void progress(long completed, long total, String operation) {
        if (operation != null && !operation.isBlank()) {
          listener.onStatus(operation);
        }
      }

      @Override
      public void heartbeat(String operation) {
        if (operation != null && !operation.isBlank()) {
          listener.onStatus(operation);
        }
      }
    };
  }

  private String buildUrl(TrafficPacket packet) {
    String scheme = packet.getScheme() == null ? "http" : packet.getScheme().toLowerCase(Locale.ROOT);
    if (!Set.of("http", "https").contains(scheme) || packet.getHost() == null
        || packet.getHost().isBlank() || packet.getPort() < 0 || packet.getPort() > 65535) {
      throw new ApiException("流量记录不是有效的 HTTP 目标");
    }
    int defaultPort = "https".equals(scheme) ? 443 : 80;
    int port = packet.getPort() > 0 ? packet.getPort() : defaultPort;
    String path = packet.getPath() == null || packet.getPath().isEmpty() ? "/" : packet.getPath();
    if (!path.startsWith("/")) path = "/" + path;
    try {
      URI relative = URI.create(path);
      if (relative.getRawAuthority() != null || relative.getRawFragment() != null) {
        throw new ApiException("流量路径不能覆盖目标主机或包含片段");
      }
      URI origin = new URI(scheme, null, packet.getHost(), port == defaultPort ? -1 : port, null, null, null);
      if (origin.getHost() == null) throw new ApiException("无法识别流量目标主机");
      return URI.create(origin.toASCIIString() + path).toASCIIString();
    } catch (ApiException ex) { throw ex; }
    catch (Exception ex) { throw new ApiException("流量目标 URL 格式不正确"); }
  }

  private URI validatedPacketUri(TrafficPacket packet, AuthorizedTarget target) {
    TrafficRequestSafety.validateAuthorization(target);
    URI uri = URI.create(buildUrl(packet));
    String host = policy.validatedHost(target);
    if (!uri.getHost().equalsIgnoreCase(host)) throw new ApiException("流量主机与授权目标不一致");
    policy.validateAuthorizedPort(target, effectivePort(uri));
    return uri;
  }

  private int effectivePort(URI uri) {
    return uri.getPort() >= 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
  }

  private boolean alertMatchesTarget(String url, URI target) {
    try {
      URI candidate = URI.create(url);
      return candidate.getHost() != null && candidate.getRawUserInfo() == null
          && Set.of("http", "https").contains(candidate.getScheme())
          && candidate.getHost().equalsIgnoreCase(target.getHost())
          && effectivePort(candidate) == effectivePort(target);
    } catch (Exception ex) { return false; }
  }

  private AuthorizedTarget resolveTarget(TrafficPacket packet, Long requestedTargetId) {
    URI packetUri = URI.create(buildUrl(packet));
    int packetPort = effectivePort(packetUri);
    if (requestedTargetId != null && requestedTargetId > 0) {
      AuthorizedTarget selected = targets.get(requestedTargetId);
      validatedPacketUri(packet, selected);
      return selected;
    }
    if (packet.getTargetId() != null && packet.getTargetId() > 0) {
      AuthorizedTarget direct = targets.get(packet.getTargetId());
      if (direct != null && direct.isEnabled() && isPortAuthorized(direct, packetPort)
          && isHostMatch(direct.getTargetValue(), packetUri.getHost())) {
        return direct;
      }
      throw new ApiException("流量记录绑定的目标已停用或主机、端口不在该目标授权范围内");
    }
    String host = packetUri.getHost();
    List<AuthorizedTarget> matches =
        targetRepository.findAll().stream()
            .filter(AuthorizedTarget::isEnabled)
            .filter(t -> t.getTargetValue() != null && isHostMatch(t.getTargetValue(), host))
            .toList();

    if (matches.isEmpty()) {
      throw new ApiException("该流量记录所属主机 [" + host + "] 未绑定授权目标，无法执行主动安全测试");
    }

    List<AuthorizedTarget> candidates = matches.stream()
        .filter(t -> isPortAuthorized(t, packetPort))
        .toList();
    if (candidates.isEmpty()) throw new ApiException("流量目标端口不在已启用目标的授权范围内");
    if (candidates.size() > 1) throw new ApiException("这条流量匹配多个授权目标，请在执行前选择目标");
    return targets.get(candidates.get(0).getId());
  }

  private boolean isPortAuthorized(AuthorizedTarget target, int port) {
    if (target == null || target.getAllowedPorts() == null || target.getAllowedPorts().isBlank()) {
      return false;
    }
    try {
      return portRangeParser.parse(target.getAllowedPorts()).contains(port);
    } catch (Exception ex) {
      return false;
    }
  }

  private boolean isHostMatch(String targetValue, String host) {
    if (targetValue == null || host == null) return false;
    try {
      URI uri = URI.create(targetValue.contains("://") ? targetValue : "http://" + targetValue);
      return uri.getHost() != null && uri.getRawUserInfo() == null && uri.getHost().equalsIgnoreCase(host);
    } catch (Exception ex) {
      return false;
    }
  }

  private boolean zapAvailable() {
    try {
      SystemDependenciesResponse response = dependencies.detect(false);
      if (response == null || response.dependencies() == null) return false;
      return response.dependencies().stream()
          .anyMatch(
              dep ->
                  dep != null
                      && "OWASP ZAP".equalsIgnoreCase(dep.name())
                      && "AVAILABLE".equalsIgnoreCase(dep.status()));
    } catch (Exception ex) {
      return false;
    }
  }
}
