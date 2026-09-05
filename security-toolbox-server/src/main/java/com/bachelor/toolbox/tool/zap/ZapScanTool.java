package com.bachelor.toolbox.tool.zap;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.tool.FindingDraft;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Semaphore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * OWASP ZAP adapter that performs an active (DAST) scan of an authorized web target. ZAP runs as a
 * headless daemon exposed over its JSON REST API; this tool drives spider + active scan, streams
 * native progress through {@link ToolExecutionObserver}, and converts ZAP alerts into the project's
 * {@link FindingDraft} model so results flow into the same report/task pipeline as the other
 * scanners.
 *
 * <p>ZAP serializes scan work to a single daemon, so a JVM-wide {@link Semaphore} prevents
 * concurrent scans from clashing on the shared instance while still allowing the rest of the
 * toolbox to run in parallel.
 */
@Component
public class ZapScanTool implements SecurityTool {
  private static final Logger LOGGER = LoggerFactory.getLogger(ZapScanTool.class);
  private static final Semaphore DAEMON_LOCK = new Semaphore(1);
  private static final Set<String> SUPPORTED_STRENGTHS = Set.of("LOW", "MEDIUM", "HIGH", "INSANE");
  private static final int MAX_FINDINGS = 300;

  private final TargetPolicyService policy;
  private final ZapDaemonSupplier daemonSupplier;
  private final long scanTimeoutSeconds;

  public ZapScanTool(
      TargetPolicyService policy,
      ZapDaemonSupplier daemonSupplier,
      @Value("${toolbox.execution.zap-scan-timeout-seconds:1800}") long scanTimeoutSeconds) {
    this.policy = policy;
    this.daemonSupplier = daemonSupplier;
    this.scanTimeoutSeconds = scanTimeoutSeconds;
  }

  @Override
  public String code() {
    return "zap_scan";
  }

  @Override
  public String displayName() {
    return "OWASP ZAP 主动扫描";
  }

  @Override
  public String description() {
    return "在授权 Web 目标上运行 OWASP ZAP 主动漏洞扫描（爬虫 + 主动攻击）";
  }

  @Override
  public ToolExecutionResult execute(AuthorizedTarget target, Map<String, Object> parameters)
      throws Exception {
    return execute(target, parameters, ToolExecutionObserver.NOOP);
  }

  @Override
  public ToolExecutionResult execute(
      AuthorizedTarget target, Map<String, Object> parameters, ToolExecutionObserver observer)
      throws Exception {
    URI targetUri = policy.validatedHttpUri(target);
    String strength = resolveStrength(parameters);
    boolean withSpider = !Boolean.FALSE.equals(parameters == null ? null : parameters.get("spider"));

    int acquired = 0;
    if (!DAEMON_LOCK.tryAcquire()) {
      throw new ApiException("已有 ZAP 扫描正在进行，请稍后再试");
    }
    acquired = 1;
    try (ZapDaemon daemon = daemonSupplier.create()) {
      daemon.start();
      observer.operation("ZAP daemon 已就绪，正在将目标纳入扫描范围");
      daemon.includeInScope(targetUri);

      if (withSpider) {
        runSpider(daemon, targetUri, observer);
      }
      return runActiveScan(daemon, targetUri, strength, observer);
    } catch (Exception ex) {
      if (ex instanceof ApiException) {
        throw ex;
      }
      LOGGER.warn("ZAP 扫描失败 target={}", targetUri, ex);
      throw new ApiException("ZAP 主动扫描执行失败：" + ex.getMessage());
    } finally {
      if (acquired == 1) {
        DAEMON_LOCK.release();
      }
    }
  }

  private void runSpider(ZapDaemon daemon, URI target, ToolExecutionObserver observer)
      throws Exception {
    String spiderId;
    try {
      observer.operation("正在对 " + target + " 进行爬虫");
      spiderId = daemon.startSpider(target);
      while (true) {
        int progress = daemon.spiderProgress(spiderId);
        if (progress >= 100) break;
        observer.progressPercent(progress, "ZAP 爬虫");
        if (observer.isCancellationRequested()) {
          daemon.stopSpider(spiderId);
          throw new ApiException("任务已取消");
        }
        Thread.sleep(600);
      }
      observer.progressPercent(100d, "爬虫完成");
    } catch (Exception ex) {
      if (ex instanceof ApiException) throw ex;
      LOGGER.warn("ZAP 爬虫阶段失败，将继续尝试主动扫描", ex);
    }
  }

  private ToolExecutionResult runActiveScan(
      ZapDaemon daemon, URI target, String strength, ToolExecutionObserver observer)
      throws Exception {
    String scanId = null;
    long deadline =
        System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(scanTimeoutSeconds);
    observer.operation("正在对 " + target + " 执行主动漏洞扫描（强度 " + strength + "）");
    scanId = daemon.startActiveScan(target);
    while (true) {
      Integer progress = daemon.activeScanProgress(scanId);
      if (progress == null || progress >= 100) break;
      observer.progressPercent(progress.doubleValue(), "ZAP 主动扫描");
      if (observer.isCancellationRequested()) {
        daemon.stopActiveScan(scanId);
        throw new ApiException("任务已取消");
      }
      if (System.nanoTime() >= deadline) {
        daemon.stopActiveScan(scanId);
        throw new ApiException("ZAP 主动扫描超过 " + scanTimeoutSeconds + " 秒，已停止");
      }
      Thread.sleep(1000);
    }
    observer.progressPercent(100d, "主动扫描完成，正在解析结果");

    List<ZapDaemon.ZapAlert> alerts = daemon.alerts();
    return toResult(target, alerts);
  }

  private ToolExecutionResult toResult(URI target, List<ZapDaemon.ZapAlert> alerts) {
    List<FindingDraft> findings = new ArrayList<>();
    List<Map<String, Object>> matches = new ArrayList<>();
    int inScope = 0;
    for (ZapDaemon.ZapAlert alert : alerts) {
      if (!isAuthorized(alert.url(), target)) {
        continue;
      }
      inScope++;
      if (findings.size() >= MAX_FINDINGS) {
        break;
      }
      findings.add(toFinding(alert));
      matches.add(
          Map.of(
              "name", alert.name(),
              "severity", normalizeSeverity(alert.risk()),
              "url", alert.url(),
              "cwe", alert.cweId() == null ? "" : alert.cweId()));
    }
    Map<String, Object> data = new LinkedHashMap<>();
    data.put("matchCount", findings.size());
    data.put("inScopeAlertCount", inScope);
    data.put("matches", matches);
    return new ToolExecutionResult(
        "ZAP 主动扫描完成，命中 " + findings.size() + " 项在授权范围内的潜在问题", data, findings);
  }

  private FindingDraft toFinding(ZapDaemon.ZapAlert alert) {
    String evidence = "url=" + alert.url();
    if (alert.cweId() != null && !alert.cweId().isBlank()) {
      evidence += "; cwe=" + alert.cweId();
    }
    return new FindingDraft(
        alert.name(),
        normalizeSeverity(alert.risk()),
        descriptionsFor(alert),
        evidence,
        "结合 ZAP 告警评估业务影响，确认后修复并复测。",
        alert.cweId());
  }

  private String normalizeSeverity(String risk) {
    if (risk == null || risk.isBlank()) {
      return "INFO";
    }
    String upper = risk.toUpperCase(Locale.ROOT);
    if (upper.contains("CRITICAL")) return "CRITICAL";
    if (upper.contains("HIGH")) return "HIGH";
    if (upper.contains("MEDIUM")) return "MEDIUM";
    if (upper.contains("LOW")) return "LOW";
    return "INFO";
  }

  private String descriptionsFor(ZapDaemon.ZapAlert alert) {
    String base = alert.description() == null || alert.description().isBlank()
        ? "OWASP ZAP 在授权目标上主动扫描命中的潜在安全问题。"
        : alert.description();
    return base;
  }

  private boolean isAuthorized(String url, URI target) {
    if (url == null || url.isBlank()) {
      return false;
    }
    try {
      URI candidate = URI.create(url.startsWith("http") || url.startsWith("https") ? url : target.getScheme() + "://" + url);
      if (candidate.getHost() == null) {
        return false;
      }
      return candidate.getHost().equalsIgnoreCase(target.getHost()) && port(candidate) == port(target);
    } catch (IllegalArgumentException ex) {
      return false;
    }
  }

  private int port(URI uri) {
    if (uri.getPort() > 0) return uri.getPort();
    return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
  }

  private String resolveStrength(Map<String, Object> parameters) {
    if (parameters == null || parameters.get("strength") == null) {
      return "MEDIUM";
    }
    String strength = Objects.toString(parameters.get("strength"), "").trim().toUpperCase(Locale.ROOT);
    if (!SUPPORTED_STRENGTHS.contains(strength)) {
      throw new ApiException("不支持的 ZAP 攻击强度: " + strength);
    }
    return strength;
  }
}