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
  // ZAP 内置的主动扫描策略名。可用 "Default Policy" 之外的 ZAP 内建策略按需选型。
  private static final Set<String> SUPPORTED_POLICIES =
      Set.of(
          "Default Policy",
          "Developer",
          "Security Baseline",
          "Manager",
          "Testing - HIGH",
          "Testing - MEDIUM",
          "Testing - LOW");
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
    String scanPolicy = resolveScanPolicy(parameters);
    boolean passiveOnly = isPassiveOnly(parameters);
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
      configureAuthIfPresent(daemon, parameters);

      if (withSpider) {
        runSpider(daemon, targetUri, observer);
        if (isAjaxSpiderRequested(parameters)) {
          runAjaxSpider(daemon, targetUri, observer);
        }
      }
      if (passiveOnly) {
        observer.progressPercent(100d, "爬虫完成，正在采集被动扫描结果");
        List<ZapDaemon.ZapAlert> alerts = daemon.alerts();
        return toResult(targetUri, alerts);
      }
      return runActiveScan(daemon, targetUri, strength, scanPolicy, observer);
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
      ZapDaemon daemon,
      URI target,
      String strength,
      String scanPolicy,
      ToolExecutionObserver observer)
      throws Exception {
    String scanId = null;
    long deadline =
        System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(scanTimeoutSeconds);
    observer.operation(
        "正在对 "
            + target
            + " 执行主动漏洞扫描（策略 "
            + (scanPolicy == null ? "默认" : scanPolicy)
            + "，强度 "
            + strength
            + "）");
    scanId = daemon.startActiveScan(target, scanPolicy);
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
    int passiveCount = 0;
    int activeCount = 0;
    for (ZapDaemon.ZapAlert alert : alerts) {
      if (!isAuthorized(alert.url(), target)) {
        continue;
      }
      inScope++;
      if (isPassiveSource(alert)) passiveCount++;
      else activeCount++;
      if (findings.size() >= MAX_FINDINGS) {
        break;
      }
      findings.add(toFinding(alert));
      matches.add(
          Map.of(
              "name", alert.name(),
              "severity", normalizeSeverity(alert.risk()),
              "url", alert.url(),
              "source", isPassiveSource(alert) ? "passive" : "active",
              "cwe", alert.cweId() == null ? "" : alert.cweId()));
    }
    Map<String, Object> data = new LinkedHashMap<>();
    data.put("matchCount", findings.size());
    data.put("inScopeAlertCount", inScope);
    data.put("passiveAlertCount", passiveCount);
    data.put("activeAlertCount", activeCount);
    data.put("matches", matches);
    return new ToolExecutionResult(
        "ZAP 扫描完成，命中 " + findings.size() + " 项在授权范围内的潜在问题（被动 "
            + passiveCount
            + "，主动 "
            + activeCount
            + "）",
        data,
        findings);
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

  private String resolveScanPolicy(Map<String, Object> parameters) {
    if (parameters == null || parameters.get("scanPolicy") == null) {
      return null;
    }
    String policy = Objects.toString(parameters.get("scanPolicy"), "").trim();
    if (policy.isBlank()) {
      return null;
    }
    if (!SUPPORTED_POLICIES.contains(policy)) {
      throw new ApiException("不支持的 ZAP 扫描策略: " + policy);
    }
    return policy;
  }

  // 被动扫描只跑爬虫取材 + 被动规则，不做主动攻击注入，风险更低。
  private boolean isPassiveOnly(Map<String, Object> parameters) {
    if (parameters == null) {
      return false;
    }
    String mode = Objects.toString(parameters.get("mode"), "").trim().toLowerCase(Locale.ROOT);
    return "passive".equals(mode);
  }

  // ZAP alert 的 sourceid：0=被动扫描，1=主动扫描，3=手动。非 0 之外按主动归并。
  private boolean isPassiveSource(ZapDaemon.ZapAlert alert) {
    return alert.sourceId() == 0;
  }

  // 若调用方传了登录相关参数，则在爬虫/主动扫描前为上下文配置表单认证。
  private void configureAuthIfPresent(ZapDaemon daemon, Map<String, Object> parameters)
      throws Exception {
    if (parameters == null) {
      return;
    }
    String loginUrl = Objects.toString(parameters.get("authLoginUrl"), "").trim();
    String username = Objects.toString(parameters.get("authUsername"), "").trim();
    if (loginUrl.isBlank() || username.isBlank()) {
      return;
    }
    String password = Objects.toString(parameters.get("authPassword"), "");
    String userField = Objects.toString(parameters.get("authUsernameField"), "username").trim();
    String passField = Objects.toString(parameters.get("authPasswordField"), "password").trim();
    String postData = "username=" + username + "&password=" + password;
    daemon.configureFormAuthentication(
        new ZapDaemon.FormAuthSpec(null, loginUrl, loginUrl, userField, passField, postData));
  }

  private boolean isAjaxSpiderRequested(Map<String, Object> parameters) {
    return Boolean.TRUE
        .equals(parameters == null ? null : parameters.get("ajaxSpider"));
  }

  // AJAX 爬虫无固定完成点，采用有界轮询：直到 ZAP 报告 stopped 或到达时长上限。
  private void runAjaxSpider(ZapDaemon daemon, URI target, ToolExecutionObserver observer)
      throws Exception {
    try {
      observer.operation("正在对 " + target + " 执行 AJAX 深段爬虫（SPA）");
      daemon.startAjaxSpider(target);
      long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(5);
      while (System.nanoTime() < deadline) {
        if (observer.isCancellationRequested()) {
          throw new ApiException("任务已取消");
        }
        String state = daemon.ajaxSpiderState();
        if (state.contains("stopped")) {
          observer.progressPercent(100d, "AJAX 爬虫完成");
          return;
        }
        observer.progressPercent(50d, "AJAX 爬虫进行中");
        Thread.sleep(1500);
      }
      observer.progressPercent(100d, "AJAX 爬虫到达时长上限，结束");
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      LOGGER.warn("ZAP AJAX 爬虫失败，将继续后续扫描", ex);
    }
  }
}