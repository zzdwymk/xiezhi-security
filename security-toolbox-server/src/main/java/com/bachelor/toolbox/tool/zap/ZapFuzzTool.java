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
import java.util.concurrent.Semaphore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * OWASP ZAP adapter that runs the ZAP fuzzer against a single authorized HTTP request. It drives
 * ZAP's {@code fuzzer} REST API end to end and folds the resulting alerts into the project's
 * {@link FindingDraft} pipeline.
 *
 * <p>ZAP's fuzzer field names vary between releases; every fuzz call is best-effort, so a
 * version mismatch or an unavailable payload degrades to an empty match set instead of crashing.
 */
@Component
public class ZapFuzzTool implements SecurityTool {
  private static final Logger LOGGER = LoggerFactory.getLogger(ZapFuzzTool.class);
  private static final Semaphore DAEMON_LOCK = new Semaphore(1);
  private static final int MAX_FINDINGS = 200;

  private final TargetPolicyService policy;
  private final ZapDaemonSupplier daemonSupplier;

  public ZapFuzzTool(TargetPolicyService policy, ZapDaemonSupplier daemonSupplier) {
    this.policy = policy;
    this.daemonSupplier = daemonSupplier;
  }

  @Override
  public String code() {
    return "zap_fuzz";
  }

  @Override
  public String displayName() {
    return "ZAP 参数模糊测试";
  }

  @Override
  public String description() {
    return "对授权 Web 目标的指定请求/参数运行 OWASP ZAP 模糊压测（Fuzz）";
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
    if (!DAEMON_LOCK.tryAcquire()) {
      throw new ApiException("已有 ZAP 模糊测试正在进行，请稍后再试");
    }
    try {
      int acquired = 1;
      try (ZapDaemon daemon = daemonSupplier.create()) {
        daemon.start();
        daemon.includeInScope(targetUri);
        observer.operation("ZAP daemon 已就绪，正在启动参数模糊压测");

        ZapDaemon.FuzzSpec spec = buildFuzzSpec(targetUri, parameters);
        if (spec == null) {
          return emptyResult("缺少可执行的 fuzz 参数（需指定 requestUrl 和 payload）");
        }

        String fuzzId = daemon.startFuzz(spec);
        if (fuzzId == null || fuzzId.isBlank()) {
          return emptyResult("ZAP fuzz 未能启动（可能不支持当前 payload 或版本差异）");
        }

        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(10);
        while (System.nanoTime() < deadline) {
          if (observer.isCancellationRequested()) {
            throw new ApiException("任务已取消");
          }
          String state = daemon.fuzzStatus(fuzzId);
          if (state.contains("stopped") && !state.contains("stopped=false")) {
            break;
          }
          observer.progressPercent(60d, "ZAP 模糊压测进行中");
          Thread.sleep(1200);
        }
        observer.progressPercent(100d, "模糊压测完成，正在解析结果");

        List<ZapDaemon.ZapAlert> alerts = daemon.alerts();
        return toResult(targetUri, alerts);
      }
    } finally {
      DAEMON_LOCK.release();
    }
  }

  private ZapDaemon.FuzzSpec buildFuzzSpec(URI target, Map<String, Object> parameters) {
    if (parameters == null) {
      return null;
    }
    String requestUrl = Objects.toString(parameters.get("fuzzRequestUrl"), "").trim();
    if (requestUrl.isBlank()) {
      requestUrl = target.toString();
    }
    String method = Objects.toString(parameters.get("method"), "POST").trim().toUpperCase(Locale.ROOT);
    String postBody = Objects.toString(parameters.get("fuzzPostBody"), "");
    String payload = Objects.toString(parameters.get("fuzzPayload"), "").trim();
    String field = Objects.toString(parameters.get("fuzzTargetField"), "").trim();
    if (payload.isBlank() && field.isBlank()) {
      return null;
    }
    return new ZapDaemon.FuzzSpec(target, requestUrl, method, postBody, payload, field);
  }

  private ToolExecutionResult emptyResult(String message) {
    return new ToolExecutionResult(message, Map.of("matchCount", 0, "matches", List.of()), List.of());
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
              "url", alert.url()));
    }
    Map<String, Object> data = new LinkedHashMap<>();
    data.put("matchCount", findings.size());
    data.put("inScopeAlertCount", inScope);
    data.put("matches", matches);
    return new ToolExecutionResult(
        "ZAP 模糊压测完成，命中 " + findings.size() + " 项在授权范围内的潜在问题", data, findings);
  }

  private FindingDraft toFinding(ZapDaemon.ZapAlert alert) {
    String evidence = "url=" + alert.url();
    if (alert.cweId() != null && !alert.cweId().isBlank()) {
      evidence += "; cwe=" + alert.cweId();
    }
    return new FindingDraft(
        alert.name(),
        normalizeSeverity(alert.risk()),
        alert.description(),
        evidence,
        "结合 ZAP 模糊测试告警评估业务影响，确认后修复并复测。",
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

  private boolean isAuthorized(String url, URI target) {
    if (url == null || url.isBlank()) {
      return false;
    }
    try {
      URI candidate =
          URI.create(url.startsWith("http") || url.startsWith("https") ? url : target.getScheme() + "://" + url);
      if (candidate.getHost() == null) {
        return false;
      }
      return candidate.getHost().equalsIgnoreCase(target.getHost())
          && port(candidate) == port(target);
    } catch (IllegalArgumentException ex) {
      return false;
    }
  }

  private int port(URI uri) {
    if (uri.getPort() > 0) return uri.getPort();
    return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
  }
}