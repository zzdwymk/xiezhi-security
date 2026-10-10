package com.bachelor.toolbox.tool.zap;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.WebTargetResolver;
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
import java.util.Set;
import java.util.concurrent.Semaphore;
import org.springframework.stereotype.Component;

/**
 * Sends one literal query/form field mutation through ZAP and collects its passive alerts.
 * The bundled GUI fuzzer has no REST API; no dictionary, file, script, or generator is executed.
 */
@Component
public class ZapFuzzTool implements SecurityTool {
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
    return "ZAP 单次参数变异验证";
  }

  @Override
  public String description() {
    return "将一个字面值替换授权请求的指定字段，发送一次请求并收集 ZAP 被动告警";
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
    ZapDaemon.FuzzSpec spec = buildFuzzSpec(target, parameters);
    URI targetUri = URI.create(spec.requestUrl());
    if (observer.isCancellationRequested()) throw new ApiException("任务已取消");
    if (!DAEMON_LOCK.tryAcquire()) {
      throw new ApiException("已有 ZAP 参数变异验证正在进行，请稍后再试");
    }
    try {
      try (ZapDaemon daemon = daemonSupplier.create()) {
        try {
          daemon.start();
          daemon.includeInScope(targetUri);
          if (observer.isCancellationRequested()) throw new ApiException("任务已取消");
          observer.operation("ZAP 已就绪，正在发送单次参数变异请求");
          String fuzzId = daemon.startFuzz(spec);
          if (fuzzId == null || fuzzId.isBlank()) {
            throw new ApiException("ZAP 未确认参数变异请求响应，检测未完成");
          }
          awaitCompletion(daemon, fuzzId, observer,
              System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(2));
          List<ZapDaemon.ZapAlert> alerts = daemon.alerts();
          if (alerts == null) throw new ApiException("ZAP 未返回有效告警结果，检测未完成");
          if (observer.isCancellationRequested()) throw new ApiException("任务已取消");
          observer.progressPercent(100d, "单次参数变异验证与被动检查完成");
          return toResult(targetUri, alerts);
        } catch (Exception ex) {
          try { daemon.kill(); } catch (Exception cleanup) { ex.addSuppressed(cleanup); }
          throw ex;
        }
      }
    } finally {
      DAEMON_LOCK.release();
    }
  }

  void awaitCompletion(ZapDaemon daemon, String fuzzId, ToolExecutionObserver observer, long deadline)
      throws Exception {
    while (true) {
      if (observer.isCancellationRequested()) throw new ApiException("任务已取消");
      if (System.nanoTime() >= deadline) throw new ApiException("ZAP 被动检查超时，检测未完成");
      String state = daemon.fuzzStatus(fuzzId);
      String phase = state == null ? "" : state.split(";", 2)[0];
      if ("stopped".equals(phase)) return;
      if (!"running".equals(phase)) throw new ApiException("ZAP 返回未知执行状态，检测未完成");
      observer.heartbeat("参数变异请求已响应，正在等待 ZAP 被动检查");
      Thread.sleep(250);
    }
  }

  private ZapDaemon.FuzzSpec buildFuzzSpec(AuthorizedTarget target, Map<String, Object> parameters) {
    Map<String, Object> values = WebTargetResolver.scanParameters(parameters);
    if (values == null || !Set.of("fuzzRequestUrl", "method", "fuzzPostBody", "fuzzPayload", "fuzzTargetField")
        .containsAll(values.keySet())) throw new ApiException("参数变异请求包含未知或缺失参数");
    String requestUrl = stringValue(values, "fuzzRequestUrl", null);
    URI uri;
    try { uri = URI.create(requestUrl == null ? "" : requestUrl); }
    catch (IllegalArgumentException ex) { throw new ApiException("fuzzRequestUrl 格式不正确"); }
    String host = policy.validatedHost(target);
    if (uri.getHost() == null || !uri.getHost().equalsIgnoreCase(host)) {
      throw new ApiException("参数变异请求主机与授权目标不一致");
    }
    policy.validateAuthorizedPort(target, port(uri));
    ZapDaemon.FuzzSpec spec = new ZapDaemon.FuzzSpec(uri, requestUrl,
        stringValue(values, "method", "POST"), stringValue(values, "fuzzPostBody", ""),
        stringValue(values, "fuzzPayload", null), stringValue(values, "fuzzTargetField", null));
    spec.requestMessage(); // Check field existence/uniqueness before starting a daemon or sending traffic.
    return spec;
  }

  private String stringValue(Map<String, Object> values, String key, String fallback) {
    if (!values.containsKey(key)) return fallback;
    if (!(values.get(key) instanceof String value)) throw new ApiException(key + " 必须是字符串");
    return value;
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
    data.put("requestCount", 1);
    data.put("mode", "SINGLE_PARAMETER_MUTATION");
    data.put("matchCount", findings.size());
    data.put("inScopeAlertCount", inScope);
    data.put("matches", matches);
    return new ToolExecutionResult(
        "单次参数变异验证完成，ZAP 被动告警 " + findings.size() + " 项", data, findings);
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
        "结合单次参数变异请求的 ZAP 被动告警评估业务影响，确认后修复并复测。",
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
    if (uri.getPort() >= 0) return uri.getPort();
    return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
  }
}
