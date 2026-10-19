package com.bachelor.toolbox.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Client for the local runtime's Jev-style semantic judge.
 *
 * <h2>What it is for</h2>
 *
 * <p>Before a plan is shown to an administrator for confirmation, each step is classified into
 * "what does this actually do" plus a risk level. The verdict is attached to the approval ticket so
 * the dialog can show a plain-language warning ("疑似 SQL 注入探测") instead of a bare tool code.
 *
 * <h2>Fail-closed, unconditionally</h2>
 *
 * <p>Every failure — runtime disabled, model not configured, HTTP error, timeout, unparseable body,
 * missing field — resolves to a <em>degraded</em> verdict with {@code allow=false} and
 * {@code risk=CRITICAL}. There is intentionally no path that produces "allow" without a real
 * answer, because a judge that is down must never look like a judge that approved.
 *
 * <p>The judge is advisory: it cannot grant execution. The approval record and the four-layer
 * capability gate remain the only thing that decides whether anything runs.
 */
@Service
public class SemanticJudgeClient {
  private static final Logger log = LoggerFactory.getLogger(SemanticJudgeClient.class);

  /** Bound on how many steps get judged per plan; matches the per-dispatch action limit. */
  private static final int MAX_JUDGED_STEPS = 16;

  private final ObjectMapper mapper;
  private final boolean enabled;
  private final String baseUrl;
  private final String runtimeToken;
  private final Duration timeout;
  private final HttpClient http;

  public SemanticJudgeClient(
      ObjectMapper mapper,
      @Value("${toolbox.ai.agent.runtime-base-url:}") String configuredBaseUrl,
      @Value("${toolbox.ai.agent.runtime-port:8090}") int port,
      @Value("${toolbox.ai.agent.runtime-token:}") String runtimeToken,
      @Value("${toolbox.ai.agent.semantic-judge-enabled:true}") boolean enabled,
      @Value("${toolbox.ai.agent.semantic-judge-timeout-seconds:20}") int timeoutSeconds) {
    this.mapper = mapper;
    this.enabled = enabled;
    // Same loopback-only rule as AiAgentRuntimeClient: the judge is a local service, and accepting
    // a remote base URL here would ship target metadata and command text off the machine.
    String resolved =
        configuredBaseUrl == null || configuredBaseUrl.isBlank()
            ? "http://127.0.0.1:" + Math.max(1, Math.min(port, 65535))
            : configuredBaseUrl.strip();
    if (!resolved.matches("https?://(127\\.0\\.0\\.1|localhost|\\[::1])(?::\\d+)?/?")) {
      throw new IllegalArgumentException("语义判官仅允许连接本机回环地址");
    }
    this.baseUrl = stripTrailingSlash(resolved);
    this.runtimeToken = runtimeToken == null ? "" : runtimeToken.strip();
    this.timeout = Duration.ofSeconds(Math.max(1, Math.min(timeoutSeconds, 30)));
    this.http =
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .version(HttpClient.Version.HTTP_1_1)
            .build();
  }

  private static String stripTrailingSlash(String value) {
    String result = value;
    while (result.endsWith("/")) {
      result = result.substring(0, result.length() - 1);
    }
    return result;
  }

  /**
   * Judges every step of a plan.
   *
   * @return a serialisable verdict document, never null. When the judge cannot run at all the
   *     document carries {@code degraded=true} and an empty {@code steps} list, which the UI is
   *     expected to render as "未能判定，请人工判断".
   */
  public Map<String, Object> judgePlan(List<AiPlanResponse.PlanStep> steps, Long targetId) {
    Map<String, Object> document = new LinkedHashMap<>();
    List<Map<String, Object>> judged = new ArrayList<>();
    boolean anyDegraded = false;
    boolean anyBlocking = false;
    String worstRisk = "SAFE";
    String headline = "";

    if (steps == null || steps.isEmpty()) {
      document.put("degraded", false);
      document.put("steps", List.of());
      document.put("worstRisk", "SAFE");
      document.put("requiresHumanReview", false);
      return document;
    }
    if (!enabled || baseUrl == null || baseUrl.isBlank()) {
      return unavailableDocument("判官未启用或智能服务地址不可达，请人工判断");
    }

    int judgedCount = 0;
    for (AiPlanResponse.PlanStep step : steps) {
      if (step == null || judgedCount >= MAX_JUDGED_STEPS) {
        continue;
      }
      judgedCount++;
      Map<String, Object> verdict = judgeOne(step, targetId);
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("workflowNodeId", step.workflowNodeId());
      entry.put("toolCode", step.toolCode());
      entry.put("allow", verdict.get("allow"));
      entry.put("behaviour", verdict.get("behaviour"));
      entry.put("risk", verdict.get("risk"));
      entry.put("confidence", verdict.get("confidence"));
      entry.put("summary", verdict.get("summary"));
      entry.put("degraded", verdict.get("degraded"));
      entry.put("degradedReason", verdict.get("degradedReason"));
      judged.add(entry);

      if (Boolean.TRUE.equals(verdict.get("degraded"))) {
        anyDegraded = true;
      }
      if (!Boolean.TRUE.equals(verdict.get("allow"))) {
        anyBlocking = true;
      }
      worstRisk = stricter(worstRisk, String.valueOf(verdict.get("risk")));
      if (headline.isBlank() && !Boolean.TRUE.equals(verdict.get("allow"))) {
        headline = String.valueOf(verdict.get("behaviour"));
      }
    }

    document.put("degraded", anyDegraded);
    document.put("steps", judged);
    document.put("worstRisk", worstRisk);
    // "Requires human review" is true whenever anything was not positively cleared, including
    // degraded verdicts. The dialog uses this to decide whether to show the warning banner.
    document.put("requiresHumanReview", anyBlocking || anyDegraded || judged.isEmpty());
    document.put("headline", headline);
    return document;
  }

  /** Judges a single step. Never throws; every failure returns a degraded verdict. */
  public Map<String, Object> judgeOne(AiPlanResponse.PlanStep step, Long targetId) {
    Map<String, Object> action = new LinkedHashMap<>();
    action.put("toolCode", step.toolCode());
    action.put("title", step.title());
    action.put("reason", step.reason());
    action.put("parameters", step.parameters() == null ? Map.of() : step.parameters());
    if (targetId != null) {
      action.put("targetId", targetId);
    }
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("action", action);
    try {
      String body = mapper.writeValueAsString(payload);
      HttpRequest.Builder builder =
          HttpRequest.newBuilder(URI.create(baseUrl + "/agent/judge/evaluate"))
              .timeout(timeout)
              .header("Content-Type", "application/json")
              .POST(HttpRequest.BodyPublishers.ofString(body));
      if (runtimeToken != null && !runtimeToken.isBlank()) {
        // Must match require_runtime_token() in ai-runtime/app/security.py exactly.
        builder.header("X-AI-Runtime-Token", runtimeToken);
      }
      HttpResponse<String> response =
          http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() != 200) {
        log.warn("语义判官返回非 200（{}），按未判定处理", response.statusCode());
        return degradedVerdict("judge_http_" + response.statusCode());
      }
      JsonNode node = mapper.readTree(response.body());
      Map<String, Object> verdict = new LinkedHashMap<>();
      verdict.put("allow", node.path("allow").asBoolean(false));
      verdict.put("behaviour", node.path("behaviour").asText("未知高风险行为"));
      verdict.put("risk", node.path("risk").asText("CRITICAL"));
      verdict.put("confidence", node.path("confidence").asDouble(0d));
      verdict.put("summary", node.path("summary").asText(""));
      verdict.put("degraded", node.path("degraded").asBoolean(true));
      verdict.put("degradedReason", node.path("degradedReason").asText(""));
      return verdict;
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      return degradedVerdict("judge_interrupted");
    } catch (Exception ex) {
      log.warn("语义判官调用失败：{}", ex.getClass().getSimpleName());
      return degradedVerdict("judge_unavailable");
    }
  }

  /** True when the judge is configured and reachable enough to be asked at all. */
  public boolean available() {
    return enabled && baseUrl != null && !baseUrl.isBlank();
  }

  private Map<String, Object> degradedVerdict(String reason) {
    Map<String, Object> verdict = new LinkedHashMap<>();
    verdict.put("allow", false);
    verdict.put("behaviour", "判官熔断（无法判定）");
    verdict.put("risk", "CRITICAL");
    verdict.put("confidence", 0.0);
    verdict.put("summary", "语义判官未能给出可信判定，已按最坏情况拦截并转人工确认");
    verdict.put("degraded", true);
    verdict.put("degradedReason", reason);
    return verdict;
  }

  private Map<String, Object> unavailableDocument(String reason) {
    Map<String, Object> document = new LinkedHashMap<>();
    document.put("degraded", true);
    document.put("steps", List.of());
    document.put("worstRisk", "CRITICAL");
    document.put("requiresHumanReview", true);
    document.put("headline", "判官熔断（无法判定）");
    document.put("degradedReason", reason);
    return document;
  }

  /** Returns whichever risk level is more severe; unknown values count as CRITICAL. */
  static String stricter(String left, String right) {
    List<String> order = List.of("SAFE", "CAUTION", "HIGH", "CRITICAL");
    int leftIndex = order.indexOf(String.valueOf(left).toUpperCase());
    int rightIndex = order.indexOf(String.valueOf(right).toUpperCase());
    if (leftIndex < 0 || rightIndex < 0) {
      return "CRITICAL";
    }
    return leftIndex >= rightIndex ? left : right;
  }
}
