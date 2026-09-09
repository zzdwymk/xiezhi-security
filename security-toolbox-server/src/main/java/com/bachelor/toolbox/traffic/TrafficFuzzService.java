package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse;
import com.bachelor.toolbox.tool.zap.ZapDaemon;
import com.bachelor.toolbox.tool.zap.ZapDaemonSupplier;
import com.bachelor.toolbox.traffic.TrafficReplayService.ReplayRequest;
import com.bachelor.toolbox.traffic.TrafficReplayService.ReplayResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Parameter fuzzing against an authorized HTTP target. The request (method/URL/headers or body) may
 * contain one or more placeholder variables of the form {@code §name§}. Each variable can be given
 * its own payload list; every payload is substituted in turn and the request is replayed through
 * {@link TrafficReplayService}, then every response is compared to a baseline (all variables :=
 * empty) to surface likely reflections or anomalies.
 *
 * <p>Multiple variables are combined per the chosen {@code combination} strategy, mirroring Burp
 * Intruder Attack Types:
 * <ul>
 *   <li>{@code SNIPER}: single payload set tested against each placeholder position in turn,
 *       keeping base values in other positions.</li>
 *   <li>{@code BATTERING_RAM}: single payload set tested against all placeholder positions
 *       simultaneously.</li>
 *   <li>{@code PITCHFORK}: multiple payload sets iterated in lockstep (defaults to shortest list,
 *       also aliased as {@code SHORTEST}).</li>
 *   <li>{@code PITCHFORK_LONGEST}: multiple payload sets iterated in lockstep, shorter lists
 *       repeating their last value (aliased as {@code LONGEST}).</li>
 *   <li>{@code CLUSTER_BOMB}: Cartesian product of all payload sets (aliased as {@code CARTESIAN}).</li>
 * </ul>
 *
 * <p>When an OWASP ZAP installation is detected, the whole request is handed to ZAP's fuzzer (which
 * contributes ZAP's own Fuzz DB / payload generation and encoders) and the resulting alerts are
 * folded into a {@code engine=ZAP} response; otherwise the self-contained loop runs {@code
 * engine=LOOP}. ZAP is best-effort: any detection, start, or version mismatch degrades back to the
 * loop instead of failing. A baseline request always runs first in the loop path so all payloads can
 * be diffed for response changes.
 */
@Service
public class TrafficFuzzService {
  private static final Logger LOGGER = LoggerFactory.getLogger(TrafficFuzzService.class);
  private static final String MARKER = "\u00a7name\u00a7"; // §name§
  private static final Pattern VARIABLE = Pattern.compile("§([^§]+)§");
  private static final int MAX_PAYLOADS = 200;
  private static final int MAX_PAYLOAD_LENGTH = 4 * 1024;
  private static final int MAX_DISPLAY_PAYLOAD = 48;
  private static final long ZAP_FUZZ_DEADLINE_MINUTES = 8;

  private final TrafficReplayService replay;
  private final ZapDaemonSupplier daemonSupplier;
  private final DependencyDetectionService dependencies;

  @Autowired
  public TrafficFuzzService(
      TrafficReplayService replay,
      ZapDaemonSupplier daemonSupplier,
      DependencyDetectionService dependencies) {
    this.replay = replay;
    this.daemonSupplier = daemonSupplier;
    this.dependencies = dependencies;
  }

  /** Backwards-compatible constructor used by tests when no ZAP path is required. */
  public TrafficFuzzService(TrafficReplayService replay) {
    this(replay, null, null);
  }

  public FuzzResponse fuzz(Long packetId, FuzzRequest request) {
    if (request == null) {
      throw new ApiException("fuzz 请求不能为空");
    }
    String url = request.url() == null ? "" : request.url();
    String body = request.body() == null ? "" : request.body();
    String headers = request.headers() == null ? "" : request.headers();
    Set<String> variables = collectVariables(url, body, headers);
    if (variables.isEmpty()) {
      throw new ApiException("请求中未发现要模糊的占位符（例如 " + MARKER + "）");
    }

    Map<String, List<String>> payloadGroups = request.multiPayloads();
    if (payloadGroups == null || payloadGroups.isEmpty()) {
      payloadGroups = Map.of("name", normalizePayloads(request.payloads()));
    }
    String combination = request.combination();
    if (combination == null || combination.isBlank()) {
      combination = "SNIPER";
    }

    boolean forceLoop = "LOOP".equalsIgnoreCase(request.engine());
    if (forceLoop) {
      return loopFuzz(packetId, request, url, body, headers, variables, payloadGroups, combination);
    }
    FuzzResponse zapResult = zapFuzz(packetId, request, url, body, headers);
    if (zapResult != null) {
      return zapResult;
    }
    if ("ZAP".equalsIgnoreCase(request.engine())) {
      throw new ApiException("ZAP 引擎不可用，请先安装或启动 OWASP ZAP，或改用内置循环引擎");
    }
    return loopFuzz(packetId, request, url, body, headers, variables, payloadGroups, combination);
  }

  private Set<String> collectVariables(String url, String body, String headers) {
    Set<String> names = new LinkedHashSet<>();
    Matcher m = VARIABLE.matcher(url);
    addVars(m, names);
    m = VARIABLE.matcher(body);
    addVars(m, names);
    m = VARIABLE.matcher(headers);
    addVars(m, names);
    return names;
  }

  private void addVars(Matcher m, Set<String> names) {
    while (m.find()) {
      String name = m.group(1).trim();
      if (!name.isEmpty()) {
        names.add(name);
      }
    }
  }

  /**
   * Attempts to fuzz the whole request through a local ZAP fuzzer (its own Fuzz DB). Returns null on
   * any unavailability or failure so the caller falls back to the self-loop. Best effort only.
   */
  private FuzzResponse zapFuzz(Long packetId, FuzzRequest request, String url, String body,
      String headers) {
    if (daemonSupplier == null || dependencies == null || !zapAvailable()) {
      return null;
    }
    try (ZapDaemon daemon = daemonSupplier.create()) {
      daemon.start();
      URI target = URI.create(url);
      daemon.includeInScope(target);
      String requestUrl = stripPlaceholders(url);
      String postBody = stripPlaceholders(body);
      ZapDaemon.FuzzSpec spec =
          new ZapDaemon.FuzzSpec(target, requestUrl, request.method(), postBody, "", "");
      String fuzzId = daemon.startFuzz(spec);
      if (fuzzId == null || fuzzId.isBlank()) {
        LOGGER.info("ZAP fuzz 未启动，降级到自研循环重放");
        return null;
      }
      long deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(ZAP_FUZZ_DEADLINE_MINUTES);
      while (System.nanoTime() < deadline) {
        String state = daemon.fuzzStatus(fuzzId);
        if (state.contains("stopped") && !state.contains("stopped=false")) {
          break;
        }
        Thread.sleep(800);
      }
      List<ZapDaemon.ZapAlert> alerts = daemon.alerts();
      return toZapResponse(packetId, request.method(), url, alerts);
    } catch (Exception ex) {
      LOGGER.info("ZAP 模糊引擎不可用，降级为自研循环重放: {}", ex.getMessage());
      return null;
    }
  }

  private String stripPlaceholders(String value) {
    if (value == null) {
      return "";
    }
    return substitute(value, Map.of());
  }

  private boolean zapAvailable() {
    try {
      SystemDependenciesResponse response = dependencies.detect(false);
      if (response == null || response.dependencies() == null) {
        return false;
      }
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

  private FuzzResponse toZapResponse(
      Long packetId, String method, String url, List<ZapDaemon.ZapAlert> alerts) {
    List<FuzzHit> results = new ArrayList<>();
    if (alerts != null) {
      for (ZapDaemon.ZapAlert alert : alerts) {
        if (alert == null) {
          continue;
        }
        results.add(
            new FuzzHit(
                abbreviate(alert.name()),
                null,
                alert.risk() == null ? "" : alert.risk(),
                0,
                0,
                riskPrefix(alert.risk()),
                null,
                true));
      }
    }
    return new FuzzResponse(packetId, method, url, results, results.size(), "ZAP");
  }

  private String riskPrefix(String risk) {
    if (risk == null) return "-";
    return risk.toUpperCase(java.util.Locale.ROOT);
  }

  private FuzzResponse loopFuzz(
      Long packetId,
      FuzzRequest request,
      String url,
      String body,
      String headers,
      Set<String> variables,
      Map<String, List<String>> payloadGroups,
      String combination) {
    ReplayResponse baseline = run(packetId, request, url, body, headers, Map.of());
    String baselineDigest = digestOf(baseline);

    List<FuzzHit> results = new ArrayList<>();
    results.add(
        new FuzzHit(
            "<<baseline>>",
            baseline.statusCode(),
            baseline.reasonPhrase() == null ? "" : baseline.reasonPhrase(),
            baseline.durationMs(),
            baseline.responseBytes(),
            baselineDigest.substring(0, Math.min(8, baselineDigest.length())),
            baseline.statusCode(),
            false));

    List<Map<String, String>> combos = buildCombinations(variables, payloadGroups, combination);
    for (Map<String, String> bindings : combos) {
      String label = describeBindings(bindings);
      ReplayResponse result = run(packetId, request, url, body, headers, bindings);
      String digest = digestOf(result);
      boolean changed =
          !statusAndLen(result).equals(statusAndLen(baseline)) || !digest.equals(baselineDigest);
      results.add(
          new FuzzHit(
              abbreviate(label),
              result.statusCode(),
              result.reasonPhrase() == null ? "" : result.reasonPhrase(),
              result.durationMs(),
              result.responseBytes(),
              digest.substring(0, Math.min(8, digest.length())),
              result.statusCode(),
              changed));
    }
    return new FuzzResponse(packetId, request.method(), url, results, combos.size(), "LOOP");
  }

  /**
   * Builds the ordered list of variable bindings to replay according to the combination strategy.
   * Payload groups that have no entries for a variable keep the variable's empty value.
   */
  private List<Map<String, String>> buildCombinations(
      Set<String> variables,
      Map<String, List<String>> payloadGroups,
      String combination) {
    List<String> ordered = new ArrayList<>(variables);
    List<List<String>> rawGroups = new ArrayList<>();
    for (String name : ordered) {
      List<String> values = normalizePayloads(payloadGroups == null ? null : payloadGroups.get(name));
      rawGroups.add(values);
    }
    String comb = combination == null ? "SNIPER" : combination.trim().toUpperCase(java.util.Locale.ROOT);
    if ("BATTERING_RAM".equals(comb) || "BATTERINGRAM".equals(comb) || "RAM".equals(comb)) {
      return buildBatteringRam(ordered, payloadGroups, rawGroups);
    }
    if ("PITCHFORK".equals(comb) || "SHORTEST".equals(comb)) {
      return buildAligned(ordered, rawGroups, true);
    }
    if ("PITCHFORK_LONGEST".equals(comb) || "LONGEST".equals(comb)) {
      return buildAligned(ordered, rawGroups, false);
    }
    if ("CLUSTER_BOMB".equals(comb) || "CLUSTERBOMB".equals(comb) || "CARTESIAN".equals(comb)) {
      return buildCartesian(ordered, rawGroups);
    }
    return buildSniper(ordered, payloadGroups, rawGroups);
  }

  /**
   * Burp Sniper mode: uses a single payload set and targets each placeholder position in turn,
   * replacing one position at a time while leaving all other positions set to their base values
   * (the original placeholder literal name).
   */
  private List<Map<String, String>> buildSniper(
      List<String> names,
      Map<String, List<String>> payloadGroups,
      List<List<String>> rawGroups) {
    List<String> sharedPayloads = findSharedPayloads(rawGroups, payloadGroups);
    List<Map<String, String>> plans = new ArrayList<>();

    for (int i = 0; i < names.size(); i++) {
      List<String> payloads = rawGroups.get(i);
      if (payloads.isEmpty()) {
        payloads = sharedPayloads;
      }
      if (payloads.isEmpty()) {
        continue;
      }
      for (String p : payloads) {
        Map<String, String> binding = new LinkedHashMap<>();
        for (int j = 0; j < names.size(); j++) {
          String varName = names.get(j);
          if (j == i) {
            binding.put(varName, p);
          } else {
            // Other positions retain their original base value (literal variable marker)
            binding.put(varName, varName);
          }
        }
        plans.add(binding);
        if (plans.size() >= MAX_PAYLOADS) {
          return plans;
        }
      }
    }
    if (plans.isEmpty()) {
      plans.add(new LinkedHashMap<>());
    }
    return plans;
  }

  /**
   * Burp Battering Ram mode: uses a single payload set and iterates through it once,
   * placing the same payload into all defined placeholder positions simultaneously.
   */
  private List<Map<String, String>> buildBatteringRam(
      List<String> names,
      Map<String, List<String>> payloadGroups,
      List<List<String>> rawGroups) {
    List<String> payloads = findSharedPayloads(rawGroups, payloadGroups);
    List<Map<String, String>> plans = new ArrayList<>();
    for (String p : payloads) {
      Map<String, String> binding = new LinkedHashMap<>();
      for (String name : names) {
        binding.put(name, p);
      }
      plans.add(binding);
      if (plans.size() >= MAX_PAYLOADS) {
        break;
      }
    }
    if (plans.isEmpty()) {
      plans.add(new LinkedHashMap<>());
    }
    return plans;
  }

  private List<String> findSharedPayloads(
      List<List<String>> rawGroups,
      Map<String, List<String>> payloadGroups) {
    if (payloadGroups != null) {
      if (payloadGroups.containsKey("default") && !payloadGroups.get("default").isEmpty()) {
        return normalizePayloads(payloadGroups.get("default"));
      }
      if (payloadGroups.containsKey("payloads") && !payloadGroups.get("payloads").isEmpty()) {
        return normalizePayloads(payloadGroups.get("payloads"));
      }
      if (payloadGroups.containsKey("name") && !payloadGroups.get("name").isEmpty()) {
        return normalizePayloads(payloadGroups.get("name"));
      }
    }
    for (List<String> group : rawGroups) {
      if (!group.isEmpty()) {
        return group;
      }
    }
    return List.of();
  }

  /** Aligned iteration. shortest=true: stop at the shortest list; false (longest): go to the longest list, short lists repeat their last value. */
  private List<Map<String, String>> buildAligned(
      List<String> names, List<List<String>> groups, boolean shortest) {
    int maxLen = 1;
    int minLen = Integer.MAX_VALUE;
    for (List<String> group : groups) {
      if (group.isEmpty()) {
        minLen = 0;
        continue;
      }
      maxLen = Math.max(maxLen, group.size());
      minLen = Math.min(minLen, group.size());
    }
    int count = shortest ? (minLen == Integer.MAX_VALUE ? 0 : minLen) : maxLen;
    if (minLen == 0 && shortest) {
      count = 0;
    }
    List<Map<String, String>> plans = new ArrayList<>();
    if (count <= 0) {
      plans.add(new LinkedHashMap<>());
      return plans;
    }
    for (int i = 0; i < count; i++) {
      Map<String, String> binding = new LinkedHashMap<>();
      for (int j = 0; j < names.size(); j++) {
        String name = names.get(j);
        List<String> group = groups.get(j);
        binding.put(name, group.isEmpty() ? "" : group.get(Math.min(i, group.size() - 1)));
      }
      plans.add(binding);
    }
    return plans;
  }

  private List<Map<String, String>> buildCartesian(List<String> names, List<List<String>> groups) {
    List<Map<String, String>> plans = new ArrayList<>();
    plans.add(new LinkedHashMap<>());
    for (int j = 0; j < names.size(); j++) {
      List<Map<String, String>> next = new ArrayList<>();
      List<String> group = groups.get(j);
      List<String> values = group.isEmpty() ? List.of("") : group;
      for (Map<String, String> base : plans) {
        for (String value : values) {
          Map<String, String> copy = new LinkedHashMap<>(base);
          copy.put(names.get(j), value);
          next.add(copy);
        }
      }
      plans = next;
      if (plans.size() > MAX_PAYLOADS) {
        break;
      }
    }
    return plans;
  }

  private String describeBindings(Map<String, String> bindings) {
    String single = null;
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, String> entry : bindings.entrySet()) {
      if (entry.getValue().isEmpty()) {
        continue;
      }
      if (single == null) {
        single = entry.getValue();
      } else {
        single = null;
        break;
      }
    }
    if (single != null) {
      return single;
    }
    for (Map.Entry<String, String> entry : bindings.entrySet()) {
      if (entry.getValue().isEmpty()) {
        continue;
      }
      if (sb.length() > 0) {
        sb.append(" · ");
      }
      sb.append(entry.getKey()).append('=').append(entry.getValue());
    }
    return sb.length() == 0 ? "<<empty>>" : sb.toString();
  }

  private ReplayResponse run(
      Long packetId,
      FuzzRequest request,
      String url,
      String body,
      String headers,
      Map<String, String> bindings) {
    String resolvedUrl = substitute(url, bindings);
    String resolvedHeaders = substitute(headers, bindings);
    String resolvedBody = substitute(body, bindings);
    ReplayRequest nested =
        new ReplayRequest(
            request.targetId(),
            request.method(),
            resolvedUrl,
            resolvedHeaders,
            resolvedBody);
    return replay.replay(packetId, nested);
  }

  /** Replaces every {@code §name§} in {@code value} with its binding (or "" if unset). */
  private String substitute(String value, Map<String, String> bindings) {
    if (value == null || value.indexOf('§') < 0) {
      return value == null ? "" : value;
    }
    Matcher m = VARIABLE.matcher(value);
    StringBuffer sb = new StringBuffer();
    while (m.find()) {
      String name = m.group(1).trim();
      String replacement = bindings == null ? "" : bindings.getOrDefault(name, "");
      m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
    }
    m.appendTail(sb);
    return sb.toString();
  }

  private List<String> normalizePayloads(List<String> payloads) {
    List<String> result = new ArrayList<>();
    if (payloads == null) {
      return result;
    }
    for (String payload : payloads) {
      if (payload == null || payload.isBlank()) {
        continue;
      }
      String value =
          payload.length() > MAX_PAYLOAD_LENGTH ? payload.substring(0, MAX_PAYLOAD_LENGTH) : payload;
      result.add(value);
      if (result.size() >= MAX_PAYLOADS) {
        break;
      }
    }
    return result;
  }

  private String abbreviate(String value) {
    if (value == null) {
      return "";
    }
    return value.length() > MAX_DISPLAY_PAYLOAD ? value.substring(0, MAX_DISPLAY_PAYLOAD) : value;
  }

  private String digestOf(ReplayResponse response) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] bytes =
          (response.statusCode() + "|" + response.responseBody()).getBytes(StandardCharsets.UTF_8);
      return hex(digest.digest(bytes));
    } catch (Exception ex) {
      return String.valueOf(response.statusCode());
    }
  }

  private String statusAndLen(ReplayResponse response) {
    return response.statusCode() + ":" + response.responseBody().length();
  }

  private String hex(byte[] bytes) {
    StringBuilder builder = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      builder.append(String.format("%02x", b));
    }
    return builder.toString();
  }

  /**
   * Request descriptor. {@code payloads} (legacy single {@code §name§} list) and {@code multiPayloads}
   * are mutually convertible: when only {@code payloads} is present it is used as the tenantId list
   * for the variable "name".
   */
  public record FuzzRequest(
      Long targetId,
      String method,
      String url,
      String headers,
      String body,
      Map<String, List<String>> multiPayloads,
      List<String> payloads,
      String engine,
      String combination) {

    /**
     * Variable name → payload list. When only the legacy single {@code payloads} is supplied it is
     * used as the payload list for the variable "name".
     */
    public Map<String, List<String>> multiPayloads() {
      if (multiPayloads != null && !multiPayloads.isEmpty()) {
        return multiPayloads;
      }
      return Map.of("name", payloads == null ? List.of() : payloads);
    }

    public FuzzRequest(
        Long targetId,
        String method,
        String url,
        String headers,
        String body,
        List<String> payloads) {
      this(targetId, method, url, headers, body, null, payloads, null, null);
    }

    public FuzzRequest(
        Long targetId,
        String method,
        String url,
        String headers,
        String body,
        Map<String, List<String>> multiPayloads,
        List<String> payloads) {
      this(targetId, method, url, headers, body, multiPayloads, payloads, null, null);
    }
  }

  public record FuzzHit(
      String payload,
      Integer statusCode,
      String reason,
      long durationMs,
      long responseBytes,
      String digestPrefix,
      Integer effectiveStatus,
      boolean changed) {}

  public record FuzzPreset(String id, String name, String category, List<String> payloads) {}

  public List<FuzzPreset> getPresets() {
    return List.of(
        new FuzzPreset("SQLI_BASIC", "SQL 注入基础探针 (FuzzDB)", "SQL Injection", List.of(
            "'", "\"", "''", "1' OR '1'='1", "1 OR 1=1", "admin' --", "1' AND SLEEP(5)--", "1' UNION SELECT NULL--", "') OR ('1'='1"
        )),
        new FuzzPreset("XSS_CORE", "XSS 跨站脚本载荷 (FuzzDB)", "Cross-Site Scripting", List.of(
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "'><script>alert(1)</script>",
            "\"><svg onload=confirm(1)>",
            "<details open ontoggle=alert(1)>"
        )),
        new FuzzPreset("PATH_TRAVERSAL", "目录穿越与敏感文件 (FuzzDB)", "Path Traversal", List.of(
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/WEB-INF/web.xml",
            "/.env",
            "/.git/config"
        )),
        new FuzzPreset("CMD_INJECTION", "OS 命令注入探针 (FuzzDB)", "Command Injection", List.of(
            "; id",
            "| whoami",
            "& ping -c 1 127.0.0.1",
            "`id`",
            "$(whoami)",
            "; type C:\\Windows\\win.ini"
        )),
        new FuzzPreset("AUTH_WORDLIST", "常见用户名与弱口令", "Authentication", List.of(
            "admin", "root", "guest", "test", "password", "123456", "admin123", "default"
        )),
        new FuzzPreset("BOUNDARY_FORMAT", "边界异常与特殊截断字符", "Format & Special", List.of(
            "%00", "\\u0000", "%0d%0a", "%0a", "%20", "%ff", "{{7*7}}", "${7*7}", "<%= 7*7 %>"
        ))
    );
  }

  public record FuzzResponse(
      Long packetId,
      String method,
      String url,
      List<FuzzHit> results,
      int payloadCount,
      String engine) {}
}