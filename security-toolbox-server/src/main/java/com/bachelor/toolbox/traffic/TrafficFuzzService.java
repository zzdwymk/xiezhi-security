package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.zap.ZapDaemon;
import com.bachelor.toolbox.tool.zap.ZapDaemonSupplier;
import com.bachelor.toolbox.traffic.TrafficReplayService.ReplayRequest;
import com.bachelor.toolbox.traffic.TrafficReplayService.ReplayResponse;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
 * <p>ZAP sends one literal query/form field mutation per selected candidate and collects passive
 * alerts. AUTO may choose LOOP before any ZAP request is attempted, with an explicit reason. Once
 * sending begins, errors stop the run without repeating requests through another engine.
 */
@Service
public class TrafficFuzzService {
  private static final String MARKER = "\u00a7name\u00a7"; // §name§
  private static final Pattern VARIABLE = Pattern.compile("§([^§]+)§");
  private static final int MAX_PAYLOADS = 200;
  private static final int MAX_PAYLOAD_LENGTH = 4 * 1024;
  private static final int MAX_DISPLAY_PAYLOAD = 48;
  // Match JavaScript String.trim(): ASCII whitespace, Unicode separators and BOM.
  private static final Pattern DICTIONARY_EDGE_WHITESPACE =
      Pattern.compile("^[\\s\\p{Z}\\uFEFF]+|[\\s\\p{Z}\\uFEFF]+$");
  private static final long ZAP_FUZZ_DEADLINE_MINUTES = 8;

  private final TrafficReplayService replay;
  private final ZapDaemonSupplier daemonSupplier;
  private final DependencyDetectionService dependencies;
  private final TrafficPacketRepository packets;
  private final TargetService targets;
  private final TargetPolicyService targetPolicy;

  @Autowired
  public TrafficFuzzService(
      TrafficReplayService replay,
      ZapDaemonSupplier daemonSupplier,
      DependencyDetectionService dependencies,
      TrafficPacketRepository packets,
      TargetService targets,
      TargetPolicyService targetPolicy) {
    this.replay = replay;
    this.daemonSupplier = daemonSupplier;
    this.dependencies = dependencies;
    this.packets = packets;
    this.targets = targets;
    this.targetPolicy = targetPolicy;
  }

  public TrafficFuzzService(TrafficReplayService replay, ZapDaemonSupplier daemonSupplier,
      DependencyDetectionService dependencies) {
    this(replay, daemonSupplier, dependencies, null, null, null);
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
    if ((payloadGroups == null || payloadGroups.isEmpty())
        && !isMultiDictionaryCombination(request.combination())) {
      payloadGroups = Map.of("name", normalizePayloads(request.payloads()));
    }
    String combination = request.combination();
    if (combination == null || combination.isBlank()) {
      combination = "SNIPER";
    }
    if (isMultiDictionaryCombination(combination)) {
      Map<String, List<String>> normalized = new LinkedHashMap<>();
      for (String variable : variables) {
        normalized.put(variable, normalizeDictionaryPayloads(payloadGroups.get(variable)));
      }
      requireNonEmptyDictionaryGroups(new ArrayList<>(variables), new ArrayList<>(normalized.values()));
      payloadGroups = normalized;
    }
    if (payloadGroups.values().stream().allMatch(values -> normalizePayloads(values).isEmpty())) {
      throw new ApiException("请提供至少一个非空候选值");
    }
    String engine = request.engine() == null ? "AUTO" : request.engine().trim().toUpperCase(java.util.Locale.ROOT);
    if (!Set.of("AUTO", "LOOP", "ZAP").contains(engine)) throw new ApiException("未知模糊测试引擎");

    boolean forceLoop = "LOOP".equals(engine);
    if (forceLoop) {
      return loopFuzz(packetId, request, url, body, headers, variables, payloadGroups, combination);
    }
    try {
      List<Map<String, String>> candidates = buildCombinations(variables, payloadGroups, combination);
      List<ZapDaemon.FuzzSpec> specs = prepareZapSpecs(packetId, request, url, body, headers, candidates);
      return zapFuzz(packetId, request, specs);
    } catch (ZapUnavailable unavailable) {
      if ("ZAP".equals(engine)) throw new ApiException(unavailable.getMessage());
      FuzzResponse result = loopFuzz(packetId, request, url, body, headers, variables, payloadGroups, combination);
      return new FuzzResponse(result.packetId(), result.method(), result.url(), result.results(),
          result.payloadCount(), "LOOP", result.status(), "AUTO 已使用内置循环重放：" + unavailable.getMessage(),
          result.completedRequests());
    }
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

  private static boolean isMultiDictionaryCombination(String combination) {
    String value = combination == null ? "" : combination.trim().toUpperCase(java.util.Locale.ROOT);
    return Set.of("PITCHFORK", "SHORTEST", "PITCHFORK_LONGEST", "LONGEST",
        "CLUSTER_BOMB", "CLUSTERBOMB", "CARTESIAN").contains(value);
  }

  private void requireNonEmptyDictionaryGroups(List<String> names, List<List<String>> groups) {
    List<String> missing = new ArrayList<>();
    for (int i = 0; i < names.size(); i++) {
      if (groups.get(i).isEmpty()) missing.add("§" + names.get(i) + "§");
    }
    if (!missing.isEmpty()) {
      throw new ApiException("多字典模式的每个占位符都需要至少一行非空载荷：" + String.join("、", missing));
    }
  }

  private List<String> normalizeDictionaryPayloads(List<String> values) {
    if (values == null) return List.of();
    List<String> trimmed = new ArrayList<>();
    for (String value : values) {
      if (value == null) continue;
      String candidate = DICTIONARY_EDGE_WHITESPACE.matcher(value).replaceAll("");
      if (!candidate.isEmpty()) trimmed.add(candidate);
    }
    // Keep duplicate payloads and the established per-value/count limits.
    return normalizePayloads(trimmed);
  }

  private static final class ZapUnavailable extends RuntimeException {
    ZapUnavailable(String message) { super(message); }
  }

  /** Validate the whole candidate list before starting ZAP or sending any request. */
  private List<ZapDaemon.FuzzSpec> prepareZapSpecs(Long packetId, FuzzRequest request,
      String url, String body, String headers, List<Map<String, String>> candidates) {
    if (daemonSupplier == null || dependencies == null || !zapAvailable()) {
      throw new ZapUnavailable("OWASP ZAP 未安装或不可用");
    }
    String method = request.method() == null ? "" : request.method().trim().toUpperCase(java.util.Locale.ROOT);
    if (!Set.of("GET", "POST").contains(method)) {
      throw new ZapUnavailable("ZAP 单次参数变异仅支持 GET 查询或 POST 表单字段");
    }
    Matcher allMarkers = VARIABLE.matcher(url + "\n" + body + "\n" + headers);
    int markerCount = 0;
    while (allMarkers.find()) markerCount++;
    if (markerCount != 1) throw new ZapUnavailable("ZAP 单次参数变异仅支持一个占位符；多字段组合请使用 LOOP");
    if (VARIABLE.matcher(headers).find()) throw new ZapUnavailable("ZAP 单次参数变异不支持请求头占位符");
    String baselineUrl = substitute(url, Map.of());
    URI uri;
    try { uri = URI.create(baselineUrl); }
    catch (RuntimeException ex) { throw new ApiException("模糊测试 URL 无效"); }
    validateZapScope(packetId, request, uri);
    validateZapHeaders(headers, method, uri);
    if (("GET".equals(method) && !body.isEmpty()) || ("POST".equals(method) && VARIABLE.matcher(url).find())) {
      throw new ZapUnavailable("ZAP GET 只变异查询字段，POST 只变异表单字段");
    }
    String template = "GET".equals(method) ? URI.create(url).getRawQuery() : body;
    if (template == null || !VARIABLE.matcher(template).find()) {
      throw new ZapUnavailable("ZAP 占位符必须位于现有查询或表单字段的值中");
    }
    String fieldName = null;
    String valueTemplate = null;
    for (String field : template.split("&", -1)) {
      String[] pair = field.split("=", 2);
      if (!VARIABLE.matcher(field).find()) continue;
      if (pair.length != 2 || VARIABLE.matcher(pair[0]).find()) {
        throw new ZapUnavailable("ZAP 占位符必须位于字段值中，不能变异字段名");
      }
      try {
        fieldName = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
        valueTemplate = URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
      } catch (IllegalArgumentException invalid) {
        throw new ZapUnavailable("ZAP 查询或表单字段必须使用合法的 URL 编码");
      }
    }
    List<ZapDaemon.FuzzSpec> specs = new ArrayList<>();
    for (Map<String, String> bindings : candidates) {
      try {
        ZapDaemon.FuzzSpec spec = new ZapDaemon.FuzzSpec(uri, baselineUrl, method,
            substitute(body, Map.of()), substitute(valueTemplate, bindings), fieldName);
        spec.requestMessage();
        specs.add(spec);
      } catch (ApiException invalid) {
        throw new ZapUnavailable("ZAP 单次参数变异无法表达此请求：" + invalid.getMessage());
      }
    }
    return List.copyOf(specs);
  }

  private void validateZapScope(Long packetId, FuzzRequest request, URI uri) {
    if (packets == null || targets == null || targetPolicy == null) {
      throw new ZapUnavailable("ZAP 授权范围校验未配置");
    }
    TrafficPacket source = packets.findById(packetId).orElseThrow(() -> new ApiException("流量记录不存在"));
    if (uri.getHost() == null || !uri.getHost().equalsIgnoreCase(source.getHost())) {
      throw new ApiException("ZAP 请求主机必须与源流量一致");
    }
    int port = uri.getPort() > 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
    int sourcePort = source.getPort() > 0 ? source.getPort() : ("https".equalsIgnoreCase(source.getScheme()) ? 443 : 80);
    if (port != sourcePort) throw new ApiException("ZAP 请求端口必须与源流量一致");
    if (request.targetId() == null || request.targetId() <= 0) {
      throw new ZapUnavailable("ZAP 单次参数变异需要选择启用的授权目标");
    }
    AuthorizedTarget target = targets.get(request.targetId());
    if (target == null) throw new ApiException("授权目标不存在");
    TrafficRequestSafety.validateAuthorization(target);
    if (!targetPolicy.validatedHost(target).equalsIgnoreCase(uri.getHost())) {
      throw new ApiException("ZAP 请求主机与授权目标不一致");
    }
    targetPolicy.validateAuthorizedPort(target, port);
  }

  private void validateZapHeaders(String headers, String method, URI uri) {
    for (String line : headers.split("\r?\n")) {
      if (line.isBlank()) continue;
      int colon = line.indexOf(':');
      if (colon < 1) throw new ZapUnavailable("ZAP 单次参数变异无法无损保留这些请求头，请使用 LOOP");
      String name = line.substring(0, colon).trim().toLowerCase(java.util.Locale.ROOT);
      String value = line.substring(colon + 1).trim();
      boolean supported = switch (name) {
        case "host" -> value.equalsIgnoreCase(uri.getRawAuthority());
        case "content-type" -> "POST".equals(method)
            && value.matches("(?i)application/x-www-form-urlencoded(?:;\\s*charset=UTF-8)?");
        case "content-length" -> value.matches("[0-9]+");
        case "connection" -> "close".equalsIgnoreCase(value);
        default -> false;
      };
      if (!supported) throw new ZapUnavailable("ZAP 单次参数变异无法无损保留请求头 " + name + "，请使用 LOOP");
    }
  }

  private FuzzResponse zapFuzz(Long packetId, FuzzRequest request, List<ZapDaemon.FuzzSpec> specs) {
    int attempted = 0;
    int completed = 0;
    List<ZapDaemon.ZapAlert> alerts = List.of();
    try (ZapDaemon daemon = daemonSupplier.create()) {
      try {
        daemon.start();
        daemon.includeInScope(specs.get(0).target());
        long deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(ZAP_FUZZ_DEADLINE_MINUTES);
        for (ZapDaemon.FuzzSpec spec : specs) {
          if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
          if (System.nanoTime() >= deadline) throw new TimeoutException("ZAP 参数变异验证超时");
          attempted++;
          String fuzzId = daemon.startFuzz(spec);
          if (fuzzId == null || fuzzId.isBlank()) throw new ApiException("ZAP 未确认请求响应");
          awaitZapCompletion(daemon, fuzzId, deadline);
          List<ZapDaemon.ZapAlert> observed = daemon.alerts();
          if (observed == null) throw new ApiException("ZAP 未返回有效被动告警结果");
          alerts = observed.stream().filter(alert -> inScope(alert, spec.target())).toList();
          completed++;
        }
      } catch (Exception failure) {
        try { daemon.kill(); } catch (Exception cleanup) { failure.addSuppressed(cleanup); }
        throw failure;
      }
    } catch (Exception failure) {
      if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
      if (attempted == 0 && !(failure instanceof InterruptedException)) {
        throw new ZapUnavailable("ZAP 在发送前启动失败：" + safeReason(failure));
      }
      String status = failure instanceof TimeoutException || failure instanceof java.net.http.HttpTimeoutException
          || failure instanceof java.net.SocketTimeoutException ? "TIMEOUT"
          : failure instanceof InterruptedException ? "CANCELLED" : "FAILED";
      return toZapResponse(packetId, request.method(), request.url(), alerts, specs.size(), completed, status,
          "ZAP 单次参数变异未完成：" + safeReason(failure) + "；已尝试 " + attempted
              + " 次、确认完成 " + completed + " 次。后续请求已停止，未切换引擎重复发送。");
    }
    return toZapResponse(packetId, request.method(), request.url(), alerts, specs.size(), completed, "COMPLETED",
        "ZAP 单次参数变异验证完成，共确认 " + completed + " 次请求、" + alerts.size()
            + " 项被动告警；不包含响应基线比较或字典生成器。");
  }

  void awaitZapCompletion(ZapDaemon daemon, String fuzzId, long deadline) throws Exception {
    while (true) {
      if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
      if (System.nanoTime() >= deadline) throw new TimeoutException("ZAP 参数变异验证超时");
      String state = daemon.fuzzStatus(fuzzId);
      String phase = state == null ? "" : state.split(";", 2)[0];
      if ("stopped".equals(phase)) return;
      if (!"running".equals(phase)) throw new ApiException("ZAP 返回未知执行状态");
      Thread.sleep(250);
    }
  }

  private boolean inScope(ZapDaemon.ZapAlert alert, URI target) {
    if (alert == null || alert.url() == null) return false;
    try {
      URI uri = URI.create(alert.url());
      int port = uri.getPort() > 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
      int targetPort = target.getPort() > 0 ? target.getPort() : ("https".equalsIgnoreCase(target.getScheme()) ? 443 : 80);
      return uri.getHost() != null && uri.getHost().equalsIgnoreCase(target.getHost()) && port == targetPort;
    } catch (RuntimeException invalid) { return false; }
  }

  private String safeReason(Exception failure) {
    String value = failure.getMessage();
    if (value == null || value.isBlank()) return "执行未完成";
    return value.length() > 250 ? value.substring(0, 250) : value;
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
      Long packetId, String method, String url, List<ZapDaemon.ZapAlert> alerts,
      int payloadCount, int completed, String status, String message) {
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
    return new FuzzResponse(packetId, method, url, results, payloadCount, "ZAP", status, message, completed);
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
    ReplayRequest baselineRequest = resolveRequest(request, url, body, headers, Map.of());
    ReplayResponse baseline = replay.replay(packetId, baselineRequest);
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
            false,
            requestSnapshot(baselineRequest, baseline)));

    List<Map<String, String>> combos = buildCombinations(variables, payloadGroups, combination);
    for (Map<String, String> bindings : combos) {
      String label = describeBindings(bindings);
      ReplayRequest resolvedRequest = resolveRequest(request, url, body, headers, bindings);
      ReplayResponse result = replay.replay(packetId, resolvedRequest);
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
              changed,
              requestSnapshot(resolvedRequest, result)));
    }
    return new FuzzResponse(packetId, request.method(), url, results, combos.size(), "LOOP");
  }

  /**
   * Builds the ordered list of variable bindings to replay according to the combination strategy.
   * Multi-dictionary groups are validated before the baseline or any candidate is sent.
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
    if (isMultiDictionaryCombination(comb)) requireNonEmptyDictionaryGroups(ordered, rawGroups);
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
    int count = shortest ? groups.stream().mapToInt(List::size).min().orElse(0)
        : groups.stream().mapToInt(List::size).max().orElse(0);
    List<Map<String, String>> plans = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      Map<String, String> binding = new LinkedHashMap<>();
      for (int j = 0; j < names.size(); j++) {
        String name = names.get(j);
        List<String> group = groups.get(j);
        binding.put(name, group.get(Math.min(i, group.size() - 1)));
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
      List<String> values = group;
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

  private ReplayRequest resolveRequest(
      FuzzRequest request,
      String url,
      String body,
      String headers,
      Map<String, String> bindings) {
    String resolvedUrl = substitute(url, bindings);
    String resolvedHeaders = substitute(headers, bindings);
    String resolvedBody = substitute(body, bindings);
    return new ReplayRequest(
        request.targetId(), request.method(), resolvedUrl, resolvedHeaders, resolvedBody);
  }

  private FuzzReplayRequest requestSnapshot(ReplayRequest request, ReplayResponse response) {
    // Keep the exact resolved input used for this exchange; the display label can be truncated
    // or contain multiple bindings. Revalidation and authorization still happen on every replay.
    return new FuzzReplayRequest(response.method(), response.url(), request.headers(), request.body());
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
      if (payload == null || payload.isEmpty()) {
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
   * Request descriptor. Single-dictionary modes may use legacy {@code payloads} for "name";
   * multi-dictionary modes require an explicit list for every participating variable.
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
     * Variable name → payload list. Legacy single {@code payloads} may supply "name" only outside
     * multi-dictionary modes; it must never silently fill an omitted multi-dictionary group.
     */
    public Map<String, List<String>> multiPayloads() {
      if (multiPayloads != null && !multiPayloads.isEmpty()) {
        return multiPayloads;
      }
      if (isMultiDictionaryCombination(combination)) return Map.of();
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
      boolean changed,
      FuzzReplayRequest request) {
    /** Legacy persisted results and ZAP passive alerts have no unambiguous request snapshot. */
    public FuzzHit(String payload, Integer statusCode, String reason, long durationMs,
        long responseBytes, String digestPrefix, Integer effectiveStatus, boolean changed) {
      this(payload, statusCode, reason, durationMs, responseBytes, digestPrefix, effectiveStatus, changed, null);
    }
  }

  public record FuzzReplayRequest(String method, String url, String headers, String body) {}

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
      String engine,
      String status,
      String message,
      int completedRequests) {
    public FuzzResponse(Long packetId, String method, String url, List<FuzzHit> results,
        int payloadCount, String engine) {
      this(packetId, method, url, results, payloadCount, engine, "COMPLETED", "内置循环重放完成", results.size());
    }
  }
}
