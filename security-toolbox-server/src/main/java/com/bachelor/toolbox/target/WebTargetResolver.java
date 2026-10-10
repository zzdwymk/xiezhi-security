package com.bachelor.toolbox.target;

import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.common.ApiException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 为授权目标推导「真实可达的 Web 基址集合」，让对输入格式要求各异的扫描器都能拿到可用的 http(s) URL，
 * 避免 web 类工具（afrog/xray/zap/sqlmap/http_headers 等）对裸 IP/域名目标被粗暴补成
 * {@code http://host:80} 而空跑。
 *
 * <p>推导优先级：
 * <ol>
 *   <li>显式 URL 目标（targetValue 以 http:// 或 https:// 开头）→ 直接采用其 scheme + 端口。</li>
 *   <li>复用前置端口发现结果（例如同一工作流中 tcp_ports / nmap 已探明的开放端口）→ 对每个开放端口
 *       确认 http / https 哪个可达。</li>
 *   <li>回退轻量探测：仅对授权目标的允许端口（target.allowedPorts + 默认 80/443）做并发连接与 GET
 *       探测。</li>
 * </ol>
 * 以上均不可达时：{@link #resolve} 抛 {@link ApiException}（供预检/调度拦截，避免空跑），
 * {@link #tryResolve} 返回空列表（只读预检，不落库）。
 *
 * <p>安全约束全程保持：仅解析授权目标自身主机与授权端口（复用 {@link TargetPolicyService} 的
 * {@code validatedHost} / {@code validateAuthorizedPort}），HTTP 请求不跟随重定向、带超时、不访问任何
 * 未授权主机。
 */
@Component
public class WebTargetResolver {
  private static final Logger log = LoggerFactory.getLogger(WebTargetResolver.class);
  /** 任务参数中携带「预解析 Web 基址列表」的键；由工作流/主动检测解析后注入，工具优先采用。 */
  public static final String PARAM_RESOLVED_BASES = "__resolvedWebBases";
  private static final Set<Integer> DEFAULT_WEB_PORTS = Set.of(80, 443);
  private static final int MAX_RESOLVED_BASES = 8;
  private static final int CONNECT_TIMEOUT_MS = 3000;
  private static final int REQUEST_TIMEOUT_SECONDS = 5;
  private static final int PROBE_BUDGET_SECONDS = REQUEST_TIMEOUT_SECONDS + 2;

  private final TargetPolicyService policyService;
  private final PortRangeParser portRangeParser;
  private final DiscoveredPathService discoveredPaths;
  private final HttpClient httpClient;

  @Autowired
  public WebTargetResolver(
      TargetPolicyService policyService,
      PortRangeParser portRangeParser,
      DiscoveredPathService discoveredPaths) {
    this(policyService, portRangeParser, discoveredPaths,
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(CONNECT_TIMEOUT_MS))
            .version(HttpClient.Version.HTTP_1_1)
            // 绝不跟随重定向，避免授权私有目标被引导到未授权的公网或元数据主机。
            .followRedirects(HttpClient.Redirect.NEVER)
            .build());
  }

  WebTargetResolver(
      TargetPolicyService policyService, PortRangeParser portRangeParser,
      DiscoveredPathService discoveredPaths, HttpClient httpClient) {
    this.policyService = policyService;
    this.portRangeParser = portRangeParser;
    this.discoveredPaths = discoveredPaths;
    this.httpClient = httpClient;
  }

  /**
   * 解析出真实可达的 Web 基址集合，并作为资产汇入资产拓扑存储（source=TARGET_RESOLVER，精确 URL
   * 查重已在 {@link DiscoveredPathService#record} 内部保证）。无任何可达 Web 基址时抛出
   * {@link ApiException}。
   *
   * @param discoveredOpenPorts 前置端口扫描（tcp_ports / nmap / fscan）已探明的开放端口，
   *     元素形如 {@code {"port": 8080, "protocol":"tcp", "service":"http"}}；可为空列表。
   */
  public List<URI> resolve(
      AuthorizedTarget target, List<Map<String, Object>> discoveredOpenPorts) {
    List<URI> bases = resolveBases(target, discoveredOpenPorts);
    if (bases.isEmpty()) {
      String host = policyService.validatedHost(target);
      throw new ApiException(
          "无法确认目标 "
              + host
              + " 上可访问的 Web 服务地址(scheme:port)；若主机确实运行 Web 服务，请先执行端口扫描"
              + "，或改用带 http[s]:// 协议的 URL 目标。");
    }
    return bases;
  }

  /** 只读预检：解析目标并返回可达基址；不可达或异常时返回空列表（不抛出、不落库）。 */
  public List<URI> tryResolve(AuthorizedTarget target) {
    try {
      return resolveBases(target, List.of());
    } catch (RuntimeException ex) {
      log.warn("Web目标解析失败 targetId={} type={}", target.getId(), ex.getClass().getSimpleName());
      return List.of();
    }
  }

  /** 解析出的可达基址汇入资产拓扑（source=TARGET_RESOLVER）。带 projectId 时才落库。 */
  public void recordAssets(AuthorizedTarget target, Long projectId, List<URI> bases) {
    if (projectId == null || discoveredPaths == null || bases == null) return;
    for (URI uri : bases) {
      try {
        discoveredPaths.record(
            target, projectId, uri.toString(), "TARGET_RESOLVER", 0, 0L, "由目标地址解析确认可达");
      } catch (RuntimeException ignored) {
        // best-effort，不影响扫描主流程
      }
    }
  }

  /**
   * 从任务参数中取出预解析的 Web 基址列表（由工作流/主动检测在创建任务时注入）。无则返回空列表。
   * 工具可通过静态方式调用，无需注入 resolver。
   */
  /** 从任务参数中取出预解析的 Web 基址列表（由工作流/主动检测在创建任务时注入）。无则返回空列表。
   * 工具可通过静态方式调用，无需注入 resolver。
   */
  public static List<URI> basesFromParameters(Map<String, Object> parameters) {
    if (parameters == null) return List.of();
    Object value = parameters.get(PARAM_RESOLVED_BASES);
    if (!(value instanceof List<?> list)) return List.of();
    List<URI> bases = new ArrayList<>();
    for (Object item : list) {
      if (item == null) continue;
      String text = String.valueOf(item).trim();
      try {
        bases.add(URI.create(text));
      } catch (RuntimeException ignored) {
        // skip malformed uri
      }
    }
    return bases;
  }

  /**
   * 返回移除了框架内部传输参数（预解析基址）后的扫描参数副本，供参数白名单校验（如 PoC 选择）使用。
   * 工具仍需调用 {@link #basesFromParameters} 读取完整参数里的基址，因此这里不改写入参。
   */
  public static Map<String, Object> scanParameters(Map<String, Object> parameters) {
    if (parameters == null || !parameters.containsKey(PARAM_RESOLVED_BASES)) return parameters;
    Map<String, Object> copy = new java.util.HashMap<>(parameters);
    copy.remove(PARAM_RESOLVED_BASES);
    return copy;
  }

  /** 把一个基址（或直接给定的 URL 基址）与可选路径拼成可请求的 URI。 */
  public URI join(URI base, String path) {
    if (base == null) return null;
    if (path == null || path.isBlank() || "/".equals(path.trim())) return base;
    String p = path.trim();
    if (p.startsWith("http://") || p.startsWith("https://")) {
      try {
        return URI.create(p);
      } catch (RuntimeException ex) {
        return base;
      }
    }
    if (!p.startsWith("/")) p = "/" + p;
    String rawPath = p;
    String rawQuery = null;
    int q = p.indexOf('?');
    if (q >= 0) {
      rawPath = p.substring(0, q);
      rawQuery = p.substring(q + 1);
    }
    try {
      return new URI(base.getScheme(), null, base.getHost(), base.getPort(), rawPath, rawQuery, null);
    } catch (Exception ex) {
      return base;
    }
  }

  private List<URI> resolveBases(AuthorizedTarget target, List<Map<String, Object>> discoveredOpenPorts) {
    URI explicit = explicitUri(target);
    if (explicit != null) {
      return List.of(explicit);
    }
    String host = policyService.validatedHost(target);
    List<Integer> discoveredPorts = portCandidates(discoveredOpenPorts);
    Set<Integer> ports =
        discoveredPorts.isEmpty()
            ? probeCandidates(target)
            : new LinkedHashSet<>(discoveredPorts);
    return probeAll(target, host, ports);
  }

  /** 显式 URL 目标（targetValue 含 http[s]://）直接返回其 URI，否则返回 null。 */
  private URI explicitUri(AuthorizedTarget target) {
    String value = target.getTargetValue();
    if (value == null) return null;
    String trimmed = value.trim();
    if (!(trimmed.startsWith("http://") || trimmed.startsWith("https://"))) return null;
    return policyService.validatedHttpUri(target);
  }

  private List<Integer> portCandidates(List<Map<String, Object>> discoveredOpenPorts) {
    LinkedHashSet<Integer> ports = new LinkedHashSet<>();
    if (discoveredOpenPorts == null) return List.of();
    for (Map<String, Object> entry : discoveredOpenPorts) {
      if (entry == null) continue;
      Object portValue = entry.get("port");
      try {
        int port = Integer.parseInt(String.valueOf(portValue));
        if (port >= PortRangeParser.MIN_PORT && port <= PortRangeParser.MAX_PORT) {
          ports.add(port);
        }
      } catch (NumberFormatException ignored) {
        // skip malformed port entries
      }
    }
    return List.copyOf(ports);
  }

  private Set<Integer> probeCandidates(AuthorizedTarget target) {
    LinkedHashSet<Integer> candidates = new LinkedHashSet<>();
    try {
      candidates.addAll(portRangeParser.parse(target.getAllowedPorts()));
    } catch (RuntimeException ignored) {
      // fall through to	defaults
    }
    candidates.addAll(DEFAULT_WEB_PORTS);
    return candidates;
  }

  private List<URI> probeAll(AuthorizedTarget target, String host, Set<Integer> ports) {
    Set<URI> reachable = new LinkedHashSet<>();
    List<URI> candidates = new ArrayList<>();
    for (Integer port : ports) {
      if (candidates.size() >= MAX_RESOLVED_BASES * 2) break;
      URI http = webUri(target, host, port, "http");
      if (http != null) candidates.add(http);
      URI https = webUri(target, host, port, "https");
      if (https != null) candidates.add(https);
    }
    long started = System.nanoTime();
    long deadline = started + TimeUnit.SECONDS.toNanos(PROBE_BUDGET_SECONDS);
    Map<String, List<String>> diagnostics = new LinkedHashMap<>();
    ExecutorService pool = Executors.newFixedThreadPool(Math.min(8, Math.max(1, candidates.size())));
    List<Future<ProbeResult>> futures = new ArrayList<>();
    try {
      ExecutorCompletionService<ProbeResult> completions = new ExecutorCompletionService<>(pool);
      for (URI candidate : candidates) {
        futures.add(completions.submit(() -> probe(candidate, 1, deadline)));
      }
      int outstanding = futures.size();
      while (outstanding > 0 && reachable.size() < MAX_RESOLVED_BASES) {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) break;
        try {
          Future<ProbeResult> completed = completions.poll(remaining, TimeUnit.NANOSECONDS);
          if (completed == null) break;
          outstanding--;
          ProbeResult result = completed.get();
          diagnostics.computeIfAbsent(result.uri().toString(), ignored -> new ArrayList<>())
              .add("attempt=" + result.attempt() + ",outcome=" + result.outcome()
                  + ",elapsedMs=" + result.elapsedMs());
          if (result.reachable()) reachable.add(result.uri());
          // Enqueue retries behind the remaining first attempts. A cold connect
          // timeout may recover immediately; never retry TLS/HTTP/protocol errors,
          // and both attempts share the original seven-second analysis budget.
          if (result.connectTimeout() && result.attempt() == 1 && System.nanoTime() < deadline) {
            futures.add(completions.submit(() -> probe(result.uri(), 2, deadline)));
            outstanding++;
          }
        } catch (InterruptedException ex) {
          Thread.currentThread().interrupt();
          break;
        } catch (java.util.concurrent.ExecutionException ex) {
          log.warn("Web目标探测线程失败 targetId={} type={}",
              target.getId(), ex.getCause().getClass().getSimpleName());
        }
      }
    } finally {
      for (Future<ProbeResult> future : futures) {
        if (!future.isDone()) future.cancel(true);
      }
      pool.shutdownNow();
    }
    // Completion order is nondeterministic; preserve the authorized candidate order.
    List<URI> resolved = candidates.stream().filter(reachable::contains).limit(MAX_RESOLVED_BASES).toList();
    log.info("Web目标解析完成 targetId={} host={} elapsedMs={} resolved={} probes={}",
        target.getId(), host, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started),
        resolved, diagnostics);
    return resolved;
  }

  private URI webUri(AuthorizedTarget target, String host, int port, String scheme) {
    // 仅允许授权范围内的端口（纵深防御：即便发现端口来自前置扫描，也逐端口复核授权范围）。
    try {
      policyService.validateAuthorizedPort(target, port);
    } catch (ApiException ex) {
      return null;
    }
    int effectivePort = "https".equalsIgnoreCase(scheme) ? (port == 443 ? -1 : port) : (port == 80 ? -1 : port);
    try {
      return new URI(scheme, null, host, effectivePort, "/", null, null);
    } catch (Exception ex) {
      return null;
    }
  }

  private record ProbeResult(
      URI uri, int attempt, boolean reachable, boolean connectTimeout, String outcome, long elapsedMs) {}

  private ProbeResult probe(URI uri, int attempt, long deadline) {
    long started = System.nanoTime();
    long remaining = deadline - started;
    if (remaining <= 0) return new ProbeResult(uri, attempt, false, false, "BUDGET_EXHAUSTED", 0);
    try {
      HttpRequest request =
          HttpRequest.newBuilder(uri)
              .timeout(Duration.ofNanos(Math.min(remaining, TimeUnit.SECONDS.toNanos(REQUEST_TIMEOUT_SECONDS))))
              .header("User-Agent", "Xiezhi-Authorized-Security/0.2")
              .GET()
              .build();
      HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
      return new ProbeResult(uri, attempt, response.statusCode() < 500, false,
          "HTTP_" + response.statusCode(), TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      return new ProbeResult(uri, attempt, false, false, "INTERRUPTED",
          TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
    } catch (Exception ex) {
      return new ProbeResult(uri, attempt, false, ex instanceof HttpConnectTimeoutException,
          ex.getClass().getSimpleName(), TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
    }
  }
}
