package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.recon.PathDictionaryService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.WebTargetResolver;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Authorized web directory / path enumeration.
 *
 * <h2>Why this tool exists</h2>
 *
 * <p>Before this tool, path enumeration only existed inside the project-detail "信息收集" tab, was
 * bound to a 38-entry built-in wordlist, and silently stopped after 400 requests. That made it
 * unusable on real targets (application paths are rarely named {@code admin/} or {@code test/}).
 * The AI assistant and the workflow engine could not reach it at all.
 *
 * <p>This tool makes enumeration a first-class, governable capability:
 *
 * <ul>
 *   <li><b>Real dictionaries</b> from {@link PathDictionaryService} (dirb / dirbuster), selectable.
 *   <li><b>Operator-configurable concurrency</b> (1..{@value #MAX_WORKERS}), bounded by an in-flight
 *       request budget so a high worker count cannot open unbounded sockets.
 *   <li><b>Explicit truncation evidence</b>: when the dictionary exceeds the request budget the
 *       result states exactly how many entries were skipped, instead of silently dropping them.
 *   <li><b>Soft-404 baseline</b>: a random path is requested first; a response that matches the
 *       baseline status and body size is treated as "not found", so SPA catch-all handlers and
 *       wildcard 200s do not produce thousands of false positives.
 * </ul>
 *
 * <h2>Authorization invariants (unchanged)</h2>
 *
 * <p>Concurrency changes only <em>how fast</em> the same requests are sent. It must never change
 * <em>which</em> hosts can be reached. Every request URL is built from
 * {@link TargetPolicyService#validatedHttpUri(AuthorizedTarget, String)}, and every hit is written
 * through {@link DiscoveredPathService#record} which re-checks host + authorized port. An
 * out-of-scope URL cannot be reached even if a dictionary entry or redirect tries to produce one.
 *
 * <p>Redirects are never followed: a {@code 302} to another host is recorded as a finding about the
 * redirect target, never fetched.
 */
@Component
public class DirScanTool implements SecurityTool {
  private static final Logger log = LoggerFactory.getLogger(DirScanTool.class);

  public static final String CODE = "dir_scan";

  /** Hard ceiling for the operator-configurable worker count. */
  public static final int MAX_WORKERS = 50;

  /** Default worker count when the caller does not set one. */
  public static final int DEFAULT_WORKERS = 10;

  /** Hard ceiling for a single scan's request budget, regardless of dictionary size. */
  private static final int HARD_MAX_REQUESTS = 200_000;

  private static final String USER_AGENT = "Xiezhi-Authorized-Security/0.2";

  /** Bodies larger than this are not retained, only their length. */
  private static final int MAX_BODY_BYTES = 256 * 1024;

  /** Tolerance when comparing a candidate body length against the soft-404 baseline. */
  private static final int SOFT_404_LENGTH_TOLERANCE = 24;

  /** Static assets are recorded as discovered but are not recursed into. */
  private static final Pattern STATIC_ASSET =
      Pattern.compile(
          ".*\\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|eot|otf|map"
              + "|pdf|zip|gz|tar|rar|7z|mp4|mp3|avi|mov|wav|ogg)$");

  /** Directory entries are recursed into; file entries are not. */
  private static final Pattern DIRECTORY_ENTRY = Pattern.compile(".*/.*");

  private final TargetPolicyService policyService;
  private final PathDictionaryService dictionaries;
  private final DiscoveredPathService discoveredPaths;
  private final int defaultRequestBudget;

  public DirScanTool(
      TargetPolicyService policyService,
      PathDictionaryService dictionaries,
      DiscoveredPathService discoveredPaths,
      @Value("${toolbox.recon.dir-scan-max-requests:20000}") int defaultRequestBudget) {
    this.policyService = policyService;
    this.dictionaries = dictionaries;
    this.discoveredPaths = discoveredPaths;
    this.defaultRequestBudget =
        Math.max(1, Math.min(defaultRequestBudget, HARD_MAX_REQUESTS));
  }

  @Override
  public String code() {
    return CODE;
  }

  @Override
  public String displayName() {
    return "授权目录/路径枚举";
  }

  @Override
  public String description() {
    return "使用内置 dirb/dirbuster 字典对授权 Web 目标做目录与路径枚举，命中结果作为资产登记。"
        + "并发数可配置（1-50），请求预算可配置，超出预算时在结果中明确说明截断数量。"
        + "全部请求只发往授权目标的授权端口，不跟随重定向。";
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
    if (target == null) {
      throw new ApiException("目录枚举需要明确的授权目标");
    }
    String dictionaryId = dictionaries.resolveId(text(parameters.get("dictionary")));
    int workers = workers(parameters.get("concurrency"));
    int depth = depth(parameters.get("depth"));
    int budget = requestBudget(parameters.get("maxRequests"));
    int timeoutSeconds = timeoutSeconds(parameters.get("timeoutSeconds"));
    Set<String> extensions = extensions(parameters.get("extensions"));

    List<URI> bases = WebTargetResolver.basesFromParameters(parameters);
    if (bases.isEmpty()) {
      bases = List.of(policyService.validatedHttpUri(target));
    }
    String host = policyService.validatedHost(target);

    List<String> rawEntries = dictionaries.words(dictionaryId);
    if (rawEntries.isEmpty()) {
      throw new ApiException("字典 " + dictionaryId + " 没有可用词条，请检查字典配置");
    }

    // The dictionary may exceed the request budget. Truncation is reported, never silent.
    List<String> planned = planDepthFirst(rawEntries, depth, extensions, budget, workers);

    observer.operation(
        "DIR_SCAN dictionary="
            + dictionaryId
            + " entries="
            + planned.size()
            + " workers="
            + workers
            + " depth="
            + depth
            + " budget="
            + budget
            + " bases="
            + bases);

    HttpClient client =
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .version(HttpClient.Version.HTTP_1_1)
            // Never follow redirects: an authorized private URL must not be able to redirect the
            // scanner to an unapproved host.
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    EnumerationRun run =
        new EnumerationRun(
            target, client, bases, host, workers, budget, timeoutSeconds, observer, depth,
            extensions, projectId(parameters));

    Soft404Baseline baseline = run.establishBaseline();
    run.enumerateRoot(planned);
    if (depth > 0) {
      run.recurseIntoHits();
    }

    return run.toResult(dictionaryId, planned.size(), rawEntries.size(), extensions);
  }

  // ---------------------------------------------------------------- parameter parsing

  private int workers(Object raw) {
    if (raw == null) {
      return DEFAULT_WORKERS;
    }
    int parsed;
    try {
      parsed = Integer.parseInt(String.valueOf(raw).trim());
    } catch (NumberFormatException ex) {
      throw new ApiException("并发数必须是 1-" + MAX_WORKERS + " 之间的整数");
    }
    if (parsed < 1 || parsed > MAX_WORKERS) {
      throw new ApiException("并发数必须在 1-" + MAX_WORKERS + " 之间，收到 " + parsed);
    }
    return parsed;
  }

  private int depth(Object raw) {
    if (raw == null) {
      return 0;
    }
    try {
      int parsed = Integer.parseInt(String.valueOf(raw).trim());
      if (parsed < 0 || parsed > 3) {
        throw new ApiException("递归深度必须在 0-3 之间，收到 " + parsed);
      }
      return parsed;
    } catch (NumberFormatException ex) {
      throw new ApiException("递归深度必须是 0-3 之间的整数");
    }
  }

  private int requestBudget(Object raw) {
    if (raw == null) {
      return defaultRequestBudget;
    }
    try {
      int parsed = Integer.parseInt(String.valueOf(raw).trim());
      if (parsed < 1) {
        throw new ApiException("请求预算必须大于 0");
      }
      return Math.min(parsed, HARD_MAX_REQUESTS);
    } catch (NumberFormatException ex) {
      throw new ApiException("请求预算必须是正整数");
    }
  }

  private int timeoutSeconds(Object raw) {
    if (raw == null) {
      return 6;
    }
    try {
      int parsed = Integer.parseInt(String.valueOf(raw).trim());
      return Math.max(1, Math.min(parsed, 30));
    } catch (NumberFormatException ex) {
      throw new ApiException("请求超时必须是 1-30 之间的整数秒");
    }
  }

  private Set<String> extensions(Object raw) {
    Set<String> result = new LinkedHashSet<>();
    if (raw == null) {
      return result;
    }
    List<String> items;
    if (raw instanceof List<?> list) {
      items = list.stream().filter(java.util.Objects::nonNull).map(String::valueOf).toList();
    } else {
      items = List.of(String.valueOf(raw));
    }
    for (String item : items) {
      for (String token : item.split("[,;\\s]+")) {
        String ext = token.trim().toLowerCase(Locale.ROOT);
        if (ext.isEmpty()) {
          continue;
        }
        if (ext.startsWith(".")) {
          ext = ext.substring(1);
        }
        if (ext.matches("[a-z0-9]{1,10}")) {
          result.add(ext);
        }
      }
    }
    return result;
  }

  private String text(Object raw) {
    return raw == null ? "" : String.valueOf(raw).trim();
  }

  // ---------------------------------------------------------------- planning

  /**
   * Builds the root-level word list, applying the extension expansion and the request budget.
   *
   * <p>Ordering is deterministic: dictionary order is preserved so that a scan is reproducible, and
   * truncation always cuts the tail rather than a random subset.
   */
  private List<String> planDepthFirst(
      List<String> entries, int depth, Set<String> extensions, int budget, int workers) {
    LinkedHashSet<String> planned = new LinkedHashSet<>();
    for (String entry : entries) {
      if (planned.size() >= budget) {
        break;
      }
      String normalized = entry.startsWith("/") ? entry.substring(1) : entry;
      if (normalized.isEmpty()) {
        continue;
      }
      planned.add(normalized);
      if (planned.size() >= budget) {
        break;
      }
      if (!extensions.isEmpty()) {
        // Extension probing only makes sense on file-like entries without their own extension.
        String lastSegment = normalized.endsWith("/")
            ? ""
            : normalized.substring(normalized.lastIndexOf('/') + 1);
        boolean alreadyHasExtension = lastSegment.contains(".");
        if (!alreadyHasExtension && !normalized.endsWith("/")) {
          for (String ext : extensions) {
            if (planned.size() >= budget) {
              break;
            }
            planned.add(normalized + "." + ext);
          }
        }
      }
    }
    return List.copyOf(planned);
  }

  // ---------------------------------------------------------------- execution

  /** Mutable per-call state; deliberately not a field so concurrent tool calls cannot interact. */
  private final class EnumerationRun {
    private final AuthorizedTarget target;
    private final HttpClient client;
    private final List<URI> bases;
    private final String host;
    private final int workers;
    private final int budget;
    private final int timeoutSeconds;
    private final ToolExecutionObserver observer;
    private final int depth;
    private final Set<String> extensions;
    private final Long projectId;

    /** Ordered result accumulation; concurrent writers, ordered read at the end. */
    private final ConcurrentLinkedQueue<Hit> hits = new ConcurrentLinkedQueue<>();

    private final AtomicInteger requests = new AtomicInteger();
    private final AtomicInteger failures = new AtomicInteger();
    private final AtomicInteger completed = new AtomicInteger();
    private volatile Soft404Baseline baseline = Soft404Baseline.none();
    private volatile int plannedTotal;

    EnumerationRun(
        AuthorizedTarget target,
        HttpClient client,
        List<URI> bases,
        String host,
        int workers,
        int budget,
        int timeoutSeconds,
        ToolExecutionObserver observer,
        int depth,
        Set<String> extensions,
        Long projectId) {
      this.target = target;
      this.client = client;
      this.bases = bases;
      this.host = host;
      this.workers = workers;
      this.budget = budget;
      this.timeoutSeconds = timeoutSeconds;
      this.observer = observer;
      this.depth = depth;
      this.extensions = extensions;
      this.projectId = projectId;
    }

    /** Requests a random path to learn what a "not found" response looks like on this host. */
    Soft404Baseline establishBaseline() {
      String marker = "xzy404-" + Long.toHexString(System.nanoTime()) + "/";
      Soft404Baseline detected = Soft404Baseline.none();
      for (URI base : bases) {
        Probe probe = request(base, marker);
        if (probe.status() > 0) {
          detected =
              new Soft404Baseline(
                  base.toString(),
                  probe.status(),
                  probe.length(),
                  probe.bodyHash());
          break;
        }
      }
      this.baseline = detected;
      return detected;
    }

    void enumerateRoot(List<String> entries) {
      plannedTotal = entries.size() * Math.max(1, bases.size());
      observer.progress(0, plannedTotal, "准备枚举 " + entries.size() + " 个路径");
      List<Candidate> work = new ArrayList<>();
      for (String entry : entries) {
        for (URI base : bases) {
          work.add(new Candidate(base, entry, 0));
        }
      }
      execute(work);
    }

    void recurseIntoHits() {
      for (int level = 1; level <= depth; level++) {
        if (observer.isCancellationRequested()) {
          return;
        }
        List<Candidate> next = new ArrayList<>();
        for (Hit hit : hits) {
          if (hit.level() != level - 1 || hit.redirectsAway()) {
            continue;
          }
          if (!hit.looksLikeDirectory()) {
            continue;
          }
          for (String entry : plannedEntriesForRecursion()) {
            if (requests.get() >= budget) {
              return;
            }
            next.add(new Candidate(hit.base(), hit.entry() + "/" + entry, level));
          }
        }
        if (next.isEmpty()) {
          return;
        }
        // Recursion must respect the same global budget as the root pass.
        int remaining = Math.max(0, budget - requests.get());
        if (remaining <= 0) {
          return;
        }
        List<Candidate> bounded =
            next.size() > remaining ? next.subList(0, remaining) : next;
        plannedTotal += bounded.size() * 2;
        observer.progress(
            completed.get(), plannedTotal, "递归第 " + level + " 层，" + bounded.size() + " 个候选");
        execute(bounded);
      }
    }

    private List<String> plannedEntriesForRecursion() {
      // Recursion uses the default dictionary's directory-like entries only, so a 200k-entry
      // wordlist cannot explode exponentially across levels.
      List<String> entries = dictionaries.words(dictionaries.defaultDictionaryId());
      List<String> directories = new ArrayList<>();
      for (String entry : entries) {
        if (directories.size() >= 500) {
          break;
        }
        if (entry.endsWith("/") && !entry.contains("..")) {
          String normalized = entry.startsWith("/") ? entry.substring(1) : entry;
          if (!normalized.isEmpty()) {
            directories.add(normalized.endsWith("/") ? normalized : normalized + "/");
          }
        }
      }
      return List.copyOf(directories);
    }

    private void execute(List<Candidate> work) {
      if (work.isEmpty()) {
        return;
      }
      ExecutorService pool =
          Executors.newFixedThreadPool(Math.min(workers, Math.max(1, work.size())), runnable -> {
            Thread thread = new Thread(runnable);
            thread.setName("dirscan-" + thread.getId());
            thread.setDaemon(true);
            return thread;
          });
      List<Future<?>> futures = new ArrayList<>(work.size());
      try {
        for (Candidate candidate : work) {
          futures.add(
              pool.submit(
                  () -> {
                    if (observer.isCancellationRequested() || requests.get() >= budget) {
                      return;
                    }
                    requests.incrementAndGet();
                    Probe probe = request(candidate.base(), candidate.entry());
                    if (probe.error() != null) {
                      failures.incrementAndGet();
                    } else if (isHit(candidate.entry(), probe)) {
                      hits.add(
                          new Hit(
                              candidate.base(),
                              candidate.entry(),
                              candidate.level(),
                              probe.status(),
                              probe.length(),
                              probe.redirectTarget()));
                      recordHit(candidate, probe);
                    }
                    int done = completed.incrementAndGet();
                    if (done % 25 == 0 || done == plannedTotal) {
                      observer.progress(
                          done, plannedTotal, "目录枚举 " + done + "/" + plannedTotal);
                    }
                  }));
        }
        for (Future<?> future : futures) {
          try {
            future.get();
          } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new ApiException("任务已取消");
          } catch (java.util.concurrent.ExecutionException ex) {
            failures.incrementAndGet();
            log.debug("目录枚举单次请求失败: {}", ex.getCause() == null ? "" : ex.getCause().getMessage());
          }
        }
      } finally {
        pool.shutdownNow();
        try {
          pool.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
          Thread.currentThread().interrupt();
        }
      }
    }

    /**
     * Decides whether a response means "this path exists".
     *
     * <p>Without a baseline the rule is "any status below 400 except 404". With a baseline, a
     * response that matches the baseline's status <em>and</em> is within the length tolerance is
     * treated as a soft-404 and discarded — this is what stops a SPA that returns 200 for every
     * path from producing a false positive for all 87k dictionary entries.
     */
    private boolean isHit(String entry, Probe probe) {
      int status = probe.status();
      if (status <= 0) {
        return false;
      }
      if (status == 404) {
        return false;
      }
      if (status >= 500) {
        // A 500 on a specific path is meaningful (e.g. an error-leaking endpoint), but on a
        // soft-404 baseline host it is usually noise. Keep it only when it differs from baseline.
        return !baseline.matches(status, probe.length(), probe.bodyHash());
      }
      if (baseline.active() && baseline.matches(status, probe.length(), probe.bodyHash())) {
        return false;
      }
      if (status >= 400 && status != 401 && status != 403) {
        return false;
      }
      // 401/403 are meaningful: the path exists but is protected.
      return true;
    }

    /**
     * Persists a hit as a discovered asset.
     *
     * <p>Requires {@code projectId} in the task parameters: {@link DiscoveredPathService#record}
     * keys assets by project, and silently dropping hits would make the scan look empty. When the
     * caller did not supply a project the hit is still reported in the tool result, it is simply not
     * added to the project's asset topology.
     */
    private void recordHit(Candidate candidate, Probe probe) {
      if (projectId == null) {
        return;
      }
      try {
        String url = candidate.base().resolve("/" + candidate.entry()).toString();
        discoveredPaths.record(
            target,
            projectId,
            url,
            "DIR_SCAN",
            probe.status(),
            probe.length(),
            "目录字典枚举（第 " + (candidate.level() + 1) + " 层）");
      } catch (RuntimeException ex) {
        // Out-of-scope URLs are rejected inside record(); that is the intended boundary.
        log.debug("目录枚举命中未落库 entry={} : {}", candidate.entry(), ex.getMessage());
      }
    }

    ToolExecutionResult toResult(
        String dictionaryId, int plannedCount, int dictionarySize, Set<String> extensions) {
      observer.progress(completed.get(), Math.max(completed.get(), plannedTotal), "目录枚举完成");

      List<Hit> ordered =
          hits.stream()
              .sorted(Comparator.comparingInt(Hit::level).thenComparing(Hit::entry))
              .toList();

      List<Map<String, Object>> found = new ArrayList<>(ordered.size());
      for (Hit hit : ordered) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("path", "/" + hit.entry());
        item.put("status", hit.status());
        item.put("length", hit.length());
        item.put("level", hit.level());
        if (hit.redirectTarget() != null) {
          item.put("redirect", hit.redirectTarget());
        }
        found.add(item);
      }

      int requested = requests.get();
      boolean truncated = dictionarySize > plannedCount;
      Map<String, Object> data = new LinkedHashMap<>();
      data.put("host", host);
      data.put("bases", bases.stream().map(Object::toString).toList());
      data.put("dictionary", dictionaryId);
      data.put("dictionaryEntries", dictionarySize);
      data.put("plannedRequests", plannedCount);
      data.put("requests", requested);
      data.put("failures", failures.get());
      data.put("workers", workers);
      data.put("depth", depth);
      if (!extensions.isEmpty()) {
        data.put("extensions", List.copyOf(extensions));
      }
      data.put("softNotFound", baseline.describe());
      data.put("paths", found);
      data.put("pathCount", found.size());
      data.put("truncated", truncated);
      if (truncated) {
        data.put(
            "truncationNote",
            "字典共 "
                + dictionarySize
                + " 条，受请求预算限制实际使用 "
                + plannedCount
                + " 条；如需完整覆盖请提高 maxRequests 或换用更小的字典");
      }
      data.put("assessmentType", "ASSET_OBSERVATION");
      data.put("vulnerability", false);
      data.put(
          "note",
          "目录/路径命中仅代表该地址可达，不自动判定为漏洞；需结合未授权访问、敏感信息泄露或已知漏洞证据后才能形成漏洞");

      String summary =
          "目录枚举完成：字典 "
              + dictionaryId
              + "（"
              + dictionarySize
              + " 条），发出 "
              + requested
              + " 个请求，发现 "
              + found.size()
              + " 条可达路径"
              + (truncated ? "；因请求预算截断至 " + plannedCount + " 条" : "");
      return new ToolExecutionResult(summary, data, List.of());
    }

    private Probe request(URI base, String entry) {
      String targetPath = entry.startsWith("/") ? entry : "/" + entry;
      String url;
      try {
        url = base.resolve(targetPath).toString();
      } catch (RuntimeException ex) {
        return Probe.error("INVALID_URL");
      }
      try {
        URI uri = URI.create(url);
        // Defense in depth: never send a request whose host differs from the authorized host.
        if (uri.getHost() == null || !uri.getHost().equalsIgnoreCase(host)) {
          return Probe.error("HOST_OUT_OF_SCOPE");
        }
        policyService.validateAuthorizedPort(
            target,
            uri.getPort() > 0
                ? uri.getPort()
                : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80));
        HttpRequest request =
            HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("User-Agent", USER_AGENT)
                .GET()
                .build();
        HttpResponse<byte[]> response =
            client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        byte[] raw = response.body() == null ? new byte[0] : response.body();
        int length = raw.length;
        String hash = "";
        if (length <= MAX_BODY_BYTES) {
          hash = Integer.toHexString(java.util.Arrays.hashCode(raw));
        }
        String redirect = response.headers().firstValue("location").orElse(null);
        return new Probe(response.statusCode(), length, hash, redirect, null);
      } catch (ApiException ex) {
        // Out-of-scope port: report as an error so it is never counted as a hit.
        return Probe.error("PORT_OUT_OF_SCOPE");
      } catch (InterruptedException ex) {
        Thread.currentThread().interrupt();
        return Probe.error("INTERRUPTED");
      } catch (Exception ex) {
        return Probe.error(ex.getClass().getSimpleName());
      }
    }
  }

  /**
   * Reads the owning project id from the task parameters.
   *
   * <p>The dispatcher always injects {@code projectId}; it is read here rather than from a field so
   * concurrent scans of different projects cannot cross-write assets.
   */
  private Long projectId(Map<String, Object> parameters) {
    if (parameters == null) {
      return null;
    }
    Object raw = parameters.get("projectId");
    if (raw == null) {
      return null;
    }
    try {
      long value = Long.parseLong(String.valueOf(raw).trim());
      return value > 0 ? value : null;
    } catch (NumberFormatException ex) {
      return null;
    }
  }

  // ---------------------------------------------------------------- records

  private record Candidate(URI base, String entry, int level) {}

  private record Hit(
      URI base, String entry, int level, int status, long length, String redirectTarget) {

    boolean looksLikeDirectory() {
      return entry.endsWith("/") || DIRECTORY_ENTRY.matcher(entry).matches()
          || (redirectTarget != null && redirectTarget.endsWith("/"));
    }

    boolean redirectsAway() {
      return redirectTarget != null && !redirectTarget.startsWith("/");
    }
  }

  private record Probe(int status, long length, String bodyHash, String redirectTarget, String error) {
    static Probe error(String reason) {
      return new Probe(-1, -1, "", null, reason);
    }
  }

  private record Soft404Baseline(String baseUrl, int status, long length, String bodyHash) {
    static Soft404Baseline none() {
      return new Soft404Baseline("", -1, -1, "");
    }

    boolean active() {
      return status > 0;
    }

    boolean matches(int candidateStatus, long candidateLength, String candidateHash) {
      if (!active() || candidateStatus != status) {
        return false;
      }
      if (!bodyHash.isEmpty() && bodyHash.equals(candidateHash)) {
        return true;
      }
      return Math.abs(candidateLength - length) <= SOFT_404_LENGTH_TOLERANCE;
    }

    String describe() {
      return active() ? status + "/" + length + "B" : "无（基线请求失败）";
    }
  }
}
