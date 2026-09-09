package com.bachelor.toolbox.recon;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.traffic.TrafficPacketRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.net.ConnectException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.Context;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class ReconService {
  private static final Logger log = LoggerFactory.getLogger(ReconService.class);
  private static final List<String> DEFAULT_SUBDOMAIN_WORDS =
      List.of("www", "api", "admin", "dev", "test", "staging", "mail", "vpn", "portal", "cdn");
  private static final Pattern TITLE_PATTERN = Pattern.compile("(?is)<title[^>]*>(.*?)</title>");
  private static final Duration PASSIVE_CONNECT_TIMEOUT = Duration.ofSeconds(4);
  private static final Duration PASSIVE_REQUEST_TIMEOUT = Duration.ofSeconds(8);
  private static final long PASSIVE_CACHE_TTL_MILLIS = 3_600_000;
  private static final int PASSIVE_CACHE_MAX_ENTRIES = 128;
  private static final int MAX_PASSIVE_RESPONSE_LENGTH = 2_000_000;
  private static final String USER_AGENT = "Xiezhi-Recon/1.0";
  private static final Pageable HISTORY_PAGE = PageRequest.of(0, 1_000);

  /**
   * 常见后端数据库报错指纹（大小写不敏感、跨行匹配）。命中即视为参数触发了 SQL 报错回显，
   * 用于「参数探测」阶段把疑似可注入的 URL 参数补进已发现路径，交由 sqlmap 复核确认。
   */
  private static final Pattern SQL_ERROR_SIGNATURE =
      Pattern.compile(
          "(?is)(you have an error in your sql syntax"
              + "|warning:\\s*mysqli?"
              + "|mysqli?_(?:fetch|num_rows|query|result)"
              + "|valid mysql result"
              + "|com\\.mysql\\.jdbc"
              + "|mysqlsyntaxerrorexception"
              + "|check the manual that corresponds to your (?:mysql|mariadb)"
              + "|unknown column '[^']*' in 'where clause'"
              + "|postgresql.{0,24}error"
              + "|pg_query\\(\\)|pg::syntaxerror"
              + "|ora-\\d{4,5}|quoted string not properly terminated"
              + "|microsoft ole db provider for sql server"
              + "|unclosed quotation mark after the character string"
              + "|odbc sql server driver|system\\.data\\.sqlclient"
              + "|sqlite/jdbcdriver|sqlite3?::|sqlite3\\.operationalerror"
              + "|near \\\"[^\\\"]+\\\": syntax error"
              + "|sqlstate\\[)");

  /** 参数探测使用的常见 GET 参数名（按命中概率排序，id 优先);受预算与命中上限约束。 */
  private static final List<String> MINE_PARAM_NAMES =
      List.of(
          "id", "uid", "cat", "page", "pid", "user", "name", "q", "item", "cid", "gid", "tid");

  private final ReconResultRepository results;
  private final AssessmentProjectService projects;
  private final AuthorizedTargetRepository targets;
  private final TargetService targetService;
  private final ObjectMapper json;
  private final IcpBrowserCaptureStore icpBrowserCaptures;
  private final DiscoveredPathService discoveredPaths;
  private final TrafficPacketRepository trafficPackets;
  private final HttpClient passiveClient =
      HttpClient.newBuilder()
          .connectTimeout(PASSIVE_CONNECT_TIMEOUT)
          .followRedirects(HttpClient.Redirect.NEVER)
          .build();
  private final PassiveResponseCache passiveCache =
      new PassiveResponseCache(PASSIVE_CACHE_MAX_ENTRIES);

  @Value("${toolbox.recon.passive-sources-enabled:true}")
  private boolean passiveSourcesEnabled;

  @Value("${toolbox.recon.icp-api-url:}")
  private String icpApiUrl;

  @Value("${toolbox.recon.icp-mi-enabled:true}")
  private boolean miitEnabled;

  @Value("${toolbox.recon.icp-mi-auto-enabled:false}")
  private boolean miitAutoEnabled;

  @Value("${toolbox.recon.icp-ocr-models-path:./data/models/icp}")
  private String icpOcrModelsPath;

  @Value("${toolbox.recon.param-probe-enabled:true}")
  private boolean paramProbeEnabled;

  @Value("${toolbox.recon.param-probe-max-endpoints:16}")
  private int paramProbeMaxEndpoints;

  @Value("${toolbox.recon.param-probe-max-findings:8}")
  private int paramProbeMaxFindings;

  public ReconService(
      ReconResultRepository results,
      AssessmentProjectService projects,
      AuthorizedTargetRepository targets,
      TargetService targetService,
      ObjectMapper json,
      IcpBrowserCaptureStore icpBrowserCaptures,
      DiscoveredPathService discoveredPaths,
      TrafficPacketRepository trafficPackets) {
    this.results = results;
    this.projects = projects;
    this.targets = targets;
    this.targetService = targetService;
    this.json = json;
    this.icpBrowserCaptures = icpBrowserCaptures;
    this.discoveredPaths = discoveredPaths;
    this.trafficPackets = trafficPackets;
  }

  public ReconResult collect(Long projectId, ReconRequest request) {
    validateCollectRequest(request);
    projects.validateProjectTarget(projectId, request.targetId());
    targetService.getCurrentlyAuthorized(request.targetId(), projectId);

    AuthorizedTarget target = findTarget(request.targetId());
    String rootDomain = requireRootDomain(target);

    try {
      List<Map<String, Object>> evidence = new ArrayList<>();
      ReconSnapshot snapshot = collectSnapshot(rootDomain, target, request, evidence);
      List<String> webPaths = collectWebPaths(projectId, target, request, evidence);
      ReconResult result =
          createResult(projectId, request.targetId(), rootDomain, snapshot, evidence, webPaths);
      return results.save(result);
    } catch (Exception exception) {
      log.error(
          "信息收集处理失败，projectId={}，targetId={}",
          projectId,
          request.targetId(),
          exception);
      throw new IllegalStateException("信息收集失败，请稍后重试", exception);
    }
  }

  public List<ReconResult> history(Long projectId) {
    projects.get(projectId);
    return results.findByProjectIdOrderByCollectedAtDescIdDesc(projectId, HISTORY_PAGE);
  }

  public List<ReconResult> history(Long projectId, Long targetId) {
    projects.validateProjectTargetMembership(projectId, targetId);
    return results.findByProjectIdAndTargetIdOrderByCollectedAtDescIdDesc(
        projectId, targetId, HISTORY_PAGE);
  }

  public List<IcpResult> icpBatch(Long projectId, IcpBatchRequest request) {
    validateIcpBatchRequest(request);
    return request.targetIds().stream()
        .filter(Objects::nonNull)
        .distinct()
        .limit(100)
        .map(targetId -> collectIcpResult(projectId, targetId))
        .toList();
  }

  private void validateCollectRequest(ReconRequest request) {
    if (request == null || request.targetId() == null) {
      throw new IllegalArgumentException("目标 ID 不能为空");
    }
  }

  private AuthorizedTarget findTarget(Long targetId) {
    return targets.findById(targetId).orElseThrow(() -> new IllegalArgumentException("未找到目标"));
  }

  private String requireRootDomain(AuthorizedTarget target) {
    String rootDomain = hostOf(target.getTargetValue());
    if (rootDomain == null || rootDomain.isBlank()) {
      throw new IllegalArgumentException("授权目标必须包含有效主机名");
    }
    return rootDomain;
  }

  private ReconSnapshot collectSnapshot(
      String rootDomain,
      AuthorizedTarget target,
      ReconRequest request,
      List<Map<String, Object>> evidence) {
    List<InetAddress> addresses = resolveAddresses(rootDomain, evidence);
    Map<String, Object> dnsRecords =
        collectStep("DNS 记录", evidence, () -> dns(rootDomain, addresses));
    Map<String, Object> ipInformation =
        addresses.isEmpty() ? unavailable("域名未解析到可用 IP 地址") : ipInfo(addresses);
    Map<String, Object> tlsInformation =
        Boolean.FALSE.equals(request.includeTls())
            ? skipped("未选择 TLS/证书收集")
            : collectStep("TLS/证书", evidence, () -> tls(rootDomain, tlsPort(target)));
    Map<String, Object> httpInformation =
        Boolean.FALSE.equals(request.includeHttp())
            ? skipped("未选择 HTTP 信息收集")
            : collectStep("HTTP", evidence, () -> http(rootDomain, target));

    Set<String> subdomains = collectSubdomains(rootDomain, request, tlsInformation, evidence);
    Map<String, Object> networkInformation =
        networkInfo(addresses, Boolean.TRUE.equals(request.activeNetworkProbe()));
    Map<String, Object> registrationInformation =
        passiveSourcesEnabled ? rdap(rootDomain, evidence) : unavailable("被动数据源已禁用");
    Map<String, Object> geolocationInformation =
        passiveSourcesEnabled ? geolocate(addresses, evidence) : unavailable("被动数据源已禁用");

    return new ReconSnapshot(
        dnsRecords,
        ipInformation,
        tlsInformation,
        httpInformation,
        subdomains,
        networkInformation,
        registrationInformation,
        geolocationInformation);
  }

  private Set<String> collectSubdomains(
      String rootDomain,
      ReconRequest request,
      Map<String, Object> tlsInformation,
      List<Map<String, Object>> evidence) {
    Set<String> subdomains = new TreeSet<>(certSans(tlsInformation, rootDomain));
    if (passiveSourcesEnabled) {
      subdomains.addAll(crtSh(rootDomain, evidence));
    }
    if (Boolean.TRUE.equals(request.enumerateSubdomains())) {
      enumerate(rootDomain, request.subdomainWords(), subdomains);
    }
    return subdomains;
  }

  private ReconResult createResult(
      Long projectId,
      Long targetId,
      String rootDomain,
      ReconSnapshot snapshot,
      List<Map<String, Object>> evidence,
      List<String> webPaths)
      throws Exception {
    ReconResult result = new ReconResult();
    result.setProjectId(projectId);
    result.setTargetId(targetId);
    result.setRootDomain(rootDomain);
    result.setDnsRecords(write(snapshot.dnsRecords()));
    result.setIpInformation(write(snapshot.ipInformation()));
    result.setTlsInformation(write(snapshot.tlsInformation()));
    result.setHttpInformation(write(snapshot.httpInformation()));
    result.setSubdomains(write(snapshot.subdomains()));
    result.setWebPaths(write(webPaths == null ? List.of() : webPaths));
    result.setNetworkInformation(write(snapshot.networkInformation()));
    result.setRegistrationInformation(write(snapshot.registrationInformation()));
    result.setGeolocationInformation(write(snapshot.geolocationInformation()));
    result.setSourceEvidence(write(evidence));

    // 相邻主机探测必须由单独、经过审核且明确授权 CIDR 的任务执行。
    result.setActiveNetworkProbe(false);
    return result;
  }

  /**
   * 子路径/资产发现：主动目录枚举（含软-404 基线）、站点链接提取、代理会话路径聚合。
   * 全部只在授权 host:端口 内进行；命中写入 DiscoveredPath 并返回本次发现的 URL 列表。
   */
  private List<String> collectWebPaths(
      Long projectId, AuthorizedTarget target, ReconRequest request, List<Map<String, Object>> evidence) {
    java.util.LinkedHashSet<String> discovered = new java.util.LinkedHashSet<>();
    HttpEndpoint endpoint = httpEndpoint(target);
    URI targetUri = targetUri(target.getTargetValue());
    String host = targetUri == null ? null : targetUri.getHost();
    if (host == null || endpoint == null) {
      // 目标无可用 HTTP 端口时仍尝试代理路径聚合（基于已抓包）。
      aggregateProxyPaths(projectId, target, host, discovered, evidence);
      return mergeKnownPaths(projectId, target.getId(), discovered);
    }
    String base = endpoint.scheme() + "://" + host + ":" + endpoint.port();
    HttpClient client =
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(4))
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    // ---- 主动目录枚举（仅 ACTIVE 且勾选）----
    if (request.activeMode() && Boolean.TRUE.equals(request.enumeratePaths())) {
      enumerateWebPaths(projectId, target, base, request.pathWords(), client, discovered, evidence);
    }
    // ---- 站点链接提取 / 爬取（抓根页面，提取同源链接）----
    if (request.activeMode() && Boolean.TRUE.equals(request.crawlSite())) {
      crawlLinks(projectId, target, base, client, discovered, evidence);
    }
    // ---- 参数探测：对已发现端点补测常见可注入 GET 参数，命中 SQL 报错则登记候选 ----
    if (request.activeMode()
        && (Boolean.TRUE.equals(request.crawlSite())
            || Boolean.TRUE.equals(request.enumeratePaths()))) {
      mineInjectableParameters(projectId, target, base, discovered, evidence);
    }
    // ---- 被动代理会话路径聚合 ----
    if (!request.activeMode() || Boolean.TRUE.equals(request.aggregateProxyPaths())) {
      aggregateProxyPaths(projectId, target, host, discovered, evidence);
    }
    return mergeKnownPaths(projectId, target.getId(), discovered);
  }

  /**
   * 快照并入该目标当前已知的全部路径（含历史与各来源），使「已发现路径」结果与主动检测的路径选择保持一致。
   * 去重由 {@link DiscoveredPathService#record} 保证，这里只是把完整集合并入本次返回的快照。
   */
  private List<String> mergeKnownPaths(
      Long projectId, Long targetId, java.util.LinkedHashSet<String> discovered) {
    try {
      for (var dp : discoveredPaths.list(projectId, targetId)) {
        if (dp.getUrl() != null && !dp.getUrl().isBlank()) {
          discovered.add(dp.getUrl());
        }
      }
    } catch (RuntimeException ex) {
      log.debug("合并已知路径快照失败 targetId={} : {}", targetId, ex.getMessage());
    }
    return List.copyOf(discovered);
  }

  private void enumerateWebPaths(
      Long projectId,
      AuthorizedTarget target,
      String base,
      List<String> requestedWords,
      HttpClient client,
      java.util.LinkedHashSet<String> discovered,
      List<Map<String, Object>> evidence) {
    List<String> words = expandPathWords(requestedWords);
    if (words.isEmpty()) return;
    // 软-404 基线：请求一个几乎不可能存在的路径。
    long[] baseline = probePath(client, base + "/xzy404-" + Long.toHexString(System.nanoTime()) + "/");
    int found = 0;
    int limit = 400;
    for (String word : words) {
      if (limit-- <= 0) break;
      String url = base + "/" + word.replaceFirst("^/+", "");
      long[] r = probePath(client, url);
      if (r == null) continue;
      int status = (int) r[0];
      long len = r[1];
      boolean exists;
      if (baseline == null) {
        exists = status > 0 && status < 400;
      } else {
        exists = status != (int) baseline[0] || Math.abs(len - baseline[1]) > 24;
      }
      if (exists && status > 0 && status < 500 && status != 404) {
        if (discoveredPaths.record(target, projectId, url, "ACTIVE_ENUM", status, len, "目录字典枚举")) {
          discovered.add(url);
          found++;
        }
      }
    }
    evidence.add(
        Map.of("source", "PATH_ENUM", "available", true, "candidates", words.size(), "found", found));
  }

  private void crawlLinks(
      Long projectId,
      AuthorizedTarget target,
      String base,
      HttpClient client,
      java.util.LinkedHashSet<String> discovered,
      List<Map<String, Object>> evidence) {
    int found = 0;
    try {
      HttpRequest req =
          HttpRequest.newBuilder(URI.create(base + "/"))
              .timeout(Duration.ofSeconds(8))
              .header("User-Agent", USER_AGENT)
              .GET()
              .build();
      HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
      String body = resp.body() == null ? "" : resp.body();
      Matcher m =
          Pattern.compile("(?i)(?:href|src|action)\\s*=\\s*[\"']([^\"'#>]+)[\"']").matcher(body);
      int limit = 200;
      while (m.find() && limit-- > 0) {
        String link = m.group(1).trim();
        if (link.isBlank() || link.startsWith("javascript:") || link.startsWith("mailto:")
            || link.startsWith("data:")) continue;
        String url = resolveLink(base, link);
        if (url == null) continue;
        if (discoveredPaths.record(target, projectId, url, "PASSIVE_LINK", null, null, "页面源码链接提取")) {
          discovered.add(url);
          found++;
        }
      }
    } catch (Exception ex) {
      log.debug("站点链接提取失败 base={} : {}", base, ex.getMessage());
    }
    evidence.add(Map.of("source", "SITE_CRAWL", "available", true, "found", found));
  }

  /**
   * 参数探测：对本次已发现的端点（目录/动态页面）逐个补测常见 GET 参数。若注入单引号后
   * 出现后端 SQL 报错回显（而合法值不报错），则把带合法值的 URL 作为疑似可注入候选登记进
   * 已发现路径，交由后续 sqlmap 主动检测复核确认——用以降低「站点存在注入却因未带参数
   * 而漏报」的情况。全部请求仅在授权 host:端口 内进行，且受端点数、命中数与请求预算约束。
   */
  private void mineInjectableParameters(
      Long projectId,
      AuthorizedTarget target,
      String base,
      java.util.LinkedHashSet<String> discovered,
      List<Map<String, Object>> evidence) {
    if (!paramProbeEnabled || paramProbeMaxEndpoints <= 0 || paramProbeMaxFindings <= 0) {
      return;
    }
    HttpClient client =
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(4))
            .version(HttpClient.Version.HTTP_1_1)
            // 跟随同源目录 301（如 /Less-2 → /Less-2/），否则注入报错会被重定向掩盖。
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    // 候选端点：基址本身 + 本次已发现、非静态资源的 URL。
    // 端点数受 maxPathsPerScan 上限约束，直接按发现顺序截断会漏掉排在后面的可注入端点，
    // 因此先按「可注入可能性」排序再截断：已带查询串 > 脚本后缀(.php/.asp/...) > 其它动态目录，
    // 让有限的请求预算优先花在更可能存在注入的端点上，降低规模化站点下的漏报。
    java.util.LinkedHashSet<String> candidates = new java.util.LinkedHashSet<>();
    candidates.add(base + "/");
    for (String url : discovered) {
      if (url == null || url.isBlank() || isStaticAsset(url)) continue;
      candidates.add(url);
    }
    List<String> ordered = new ArrayList<>(candidates);
    ordered.sort(java.util.Comparator.comparingInt(this::injectionLikelihoodRank));
    java.util.LinkedHashSet<String> endpoints = new java.util.LinkedHashSet<>();
    for (String url : ordered) {
      if (endpoints.size() >= paramProbeMaxEndpoints) break;
      // 已带查询串的端点，去掉查询串后作为探测基址（避免把探测参数拼到已有 query 上重复）。
      endpoints.add(url.contains("?") ? url.substring(0, url.indexOf('?')) : url);
    }

    String targetHost = URI.create(base + "/").getHost();
    int tested = 0;
    int found = 0;
    int budget = paramProbeMaxEndpoints * 6 + 24; // 请求预算兜底，避免探测放大。
    outer:
    for (String endpoint : endpoints) {
      if (found >= paramProbeMaxFindings) break;
      for (String param : MINE_PARAM_NAMES) {
        if (found >= paramProbeMaxFindings) break outer;
        if (budget-- <= 0) break outer;
        MineResponse baseResp = mineProbe(client, appendParam(endpoint, param, "1"), targetHost);
        if (baseResp == null || baseResp.status() >= 500) continue;
        tested++;
        MineResponse brkResp = mineProbe(client, appendParam(endpoint, param, "1'"), targetHost);
        if (brkResp == null) continue;
        boolean errorTriggered =
            SQL_ERROR_SIGNATURE.matcher(brkResp.body()).find()
                && !SQL_ERROR_SIGNATURE.matcher(baseResp.body()).find();
        if (!errorTriggered) continue;
        String candidate =
            baseResp.finalUrl() != null ? baseResp.finalUrl() : appendParam(endpoint, param, "1");
        String note =
            "疑似可注入参数(" + param + ")：注入单引号触发后端 SQL 报错回显，建议用 sqlmap 复核确认";
        if (discoveredPaths.record(
            target,
            projectId,
            candidate,
            "ACTIVE_ENUM",
            baseResp.status(),
            (long) baseResp.body().length(),
            note)) {
          discovered.add(candidate);
          found++;
        }
        continue outer; // 每个端点命中一个可注入参数即足够，避免重复登记。
      }
    }
    evidence.add(
        Map.of("source", "PARAM_PROBE", "available", true, "tested", tested, "found", found));
  }

  /** 参数探测的单次响应快照（状态码、跟随重定向后的最终 URL、受限正文）。 */
  private record MineResponse(int status, String finalUrl, String body) {}

  private MineResponse mineProbe(HttpClient client, String url, String targetHost) {
    try {
      HttpRequest req =
          HttpRequest.newBuilder(URI.create(url))
              .timeout(Duration.ofSeconds(6))
              .header("User-Agent", USER_AGENT)
              .GET()
              .build();
      HttpResponse<byte[]> resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray());
      URI finalUri = resp.uri();
      // 重定向可能被跟随到其它主机——越界则丢弃，登记环节也会再兜底一次。
      if (finalUri == null
          || finalUri.getHost() == null
          || (targetHost != null && !targetHost.equalsIgnoreCase(finalUri.getHost()))) {
        return null;
      }
      byte[] raw = resp.body() == null ? new byte[0] : resp.body();
      int len = Math.min(raw.length, 200_000);
      String body = new String(raw, 0, len, StandardCharsets.UTF_8);
      return new MineResponse(resp.statusCode(), finalUri.toString(), body);
    } catch (Exception ex) {
      return null;
    }
  }

  private String appendParam(String endpoint, String name, String value) {
    String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8);
    String sep = endpoint.contains("?") ? "&" : "?";
    return endpoint + sep + name + "=" + encoded;
  }

  /**
   * 端点可注入可能性排序权重（越小越优先探测）：已带查询参数(0) > 常见脚本后缀(1) >
   * 其它动态目录/路径(2)。仅用于在预算受限时决定探测顺序，不代表判定注入与否。
   */
  private int injectionLikelihoodRank(String url) {
    if (url == null) return 3;
    String lower = url.toLowerCase(Locale.ROOT);
    int q = lower.indexOf('?');
    String pathPart = q >= 0 ? lower.substring(0, q) : lower;
    if (q >= 0 && lower.substring(q).contains("=")) {
      return 0; // 已带 key=value 查询串，最可能可注入
    }
    if (pathPart.matches(".*\\.(?:php|asp|aspx|jsp|jspx|do|action|cgi|pl|py|rb)$")) {
      return 1; // 动态脚本后缀
    }
    return 2;
  }

  private boolean isStaticAsset(String url) {
    String lower = url.toLowerCase(Locale.ROOT);
    int q = lower.indexOf('?');
    if (q >= 0) lower = lower.substring(0, q);
    return lower.matches(
        ".*\\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|eot|otf|map"
            + "|pdf|zip|gz|tar|rar|7z|mp4|mp3|avi|mov|wav|ogg)$");
  }

  private void aggregateProxyPaths(
      Long projectId,
      AuthorizedTarget target,
      String host,
      java.util.LinkedHashSet<String> discovered,
      List<Map<String, Object>> evidence) {
    if (host == null) return;
    int found = 0;
    try {
      for (Object[] row : trafficPackets.findDistinctEndpointsByHost(host)) {
        String scheme = row[0] == null ? "http" : String.valueOf(row[0]);
        Integer port = row[2] == null ? null : ((Number) row[2]).intValue();
        String path = row[3] == null ? "/" : String.valueOf(row[3]);
        String url =
            scheme + "://" + host + (port != null && port > 0 ? ":" + port : "") + path;
        if (discoveredPaths.record(target, projectId, url, "PROXY", null, null, "代理会话路径聚合")) {
          discovered.add(url);
          found++;
        }
      }
    } catch (Exception ex) {
      log.debug("代理路径聚合失败 host={} : {}", host, ex.getMessage());
    }
    evidence.add(Map.of("source", "PROXY_PATHS", "available", true, "found", found));
  }

  private long[] probePath(HttpClient client, String url) {
    try {
      HttpRequest req =
          HttpRequest.newBuilder(URI.create(url))
              .timeout(Duration.ofSeconds(6))
              .header("User-Agent", USER_AGENT)
              .GET()
              .build();
      HttpResponse<byte[]> resp = client.send(req, HttpResponse.BodyHandlers.ofByteArray());
      long len = resp.body() == null ? 0 : resp.body().length;
      return new long[] {resp.statusCode(), len};
    } catch (Exception ex) {
      return null;
    }
  }

  private String resolveLink(String base, String link) {
    try {
      URI baseUri = URI.create(base + "/");
      URI resolved = baseUri.resolve(link);
      if (resolved.getHost() == null) return null;
      // 仅同源（同 host）链接；端口授权由 discoveredPaths.record 兜底。
      if (!resolved.getHost().equalsIgnoreCase(baseUri.getHost())) return null;
      if (!"http".equalsIgnoreCase(resolved.getScheme())
          && !"https".equalsIgnoreCase(resolved.getScheme())) return null;
      return resolved.toString();
    } catch (Exception ex) {
      return null;
    }
  }

  private List<String> expandPathWords(List<String> requested) {
    List<String> raw =
        (requested == null || requested.isEmpty()) ? loadDefaultPathWords() : requested;
    java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
    Pattern range = Pattern.compile("(.*?)\\[(\\d+)-(\\d+)\\](.*)");
    for (String w : raw) {
      if (w == null) continue;
      String word = w.trim();
      if (word.isEmpty() || word.startsWith("#")) continue;
      Matcher rm = range.matcher(word);
      if (rm.matches()) {
        int from = Integer.parseInt(rm.group(2));
        int to = Integer.parseInt(rm.group(3));
        if (to - from > 500) to = from + 500; // 上限保护
        for (int i = from; i <= to; i++) {
          out.add(rm.group(1) + i + rm.group(4));
        }
      } else {
        out.add(word);
      }
      if (out.size() >= 600) break;
    }
    return List.copyOf(out);
  }

  private List<String> loadDefaultPathWords() {
    try {
      ClassPathResource resource = new ClassPathResource("wordlists/web-paths.txt");
      if (!resource.exists()) return List.of();
      try (var in = resource.getInputStream()) {
        String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        return Arrays.stream(text.split("\\R"))
            .map(String::trim)
            .filter(s -> !s.isEmpty() && !s.startsWith("#"))
            .toList();
      }
    } catch (Exception ex) {
      log.debug("加载默认路径字典失败: {}", ex.getMessage());
      return List.of();
    }
  }

  private void validateIcpBatchRequest(IcpBatchRequest request) {
    if (request == null || request.targetIds() == null || request.targetIds().isEmpty()) {
      throw new IllegalArgumentException("目标 ID 列表不能为空");
    }
    if (request.targetIds().stream().anyMatch(Objects::isNull)) {
      throw new IllegalArgumentException("目标 ID 不能为空");
    }
  }

  private IcpResult collectIcpResult(Long projectId, Long targetId) {
    projects.validateProjectTarget(projectId, targetId);
    targetService.getCurrentlyAuthorized(targetId, projectId);
    AuthorizedTarget target = targets.findById(targetId).orElse(null);
    if (target == null) {
      return new IcpResult(targetId, "", "UNAVAILABLE", "授权目标不存在或已删除", Map.of());
    }
    String domain = hostOf(target.getTargetValue());

    if (domain == null) {
      return new IcpResult(targetId, "", "UNAVAILABLE", "目标中没有可查询的域名", Map.of());
    }

    IcpBrowserCaptureStore.Capture captured = icpBrowserCaptures.take(projectId, targetId);
    if (captured != null && captured.records() != null && !captured.records().isEmpty()) {
      log.info("[icp-batch] targetId={} using captured records n={}", targetId,
          captured.records().size());
      return new IcpResult(
          targetId, domain, "AVAILABLE", "",
          Map.of(
              "source", "miit-browser-capture",
              "records", captured.records(),
              "total", captured.records().size()));
    }

    if (miitEnabled) {
      if (miitAutoEnabled) {
        MiitIcpClient.MiitResult builtIn =
            new MiitIcpClient(json, icpOcrModelsPath).queryByUnit(domain);
        if (builtIn.success()) {
          return new IcpResult(
              targetId, domain, "AVAILABLE", "",
              Map.of(
                  "source", "miit",
                  "records", convertRecords(builtIn.records),
                  "total", builtIn.total));
        }
        if (!hasManualIcpSource()) {
          return new IcpResult(
              targetId, domain, "CAPTCHA_REQUIRED", builtIn.reason,
              Map.of("source", "miit", "reason", builtIn.reason));
        }
        return collectManualIcpResult(targetId, domain);
      }
      // The MIIT gateway no longer returns a challenge secretKey, so the built-in
      // auto chain cannot satisfy its point challenge. Route the operator to the
      // desktop browser assistant (浏览器代填) instead of surfacing an internal error.
      if (!hasManualIcpSource()) {
        log.info("[icp-batch] targetId={} -> BROWSER_REQUIRED (no captured, auto disabled)",
            targetId);
        return new IcpResult(
            targetId,
            domain,
            "BROWSER_REQUIRED",
            "请使用“浏览器代填”完成备案查询",
            Map.of("source", "miit-browser", "reason", "请使用浏览器代填"));
      }
      return collectManualIcpResult(targetId, domain);
    }

    return collectManualIcpResult(targetId, domain);
  }

  private boolean hasManualIcpSource() {
    return icpApiUrl != null && !icpApiUrl.isBlank();
  }

  private IcpResult collectManualIcpResult(Long targetId, String domain) {
    if (!hasManualIcpSource()) {
      return new IcpResult(
          targetId,
          domain,
          "CONFIG_REQUIRED",
          "尚未配置 ICP 查询数据源（ICP_API_URL）",
          Map.of("source", "configuration", "requiredSetting", "ICP_API_URL"));
    }

    try {
      String endpoint = buildIcpEndpoint(domain);
      URI sourceUri = URI.create(endpoint);
      if (!"https".equalsIgnoreCase(sourceUri.getScheme())) {
        throw new IllegalArgumentException("ICP 数据源必须使用 HTTPS");
      }
      var body = json.readTree(getCached(endpoint));
      return new IcpResult(targetId, domain, "AVAILABLE", "", json.convertValue(body, Map.class));
    } catch (Exception exception) {
      return new IcpResult(targetId, domain, "UNAVAILABLE", safeError(exception), Map.of());
    }
  }

  private List<Map<String, Object>> convertRecords(List<IcpRecord> records) {
    if (records == null) {
      return List.of();
    }
    List<Map<String, Object>> rows = new ArrayList<>();
    for (IcpRecord record : records) {
      Map<String, Object> row = new LinkedHashMap<>();
      row.put("owner", record.owner());
      row.put("domain", record.domain());
      row.put("mainLicense", record.mainLicense());
      row.put("serviceLicense", record.serviceLicense());
      row.put("type", record.type());
      row.put("approvedContent", record.approvedContent());
      row.put("limitAccess", record.limitAccess());
      row.put("approveDate", record.approveDate());
      rows.add(row);
    }
    return rows;
  }

  private String buildIcpEndpoint(String domain) {
    String encodedDomain = URLEncoder.encode(domain, StandardCharsets.UTF_8);
    if (icpApiUrl != null && icpApiUrl.contains("{domain}")) {
      return icpApiUrl.replace("{domain}", encodedDomain);
    }
    String separator = icpApiUrl != null && icpApiUrl.contains("?") ? "&" : "?";
    return icpApiUrl + separator + "domain=" + encodedDomain;
  }

  private Map<String, Object> dns(String host, List<InetAddress> addresses) throws Exception {
    Map<String, Object> records = new LinkedHashMap<>();
    records.put(
        "A",
        addresses.stream()
            .filter(address -> address instanceof Inet4Address)
            .map(InetAddress::getHostAddress)
            .toList());
    records.put(
        "AAAA",
        addresses.stream()
            .filter(address -> address instanceof Inet6Address)
            .map(InetAddress::getHostAddress)
            .toList());

    Hashtable<String, String> environment = new Hashtable<>();
    environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
    DirContext context = new InitialDirContext(environment);
    for (String type : List.of("CNAME", "MX", "NS", "TXT")) {
      records.put(type, readDnsValues(context, host, type));
    }
    context.close();
    return records;
  }

  private List<String> readDnsValues(DirContext context, String host, String type) {
    List<String> values = new ArrayList<>();
    try {
      Attributes attributes = context.getAttributes(host, new String[] {type});
      Attribute attribute = attributes.get(type);
      if (attribute != null) {
        for (int index = 0; index < attribute.size(); index++) {
          values.add(String.valueOf(attribute.get(index)));
        }
      }
    } catch (Exception ignored) {
      // 单个记录类型查询失败时，保留其他已采集的 DNS 信息。
    }
    return values;
  }

  private List<InetAddress> resolve(String host) throws Exception {
    return Arrays.asList(InetAddress.getAllByName(host));
  }

  private List<InetAddress> resolveAddresses(String host, List<Map<String, Object>> evidence) {
    try {
      List<InetAddress> addresses = resolve(host);
      evidence.add(source("DNS/IP 解析", "AVAILABLE", addresses.size() + " 个地址"));
      return addresses;
    } catch (Exception exception) {
      evidence.add(source("DNS/IP 解析", "UNAVAILABLE", safeError(exception)));
      return List.of();
    }
  }

  private Map<String, Object> collectStep(
      String name, List<Map<String, Object>> evidence, CheckedMapSupplier supplier) {
    try {
      Map<String, Object> value = supplier.get();
      String status = String.valueOf(value.getOrDefault("status", "AVAILABLE"));
      String detail =
          "SKIPPED".equals(status) ? String.valueOf(value.getOrDefault("reason", "已跳过")) : "采集完成";
      evidence.add(source(name, status, detail));
      return value;
    } catch (Exception exception) {
      String reason = safeError(exception);
      evidence.add(source(name, "UNAVAILABLE", reason));
      return unavailable(reason);
    }
  }

  private Map<String, Object> ipInfo(List<InetAddress> addresses) {
    List<Map<String, Object>> rows = new ArrayList<>();
    for (InetAddress address : addresses) {
      String reverseDns;
      try {
        reverseDns = address.getCanonicalHostName();
      } catch (Exception exception) {
        reverseDns = "";
      }
      rows.add(
          Map.of(
              "address", address.getHostAddress(),
              "version", address instanceof Inet4Address ? 4 : 6,
              "reverseDns", reverseDns,
              "siteLocal", address.isSiteLocalAddress(),
              "loopback", address.isLoopbackAddress()));
    }
    return Map.of("addresses", rows);
  }

  private Map<String, Object> tls(String host, int port) throws Exception {
    if (port < 0) {
      return skipped("目标未声明已授权的 TLS 端口");
    }

    try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
      socket.connect(new InetSocketAddress(host, port), 5_000);
      socket.setSoTimeout(7_000);
      socket.startHandshake();

      X509Certificate certificate = (X509Certificate) socket.getSession().getPeerCertificates()[0];
      List<String> subjectAlternativeNames = certificateDnsNames(certificate);
      return Map.of(
          "port", port,
          "subject", certificate.getSubjectX500Principal().getName(),
          "issuer", certificate.getIssuerX500Principal().getName(),
          "validFrom", certificate.getNotBefore().toInstant().toString(),
          "validTo", certificate.getNotAfter().toInstant().toString(),
          "serial", certificate.getSerialNumber().toString(16),
          "sans", subjectAlternativeNames);
    }
  }

  private List<String> certificateDnsNames(X509Certificate certificate) throws Exception {
    List<String> names = new ArrayList<>();
    Collection<List<?>> entries = certificate.getSubjectAlternativeNames();
    if (entries != null) {
      for (List<?> entry : entries) {
        if (Objects.equals(entry.get(0), 2)) {
          names.add(String.valueOf(entry.get(1)));
        }
      }
    }
    return names;
  }

  private Map<String, Object> http(String host, AuthorizedTarget target) throws Exception {
    HttpEndpoint endpoint = httpEndpoint(target);
    if (endpoint == null) {
      return skipped("目标 URL 对应的 HTTP 端口不在项目授权端口范围内");
    }

    URI uri = new URI(endpoint.scheme(), null, host, endpoint.port(), "/", null, null);
    HttpClient client =
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    HttpRequest request =
        HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(10))
            .header("User-Agent", USER_AGENT)
            .GET()
            .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    Matcher titleMatcher = TITLE_PATTERN.matcher(response.body());

    return Map.of(
        "url", uri.toString(),
        "status", response.statusCode(),
        "title", titleMatcher.find() ? titleMatcher.group(1).replaceAll("\\s+", " ").trim() : "",
        "server", response.headers().firstValue("server").orElse(""),
        "headers", response.headers().map(),
        "redirect", response.headers().firstValue("location").orElse(""));
  }

  private void enumerate(String rootDomain, List<String> requested, Set<String> output) {
    List<String> words =
        requested == null || requested.isEmpty()
            ? DEFAULT_SUBDOMAIN_WORDS
            : requested.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(word -> word.matches("[A-Za-z0-9-]{1,63}"))
                .distinct()
                .limit(50)
                .toList();

    for (String word : words) {
      String host = word + "." + rootDomain;
      if (!withinRoot(host, rootDomain)) {
        continue;
      }
      try {
        if (InetAddress.getAllByName(host).length > 0) {
          output.add(host);
        }
      } catch (Exception ignored) {
        // 无法解析的候选子域不计入结果。
      }
    }
  }

  private Set<String> certSans(Map<String, Object> tlsInformation, String rootDomain) {
    Set<String> names = new HashSet<>();
    Object value = tlsInformation.get("sans");
    if (value instanceof Collection<?> collection) {
      for (Object item : collection) {
        String host = String.valueOf(item).toLowerCase(Locale.ROOT).replaceFirst("^\\*\\.", "");
        if (withinRoot(host, rootDomain)) {
          names.add(host);
        }
      }
    }
    return names;
  }

  private Map<String, Object> networkInfo(List<InetAddress> addresses, boolean requested) {
    List<String> cidrs =
        addresses.stream()
            .map(
                address ->
                    address instanceof Inet4Address
                        ? ipv4Cidr(address.getAddress())
                        : address.getHostAddress().split("%", 2)[0] + "/64")
            .toList();
    return Map.of(
        "derivedCidrs",
        cidrs,
        "neighbourProbeRequested",
        requested,
        "neighbourProbePerformed",
        false,
        "notice",
        "仅计算候选 CIDR；没有明确的 CIDR 授权和审批时，不会访问相邻主机。");
  }

  private String ipv4Cidr(byte[] address) {
    return (address[0] & 255) + "." + (address[1] & 255) + "." + (address[2] & 255) + ".0/24";
  }

  private boolean allowedPort(AuthorizedTarget target, int port) {
    for (String part : target.getAllowedPorts().split(",")) {
      String value = part.trim();
      try {
        if (value.contains("-")) {
          String[] range = value.split("-", 2);
          int start = Integer.parseInt(range[0]);
          int end = Integer.parseInt(range[1]);
          if (port >= start && port <= end) {
            return true;
          }
        } else if (Integer.parseInt(value) == port) {
          return true;
        }
      } catch (Exception ignored) {
        // 无效端口配置不能扩大授权范围。
      }
    }
    return false;
  }

  private HttpEndpoint httpEndpoint(AuthorizedTarget target) {
    URI uri = targetUri(target.getTargetValue());
    String declaredScheme =
        uri == null || uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
    int explicitPort = uri == null ? -1 : uri.getPort();

    if ("http".equals(declaredScheme) || "https".equals(declaredScheme)) {
      int port = explicitPort > 0 ? explicitPort : ("https".equals(declaredScheme) ? 443 : 80);
      return allowedPort(target, port) ? new HttpEndpoint(declaredScheme, port) : null;
    }
    if (explicitPort > 0) {
      String scheme = explicitPort == 443 || explicitPort == 8443 ? "https" : "http";
      return allowedPort(target, explicitPort) ? new HttpEndpoint(scheme, explicitPort) : null;
    }
    if (allowedPort(target, 443)) {
      return new HttpEndpoint("https", 443);
    }
    if (allowedPort(target, 80)) {
      return new HttpEndpoint("http", 80);
    }
    return null;
  }

  private int tlsPort(AuthorizedTarget target) {
    URI uri = targetUri(target.getTargetValue());
    String declaredScheme =
        uri == null || uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
    int explicitPort = uri == null ? -1 : uri.getPort();

    if ("https".equals(declaredScheme)) {
      int port = explicitPort > 0 ? explicitPort : 443;
      return allowedPort(target, port) ? port : -1;
    }
    if (!"http".equals(declaredScheme)
        && explicitPort > 0
        && (explicitPort == 443 || explicitPort == 8443)
        && allowedPort(target, explicitPort)) {
      return explicitPort;
    }
    return allowedPort(target, 443) ? 443 : -1;
  }

  private boolean withinRoot(String host, String rootDomain) {
    String normalizedHost = host.toLowerCase(Locale.ROOT);
    String normalizedRoot = rootDomain.toLowerCase(Locale.ROOT);
    return normalizedHost.equals(normalizedRoot) || normalizedHost.endsWith("." + normalizedRoot);
  }

  private URI targetUri(String raw) {
    try {
      String value = raw.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*") ? raw : "//" + raw;
      return URI.create(value);
    } catch (Exception exception) {
      return null;
    }
  }

  private String hostOf(String raw) {
    URI uri = targetUri(raw);
    return uri == null ? null : uri.getHost();
  }

  private String write(Object value) throws Exception {
    return json.writeValueAsString(value);
  }

  private Set<String> crtSh(String rootDomain, List<Map<String, Object>> evidence) {
    try {
      String encodedDomain = URLEncoder.encode(rootDomain, StandardCharsets.UTF_8);
      String body = getCached("https://crt.sh/?q=%25." + encodedDomain + "&output=json");
      Set<String> names = new TreeSet<>();
      for (var row : json.readTree(body)) {
        for (String rawName : row.path("name_value").asText().split("\\n")) {
          String host = rawName.trim().toLowerCase(Locale.ROOT).replaceFirst("^\\*\\.", "");
          if (withinRoot(host, rootDomain)) {
            names.add(host);
          }
        }
      }
      evidence.add(source("crt.sh", "AVAILABLE", names.size() + " 个范围内证书域名"));
      return names;
    } catch (Exception exception) {
      evidence.add(source("crt.sh", "UNAVAILABLE", safeError(exception)));
      return Collections.emptySet();
    }
  }

  private Map<String, Object> rdap(String rootDomain, List<Map<String, Object>> evidence) {
    try {
      String encodedDomain = URLEncoder.encode(rootDomain, StandardCharsets.UTF_8);
      var node = json.readTree(getCached("https://rdap.org/domain/" + encodedDomain));
      Map<String, Object> registration = new LinkedHashMap<>();
      registration.put("status", "AVAILABLE");
      registration.put("source", "rdap.org bootstrap");
      registration.put("handle", node.path("handle").asText(""));
      registration.put("ldhName", node.path("ldhName").asText(rootDomain));
      registration.put("statuses", json.convertValue(node.path("status"), List.class));
      registration.put("events", json.convertValue(node.path("events"), List.class));
      registration.put("nameservers", json.convertValue(node.path("nameservers"), List.class));
      evidence.add(source("RDAP", "AVAILABLE", "已返回注册信息"));
      return registration;
    } catch (Exception exception) {
      String reason = safeError(exception);
      evidence.add(source("RDAP", "UNAVAILABLE", reason));
      return unavailable(reason);
    }
  }

  private Map<String, Object> geolocate(
      List<InetAddress> addresses, List<Map<String, Object>> evidence) {
    List<Object> rows = new ArrayList<>();
    for (InetAddress address : addresses) {
      if (address.isAnyLocalAddress()
          || address.isLoopbackAddress()
          || address.isSiteLocalAddress()) {
        continue;
      }
      rows.add(geolocateAddress(address));
    }

    String status = rows.isEmpty() ? "UNAVAILABLE" : "AVAILABLE";
    evidence.add(source("ipwho.is", status, rows.size() + " 个公网地址已查询"));
    return Map.of(
        "status",
        status,
        "source",
        "ipwho.is",
        "addresses",
        rows,
        "notice",
        "地理位置为近似结果，不应视为实际物理位置事实。");
  }

  private Object geolocateAddress(InetAddress address) {
    try {
      String encodedAddress = URLEncoder.encode(address.getHostAddress(), StandardCharsets.UTF_8);
      var node = json.readTree(getCached("https://ipwho.is/" + encodedAddress));
      Map<String, Object> row = new LinkedHashMap<>();
      row.put("ip", address.getHostAddress());
      row.put("success", node.path("success").asBoolean(false));
      for (String key : List.of("continent", "country", "region", "city", "connection")) {
        row.put(key, json.convertValue(node.path(key), Object.class));
      }
      return row;
    } catch (Exception exception) {
      return Map.of(
          "ip", address.getHostAddress(),
          "status", "UNAVAILABLE",
          "reason", safeError(exception));
    }
  }

  private String getCached(String url) throws Exception {
    long now = System.currentTimeMillis();
    String cached = passiveCache.get(url, now);
    if (cached != null) return cached;

    URI uri = URI.create(url);
    if (!"https".equalsIgnoreCase(uri.getScheme())) {
      throw new IllegalArgumentException("被动数据源必须使用 HTTPS");
    }
    HttpRequest request =
        HttpRequest.newBuilder(uri)
            .timeout(PASSIVE_REQUEST_TIMEOUT)
            .header("User-Agent", USER_AGENT)
            .GET()
            .build();
    HttpResponse<String> response =
        passiveClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() / 100 != 2) {
      throw new IllegalStateException("数据源返回 HTTP " + response.statusCode());
    }
    if (response.body().length() > MAX_PASSIVE_RESPONSE_LENGTH) {
      throw new IllegalStateException("数据源响应过大");
    }

    passiveCache.put(url, response.body(), now + PASSIVE_CACHE_TTL_MILLIS, now);
    return response.body();
  }

  private Map<String, Object> unavailable(String reason) {
    return Map.of("status", "UNAVAILABLE", "reason", reason);
  }

  private Map<String, Object> skipped(String reason) {
    return Map.of("status", "SKIPPED", "reason", reason);
  }

  private Map<String, Object> source(String name, String status, String detail) {
    return Map.of(
        "source", name,
        "status", status,
        "detail", detail,
        "collectedAt", java.time.Instant.now().toString());
  }

  private String safeError(Exception error) {
    log.warn("信息收集数据源请求失败", error);
    for (Throwable cause = error; cause != null; cause = cause.getCause()) {
      if (cause instanceof UnknownHostException) {
        return "域名无法解析";
      }
      if (cause instanceof HttpTimeoutException || cause instanceof SocketTimeoutException) {
        return "连接或读取超时";
      }
      if (cause instanceof ConnectException) {
        return "连接被拒绝：目标服务未启动、端口未开放，或依赖服务当前不可用";
      }
      if (cause instanceof SSLException) {
        return "TLS 握手失败";
      }
    }
    String message = error.getMessage();
    if ("被动数据源必须使用 HTTPS".equals(message)
        || "ICP 数据源必须使用 HTTPS".equals(message)
        || "数据源响应过大".equals(message)) {
      return message;
    }
    if (message != null && message.matches("数据源返回 HTTP \\d{3}")) {
      return message;
    }
    return "外部数据源请求失败，请稍后重试";
  }

  static final class PassiveResponseCache {
    private final int maxEntries;
    private final LinkedHashMap<String, CacheEntry> entries =
        new LinkedHashMap<>(16, 0.75f, true);

    PassiveResponseCache(int maxEntries) {
      if (maxEntries < 1) throw new IllegalArgumentException("缓存容量必须大于 0");
      this.maxEntries = maxEntries;
    }

    synchronized String get(String key, long now) {
      CacheEntry cached = entries.get(key);
      if (cached == null) return null;
      if (cached.expiresAt() <= now) {
        entries.remove(key);
        return null;
      }
      return cached.body();
    }

    synchronized void put(String key, String body, long expiresAt, long now) {
      entries.entrySet().removeIf(entry -> entry.getValue().expiresAt() <= now);
      entries.put(key, new CacheEntry(body, expiresAt));
      while (entries.size() > maxEntries) {
        String eldest = entries.keySet().iterator().next();
        entries.remove(eldest);
      }
    }

    synchronized int size() {
      return entries.size();
    }
  }

  private record ReconSnapshot(
      Map<String, Object> dnsRecords,
      Map<String, Object> ipInformation,
      Map<String, Object> tlsInformation,
      Map<String, Object> httpInformation,
      Set<String> subdomains,
      Map<String, Object> networkInformation,
      Map<String, Object> registrationInformation,
      Map<String, Object> geolocationInformation) {}

  private record CacheEntry(String body, long expiresAt) {}

  private record HttpEndpoint(String scheme, int port) {}

  @FunctionalInterface
  private interface CheckedMapSupplier {
    Map<String, Object> get() throws Exception;
  }

  public record IcpBatchRequest(
      @NotEmpty(message = "目标 ID 列表不能为空") List<@NotNull(message = "目标 ID 不能为空") Long> targetIds) {}

  public record IcpResult(
      Long targetId, String domain, String status, String reason, Map<String, Object> data) {}
}
