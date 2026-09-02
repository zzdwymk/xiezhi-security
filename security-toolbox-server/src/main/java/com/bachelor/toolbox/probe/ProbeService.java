package com.bachelor.toolbox.probe;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.fingerprint.FaviconHashUtil;
import com.bachelor.toolbox.fingerprint.FingerprintMatcher;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.net.ssl.SSLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class ProbeService {
  private static final Logger log = LoggerFactory.getLogger(ProbeService.class);
  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(8);
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);
  private static final String USER_AGENT = "Xiezhi-Probe/1.0";
  private static final Pageable HISTORY_PAGE = PageRequest.of(0, 1_000);

  private final ProbeResultRepository results;
  private final AssessmentProjectRepository projects;
  private final ProjectTargetRepository projectTargets;
  private final AuthorizedTargetRepository targets;
  private final TargetService targetService;
  private final FingerprintMatcher fingerprints;
  private final ObjectMapper mapper;

  public ProbeService(
      ProbeResultRepository results,
      AssessmentProjectRepository projects,
      ProjectTargetRepository projectTargets,
      AuthorizedTargetRepository targets,
      TargetService targetService,
      FingerprintMatcher fingerprints,
      ObjectMapper mapper) {
    this.results = results;
    this.projects = projects;
    this.projectTargets = projectTargets;
    this.targets = targets;
    this.targetService = targetService;
    this.fingerprints = fingerprints;
    this.mapper = mapper;
  }

  public ProbeResult probe(ProbeRequest request) {
    validateRequest(request);

    AssessmentProject project = findProject(request.getProjectId());
    validateProjectAuthorization(project);
    validateProjectTarget(request.getProjectId(), request.getTargetId());

    AuthorizedTarget target = targetService.getCurrentlyAuthorized(request.getTargetId(), request.getProjectId());
    List<PreparedProbe> probeCandidates = prepareProbeCandidates(request, target);

    IOException lastIoException = null;
    PreparedProbe lastAttemptedProbe = probeCandidates.get(0);

    for (PreparedProbe preparedProbe : probeCandidates) {
      lastAttemptedProbe = preparedProbe;
      try {
        HttpResponse<String> response = send(preparedProbe.uri());
        ProbeResult result = buildResult(request, preparedProbe.url(), response);
        return results.save(result);
      } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
        throw new IllegalStateException("探测任务已中断", exception);
      } catch (IOException exception) {
        lastIoException = exception;
        log.info(
            "目标探测尝试失败，正在尝试备选协议/URL，candidate={}",
            preparedProbe.url());
      }
    }

    if (lastIoException != null) {
      log.warn(
          "目标探测网络请求最终失败，projectId={}，targetId={}",
          request.getProjectId(),
          request.getTargetId(),
          lastIoException);
      return saveUnavailable(request, lastAttemptedProbe.url(), friendlyNetworkError(lastIoException));
    }

    throw new IllegalStateException("探测失败，未找到可探测地址");
  }

  public List<ProbeResult> history(Long projectId, Long targetId) {
    return results.findByProjectIdAndTargetIdOrderByDetectedAtDescIdDesc(
        projectId, targetId, HISTORY_PAGE);
  }

  public List<ProbeResult> history(Long projectId) {
    return results.findByProjectIdOrderByDetectedAtDescIdDesc(projectId, HISTORY_PAGE);
  }

  private void validateRequest(ProbeRequest request) {
    if (request.getProjectId() == null || request.getTargetId() == null) {
      throw new IllegalArgumentException("项目 ID 和目标 ID 不能为空");
    }
  }

  private AssessmentProject findProject(Long projectId) {
    return projects.findById(projectId).orElseThrow(() -> new IllegalArgumentException("未找到项目"));
  }

  private void validateProjectAuthorization(AssessmentProject project) {
    Instant now = Instant.now();
    boolean authorizationInactive =
        !"ACTIVE".equalsIgnoreCase(project.getStatus())
            || now.isBefore(project.getAuthorizationValidFrom())
            || now.isAfter(project.getAuthorizationExpiresAt());
    if (authorizationInactive) {
      throw new ApiException("项目授权已过期或尚未生效");
    }
  }

  private void validateProjectTarget(Long projectId, Long targetId) {
    projectTargets
        .findByProjectIdAndTargetId(projectId, targetId)
        .orElseThrow(() -> new IllegalArgumentException("目标不属于当前项目"));
  }

  private List<PreparedProbe> prepareProbeCandidates(ProbeRequest request, AuthorizedTarget target) {
    String requestedUrl =
        request.getUrl() != null && !request.getUrl().isBlank()
            ? request.getUrl()
            : target.getTargetValue();
    String authorizedUrl = withDefaultHttpScheme(target.getTargetValue());
    URI authorizedUri = parseHttpUri(authorizedUrl, "授权目标无效");

    boolean explicitScheme = requestedUrl.matches("(?i)^https?://.*");
    List<String> rawUrls = new java.util.ArrayList<>();
    if (explicitScheme) {
      rawUrls.add(requestedUrl);
    } else {
      rawUrls.add("http://" + requestedUrl);
      rawUrls.add("https://" + requestedUrl);
    }

    List<PreparedProbe> candidates = new java.util.ArrayList<>();
    IllegalArgumentException lastValidationException = null;

    for (String rawUrl : rawUrls) {
      try {
        URI probeUri = parseHttpUri(rawUrl, "探测 URL 无效");
        validateAuthorizedHost(probeUri, authorizedUri);
        validateAuthorizedPort(probeUri, target.getAllowedPorts());
        candidates.add(new PreparedProbe(rawUrl, probeUri));
      } catch (IllegalArgumentException ex) {
        lastValidationException = ex;
      }
    }

    if (candidates.isEmpty()) {
      if (lastValidationException != null) {
        throw lastValidationException;
      }
      throw new IllegalArgumentException("探测 URL 超出授权目标或端口范围");
    }

    return candidates;
  }

  private String withDefaultHttpScheme(String url) {
    return url.matches("(?i)^https?://.*") ? url : "http://" + url;
  }

  private URI parseHttpUri(String value, String errorMessage) {
    try {
      URI uri = URI.create(value);
      if (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme())) {
        throw new IllegalArgumentException(errorMessage);
      }
      return uri;
    } catch (Exception exception) {
      throw new IllegalArgumentException(errorMessage, exception);
    }
  }

  private void validateAuthorizedHost(URI probeUri, URI authorizedUri) {
    if (probeUri.getHost() == null
        || authorizedUri.getHost() == null
        || !probeUri.getHost().equalsIgnoreCase(authorizedUri.getHost())) {
      throw new IllegalArgumentException("探测 URL 必须与授权目标使用相同主机");
    }
  }

  private void validateAuthorizedPort(URI probeUri, String allowedPorts) {
    int port =
        probeUri.getPort() > 0
            ? probeUri.getPort()
            : ("https".equalsIgnoreCase(probeUri.getScheme()) ? 443 : 80);
    if (!allowedPort(allowedPorts, port)) {
      throw new IllegalArgumentException("探测端口超出授权端口范围");
    }
  }

  private boolean allowedPort(String specification, int port) {
    if (specification == null) {
      return false;
    }

    for (String token : specification.split(",")) {
      String value = token.trim();
      try {
        if (value.contains("-")) {
          String[] range = value.split("-", 2);
          int start = Integer.parseInt(range[0].trim());
          int end = Integer.parseInt(range[1].trim());
          if (port >= start && port <= end) {
            return true;
          }
        } else if (port == Integer.parseInt(value)) {
          return true;
        }
      } catch (NumberFormatException ignored) {
        // 无效端口配置不能扩大授权范围。
      }
    }
    return false;
  }

  private HttpResponse<String> send(URI uri) throws IOException, InterruptedException {
    HttpClient client =
        HttpClient.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT)
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    HttpRequest request =
        HttpRequest.newBuilder(uri)
            .timeout(REQUEST_TIMEOUT)
            .header("User-Agent", USER_AGENT)
            .GET()
            .build();
    return client.send(request, HttpResponse.BodyHandlers.ofString());
  }

  private static final Pattern FAVICON_LINK =
      Pattern.compile("(?i)<link[^>]+rel=[\"']?(?:shortcut\\s+)?icon[\"']?[^>]+href=[\"']?([^\"'>\\s]+)[\"']?");

  private ProbeResult buildResult(ProbeRequest request, String url, HttpResponse<String> response)
      throws IOException {
    Map<String, List<String>> headers = response.headers().map();
    String server = firstHeader(headers, "server");

    // 智能提取 Favicon 并计算 MurmurHash3 与 MD5（EHole/FOFA 标准）
    FaviconData favicon = fetchFavicon(url, response.body());
    var fingerprintResult =
        fingerprints.match(
            headers,
            response.body(),
            favicon.murmurHash(),
            favicon.md5());

    String technologies =
        fingerprintResult.matches().stream()
            .map(FingerprintMatcher.Match::name)
            .distinct()
            .reduce((left, right) -> left + ", " + right)
            .orElse("");
    String framework =
        fingerprintResult.matches().stream()
            .filter(match -> "FRAMEWORK".equals(match.category()))
            .map(FingerprintMatcher.Match::name)
            .findFirst()
            .orElse("");

    Map<String, Object> evidenceMap = new java.util.LinkedHashMap<>();
    evidenceMap.put("status", response.statusCode());
    evidenceMap.put("title", fingerprintResult.title());
    evidenceMap.put("headers", headers.keySet());
    if (!favicon.murmurHash().isEmpty()) {
      evidenceMap.put("faviconHash", favicon.murmurHash());
    }
    if (!favicon.md5().isEmpty()) {
      evidenceMap.put("faviconMd5", favicon.md5());
    }
    evidenceMap.put("fingerprints", fingerprintResult.matches());
    evidenceMap.put("ruleCatalog", fingerprintResult.catalog());

    String evidence = mapper.writeValueAsString(evidenceMap);

    ProbeResult result = new ProbeResult();
    result.setProjectId(request.getProjectId());
    result.setTargetId(request.getTargetId());
    result.setUrl(url);
    result.setServer(server);
    result.setFramework(framework);
    result.setTechnologies(technologies);
    result.setWaf(detectWaf(headers, response.body()));
    result.setEvidence(evidence);
    return result;
  }

  private FaviconData fetchFavicon(String pageUrl, String htmlBody) {
    try {
      URI baseUri = URI.create(pageUrl);
      String iconHref = extractFaviconHref(htmlBody);
      URI iconUri;
      if (iconHref != null && !iconHref.isBlank()) {
        iconUri = baseUri.resolve(iconHref);
      } else {
        iconUri = baseUri.resolve("/favicon.ico");
      }

      // 仅允许探测同一主机的 Favicon，避免 SSRF 或越界
      if (iconUri.getHost() == null || !iconUri.getHost().equalsIgnoreCase(baseUri.getHost())) {
        return new FaviconData("", "");
      }

      HttpClient client =
          HttpClient.newBuilder()
              .connectTimeout(Duration.ofSeconds(4))
              .version(HttpClient.Version.HTTP_1_1)
              .followRedirects(HttpClient.Redirect.NORMAL)
              .build();
      HttpRequest iconRequest =
          HttpRequest.newBuilder(iconUri)
              .timeout(Duration.ofSeconds(6))
              .header("User-Agent", USER_AGENT)
              .GET()
              .build();

      HttpResponse<byte[]> iconResponse = client.send(iconRequest, HttpResponse.BodyHandlers.ofByteArray());
      if (iconResponse.statusCode() == 200 && iconResponse.body() != null && iconResponse.body().length > 0) {
        byte[] bytes = iconResponse.body();
        // 限制 Favicon 大小为 512KB 以内
        if (bytes.length <= 512 * 1024) {
          String murmur = FaviconHashUtil.calculateMurmur3(bytes);
          String md5 = FaviconHashUtil.calculateMd5(bytes);
          return new FaviconData(murmur, md5);
        }
      }
    } catch (Exception ex) {
      log.debug("Favicon 抓取失败或不存在，url={}", pageUrl, ex);
    }
    return new FaviconData("", "");
  }

  private String extractFaviconHref(String html) {
    if (html == null || html.isBlank()) return null;
    java.util.regex.Matcher m = FAVICON_LINK.matcher(html);
    if (m.find()) {
      return m.group(1).trim();
    }
    return null;
  }

  private record FaviconData(String murmurHash, String md5) {}

  private ProbeResult saveUnavailable(ProbeRequest request, String url, String reason) {
    ProbeResult result = new ProbeResult();
    result.setProjectId(request.getProjectId());
    result.setTargetId(request.getTargetId());
    result.setUrl(url);
    result.setServer("");
    result.setFramework("");
    result.setTechnologies("");
    result.setWaf("未识别");
    try {
      result.setEvidence(
          mapper.writeValueAsString(
              Map.of(
                  "status", "UNAVAILABLE",
                  "reason", reason,
                  "url", url)));
    } catch (Exception ignored) {
      result.setEvidence("{\"status\":\"UNAVAILABLE\",\"reason\":\"探测服务暂不可用\"}");
    }
    return results.save(result);
  }

  private String friendlyNetworkError(Exception error) {
    for (Throwable cause = error; cause != null; cause = cause.getCause()) {
      if (cause instanceof UnknownHostException) {
        return "域名无法解析";
      }
      if (cause instanceof HttpTimeoutException || cause instanceof SocketTimeoutException) {
        return "连接或读取超时";
      }
      if (cause instanceof ConnectException) {
        return "连接被拒绝：目标服务未启动或端口未开放";
      }
      if (cause instanceof SSLException) {
        return "TLS 握手失败";
      }
    }
    return "网络请求失败，请检查目标地址和网络状态";
  }

  private String firstHeader(Map<String, List<String>> headers, String name) {
    return headers.getOrDefault(name, List.of("")).stream().findFirst().orElse("");
  }

  private String detectWaf(Map<String, List<String>> headers, String body) {
    String evidence = headers.toString().toLowerCase() + body.toLowerCase();
    if (evidence.contains("cloudflare")) {
      return "Cloudflare";
    }
    if (evidence.contains("akamai")) {
      return "Akamai";
    }
    if (evidence.contains("sucuri")) {
      return "Sucuri";
    }
    if (evidence.contains("awswaf") || evidence.contains("aws waf")) {
      return "AWS WAF";
    }
    return "未识别";
  }

  private record PreparedProbe(String url, URI uri) {}
}
