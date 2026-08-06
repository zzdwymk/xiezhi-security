package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.stereotype.Service;

@Service
public class TrafficCaptureFilterService {
  private static final Set<String> TYPES = Set.of("URL", "DOMAIN", "KEYWORD");

  private final TrafficCaptureFilterRepository repository;
  private final AuditService audit;
  private volatile List<TrafficCaptureFilter> enabledRules = List.of();

  public TrafficCaptureFilterService(
      TrafficCaptureFilterRepository repository, AuditService audit) {
    this.repository = repository;
    this.audit = audit;
  }

  @PostConstruct
  void reload() {
    enabledRules =
        repository.findAllByOrderByCreatedAtAsc().stream()
            .filter(TrafficCaptureFilter::isEnabled)
            .toList();
  }

  public List<TrafficCaptureFilter> list() {
    return repository.findAllByOrderByCreatedAtAsc();
  }

  public TrafficCaptureFilter create(FilterRequest request) {
    TrafficCaptureFilter rule = new TrafficCaptureFilter();
    apply(rule, request);
    TrafficCaptureFilter saved = repository.save(rule);
    reload();
    audit.record(
        "CREATE_TRAFFIC_CAPTURE_FILTER",
        "TRAFFIC_CAPTURE_FILTER",
        saved.getId(),
        saved.getListType() + ":" + saved.getType() + ":" + saved.getPattern(),
        "SUCCESS");
    return saved;
  }

  public TrafficCaptureFilter update(Long id, FilterRequest request) {
    TrafficCaptureFilter rule =
        repository.findById(id).orElseThrow(() -> new ApiException("抓包排除规则不存在"));
    apply(rule, request);
    TrafficCaptureFilter saved = repository.save(rule);
    reload();
    audit.record(
        "UPDATE_TRAFFIC_CAPTURE_FILTER",
        "TRAFFIC_CAPTURE_FILTER",
        saved.getId(),
        saved.getListType()
            + ":"
            + saved.getType()
            + ":"
            + saved.getPattern()
            + ",enabled="
            + saved.isEnabled(),
        "SUCCESS");
    return saved;
  }

  public void delete(Long id) {
    TrafficCaptureFilter rule =
        repository.findById(id).orElseThrow(() -> new ApiException("抓包排除规则不存在"));
    repository.delete(rule);
    reload();
    audit.record(
        "DELETE_TRAFFIC_CAPTURE_FILTER",
        "TRAFFIC_CAPTURE_FILTER",
        id,
        rule.getListType() + ":" + rule.getType() + ":" + rule.getPattern(),
        "SUCCESS");
  }

  public boolean shouldExclude(LocalTrafficProxy.Capture capture) {
    if (enabledRules.isEmpty()) {
      return false;
    }
    String host = normalizeHost(capture.host());
    String url = buildUrl(capture).toLowerCase(Locale.ROOT);
    boolean hasWhitelist = false;
    boolean matchesWhitelist = false;
    for (TrafficCaptureFilter rule : enabledRules) {
      boolean matched = matches(rule, capture, host, url);
      if ("BLACKLIST".equals(rule.getListType()) && matched) {
        return true;
      }
      if ("WHITELIST".equals(rule.getListType())) {
        hasWhitelist = true;
        if (matched) matchesWhitelist = true;
      }
    }
    return hasWhitelist && !matchesWhitelist;
  }

  private void apply(TrafficCaptureFilter rule, FilterRequest request) {
    String type = request.type() == null ? "" : request.type().trim().toUpperCase(Locale.ROOT);
    String listType =
        request.listType() == null
            ? "BLACKLIST"
            : request.listType().trim().toUpperCase(Locale.ROOT);
    String pattern = request.pattern() == null ? "" : request.pattern().trim();
    if (!TYPES.contains(type)) {
      throw new ApiException("抓包匹配类型仅支持 URL、域名或关键词");
    }
    if (!Set.of("BLACKLIST", "WHITELIST").contains(listType)) {
      throw new ApiException("抓包名单类型仅支持黑名单或白名单");
    }
    if (pattern.isBlank()) {
      throw new ApiException("抓包匹配内容不能为空");
    }
    rule.setType(type);
    rule.setListType(listType);
    rule.setPattern(pattern);
    rule.setEnabled(request.enabled() == null || request.enabled());
  }

  private boolean matches(
      TrafficCaptureFilter rule, LocalTrafficProxy.Capture capture, String host, String url) {
    String pattern = rule.getPattern().toLowerCase(Locale.ROOT);
    if ("URL".equals(rule.getType())) {
      return url.contains(pattern);
    }
    if ("DOMAIN".equals(rule.getType())) {
      String domain = normalizeDomain(pattern);
      return !domain.isBlank() && (host.equals(domain) || host.endsWith("." + domain));
    }
    return "KEYWORD".equals(rule.getType()) && containsKeyword(capture, url, pattern);
  }

  private String buildUrl(LocalTrafficProxy.Capture capture) {
    String scheme =
        capture.scheme() == null || capture.scheme().isBlank() ? "http" : capture.scheme();
    String host = capture.host() == null ? "" : capture.host();
    boolean defaultPort =
        ("http".equalsIgnoreCase(scheme) && capture.port() == 80)
            || ("https".equalsIgnoreCase(scheme) && capture.port() == 443);
    String path = capture.path() == null || capture.path().isBlank() ? "/" : capture.path();
    return scheme + "://" + host + (defaultPort ? "" : ":" + capture.port()) + path;
  }

  private boolean containsKeyword(LocalTrafficProxy.Capture capture, String url, String pattern) {
    return contains(capture.protocol(), pattern)
        || contains(capture.method(), pattern)
        || url.contains(pattern)
        || contains(capture.requestHeaders(), pattern)
        || contains(capture.requestBody(), pattern)
        || contains(capture.responseHeaders(), pattern)
        || contains(capture.responseBody(), pattern)
        || contains(capture.contentType(), pattern);
  }

  private boolean contains(String value, String pattern) {
    return value != null && value.toLowerCase(Locale.ROOT).contains(pattern);
  }

  private String normalizeHost(String value) {
    return value == null ? "" : value.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
  }

  private String normalizeDomain(String value) {
    String domain = value.trim().toLowerCase(Locale.ROOT);
    try {
      if (domain.contains("://")) {
        domain = URI.create(domain).getHost();
      }
    } catch (Exception ignored) {
    }
    if (domain == null) {
      return "";
    }
    domain = domain.replaceFirst("^\\*\\.", "");
    int slash = domain.indexOf('/');
    if (slash >= 0) {
      domain = domain.substring(0, slash);
    }
    int colon = domain.lastIndexOf(':');
    if (colon > 0 && domain.indexOf(':') == colon) {
      domain = domain.substring(0, colon);
    }
    return domain.replaceAll("\\.$", "");
  }

  public record FilterRequest(
      @NotBlank(message = "抓包名单类型不能为空")
          @Pattern(regexp = "(?i)BLACKLIST|WHITELIST", message = "抓包名单类型仅支持黑名单或白名单")
          String listType,
      @NotBlank(message = "抓包匹配类型不能为空")
          @Pattern(regexp = "(?i)URL|DOMAIN|KEYWORD", message = "抓包匹配类型仅支持 URL、域名或关键词")
          String type,
      @NotBlank(message = "抓包匹配内容不能为空") @Size(max = 500, message = "抓包匹配内容不能超过 500 个字符")
          String pattern,
      Boolean enabled) {}
}
