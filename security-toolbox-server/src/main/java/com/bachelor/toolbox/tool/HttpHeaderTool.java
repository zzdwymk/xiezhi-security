package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.WebTargetResolver;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import org.springframework.stereotype.Component;

@Component
public class HttpHeaderTool implements SecurityTool {
  private static final Map<String, String> RECOMMENDATIONS =
      Map.of(
          "content-security-policy", "配置与业务匹配的 Content-Security-Policy，限制脚本、样式和资源来源。",
          "x-content-type-options", "设置 X-Content-Type-Options: nosniff。",
          "x-frame-options", "设置 X-Frame-Options 或在 CSP 中配置 frame-ancestors。",
          "referrer-policy", "设置 Referrer-Policy，减少敏感路径和参数泄露。",
          "permissions-policy", "设置 Permissions-Policy，限制非必要浏览器能力。",
          "strict-transport-security",
              "HTTPS 站点设置 Strict-Transport-Security，并在确认所有子域均支持 HTTPS 后考虑 includeSubDomains。");

  private final TargetPolicyService policyService;
  private final HttpClient httpClient =
      HttpClient.newBuilder()
          .connectTimeout(Duration.ofSeconds(5))
          .version(HttpClient.Version.HTTP_1_1)
          // Never follow redirects automatically: a private authorized URL must not
          // be able to redirect the scanner to an unapproved public or metadata host.
          .followRedirects(HttpClient.Redirect.NEVER)
          .build();

  public HttpHeaderTool(TargetPolicyService policyService) {
    this.policyService = policyService;
  }

  @Override
  public String code() {
    return "http_headers";
  }

  @Override
  public String displayName() {
    return "HTTP 安全响应头检查";
  }

  @Override
  public String description() {
    return "检查授权 Web 目标的常见浏览器安全响应头";
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
    String path = java.util.Objects.toString(parameters.getOrDefault("path", ""), "").trim();
    // 优先采用工作流/主动检测预解析出的真实 Web 基址；否则回退到授权目标的默认 http(s) 基址。
    List<URI> bases = WebTargetResolver.basesFromParameters(parameters);
    if (bases.isEmpty()) {
      bases = List.of(policyService.validatedHttpUri(target, path.isBlank() ? null : path));
    }
    List<FindingDraft> findings = new ArrayList<>();
    List<Map<String, Object>> responses = new ArrayList<>();
    int total = 0;
    for (URI base : bases) {
      URI uri = resolverJoin(base, path);
      HttpRequest request =
          HttpRequest.newBuilder(uri)
              .timeout(Duration.ofSeconds(10))
              .header("User-Agent", "Xiezhi-Authorized-Security/0.2")
              .GET()
              .build();
      observer.operation("HTTP GET " + uri + " User-Agent=Xiezhi-Authorized-Security/0.2");
      observer.progress(total, bases.size() * 2, "正在请求授权 HTTP 目标");
      HttpResponse<Void> response =
          httpClient.send(request, HttpResponse.BodyHandlers.discarding());
      total++;
      observer.progress(total * 2, bases.size() * 2, "已收到 HTTP 响应，正在检查安全响应头");

      Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
      headers.putAll(response.headers().map());
      RECOMMENDATIONS.forEach(
          (header, remediation) -> {
            if (header.equals("strict-transport-security")
                && !"https".equalsIgnoreCase(uri.getScheme())) return;
            if (!headers.containsKey(header)) {
              findings.add(
                  new FindingDraft(
                      "缺少安全响应头: " + header,
                      header.equals("content-security-policy") ? "MEDIUM" : "LOW",
                      "响应中未发现 " + header + "，浏览器侧安全防护能力可能不足。",
                      "GET " + uri + " returned HTTP " + response.statusCode(),
                      remediation));
            }
          });
      responses.add(
          Map.of("url", uri.toString(), "status", (Object) response.statusCode(), "headers", headers));
    }
    observer.progress(bases.size() * 2, bases.size() * 2, "HTTP 安全响应头检查完成");

    Map<String, Object> data = new LinkedHashMap<>();
    data.put("urls", responses);
    // 兼容旧形态：单基址时同时暴露 url/status/headers 顶层字段。
    if (!responses.isEmpty()) {
      @SuppressWarnings("unchecked")
      Map<String, Object> first = (Map<String, Object>) responses.get(0);
      data.put("url", first.get("url"));
      data.put("status", first.get("status"));
      data.put("headers", first.get("headers"));
    }

    return new ToolExecutionResult(
        "HTTP 检查完成，" + findings.size() + " 项响应头改进建议",
        data,
        findings);
  }

  private URI resolverJoin(URI base, String path) {
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
}
