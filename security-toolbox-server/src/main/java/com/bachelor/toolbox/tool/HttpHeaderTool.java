package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
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
    URI uri = policyService.validatedHttpUri(target);
    HttpRequest request =
        HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(10))
            .header("User-Agent", "Xiezhi-Authorized-Security/0.2")
            .GET()
            .build();
    observer.operation("HTTP GET " + uri + " User-Agent=Xiezhi-Authorized-Security/0.2");
    observer.progress(0, 2, "正在请求授权 HTTP 目标");
    HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
    observer.progress(1, 2, "已收到 HTTP 响应，正在检查安全响应头");

    Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    headers.putAll(response.headers().map());
    List<FindingDraft> findings = new ArrayList<>();
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
    observer.progress(2, 2, "HTTP 安全响应头检查完成");

    return new ToolExecutionResult(
        "HTTP " + response.statusCode() + "，发现 " + findings.size() + " 项响应头改进建议",
        Map.of("url", uri.toString(), "status", response.statusCode(), "headers", headers),
        findings);
  }
}
