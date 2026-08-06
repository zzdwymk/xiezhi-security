package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class HttpSecurityCheckTool implements SecurityTool {
  private static final String TEST_ORIGIN = "https://security-toolbox.invalid";
  private static final Set<String> SUPPORTED_CHECKS =
      Set.of("cookies", "cors", "methods", "disclosure");
  private static final Pattern SENSITIVE_COOKIE_NAME =
      Pattern.compile(
          "(?i).*(session|sess|sid|auth|token|jwt|remember|login|jsessionid|phpsessid|asp[.]net_sessionid).*");
  private static final Map<String, String> DISCLOSURE_HEADERS =
      Map.of(
          "server", "Web 服务器",
          "x-powered-by", "应用技术栈",
          "x-aspnet-version", "ASP.NET 版本",
          "x-aspnetmvc-version", "ASP.NET MVC 版本",
          "x-runtime", "运行时",
          "x-generator", "内容生成器");

  private final TargetPolicyService policyService;
  private final HttpClient httpClient =
      HttpClient.newBuilder()
          .connectTimeout(Duration.ofSeconds(5))
          .followRedirects(HttpClient.Redirect.NEVER)
          .build();

  public HttpSecurityCheckTool(TargetPolicyService policyService) {
    this.policyService = policyService;
  }

  @Override
  public String code() {
    return "http_security_check";
  }

  @Override
  public String displayName() {
    return "HTTP 常见漏洞检查";
  }

  @Override
  public String description() {
    return "检查 Cookie、CORS、危险 HTTP 方法和技术栈信息泄露";
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
    String check = validateCheck(parameters);
    URI uri = policyService.validatedHttpUri(target);
    HttpRequest.Builder request =
        HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(10))
            .header("User-Agent", "Xiezhi-Authorized-Security/0.2");
    if ("cors".equals(check)) {
      request.header("Origin", TEST_ORIGIN).GET();
    } else if ("methods".equals(check)) {
      request.method("OPTIONS", HttpRequest.BodyPublishers.noBody());
    } else {
      request.GET();
    }
    String method = "methods".equals(check) ? "OPTIONS" : "GET";
    observer.operation(
        "HTTP "
            + method
            + " "
            + uri
            + ("cors".equals(check) ? " Origin=" + TEST_ORIGIN : "")
            + " check="
            + check);

    observer.progress(0, 2, "正在执行 " + checkName(check));
    HttpResponse<Void> response =
        httpClient.send(request.build(), HttpResponse.BodyHandlers.discarding());
    observer.progress(1, 2, "已收到 HTTP 响应，正在分析 " + checkName(check));
    List<FindingDraft> findings =
        switch (check) {
          case "cookies" -> analyzeCookies(uri, response.headers());
          case "cors" -> analyzeCors(response.headers(), TEST_ORIGIN);
          case "methods" -> analyzeMethods(response.headers());
          case "disclosure" -> analyzeDisclosure(response.headers());
          default -> throw new ApiException("不支持的 HTTP 检查类型");
        };
    observer.progress(2, 2, checkName(check) + "完成");

    Map<String, Object> data = new LinkedHashMap<>();
    data.put("url", uri.toString());
    data.put("check", check);
    data.put("status", response.statusCode());
    data.put("headers", sanitizedHeaders(response.headers()));
    return new ToolExecutionResult(
        "HTTP "
            + response.statusCode()
            + "，"
            + checkName(check)
            + "发现 "
            + findings.size()
            + " 项潜在问题",
        data,
        findings);
  }

  List<FindingDraft> analyzeCookies(URI uri, HttpHeaders headers) {
    List<FindingDraft> findings = new ArrayList<>();
    for (String rawCookie : headers.allValues("set-cookie")) {
      String name = cookieName(rawCookie);
      if (name.isBlank() || !SENSITIVE_COOKIE_NAME.matcher(name).matches()) continue;
      List<String> missing = new ArrayList<>();
      boolean secure = hasCookieAttribute(rawCookie, "secure");
      boolean httpOnly = hasCookieAttribute(rawCookie, "httponly");
      String sameSite = cookieAttributeValue(rawCookie, "samesite");
      if (!secure) missing.add("Secure");
      if (!httpOnly) missing.add("HttpOnly");
      if (sameSite == null) missing.add("SameSite");
      boolean noneWithoutSecure = "none".equalsIgnoreCase(sameSite) && !secure;
      if (missing.isEmpty() && !noneWithoutSecure) continue;
      String evidence =
          "cookie="
              + name
              + "; missing="
              + String.join(",", missing)
              + (noneWithoutSecure ? "; SameSite=None without Secure" : "")
              + "; scheme="
              + uri.getScheme();
      findings.add(
          new FindingDraft(
              "敏感 Cookie 缺少安全属性: " + name,
              missing.contains("Secure") || missing.contains("HttpOnly") ? "MEDIUM" : "LOW",
              "疑似会话或认证 Cookie 未完整启用浏览器安全属性，可能增加会话泄露或跨站请求风险。",
              evidence,
              "全站使用 HTTPS，并为敏感 Cookie 设置 Secure、HttpOnly 和符合业务需求的 SameSite 属性。"));
    }
    return findings;
  }

  List<FindingDraft> analyzeCors(HttpHeaders headers, String origin) {
    String allowedOrigin = headers.firstValue("access-control-allow-origin").orElse("").trim();
    if (allowedOrigin.isBlank()) return List.of();
    boolean credentials =
        headers
            .firstValue("access-control-allow-credentials")
            .map(value -> "true".equalsIgnoreCase(value.trim()))
            .orElse(false);
    if (allowedOrigin.equalsIgnoreCase(origin)) {
      return List.of(
          new FindingDraft(
              "CORS 可能反射任意来源",
              credentials ? "HIGH" : "MEDIUM",
              "服务将测试用的非可信 Origin 原样加入允许来源，跨站页面可能读取接口响应。",
              "Origin="
                  + origin
                  + "; Access-Control-Allow-Origin="
                  + allowedOrigin
                  + "; credentials="
                  + credentials,
              "使用固定来源白名单进行精确匹配；涉及凭据时禁止动态反射 Origin，并复核敏感接口的跨域策略。"));
    }
    if ("*".equals(allowedOrigin)) {
      return List.of(
          new FindingDraft(
              "CORS 允许任意来源",
              "LOW",
              "服务返回 Access-Control-Allow-Origin: *，任何站点都可发起跨域读取；公开 API 除外需确认是否符合设计。",
              "Access-Control-Allow-Origin=*; credentials=" + credentials,
              "若接口并非完全公开，请改用最小化的可信来源白名单，并避免对敏感响应开放跨域读取。"));
    }
    return List.of();
  }

  List<FindingDraft> analyzeMethods(HttpHeaders headers) {
    Set<String> methods = new LinkedHashSet<>();
    headers.allValues("allow").stream()
        .flatMap(value -> Arrays.stream(value.split("[,\\s]+")))
        .map(value -> value.trim().toUpperCase(Locale.ROOT))
        .filter(value -> !value.isBlank())
        .forEach(methods::add);
    List<String> dangerous =
        methods.stream().filter(Set.of("TRACE", "TRACK", "CONNECT")::contains).toList();
    if (dangerous.isEmpty()) return List.of();
    return List.of(
        new FindingDraft(
            "危险 HTTP 方法已启用",
            dangerous.contains("CONNECT") ? "HIGH" : "MEDIUM",
            "OPTIONS 响应声明支持通常不应对普通 Web 端点开放的 HTTP 方法，可能扩大代理滥用或请求回显风险。",
            "Allow=" + String.join(",", methods) + "; dangerous=" + String.join(",", dangerous),
            "在 Web 服务器、反向代理和应用路由中禁用不需要的 TRACE、TRACK、CONNECT 方法。"));
  }

  List<FindingDraft> analyzeDisclosure(HttpHeaders headers) {
    Map<String, String> exposed = new LinkedHashMap<>();
    DISCLOSURE_HEADERS.forEach(
        (header, label) ->
            headers
                .firstValue(header)
                .filter(value -> !value.isBlank())
                .ifPresent(value -> exposed.put(header, value.trim())));
    if (exposed.isEmpty()) return List.of();
    return List.of(
        new FindingDraft(
            "HTTP 响应泄露服务技术栈信息",
            "LOW",
            "响应头公开了服务器或应用技术栈信息，可能帮助攻击者进行组件识别和漏洞关联。",
            exposed.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .reduce((a, b) -> a + "; " + b)
                .orElse(""),
            "移除或泛化 Server、X-Powered-By、X-AspNet-Version 等非必要响应头，并通过补丁管理降低组件识别后的风险。"));
  }

  private String validateCheck(Map<String, Object> parameters) {
    if (parameters == null || parameters.size() != 1 || !parameters.containsKey("check")) {
      throw new ApiException("HTTP 漏洞检查要求且仅允许 check 参数");
    }
    String check = Objects.toString(parameters.get("check"), "").trim().toLowerCase(Locale.ROOT);
    if (!SUPPORTED_CHECKS.contains(check)) throw new ApiException("不支持的 HTTP 检查类型: " + check);
    return check;
  }

  private Map<String, List<String>> sanitizedHeaders(HttpHeaders headers) {
    Map<String, List<String>> sanitized = new LinkedHashMap<>();
    headers
        .map()
        .forEach(
            (name, values) -> {
              if ("set-cookie".equalsIgnoreCase(name)) {
                sanitized.put(name, values.stream().map(this::redactCookieValue).toList());
              } else {
                sanitized.put(name, values);
              }
            });
    return sanitized;
  }

  private String redactCookieValue(String rawCookie) {
    int equals = rawCookie.indexOf('=');
    if (equals < 0) return "<redacted>";
    int semicolon = rawCookie.indexOf(';', equals + 1);
    return rawCookie.substring(0, equals + 1)
        + "<redacted>"
        + (semicolon >= 0 ? rawCookie.substring(semicolon) : "");
  }

  private String cookieName(String rawCookie) {
    int equals = rawCookie.indexOf('=');
    return equals <= 0 ? "" : rawCookie.substring(0, equals).trim();
  }

  private boolean hasCookieAttribute(String rawCookie, String expected) {
    for (String part : rawCookie.split(";")) {
      if (part.trim().equalsIgnoreCase(expected)) return true;
    }
    return false;
  }

  private String cookieAttributeValue(String rawCookie, String expected) {
    for (String part : rawCookie.split(";")) {
      String item = part.trim();
      int equals = item.indexOf('=');
      if (equals > 0 && item.substring(0, equals).trim().equalsIgnoreCase(expected)) {
        return item.substring(equals + 1).trim();
      }
    }
    return null;
  }

  private String checkName(String check) {
    return switch (check) {
      case "cookies" -> "Cookie 安全检查";
      case "cors" -> "CORS 配置检查";
      case "methods" -> "HTTP 方法检查";
      case "disclosure" -> "信息泄露检查";
      default -> check;
    };
  }
}
