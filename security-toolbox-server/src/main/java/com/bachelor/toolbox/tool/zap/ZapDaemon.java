package com.bachelor.toolbox.tool.zap;

import com.bachelor.toolbox.common.ApiException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

/**
 * Abstraction over an OWASP ZAP daemon (headless proxy/SAST engine). Concrete implementations
 * drive a real ZAP process over its JSON REST API; tests substitute a stub. Keeping a thin
 * interface lets {@code ZapScanTool} stay testable without a heavyweight ZAP install.
 *
 * <p>All methods speak in ZAP domain concepts: a scan is bound to one caller-chosen "context",
 * progress is reported as a native 0-100 percentage, and results arrive as normalized alerts.
 */
public interface ZapDaemon extends AutoCloseable {

  /**
   * Whether the underlying daemon is reachable and ready to accept scans (REST reachable).
   */
  boolean isReady();

  /**
   * Starts the daemon if not already running. Returns after the REST endpoint responds or the
   * configured startup window elapses.
   */
  void start() throws Exception;

  /**
   * Sends the authorized target's origin into ZAP as an "in scope" node so that spider and the
   * active scanner only act on it.
   */
  void includeInScope(URI target) throws Exception;

  /** Fetches only the selected URL into the Sites tree, without following redirects. */
  default void accessUrl(URI target) throws Exception {}

  /** Starts the spider (crawler) for the target and returns the spider task id. */
  String startSpider(URI target) throws Exception;

  /**
   * Rooster AJAX spider for modern/SPA targets. The default is a no-op and returns immediately
   * (no AJAX scanning); implementations that support the ZAP {@code ajaxSpider} view (such as
   * {@link LocalZapDaemon}) override to actually drive it. AJAX spiders have no scalar completion,
   * so callers poll state via {@link #ajaxSpiderState()}.
   */
  default void startAjaxSpider(URI target) throws Exception {}

  /** Returns a textual AJAX-spider progress/state marker (e.g. "running"/"stopped"/"number=.."). */
  default String ajaxSpiderState() throws Exception {
    return "notSupported";
  }

  /**
   * Sends one literal field mutation through ZAP's core sendRequest API and returns a local receipt
   * id only after a response is received. This is not the GUI fuzzer add-on or a payload generator.
   */
  default String startFuzz(FuzzSpec spec) throws Exception {
    throw new ApiException("当前 ZAP 适配器不支持单次参数变异请求");
  }

  /** Polls passive processing for a known request receipt; unknown/error status must throw. */
  default String fuzzStatus(String fuzzId) throws Exception {
    throw new ApiException("当前 ZAP 适配器不支持参数变异状态查询");
  }

  /** Remaining passive checks. An unavailable/invalid status must not mean completion. */
  default long passiveScanRemaining() throws Exception {
    throw new ApiException("无法读取 ZAP 检测进度，不能确认检测是否完成");
  }

  /** Bounded single-request mutation. Payload is always literal text, never a file or script. */
  record FuzzSpec(
      URI target,
      String requestUrl,
      String method,
      String postBody,
      String payload,
      String targetField) {
    public FuzzSpec {
      if (target == null || requestUrl == null || requestUrl.isBlank() || requestUrl.length() > 2000) {
        throw new ApiException("fuzzRequestUrl 必须是 1–2000 字符的授权 HTTP URL");
      }
      URI request;
      try { request = URI.create(requestUrl); }
      catch (IllegalArgumentException ex) { throw new ApiException("fuzzRequestUrl 格式不正确"); }
      if (!httpUri(target) || !httpUri(request)
          || !request.getHost().equalsIgnoreCase(target.getHost())
          || effectivePort(request) != effectivePort(target)) {
        throw new ApiException("参数变异请求必须使用已授权的 HTTP 主机和端口");
      }
      if (method == null) method = "POST";
      if (!Set.of("GET", "POST").contains(method)) {
        throw new ApiException("method 仅支持 GET 或 POST");
      }
      if (postBody == null) postBody = "";
      if (postBody.length() > 4000 || postBody.chars().anyMatch(Character::isISOControl)
          || ("GET".equals(method) && !postBody.isEmpty())) {
        throw new ApiException("fuzzPostBody 最多 4000 字符，GET 请求不能包含表单正文");
      }
      if (payload == null || payload.isEmpty() || payload.length() > 1000
          || payload.chars().anyMatch(Character::isISOControl)) {
        throw new ApiException("fuzzPayload 必须是 1–1000 字符的单个字面值");
      }
      if (targetField == null || targetField.isBlank() || targetField.length() > 128
          || targetField.chars().anyMatch(Character::isISOControl)) {
        throw new ApiException("fuzzTargetField 必须是 1–128 字符的字段名且不能包含控制字符");
      }
    }

    /** Builds exactly one GET query or POST form mutation, preserving all unrelated fields. */
    public String requestMessage() {
      URI uri = URI.create(requestUrl);
      String url = uri.toASCIIString();
      String body = "";
      if ("GET".equals(method)) {
        String query = replaceField(uri.getRawQuery());
        url = URI.create(url.substring(0, url.indexOf('?')) + "?" + query).toASCIIString();
      } else {
        body = replaceField(postBody);
      }
      String headers = method + " " + url + " HTTP/1.1\r\nHost: " + uri.getRawAuthority()
          + "\r\nConnection: close\r\n";
      if ("POST".equals(method)) {
        headers += "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
            + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n";
      }
      return headers + "\r\n" + body;
    }

    private String replaceField(String form) {
      if (form == null || form.isEmpty() || form.chars().anyMatch(Character::isISOControl)) {
        throw new ApiException("指定的查询或表单中没有可变异字段");
      }
      String[] fields = form.split("&", -1);
      int matches = 0;
      for (int i = 0; i < fields.length; i++) {
        String[] pair = fields[i].split("=", 2);
        try {
          String name = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
          if (pair.length == 2) URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
          if (name.equals(targetField)) {
            matches++;
            fields[i] = pair[0] + "=" + URLEncoder.encode(payload, StandardCharsets.UTF_8);
          }
        } catch (IllegalArgumentException ex) {
          throw new ApiException("查询或表单必须使用合法的 URL 编码");
        }
      }
      if (matches != 1) {
        throw new ApiException("fuzzTargetField 必须在选定查询或表单中恰好出现一次");
      }
      return String.join("&", fields);
    }

    private static boolean httpUri(URI uri) {
      return uri.getHost() != null && uri.getRawUserInfo() == null && uri.getRawFragment() == null
          && ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
          && (uri.getPort() == -1 || (uri.getPort() > 0 && uri.getPort() <= 65535));
    }

    private static int effectivePort(URI uri) {
      return uri.getPort() > 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
    }
  }

  /** Polls the spider progress; returns percentage 0..100. */
  int spiderProgress(String taskId) throws Exception;

  /** Cancels the running spider. */
  void stopSpider(String taskId) throws Exception;

  /** Starts the active scan policy on the target; returns the ascan id. */
  String startActiveScan(URI target) throws Exception;

  /**
   * Starts the active scan on the target using a named ZAP scan policy. Default delegates to {@link
   * #startActiveScan(URI)}; implementations that support the ZAP {@code ascan/action/scan}
   * {@code scanPolicyName} option (such as {@link LocalZapDaemon}) override to honour it.
   *
   * @param scanPolicyName the ZAP scan policy name (e.g. "Default Policy"), or {@code null} to use
   *     ZAP's default behaviour.
   */
  default String startActiveScan(URI target, String scanPolicyName) throws Exception {
    return startActiveScan(target);
  }

  /** Applies the requested strength and limits recursion to the chosen crawl scope. */
  default String startActiveScan(URI target, String scanPolicyName, String strength, boolean recurse)
      throws Exception {
    return startActiveScan(target, scanPolicyName);
  }

  /** Polls the active scan progress; returns percentage 0..100. */
  int activeScanProgress(String scanId) throws Exception;

  /** Optional diagnostics only; null does not mean the scan failed or completed. */
  default ScanActivity activeScanActivity(String scanId) { return null; }

  record ScanActivity(Long requestCount, List<String> runningRules, String state) {}

  /** Stops the running active scan. */
  void stopActiveScan(String scanId) throws Exception;

  /** Returns all alerts in the current session as normalized records. */
  List<ZapAlert> alerts() throws Exception;

  /**
   * 读取当前会话爬到的 URL 清单（sites）。返回绝对 URL 字符串或相对路径；实现支持 ZAP 的
   * {@code core/view/sites} 视图返回全量 URL，否则返回空列表。供“ZAP 爬虫结果回填资产/资源发现”。
   */
  default List<String> crawlResults(URI target) throws Exception {
    return List.of();
  }

  /**
   * 读取 ZAP 识别到的目标技术栈（框架/服务/语言等）。ZAP 具体版本对“技术指纹”REST 支持不一，
   * 实现尽力探测，失败或空时返回空列表，不影响主扫描流程。
   */
  default List<String> technologies(URI target) throws Exception {
    return List.of();
  }

  /**
   * 导入 OpenAPI/Swagger 定义并纳入扫描范围（{@code openapi/action/importUrl}）。成功返回 true；
   * 实现不支持或失败返回 false，由调用方降级为普通目标扫描。
   */
  default boolean importOpenApi(String specUrl) throws Exception {
    return false;
  }

  /** 立即终止 daemon 进程（用于取消/出错）。 */
  void kill() throws Exception;

  /**
   * Configures form-based authentication so the daemon can log into the target before crawling and
   * scanning. {@link #includeInScope} and this method share a context, so the authenticated session
   * applies only to in-scope traffic. Default is a no-op so unauthenticated installs keep working.
   */
  default void configureFormAuthentication(FormAuthSpec spec) throws Exception {}

  /** 凭据与表单字段、认证方式。authType 支持 form/cookie(脚本式凭据可延展)。 */
  record FormAuthSpec(
      String contextName,
      String loginPageUrl,
      String loginRequestUrl,
      String usernameField,
      String passwordField,
      String postData,
      String authType) {

    FormAuthSpec(
        String contextName,
        String loginPageUrl,
        String loginRequestUrl,
        String usernameField,
        String passwordField,
        String postData) {
      this(contextName, loginPageUrl, loginRequestUrl, usernameField, passwordField, postData, "form");
    }
  }

  record ZapAlert(
      String url,
      String name,
      String risk,
      String confidence,
      String cweId,
      String description,
      int sourceId) {}
}
