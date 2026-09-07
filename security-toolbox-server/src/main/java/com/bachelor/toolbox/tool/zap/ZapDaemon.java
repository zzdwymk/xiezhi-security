package com.bachelor.toolbox.tool.zap;

import java.net.URI;
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
   * Drives the ZAP fuzzer for a single HTTP message against a target, returning a fuzz result id
   * (or a blank string when unsupported). The default is a no-op; implementations that support the
   * ZAP {@code fuzzer/action/scan} API (such as {@link LocalZapDaemon}) override.
   */
  default String startFuzz(FuzzSpec spec) throws Exception {
    return "";
  }

  /** Polls a fuzz run; returns a status marker (e.g. "running"/"stopped"/"number=.."). */
  default String fuzzStatus(String fuzzId) throws Exception {
    return "stopped;number=0";
  }

  /** Parameters for a ZAP fuzzing attempt against an authorized Web target. */
  record FuzzSpec(
      URI target,
      String requestUrl,
      String method,
      String postBody,
      String payload,
      String targetField) {}

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

  /** Polls the active scan progress; returns percentage 0..100. */
  int activeScanProgress(String scanId) throws Exception;

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