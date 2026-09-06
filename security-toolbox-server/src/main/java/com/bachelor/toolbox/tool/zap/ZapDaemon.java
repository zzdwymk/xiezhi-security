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

  /** Immediately terminates the daemon process (used on cancellation / error). */
  void kill() throws Exception;

  /**
   * Configures form-based authentication so the daemon can log into the target before crawling and
   * scanning. {@link #includeInScope} and this method share a context, so the authenticated session
   * applies only to in-scope traffic. Default is a no-op so unauthenticated installs keep working.
   */
  default void configureFormAuthentication(FormAuthSpec spec) throws Exception {}

  /** Credentials and form fields needed for ZAP form-based authentication. */
  record FormAuthSpec(
      String contextName,
      String loginPageUrl,
      String loginRequestUrl,
      String usernameField,
      String passwordField,
      String postData) {}

  record ZapAlert(
      String url,
      String name,
      String risk,
      String confidence,
      String cweId,
      String description,
      int sourceId) {}
}