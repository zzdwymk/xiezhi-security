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

  /** Starts (or continues) the spider for the target and returns the spider task id. */
  String startSpider(URI target) throws Exception;

  /** Polls the spider progress; returns percentage 0..100. */
  int spiderProgress(String taskId) throws Exception;

  /** Cancels the running spider. */
  void stopSpider(String taskId) throws Exception;

  /** Starts the active scan policy on the target; returns the ascan id. */
  String startActiveScan(URI target) throws Exception;

  /** Polls the active scan progress; returns percentage 0..100. */
  int activeScanProgress(String scanId) throws Exception;

  /** Stops the running active scan. */
  void stopActiveScan(String scanId) throws Exception;

  /** Returns all alerts in the current session as normalized records. */
  List<ZapAlert> alerts() throws Exception;

  /** Immediately terminates the daemon process (used on cancellation / error). */
  void kill() throws Exception;

  record ZapAlert(String url, String name, String risk, String confidence, String cweId, String description) {}
}