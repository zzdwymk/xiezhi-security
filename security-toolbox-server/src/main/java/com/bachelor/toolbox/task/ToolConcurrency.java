package com.bachelor.toolbox.task;

import java.util.Set;

/**
 * How a tool occupies the target it scans, used to decide which tasks may run together.
 *
 * <p>Serial-by-risk was too blunt: an HTTP header probe and a TLS check read one response each and
 * never interfere, yet both were forced to wait behind a full-port Nmap sweep. The real conflict is
 * <em>resource contention on one target</em>, not the risk label:
 *
 * <ul>
 *   <li>{@link #EXCLUSIVE} tools open many connections or sweep the whole port range. While one
 *       runs, it distorts everything else's timing and can trip the target's rate limiting, so it
 *       forms a barrier: nothing else touches the target at the same time.
 *   <li>{@link #LIGHT} tools make a small, bounded number of requests. They can share the target
 *       with each other, but not with an {@code EXCLUSIVE} sweep.
 *   <li>{@link #ATTACK} tools mutate requests or exploit parameters. They stay serial for their own
 *       reasons (approval, state changes) and also act as barriers.
 * </ul>
 *
 * <p>This is a deliberate default, not a hard rule: nothing here widens authorization or skips
 * approval. It only decides batching order.
 */
public final class ToolConcurrency {
  private ToolConcurrency() {}

  /** Resource occupancy class of one tool against one target. */
  public enum Profile {
    /** Full-range or high-connection scans; acts as a barrier. */
    EXCLUSIVE,
    /** Bounded read-only probes; may run alongside other LIGHT work. */
    LIGHT,
    /** Request mutation or exploitation; acts as a barrier. */
    ATTACK
  }

  /**
   * Tools that sweep large port ranges or fan out connections. These distort concurrent timing and
   * can look like a flood to the target, so they never share the target with anything else.
   */
  private static final Set<String> EXCLUSIVE = Set.of(
      "nmap_service_scan",
      "fscan_scan",
      "msf_scan",
      "nuclei_scan",
      "afrog_scan",
      "xray_scan",
      "zap_scan",
      "dir_scan",
      "site_crawl");

  /** Request-mutating tools. Already approval-gated; also barriers so evidence stays attributable. */
  private static final Set<String> ATTACK = Set.of("sqlmap_scan", "zap_fuzz");

  /** Bounded, read-only probes that can safely overlap with one another. */
  private static final Set<String> LIGHT = Set.of(
      "tcp_ports",
      "http_headers",
      "http_security_check",
      "tls_config",
      "retrieve_project_context");

  /**
   * Classify one tool. Unknown tools default to {@link Profile#EXCLUSIVE}: a new tool we have not
   * reasoned about yet must not be treated as safe to run concurrently.
   */
  public static Profile profileOf(String toolCode) {
    String code = toolCode == null ? "" : toolCode.strip();
    if (ATTACK.contains(code)) return Profile.ATTACK;
    if (LIGHT.contains(code)) return Profile.LIGHT;
    if (EXCLUSIVE.contains(code)) return Profile.EXCLUSIVE;
    return Profile.EXCLUSIVE;
  }

  /** Only LIGHT work may batch together; every other profile is its own barrier. */
  public static boolean canRunConcurrently(String leftTool, String rightTool) {
    return profileOf(leftTool) == Profile.LIGHT && profileOf(rightTool) == Profile.LIGHT;
  }

  /** True when this task must not share the target with a different task. */
  public static boolean isBarrier(String toolCode) {
    return profileOf(toolCode) != Profile.LIGHT;
  }
}
