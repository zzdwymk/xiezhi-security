package com.bachelor.toolbox.finding;

import java.util.Collection;
import java.util.Locale;
import java.util.Set;

/**
 * Single source of truth for "is this finding an actual vulnerability, or just an informational /
 * asset-exposure observation (a 风险点 / 信息项)?".
 *
 * <p>Open ports produced by tcp_ports / nmap_service_scan are recorded as INFO findings with no
 * vulnerabilityCode: they describe attack surface, not a confirmed vulnerability, and must not
 * inflate the "漏洞发现" count. Nuclei INFO matches DO carry a vulnerabilityCode and therefore remain
 * counted as vulnerabilities. Keeping this decision in one place lets every counter and report
 * label agree without deleting any historical finding rows.
 */
public final class FindingClassification {
  private static final Set<String> ASSET_OBSERVATION_TOOLS =
      Set.of("tcp_ports", "nmap_service_scan");

  private FindingClassification() {}

  public static boolean isVulnerability(Finding finding) {
    if (finding == null) return false;
    return isVulnerability(
        finding.getSeverity(), finding.getSourceTool(), finding.getVulnerabilityCode());
  }

  public static boolean isVulnerability(
      String severity, String sourceTool, String vulnerabilityCode) {
    if (vulnerabilityCode != null && !vulnerabilityCode.isBlank()) return true;
    if (sourceTool != null && ASSET_OBSERVATION_TOOLS.contains(sourceTool.toLowerCase(Locale.ROOT)))
      return false;
    String normalized = severity == null ? "" : severity.trim().toUpperCase(Locale.ROOT);
    return !"INFO".equals(normalized);
  }

  public static long vulnerabilityCount(Collection<Finding> findings) {
    return findings == null
        ? 0
        : findings.stream().filter(FindingClassification::isVulnerability).count();
  }

  public static long informationalCount(Collection<Finding> findings) {
    return findings == null
        ? 0
        : findings.stream().filter(finding -> !isVulnerability(finding)).count();
  }
}
