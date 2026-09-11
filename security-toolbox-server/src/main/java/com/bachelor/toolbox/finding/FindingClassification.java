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
  private static final Set<String> RISK_POINT_TOOLS =
      Set.of("http_headers", "tcp_ports", "nmap_service_scan");

  private static final Set<String> RISK_POINT_CODES =
      Set.of("STB-WEB-001", "STB-WEB-005", "STB-TLS-001", "STB-NET-001", "STB-SMB-SMBV1");

  private FindingClassification() {}

  public static boolean isVulnerability(Finding finding) {
    if (finding == null) return false;
    return isVulnerability(
        finding.getSeverity(), finding.getSourceTool(), finding.getVulnerabilityCode());
  }

  public static boolean isVulnerability(
      String severity, String sourceTool, String vulnerabilityCode) {
    String normalizedTool = sourceTool == null ? "" : sourceTool.trim().toLowerCase(Locale.ROOT);
    String normalizedCode = vulnerabilityCode == null ? "" : vulnerabilityCode.trim().toUpperCase(Locale.ROOT);
    String normalizedSev = severity == null ? "" : severity.trim().toUpperCase(Locale.ROOT);

    // 1. 安全响应头检查、端口开放探测等纯基线与暴露面工具，归为风险点（非直接漏洞）
    if (RISK_POINT_TOOLS.contains(normalizedTool)) {
      return false;
    }
    // 2. 属于安全响应头缺失、技术栈暴露、TLS配置、SMBv1协议等基线配置与暴露面编号的，归为风险点
    if (RISK_POINT_CODES.contains(normalizedCode)) {
      return false;
    }
    // 3. LOW 或 INFO 级别的配置加固项归为风险点
    if ("LOW".equals(normalizedSev) || "INFO".equals(normalizedSev)) {
      return false;
    }

    // 4. CRITICAL 或 HIGH 等高威胁项，或具备非基线漏洞代码的项，判定为漏洞发现
    if ("CRITICAL".equals(normalizedSev) || "HIGH".equals(normalizedSev)) {
      return true;
    }
    return !normalizedCode.isBlank();
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
