package com.bachelor.toolbox.ai;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/** The executable AI boundary shared by workflow validation, dispatch and product guidance. */
final class AiToolCatalog {
  private AiToolCatalog() {}

  static final List<String> EXECUTABLE_CODES = List.of(
      "nmap_service_scan", "tcp_ports", "http_headers", "http_security_check", "tls_config",
      "nuclei_scan", "afrog_scan", "xray_scan", "zap_scan", "fscan_scan", "sqlmap_scan",
      "msf_scan", "zap_fuzz");
  static final Set<String> EXECUTABLE_TOOLS = Set.copyOf(EXECUTABLE_CODES);
  static final List<String> RUNTIME_CODES =
      Stream.concat(Stream.of("retrieve_project_context"), EXECUTABLE_CODES.stream()).toList();
  static final Set<String> RUNTIME_TOOLS = Set.copyOf(RUNTIME_CODES);

  static boolean requiresApproval(String code) {
    return Set.of("sqlmap_scan", "zap_fuzz").contains(code);
  }

  static String displayName(String code) {
    return switch (code == null ? "" : code) {
      case "nmap_service_scan" -> "Nmap 服务识别";
      case "nuclei_scan" -> "Nuclei 安全模板检测";
      case "afrog_scan" -> "Afrog PoC 漏洞扫描";
      case "xray_scan" -> "Xray PoC 漏洞扫描";
      case "zap_scan" -> "OWASP ZAP 主动扫描";
      case "fscan_scan" -> "fscan 主机扫描";
      case "msf_scan" -> "Metasploit 授权模块检查";
      case "sqlmap_scan" -> "sqlmap SQL 注入检测";
      case "zap_fuzz" -> "ZAP 单次参数变异验证";
      case "tcp_ports" -> "授权端口探测";
      case "http_headers" -> "HTTP 安全响应头检查";
      case "http_security_check" -> "HTTP 常见安全检查";
      case "tls_config" -> "TLS 基础配置检查";
      case "retrieve_project_context" -> "项目资料检索";
      default -> "安全检测工具";
    };
  }
}
