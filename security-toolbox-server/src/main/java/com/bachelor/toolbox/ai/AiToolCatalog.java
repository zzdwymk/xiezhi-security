package com.bachelor.toolbox.ai;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * The executable AI boundary shared by workflow validation, dispatch and product guidance.
 *
 * <h2>Why this class is the single source of truth</h2>
 *
 * <p>Before this class became the authority, adding one tool required editing seven places across
 * two languages (this catalog, the product guide, the shipped default workflow, and on the Python
 * side {@code SAFE_TOOLS}, {@code _PARAMETER_SCHEMAS}, the {@code WorkflowStep.tool} literal plus
 * three unions, and {@code TOOL_STAGE}). Missing the literal silently broke every AI turn with a
 * schema validation error.
 *
 * <p>{@link #descriptors()} exposes the same information over HTTP so the Python runtime can build
 * its own contract from it instead of keeping a hand-copied list. The Python side still keeps a
 * static {@code Literal} (schema-level validation is a security boundary, not an inconvenience) and
 * a drift-detection test asserts the two agree — a mismatch now fails a test instead of a user turn.
 */
final class AiToolCatalog {
  private AiToolCatalog() {}

  static final List<String> EXECUTABLE_CODES = List.of(
      "tcp_ports", "nmap_service_scan", "http_headers", "tls_config", "site_crawl",
      "dir_scan", "http_security_check", "nuclei_scan", "afrog_scan", "xray_scan",
      "zap_scan", "fscan_scan", "msf_scan", "sqlmap_scan", "zap_fuzz");
  static final Set<String> EXECUTABLE_TOOLS = Set.copyOf(EXECUTABLE_CODES);
  static final List<String> RUNTIME_CODES =
      Stream.concat(Stream.of("retrieve_project_context"), EXECUTABLE_CODES.stream()).toList();
  static final Set<String> RUNTIME_TOOLS = Set.copyOf(RUNTIME_CODES);

  /** Codes whose execution always needs an administrator decision, even when SAFE-ish. */
  private static final Set<String> APPROVAL_REQUIRED = Set.of("sqlmap_scan", "zap_fuzz");

  /**
   * Tools that raise capability approval problems when the project cannot see them: they are the
   * intrusive tier. Marker only — it never grants or widens anything.
   */
  private static final Set<String> INTRUSIVE = Set.of(
      "sqlmap_scan", "zap_fuzz", "msf_scan", "fscan_scan", "nuclei_scan", "afrog_scan",
      "xray_scan", "zap_scan", "dir_scan");

  static boolean requiresApproval(String code) {
    return APPROVAL_REQUIRED.contains(code);
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
      case "dir_scan" -> "授权目录/路径探测（线索）";
      case "http_headers" -> "HTTP 安全响应头检查";
      case "http_security_check" -> "HTTP 常见安全检查";
      case "tls_config" -> "TLS 基础配置检查";
      case "site_crawl" -> "站点链接爬取";
      case "retrieve_project_context" -> "项目资料检索";
      default -> "安全检测工具";
    };
  }

  /** One-line summary shown to the model when it considers a tool. */
  static String summary(String code) {
    return switch (code == null ? "" : code) {
      case "nmap_service_scan" -> "对授权主机做端口与服务识别，输出开放端口和服务版本";
      case "nuclei_scan" -> "使用 Nuclei 模板检查授权目标上的已知漏洞与错误配置";
      case "afrog_scan" -> "使用已同步的 Afrog PoC 检查授权 Web 目标";
      case "xray_scan" -> "使用已同步的 Xray PoC 检查授权 Web 目标";
      case "zap_scan" -> "使用 OWASP ZAP 对授权 Web 目标做主动爬取与扫描";
      case "fscan_scan" -> "对授权主机做端口、服务指纹与安全漏洞指纹扫描";
      case "msf_scan" -> "运行指定的 Metasploit auxiliary/exploit 模块做授权检查";
      case "sqlmap_scan" -> "对已有授权 URL 查询参数做受控 SQL 注入检测";
      case "zap_fuzz" -> "向授权请求发送一次参数变异，验证单点输入处理";
      case "tcp_ports" -> "仅在授权端口范围内探测 TCP 连通性";
      case "dir_scan" -> "用内置字典探测授权 Web 目标的目录与路径；命中仅为待核实线索，不单独作为漏洞确认";
      case "http_headers" -> "采集 HTTP 响应头并检查常见浏览器安全头";
      case "http_security_check" -> "检查 cookies、CORS、HTTP 方法与信息泄露";
      case "tls_config" -> "检查 HTTPS 证书与 TLS 基础配置";
      case "site_crawl" -> "抓取授权目标首页，提取同源链接与疑似可注入参数候选并登记资产（只读信息收集）";
      case "retrieve_project_context" -> "检索已索引的项目资料、历史任务与证据（只读，不产生动作）";
      default -> "安全检测工具";
    };
  }

  /** Stage this tool contributes to, mirroring the Python runtime's TOOL_STAGE map. */
  static String phase(String code) {
    return switch (code == null ? "" : code) {
      case "retrieve_project_context" -> "recon";
      case "site_crawl" -> "recon";
      case "tcp_ports", "nmap_service_scan", "http_headers", "tls_config", "dir_scan",
          "fscan_scan" -> "map";
      default -> "validate";
    };
  }

  /**
   * Full descriptors for every runtime tool.
   *
   * <p>Ordered by {@link #RUNTIME_CODES} so the payload is stable across JVM runs, which keeps the
   * drift-detection test deterministic.
   */
  static List<Map<String, Object>> descriptors() {
    return RUNTIME_CODES.stream().map(AiToolCatalog::descriptor).toList();
  }

  private static Map<String, Object> descriptor(String code) {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("code", code);
    value.put("displayName", displayName(code));
    value.put("summary", summary(code));
    value.put("phase", phase(code));
    value.put("executable", EXECUTABLE_TOOLS.contains(code));
    value.put("requiresApproval", requiresApproval(code));
    value.put("intrusive", INTRUSIVE.contains(code));
    value.put("parameterSchema", parameterSchema(code));
    return value;
  }

  /**
   * Parameter schema for a tool.
   *
   * <p>Kept in lockstep with the Python {@code _PARAMETER_SCHEMAS} table by
   * {@code AiToolCatalogDriftTests}; the server-side dispatch validation remains authoritative for
   * values, this schema only tells the model what it may propose.
   */
  static Map<String, Object> parameterSchema(String code) {
    return switch (code == null ? "" : code) {
      case "nmap_service_scan" ->
          object(
              Map.of(
                  "ports", string(1, 200, "授权端口，如 80,443 或 1-1000"),
                  // Single source of truth: the tool's own accepted modes.
                  "mode",
                      enumeration(
                          "扫描模式",
                          com.bachelor.toolbox.ai.ToolParameterSpec.NMAP_MODES.stream()
                              .sorted()
                              .toList())));
      // 只暴露 ports 与 udp：扫描面由授权范围与 ports 的交集决定，不存在会改变扫描面的 mode。
      case "tcp_ports" ->
          object(
              Map.of(
                  "ports", string(1, 200, "授权端口，如 80,443 或 1-1024"),
                  "udp", bool("是否追加 UDP 快速探测；UDP 只能判定「开放或过滤」，不能确证开放")));
      case "fscan_scan" ->
          object(
              Map.of(
                  "ports", string(1, 200, "授权端口"),
                  "vulnMode", enumeration("检测深度", List.of("SAFE", "FINGERPRINT", "FULL"))));
      case "http_security_check" ->
          object(
              Map.of(
                  "check",
                  enumeration("检查项", List.of("cookies", "cors", "methods", "disclosure"))));
      case "zap_scan" ->
          object(
              Map.of(
                  "spider", Map.of("type", "boolean", "description", "是否启用爬虫"),
                  "strength",
                  enumeration("扫描强度", List.of("LOW", "MEDIUM", "HIGH", "INSANE"))));
      case "afrog_scan", "xray_scan" ->
          object(
              Map.of(
                  "pocCodes",
                  Map.of("type", "array", "items", Map.of("type", "string"), "maxItems", 50),
                  "allPocs", Map.of("type", "boolean", "description", "使用全部已同步 PoC")));
      case "nuclei_scan" ->
          object(
              Map.of(
                  "pocCodes",
                  Map.of("type", "array", "items", Map.of("type", "string"), "maxItems", 50),
                  "allPocs", Map.of("type", "boolean")));
      case "msf_scan" ->
          object(
              Map.of(
                  "module", string(1, 200, "auxiliary/ 或 exploit/ 模块路径"),
                  "modules",
                  Map.of("type", "array", "items", Map.of("type", "string"), "maxItems", 20),
                  "options", Map.of("type", "object", "additionalProperties", true)));
      case "sqlmap_scan" ->
          object(
              Map.of(
                  "path", string(1, 2000, "带查询参数的授权 URL 路径"),
                  "level", number(1, 5, "检测等级"),
                  "risk", number(1, 3, "检测风险"),
                  "technique", string(1, 16, "注入技术")));
      case "zap_fuzz" ->
          object(
              Map.of(
                  "fuzzRequestUrl", string(1, 2000, "原授权请求 URL"),
                  "method", enumeration("HTTP 方法", List.of("GET", "POST")),
                  "fuzzPostBody", string(0, 4000, "POST 请求体"),
                  "fuzzPayload", string(1, 1000, "测试值"),
                  "fuzzTargetField", string(1, 128, "要替换的字段名")));
      case "dir_scan" ->
          object(
              Map.of(
                  "dictionary",
                      Map.of(
                          "type", "string",
                          "minLength", 1,
                          "maxLength", 64,
                          "description",
                              "字典 id：dirb-common / dirb-big / dirb-small / dirb-best1050 / "
                                  + "dirbuster-2.3-small / custom；留空用默认 dirb-common"),
                  "concurrency", number(1, 50, "并发数，用户可设置 1-50"),
                  "depth", number(0, 3, "递归深度 0-3"),
                  "maxRequests", number(1, 200_000, "请求预算"),
                  "extensions",
                      Map.of(
                          "type", "array",
                          "items", Map.of("type", "string"),
                          "maxItems", 10,
                          "description", "附加后缀探测，如 php、txt")));
      case "site_crawl" -> object(Map.of());
      default -> object(Map.of());
    };
  }

  private static Map<String, Object> object(Map<String, Object> properties) {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("type", "object");
    value.put("properties", properties);
    value.put("additionalProperties", false);
    return value;
  }

  private static Map<String, Object> string(int min, int max, String description) {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("type", "string");
    if (min > 0) value.put("minLength", min);
    value.put("maxLength", max);
    if (!description.isBlank()) value.put("description", description);
    return value;
  }

  private static Map<String, Object> number(int min, int max, String description) {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("type", "integer");
    value.put("minimum", min);
    value.put("maximum", max);
    if (!description.isBlank()) value.put("description", description);
    return value;
  }

  private static Map<String, Object> enumeration(String description, List<String> values) {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("enum", values);
    value.put("description", description);
    return value;
  }

  private static Map<String, Object> bool(String description) {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("type", "boolean");
    if (!description.isBlank()) value.put("description", description);
    return value;
  }
}
