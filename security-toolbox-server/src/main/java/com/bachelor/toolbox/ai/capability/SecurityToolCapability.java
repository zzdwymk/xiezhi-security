package com.bachelor.toolbox.ai.capability;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.tool.SecurityTool;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 把现有 {@link SecurityTool}（{@code tool/} 包）适配为 {@link AgentCapability}。
 *
 * <p>这是"路线 A"之外的一条低成本通道：现有 14 个安全工具无需改动即可进入统一能力模型，治理层对它们与手工封装能力一视同仁。
 *
 * <h2>为什么 {@code targetBindings} 在这里必须准确</h2>
 *
 * <p>现有 AI 执行链路把目标 ID 放在 <em>请求</em> 上（{@code AiPlanRequest.targetId}），而能力参数里并不总是带目标。一旦
 * 能力被 Agent 直接调用（而不是经由计划派发），参数里的目标 ID 就成了唯一的授权校验依据（设计文档 §6.2）。因此本适配器把
 * {@code targetId} 列入每个扫描类能力的参数 schema，并要求能力显式声明 {@link TargetScope}：
 *
 * <ul>
 *   <li>{@link TargetScope#REQUIRED}：扫描/探测类能力，最终一定触及授权目标。参数里解析不到目标 ID 时返回 {@link
 *       #TARGET_BINDING_UNRESOLVED}，让治理层 fail-closed，而不是伪装成"不触及目标"放行。
 *   <li>{@link TargetScope#NONE}：确实不触及目标的能力（如项目资料检索）。
 * </ul>
 */
public final class SecurityToolCapability implements AgentCapability {

  /** 目标绑定语义。 */
  public enum TargetScope {
    /** 最终一定触及授权目标，必须能解析出目标 ID。 */
    REQUIRED,
    /** 不触及任何授权目标。 */
    NONE
  }

  /** 参数中承载授权目标 ID 的键，与 AI 请求体保持一致。 */
  public static final String TARGET_ID_KEY = "targetId";

  /** 扫描类工具的通用参数 schema 片段：目标 ID。 */
  private static final Map<String, Object> TARGET_ID_PROPERTY =
      Map.of(
          TARGET_ID_KEY,
          Map.of(
              "type", "integer",
              "minimum", 1,
              "description", "本次执行触及的授权目标 ID，用于护栏授权校验"));

  private static final Pattern DIGITS = Pattern.compile("\\d{1,18}");

  private final SecurityTool tool;
  private final CapabilityKind kind;
  private final RiskLevel risk;
  private final boolean requiresApproval;
  private final TargetScope targetScope;

  public SecurityToolCapability(
      SecurityTool tool,
      CapabilityKind kind,
      RiskLevel risk,
      boolean requiresApproval,
      TargetScope targetScope) {
    this.tool = Objects.requireNonNull(tool, "安全工具不能为空");
    this.kind = Objects.requireNonNull(kind, "能力类别不能为空");
    this.risk = Objects.requireNonNull(risk, "风险等级不能为空");
    this.requiresApproval = requiresApproval;
    this.targetScope = Objects.requireNonNull(targetScope, "目标绑定语义不能为空");
  }

  /**
   * 用内置策略为工具创建适配器。
   *
   * <p>策略表见 {@link #inferKind}/{@link #inferRisk}/{@link #inferTargetScope}。未知工具一律按最保守的方式处理（触及目标 +
   * 需确认），避免新工具上线即成为护栏缺口。
   */
  public static SecurityToolCapability of(SecurityTool tool) {
    Objects.requireNonNull(tool, "安全工具不能为空");
    return of(tool, inferKind(tool.code()), inferRisk(tool.code()), inferTargetScope(tool.code()));
  }

  /** 用指定的类别与风险等级创建适配器；是否需要确认由类别与风险等级推导。 */
  public static SecurityToolCapability of(
      SecurityTool tool, CapabilityKind kind, RiskLevel risk, TargetScope targetScope) {
    return new SecurityToolCapability(
        tool, kind, risk, inferRequiresApproval(kind, risk), targetScope);
  }

  /** 是否为项目内只读检索类能力（不触及授权目标，无需确认）。 */
  private static final Set<String> READ_ONLY_TOOL_CODES = Set.of("retrieve_project_context");

  /**
   * 只读信息收集类工具：触及授权目标但仅做 GET 类只读请求（页面爬取/链接提取），不发送攻击载荷、
   * 不产生漏洞发现，因此按 SAFE 处理、无需逐次审批（仍受授权目标与端口守卫约束）。
   */
  private static final Set<String> READ_ONLY_RECON_CODES = Set.of("site_crawl");

  /** 需要逐次人工确认的高风险工具，与 {@code AiToolCatalog#requiresApproval} 的既有判定保持一致。 */
  private static final Set<String> MANDATORY_APPROVAL_CODES = Set.of("sqlmap_scan", "zap_fuzz");

  /** 不可逆或直接发起利用/变异探测的工具。 */
  private static final Set<String> DESTRUCTIVE_CODES =
      Set.of("sqlmap_scan", "msf_scan", "zap_fuzz");

  /** 扫描类工具的参数 schema（键名与 {@code AiTaskDispatchService#normalizeParameters} 的白名单一致）。 */
  private static final Map<String, Map<String, Object>> EXTRA_SCHEMA =
      Map.ofEntries(
          Map.entry("tcp_ports", property("ports", "string", "授权端口范围，如 80,443 或 1-1024")),
          Map.entry(
              "nmap_service_scan",
              merge(
                  property("ports", "string", "授权端口范围"),
                  property("mode", "string", "扫描模式，可选：" + String.join("、", com.bachelor.toolbox.ai.ToolParameterSpec.NMAP_MODES.stream().sorted().toList())))),
          Map.entry(
              "fscan_scan",
              merge(
                  property("ports", "string", "授权端口范围"),
                  property("vulnMode", "string", "扫描模式：SAFE、FINGERPRINT 或 FULL"))),
          Map.entry("nuclei_scan", pocSchema()),
          Map.entry("afrog_scan", pocSchema()),
          Map.entry("xray_scan", pocSchema()),
          Map.entry(
              "zap_scan",
              merge(
                  property("spider", "boolean", "是否启用爬虫"),
                  property("strength", "string", "扫描强度：LOW、MEDIUM、HIGH 或 INSANE"))),
          Map.entry(
              "msf_scan",
              merge(
                  property("module", "string", "Metasploit 模块名，须以 auxiliary/ 或 exploit/ 开头"),
                  property("modules", "array", "批量模块列表，与 module 互斥"),
                  property("options", "object", "模块参数"))),
          Map.entry(
              "sqlmap_scan",
              merge(
                  property("path", "string", "目标 URL 路径，须带查询参数"),
                  property("level", "integer", "探测等级 1-5"),
                  property("risk", "integer", "风险等级 1-3"),
                  property("technique", "string", "注入技术，如 BEUT"))),
          Map.entry(
              "http_security_check",
              property("check", "string", "检查类型：cookies、cors、methods 或 disclosure")),
          Map.entry("http_headers", Map.of()),
          Map.entry("tls_config", Map.of()),
          Map.entry("site_crawl", Map.of()));

  // ---------------------------------------------------------------- 策略推导

  static CapabilityKind inferKind(String code) {
    return READ_ONLY_TOOL_CODES.contains(code) ? CapabilityKind.READ : CapabilityKind.EXECUTE;
  }

  static RiskLevel inferRisk(String code) {
    if (READ_ONLY_TOOL_CODES.contains(code) || READ_ONLY_RECON_CODES.contains(code)) {
      return RiskLevel.SAFE;
    }
    if (DESTRUCTIVE_CODES.contains(code)) return RiskLevel.DESTRUCTIVE;
    return RiskLevel.SENSITIVE;
  }

  static boolean inferRequiresApproval(CapabilityKind kind, RiskLevel risk) {
    return kind == CapabilityKind.ADMIN || risk == RiskLevel.DESTRUCTIVE;
  }

  static TargetScope inferTargetScope(String code) {
    return READ_ONLY_TOOL_CODES.contains(code) ? TargetScope.NONE : TargetScope.REQUIRED;
  }

  /** 该工具码是否被本适配器识别（未识别时仍可适配，只是走最保守的默认策略）。 */
  public static boolean isKnown(String code) {
    return READ_ONLY_TOOL_CODES.contains(code)
        || READ_ONLY_RECON_CODES.contains(code)
        || EXTRA_SCHEMA.containsKey(code);
  }

  // ---------------------------------------------------------------- 能力接口

  @Override
  public String code() {
    return tool.code();
  }

  @Override
  public String displayName() {
    return tool.displayName();
  }

  @Override
  public String description() {
    return tool.description();
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMapWithTargetId();
    if (targetScope == TargetScope.REQUIRED) {
      properties.putAll(TARGET_ID_PROPERTY);
    }
    properties.putAll(EXTRA_SCHEMA.getOrDefault(code(), Map.of()));
    if (properties.isEmpty()) {
      return Map.of();
    }
    return Map.of(
        "type",
        "object",
        "properties",
        Map.copyOf(properties),
        "required",
        targetScope == TargetScope.REQUIRED ? List.of(TARGET_ID_KEY) : List.of(),
        "additionalProperties",
        false);
  }

  @Override
  public CapabilityKind kind() {
    return kind;
  }

  @Override
  public RiskLevel risk() {
    return risk;
  }

  @Override
  public boolean requiresApproval() {
    return requiresApproval || MANDATORY_APPROVAL_CODES.contains(code());
  }

  /**
   * 从参数中提取本次调用触及的授权目标 ID。
   *
   * <p>识别以下写法：{@code targetId} / {@code target_id} / {@code targetIds} / {@code target_ids}
   * / {@code targets}；值可以是数字、数字字符串、集合或数组。所有能解析出的 ID 都会返回，而不是只取第一个——多目标调用必须逐个过授权校验。
   */
  @Override
  public Set<String> targetBindings(Map<String, Object> params) {
    if (targetScope == TargetScope.NONE) {
      return Set.of();
    }
    Set<String> bound = new LinkedHashSet<>();
    if (params != null) {
      for (Map.Entry<String, Object> entry : params.entrySet()) {
        if (isTargetKey(entry.getKey())) {
          collectTargetIds(entry.getValue(), bound);
        }
      }
    }
    if (bound.isEmpty()) {
      // 扫描类能力必须声明目标；解析不到时交给治理层 fail-closed，不能冒充"不触及目标"。
      return Set.of(TARGET_BINDING_UNRESOLVED);
    }
    return Set.copyOf(bound);
  }

  /**
   * 参数校验：目标 ID 必须存在且为正整数，端口范围格式必须合法。
   *
   * <p>这里只做"能力自身可判定"的检查；越权判定（目标是否授权、端口是否在授权范围内）属于治理层与 {@code TargetPolicyService}，
   * 不在本层重复实现，避免出现两套互相漂移的授权规则。
   */
  @Override
  public void validateParams(Map<String, Object> params) {
    Map<String, Object> safe = params == null ? Map.of() : params;
    if (targetScope == TargetScope.REQUIRED) {
      Set<String> bound = targetBindings(safe);
      if (bound.contains(TARGET_BINDING_UNRESOLVED)) {
        throw new ApiException("能力 " + code() + " 缺少授权目标 ID，无法通过授权校验");
      }
    }
    Object ports = safe.get("ports");
    if (ports != null && !isValidPortExpression(Objects.toString(ports, ""))) {
      throw new ApiException("端口范围格式无效: " + ports);
    }
  }

  /** 底层安全工具，供执行阶段取用。 */
  public SecurityTool tool() {
    return tool;
  }

  /** 目标绑定语义。 */
  public TargetScope targetScope() {
    return targetScope;
  }

  // ---------------------------------------------------------------- 内部工具

  static boolean isTargetKey(String key) {
    if (key == null) return false;
    String normalized = key.trim().toLowerCase(Locale.ROOT).replace("_", "");
    return Set.of("targetid", "targetids", "targets").contains(normalized);
  }

  static void collectTargetIds(Object value, Collection<String> sink) {
    if (value == null) return;
    if (value instanceof Collection<?> collection) {
      for (Object item : collection) {
        collectTargetIds(item, sink);
      }
      return;
    }
    if (value instanceof Object[] array) {
      for (Object item : array) {
        collectTargetIds(item, sink);
      }
      return;
    }
    if (value instanceof Number number) {
      long id = number.longValue();
      if (id > 0) sink.add(Long.toString(id));
      return;
    }
    String text = value.toString().trim();
    if (text.isEmpty()) return;
    if (DIGITS.matcher(text).matches()) {
      long id = Long.parseLong(text);
      if (id > 0) sink.add(Long.toString(id));
      return;
    }
    // 逗号/分号/空白分隔的列表写法
    for (String part : text.split("[,;\\s]+")) {
      String item = part.trim();
      if (DIGITS.matcher(item).matches() && Long.parseLong(item) > 0) {
        sink.add(Long.toString(Long.parseLong(item)));
      }
    }
  }

  static boolean isValidPortExpression(String text) {
    if (text == null || text.isBlank()) return true;
    for (String part : text.split(",")) {
      String item = part.trim();
      if (item.isEmpty()) continue;
      String[] range = item.split("-", -1);
      if (range.length > 2) return false;
      for (String bound : range) {
        if (!DIGITS.matcher(bound.trim()).matches()) return false;
        long port = Long.parseLong(bound.trim());
        if (port < 1 || port > 65535) return false;
      }
    }
    return true;
  }

  private static Map<String, Object> property(String name, String type, String description) {
    return Map.of(name, Map.of("type", type, "description", description));
  }

  private static Map<String, Object> pocSchema() {
    return merge(
        property("pocCodes", "array", "要执行的 PoC 编号列表，1-50 个"),
        property("allPocs", "boolean", "是否执行全部 PoC，与 pocCodes 互斥"));
  }

  @SafeVarargs
  private static Map<String, Object> merge(Map<String, Object>... parts) {
    List<Map.Entry<String, Object>> entries = new ArrayList<>();
    for (Map<String, Object> part : parts) {
      entries.addAll(part.entrySet());
    }
    return Map.copyOf(entries.stream().collect(java.util.stream.Collectors.toMap(
        Map.Entry::getKey, Map.Entry::getValue, (a, b) -> a, java.util.LinkedHashMap::new)));
  }

  /** 保持插入顺序的可变 Map，用于拼装 properties。 */
  private static final class LinkedHashMapWithTargetId
      extends java.util.LinkedHashMap<String, Object> {}
}
