package com.bachelor.toolbox.ai.endpoint;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.common.ApiException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 由 REST 端点自动派生出的 {@link AgentCapability}（设计文档 §4.2 路线 B）。
 *
 * <p>每个实例对应"一个 HTTP 方法 + 一个路径模板"。风险等级与确认要求来自 {@link RiskInference}，可由
 * {@link EndpointCapabilityScanner#setRiskOverrides} 人工校准。
 *
 * <h2>目标绑定（§4.1 三态语义）</h2>
 *
 * <p>端点能力的参数结构由业务决定，无法静态判定它是否触及授权目标。因此本类<strong>不猜测</strong>，而是按 §4.1.1 的哨兵兜底规则处理：
 *
 * <ul>
 *   <li>只读端点（{@code GET}/{@code HEAD}）且路径不含目标参数 → 返回<b>真空集</b>，确实不触及目标（如
 *       {@code GET /api/vulnerabilities}）。这是三态中唯一合法的"跳过 L-A"情形。
 *   <li>其余端点（写操作、执行类、路径含 {@code {targetId}}）→ 返回<b>含 {@link #TARGET_BINDING_UNRESOLVED}
 *       的集合</b>，让治理层 fail-closed。
 * </ul>
 *
 * <p><b>为什么不能反过来"尽量解析 targetId"</b>：端点参数 schema 是任意 JSON（{@code @RequestBody Map<String,
 * Object>}、嵌套 DTO、query 参数混用），静态解析出的目标集合必然不完整。宁可让护栏拒绝并转人工确认，也不能给出一个"看起来解析成功但
 * 漏了目标"的集合——那正是 §4.1.1 记录的 fail-open 缺陷。
 *
 * <h2>与手工封装能力的关系</h2>
 *
 * <p>路线 A 的手工能力（如 {@code create_workflow}）与路线 B 的端点能力（如 {@code endpoint_post_api_workflows}）
 * 语义上重叠，但<b>能力码不同</b>，因此可以同时存在于 {@link com.bachelor.toolbox.ai.capability.CapabilityRegistry}。
 * 手工能力的 {@code targetBindings} 是精确的；端点能力是保守的哨兵。Agent 应优先用手工能力。
 */
public final class EndpointCapability implements AgentCapability {

  /** 能力码前缀，便于在注册表里区分路线 A 的手工能力与路线 B 的派生能力。 */
  public static final String CODE_PREFIX = "endpoint_";

  /** 参数中用于承载目标 ID 的键（与 {@code AiPlanRequest.targetId} 一致）。 */
  public static final String TARGET_ID_KEY = "targetId";

  /** 路径模板参数的匹配器，如 {@code {id}}、{@code {targetId}}。 */
  private static final Pattern TEMPLATE_PARAM = Pattern.compile("\\{([A-Za-z0-9_]+)(?::[^}]*)?}");

  /** 只读方法：这类端点若路径不含目标参数，则确实不触及授权目标。 */
  private static final Set<String> READ_METHODS = Set.of("GET", "HEAD", "OPTIONS", "TRACE");

  private final String method;
  private final String pathTemplate;
  private final String code;
  private final CapabilityKind kind;
  private final RiskLevel risk;
  private final boolean requiresApproval;
  private final boolean targetBound;
  private final String handlerDescription;
  private final List<String> pathVariables;

  /**
   * @param method HTTP 方法（会被规范化为大写）
   * @param pathTemplate 路径模板，如 {@code /api/targets/{targetId}/discovered-paths}
   * @param kind 能力类别
   * @param risk 风险等级
   * @param requiresApproval 是否需要人工确认
   * @param targetBound 该端点是否可能触及授权目标（决定 {@link #targetBindings} 走哨兵还是空集）
   * @param handlerDescription 处理器方法说明，附加到描述末尾帮助 LLM 选择
   */
  public EndpointCapability(
      String method,
      String pathTemplate,
      CapabilityKind kind,
      RiskLevel risk,
      boolean requiresApproval,
      boolean targetBound,
      String handlerDescription) {
    this.method = RiskInference.normalizeMethod(Objects.requireNonNull(method, "HTTP 方法不能为空"));
    this.pathTemplate = Objects.requireNonNull(pathTemplate, "端点路径不能为空");
    this.code = codeOf(this.method, this.pathTemplate);
    this.kind = Objects.requireNonNull(kind, "能力类别不能为空");
    this.risk = Objects.requireNonNull(risk, "风险等级不能为空");
    this.requiresApproval = requiresApproval;
    this.targetBound = targetBound;
    this.handlerDescription = handlerDescription == null ? "" : handlerDescription.trim();
    this.pathVariables = extractPathVariables(this.pathTemplate);
  }

  /** 用 {@link RiskInference} 的默认策略构造端点能力。 */
  public static EndpointCapability derive(
      String method, String pathTemplate, String handlerDescription) {
    String normalizedMethod = RiskInference.normalizeMethod(method);
    return new EndpointCapability(
        normalizedMethod,
        pathTemplate,
        RiskInference.inferKind(normalizedMethod, pathTemplate),
        RiskInference.inferRisk(normalizedMethod, pathTemplate),
        RiskInference.inferRequiresApproval(normalizedMethod, pathTemplate),
        isTargetBound(normalizedMethod, pathTemplate),
        handlerDescription);
  }

  /**
   * 该端点是否应声明"可能触及授权目标"。
   *
   * <p>判定：
   *
   * <ul>
   *   <li>非只读方法一律视为可能触及目标（写/执行类端点的效果无法静态判定）
   *   <li>只读方法中，路径含 {@code target}/{@code targets} 段（如 {@code /api/targets/{targetId}/...}）也视为触及目标
   * </ul>
   *
   * <p>注意这里不能直接复用 {@link RiskInference#pathTokens} 的 token 集合：它会把 {@code {targetId}} 剥成
   * {@code targetid}，而 {@code targetid} 并不等于 {@code target}。因此按"段是否以 target 开头"判定，同时兼顾
   * 驼峰写法（{@code targetId}）与下划线写法（{@code target_id}）。
   */
  public static boolean isTargetBound(String method, String pathTemplate) {
    String normalizedMethod = RiskInference.normalizeMethod(method);
    if (!READ_METHODS.contains(normalizedMethod)) {
      return true;
    }
    if (pathTemplate == null) {
      return false;
    }
    for (String segment : pathTemplate.split("/")) {
      String cleaned = segment.trim().toLowerCase(Locale.ROOT);
      if (cleaned.startsWith("{") && cleaned.endsWith("}")) {
        cleaned = cleaned.substring(1, cleaned.length() - 1);
      }
      if (cleaned.isEmpty()) {
        continue;
      }
      if (cleaned.equals("target")
          || cleaned.equals("targets")
          || cleaned.startsWith("target-")
          || cleaned.startsWith("target_")
          || (cleaned.startsWith("target") && cleaned.length() > 6)) {
        return true;
      }
    }
    return false;
  }

  /**
   * 由方法与路径模板生成能力码。
   *
   * <p>规则：{@code endpoint_} + 小写方法 + {@code _} + 路径中非占位符段以下划线连接；占位符段转成
   * {@code by_<参数名>}。例如
   * {@code GET /api/targets/{targetId}/discovered-paths} → {@code endpoint_get_api_targets_by_targetid_discovered_paths}。
   *
   * <p>生成规则必须<b>单射</b>：不同 (method, path) 不能映射到同一能力码，否则 {@code CapabilityRegistry} 会抛
   * "能力 code 重复注册"而启动失败。本规则保留了全部非占位符段与占位符名，因此是单射的。
   */
  public static String codeOf(String method, String pathTemplate) {
    String normalizedMethod = RiskInference.normalizeMethod(method);
    StringBuilder builder = new StringBuilder(CODE_PREFIX).append(normalizedMethod.toLowerCase(Locale.ROOT));
    if (pathTemplate != null) {
      for (String segment : pathTemplate.split("/")) {
        String cleaned = segment.trim();
        if (cleaned.isEmpty()) continue;
        var matcher = TEMPLATE_PARAM.matcher(cleaned);
        if (matcher.matches()) {
          builder.append("_by_").append(matcher.group(1).toLowerCase(Locale.ROOT));
          continue;
        }
        builder.append('_').append(sanitize(cleaned));
      }
    }
    return builder.toString();
  }

  private static String sanitize(String segment) {
    StringBuilder builder = new StringBuilder(segment.length());
    for (int index = 0; index < segment.length(); index++) {
      char current = segment.charAt(index);
      if (Character.isLetterOrDigit(current)) {
        builder.append(Character.toLowerCase(current));
      } else {
        builder.append('_');
      }
    }
    return builder.toString();
  }

  static List<String> extractPathVariables(String pathTemplate) {
    List<String> names = new java.util.ArrayList<>();
    var matcher = TEMPLATE_PARAM.matcher(pathTemplate);
    while (matcher.find()) {
      names.add(matcher.group(1));
    }
    return List.copyOf(names);
  }

  // ---------------------------------------------------------------- 能力接口

  @Override
  public String code() {
    return code;
  }

  @Override
  public String displayName() {
    return method + " " + pathTemplate;
  }

  @Override
  public String description() {
    StringBuilder builder = new StringBuilder();
    builder.append("调用平台端点 ").append(method).append(' ').append(pathTemplate);
    if (!handlerDescription.isBlank()) {
      builder.append("。功能：").append(handlerDescription);
    }
    builder.append("。风险等级 ").append(risk);
    if (requiresApproval) {
      builder.append("，调用前需人工确认");
    }
    if (targetBound) {
      builder.append("。该端点可能触及授权目标，护栏将按 fail-closed 处理，请显式提供 targetId 以便授权校验");
    }
    return builder.toString();
  }

  /**
   * 参数 schema。
   *
   * <p>按 §4.1.1 的配套要求，可能触及目标的端点把 {@code targetId} 标为 {@code required}，让 Agent 显式携带；同时保留
   * {@link #targetBindings} 的哨兵兜底——万一未传，走 fail-closed 而不是 fail-open。
   *
   * <p>当路径模板本身就含 {@code {targetId}} 时（如 {@code /api/targets/{targetId}/discovered-paths}），该路径参数<b>就是</b>
   * 授权目标，不再重复声明一个同名的顶层 {@code targetId} 属性，否则 schema 里会出现两个同名键，既冗余又让调用方困惑。
   */
  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    for (String variable : pathVariables) {
      if (isTargetVariable(variable)) {
        properties.put(
            variable,
            Map.of(
                "type", "integer",
                "minimum", 1,
                "description", "授权目标 ID（路径参数 {" + variable + "}），用于护栏 L-A 授权校验"));
        continue;
      }
      properties.put(
          variable,
          Map.of(
              "type", "string",
              "description", "路径参数 {" + variable + "}，调用时须替换为实际值"));
    }
    if (targetBound && !declaresTargetPathVariable()) {
      properties.put(
          TARGET_ID_KEY,
          Map.of(
              "type", "integer",
              "minimum", 1,
              "description", "本次调用触及的授权目标 ID，用于护栏 L-A 授权校验"));
    }
    properties.put(
        "body",
        Map.of(
            "type", "object",
            "description", "请求体 JSON 对象；无请求体的端点可省略"));
    properties.put(
        "query",
        Map.of(
            "type", "object",
            "description", "查询参数键值对；无查询参数的端点可省略"));

    List<String> required = new java.util.ArrayList<>(pathVariables);
    if (targetBound && !declaresTargetPathVariable()) {
      required.add(TARGET_ID_KEY);
    }
    return Map.of(
        "type", "object",
        "properties", Map.copyOf(properties),
        "required", List.copyOf(required),
        "additionalProperties", true);
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
    return requiresApproval;
  }

  /**
   * 目标绑定：见类注释的三态说明。
   *
   * <p>可能触及目标的端点一律返回 {@link #TARGET_BINDING_UNRESOLVED} 哨兵，让护栏 fail-closed；只读且路径不含目标参数的
   * 端点返回真空集，这是合法的"确实不触及目标"。
   *
   * <p>注意本方法<b>不看 params</b>：即便调用方传了看起来正确的 {@code targetId}，端点实际执行的路径参数可能来自
   * {@code body}/{@code query} 中的其它键，静态解析无法保证完整。少解析一个目标就等于漏一次授权校验。
   */
  @Override
  public Set<String> targetBindings(Map<String, Object> params) {
    if (!targetBound) {
      return Set.of();
    }
    Set<String> unresolved = new LinkedHashSet<>();
    unresolved.add(TARGET_BINDING_UNRESOLVED);
    return Set.copyOf(unresolved);
  }

  /**
   * 类型级声明：本端点能力是否触及授权目标。供护栏 {@code TargetBindingProbe} 反射读取。
   *
   * <p><strong>为什么必须有本方法</strong>：护栏对"空集"采取 fail-closed——{@code emptyBindingAllowed}
   * 只在能力<em>显式声明</em> {@code NONE} 时才返回 true。若缺少本访问器，
   * {@code TargetBindingProbe.declarationOf} 返回 {@code UNKNOWN}，于是
   * {@code targetBound == false} 的只读端点虽然正确地返回空集，却被 {@code MISSING_TARGET_BINDING}
   * 拒绝——<strong>能力归零</strong>。
   *
   * <p><strong>语义必须与 {@link #targetBindings} 严格一致</strong>：
   *
   * <ul>
   *   <li>返回 {@code false} ⟺ {@code targetBound == false} ⟺ {@code targetBindings} 恒返回空集</li>
   *   <li>返回 {@code true} ⟺ {@code targetBound == true} ⟺ {@code targetBindings} 恒返回哨兵</li>
   * </ul>
   *
   * <p>二者不一致会重新引入 fail-open（声明"不触及目标"却返回真实 ID → 空集判定被跳过）。
   * 一致性由全量断言测试保证。
   *
   * <p><strong>安全性</strong>：{@code targetBound} 的判定见 {@link #isTargetBound}——<em>所有非读方法</em>
   * （POST/PUT/PATCH/DELETE）一律返回 {@code true}，因此本声明<strong>不会</strong>让任何写操作跳过授权校验。
   */
  public boolean targetBindingsDeclared() {
    return targetBound;
  }

  @Override
  public void validateParams(Map<String, Object> params) {
    Map<String, Object> safe = params == null ? Map.of() : params;
    for (String variable : pathVariables) {
      Object value = safe.get(variable);
      if (value == null || value.toString().isBlank()) {
        throw new ApiException("端点 " + method + " " + pathTemplate + " 缺少路径参数: " + variable);
      }
      String text = value.toString();
      if (text.contains("/") || text.contains("..") || text.contains("\\") || text.contains("%")) {
        throw new ApiException("端点路径参数 " + variable + " 含非法字符: " + text);
      }
      if (isTargetVariable(variable)) {
        requirePositiveInteger(value, "路径参数 " + variable);
      }
    }
    if (targetBound && !declaresTargetPathVariable()) {
      Object targetId = safe.get(TARGET_ID_KEY);
      if (targetId == null) {
        throw new ApiException(
            "端点 " + method + " " + pathTemplate + " 未提供 targetId，无法通过授权校验（fail-closed）");
      }
      requirePositiveInteger(targetId, TARGET_ID_KEY);
    }
  }

  private static void requirePositiveInteger(Object value, String label) {
    if (value instanceof Number number) {
      if (number.longValue() > 0) return;
      throw new ApiException(label + " 必须为正整数: " + value);
    }
    String text = value.toString().trim();
    if (text.matches("\\d{1,18}") && Long.parseLong(text) > 0) {
      return;
    }
    throw new ApiException(label + " 必须为正整数: " + value);
  }

  // ---------------------------------------------------------------- 端点信息

  /** HTTP 方法（大写）。 */
  public String method() {
    return method;
  }

  /** 路径模板，如 {@code /api/targets/{targetId}/discovered-paths}。 */
  public String pathTemplate() {
    return pathTemplate;
  }

  /** 路径模板中的变量名（按出现顺序）。 */
  public List<String> pathVariables() {
    return pathVariables;
  }

  /** 该端点是否可能触及授权目标（即 {@link #targetBindings} 是否返回哨兵）。 */
  public boolean isTargetBound() {
    return targetBound;
  }

  /** 路径参数名是否就是授权目标 ID（{@code targetId} / {@code target_id}）。 */
  static boolean isTargetVariable(String variable) {
    if (variable == null) return false;
    return variable.trim().toLowerCase(Locale.ROOT).replace("_", "").equals(TARGET_ID_KEY.toLowerCase(Locale.ROOT));
  }

  /** 路径模板里是否已经显式声明了授权目标参数。 */
  private boolean declaresTargetPathVariable() {
    for (String variable : pathVariables) {
      if (isTargetVariable(variable)) {
        return true;
      }
    }
    return false;
  }

  /** 人工校准后的风险等级是否覆盖了推断值（供审计与报告使用）。 */
  public EndpointCapability withRisk(RiskLevel overriddenRisk, boolean overriddenApproval) {
    return new EndpointCapability(
        method, pathTemplate, kind, overriddenRisk, overriddenApproval, targetBound, handlerDescription);
  }

  @Override
  public String toString() {
    return method + " " + pathTemplate + " [" + code + ", " + risk + "]";
  }
}
