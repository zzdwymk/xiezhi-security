package com.bachelor.toolbox.ai.endpoint;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.capability.TargetIdExtractor;
import com.bachelor.toolbox.common.ApiException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * {@code invoke_endpoint} 通用端点原语（设计文档 §4.2 路线 C、§6.5）。
 *
 * <p>这是"完全调用项目各个功能"的兜底：即使某个端点没有被手工封装或自动派生为独立能力，Agent 仍可通过它触达。但它同时是
 * <strong>最大的绕过风险点</strong>，因此本类实现 §6.5 的三重约束，并额外提供第四重（参数结构校验）。
 *
 * <h2>核心思想：不是特权通道，而是"反查能力并套用同等治理"</h2>
 *
 * <p>{@code invoke_endpoint} 的 {@link #risk()}、{@link #requiresApproval()} 与
 * {@link #targetBindings(Map)} <strong>不是固定的</strong>，而是每次调用时按目标端点反查底层能力后动态给出：
 *
 * <ul>
 *   <li>{@link #riskFor(String, String)} —— 取底层能力的风险等级
 *   <li>{@link #requiresApprovalFor(String, String)} —— 取底层能力的确认要求
 *   <li>{@link #targetBindings(Map)} —— <strong>深度解析</strong>参数中的真实目标 ID；
 *       解析不出时返回 {@link #TARGET_BINDING_UNRESOLVED} 哨兵（fail-closed）
 * </ul>
 *
 * <p>这样护栏对"直接调用 {@code POST /api/system/shutdown}"与"通过 {@code invoke_endpoint} 调用
 * {@code POST /api/system/shutdown}"给出<strong>完全一致</strong>的判定。若本类硬编码一个较低的 {@link RiskLevel}
 * （例如 SAFE），它就真的成了绕过通道。
 *
 * <h2>三重约束（§6.5）</h2>
 *
 * <ol>
 *   <li><b>端点白名单校验</b>：{@link EndpointRegistry#contains} 必须为真，否则拒绝"未知端点"。
 *   <li><b>反向能力映射</b>：{@link EndpointRegistry#capabilityFor} 取回底层能力，{@link CapabilityRegistry#isBlocked}
 *       为真则拒绝"该端点被禁止"。
 *   <li><b>路径规范化</b>：{@link PathNormalizer#normalize} 必须成功，且<strong>规范化结果必须与输入完全相等</strong>，
 *       否则拒绝"非法路径"（防 {@code ../}、{@code %2e%2e}、{@code //} 等解析差异绕过）。
 * </ol>
 *
 * <h2>第四重（本实现新增，如实记录为与设计文档的偏差）</h2>
 *
 * <p>文档未要求，但把三重约束与 {@link #targetBindings} 的哨兵语义接起来必须补上这一步：<b>三重约束只在调用
 * {@link #validateParams} 时执行，而护栏是先看 {@code targetBindings} 再校验参数的</b>。若校验只在
 * {@code validateParams} 里做，一个"参数里没有 {@code method}/{@code path}"的畸形调用仍会走到护栏，此时无法证明端点已注册，
 * 返回哨兵是正确的（fail-closed 拒绝）。{@link #validateParams} 因此承担"三重约束的可证明性检查"，并额外要求
 * {@code method}/{@code path} 均为非空字符串，使任何调用都能被明确判定，而不是落入"无法判定"的灰区。
 *
 * <h2>{@code targetBindings} 的语义（P1-4 修复后）</h2>
 *
 * <p>本原语的参数结构任意（{@code method}/{@code path}/{@code body}/{@code query}，其中 body 与 query 是自由 JSON），
 * 目标可能藏在 body 的任意嵌套字段、query 的任意键、或顶层 {@code targetId}。
 *
 * <p><strong>修复前</strong>：恒返回哨兵 → 护栏 L-A 无条件拒绝 → 本原语对<em>一切</em>调用都不可用，
 * 且因 L-A 在 L-C' 之前而<strong>使 L-C' 成为死代码</strong>。
 *
 * <p><strong>修复后</strong>：用 {@link TargetIdExtractor#extractDeep} 在<strong>任意嵌套层级</strong>采集
 * <em>所有</em> {@code targetId}/{@code targetIds} 键，从而消除"部分解析"的风险（原注释的顾虑）。
 *
 * <p>仍然保持 fail-closed：<strong>解析不出任何目标时返回哨兵</strong>（护栏拒绝），
 * <strong>绝不返回空集</strong>——空集意味着宣称"不触及目标"，会让护栏跳过 L-A（fail-open）。
 *
 * <p>为什么"解析不出"是合法的拒绝理由：本原语的参数结构无法静态证明"该端点不触及目标"，
 * 因此无法安全声明 {@code NONE}。只读端点应改用<strong>具体能力</strong>调用（它们能正确声明 NONE）。
 */
public final class InvokeEndpointCapability implements AgentCapability {

  /** 能力码，与设计文档 §4.2 路线 C 的 {@code invoke_endpoint} 一致。 */
  public static final String CODE = "invoke_endpoint";

  /** 参数名：HTTP 方法。 */
  public static final String PARAM_METHOD = "method";

  /** 参数名：端点路径。 */
  public static final String PARAM_PATH = "path";

  /** 参数名：请求体。 */
  public static final String PARAM_BODY = "body";

  /** 参数名：查询参数。 */
  public static final String PARAM_QUERY = "query";

  /** 允许的 HTTP 方法（与 {@link RiskInference} 的推断表一致）。 */
  public static final Set<String> ALLOWED_METHODS =
      Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE");

  /** 参数值长度上限，防止用超长 body/query 绕过日志与审计。 */
  private static final int MAX_PARAM_TEXT_LENGTH = 200_000;

  private final EndpointRegistry endpointRegistry;
  private final CapabilityRegistry capabilityRegistry;

  public InvokeEndpointCapability(
      EndpointRegistry endpointRegistry, CapabilityRegistry capabilityRegistry) {
    this.endpointRegistry = Objects.requireNonNull(endpointRegistry, "端点注册表不能为空");
    this.capabilityRegistry =
        Objects.requireNonNull(capabilityRegistry, "能力注册表不能为空");
  }

  // ---------------------------------------------------------------- 能力接口

  @Override
  public String code() {
    return CODE;
  }

  @Override
  public String displayName() {
    return "通用端点调用";
  }

  @Override
  public String description() {
    return "调用平台任意已注册的 REST 端点，作为能力完备性的兜底。"
        + "参数：method（HTTP 方法）、path（端点路径，须与平台注册的路径模板一致）、body（请求体对象）、query（查询参数对象）。"
        + "本原语不是特权通道：其风险等级、确认要求与授权校验与直接调用该端点完全一致，"
        + "端点必须已注册、不得命中黑名单、路径必须规范化；"
        + "护栏会深度解析参数中的 targetId 并做完整授权校验（端口、有效期、端点透传参数策略）；"
        + "解析不出目标时一律 fail-closed 拒绝并要求显式人工确认。";
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put(
        PARAM_METHOD,
        Map.of(
            "type", "string",
            "enum", List.copyOf(new java.util.TreeSet<>(ALLOWED_METHODS)),
            "description", "HTTP 方法，须为 GET/HEAD/POST/PUT/PATCH/DELETE 之一"));
    properties.put(
        PARAM_PATH,
        Map.of(
            "type", "string",
            "description",
            "端点路径，如 /api/audits 或 /api/workflow-runs/12；必须已注册且通过路径规范化（拒绝 ../、%2e%2e、// 等）"));
    properties.put(
        PARAM_BODY,
        Map.of(
            "type", "object",
            "description", "请求体 JSON 对象；无请求体的端点可省略",
            // P1-4 修复：必须显式允许任意键。
            // SchemaValidator 会递归检查 additionalProperties；若此处不声明为 true，
            // 根级的 "additionalProperties": false 会传递到 body 内部 → ENFORCE 模式下
            // 任何非空 body 都被判为"未声明属性"而拒绝，使 body 通道完全不可用。
            "additionalProperties", true));
    properties.put(
        PARAM_QUERY,
        Map.of(
            "type", "object",
            "description", "查询参数键值对；无查询参数的端点可省略",
            // 同上：query 的键由底层端点决定，无法静态枚举。
            "additionalProperties", true));
    return Map.of(
        "type", "object",
        "properties", Map.copyOf(properties),
        "required", List.of(PARAM_METHOD, PARAM_PATH),
        "additionalProperties", false);
  }

  /**
   * 本原语自身的静态风险等级。
   *
   * <p>返回 {@link RiskLevel#DESTRUCTIVE}：静态视角下本原语可达任意端点，必须按最高等级处理。真实调用时应改用
   * {@link #riskFor(String, String)} 取底层端点的等级——两者取较高者才安全，因此这里宁可高估。
   */
  @Override
  public RiskLevel risk() {
    return RiskLevel.DESTRUCTIVE;
  }

  @Override
  public CapabilityKind kind() {
    return CapabilityKind.EXECUTE;
  }

  /**
   * 本原语恒需人工确认。
   *
   * <p>理由：护栏无法从参数解析授权目标（见 {@link #targetBindings}），任何放行都建立在"未经验证的端点 + 未经验证的目标"
   * 之上。§6.6 把"对授权目标发起实际执行"与"不可逆操作"列为 {@code REQUIRED}，本原语可能两者兼具，故恒为
   * {@code true}。真实调用时 {@link #requiresApprovalFor(String, String)} 会取底层能力的判定，但返回值只可能更严。
   */
  @Override
  public boolean requiresApproval() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * <p><strong>P1-4 修复（2026-10-12）：从"恒返回哨兵"改为"深度解析真实目标"。</strong>
   *
   * <h2>修复前的问题（能力归零 + L-C' 死代码）</h2>
   *
   * <p>原实现恒返回 {@code Set.of(TARGET_BINDING_UNRESOLVED)}，导致：
   *
   * <ol>
   *   <li>护栏 L-A 的哨兵分支<strong>无条件拒绝</strong> → 本原语对<em>一切</em>调用（含只读）都不可用
   *   <li>由于 L-A 在 L-C' 之前，且 L-A 必然抛异常 → <strong>L-C' 成为死代码</strong>，
   *       X-7 的修复（端点透传参数策略）<strong>永不执行</strong>
   * </ol>
   *
   * <h2>原注释的顾虑，以及为什么现在能解决</h2>
   *
   * <p>原文写道："即便解析成功，也只能覆盖'目标恰好写在顶层 targetId 键'这一种写法，而 body/query 是自由 JSON，
   * 目标可能在任意嵌套位置。部分解析出的目标集合会让护栏以为'已校验完毕'而放行其余目标，比完全解析不出更危险。"
   *
   * <p><strong>这个顾虑是对的</strong>——"部分解析"确实危险。解决办法不是"不解析"，而是
   * <strong>深度解析</strong>（{@link TargetIdExtractor#extractDeep}）：在任意嵌套层级采集
   * <em>所有</em> {@code targetId}/{@code targetIds} 键，从而消除"漏掉某个嵌套目标"的风险。
   *
   * <h2>fail-closed 语义保持不变</h2>
   *
   * <p>深度解析后<strong>仍然解析不出</strong>任何目标时，依旧返回哨兵 → 护栏拒绝。
   * <strong>绝不返回空集</strong>——空集意味着"宣称不触及目标"，会让护栏跳过 L-A（fail-open）。
   *
   * <p>为什么"解析不出"是合法的拒绝理由：本原语的参数结构无法静态证明"该端点不触及目标"，
   * 因此无法安全地声明 {@code NONE}。只读端点应改用<strong>具体能力</strong>调用（它们能正确声明 NONE）。
   */
  @Override
  public Set<String> targetBindings(Map<String, Object> params) {
    Map<String, Object> safe = params == null ? Map.of() : params;
    Set<String> ids = new LinkedHashSet<>();
    // 深度解析：body/query 是自由 JSON，目标可能藏在任意嵌套层级。
    ids.addAll(TargetIdExtractor.extractDeep(safe.get(PARAM_BODY)));
    ids.addAll(TargetIdExtractor.extractDeep(safe.get(PARAM_QUERY)));
    // 兼容顶层直接传 targetId（以及 body/query 之外的键）。
    ids.addAll(TargetIdExtractor.extractDeep(safe));
    if (ids.isEmpty()) {
      // 解析不出 → 仍 fail-closed（保持原语义，绝不返回空集冒充"不触及目标"）。
      return Set.of(TARGET_BINDING_UNRESOLVED);
    }
    return Set.copyOf(ids);
  }

  /**
   * 参数校验：§6.5 三重约束 + 第四重结构校验。
   *
   * <p>任何一条不满足都抛 {@link ApiException}，绝不静默放行。
   */
  @Override
  public void validateParams(Map<String, Object> params) {
    Map<String, Object> safe = params == null ? Map.of() : params;

    // ---- 第四重：参数结构必须完整，否则三重约束无法被证明
    Object rawMethod = safe.get(PARAM_METHOD);
    Object rawPath = safe.get(PARAM_PATH);
    if (rawMethod == null || rawMethod.toString().isBlank()) {
      throw new ApiException("invoke_endpoint 缺少参数 " + PARAM_METHOD + "，无法确定端点（fail-closed）");
    }
    if (rawPath == null || rawPath.toString().isBlank()) {
      throw new ApiException("invoke_endpoint 缺少参数 " + PARAM_PATH + "，无法确定端点（fail-closed）");
    }
    String method = RiskInference.normalizeMethod(rawMethod.toString());
    String path = rawPath.toString();
    if (!ALLOWED_METHODS.contains(method)) {
      throw new ApiException("invoke_endpoint 不支持的 HTTP 方法: " + rawMethod);
    }
    if (path.length() > PathNormalizer.MAX_LENGTH) {
      throw new ApiException("invoke_endpoint 路径过长");
    }
    if (safe.get(PARAM_BODY) != null && !(safe.get(PARAM_BODY) instanceof Map)) {
      throw new ApiException("invoke_endpoint 参数 " + PARAM_BODY + " 必须是 JSON 对象");
    }
    if (safe.get(PARAM_QUERY) != null && !(safe.get(PARAM_QUERY) instanceof Map)) {
      throw new ApiException("invoke_endpoint 参数 " + PARAM_QUERY + " 必须是 JSON 对象");
    }
    if (safe.get(PARAM_QUERY) instanceof Map<?, ?> query) {
      for (Map.Entry<?, ?> entry : query.entrySet()) {
        if (entry.getKey() == null) {
          throw new ApiException("invoke_endpoint 查询参数名不能为空");
        }
        if (entry.getValue() != null
            && entry.getValue().toString().length() > MAX_PARAM_TEXT_LENGTH) {
          throw new ApiException("invoke_endpoint 查询参数 " + entry.getKey() + " 取值过长");
        }
      }
    }

    // ---- 第三重：路径规范化（先做，避免把畸形路径拿去匹配注册表）
    String normalized;
    try {
      normalized = PathNormalizer.normalize(path);
    } catch (PathNormalizer.InvalidEndpointPathException error) {
      throw new ApiException("invoke_endpoint 拒绝非法路径：" + error.getMessage());
    }
    if (!normalized.equals(path)) {
      // PathNormalizer 对合法输入恒等返回；这条断言是第二道防线，防止未来有人给它加上"改写"逻辑。
      throw new ApiException("invoke_endpoint 拒绝需要改写的路径（规范化前后不一致）: " + path);
    }

    // ---- 第一重：端点白名单校验
    if (!endpointRegistry.contains(method, normalized)) {
      throw new ApiException("invoke_endpoint 拒绝未知端点: " + method + " " + normalized);
    }

    // ---- 第二重：反向能力映射 + 黑名单
    AgentCapability underlying = requireUnderlying(method, normalized);
    if (capabilityRegistry.isBlocked(underlying)) {
      throw new ApiException(
          "invoke_endpoint 拒绝被禁止的端点: " + method + " " + normalized
              + "（底层能力 " + underlying.code() + " 命中黑名单）");
    }
    // 底层能力自身的参数校验也要跑一遍，保证"经原语调用"与"直接调用"的准入条件一致。
    underlying.validateParams(underlyingParams(safe));
  }

  // ---------------------------------------------------------------- 动态治理策略

  /**
   * 取本次调用应使用的风险等级：<strong>本原语静态等级与底层端点等级取较高者</strong>。
   *
   * <p>取较高者而不是直接取底层值，是因为本原语自身可达任意端点，静态上必须按最高等级对待；同时底层端点的等级也不能被稀释。
   *
   * @param method HTTP 方法
   * @param path 端点路径（须已规范化）
   * @return 生效的风险等级；端点未注册时返回 {@link RiskLevel#DESTRUCTIVE}（fail-closed）
   */
  public RiskLevel riskFor(String method, String path) {
    return endpointRegistry
        .capabilityFor(method, path)
        .map(underlying -> max(risk(), underlying.risk()))
        .orElse(RiskLevel.DESTRUCTIVE);
  }

  /**
   * 取本次调用是否需人工确认：<strong>本原语恒需确认，或底层端点需确认</strong>。
   *
   * @param method HTTP 方法
   * @param path 端点路径（须已规范化）
   * @return 是否需要确认；端点未注册时返回 {@code true}（fail-closed）
   */
  public boolean requiresApprovalFor(String method, String path) {
    if (requiresApproval()) {
      return true;
    }
    return endpointRegistry
        .capabilityFor(method, path)
        .map(AgentCapability::requiresApproval)
        .orElse(true);
  }

  /**
   * 反向映射取底层能力（§6.5 第二重约束）。
   *
   * @throws ApiException 端点未注册时抛出
   */
  public AgentCapability requireUnderlying(String method, String path) {
    return endpointRegistry
        .capabilityFor(method, path)
        .<AgentCapability>map(capability -> capability)
        .orElseThrow(
            () ->
                new ApiException(
                    "invoke_endpoint 拒绝未知端点: "
                        + RiskInference.normalizeMethod(method)
                        + " "
                        + path));
  }

  /** 端点是否可经本原语调用（三重约束全部通过）。供上层做"可达性预检"而不实际执行。 */
  public boolean isReachable(String method, String path) {
    try {
      validateParams(Map.of(PARAM_METHOD, method, PARAM_PATH, path));
      return true;
    } catch (ApiException error) {
      return false;
    }
  }

  /** 同上，但额外带上授权目标 ID，用于 target-bound 端点的可达性预检。 */
  public boolean isReachable(String method, String path, int targetId) {
    try {
      validateParams(
          Map.of(PARAM_METHOD, method, PARAM_PATH, path, "targetId", targetId));
      return true;
    } catch (ApiException error) {
      return false;
    }
  }

  /** 本次调用被拒绝的原因；可调用时返回空。用于审计与人工确认界面展示。 */
  public Optional<String> rejectionReason(String method, String path) {
    try {
      validateParams(Map.of(PARAM_METHOD, method, PARAM_PATH, path));
      return Optional.empty();
    } catch (ApiException error) {
      return Optional.of(error.getMessage());
    }
  }

  /** 底层端点能力（若已注册）。 */
  public Optional<EndpointCapability> underlyingEndpoint(String method, String path) {
    return endpointRegistry.capabilityFor(method, path);
  }

  /** 底层能力的治理策略摘要，供护栏与审计使用。 */
  public Map<String, Object> governanceSnapshot(String method, String path) {
    Map<String, Object> snapshot = new LinkedHashMap<>();
    String normalizedMethod = RiskInference.normalizeMethod(method);
    snapshot.put("method", normalizedMethod);
    snapshot.put("path", path);
    Optional<EndpointCapability> underlying = endpointRegistry.capabilityFor(normalizedMethod, path);
    snapshot.put("registered", underlying.isPresent());
    snapshot.put("risk", riskFor(normalizedMethod, path).name());
    snapshot.put("requiresApproval", requiresApprovalFor(normalizedMethod, path));
    underlying.ifPresent(
        endpoint -> {
          snapshot.put("underlyingCode", endpoint.code());
          snapshot.put("underlyingRisk", endpoint.risk().name());
          snapshot.put("underlyingRequiresApproval", endpoint.requiresApproval());
          snapshot.put("blocked", capabilityRegistry.isBlocked(endpoint));
        });
    snapshot.put("targetBindings", List.copyOf(targetBindings(Map.of())));
    return Map.copyOf(snapshot);
  }

  // ---------------------------------------------------------------- 内部实现

  /**
   * 把 {@code invoke_endpoint} 的参数投影为底层能力的参数。
   *
   * <p>投影规则（顺序即优先级，先到先得）：
   *
   * <ol>
   *   <li>{@code body} 中的键提升到顶层——底层端点能力（如要求 {@code targetId} 的写操作）据此校验
   *   <li>{@code query} 中的键补充——已在 body 中出现的键不覆盖
   *   <li>调用参数自身的顶层键（{@code targetId}、路径参数等）补充——这是调用方最直接的写法，
   *       必须能传递到底层能力，否则"经原语调用"会比"直接调用"更容易通过，形成绕过
   *   <li>最后写入 {@code method}/{@code path}，兼容底层能力读取这两个键的情况
   * </ol>
   */
  private static Map<String, Object> underlyingParams(Map<String, Object> params) {
    Map<String, Object> projected = new LinkedHashMap<>();
    if (params.get(PARAM_BODY) instanceof Map<?, ?> body) {
      body.forEach(
          (key, value) -> {
            if (key != null) {
              projected.put(key.toString(), value);
            }
          });
    }
    if (params.get(PARAM_QUERY) instanceof Map<?, ?> query) {
      query.forEach(
          (key, value) -> {
            if (key != null) {
              projected.putIfAbsent(key.toString(), value);
            }
          });
    }
    // 顶层键（body/query 之外的参数）同样要投影，否则调用方把 targetId 写在顶层时底层能力看不到。
    params.forEach(
        (key, value) -> {
          if (key != null
              && !PARAM_BODY.equals(key)
              && !PARAM_QUERY.equals(key)
              && !PARAM_METHOD.equals(key)
              && !PARAM_PATH.equals(key)) {
            projected.putIfAbsent(key, value);
          }
        });
    projected.put(PARAM_METHOD, params.get(PARAM_METHOD));
    projected.put(PARAM_PATH, params.get(PARAM_PATH));
    return projected;
  }

  private static RiskLevel max(RiskLevel left, RiskLevel right) {
    return left.ordinal() >= right.ordinal() ? left : right;
  }

  /** 便于日志与审计：单行描述本次调用意图。 */
  public String describeIntent(Map<String, Object> params) {
    if (params == null) {
      return "invoke_endpoint (无参数)";
    }
    return "invoke_endpoint "
        + RiskInference.normalizeMethod(Objects.toString(params.get(PARAM_METHOD), ""))
        + " "
        + Objects.toString(params.get(PARAM_PATH), "");
  }

  /** 参数名常量的只读视图，便于护栏与提示词构建复用。 */
  public static Set<String> parameterNames() {
    return Set.of(PARAM_METHOD, PARAM_PATH, PARAM_BODY, PARAM_QUERY);
  }

  /** 方法名规范化入口，避免调用方各自实现。 */
  public static String normalizeMethod(String method) {
    return method == null ? "" : method.trim().toUpperCase(Locale.ROOT);
  }
}
