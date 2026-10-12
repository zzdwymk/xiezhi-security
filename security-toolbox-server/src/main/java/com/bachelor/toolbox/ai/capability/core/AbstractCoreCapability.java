package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.guard.TargetBindingProbe;
import com.bachelor.toolbox.common.ApiException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 手工封装能力的公共基类（设计文档 §4.2 路线 A）。
 *
 * <h2>本类解决的三个具体问题</h2>
 *
 * <ol>
 *   <li><strong>目标绑定的三态语义必须"默认 fail-closed"</strong>。{@link AgentCapability#targetBindings(Map)} 的接口默认实现
 *       返回空集，而空集在三态语义里等于"我确实不触及任何目标 → 跳过 L-A 授权校验"。任何子类忘记覆写就等于开了一个
 *       fail-open 通道（设计文档 §4.1.1 记录的真实缺陷）。因此本基类把三态做成<strong>显式的、必须选择的构造参数</strong>，
 *       而不是"记得覆写某个方法"。
 *   <li><strong>空集需要类型级声明</strong>。护栏只认显式声明为"不触及目标"的空集（{@link TargetBindingProbe}）。本类实现
 *       {@link TargetBindingProbe.TargetBindingDeclaration}，把 {@link BindingMode} 映射成护栏能读懂的 {@code NONE} /
 *       {@code REQUIRED}，避免依赖反射猜方法名。
 *   <li><strong>参数解析逻辑必须只有一份</strong>。目标 ID 的写法五花八门（{@code targetId} / {@code target_id} /
 *       {@code targetIds} / 数字字符串 / 集合），如果每个能力各写一遍，迟早出现"某个能力少认一种写法 → 解析不到目标 →
 *       返回哨兵 → 误拦"或更糟的"解析出一部分目标就以为校验完了"。这里统一实现。
 * </ol>
 *
 * <h2>三态语义与护栏行为（务必逐条对齐）</h2>
 *
 * <table border="1">
 *   <caption>{@link BindingMode} 与护栏 L-A 的对应关系</caption>
 *   <tr><th>{@link BindingMode}</th><th>{@code targetBindings} 返回</th><th>护栏 L-A 行为</th></tr>
 *   <tr><td>{@link BindingMode#NONE}</td><td>真空集（恒）</td><td>跳过授权校验（仅当显式声明时合法）</td></tr>
 *   <tr><td>{@link BindingMode#RESOLVED}</td><td>参数里解析出的真实 targetId 集合；解析不到 → 哨兵</td>
 *       <td>逐个校验范围/端口/有效期；解析不到则 fail-closed 拒绝</td></tr>
 *   <tr><td>{@link BindingMode#UNRESOLVED}</td><td>恒返回哨兵 {@code __UNRESOLVED__}</td>
 *       <td><strong>恒 fail-closed 拒绝</strong></td></tr>
 * </table>
 *
 * <h2>{@link BindingMode#UNRESOLVED} 不是"偷懒"，而是正确声明</h2>
 *
 * <p>{@code bash_probe}、{@code search_capabilities}、{@code unlock_capability} 的参数结构无法静态保证解析出目标
 * （命令字符串里可以出现任意主机名与 IP；搜索关键词更与目标无关）。这类能力若返回空集，等于告诉护栏"不需要授权校验"——
 * 那是 fail-open。返回哨兵后护栏会拒绝，再由人工确认流程兜底：<strong>拒绝是正确结论，放行才是缺陷</strong>。
 *
 * <h2>装配约定（task-3 实测的硬约束）</h2>
 *
 * <p>本包的全部能力都是独立的 {@code @Component}，<strong>绝不</strong>包成 {@code @Bean List<AgentCapability>} 提交：
 * Spring 对 {@code List<T>} 构造注入只汇总"类型为 {@code T} 的独立 Bean"，不会展开集合 Bean，打包提交会让 25 个能力
 * <strong>静默丢失且单元测试全绿</strong>（设计文档附录 D.4 的 6 种装配方式实测对照表）。
 */
public abstract class AbstractCoreCapability
    implements AgentCapability, TargetBindingProbe.TargetBindingDeclaration {

  /** 目标绑定模式。 */
  public enum BindingMode {
    /**
     * 确实不触及任何授权目标 → 恒返回真空集。
     *
     * <p>只允许用于"按项目/平台维度检索"的只读能力。用于任何会触及目标的能力都是 fail-open 缺陷。
     */
    NONE,

    /**
     * 会触及授权目标，且能从参数解析出目标 ID → 返回真实 ID 集合；解析不到时返回哨兵（fail-closed）。
     *
     * <p>这是绝大多数能力应该选的模式，包括 {@code kind = WRITE} 但会创建"扫描目标的任务"的
     * <strong>间接执行类</strong>能力（{@code create_task} / {@code run_workflow}）——按 {@code kind} 判定授权正是 §6.2
     * 要修正的错误。
     */
    RESOLVED,

    /**
     * 参数结构任意，无法静态保证解析出目标 → 恒返回哨兵，由护栏 fail-closed 拒绝。
     *
     * <p>用于 {@code bash_probe} / {@code search_capabilities} / {@code unlock_capability}。
     */
    UNRESOLVED
  }

  /** 参数中承载授权目标 ID 的键名（大小写与下划线不敏感）。 */
  private static final Set<String> TARGET_KEYS = Set.of("targetid", "targetids", "targets");

  /** 只允许正整数的目标 ID。 */
  private static final Pattern DIGITS = Pattern.compile("\\d{1,18}");

  private final String code;
  private final String displayName;
  private final String description;
  private final CapabilityKind kind;
  private final RiskLevel risk;
  private final boolean requiresApproval;
  private final BindingMode bindingMode;
  private final AiCapabilityLayer layer;

  /**
   * @param code 能力码，全局唯一（重复注册会让 {@code CapabilityRegistry} 抛异常使应用启动失败）
   * @param displayName 中文名，用于人工确认界面
   * @param description 给 LLM 的自然语言描述，应说明用途与边界
   * @param kind 能力类别（<strong>不</strong>用于授权判定）
   * @param risk 风险等级
   * @param requiresApproval 是否需要人工确认
   * @param bindingMode 目标绑定模式，见 {@link BindingMode}
   * @param layer 分层标注，见 {@link AiCapabilityLayer}
   */
  protected AbstractCoreCapability(
      String code,
      String displayName,
      String description,
      CapabilityKind kind,
      RiskLevel risk,
      boolean requiresApproval,
      BindingMode bindingMode,
      AiCapabilityLayer layer) {
    this.code = requireText(code, "能力码");
    this.displayName = requireText(displayName, "能力名");
    this.description = requireText(description, "能力描述");
    this.kind = Objects.requireNonNull(kind, "能力类别不能为空");
    this.risk = Objects.requireNonNull(risk, "风险等级不能为空");
    this.requiresApproval = requiresApproval;
    this.bindingMode = Objects.requireNonNull(bindingMode, "目标绑定模式不能为空");
    this.layer = Objects.requireNonNull(layer, "能力分层不能为空");
  }

  // ---------------------------------------------------------------- 能力接口

  @Override
  public final String code() {
    return code;
  }

  @Override
  public final String displayName() {
    return displayName;
  }

  @Override
  public final String description() {
    return description;
  }

  @Override
  public final CapabilityKind kind() {
    return kind;
  }

  @Override
  public final RiskLevel risk() {
    return risk;
  }

  @Override
  public final boolean requiresApproval() {
    return requiresApproval;
  }

  /**
   * {@inheritDoc}
   *
   * <p>实现见 {@link #bindingMode} 的三态语义。本方法被 {@code final} 固定，子类无法"忘记覆写"或"覆写成空集"——
   * 目标绑定是本包唯一不允许子类自由发挥的部分。
   */
  @Override
  public final Set<String> targetBindings(Map<String, Object> params) {
    return switch (bindingMode) {
      case NONE -> Set.of();
      case UNRESOLVED -> Set.of(TARGET_BINDING_UNRESOLVED);
      case RESOLVED -> resolveBindings(params);
    };
  }

  /**
   * 类型级声明，供护栏 {@link TargetBindingProbe} 判定"空集是否合法"。
   *
   * <p>{@link BindingMode#NONE} → {@code NONE}（空集合法）；其余 → {@code REQUIRED}（空集非法，必须 fail-closed）。
   */
  @Override
  public final TargetBindingProbe.Declaration targetBindingDeclaration() {
    return bindingMode == BindingMode.NONE
        ? TargetBindingProbe.Declaration.NONE
        : TargetBindingProbe.Declaration.REQUIRED;
  }

  @Override
  public void validateParams(Map<String, Object> params) {
    Map<String, Object> safe = params == null ? Map.of() : params;
    if (bindingMode == BindingMode.RESOLVED) {
      // 解析不到目标时提前给出可读的错误，而不是让护栏报一句笼统的"无法解析授权目标"。
      if (targetBindings(safe).contains(TARGET_BINDING_UNRESOLVED)) {
        throw new ApiException(
            "能力 " + code + " 缺少授权目标 ID（" + targetIdKeyHint() + "），无法通过授权校验（fail-closed）");
      }
    }
    validateCoreParams(safe);
  }

  /** 子类实现自身参数校验（互斥参数、取值范围等）；默认不做任何检查。 */
  protected void validateCoreParams(Map<String, Object> params) {}

  // ---------------------------------------------------------------- 分层与绑定信息

  /** 能力分层（§5）。<strong>仅供提示词构建与展示</strong>，不参与任何授权判定。 */
  public final AiCapabilityLayer layer() {
    return layer;
  }

  /** 目标绑定模式。 */
  public final BindingMode bindingMode() {
    return bindingMode;
  }

  /** 该能力是否需要显式携带授权目标 ID 才能通过护栏。 */
  public final boolean requiresTargetBinding() {
    return bindingMode != BindingMode.NONE;
  }

  // ---------------------------------------------------------------- 参数解析工具

  /** 参数里要求的能力码提示（错误信息用）。 */
  protected String targetIdKeyHint() {
    return "targetId";
  }

  /** 解析三态中的 {@link BindingMode#RESOLVED} 一态。 */
  private Set<String> resolveBindings(Map<String, Object> params) {
    Set<String> bound = collectTargetIds(params);
    if (bound.isEmpty()) {
      // 应触及目标但解析不到 → 交给护栏 fail-closed。绝不能返回空集冒充"不触及目标"。
      return Set.of(TARGET_BINDING_UNRESOLVED);
    }
    return Set.copyOf(bound);
  }

  /**
   * 从参数中收集全部授权目标 ID。
   *
   * <p>识别 {@code targetId} / {@code target_id} / {@code targetIds} / {@code target_ids} / {@code targets}
   * 五种写法；值可以是数字、数字字符串、逗号/分号/空白分隔的字符串、集合或数组。
   *
   * <p><strong>返回全部能解析出的 ID，而不是第一个</strong>：多目标调用必须逐个过授权校验，只取第一个会让其余目标
   * 静默绕过 L-A。
   */
  public static Set<String> collectTargetIds(Map<String, Object> params) {
    Set<String> bound = new LinkedHashSet<>();
    if (params == null) {
      return bound;
    }
    for (Map.Entry<String, Object> entry : params.entrySet()) {
      if (isTargetKey(entry.getKey())) {
        collectInto(entry.getValue(), bound);
      }
    }
    return bound;
  }

  /** 键名是否为授权目标 ID（大小写、下划线不敏感）。 */
  public static boolean isTargetKey(String key) {
    if (key == null) {
      return false;
    }
    String normalized = key.trim().toLowerCase(Locale.ROOT).replace("_", "");
    return TARGET_KEYS.contains(normalized);
  }

  /** 把任意形态的目标 ID 值递归收集进 {@code sink}。 */
  public static void collectInto(Object value, Collection<String> sink) {
    if (value == null) {
      return;
    }
    if (value instanceof Collection<?> collection) {
      for (Object item : collection) {
        collectInto(item, sink);
      }
      return;
    }
    if (value instanceof Object[] array) {
      for (Object item : array) {
        collectInto(item, sink);
      }
      return;
    }
    if (value instanceof Number number) {
      long id = number.longValue();
      if (id > 0) {
        sink.add(Long.toString(id));
      }
      return;
    }
    String text = value.toString().trim();
    if (text.isEmpty()) {
      return;
    }
    if (DIGITS.matcher(text).matches()) {
      long id = Long.parseLong(text);
      if (id > 0) {
        sink.add(Long.toString(id));
      }
      return;
    }
    for (String part : text.split("[,;\\s]+")) {
      String item = part.trim();
      if (DIGITS.matcher(item).matches() && Long.parseLong(item) > 0) {
        sink.add(Long.toString(Long.parseLong(item)));
      }
    }
  }

  /** 取正整数参数；缺失或非法时抛 {@link ApiException}。 */
  protected static long requirePositiveLong(Map<String, Object> params, String key) {
    Object value = params.get(key);
    if (value == null) {
      throw new ApiException("缺少参数 " + key);
    }
    long parsed;
    if (value instanceof Number number) {
      parsed = number.longValue();
    } else {
      String text = value.toString().trim();
      if (!DIGITS.matcher(text).matches()) {
        throw new ApiException("参数 " + key + " 必须为正整数: " + value);
      }
      parsed = Long.parseLong(text);
    }
    if (parsed <= 0) {
      throw new ApiException("参数 " + key + " 必须为正整数: " + value);
    }
    return parsed;
  }

  /**
   * 取可选正整数参数；缺失时返回 {@code null}。
   *
   * <p><strong>注意</strong>：本方法把 {@code 0} 与负数折叠成 {@code null}（"等同缺失"）。对"缺失即取默认值"的
   * 场景这是合理的，但对<strong>必须拒绝非法取值</strong>的场景是 fail-open——调用方写了 {@code 0} 却被静默替换成默认值，
   * 用户以为"不限时/立即超时"，实际得到的是 30 秒。
   *
   * <p>这类场景请改用 {@link #optionalStrictPositiveInt}。
   */
  protected static Long optionalPositiveLong(Map<String, Object> params, String key) {
    Object value = params.get(key);
    if (value == null) {
      return null;
    }
    if (value instanceof Number number) {
      return number.longValue() > 0 ? number.longValue() : null;
    }
    String text = value.toString().trim();
    if (text.isEmpty()) {
      return null;
    }
    if (!DIGITS.matcher(text).matches()) {
      throw new ApiException("参数 " + key + " 必须为正整数: " + value);
    }
    long parsed = Long.parseLong(text);
    return parsed > 0 ? parsed : null;
  }

  /**
   * 取可选正整数参数，<strong>严格模式</strong>：缺失返回 {@code null}，但"给了值却不合法"（0、负数、非数字）
   * <strong>抛异常拒绝</strong>，不折叠成默认值。
   *
   * <p>为什么需要与 {@link #optionalPositiveLong} 并存：两者对"非法取值"的处理不同，而这个差异是安全相关的。
   *
   * <p>本任务实测踩到过这个坑：{@code bash_probe} 的 {@code timeoutSeconds} 用宽松版解析，
   * 于是调用方传 {@code timeoutSeconds: 0} 时被静默替换成默认 30 秒——用户以为自己表达了"立即超时"，
   * 实际得到 30 秒的执行窗口。这类"参数被静默改写"属于 fail-open：护栏以为约束已生效，实际生效的是另一个值。
   *
   * <p>判据：只要该参数的<strong>取值本身参与安全约束</strong>（超时、并发数、条数上限），就必须用严格版。
   */
  protected static Integer optionalStrictPositiveInt(Map<String, Object> params, String key) {
    Object value = params.get(key);
    if (value == null) {
      return null;
    }
    if (value instanceof Number number) {
      int parsed = number.intValue();
      if (parsed <= 0) {
        throw new ApiException("参数 " + key + " 必须为正整数: " + value);
      }
      return parsed;
    }
    String text = value.toString().trim();
    if (text.isEmpty()) {
      return null;
    }
    if (!DIGITS.matcher(text).matches()) {
      throw new ApiException("参数 " + key + " 必须为正整数: " + value);
    }
    long parsed = Long.parseLong(text);
    if (parsed <= 0 || parsed > Integer.MAX_VALUE) {
      throw new ApiException("参数 " + key + " 必须为正整数: " + value);
    }
    return (int) parsed;
  }

  /** 取必填文本参数（去空白）；缺失时抛 {@link ApiException}。 */
  protected static String requireText(Map<String, Object> params, String key) {    Object value = params.get(key);
    String text = value == null ? "" : value.toString().trim();
    if (text.isEmpty()) {
      throw new ApiException("缺少参数 " + key);
    }
    return text;
  }

  /** 取可选文本参数；缺失或空白时返回 {@code null}。 */
  protected static String optionalText(Map<String, Object> params, String key) {
    Object value = params.get(key);
    if (value == null) {
      return null;
    }
    String text = value.toString().trim();
    return text.isEmpty() ? null : text;
  }

  /** 取可选整数参数（允许 0 与负数语义由调用方判定）；缺失或非数字时返回 {@code fallback}。 */
  protected static int optionalInt(Map<String, Object> params, String key, int fallback) {
    Object value = params.get(key);
    if (value == null) {
      return fallback;
    }
    if (value instanceof Number number) {
      return number.intValue();
    }
    try {
      return Integer.parseInt(value.toString().trim());
    } catch (NumberFormatException ignored) {
      return fallback;
    }
  }

  /** 取可选布尔参数。 */
  protected static boolean optionalBoolean(Map<String, Object> params, String key, boolean fallback) {
    Object value = params.get(key);
    if (value == null) {
      return fallback;
    }
    if (value instanceof Boolean flag) {
      return flag;
    }
    String text = value.toString().trim().toLowerCase(Locale.ROOT);
    if (text.isEmpty()) {
      return fallback;
    }
    return "true".equals(text) || "1".equals(text) || "yes".equals(text);
  }

  /** 取可选字符串列表。 */
  protected static List<String> optionalStringList(Map<String, Object> params, String key) {
    Object value = params.get(key);
    if (value == null) {
      return List.of();
    }
    if (value instanceof Collection<?> collection) {
      List<String> result = new ArrayList<>();
      for (Object item : collection) {
        if (item != null && !item.toString().isBlank()) {
          result.add(item.toString().trim());
        }
      }
      return List.copyOf(result);
    }
    String text = value.toString().trim();
    if (text.isEmpty()) {
      return List.of();
    }
    List<String> result = new ArrayList<>();
    for (String part : text.split("[,;\\s]+")) {
      if (!part.isBlank()) {
        result.add(part.trim());
      }
    }
    return List.copyOf(result);
  }

  /** 取可选对象 Map 参数。 */
  protected static Map<String, Object> optionalMap(Map<String, Object> params, String key) {
    Object value = params.get(key);
    if (!(value instanceof Map<?, ?> map)) {
      return Map.of();
    }
    Map<String, Object> result = new LinkedHashMap<>();
    map.forEach(
        (k, v) -> {
          if (k != null) {
            result.put(k.toString(), v);
          }
        });
    return result;
  }

  // ---------------------------------------------------------------- schema 构建工具

  /** 构造一个 JSON Schema 属性描述。 */
  protected static Map<String, Object> property(String type, String description) {
    return Map.of("type", type, "description", description);
  }

  /** 构造一个带枚举取值的 JSON Schema 属性描述。 */
  protected static Map<String, Object> enumProperty(List<String> values, String description) {
    return Map.of("type", "string", "enum", List.copyOf(values), "description", description);
  }

  /** 构造一个带下界的整数属性描述。 */
  protected static Map<String, Object> integerProperty(long minimum, String description) {
    return Map.of("type", "integer", "minimum", minimum, "description", description);
  }

  /** 构造对象型 schema。 */
  protected static Map<String, Object> objectSchema(
      Map<String, Object> properties, List<String> required) {
    return Map.of(
        "type",
        "object",
        "properties",
        Map.copyOf(properties),
        "required",
        List.copyOf(required),
        "additionalProperties",
        false);
  }

  private static String requireText(String value, String label) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(label + "不能为空");
    }
    return value.trim();
  }

  @Override
  public String toString() {
    return code + " [" + kind + "/" + risk + ", " + layer + ", binding=" + bindingMode + "]";
  }
}
