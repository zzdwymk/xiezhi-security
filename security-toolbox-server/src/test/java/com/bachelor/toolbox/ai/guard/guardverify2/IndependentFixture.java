package com.bachelor.toolbox.ai.guard.guardverify2;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.capability.TargetIdExtractor;
import com.bachelor.toolbox.ai.endpoint.EndpointCapability;
import com.bachelor.toolbox.ai.endpoint.EndpointRegistry;
import com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability;
import com.bachelor.toolbox.ai.endpoint.RiskInference;
import com.bachelor.toolbox.ai.guard.ApprovalPolicy;
import com.bachelor.toolbox.ai.guard.CapabilityApprovalGrantResolver;
import com.bachelor.toolbox.ai.guard.CapabilityAuditSink;
import com.bachelor.toolbox.ai.guard.CapabilityBlacklist;
import com.bachelor.toolbox.ai.guard.CapabilityContext;
import com.bachelor.toolbox.ai.guard.CapabilityDeniedException;
import com.bachelor.toolbox.ai.guard.CapabilityGate;
import com.bachelor.toolbox.ai.guard.EndpointParameterPolicy;
import com.bachelor.toolbox.ai.guard.TargetBindingProbe;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Assertions;

/**
 * fix-verifier 的<strong>独立</strong>验证夹具（{@code guardverify2} 包）。
 *
 * <h2>为什么再写一个夹具，而不复用 {@code GuardSupport}</h2>
 *
 * <p>{@code GuardSupport} 是 Lead 为本轮修复写的夹具。独立复核的价值在于<strong>不继承实现者的装配假设</strong>——
 * 若 Lead 的夹具在某处"顺手关掉"了某个校验（例如 {@code fixture()} 用两参构造的
 * {@code EndpointParameterPolicy}，使 D-5 静默跳过），复用它会把这个假设一并继承，
 * 验证就退化成复述。
 *
 * <p>本夹具<strong>只依赖 {@code src/main} 的公开契约</strong>，从零装配护栏。
 *
 * <h2>核心纪律：拒绝必须可归因到「层 + 原因码」</h2>
 *
 * <p>本项目有真实教训——Lead 写 A-4 用例时连续两次"通过"了<strong>错误的层</strong>
 * （先撞 L-B {@code CAPABILITY_NOT_ENABLED}、再撞 L-C {@code INVALID_PARAMETER}）。
 * 若只写 {@code assertThrows}，那两次会一直显示"通过"却从未验证目标层。
 *
 * <p>因此 {@link #assertDeniedAt} <strong>同时</strong>锁定层与原因码，并让"抛了别的异常"与"根本没抛"都失败。
 */
final class IndependentFixture {

  private IndependentFixture() {}

  // ------------------------------------------------------------------ 目标

  /** 授权目标：默认 LAN 地址 + 有效窗口 + 启用。 */
  static AuthorizedTarget target(long id, String value, String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(id);
    target.setName("target-" + id);
    target.setTargetValue(value);
    target.setTargetType("IP");
    target.setAuthorizationNote("fix-verifier 独立验证");
    target.setAllowedPorts(allowedPorts);
    target.setEnabled(true);
    return target;
  }

  /** 端口为 80/443 的常规目标。 */
  static AuthorizedTarget webTarget(long id) {
    return target(id, "10.0.0.10", "80,443");
  }

  // ------------------------------------------------------------------ 装配

  /** 收集审计的内存实现（用于验证"拒绝也留痕"）。 */
  static final class RecordingAudit implements CapabilityAuditSink {
    final List<Map<String, Object>> denials = new ArrayList<>();
    final List<String> actions = new ArrayList<>();

    @Override
    public void record(String action, String code, Map<String, Object> detail, String result) {
      actions.add(action);
      if ("AGENT_CAPABILITY_DENIED".equals(action)) {
        denials.add(detail == null ? Map.of() : new LinkedHashMap<>(detail));
      }
    }

    boolean hasDenialReason(String reasonCode) {
      return denials.stream().anyMatch(d -> reasonCode.equals(d.get("deniedReason")));
    }
  }

  /** 装配结果。 */
  record Rig(CapabilityGate gate, CapabilityRegistry registry, RecordingAudit audit) {}

  /**
   * 装配一个护栏。
   *
   * @param capabilities 注册的能力
   * @param targets 可按 ID 解析的目标
   * @param whitelist 需显式开启的高危能力码（逗号分隔）
   * @param endpointPolicy 端点参数策略；{@code null} 表示<strong>真正不装配</strong>（L-C' 跳过）。
   *     若需要"默认装配但选择是否注入 TargetPolicyService"，请用
   *     {@link #rigWithDefaultPolicy(List, Map, String, boolean, CapabilityApprovalGrantResolver)}
   * @param grantResolver 按需授权凭据解析器；{@code null} 表示未装配
   * @param withTargetPolicyService 仅在 {@code endpointPolicy == null} 且
   *     {@code useDefaultPolicy} 为 true 时生效（见另一个重载）
   */
  static Rig rig(
      List<AgentCapability> capabilities,
      Map<Long, AuthorizedTarget> targets,
      String whitelist,
      EndpointParameterPolicy endpointPolicy,
      CapabilityApprovalGrantResolver grantResolver,
      boolean withTargetPolicyService) {
    return buildRig(
        capabilities, targets, whitelist, endpointPolicy, grantResolver, withTargetPolicyService, false);
  }

  /**
   * 与 {@link #rig} 相同，但 {@code endpointPolicy == null} 时<strong>装配一个默认策略</strong>。
   *
   * <p>用于需要"策略存在，但 TargetPolicyService 是否注入作为变量"的场景（D-5 对照实验）。
   */
  static Rig rigWithDefaultPolicy(
      List<AgentCapability> capabilities,
      Map<Long, AuthorizedTarget> targets,
      String whitelist,
      boolean withTargetPolicyService,
      CapabilityApprovalGrantResolver grantResolver) {
    return buildRig(
        capabilities, targets, whitelist, null, grantResolver, withTargetPolicyService, true);
  }

  private static Rig buildRig(
      List<AgentCapability> capabilities,
      Map<Long, AuthorizedTarget> targets,
      String whitelist,
      EndpointParameterPolicy endpointPolicy,
      CapabilityApprovalGrantResolver grantResolver,
      boolean withTargetPolicyService,
      boolean useDefaultPolicyWhenNull) {
    PortRangeParser portRangeParser = new PortRangeParser();
    TargetPolicyService targetPolicyService = new TargetPolicyService(false, portRangeParser);
    EndpointParameterPolicy policy = endpointPolicy;
    if (policy == null && useDefaultPolicyWhenNull) {
      policy =
          new EndpointParameterPolicy(
              portRangeParser, 65535, withTargetPolicyService ? targetPolicyService : null);
    }
    CapabilityRegistry registry = new CapabilityRegistry(capabilities, Set.of());
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        new CapabilityGate(
            registry,
            targetPolicyService,
            CapabilityBlacklist.defaults(),
            new ApprovalPolicy(),
            audit,
            targetId -> Optional.ofNullable(targets.get(targetId)),
            "warn",
            whitelist,
            "",
            policy,
            grantResolver);
    return new Rig(gate, registry, audit);
  }

  /** 便捷：不装配按需授权（{@code grantResolver == null}）。 */
  static Rig rig(
      List<AgentCapability> capabilities,
      Map<Long, AuthorizedTarget> targets,
      String whitelist,
      boolean withTargetPolicyService) {
    return rig(capabilities, targets, whitelist, null, null, withTargetPolicyService);
  }

  // ------------------------------------------------------------------ 断言（伪通过规则）

  /**
   * 断言调用在<strong>指定层</strong>被拒绝，且原因码精确匹配。
   *
   * <p>这是"伪通过"规则的执行点：只看"抛了异常"不够——必须证明拦下它的是<em>目标层</em>。
   */
  static CapabilityDeniedException assertDeniedAt(
      CapabilityDeniedException.Layer layer, String reasonCode, Runnable call) {
    CapabilityDeniedException error =
        Assertions.assertThrows(
            CapabilityDeniedException.class,
            call::run,
            "预期在 " + layer.label() + " 被拒绝，但没有抛出护栏拒绝异常（可能是放行了）");
    Assertions.assertEquals(
        layer,
        error.layer(),
        "【伪通过】拒绝层错误：预期 "
            + layer.label()
            + "，实际 "
            + error.layer().label()
            + "，原因码 "
            + error.reasonCode()
            + "，消息 "
            + error.getMessage());
    if (reasonCode != null) {
      Assertions.assertEquals(
          reasonCode,
          error.reasonCode(),
          "【伪通过】拒绝层对了（" + layer.label() + "）但原因码不符：预期 " + reasonCode + "，实际 " + error.reasonCode());
    }
    return error;
  }

  /** 对照组：断言调用<strong>未</strong>被护栏拒绝。 */
  static void assertAllowed(Runnable call) {
    assertAllowed(call, "对照组预期放行");
  }

  static void assertAllowed(Runnable call, String message) {
    try {
      call.run();
    } catch (CapabilityDeniedException denied) {
      Assertions.fail(
          message
              + "：被 "
              + denied.layer().label()
              + " 拒绝（"
              + denied.reasonCode()
              + "）："
              + denied.getMessage());
    }
  }

  /** 可变参数体。 */
  static Map<String, Object> params(Object... keyValues) {
    Map<String, Object> map = new LinkedHashMap<>();
    for (int i = 0; i + 1 < keyValues.length; i += 2) {
      map.put(String.valueOf(keyValues[i]), keyValues[i + 1]);
    }
    return map;
  }

  // ------------------------------------------------------------------ 能力桩

  /**
   * 参数驱动的能力桩：{@code targetBindings} 从 {@code params.targetId} 解析。
   *
   * <p>必须"参数驱动"才能构造出"已授权目标"与"未授权目标"的<strong>对照</strong>；
   * 返回固定绑定集的桩做不到这一点。
   *
   * <p><strong>层序注意事项</strong>：{@code ApprovalPolicy} 会把"触及目标 + 非 READ"的能力
   * 判为 {@code REQUIRED}。因此本桩的 {@code code} 刻意<strong>不含</strong>
   * scan/probe/exploit 等执行特征词，且 {@code requiresApproval()} 返回 {@code false}——
   * 这样调用会落到 L-A 判定，而不是被 L-B 的 {@code APPROVAL_REQUIRED} 提前拦下。
   * （这正是"要让某层生效必须先让更早的层放行"的实践。）
   */
  static class ParamsDrivenCapability implements AgentCapability {
    private final String code;
    private final CapabilityKind kind;
    private final RiskLevel risk;
    private final TargetBindingProbe.Declaration declaration;

    ParamsDrivenCapability(
        String code, CapabilityKind kind, RiskLevel risk, TargetBindingProbe.Declaration declaration) {
      this.code = code;
      this.kind = kind;
      this.risk = risk;
      this.declaration = declaration;
    }

    /** 常规执行类能力：显式声明"应触及目标"。 */
    static ParamsDrivenCapability executing(String code) {
      return new ParamsDrivenCapability(
          code, CapabilityKind.EXECUTE, RiskLevel.SENSITIVE, TargetBindingProbe.Declaration.REQUIRED);
    }

    @Override
    public String code() {
      return code;
    }

    @Override
    public String displayName() {
      return code;
    }

    @Override
    public String description() {
      return "fix-verifier 独立验证桩 " + code;
    }

    @Override
    public Map<String, Object> parameterSchema() {
      return Map.of();
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
      return false;
    }

    @Override
    public Set<String> targetBindings(Map<String, Object> params) {
      return TargetIdExtractor.extract(params);
    }

    @Override
    public void validateParams(Map<String, Object> params) {
      // 无额外约束。
    }

    /** 类型级声明（供护栏反射读取）。 */
    public TargetBindingProbe.Declaration targetBindingDeclaration() {
      return declaration;
    }
  }

  /**
   * <strong>原样</strong>返回绑定的桩：不做正整数过滤。
   *
   * <p>用于构造 {@code INVALID_TARGET_BINDING} 场景——{@link TargetIdExtractor} 会把
   * 非数字 ID 静默丢弃（返回空集 → {@code MISSING_TARGET_BINDING}），
   * 因此必须由桩自己原样返回才能到达"绑定非法"分支。
   */
  static class RawBindingCapability implements AgentCapability,
      TargetBindingProbe.TargetBindingDeclaration {
    private final String code;
    private final java.util.function.Function<Map<String, Object>, Set<String>> bindings;

    RawBindingCapability(
        String code, java.util.function.Function<Map<String, Object>, Set<String>> bindings) {
      this.code = code;
      this.bindings = bindings;
    }

    /** 从 {@code targetId} 原样取值（不校验是否为数字）。 */
    static RawBindingCapability rawTargetId(String code) {
      return new RawBindingCapability(
          code,
          params -> {
            Object raw = params == null ? null : params.get("targetId");
            return raw == null ? Set.of() : Set.of(String.valueOf(raw));
          });
    }

    @Override
    public String code() {
      return code;
    }

    @Override
    public String displayName() {
      return code;
    }

    @Override
    public String description() {
      return "fix-verifier 原样绑定桩 " + code;
    }

    @Override
    public Map<String, Object> parameterSchema() {
      return Map.of();
    }

    @Override
    public CapabilityKind kind() {
      return CapabilityKind.EXECUTE;
    }

    @Override
    public RiskLevel risk() {
      return RiskLevel.SENSITIVE;
    }

    @Override
    public boolean requiresApproval() {
      return false;
    }

    @Override
    public Set<String> targetBindings(Map<String, Object> params) {
      return bindings.apply(params);
    }

    @Override
    public void validateParams(Map<String, Object> params) {
      // 无额外约束。
    }

    @Override
    public TargetBindingProbe.Declaration targetBindingDeclaration() {
      return TargetBindingProbe.Declaration.REQUIRED;
    }
  }

  /** 声明接口版本（护栏用反射读取，因此必须真正实现接口）。 */
  static class DeclaredParamsDriven extends ParamsDrivenCapability
      implements TargetBindingProbe.TargetBindingDeclaration {
    private final TargetBindingProbe.Declaration declaration;

    DeclaredParamsDriven(
        String code, CapabilityKind kind, RiskLevel risk, TargetBindingProbe.Declaration declaration) {
      super(code, kind, risk, declaration);
      this.declaration = declaration;
    }

    static DeclaredParamsDriven executing(String code) {
      return new DeclaredParamsDriven(
          code, CapabilityKind.EXECUTE, RiskLevel.SENSITIVE, TargetBindingProbe.Declaration.REQUIRED);
    }

    @Override
    public TargetBindingProbe.Declaration targetBindingDeclaration() {
      return declaration;
    }
  }

  // ------------------------------------------------------------------ invoke_endpoint 装配

  /**
   * 构造真实的 {@link InvokeEndpointCapability}，其端点注册表包含给定的 (method, path) 端点。
   *
   * <p>用于验证声明 2：经通用原语调用<strong>写端点</strong>时 L-C' 是否可达。
   *
   * @param endpoints (method, path) 对
   */
  static InvokeEndpointCapability invokeEndpoint(List<String[]> endpoints) {
    List<EndpointCapability> derived = new ArrayList<>();
    for (String[] endpoint : endpoints) {
      derived.add(
          new EndpointCapability(
              endpoint[0],
              endpoint[1],
              RiskInference.inferKind(endpoint[0], endpoint[1]),
              RiskInference.inferRisk(endpoint[0], endpoint[1]),
              RiskInference.inferRequiresApproval(endpoint[0], endpoint[1]),
              EndpointCapability.isTargetBound(endpoint[0], endpoint[1]),
              "独立验证端点"));
    }
    CapabilityRegistry registry = new CapabilityRegistry(new ArrayList<>(derived), Set.of());
    EndpointRegistry endpointRegistry = new EndpointRegistry(derived);
    return new InvokeEndpointCapability(endpointRegistry, registry);
  }

  /** 把 {@code invoke_endpoint} 与端点能力一起装配成护栏。 */
  static Rig rigWithInvokeEndpoint(
      Map<Long, AuthorizedTarget> targets,
      String whitelist,
      EndpointParameterPolicy policy,
      CapabilityApprovalGrantResolver grantResolver,
      List<String[]> endpoints) {
    InvokeEndpointCapability invoke = invokeEndpoint(endpoints);
    List<AgentCapability> all = new ArrayList<>();
    all.add(invoke);
    return rig(all, targets, whitelist, policy, grantResolver, true);
  }

  /** 空上下文。 */
  static CapabilityContext anonymous() {
    return CapabilityContext.anonymous();
  }

  /**
   * <strong>已人工批准</strong>的上下文。
   *
   * <h2>为什么 Claim3 必须用它</h2>
   *
   * <p>{@code ApprovalPolicy.isActualExecution} 对"触及目标 + 非 READ"的能力返回
   * {@code REQUIRED}，护栏随后要求 {@code context.humanApproved()}——否则在
   * <strong>L-B/确认阶段</strong>抛 {@code APPROVAL_REQUIRED}。
   *
   * <p>这是<strong>独立于"按需授权"的第二道确认机制</strong>。要干净地验证
   * "未授权 → 申请 → 持凭据放行"这条链，必须让第二道机制放行
   * （即模拟"用户已经同意这次执行"的真实场景），否则断言会被
   * {@code APPROVAL_REQUIRED} 干扰——这正是"层序：要让某层生效，必须先让更早的层放行"。
   */
  static CapabilityContext humanApproved() {
    return CapabilityContext.anonymous().approved(1L);
  }
}
