package com.bachelor.toolbox.ai.guard;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.guard.ApprovalPolicy;
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

/**
 * 对抗验证的共享夹具（{@code guardverify} 包）。
 *
 * <p><strong>为什么单独写一个夹具类而不是复用实现者的测试基类</strong>：独立验证要求测试装置也独立。若复用实现者的夹具，其装配
 * 假设（例如"顺手关掉某个校验"）会一并被继承，验证就退化成复述。这里全部按接口契约从零装配。
 *
 * <h2>本夹具的核心约定：拒绝必须可归因</h2>
 *
 * <p>清单 §0 立的"伪通过"规则要求断言<strong>拒绝来自哪一层</strong>。因此本类提供 {@link #assertDeniedAt}，它同时断言层与
 * 原因码，并刻意让"抛了别的异常"与"根本没抛"都失败——避免"护栏坏了但测试绿了"。
 */
final class GuardSupport {

  private GuardSupport() {}

  /** 审计记录（用于验证"拒绝也留痕"）。 */
  record AuditEntry(String action, String code, Map<String, Object> detail, String result) {}

  /** 收集审计的内存实现。 */
  static final class RecordingAudit implements CapabilityAuditSink {
    final List<AuditEntry> entries = new ArrayList<>();

    @Override
    public void record(String action, String code, Map<String, Object> detail, String result) {
      entries.add(
          new AuditEntry(
              action, code, detail == null ? Map.of() : Map.copyOf(detail), result));
    }

    boolean hasDenial(String reasonCode) {
      return entries.stream()
          .anyMatch(
              entry ->
                  "AGENT_CAPABILITY_DENIED".equals(entry.action())
                      && reasonCode.equals(entry.detail().get("deniedReason")));
    }
  }

  /** 授权目标构造器：默认 LAN 地址 + 有效窗口 + 启用。 */
  static AuthorizedTarget target(long id, String value, String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(id);
    target.setName("target-" + id);
    target.setTargetValue(value);
    target.setTargetType("IP");
    target.setAuthorizationNote("对抗验证夹具");
    target.setAllowedPorts(allowedPorts);
    target.setEnabled(true);
    return target;
  }

  /** 已过期目标（用于 G-03）。 */
  static AuthorizedTarget expiredTarget(long id, String value, String allowedPorts) {
    AuthorizedTarget target = target(id, value, allowedPorts);
    target.setAuthorizationExpiresAt(java.time.Instant.now().minusSeconds(3600));
    return target;
  }

  /** 已停用目标。 */
  static AuthorizedTarget disabledTarget(long id, String value, String allowedPorts) {
    AuthorizedTarget target = target(id, value, allowedPorts);
    target.setEnabled(false);
    return target;
  }

  /**
   * 装配一个护栏。
   *
   * @param capabilities 注册的能力
   * @param targets 可按 ID 解析的目标（模拟 {@code TargetService.getCurrentlyAuthorized}）
   */
  static Fixture fixture(List<AgentCapability> capabilities, Map<Long, AuthorizedTarget> targets) {
    return fixture(capabilities, targets, CapabilityBlacklist.defaults(), "", "");
  }

  static Fixture fixture(
      List<AgentCapability> capabilities,
      Map<Long, AuthorizedTarget> targets,
      CapabilityBlacklist blacklist,
      String whitelist,
      String activeWhitelist) {
    return fixture(
        capabilities, targets, blacklist, whitelist, activeWhitelist, CapabilityGate.SchemaMode.WARN, true);
  }

  static Fixture fixture(
      List<AgentCapability> capabilities,
      Map<Long, AuthorizedTarget> targets,
      CapabilityBlacklist blacklist,
      String whitelist,
      String activeWhitelist,
      CapabilityGate.SchemaMode schemaMode,
      boolean withEndpointPolicy) {
    CapabilityRegistry registry = new CapabilityRegistry(capabilities, Set.of());
    RecordingAudit audit = new RecordingAudit();
    PortRangeParser portRangeParser = new PortRangeParser();
    CapabilityGate.TargetAccessResolver resolver =
        targetId -> Optional.ofNullable(targets.get(targetId));
    CapabilityGate gate =
        new CapabilityGate(
            registry,
            // allowPublicTargets=false：与生产默认一致（仅允许回环/局域网/自建靶场）。
            new TargetPolicyService(false, portRangeParser),
            blacklist,
            new ApprovalPolicy(),
            audit,
            resolver,
            schemaMode.name().toLowerCase(java.util.Locale.ROOT),
            whitelist,
            activeWhitelist,
            withEndpointPolicy ? new EndpointParameterPolicy(portRangeParser, 1024) : null);
    return new Fixture(gate, registry, audit);
  }

  /** 装配结果。 */
  record Fixture(CapabilityGate gate, CapabilityRegistry registry, RecordingAudit audit) {}

  // ------------------------------------------------------------------ 自定义装配

  /** 用指定的目标访问器装配护栏（用于验证访问器故障/空返回时的 fail-closed）。 */
  static CapabilityGate gateWithResolver(
      List<AgentCapability> capabilities, CapabilityGate.TargetAccessResolver resolver) {
    PortRangeParser portRangeParser = new PortRangeParser();
    return new CapabilityGate(
        new CapabilityRegistry(capabilities, Set.of()),
        new TargetPolicyService(false, portRangeParser),
        CapabilityBlacklist.defaults(),
        new ApprovalPolicy(),
        CapabilityAuditSink.NOOP,
        resolver,
        "warn",
        "",
        "",
        new EndpointParameterPolicy(portRangeParser, 1024));
  }

  /** 恒抛异常的访问器：验证"底层故障不得变成放行"。 */
  static CapabilityGate.TargetAccessResolver failingResolver(RuntimeException failure) {
    return targetId -> {
      throw failure;
    };
  }

  /** 恒返回空（目标不存在）的访问器。 */
  static CapabilityGate.TargetAccessResolver emptyResolver() {
    return targetId -> Optional.empty();
  }

  /**
   * 装配带"按需授权"解析器的护栏（用于验证"未授权 → 申请 → 批准 → 放行"）。
   *
   * @param whitelist 需显式开启的高危能力码（逗号分隔）；空串表示不开启
   * @param approvalGrantResolver 凭据解析器；{@code null} 表示未装配（应退回 fail-closed）
   */
  static Fixture fixtureWithApproval(
      List<AgentCapability> capabilities,
      Map<Long, AuthorizedTarget> targets,
      CapabilityBlacklist blacklist,
      String whitelist,
      CapabilityGate.SchemaMode schemaMode,
      CapabilityApprovalGrantResolver approvalGrantResolver) {
    PortRangeParser portRangeParser = new PortRangeParser();
    CapabilityRegistry registry = new CapabilityRegistry(capabilities, Set.of());
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        new CapabilityGate(
            registry,
            new TargetPolicyService(false, portRangeParser),
            blacklist,
            new ApprovalPolicy(),
            audit,
            targetId -> Optional.ofNullable(targets.get(targetId)),
            schemaMode.name().toLowerCase(java.util.Locale.ROOT),
            whitelist,
            "",
            new EndpointParameterPolicy(portRangeParser, 1024),
            approvalGrantResolver);
    return new Fixture(gate, registry, audit);
  }

  /** 用指定的访问器 + 按需授权解析器装配护栏（用于验证"访问器故障不可申请"）。 */
  static CapabilityGate gateWithResolverAndApproval(
      List<AgentCapability> capabilities,
      CapabilityGate.TargetAccessResolver resolver,
      CapabilityApprovalGrantResolver approvalGrantResolver) {
    PortRangeParser portRangeParser = new PortRangeParser();
    return new CapabilityGate(
        new CapabilityRegistry(capabilities, Set.of()),
        new TargetPolicyService(false, portRangeParser),
        CapabilityBlacklist.defaults(),
        new ApprovalPolicy(),
        CapabilityAuditSink.NOOP,
        resolver,
        "warn",
        "",
        "",
        new EndpointParameterPolicy(portRangeParser, 1024),
        approvalGrantResolver);
  }

  /** 用指定的审计实现装配护栏（用于验证审计故障不影响结论）。 */
  static CapabilityGate gateWithAudit(
      List<AgentCapability> capabilities,
      Map<Long, AuthorizedTarget> targets,
      CapabilityAuditSink audit) {
    PortRangeParser portRangeParser = new PortRangeParser();
    return new CapabilityGate(
        new CapabilityRegistry(capabilities, Set.of()),
        new TargetPolicyService(false, portRangeParser),
        CapabilityBlacklist.defaults(),
        new ApprovalPolicy(),
        audit,
        targetId -> Optional.ofNullable(targets.get(targetId)),
        "warn",
        "",
        "",
        new EndpointParameterPolicy(portRangeParser, 1024));
  }

  /**
   * 装配<strong>注入 {@code TargetPolicyService}</strong> 的端点策略的护栏夹具。
   *
   * <h2>为什么需要这个重载（D-5 端到端验证缺口）</h2>
   *
   * <p>{@link #fixture} 装配的 {@code EndpointParameterPolicy} 用的是<strong>两参构造</strong>
   * （{@code targetPolicyService == null}），而 {@code EndpointParameterPolicy} 在
   * {@code targetPolicyService == null} 时<strong>跳过 D-5 的 URI/主机校验</strong>
   * （刻意的向后兼容降级，见该类注释）。
   *
   * <p>后果：D-5（云元数据 SSRF 等 URI/主机类越权）在经 {@code gate.invoke} 的
   * <strong>端到端路径上不被校验</strong>，只有显式注入 {@code TargetPolicyService}
   * 的单元级用例才覆盖得到。<strong>这是一个真实的验证缺口</strong>——
   * 本重载补上端到端覆盖。
   *
   * @param capabilities 能力列表
   * @param targets 授权目标表
   * @param whitelist 需显式开启的高危能力码（逗号分隔）
   */
  static Fixture fixtureWithTargetPolicy(
      List<AgentCapability> capabilities,
      Map<Long, AuthorizedTarget> targets,
      String whitelist) {
    PortRangeParser portRangeParser = new PortRangeParser();
    TargetPolicyService targetPolicyService = new TargetPolicyService(false, portRangeParser);
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
            // 三参构造：注入 TargetPolicyService → D-5 的 URI/主机校验生效。
            new EndpointParameterPolicy(portRangeParser, 1024, targetPolicyService));
    return new Fixture(gate, registry, audit);
  }

  // ------------------------------------------------------------------ 能力桩

  /**
   * 可编程能力桩。
   *
   * <p>{@code declaration} 为 {@code null} 表示<strong>不实现</strong> {@link TargetBindingProbe.TargetBindingDeclaration}
   * 也不提供任何反射可见的声明访问器——这正是"漏声明"场景（S-04 / B-13）。
   */
  static class StubCapability implements AgentCapability {
    private final String code;
    private final CapabilityKind kind;
    private final RiskLevel risk;
    private final boolean requiresApproval;
    private final Set<String> bindings;
    private final Map<String, Object> schema;
    private final java.util.function.Consumer<Map<String, Object>> paramValidator;
    private final TargetBindingProbe.Declaration declaration;

    StubCapability(
        String code,
        CapabilityKind kind,
        RiskLevel risk,
        boolean requiresApproval,
        Set<String> bindings,
        Map<String, Object> schema,
        java.util.function.Consumer<Map<String, Object>> paramValidator,
        TargetBindingProbe.Declaration declaration) {
      this.code = code;
      this.kind = kind;
      this.risk = risk;
      this.requiresApproval = requiresApproval;
      this.bindings = bindings;
      this.schema = schema == null ? Map.of() : schema;
      this.paramValidator = paramValidator;
      this.declaration = declaration;
    }

    /** 常规能力：显式声明"应触及目标"。 */
    static StubCapability scanning(String code, Set<String> bindings) {
      return new StubCapability(
          code,
          CapabilityKind.EXECUTE,
          RiskLevel.SENSITIVE,
          false,
          bindings,
          Map.of(),
          null,
          TargetBindingProbe.Declaration.REQUIRED);
    }

    /** 显式声明"确实不触及目标"（如 retrieve_project_context）。 */
    static StubCapability nonTargeted(String code) {
      return new StubCapability(
          code,
          CapabilityKind.READ,
          RiskLevel.SAFE,
          false,
          Set.of(),
          Map.of(),
          null,
          TargetBindingProbe.Declaration.NONE);
    }

    /** 漏声明：返回空集但没有任何显式声明（S-04 的核心场景）。 */
    static StubCapability undeclared(String code, CapabilityKind kind, RiskLevel risk) {
      return new StubCapability(code, kind, risk, false, Set.of(), Map.of(), null, null);
    }

    /** kind 伪装：声明为 WRITE 但返回真实 targetId（S-03）。 */
    static StubCapability disguised(String code, Set<String> bindings) {
      return new StubCapability(
          code,
          CapabilityKind.WRITE,
          RiskLevel.SAFE,
          false,
          bindings,
          Map.of(),
          null,
          TargetBindingProbe.Declaration.REQUIRED);
    }

    /** 恒返回哨兵（S-01）。 */
    static StubCapability unresolved(String code) {
      return new StubCapability(
          code,
          CapabilityKind.EXECUTE,
          RiskLevel.SENSITIVE,
          false,
          Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
          Map.of(),
          null,
          TargetBindingProbe.Declaration.REQUIRED);
    }

    /** 自定义返回值 + 自定义参数校验（用于参数族用例）。 */
    static StubCapability custom(
        String code,
        CapabilityKind kind,
        RiskLevel risk,
        Set<String> bindings,
        Map<String, Object> schema,
        java.util.function.Consumer<Map<String, Object>> paramValidator,
        TargetBindingProbe.Declaration declaration) {
      return new StubCapability(
          code, kind, risk, false, bindings, schema, paramValidator, declaration);
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
      return "对抗验证桩能力 " + code;
    }

    @Override
    public Map<String, Object> parameterSchema() {
      return schema;
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

    @Override
    public Set<String> targetBindings(Map<String, Object> params) {
      return bindings;
    }

    @Override
    public void validateParams(Map<String, Object> params) {
      if (paramValidator != null) {
        paramValidator.accept(params);
      }
    }
  }

  /**
   * 带显式声明的桩：实现 {@link TargetBindingProbe.TargetBindingDeclaration}。
   *
   * <p>与 {@link StubCapability} 分开是因为"声明"是一个<strong>类型级</strong>事实：不实现该接口的能力，护栏就探测不到声明，
   * 从而必须 fail-closed。用同一个类无法表达这个差异。
   */
  static class DeclaredStub extends StubCapability
      implements TargetBindingProbe.TargetBindingDeclaration {
    private final TargetBindingProbe.Declaration declaration;

    DeclaredStub(
        String code,
        CapabilityKind kind,
        RiskLevel risk,
        boolean requiresApproval,
        Set<String> bindings,
        Map<String, Object> schema,
        java.util.function.Consumer<Map<String, Object>> paramValidator,
        TargetBindingProbe.Declaration declaration) {
      super(code, kind, risk, requiresApproval, bindings, schema, paramValidator, declaration);
      this.declaration = declaration;
    }

    static DeclaredStub of(
        String code,
        CapabilityKind kind,
        RiskLevel risk,
        Set<String> bindings,
        TargetBindingProbe.Declaration declaration) {
      return new DeclaredStub(code, kind, risk, false, bindings, Map.of(), null, declaration);
    }

    /**
     * <strong>参数驱动</strong>的声明桩：从 {@code params} 的 {@code targetId} 解析目标。
     *
     * <p>与 {@link #of} 的区别：{@code of} 返回<strong>固定</strong>绑定集合（忽略参数），
     * 因此无法验证"不同参数 → 不同目标"的场景（如按需授权的凭据绑定、端口子集校验）。
     * 本方法让目标随参数变化，才能构造出"已授权目标"与"未授权目标"的对照。
     */
    static DeclaredStub paramsDriven(
        String code, RiskLevel risk, TargetBindingProbe.Declaration declaration) {
      return new DeclaredStub(code, CapabilityKind.EXECUTE, risk, false, Set.of(), Map.of(), null, declaration) {
        @Override
        public Set<String> targetBindings(Map<String, Object> params) {
          Object raw = params == null ? null : params.get("targetId");
          if (raw == null) {
            return Set.of();
          }
          try {
            long id = Long.parseLong(String.valueOf(raw).trim());
            return id > 0 ? Set.of(Long.toString(id)) : Set.of();
          } catch (NumberFormatException notAnId) {
            return Set.of(String.valueOf(raw));
          }
        }
      };
    }

    @Override
    public TargetBindingProbe.Declaration targetBindingDeclaration() {
      return declaration;
    }
  }

  /** 显式声明"不触及目标"的空集能力。 */
  static AgentCapability declaredNone(String code) {
    return DeclaredStub.of(
        code, CapabilityKind.READ, RiskLevel.SAFE, Set.of(), TargetBindingProbe.Declaration.NONE);
  }

  /** 显式声明"应触及目标"但返回空集 → 必须被拒（S-02 的反面）。 */
  static AgentCapability declaredRequiredEmpty(String code) {
    return DeclaredStub.of(
        code,
        CapabilityKind.EXECUTE,
        RiskLevel.SENSITIVE,
        Set.of(),
        TargetBindingProbe.Declaration.REQUIRED);
  }

  /** 完全未声明的能力（不实现声明接口、无反射访问器）。 */
  static AgentCapability undeclaredEmpty(String code) {
    return new StubCapability(
        code, CapabilityKind.WRITE, RiskLevel.SAFE, false, Set.of(), Map.of(), null, null);
  }

  /** 返回真实绑定且声明为 REQUIRED。 */
  static AgentCapability declaredWithBindings(String code, Set<String> bindings) {
    return DeclaredStub.of(
        code,
        CapabilityKind.EXECUTE,
        RiskLevel.SENSITIVE,
        bindings,
        TargetBindingProbe.Declaration.REQUIRED);
  }

  /** kind 伪装：WRITE + 真实绑定 + 声明 REQUIRED。 */
  static AgentCapability disguisedWrite(String code, Set<String> bindings) {
    return DeclaredStub.of(
        code, CapabilityKind.WRITE, RiskLevel.SAFE, bindings, TargetBindingProbe.Declaration.REQUIRED);
  }

  // ------------------------------------------------------------------ 断言

  /**
   * 断言调用在<strong>指定层</strong>被拒绝，且原因码匹配。
   *
   * <p>这是"伪通过"规则的执行点：只看"抛了异常"是不够的——攻击者把载荷换成形状合法的版本，若拒绝理由来自 schema 而非授权边界，
   * 就说明真正的边界不存在。
   */
  static CapabilityDeniedException assertDeniedAt(
      CapabilityDeniedException.Layer layer, String reasonCode, Runnable call) {
    CapabilityDeniedException error =
        org.junit.jupiter.api.Assertions.assertThrows(
            CapabilityDeniedException.class,
            call::run,
            "预期在 " + layer.label() + " 被拒绝，但调用没有抛出护栏拒绝异常");
    org.junit.jupiter.api.Assertions.assertEquals(
        layer,
        error.layer(),
        "拒绝层错误（伪通过）：预期 " + layer.label() + "，实际 " + error.layer().label()
            + "，原因码 " + error.reasonCode() + "，消息 " + error.getMessage());
    if (reasonCode != null) {
      org.junit.jupiter.api.Assertions.assertEquals(
          reasonCode,
          error.reasonCode(),
          "拒绝原因码不符：预期 " + reasonCode + "，实际 " + error.reasonCode());
    }
    return error;
  }

  /** 断言调用<strong>未</strong>被护栏拒绝（对照组）。 */
  static void assertAllowed(Runnable call) {
    assertAllowed(call, "对照组预期放行，但被护栏拒绝");
  }

  /** 断言调用未被拒绝，并自定义失败消息（用于"记录已知 fail-open 形态"的用例）。 */
  static void assertAllowed(Runnable call, String message) {
    try {
      call.run();
    } catch (CapabilityDeniedException denied) {
      org.junit.jupiter.api.Assertions.fail(
          message + "：被 " + denied.layer().label() + " 拒绝（" + denied.reasonCode() + "）");
    }
  }

  /** 参数体（可变）。 */
  static Map<String, Object> params(Object... keyValues) {
    Map<String, Object> map = new LinkedHashMap<>();
    for (int i = 0; i + 1 < keyValues.length; i += 2) {
      map.put(String.valueOf(keyValues[i]), keyValues[i + 1]);
    }
    return map;
  }
}
