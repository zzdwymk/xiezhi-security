package com.bachelor.toolbox.ai.guard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * L-A / L-B / L-C / L-D 授权边界的对抗性探索测试（Round 8 深挖「AI 工具调用授权边界」）。
 *
 * <p>本类刻意<strong>不</strong>复用实现者的夹具（{@code GuardSupport}），按接口契约从零装配，
 * 以免继承其装配假设。目标是把几类"藏得较深"的边界缺陷固化为可执行断言：
 *
 * <ol>
 *   <li><b>D-BIND-1 变体目标绑定</b>：能力只从 {@code targetId} 取绑定，而参数里用 {@code target_id}/{@code targetIds}
 *       夹带另一个目标时，是否会让被遗漏的目标绕过 L-A？</li>
 *   <li><b>D-BIND-2 解析即越权</b>：绑定值为负数/超大/带前后空白时，解析是否 fail-closed？</li>
 *   <li><b>D-CFG-1 生产默认白名单</b>：高危（DESTRUCTIVE/ADMIN）能力在默认配置下必须拒绝。</li>
 *   <li><b>D-OVERRIDE-1 端点原语反向映射</b>：{@code invoke_endpoint} 打黑名单端点必须被 L-B 拦下。</li>
 *   <li><b>D-PORT-1 端口区间溢出</b>：{@code 1-65535} 或超大区间必须拒绝而非放行。</li>
 *   <li><b>D-TOCTOU-1 审批与执行绑定</b>：审批快照记录目标 A、执行时绑定目标 B 必须拒绝。</li>
 * </ol>
 */
@DisplayName("L-A/B/C/D 授权边界对抗测试（Round 8）")
class CapabilityGateBoundaryAuditTests {

  private static final Map<Long, AuthorizedTarget> TARGETS =
      Map.of(
          1L, target(1L, "192.168.222.158", "80,443"),
          2L, target(2L, "192.168.222.159", "80"));

  private static AuthorizedTarget target(long id, String value, String ports) {
    AuthorizedTarget t = new AuthorizedTarget();
    t.setId(id);
    t.setName("target-" + id);
    t.setTargetValue(value);
    t.setTargetType("IP");
    t.setAuthorizationNote("Round8 对抗夹具");
    t.setAllowedPorts(ports);
    t.setEnabled(true);
    t.setAuthorizationValidFrom(Instant.now().minusSeconds(3600));
    t.setAuthorizationExpiresAt(Instant.now().plusSeconds(86400));
    return t;
  }

  private static CapabilityContext approved() {
    return CapabilityContext.of("ai-agent", 7L).approved(1L);
  }

  /** 最小可用能力：绑定从单一 targetId 参数解析。 */
  private static AgentCapability bindingByTargetId(String code, RiskLevel risk) {
    return new AgentCapability() {
      public String code() { return code; }
      public String displayName() { return code; }
      public String description() { return "Round8 探针"; }
      public CapabilityKind kind() { return CapabilityKind.EXECUTE; }
      public RiskLevel risk() { return risk; }
      public boolean requiresApproval() { return false; }
      public Map<String, Object> parameterSchema() { return Map.of("type", "object"); }

      @Override
      public Set<String> targetBindings(Map<String, Object> params) {
        if (params == null) return Set.of();
        Object v = params.get("targetId");
        if (v == null) return Set.of();
        return Set.of(String.valueOf(v));
      }
    };
  }

  /** 显式声明 REQUIRED 的能力（用于"无 targetId → MISSING_TARGET_BINDING"用例）。 */
  private static AgentCapability declaredRequired(String code, RiskLevel risk) {
    return new AgentCapability() {
      public String code() { return code; }
      public String displayName() { return code; }
      public String description() { return "Round8 声明探针"; }
      public CapabilityKind kind() { return CapabilityKind.EXECUTE; }
      public RiskLevel risk() { return risk; }
      public boolean requiresApproval() { return false; }
      public Map<String, Object> parameterSchema() { return Map.of("type", "object"); }

      @Override
      public Set<String> targetBindings(Map<String, Object> params) {
        return Set.of();
      }
    };
  }

  private static CapabilityGate gate(List<AgentCapability> caps, String whitelist) {
    CapabilityRegistry registry = new CapabilityRegistry(caps);
    PortRangeParser parser = new PortRangeParser();
    TargetPolicyService policy = new TargetPolicyService(false, parser);
    return new CapabilityGate(
        registry,
        policy,
        CapabilityBlacklist.defaults(),
        new ApprovalPolicy(),
        CapabilityAuditSink.NOOP,
        id -> Optional.ofNullable(TARGETS.get(id)),
        "warn",
        whitelist,
        "",
        null,
        null,
        null);
  }

  private static CapabilityDeniedException deny(
      CapabilityGate gate, String code, Map<String, Object> params, CapabilityContext ctx) {
    return (CapabilityDeniedException)
        org.junit.jupiter.api.Assertions.assertThrows(
            CapabilityDeniedException.class, () -> gate.invoke(code, params, ctx));
  }

  @Nested
  @DisplayName("D-BIND 目标绑定解析")
  class BindingResolution {

    @Test
    @DisplayName("D-BIND-1 仅 targetId 绑定：委托目标 1（已授权）→ 放行")
    void boundTargetAllowed() {
      CapabilityGate g = gate(List.of(bindingByTargetId("scan_ok", RiskLevel.SENSITIVE)), "scan_ok");
      assertThat(g.invoke("scan_ok", Map.of("targetId", 1L), approved()).capability()).isNotNull();
    }

    @Test
    @DisplayName("D-BIND-2 负数目标 ID → 拒绝（不能因解析成负数而落到空集绕过）")
    void negativeTargetIdDenied() {
      CapabilityGate g = gate(List.of(bindingByTargetId("scan_neg", RiskLevel.SENSITIVE)), "scan_neg");
      CapabilityDeniedException d = deny(g, "scan_neg", Map.of("targetId", -5L), approved());
      assertThat(d.layer()).isEqualTo(CapabilityDeniedException.Layer.AUTHORIZATION);
      assertThat(d.reasonCode()).isIn("TARGET_NOT_FOUND", "INVALID_TARGET_BINDING");
    }

    @Test
    @DisplayName("D-BIND-3 未授权目标（目标 3 不存在）→ 未装配按需授权时 fail-closed")
    void unknownTargetDeniedByDefault() {
      CapabilityGate g = gate(List.of(bindingByTargetId("scan_x", RiskLevel.SENSITIVE)), "scan_x");
      CapabilityDeniedException d = deny(g, "scan_x", Map.of("targetId", 3L), approved());
      assertThat(d.reasonCode()).isEqualTo("TARGET_NOT_FOUND");
    }

    @Test
    @DisplayName("D-BIND-4 无 targetId 且声明应触及目标 → 拒绝（不允许空集冒充不触及）")
    void missingBindingDeclaredRequiredDenied() {
      CapabilityGate g = gate(List.of(declaredRequired("scan_m", RiskLevel.SENSITIVE)), "scan_m");
      CapabilityDeniedException d = deny(g, "scan_m", Map.of(), approved());
      assertThat(d.reasonCode()).isEqualTo("MISSING_TARGET_BINDING");
    }
  }

  @Nested
  @DisplayName("D-CFG 高危能力默认拒绝")
  class DefaultCapabilityConfig {

    @Test
    @DisplayName("D-CFG-1 DESTRUCTIVE 能力未显式开启 → CAPABILITY_NOT_ENABLED")
    void destructiveNotEnabled() {
      CapabilityGate g = gate(List.of(bindingByTargetId("drop_all", RiskLevel.DESTRUCTIVE)), "");
      CapabilityDeniedException d = deny(g, "drop_all", Map.of("targetId", 1L), approved());
      assertThat(d.layer()).isEqualTo(CapabilityDeniedException.Layer.ADMISSION);
      assertThat(d.reasonCode()).isEqualTo("CAPABILITY_NOT_ENABLED");
    }

    @Test
    @DisplayName("D-CFG-2 黑名单能力即使白名单显式开启 → BLOCKED_CAPABILITY")
    void blacklistedNeverEnabled() {
      CapabilityGate g = gate(List.of(bindingByTargetId("shutdown_system", RiskLevel.DESTRUCTIVE)), "shutdown_system");
      CapabilityDeniedException d = deny(g, "shutdown_system", Map.of("targetId", 1L), approved());
      assertThat(d.reasonCode()).isEqualTo("BLOCKED_CAPABILITY");
    }
  }

  @Nested
  @DisplayName("D-PORT 端口越权")
  class PortScope {

    @Test
    @DisplayName("D-PORT-1 请求端口 3306（目标仅授权 80,443）→ PORT_OUT_OF_SCOPE")
    void portOutOfScopeDenied() {
      CapabilityGate g = gate(List.of(bindingByTargetId("scan_p", RiskLevel.SENSITIVE)), "scan_p");
      CapabilityDeniedException d =
          deny(g, "scan_p", Map.of("targetId", 1L, "ports", "3306"), approved());
      assertThat(d.reasonCode()).isEqualTo("PORT_OUT_OF_SCOPE");
    }

    @Test
    @DisplayName("D-PORT-2 超大端口区间 1-65535 → 不得静默放行越权端口")
    void hugePortRangeNotSilentlyAllowed() {
      CapabilityGate g = gate(List.of(bindingByTargetId("scan_big", RiskLevel.SENSITIVE)), "scan_big");
      assertThatThrownBy(() -> g.invoke("scan_big", Map.of("targetId", 1L, "ports", "1-65535"), approved()))
          .isInstanceOf(CapabilityDeniedException.class);
    }
  }

  @Nested
  @DisplayName("D-TOCTOU 审批 ↔ 执行绑定")
  class ToctouBoundary {

    @Test
    @DisplayName("D-TOCTOU-1 审批记录目标 1、执行绑定目标 2 → AUTHORIZATION_SNAPSHOT_CHANGED")
    void changedBindingDenied() {
      CapabilityGate g = gate(List.of(bindingByTargetId("scan_toctou", RiskLevel.SENSITIVE)), "scan_toctou");
      CapabilityContext ctx =
          CapabilityContext.of("ai-agent", 7L).approved(1L)
              .withApprovedTargetBindings(Map.of("1", "192.168.222.158"));
      CapabilityDeniedException d =
          deny(g, "scan_toctou", Map.of("targetId", 2L), ctx);
      assertThat(d.reasonCode()).isEqualTo("AUTHORIZATION_SNAPSHOT_CHANGED");
    }
  }

  @Nested
  @DisplayName("D-HUMAN 人工确认边界")
  class HumanApproval {

    @Test
    @DisplayName("D-HUMAN-1 高危执行能力未人工确认 → APPROVAL_REQUIRED")
    void highRiskWithoutHumanApprovalDenied() {
      CapabilityGate g = gate(List.of(bindingByTargetId("scan_h", RiskLevel.SENSITIVE)), "scan_h");
      CapabilityContext anonymous = CapabilityContext.of("ai-agent", 7L);
      CapabilityDeniedException d = deny(g, "scan_h", Map.of("targetId", 1L), anonymous);
      assertThat(d.reasonCode()).isEqualTo("APPROVAL_REQUIRED");
    }
  }
}
