package com.bachelor.toolbox.ai.guard.guardverify2;

import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.anonymous;
import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.params;

import com.bachelor.toolbox.ai.guard.ApprovalLevel;
import com.bachelor.toolbox.ai.guard.CapabilityApprovalRequest;
import com.bachelor.toolbox.ai.guard.CapabilityGate;
import com.bachelor.toolbox.ai.guard.CapabilityOutcome;
import com.bachelor.toolbox.ai.guard.InMemoryCapabilityApprovalGrantResolver;
import com.bachelor.toolbox.ai.guard.PendingApprovalRegistry;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * <strong>声明 3 的补充验证</strong>：按需授权链的"防凭空批准"性质
 * （Lead 报告 §3.4 第 5 条）。
 *
 * <h2>被验证的性质</h2>
 *
 * <blockquote>无待批申请时批准端点返回 400 —— 防止凭空构造批准请求。</blockquote>
 *
 * <p>本类验证其<strong>机制层</strong>：{@code PendingApprovalRegistry} 必须能区分
 * "护栏真实提出过的申请"与"凭空构造的申请"，且护栏返回申请时确实完成了登记。
 *
 * <p>（HTTP 400 那一层由 Lead 的 {@code GuardApprovalInfrastructureTests} 覆盖；
 * 本类验证它<em>依赖的</em>登记语义，属独立视角。）
 */
class Claim3PendingApprovalTest {

  private static final String CAP = "verify_export_capability";

  /** 装配带 pendingRegistry 的护栏。 */
  private static CapabilityGate gateWithRegistry(
      PendingApprovalRegistry registry, InMemoryCapabilityApprovalGrantResolver resolver) {
    PortRangeParser parser = new PortRangeParser();
    TargetPolicyService targetPolicy = new TargetPolicyService(false, parser);
    return new CapabilityGate(
        new com.bachelor.toolbox.ai.capability.CapabilityRegistry(
            List.of(IndependentFixture.DeclaredParamsDriven.executing(CAP)), java.util.Set.of()),
        targetPolicy,
        com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
        new com.bachelor.toolbox.ai.guard.ApprovalPolicy(),
        com.bachelor.toolbox.ai.guard.CapabilityAuditSink.NOOP,
        targetId -> java.util.Optional.empty(), // 目标一律查不到 → TARGET_NOT_FOUND → 可申请
        "warn",
        "",
        "",
        new com.bachelor.toolbox.ai.guard.EndpointParameterPolicy(parser, 65535, targetPolicy),
        resolver,
        registry);
  }

  /**
   * <strong>核心</strong>：护栏返回申请时，必须把申请登记进 {@code PendingApprovalRegistry}。
   *
   * <p>若未登记，用户批准时服务端查不到"申请确实存在过" → 无法防凭空批准。
   */
  @Test
  @DisplayName("声明3-登记：护栏返回申请时必须登记进 PendingApprovalRegistry")
  void gateRegistersPendingApproval() {
    PendingApprovalRegistry registry = new PendingApprovalRegistry();
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    CapabilityGate gate = gateWithRegistry(registry, resolver);

    Assertions.assertEquals(0, registry.size(), "初始应为空");

    CapabilityOutcome outcome = gate.invoke(CAP, params("targetId", 2L), anonymous());
    Assertions.assertTrue(outcome.isApprovalRequired(), "未授权目标应返回申请");
    Assertions.assertEquals(1, registry.size(), "护栏必须把申请登记进登记表（防凭空批准的依据）");

    // 登记的四要素必须与返回的申请一致，否则用户批准时会查不到。
    CapabilityApprovalRequest request = outcome.approvalRequest();
    Assertions.assertTrue(
        registry
            .find(request.capabilityCode(), request.targetId(), request.parameterDigest())
            .isPresent(),
        "登记表必须能按四要素查到该申请");
  }

  /**
   * <strong>反例（防凭空批准）</strong>：凭空构造的四要素必须查不到。
   *
   * <p>这是"无待批申请时批准端点返回 400"的机制层等价物。
   */
  @Test
  @DisplayName("声明3-防伪造：凭空构造的申请在登记表里查不到")
  void forgedApprovalIsNotFound() {
    PendingApprovalRegistry registry = new PendingApprovalRegistry();
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    CapabilityGate gate = gateWithRegistry(registry, resolver);

    // 真实申请（用于确认登记表本身工作正常）。
    gate.invoke(CAP, params("targetId", 2L), anonymous());

    // 凭空构造：四要素中任一不同 → 必须查不到。
    Assertions.assertTrue(
        registry.find(CAP, "2", "forged-digest").isEmpty(),
        "凭空构造的参数摘要必须查不到（防凭空批准）");
    Assertions.assertTrue(
        registry.find(CAP, "999", registry.pending().get(0).parameterDigest()).isEmpty(),
        "凭空构造的目标 ID 必须查不到（防 IDOR 式凭空批准）");
    Assertions.assertTrue(
        registry.find("other_capability", "2", registry.pending().get(0).parameterDigest()).isEmpty(),
        "凭空构造的能力码必须查不到");
  }

  /**
   * <strong>重复申请去重</strong>：同一四要素重复提出只保留一条。
   *
   * <p>防止 Agent 反复申请刷屏（用户疲劳 → 无脑同意）。
   */
  @Test
  @DisplayName("声明3-去重：同一四要素重复申请只保留一条")
  void duplicateRequestsAreDeduplicated() {
    PendingApprovalRegistry registry = new PendingApprovalRegistry();
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    CapabilityGate gate = gateWithRegistry(registry, resolver);

    for (int i = 0; i < 5; i++) {
      gate.invoke(CAP, params("targetId", 2L), anonymous());
    }
    Assertions.assertEquals(1, registry.size(), "同一申请重复 5 次应只登记 1 条（防刷屏）");
  }

  /**
   * <strong>容量上限</strong>：超过 {@code MAX_PENDING} 时必须丢弃最旧的，而不是无限增长。
   *
   * <p>防止 Agent 用海量申请把内存撑爆（拒绝服务）。
   */
  @Test
  @DisplayName("声明3-容量：超过上限时丢弃最旧申请（防内存耗尽）")
  void registryEnforcesCapacity() {
    PendingApprovalRegistry registry = new PendingApprovalRegistry();
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    CapabilityGate gate = gateWithRegistry(registry, resolver);

    int over = PendingApprovalRegistry.MAX_PENDING + 20;
    for (int i = 1; i <= over; i++) {
      gate.invoke(CAP, params("targetId", i), anonymous());
    }
    Assertions.assertTrue(
        registry.size() <= PendingApprovalRegistry.MAX_PENDING,
        "登记表不得超过容量上限 " + PendingApprovalRegistry.MAX_PENDING + "，实际 " + registry.size());
  }

  /**
   * <strong>批准后移除</strong>：移除后同一四要素查不到（防重复批准）。
   */
  @Test
  @DisplayName("声明3-移除：remove 后同一申请查不到（防重复批准）")
  void removedApprovalIsNotFound() {
    PendingApprovalRegistry registry = new PendingApprovalRegistry();
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    CapabilityGate gate = gateWithRegistry(registry, resolver);

    CapabilityOutcome outcome = gate.invoke(CAP, params("targetId", 2L), anonymous());
    CapabilityApprovalRequest request = outcome.approvalRequest();

    registry.remove(request.capabilityCode(), request.targetId(), request.parameterDigest());
    Assertions.assertTrue(
        registry
            .find(request.capabilityCode(), request.targetId(), request.parameterDigest())
            .isEmpty(),
        "移除后应查不到（防同一申请被批准两次）");
  }

  /**
   * <strong>凭据与登记的独立性</strong>：签发凭据不依赖登记表被清除。
   *
   * <p>确认"登记表（防伪造）"与"凭据（放行依据）"是两条独立机制，
   * 批准流程应按"先查登记 → 再签发 → 再移除登记"的顺序工作。
   */
  @Test
  @DisplayName("声明3-完整批准流程：登记→查登记→签发凭据→移除登记")
  void fullApprovalFlowWithRegistry() {
    PendingApprovalRegistry registry = new PendingApprovalRegistry();
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    CapabilityGate gate = gateWithRegistry(registry, resolver);

    // 1. Agent 申请 → 护栏返回申请并登记。
    CapabilityOutcome requested = gate.invoke(CAP, params("targetId", 2L), anonymous());
    Assertions.assertTrue(requested.isApprovalRequired());
    CapabilityApprovalRequest request = requested.approvalRequest();
    Assertions.assertEquals(1, registry.size());

    // 2. 用户批准 → 服务端先验证申请存在（防凭空批准）。
    var found =
        registry.find(request.capabilityCode(), request.targetId(), request.parameterDigest());
    Assertions.assertTrue(found.isPresent(), "批准前必须能在登记表中找到该申请");

    // 3. 签发凭据 + 移除登记。
    resolver.grant(found.get(), ApprovalLevel.SINGLE);
    registry.remove(request.capabilityCode(), request.targetId(), request.parameterDigest());
    Assertions.assertEquals(0, registry.size(), "批准后应移除登记");

    // 4. Agent 持凭据重试 → 放行（用已批准上下文，避开确认机制）。
    CapabilityOutcome granted =
        gate.invoke(CAP, params("targetId", 2L), IndependentFixture.humanApproved());
    Assertions.assertFalse(granted.isApprovalRequired(), "持凭据重试应放行");
  }
}
