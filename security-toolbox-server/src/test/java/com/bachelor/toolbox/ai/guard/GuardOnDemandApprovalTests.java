package com.bachelor.toolbox.ai.guard;

import static com.bachelor.toolbox.ai.guard.GuardSupport.assertAllowed;
import static com.bachelor.toolbox.ai.guard.GuardSupport.params;
import static com.bachelor.toolbox.ai.guard.GuardSupport.target;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.target.AuthorizedTarget;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * <strong>按需授权（"先看见，要用时申请"）的对抗验证</strong>。
 *
 * <h2>被验证的机制</h2>
 *
 * <p>护栏原先只有两个出口：<strong>已授权 → 放行</strong>，<strong>未授权 → 拒绝</strong>。
 * 缺少第三个：<strong>未授权 → 申请授权</strong>。后果是 Agent 能看见全部 206 个能力，
 * 但 168 个端点能力一个都用不了；遇到未授权时只得到"拒绝"，<strong>不知道可以申请</strong>。
 *
 * <p>本类验证新增的第三个出口：未授权时返回 {@link CapabilityOutcome#approvalRequired}，
 * 携带 {@link CapabilityApprovalRequest}（绑定能力+目标+参数摘要）；用户批准后签发凭据，
 * Agent 持凭据重试即放行。
 *
 * <h2>必须验证的安全性质（本类的核心）</h2>
 *
 * <ol>
 *   <li><strong>申请不是万能逃生门</strong>：只有"目标未授权"可申请；端口越界、绑定非法、
 *       目标越权等<strong>真正越权</strong>仍然直接拒绝。
 *   <li><strong>凭据绑定四要素</strong>：批准了"能力A+目标1+参数X"，不能用于"能力B"、
 *       "目标2"或"参数Y"。
 *   <li><strong>参数摘要语义等价</strong>：{@code "80,443"} 与 {@code "443,80"} 摘要相同
 *       （避免 Agent 稍作调整就要重申请 → 批准疲劳）。
 *   <li><strong>未装配时 fail-closed</strong>：没有按需授权实现时，退回"未授权即拒绝"，
 *       不因缺少实现而放行。
 *   <li><strong>申请摘要是平台生成的</strong>：不含 Agent 提供的措辞（防"把 3306 说成 80"）。
 * </ol>
 */
@DisplayName("按需授权：未授权 → 申请 → 批准 → 放行")
class GuardOnDemandApprovalTests {

  /** fixture 里只授权了目标 1（端口 80,443）。目标 2 存在但**未授权**（resolver 返回空）。 */
  private static final Map<Long, AuthorizedTarget> TARGETS =
      Map.of(1L, target(1L, "192.168.10.10", "80,443"));

  private static CapabilityContext approved() {
    return CapabilityContext.of("ai-agent", 7L).approved(1L);
  }

  private static CapabilityContext anonymous() {
    return CapabilityContext.of("ai-agent", 7L);
  }

  /**
   * 一个声明 REQUIRED、<strong>从参数解析目标</strong>的能力。
   *
   * <p>刻意用 {@code paramsDriven} 而非固定绑定：本类要验证"目标 1（已授权）放行、
   * 目标 2（未授权）申请"，固定绑定无法构造这种对照。
   */
  private static AgentCapability boundCapability(String code) {
    return GuardSupport.DeclaredStub.paramsDriven(
        code, RiskLevel.SENSITIVE, TargetBindingProbe.Declaration.REQUIRED);
  }

  /** 记录型凭据解析器（模拟"用户批准后签发"）。 */
  static final class RecordingGrantResolver implements CapabilityApprovalGrantResolver {
    final Map<String, CapabilityApprovalGrant> grants = new ConcurrentHashMap<>();
    int grantCalls = 0;

    private static String key(String code, String targetId, String digest) {
      return code + "|" + targetId + "|" + digest;
    }

    @Override
    public boolean hasValidApproval(String capabilityCode, String targetId, String parameterDigest) {
      CapabilityApprovalGrant grant = grants.get(key(capabilityCode, targetId, parameterDigest));
      return grant != null && grant.isValidAt(capabilityCode, targetId, parameterDigest, Instant.now());
    }

    @Override
    public CapabilityApprovalGrant grant(CapabilityApprovalRequest request, ApprovalLevel level) {
      grantCalls++;
      CapabilityApprovalGrant grant =
          new CapabilityApprovalGrant(
              request.capabilityCode(),
              request.targetId(),
              request.parameterDigest(),
              level,
              "user-1",
              Instant.now(),
              null);
      grants.put(key(request.capabilityCode(), request.targetId(), request.parameterDigest()), grant);
      return grant;
    }
  }

  private static GuardSupport.Fixture fixtureWith(
      List<AgentCapability> capabilities, CapabilityApprovalGrantResolver resolver) {
    return GuardSupport.fixtureWithApproval(
        capabilities,
        TARGETS,
        CapabilityBlacklist.defaults(),
        capabilities.get(0).code(),
        CapabilityGate.SchemaMode.WARN,
        resolver);
  }

  // ==================================================================
  // A. 第三个出口：未授权返回"申请"而不是"拒绝"
  // ==================================================================

  @Nested
  @DisplayName("A. 未授权 → 返回申请（不是异常）")
  class ReturnsApprovalRequest {

    @Test
    @DisplayName("A-1 目标未授权 → 返回 approvalRequired，且携带申请详情（不抛异常）")
    void unauthorizedTargetReturnsApprovalRequest() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_a")), resolver);

      CapabilityOutcome outcome =
          fixture.gate().invoke("scan_a", params("targetId", 2L), approved());

      Assertions.assertTrue(
          outcome.isApprovalRequired(),
          "目标未授权时应返回'需要申请'，而不是抛异常——否则 Agent 不知道可以申请");
      CapabilityApprovalRequest request = outcome.approvalRequest();
      Assertions.assertEquals("scan_a", request.capabilityCode());
      Assertions.assertEquals("2", request.targetId());
      Assertions.assertNotNull(request.parameterDigest(), "申请必须携带参数摘要（凭据绑定用）");
      Assertions.assertNotNull(request.humanReadableSummary(), "申请必须携带人类可读摘要");
    }

    @Test
    @DisplayName("A-2 申请摘要由平台生成，且包含能力/风险/目标（不含 Agent 措辞）")
    void summaryIsPlatformGenerated() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_b")), resolver);

      CapabilityOutcome outcome =
          fixture.gate().invoke("scan_b", params("targetId", 2L), approved());
      String summary = outcome.approvalRequest().humanReadableSummary();

      Assertions.assertTrue(summary.contains("scan_b"), "摘要应含能力码: " + summary);
      Assertions.assertTrue(summary.contains("2"), "摘要应含目标 ID: " + summary);
      Assertions.assertTrue(
          summary.contains(String.valueOf(RiskLevel.SENSITIVE)),
          "摘要应含风险等级（供用户判断）: " + summary);
    }

    @Test
    @DisplayName("A-3 申请会被审计记录（AGENT_CAPABILITY_APPROVAL_REQUESTED）")
    void approvalRequestIsAudited() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_c")), resolver);

      fixture.gate().invoke("scan_c", params("targetId", 2L), approved());

      boolean audited =
          fixture.audit().entries.stream()
              .anyMatch(entry -> String.valueOf(entry).contains("APPROVAL_REQUESTED"));
      Assertions.assertTrue(audited, "申请必须进审计账本，实际记录: " + fixture.audit().entries);
    }

    @Test
    @DisplayName("A-4 已授权目标仍直接放行（修复未误伤正常路径）")
    void authorizedTargetStillAllowed() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_d")), resolver);

      assertAllowed(
          () -> {
            CapabilityOutcome outcome =
                fixture.gate().invoke("scan_d", params("targetId", 1L), approved());
            Assertions.assertFalse(
                outcome.isApprovalRequired(), "已授权目标不应要求申请");
          });
      Assertions.assertEquals(0, resolver.grantCalls, "已授权路径不应触发任何凭据签发");
    }
  }

  // ==================================================================
  // B. "申请"不是万能逃生门：真正的越权仍直接拒绝
  // ==================================================================

  @Nested
  @DisplayName("B. 真正越权不可申请（申请不是逃生门）")
  class NotAnEscapeHatch {

    @Test
    @DisplayName("B-1 端口越权 → 仍抛异常 PORT_OUT_OF_SCOPE（不可申请）")
    void portOutOfScopeIsNotApprovable() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_e")), resolver);

      CapabilityDeniedException denied =
          Assertions.assertThrows(
              CapabilityDeniedException.class,
              () -> fixture.gate().invoke("scan_e", params("targetId", 1L, "ports", "22"), approved()),
              "端口越权是真正的越权，不应转为'可申请'");
      Assertions.assertEquals(CapabilityDeniedException.Layer.AUTHORIZATION, denied.layer());
      Assertions.assertEquals("PORT_OUT_OF_SCOPE", denied.reasonCode());
    }

    @Test
    @DisplayName("B-2 端口不可解析 → 仍抛异常 PORT_UNPARSEABLE（不可申请）")
    void unparseablePortIsNotApprovable() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_f")), resolver);

      CapabilityDeniedException denied =
          Assertions.assertThrows(
              CapabilityDeniedException.class,
              () ->
                  fixture
                      .gate()
                      .invoke("scan_f", params("targetId", 1L, "ports", "abc"), approved()));
      Assertions.assertEquals("PORT_UNPARSEABLE", denied.reasonCode());
    }

    @Test
    @DisplayName("B-3 目标绑定为非法值 → 仍抛异常 INVALID_TARGET_BINDING（不可申请）")
    void invalidBindingIsNotApprovable() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      // 该能力的 targetBindings 返回非数字 ID。
      AgentCapability weird =
          GuardSupport.DeclaredStub.of(
              "scan_g",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of("not-a-number"),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = fixtureWith(List.of(weird), resolver);

      CapabilityDeniedException denied =
          Assertions.assertThrows(
              CapabilityDeniedException.class,
              () -> fixture.gate().invoke("scan_g", Map.of(), approved()));
      Assertions.assertEquals("INVALID_TARGET_BINDING", denied.reasonCode());
      Assertions.assertEquals(0, resolver.grantCalls, "不可申请的原因不应触发凭据签发");
    }

    @Test
    @DisplayName("B-4 未装配按需授权 → 退回'未授权即拒绝'（fail-closed，不因缺实现而放行）")
    void withoutResolverItFailsClosed() {
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_h")), null);

      CapabilityDeniedException denied =
          Assertions.assertThrows(
              CapabilityDeniedException.class,
              () -> fixture.gate().invoke("scan_h", params("targetId", 2L), approved()),
              "未装配按需授权时应保持原拒绝行为，绝不放行");
      Assertions.assertEquals("TARGET_NOT_FOUND", denied.reasonCode());
    }
  }

  // ==================================================================
  // C. 凭据绑定四要素：批准 A 不能执行 B
  // ==================================================================

  @Nested
  @DisplayName("C. 凭据绑定四要素（防'批准A执行B'）")
  class GrantBinding {

    @Test
    @DisplayName("C-1 批准后持凭据重试 → 放行")
    void grantedApprovalAllowsRetry() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_i")), resolver);

      // ① 第一次：未授权 → 申请
      CapabilityOutcome requested =
          fixture.gate().invoke("scan_i", params("targetId", 2L), approved());
      Assertions.assertTrue(requested.isApprovalRequired());

      // ② 用户批准 → 签发凭据
      resolver.grant(requested.approvalRequest(), ApprovalLevel.SINGLE);
      Assertions.assertEquals(1, resolver.grantCalls);

      // ③ Agent 持凭据重试 → 放行
      CapabilityOutcome retried =
          fixture.gate().invoke("scan_i", params("targetId", 2L), approved());
      Assertions.assertFalse(
          retried.isApprovalRequired(), "持有效凭据重试应放行，而不是再次要求申请");
    }

    @Test
    @DisplayName("C-2 凭据不能用于不同目标（防 IDOR）")
    void grantIsNotReusableForAnotherTarget() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_j")), resolver);

      CapabilityOutcome requested =
          fixture.gate().invoke("scan_j", params("targetId", 2L), approved());
      resolver.grant(requested.approvalRequest(), ApprovalLevel.SINGLE);

      // 用目标 3 重试（该能力固定返回 "2"，这里改参数不影响绑定，故直接验证摘要不同）
      String digestFor2 =
          CapabilityApprovalRequest.digestOf("scan_j", "2", params("targetId", 2L));
      String digestFor3 =
          CapabilityApprovalRequest.digestOf("scan_j", "3", params("targetId", 3L));
      Assertions.assertNotEquals(
          digestFor2, digestFor3, "不同目标必须产生不同摘要（否则凭据可跨目标复用）");
      Assertions.assertFalse(
          resolver.hasValidApproval("scan_j", "3", digestFor2),
          "目标 2 的凭据不得用于目标 3");
    }

    @Test
    @DisplayName("C-3 凭据不能用于不同参数（防 TOCTOU：批准 80 却扫 3306）")
    void grantIsNotReusableForAnotherParameterSet() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_k")), resolver);

      CapabilityOutcome requested =
          fixture.gate().invoke("scan_k", params("targetId", 2L, "ports", "80"), approved());
      resolver.grant(requested.approvalRequest(), ApprovalLevel.SINGLE);

      // 参数被篡改 → 摘要不同 → 凭据不适用
      Assertions.assertFalse(
          resolver.hasValidApproval(
              "scan_k", "2", CapabilityApprovalRequest.digestOf("scan_k", "2", params("targetId", 2L, "ports", "3306"))),
          "批准 ports=80 的凭据不得用于 ports=3306（防 TOCTOU）");
    }

    @Test
    @DisplayName("C-4 参数摘要语义等价：\"80,443\" 与 \"443,80\" 摘要相同（防批准疲劳）")
    void digestIsOrderInsensitive() {
      String first =
          CapabilityApprovalRequest.digestOf("scan_l", "1", params("ports", "80,443"));
      String second =
          CapabilityApprovalRequest.digestOf("scan_l", "1", params("ports", "443,80"));
      Assertions.assertEquals(
          first, second, "端口顺序不同但语义相同 → 摘要必须相同，否则 Agent 稍作调整就要重申请");
    }

    @Test
    @DisplayName("C-5 参数摘要对 Map 键序不敏感")
    void digestIsKeyOrderInsensitive() {
      Map<String, Object> first = new java.util.LinkedHashMap<>();
      first.put("a", 1);
      first.put("b", 2);
      Map<String, Object> second = new java.util.LinkedHashMap<>();
      second.put("b", 2);
      second.put("a", 1);

      Assertions.assertEquals(
          CapabilityApprovalRequest.digestOf("scan_m", "1", first),
          CapabilityApprovalRequest.digestOf("scan_m", "1", second),
          "Map 键序不应影响摘要");
    }

    @Test
    @DisplayName("C-6 摘要对不同能力/目标必须不同")
    void digestIsSensitiveToCapabilityAndTarget() {
      Map<String, Object> p = params("ports", "80");
      Assertions.assertNotEquals(
          CapabilityApprovalRequest.digestOf("scan_n", "1", p),
          CapabilityApprovalRequest.digestOf("scan_o", "1", p),
          "不同能力必须产生不同摘要");
      Assertions.assertNotEquals(
          CapabilityApprovalRequest.digestOf("scan_n", "1", p),
          CapabilityApprovalRequest.digestOf("scan_n", "2", p),
          "不同目标必须产生不同摘要");
    }
  }

  // ==================================================================
  // D. 凭据时效
  // ==================================================================

  @Nested
  @DisplayName("D. 凭据时效")
  class GrantExpiry {

    @Test
    @DisplayName("D-1 已过期凭据无效")
    void expiredGrantIsInvalid() {
      CapabilityApprovalGrant expired =
          new CapabilityApprovalGrant(
              "scan_p",
              "2",
              "digest",
              ApprovalLevel.SINGLE,
              "user-1",
              Instant.now().minusSeconds(3600),
              Instant.now().minusSeconds(60));

      Assertions.assertFalse(
          expired.isValidAt("scan_p", "2", "digest", Instant.now()), "过期凭据必须失效");
    }

    @Test
    @DisplayName("D-2 未过期凭据有效；四要素任一不符即失效")
    void validGrantRequiresAllFourElements() {
      Instant now = Instant.now();
      CapabilityApprovalGrant grant =
          new CapabilityApprovalGrant(
              "scan_q",
              "2",
              "digest",
              ApprovalLevel.SINGLE,
              "user-1",
              now,
              now.plusSeconds(300));

      Assertions.assertTrue(grant.isValidAt("scan_q", "2", "digest", now), "四要素全符 → 有效");
      Assertions.assertFalse(grant.isValidAt("scan_OTHER", "2", "digest", now), "能力不符 → 无效");
      Assertions.assertFalse(grant.isValidAt("scan_q", "9", "digest", now), "目标不符 → 无效");
      Assertions.assertFalse(grant.isValidAt("scan_q", "2", "other", now), "摘要不符 → 无效");
    }

    @Test
    @DisplayName("D-3 denyAll 默认实现全部拒绝（未装配时 fail-closed）")
    void denyAllDeniesEverything() {
      CapabilityApprovalGrantResolver denyAll = CapabilityApprovalGrantResolver.denyAll();
      Assertions.assertFalse(
          denyAll.hasValidApproval("any", "1", "any"), "默认实现必须拒绝一切，绝不 fail-open");
      Assertions.assertThrows(
          UnsupportedOperationException.class,
          () -> denyAll.grant(null, ApprovalLevel.SINGLE),
          "未装配时不应能签发凭据");
    }
  }

  // ==================================================================
  // E'. 三种"可申请"原因都必须真的可申请（独立验证者发现的死配置项）
  // ==================================================================

  /**
   * <strong>独立验证者 fix-verifier 发现的缺陷（2026-10-12）</strong>。
   *
   * <p>原实现的 {@code APPROVABLE_REASONS} 列了三个原因，但
   * {@code validateTargetValidity} 调用在 try/catch <strong>之外</strong>——
   * 它抛出的 {@code TARGET_DISABLED} / {@code AUTHORIZATION_EXPIRED}
   * <strong>根本进不了 catch</strong>，因此永远走不到申请分支。
   *
   * <p>后果：用户停用某目标后，Agent 得到的仍是"拒绝"而非"可申请"，
   * 与"先看见，要用时申请"的设计意图不符。（方向安全，但是功能缺失 + 文档与代码不一致。）
   *
   * <p>本类锁定修复：三个原因<strong>都必须</strong>返回申请而不是抛异常。
   */
  @Nested
  @DisplayName("E'. 三种可申请原因都必须真的可申请")
  class AllApprovableReasonsAreReachable {

    private GuardSupport.Fixture fixtureFor(RecordingGrantResolver resolver) {
      return fixtureWith(List.of(boundCapability("scan_disabled")), resolver);
    }

    @Test
    @DisplayName("E'-1 目标不存在 → 返回申请（TARGET_NOT_FOUND）")
    void targetNotFoundRequestsApproval() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureFor(resolver);

      CapabilityOutcome outcome =
          fixture.gate().invoke("scan_disabled", params("targetId", 999L), approved());

      Assertions.assertTrue(outcome.isApprovalRequired(), "目标不存在应可申请");
    }

    @Test
    @DisplayName("E'-2 目标已停用 → 返回申请（TARGET_DISABLED，修复前是抛异常）")
    void disabledTargetRequestsApproval() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      // 目标 3 存在但 enabled=false。
      AuthorizedTarget disabled = target(3L, "192.168.10.30", "80,443");
      disabled.setEnabled(false);
      Map<Long, AuthorizedTarget> targets = Map.of(3L, disabled);

      CapabilityGate gate =
          GuardSupport.gateWithResolverAndApproval(
              List.of(boundCapability("scan_disabled")),
              targetId -> Optional.ofNullable(targets.get(targetId)),
              resolver);

      CapabilityOutcome outcome = gate.invoke("scan_disabled", params("targetId", 3L), approved());

      Assertions.assertTrue(
          outcome.isApprovalRequired(),
          "目标停用属于'用户同意就能解决'的未授权类，必须返回申请而不是抛异常——"
              + "否则 APPROVABLE_REASONS 里的 TARGET_DISABLED 是死配置项");
    }

    @Test
    @DisplayName("E'-3 授权已过期 → 返回申请（AUTHORIZATION_EXPIRED，修复前是抛异常）")
    void expiredAuthorizationRequestsApproval() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      AuthorizedTarget expired = target(4L, "192.168.10.40", "80,443");
      expired.setAuthorizationExpiresAt(Instant.now().minusSeconds(3600));
      Map<Long, AuthorizedTarget> targets = Map.of(4L, expired);

      CapabilityGate gate =
          GuardSupport.gateWithResolverAndApproval(
              List.of(boundCapability("scan_disabled")),
              targetId -> Optional.ofNullable(targets.get(targetId)),
              resolver);

      CapabilityOutcome outcome = gate.invoke("scan_disabled", params("targetId", 4L), approved());

      Assertions.assertTrue(
          outcome.isApprovalRequired(),
          "授权过期属于'用户同意就能解决'的未授权类，必须返回申请而不是抛异常");
    }

    @Test
    @DisplayName("E'-4 目标越权（超出授权范围）→ 仍抛异常（不可申请）")
    void outOfScopeTargetIsStillDenied() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      // 目标在授权范围内但 targetValue 是公网地址 → validateTargetScope 拒绝。
      AuthorizedTarget publicTarget = target(5L, "8.8.8.8", "80");
      Map<Long, AuthorizedTarget> targets = Map.of(5L, publicTarget);

      CapabilityGate gate =
          GuardSupport.gateWithResolverAndApproval(
              List.of(boundCapability("scan_disabled")),
              targetId -> Optional.ofNullable(targets.get(targetId)),
              resolver);

      CapabilityDeniedException denied =
          Assertions.assertThrows(
              CapabilityDeniedException.class,
              () -> gate.invoke("scan_disabled", params("targetId", 5L), approved()),
              "目标越权是真正的越权，即使申请也不应批准");
      Assertions.assertEquals("TARGET_OUT_OF_SCOPE", denied.reasonCode());
      Assertions.assertEquals(0, resolver.grantCalls);
    }
  }

  // ==================================================================
  // E. 与 L-A 其他判定的关系
  // ==================================================================
  @Nested
  @DisplayName("E. 申请与其余护栏层的关系")
  class InteractionWithOtherLayers {

    @Test
    @DisplayName("E-1 目标访问器故障 → 仍抛 TARGET_ACCESS_FAILED（不转为申请）")
    void resolverFailureIsNotApprovable() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      CapabilityGate gate =
          GuardSupport.gateWithResolverAndApproval(
              List.of(boundCapability("scan_r2")),
              GuardSupport.failingResolver(new IllegalStateException("故障")),
              resolver);

      // 必须传 targetId，否则能力返回空集 → 会在 L-A 更早的 MISSING_TARGET_BINDING 分支被拒，
      // 走不到访问器调用（这正是"要让某层生效必须先让更早的层放行"）。
      CapabilityDeniedException denied =
          Assertions.assertThrows(
              CapabilityDeniedException.class,
              () -> gate.invoke("scan_r2", params("targetId", 2L), approved()));
      Assertions.assertEquals(
          "TARGET_ACCESS_FAILED",
          denied.reasonCode(),
          "访问器故障是护栏自身故障，不是'可申请'的未授权");
      Assertions.assertEquals(0, resolver.grantCalls, "护栏自身故障不应触发凭据签发");
    }

    @Test
    @DisplayName("E-2 未注册能力 → 仍抛 UNKNOWN_CAPABILITY（申请不能绕过 L-D）")
    void unknownCapabilityIsStillDenied() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_s")), resolver);

      CapabilityDeniedException denied =
          Assertions.assertThrows(
              CapabilityDeniedException.class,
              () -> fixture.gate().invoke("does_not_exist", Map.of(), approved()));
      Assertions.assertEquals(CapabilityDeniedException.Layer.ENTRYPOINT, denied.layer());
    }

    @Test
    @DisplayName("E-3 未授权目标 + 无人工确认 → 仍返回申请（申请本身即确认入口）")
    void approvalRequestIsReturnedEvenWithoutHumanApproval() {
      RecordingGrantResolver resolver = new RecordingGrantResolver();
      GuardSupport.Fixture fixture = fixtureWith(List.of(boundCapability("scan_t")), resolver);

      CapabilityOutcome outcome =
          fixture.gate().invoke("scan_t", params("targetId", 2L), anonymous());
      Assertions.assertTrue(
          outcome.isApprovalRequired(),
          "未人工确认时应返回申请（申请就是请求确认的入口），而不是直接拒绝");
    }
  }

  // ==================================================================
  // F. 端到端：只读端点能力经具体能力调用
  // ==================================================================

  @Nested
  @DisplayName("F. 只读端点能力：合法通过护栏（P1-3 修复）")
  class ReadOnlyEndpointAvailability {

    @Test
    @DisplayName("F-1 只读端点能力（声明 NONE）→ 通过 L-A")
    void readOnlyEndpointCapabilityIsAllowed() {
      com.bachelor.toolbox.ai.endpoint.EndpointCapability readOnly =
          com.bachelor.toolbox.ai.endpoint.EndpointCapability.derive(
              "GET", "/api/vulnerabilities", "列出漏洞目录");

      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(readOnly), TARGETS, CapabilityBlacklist.defaults(), readOnly.code(), "", CapabilityGate.SchemaMode.WARN, true);

      assertAllowed(
          () -> fixture.gate().invoke(readOnly.code(), Map.of(), approved()),
          "只读端点能力应通过 L-A（空集 + 显式声明 NONE）");
    }
  }
}
