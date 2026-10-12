package com.bachelor.toolbox.ai.guard.guardverify2;

import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.anonymous;
import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.assertAllowed;
import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.assertDeniedAt;
import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.params;
import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.target;
import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.webTarget;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.guard.ApprovalLevel;
import com.bachelor.toolbox.ai.guard.CapabilityApprovalGrantResolver;
import com.bachelor.toolbox.ai.guard.CapabilityApprovalRequest;
import com.bachelor.toolbox.ai.guard.CapabilityDeniedException;
import com.bachelor.toolbox.ai.guard.CapabilityOutcome;
import com.bachelor.toolbox.ai.guard.InMemoryCapabilityApprovalGrantResolver;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * <strong>声明 3</strong>的独立验证：按需授权链是否真的能端到端闭环。
 *
 * <h2>被验证的声明（Lead 原文）</h2>
 *
 * <ol>
 *   <li>未授权目标 → {@code invoke} 返回 {@code outcome.isApprovalRequired() == true}
 *       （<strong>不是抛异常</strong>）
 *   <li>{@code grant} 签发凭据
 *   <li>同参数重试 → <strong>放行</strong>
 * </ol>
 *
 * <p>反例：端口越界（{@code PORT_OUT_OF_SCOPE}）、绑定非法（{@code INVALID_TARGET_BINDING}）
 * <strong>必须仍抛异常</strong>，不得变成"可申请"。
 *
 * <h2>本用例的独立装配</h2>
 *
 * <p>不使用 Lead 的 {@code GuardSupport.fixtureWithApproval}。这里用
 * {@link IndependentFixture.DeclaredParamsDriven}（参数驱动、显式声明 REQUIRED）从零装配，
 * 并把 {@code InMemoryCapabilityApprovalGrantResolver} 作为真实凭据存储接入。
 */
class Claim3OnDemandApprovalTest {

  /**
   * 能力码刻意<strong>不含</strong> scan/probe/exploit 等执行特征词。
   *
   * <p>{@code ApprovalPolicy.isActualExecution} 在"触及目标 + 非 READ"时返回
   * {@code REQUIRED}，或能力码含执行特征词时返回 {@code REQUIRED}。
   * 若用 {@code verify_scan_capability}，则护栏在 L-A 通过后还会在
   * <strong>L-B/确认阶段</strong>抛 {@code APPROVAL_REQUIRED}，
   * 使"按需授权闭环"的断言被<strong>另一个机制</strong>干扰（层序陷阱）。
   *
   * <p>本用例的目标是验证"按需授权"这一条链，因此刻意选一个
   * <strong>不触发确认策略</strong>的能力码，让断言精确落在按需授权上。
   */
  private static final String CAP = "verify_export_capability";

  /** 参数驱动能力：{@code targetBindings} 从 {@code params.targetId} 解析。 */
  private static AgentCapability capability() {
    return IndependentFixture.DeclaredParamsDriven.executing(CAP);
  }

  /** 已授权目标 1；目标 2 存在于表中但我们要构造"未授权"。 */
  private static Map<Long, AuthorizedTarget> authorizedTargets() {
    return Map.of(1L, webTarget(1L));
  }

  private static IndependentFixture.Rig rigWith(InMemoryCapabilityApprovalGrantResolver resolver) {
    return IndependentFixture.rig(
        List.of(capability()),
        authorizedTargets(),
        "",
        new com.bachelor.toolbox.ai.guard.EndpointParameterPolicy(
            new PortRangeParser(),
            65535,
            new TargetPolicyService(false, new PortRangeParser())),
        resolver,
        true);
  }

  // ------------------------------------------------------------------ 正向闭环

  /**
   * <strong>声明 3 的核心闭环</strong>：未授权 → 返回申请（不抛异常）→ grant → 同参数重试 → 放行。
   */
  @Test
  @DisplayName("声明3-闭环：未授权→返回申请（不抛异常）→grant→重试→放行")
  void onDemandApprovalClosesTheLoop() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    IndependentFixture.Rig fixture = rigWith(resolver);

    Map<String, Object> callParams = params("targetId", 2L);
    Map<Long, AuthorizedTarget> targets = authorizedTargets();
    // 目标 2 未授权（不在表中）→ targetAccessResolver 返回空 → TARGET_NOT_FOUND。
    Assertions.assertFalse(
        targets.containsKey(2L), "前提：目标 2 必须不在已授权表中（构造未授权场景）");

    // ---- 第 1 步：未授权 → 必须是返回值，不是异常。
    CapabilityOutcome outcome =
        Assertions.assertDoesNotThrow(
            () -> fixture.gate().invoke(CAP, callParams, anonymous()),
            "未授权目标必须返回 CapabilityOutcome（申请授权），而不是抛异常——"
                + "抛异常会让 Agent 只看到'失败'，不知道可以申请");

    Assertions.assertTrue(
        outcome.isApprovalRequired(),
        "未授权目标必须让 outcome.isApprovalRequired() 为 true");
    CapabilityApprovalRequest request = outcome.approvalRequest();
    Assertions.assertNotNull(request, "approvalRequest 不能为 null");
    Assertions.assertEquals(CAP, request.capabilityCode(), "申请的能力码必须与本次调用一致");
    Assertions.assertEquals("2", request.targetId(), "申请的目标 ID 必须是本次调用的目标");
    Assertions.assertEquals(ApprovalLevel.SINGLE, request.requestedLevel(), "默认粒度应为 SINGLE（一次性）");
    Assertions.assertTrue(
        request.parameterDigest() != null && !request.parameterDigest().isBlank(),
        "申请必须携带参数摘要（凭据绑定四要素之一）");

    // 申请摘要必须由平台生成（不含 Agent 措辞）——这里只断言它确实非空且提到目标。
    Assertions.assertTrue(
        request.humanReadableSummary().contains("2"),
        "平台生成的摘要应包含目标 ID，实际: " + request.humanReadableSummary());

    // ---- 第 2 步：grant 签发凭据。
    resolver.grant(request, ApprovalLevel.SINGLE);
    Assertions.assertEquals(1, resolver.size(), "签发后凭据存储应有 1 条");

    // ---- 第 3 步：同参数重试 → 放行。
    // 用 humanApproved() 上下文：这是"用户已同意本次执行"的真实场景。
    // 若不标记已批准，ApprovalPolicy 会因"触及目标 + 非 READ"抛 APPROVAL_REQUIRED
    // ——那是独立于按需授权的第二道机制，会干扰本用例的断言。
    CapabilityOutcome granted =
        Assertions.assertDoesNotThrow(
            () -> fixture.gate().invoke(CAP, callParams, IndependentFixture.humanApproved()),
            "持凭据重试必须放行");
    Assertions.assertFalse(
        granted.isApprovalRequired(),
        "持有效凭据重试不应再要求授权（否则闭环不成立）");
    Assertions.assertEquals(
        java.util.Set.of("2"), granted.targetBindings(), "放行结果必须记录已校验的目标");
  }

  /**
   * 一次性凭据的<strong>重放防护</strong>：SINGLE 凭据用后即焚，第二次重试必须再次申请。
   *
   * <p>这是"批准一次 ≠ 永久放行"的证据。
   */
  @Test
  @DisplayName("声明3-时效：SINGLE 凭据一次性，第二次重试必须再次申请")
  void singleGrantIsConsumedOnce() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    IndependentFixture.Rig fixture = rigWith(resolver);
    Map<String, Object> callParams = params("targetId", 2L);

    CapabilityOutcome first = fixture.gate().invoke(CAP, callParams, anonymous());
    resolver.grant(first.approvalRequest(), ApprovalLevel.SINGLE);

    // 第一次重试：放行（用已批准上下文，见闭环用例的说明）。
    CapabilityOutcome second =
        fixture.gate().invoke(CAP, callParams, IndependentFixture.humanApproved());
    Assertions.assertFalse(second.isApprovalRequired(), "第一次重试应放行");

    // 第二次重试：凭据已被消费 → 必须再次申请。
    CapabilityOutcome third = fixture.gate().invoke(CAP, callParams, anonymous());
    Assertions.assertTrue(
        third.isApprovalRequired(),
        "SINGLE 凭据必须一次性：第二次重试应再次要求授权，否则等于'批准一次永久放行'");
  }

  /**
   * <strong>凭据绑定参数摘要</strong>：批准 {@code ports=80} 不能用于 {@code ports=3306}。
   *
   * <p>若摘要未参与绑定，就会出现"用户批准 A、系统执行 B"。
   */
  @Test
  @DisplayName("声明3-绑定：批准参数A的凭据不能用于参数B（防 TOCTOU）")
  void grantIsBoundToParameterDigest() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    IndependentFixture.Rig fixture = rigWith(resolver);

    Map<String, Object> approvedParams = params("targetId", 2L, "ports", "80");
    CapabilityOutcome request = fixture.gate().invoke(CAP, approvedParams, anonymous());
    Assertions.assertTrue(request.isApprovalRequired());
    resolver.grant(request.approvalRequest(), ApprovalLevel.SINGLE);

    // 换参数重试 → 摘要不同 → 必须再次申请。
    CapabilityOutcome changed =
        fixture.gate().invoke(CAP, params("targetId", 2L, "ports", "3306"), anonymous());
    Assertions.assertTrue(
        changed.isApprovalRequired(),
        "凭据绑定参数摘要：批准 ports=80 的凭据不得用于 ports=3306（防 TOCTOU）");
  }

  /**
   * <strong>凭据绑定目标</strong>：批准目标 2 的凭据不能用于目标 3。
   */
  @Test
  @DisplayName("声明3-绑定：批准目标2的凭据不能用于目标3（防 IDOR）")
  void grantIsBoundToTarget() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    IndependentFixture.Rig fixture = rigWith(resolver);

    CapabilityOutcome request = fixture.gate().invoke(CAP, params("targetId", 2L), anonymous());
    resolver.grant(request.approvalRequest(), ApprovalLevel.SINGLE);

    CapabilityOutcome otherTarget = fixture.gate().invoke(CAP, params("targetId", 3L), anonymous());
    Assertions.assertTrue(
        otherTarget.isApprovalRequired(),
        "凭据绑定目标：批准目标 2 的凭据不得用于目标 3（防 IDOR）");
  }

  /**
   * <strong>对照组：已授权目标必须直接放行</strong>（不进入申请流程）。
   *
   * <p>证明按需授权没有把"本来就合法的调用"也变成申请。
   */
  @Test
  @DisplayName("声明3-对照组：已授权目标直接放行，不触发申请")
  void authorizedTargetPassesWithoutApproval() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    IndependentFixture.Rig fixture = rigWith(resolver);

    CapabilityOutcome outcome =
        Assertions.assertDoesNotThrow(
            () -> fixture.gate().invoke(CAP, params("targetId", 1L), IndependentFixture.humanApproved()),
            "已授权目标必须直接放行");
    Assertions.assertFalse(
        outcome.isApprovalRequired(), "已授权目标不应要求授权（对照组，证明修复未误伤）");
    Assertions.assertEquals(java.util.Set.of("1"), outcome.targetBindings());
    Assertions.assertEquals(0, resolver.size(), "已授权路径不应签发任何凭据");
  }

  // ------------------------------------------------------------------ 反例（不可申请）

  /**
   * <strong>反例 1</strong>：端口越界必须<strong>仍抛异常</strong>，不得变成"可申请"。
   *
   * <p>目标 1 已授权（端口 80,443）；请求端口 3306 越权 → L-A + {@code PORT_OUT_OF_SCOPE}。
   * 若这条变成 {@code isApprovalRequired()}，"申请"就成了绕过授权边界的逃生门。
   */
  @Test
  @DisplayName("声明3-反例：端口越界 PORT_OUT_OF_SCOPE 必须仍抛异常（不可申请）")
  void portEscalationStillThrows() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    IndependentFixture.Rig fixture = rigWith(resolver);

    assertDeniedAt(
        CapabilityDeniedException.Layer.AUTHORIZATION,
        "PORT_OUT_OF_SCOPE",
        () -> fixture.gate().invoke(CAP, params("targetId", 1L, "ports", "3306"), anonymous()));

    Assertions.assertEquals(
        0, resolver.size(), "越权调用不得签发任何凭据（申请不是逃生门）");
  }

  /**
   * <strong>反例 2</strong>：绑定非法（非数字 targetId）必须<strong>仍抛异常</strong>。
   *
   * <p><strong>层序陷阱</strong>：{@code TargetIdExtractor} 会把非数字 ID
   * <em>静默丢弃</em>，于是桩返回空集 → 撞的是 {@code MISSING_TARGET_BINDING}
   * 而不是 {@code INVALID_TARGET_BINDING}。
   * 因此这里必须用 {@link IndependentFixture.RawBindingCapability}（原样返回绑定）
   * 才能真正到达"绑定非法"分支。
   */
  @Test
  @DisplayName("声明3-反例：绑定非法 INVALID_TARGET_BINDING 必须仍抛异常（不可申请）")
  void invalidBindingStillThrows() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    IndependentFixture.Rig fixture =
        IndependentFixture.rig(
            List.of(IndependentFixture.RawBindingCapability.rawTargetId(CAP)),
            authorizedTargets(),
            "",
            null,
            resolver,
            true);

    assertDeniedAt(
        CapabilityDeniedException.Layer.AUTHORIZATION,
        "INVALID_TARGET_BINDING",
        () -> fixture.gate().invoke(CAP, params("targetId", "abc"), anonymous()));

    Assertions.assertEquals(0, resolver.size(), "绑定非法不得签发凭据");
  }

  /**
   * <strong>反例 3</strong>：目标越权（超出地址策略，如公网地址）必须仍抛异常。
   *
   * <p>目标 5 是公网地址，且 {@code allowPublicTargets=false} → {@code TARGET_OUT_OF_SCOPE}。
   */
  @Test
  @DisplayName("声明3-反例：目标越权 TARGET_OUT_OF_SCOPE 必须仍抛异常（不可申请）")
  void outOfScopeTargetStillThrows() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    // 目标 5 存在（能查到）但地址是公网 → validateTargetScope 拒绝。
    IndependentFixture.Rig fixture =
        IndependentFixture.rig(
            List.of(capability()),
            Map.of(5L, target(5L, "8.8.8.8", "80,443")),
            "",
            null,
            resolver,
            true);

    assertDeniedAt(
        CapabilityDeniedException.Layer.AUTHORIZATION,
        "TARGET_OUT_OF_SCOPE",
        () -> fixture.gate().invoke(CAP, params("targetId", 5L), anonymous()));
  }

  /**
   * <strong>重要发现（与 Lead 报告 §3.4 不符）</strong>：{@code TARGET_DISABLED} 虽然写在
   * {@code APPROVABLE_REASONS} 里，但<strong>实际无法转成申请</strong>。
   *
   * <h2>证据链</h2>
   *
   * <p>{@code CapabilityGate.resolveAndValidateAuthorization} 的<strong>修复后</strong>顺序是：
   *
   * <ol>
   *   <li>{@code requireTarget(targetId)} —— 取不到时抛 {@code TARGET_NOT_FOUND}
   *   <li>{@code validateTargetValidity(target)} —— 停用/过期在此判定（<strong>已在 try 块内</strong>）
   *   <li>⭐ 上面任一步抛异常 → 检查 {@code APPROVABLE_REASONS} → 转为申请
   * </ol>
   *
   * <h2>本用例的翻转历史（2026-10-12）</h2>
   *
   * <p><strong>修复前</strong>：{@code validateTargetValidity} 位于 try/catch <strong>之外</strong>，
   * 因此 {@code TARGET_DISABLED} / {@code AUTHORIZATION_EXPIRED}
   * <strong>根本进不了 catch</strong>——{@code APPROVABLE_REASONS} 里的这两项是<strong>死配置项</strong>。
   * 本用例当时断言的是"实际抛异常"（如实记录实际行为，作为发现上报）。
   *
   * <p><strong>修复后</strong>：Lead 采纳该发现，把 {@code validateTargetValidity} 移入 try 块，
   * 使两项<strong>真正可申请</strong>。本用例随之翻转为断言"返回申请"。
   *
   * <p>这正是"用例锁定实际行为 + 报告发现"这一流程的价值：
   * <strong>缺陷被修复后，复现用例会主动失败并提示翻转</strong>，而不是静默失去意义。
   */
  @Test
  @DisplayName("修复后：TARGET_DISABLED 真正可申请（返回申请而非抛异常）")
  void disabledTargetNowRequestsApproval() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    AuthorizedTarget disabled = target(7L, "10.0.0.77", "80,443");
    disabled.setEnabled(false);
    IndependentFixture.Rig fixture =
        IndependentFixture.rig(List.of(capability()), Map.of(7L, disabled), "", null, resolver, true);

    // 修复后行为：返回"可申请"，而不是抛 TARGET_DISABLED。
    CapabilityOutcome outcome =
        fixture.gate().invoke(CAP, params("targetId", 7L), anonymous());

    Assertions.assertTrue(
        outcome.isApprovalRequired(),
        "目标停用属于'用户同意就能解决'的未授权类，应返回申请；"
            + "若此处抛异常，说明 validateTargetValidity 又被移出了 try 块（死配置项回归）");
    Assertions.assertEquals("7", outcome.approvalRequest().targetId());
  }

  /**
   * <strong>同一修复的第二个证据</strong>：{@code AUTHORIZATION_EXPIRED} 同样可申请。
   *
   * <p>与 {@code TARGET_DISABLED} 同因——都发生在 {@code validateTargetValidity}，
   * 修复后该调用已在 try 块内，故两者都能走到申请分支。
   */
  @Test
  @DisplayName("修复后：AUTHORIZATION_EXPIRED 真正可申请")
  void expiredTargetNowRequestsApproval() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    AuthorizedTarget expired = IndependentFixture.target(8L, "10.0.0.88", "80,443");
    expired.setAuthorizationExpiresAt(java.time.Instant.now().minusSeconds(3600));
    IndependentFixture.Rig fixture =
        IndependentFixture.rig(List.of(capability()), Map.of(8L, expired), "", null, resolver, true);

    CapabilityOutcome outcome =
        fixture.gate().invoke(CAP, params("targetId", 8L), anonymous());

    Assertions.assertTrue(
        outcome.isApprovalRequired(),
        "授权过期属于'用户同意就能解决'的未授权类，应返回申请");
    Assertions.assertEquals("8", outcome.approvalRequest().targetId());
  }

  /**
   * {@code TARGET_NOT_FOUND} 可申请（三种可申请原因之一）。
   *
   * <p><strong>历史</strong>：本用例原名为 {@code targetNotFoundIsTheOnlyReachableApprovableReason}
   * （"唯一可达"）——因为在修复前，{@code APPROVABLE_REASONS} 的另两项
   * （{@code TARGET_DISABLED} / {@code AUTHORIZATION_EXPIRED}）是<strong>死配置项</strong>。
   *
   * <p>Lead 修复后，另两项也已可达，故本用例不再声称"唯一"。
   * 三者的完整覆盖见上面的两个翻转用例与 {@code GuardOnDemandApprovalTests} 的 E' 组。
   */
  @Test
  @DisplayName("声明3：TARGET_NOT_FOUND 可申请（修复后三种原因均可申请）")
  void targetNotFoundIsApprovable() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    IndependentFixture.Rig fixture = rigWith(resolver);

    CapabilityOutcome outcome =
        Assertions.assertDoesNotThrow(
            () -> fixture.gate().invoke(CAP, params("targetId", 2L), anonymous()),
            "TARGET_NOT_FOUND 应转为申请");
    Assertions.assertTrue(outcome.isApprovalRequired());
  }

  /**
   * <strong>反例 5（fail-closed）</strong>：未装配凭据解析器时，未授权目标必须<strong>退回直接拒绝</strong>。
   *
   * <p>若缺实现就放行，或缺实现仍返回"可申请"却永远批不了，都会误导 Agent。
   */
  @Test
  @DisplayName("声明3-fail-closed：未装配凭据解析器 → 未授权目标仍直接拒绝")
  void withoutResolverUnauthorizedTargetStillDenied() {
    IndependentFixture.Rig fixture =
        IndependentFixture.rig(List.of(capability()), authorizedTargets(), "", null, null, true);

    assertDeniedAt(
        CapabilityDeniedException.Layer.AUTHORIZATION,
        "TARGET_NOT_FOUND",
        () -> fixture.gate().invoke(CAP, params("targetId", 2L), anonymous()));
  }

  /**
   * <strong>边界（重要，与 Lead 描述有差异）</strong>：装配 {@code denyAll()} 时，
   * 未授权目标<strong>返回申请</strong>（而不是直接拒绝）。
   *
   * <p>{@code denyAll()} 只是"不签发凭据"，它的 {@code hasValidApproval} 恒为 false，
   * 但护栏的判定是 {@code approvalGrantResolver == null} 才退回拒绝。
   * 因此 {@code denyAll()} 会让每次调用都返回"可申请"却永远批不了——
   * <strong>对 Agent 而言是"能看见、申请了也没用"</strong>。
   *
   * <p>这与 Lead 报告 §3.4"未装配时 fail-closed"的表述<strong>不完全一致</strong>：
   * fail-closed 成立的前提是<em>未装配（null）</em>，而不是"装配了 denyAll"。
   * 本用例如实锁定这一实际行为。
   */
  @Test
  @DisplayName("声明3-边界：denyAll() 装配时未授权目标返回申请（非直接拒绝）")
  void denyAllResolverYieldsApprovalRequest() {
    IndependentFixture.Rig fixture =
        IndependentFixture.rig(
            List.of(capability()),
            authorizedTargets(),
            "",
            null,
            CapabilityApprovalGrantResolver.denyAll(),
            true);

    CapabilityOutcome outcome =
        Assertions.assertDoesNotThrow(
            () -> fixture.gate().invoke(CAP, params("targetId", 2L), anonymous()),
            "装配了 denyAll() 时，护栏视其为'已装配'，因此返回申请而不是抛异常");

    Assertions.assertTrue(
        outcome.isApprovalRequired(),
        "denyAll() 的 hasValidApproval 恒为 false → 每次都返回申请（但永远批不了）");
  }

  /**
   * <strong>摘要语义等价</strong>：{@code "80,443"} 与 {@code "443,80"} 必须产生同一摘要。
   *
   * <p>若不排序，Agent 稍作调整就要重新申请 → 批准疲劳 → 用户无脑同意。
   */
  @Test
  @DisplayName("声明3-摘要：\"80,443\" 与 \"443,80\" 摘要相同（防批准疲劳）")
  void digestIsOrderInsensitive() {
    String a = CapabilityApprovalRequest.digestOf(CAP, "2", params("targetId", 2L, "ports", "80,443"));
    String b = CapabilityApprovalRequest.digestOf(CAP, "2", params("targetId", 2L, "ports", "443,80"));
    Assertions.assertEquals(a, b, "端口串顺序不同但语义相同，摘要必须相同");

    // 反向对照：语义不同的参数必须产生不同摘要（否则绑定失效）。
    String c = CapabilityApprovalRequest.digestOf(CAP, "2", params("targetId", 2L, "ports", "80"));
    Assertions.assertNotEquals(a, c, "语义不同的参数必须产生不同摘要，否则凭据绑定失效");
  }

  /** 申请对象必须拒绝"无摘要"（构造期校验）。 */
  @Test
  @DisplayName("声明3-不变量：CapabilityApprovalRequest 拒绝空摘要")
  void requestRejectsNullDigest() {
    Assertions.assertThrows(
        NullPointerException.class,
        () -> new CapabilityApprovalRequest(CAP, "2", null, "SENSITIVE", ApprovalLevel.SINGLE, "s", Map.of()),
        "参数摘要不能为空（凭据绑定四要素之一）");
  }

  /** 凭据解析器必须拒绝为 FORBIDDEN 级别签发凭据。 */
  @Test
  @DisplayName("声明3-不变量：InMemory 解析器拒绝为 FORBIDDEN 签发凭据")
  void resolverRefusesForbiddenLevel() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    CapabilityApprovalRequest request =
        new CapabilityApprovalRequest(CAP, "2", "digest", "DESTRUCTIVE", ApprovalLevel.SINGLE, "s", Map.of());
    Assertions.assertThrows(
        IllegalArgumentException.class,
        () -> resolver.grant(request, ApprovalLevel.FORBIDDEN),
        "FORBIDDEN 能力不得签发凭据");
  }

  /** 已授权目标 + 合法参数：确认对照组在带 resolver 时也不受影响。 */
  @Test
  @DisplayName("声明3-对照组：带 resolver 时合法端口调用仍放行")
  void legalPortsStillPassWithResolver() {
    InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
    IndependentFixture.Rig fixture = rigWith(resolver);
    assertAllowed(
        () ->
            fixture
                .gate()
                .invoke(CAP, params("targetId", 1L, "ports", "80"), IndependentFixture.humanApproved()),
        "合法端口（80 在授权范围内）应放行");
  }
}
