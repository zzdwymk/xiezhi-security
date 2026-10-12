package com.bachelor.toolbox.ai.guard.guardverify2;

import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.anonymous;
import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.assertAllowed;
import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.assertDeniedAt;
import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.params;
import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.rigWithInvokeEndpoint;
import static com.bachelor.toolbox.ai.guard.guardverify2.IndependentFixture.webTarget;

import com.bachelor.toolbox.ai.guard.CapabilityDeniedException;
import com.bachelor.toolbox.ai.guard.EndpointParameterPolicy;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * <strong>声明 2</strong>的独立验证：{@code validateEndpointParameterPolicy}（L-C'）是否真的从死代码变为可达。
 *
 * <h2>被验证的声明（Lead 原文）</h2>
 *
 * <blockquote>找一个<strong>写端点</strong>（POST），构造越权参数，断言拒绝理由为
 * <strong>L-C + {@code ENDPOINT_PARAMETER_POLICY}</strong> 而<strong>不是</strong>
 * L-A + {@code TARGET_BINDING_UNRESOLVED}。</blockquote>
 *
 * <h2>为什么这是本次修复的核心</h2>
 *
 * <p>修复前 {@code InvokeEndpointCapability.targetBindings} 恒返回哨兵 → L-A 无条件拒绝 →
 * 而 L-A 排在 L-C' 之前 → <strong>L-C' 永不执行（死代码）</strong>。
 * 若只断言"抛了异常"，L-A 的拒绝会让用例一直显示"通过"，却从未证明 L-C' 可达——
 * 这正是本项目"伪通过"规则要防的形态。
 *
 * <h2>本用例如何避免伪通过</h2>
 *
 * <p>不仅断言层 + 原因码，还断言<strong>对照组</strong>：同样的端点、同样的目标，
 * 只把越权参数换成合法参数 → 必须放行。若 L-C' 仍不可达，越权用例会因 L-A 拒绝而
 * 层不匹配（预期 L-C，实际 L-A）→ <strong>失败</strong>，不会伪装通过。
 */
class Claim2LcPrimeReachabilityTest {

  /** 写端点：{@code POST /api/tasks}。 */
  private static final List<String[]> ENDPOINTS =
      List.<String[]>of(new String[] {"POST", "/api/tasks"});

  private static Map<Long, AuthorizedTarget> targets() {
    return Map.of(1L, webTarget(1L));
  }

  /**
   * 装配：真实 invoke_endpoint + 端点注册表 + 注入 TargetPolicyService 的端点策略。
   *
   * <p><strong>层序关键</strong>：{@code InvokeEndpointCapability.risk()} 恒为
   * {@code DESTRUCTIVE}，因此 {@code CapabilityGate.requiresExplicitEnable} 为真 →
   * 若不放进白名单，会在 <strong>L-B</strong> 被 {@code CAPABILITY_NOT_ENABLED} 拦下，
   * <strong>根本走不到 L-C'</strong>。
   *
   * <p>这正是"要让某层生效，必须先让更早的层放行"的实践：本用例显式把
   * {@code invoke_endpoint} 加入白名单，L-B 才会放行，L-A / L-C' 才有机会执行。
   * （Lead 报告 §0 记录的"连续两次撞错层"就是漏了这一步。）
   */
  private static final String WHITELIST = "invoke_endpoint";

  private static IndependentFixture.Rig rigForClaim2() {
    PortRangeParser parser = new PortRangeParser();
    var targetPolicy = new com.bachelor.toolbox.target.TargetPolicyService(false, parser);
    EndpointParameterPolicy policy = new EndpointParameterPolicy(parser, 65535, targetPolicy);
    return rigWithInvokeEndpoint(targets(), WHITELIST, policy, null, ENDPOINTS);
  }

  /**
   * <strong>核心断言</strong>：越权参数必须在 <strong>L-C</strong> 被
   * {@code ENDPOINT_PARAMETER_POLICY} 拦下，而不是在 L-A 被 {@code TARGET_BINDING_UNRESOLVED} 拦下。
   *
   * <p>越权载荷：{@code msf_scan} 的 {@code module} 不在 {@code auxiliary/} / {@code exploit/} 前缀内。
   */
  @Test
  @DisplayName("声明2-核心：写端点越权参数 → L-C + ENDPOINT_PARAMETER_POLICY（不是 L-A 哨兵）")
  void lcPrimeReachableForWriteEndpoint() {
    var fixture = rigForClaim2();

    CapabilityDeniedException denied =
        assertDeniedAt(
            CapabilityDeniedException.Layer.PARAMETER,
            "ENDPOINT_PARAMETER_POLICY",
            () ->
                fixture
                    .gate()
                    .invoke(
                        "invoke_endpoint",
                        params(
                            "method", "POST",
                            "path", "/api/tasks",
                            "body",
                                params(
                                    "targetId", 1L,
                                    "toolCode", "msf_scan",
                                    "parameters", params("module", "evil/not-a-real-module"))),
                        anonymous()));

    // 附加证据：确认拒绝消息确实来自端点参数策略（而非同名不同路径）。
    org.junit.jupiter.api.Assertions.assertTrue(
        denied.getMessage().contains("端点透传参数越权"),
        "拒绝消息应来自端点透传参数策略，实际: " + denied.getMessage());
    // 审计留痕（拒绝路径必须落审计）。
    org.junit.jupiter.api.Assertions.assertTrue(
        fixture.audit().hasDenialReason("ENDPOINT_PARAMETER_POLICY"),
        "L-C' 拒绝必须写审计（AGENT_CAPABILITY_DENIED + ENDPOINT_PARAMETER_POLICY）");
  }

  /**
   * <strong>对照组</strong>：同端点、同目标、同工具，只把越权 {@code module} 换成合法前缀 → 必须放行。
   *
   * <p>没有这一条，"L-C' 可达"可能只是因为策略把所有输入都拒了（误伤）。
   *
   * <p>用 {@code humanApproved()} 上下文：{@code invoke_endpoint} 恒
   * {@code requiresApproval()==true}，因此 L-B 之后的确认阶段需要
   * {@code context.humanApproved()}，否则会抛 {@code APPROVAL_REQUIRED}
   * （那是确认机制，不是 L-C'）。
   */
  @Test
  @DisplayName("声明2-对照组：写端点合法参数 → 放行（证明 L-C' 未误伤）")
  void legalWriteEndpointParametersPass() {
    var fixture = rigForClaim2();

    assertAllowed(
        () ->
            fixture
                .gate()
                .invoke(
                    "invoke_endpoint",
                    params(
                        "method", "POST",
                        "path", "/api/tasks",
                        "body",
                            params(
                                "targetId", 1L,
                                "toolCode", "msf_scan",
                                "parameters", params("module", "auxiliary/scanner/portscan/tcp"))),
                    IndependentFixture.humanApproved()),
        "合法 msf 模块（auxiliary/ 前缀）应放行");
  }

  /**
   * 越权变体二：工具参数含<strong>未允许字段</strong> → 仍须 L-C + {@code ENDPOINT_PARAMETER_POLICY}。
   *
   * <p>换一条规则（白名单而非 MSF 前缀），证明 L-C' 的可达性不依赖单条规则。
   */
  @Test
  @DisplayName("声明2-变体：未允许的工具参数字段 → L-C + ENDPOINT_PARAMETER_POLICY")
  void disallowedToolParameterFieldIsCaughtByLcPrime() {
    var fixture = rigForClaim2();

    assertDeniedAt(
        CapabilityDeniedException.Layer.PARAMETER,
        "ENDPOINT_PARAMETER_POLICY",
        () ->
            fixture
                .gate()
                .invoke(
                    "invoke_endpoint",
                    params(
                        "method", "POST",
                        "path", "/api/tasks",
                        "body",
                            params(
                                "targetId", 1L,
                                "toolCode", "tcp_ports",
                                // tcp_ports 只允许 "ports"；这里塞一个未允许字段。
                                "parameters", params("ports", "80", "evilField", "x"))),
                    anonymous()));
  }

  /**
   * 越权变体三：<strong>端口超出目标授权范围</strong> → 仍须 L-C + {@code ENDPOINT_PARAMETER_POLICY}。
   *
   * <p>目标授权端口是 {@code 80,443}；请求 {@code 3306} 属越权。
   */
  @Test
  @DisplayName("声明2-变体：透传端口越权 → L-C + ENDPOINT_PARAMETER_POLICY")
  void portEscalationThroughEndpointIsCaughtByLcPrime() {
    var fixture = rigForClaim2();

    assertDeniedAt(
        CapabilityDeniedException.Layer.PARAMETER,
        "ENDPOINT_PARAMETER_POLICY",
        () ->
            fixture
                .gate()
                .invoke(
                    "invoke_endpoint",
                    params(
                        "method", "POST",
                        "path", "/api/tasks",
                        "body",
                            params(
                                "targetId", 1L,
                                "toolCode", "tcp_ports",
                                "parameters", params("ports", "3306"))),
                    anonymous()));
  }

  /**
   * <strong>关键反证</strong>：L-C' 确实在执行——用一条<strong>只有端点策略才会产生</strong>的
   * 拒绝理由来证明。
   *
   * <p>{@code EndpointParameterPolicy} 是 {@code final} 类，无法子类化做 spy。因此改用
   * "独有原因码 + 独有消息"策略：
   *
   * <ul>
   *   <li>拒绝层必须是 <strong>L-C</strong>（{@code PARAMETER}）
   *   <li>原因码必须是 <strong>{@code ENDPOINT_PARAMETER_POLICY}</strong>
   *       —— 全项目只有 {@code validateEndpointParameterPolicy} 会产生它
   *   <li>消息必须含 {@code "端点透传参数越权"} 与策略抛出的原始文本
   * </ul>
   *
   * <p>这三者同时成立，等价于"策略的 {@code validateTaskCreationBody} 真的被调用了"。
   * 若 L-C' 是死代码，拒绝会来自 L-A（层不符）→ 本用例失败，不会伪装通过。
   */
  @Test
  @DisplayName("声明2-反证：L-C' 确实在执行（原因码 + 消息双重独有特征）")
  void lcPrimeIsActuallyExecuted() {
    PortRangeParser parser = new PortRangeParser();
    var targetPolicy = new com.bachelor.toolbox.target.TargetPolicyService(false, parser);
    EndpointParameterPolicy policy = new EndpointParameterPolicy(parser, 65535, targetPolicy);

    var fixture = rigWithInvokeEndpoint(targets(), WHITELIST, policy, null, ENDPOINTS);

    CapabilityDeniedException denied =
        assertDeniedAt(
            CapabilityDeniedException.Layer.PARAMETER,
            "ENDPOINT_PARAMETER_POLICY",
            () ->
                fixture
                    .gate()
                    .invoke(
                        "invoke_endpoint",
                        params(
                            "method", "POST",
                            "path", "/api/tasks",
                            "body",
                                params(
                                    "targetId", 1L,
                                    "toolCode", "msf_scan",
                                    "parameters", params("module", "not-a-valid-prefix"))),
                        anonymous()));

    // 消息必须包含 EndpointParameterPolicy 内部抛出的原始文本——这是"策略真的跑了"的直接证据。
    org.junit.jupiter.api.Assertions.assertTrue(
        denied.getMessage().contains("端点透传参数越权"),
        "拒绝消息必须来自 validateEndpointParameterPolicy 的包装，实际: " + denied.getMessage());
    org.junit.jupiter.api.Assertions.assertTrue(
        denied.getMessage().contains("MSF 模块仅允许"),
        "拒绝消息必须包含 EndpointParameterPolicy 内部规则抛出的原文（证明策略真的执行了），实际: "
            + denied.getMessage());

    // 直接调用策略本身，确认上面消息里的文本确实来自它（排除巧合）。
    com.bachelor.toolbox.common.ApiException direct =
        org.junit.jupiter.api.Assertions.assertThrows(
            com.bachelor.toolbox.common.ApiException.class,
            () ->
                policy.validateTaskCreationBody(
                    targets().get(1L),
                    params(
                        "toolCode", "msf_scan",
                        "parameters", params("module", "not-a-valid-prefix"))),
            "策略自身必须对同一载荷抛异常");
    org.junit.jupiter.api.Assertions.assertTrue(
        direct.getMessage().contains("MSF 模块仅允许"),
        "策略自身的拒绝文本应与经护栏包装后的一致");
  }

  /**
   * 层序证据：<strong>同一调用</strong>在"目标不存在"时必须是 L-A 拒绝，
   * 在"目标存在但参数越权"时必须是 L-C' 拒绝——证明两层都真实存在且顺序正确。
   *
   * <p>这是对"L-C' 可达"最有力的旁证：若 L-A 仍无条件先拒，本用例的前半段会通过、
   * 后半段必然失败（层不符）。
   */
  @Test
  @DisplayName("声明2-层序：目标不存在 → L-A；目标存在 + 参数越权 → L-C'")
  void layerOrderIsObservable() {
    var fixture = rigForClaim2();

    // ① 目标不存在（targetId=999 未授权）→ L-A。
    assertDeniedAt(
        CapabilityDeniedException.Layer.AUTHORIZATION,
        "TARGET_NOT_FOUND",
        () ->
            fixture
                .gate()
                .invoke(
                    "invoke_endpoint",
                    params(
                        "method", "POST",
                        "path", "/api/tasks",
                        "body",
                            params(
                                "targetId", 999L,
                                "toolCode", "tcp_ports",
                                "parameters", params("ports", "80"))),
                    anonymous()));

    // ② 目标存在（1L 已授权）+ 参数越权 → L-C'（不是 L-A）。
    assertDeniedAt(
        CapabilityDeniedException.Layer.PARAMETER,
        "ENDPOINT_PARAMETER_POLICY",
        () ->
            fixture
                .gate()
                .invoke(
                    "invoke_endpoint",
                    params(
                        "method", "POST",
                        "path", "/api/tasks",
                        "body",
                            params(
                                "targetId", 1L,
                                "toolCode", "tcp_ports",
                                "parameters", params("ports", "3306"))),
                    anonymous()));
  }

  /**
   * 负向对照：<strong>非</strong>任务创建端点不应触发 L-C'。
   *
   * <p>用 {@code GET /api/tasks}（只读、无 body）调用，应能通过（或至少不因 L-C' 被拒）。
   * 这防止"L-C' 可达"是因为它把一切都拦了。
   */
  @Test
  @DisplayName("声明2-负向对照：只读端点调用不被 L-C' 误拦")
  void readOnlyEndpointIsNotBlockedByLcPrime() {
    var fixture =
        rigWithInvokeEndpoint(
            targets(),
            WHITELIST,
            new EndpointParameterPolicy(new PortRangeParser(), 65535, null),
            null,
            List.<String[]>of(new String[] {"GET", "/api/tasks"}));

    // GET 端点不含 targetId → InvokeEndpointCapability 返回哨兵 → L-A 拒绝。
    // 这是预期的（只读端点应改用具体能力），但拒绝层必须是 L-A 而不是 L-C'。
    assertDeniedAt(
        CapabilityDeniedException.Layer.AUTHORIZATION,
        "TARGET_BINDING_UNRESOLVED",
        () ->
            fixture
                .gate()
                .invoke(
                    "invoke_endpoint",
                    params("method", "GET", "path", "/api/tasks"),
                    anonymous()));
  }

  /**
   * 未装配端点策略时 L-C' 跳过（对照组，证明装配是生效前提）。
   *
   * <p><strong>注意</strong>：这里不能断言"放行"——{@code InvokeEndpointCapability.validateParams}
   * 自身会做三重约束校验，且 {@code invoke_endpoint} 需要确认。
   * 因此本用例只断言<strong>不出现 {@code ENDPOINT_PARAMETER_POLICY}</strong>，
   * 即 L-C' 确实被跳过。
   */
  @Test
  @DisplayName("声明2-前提：未装配 EndpointParameterPolicy 时 L-C' 跳过")
  void withoutPolicyLcPrimeIsSkipped() {
    var fixture = rigWithInvokeEndpoint(targets(), WHITELIST, null, null, ENDPOINTS);
    // 未装配策略时，越权参数不会被 L-C' 拦下（策略为 null → validateEndpointParameterPolicy 直接 return）。
    try {
      fixture
          .gate()
          .invoke(
              "invoke_endpoint",
              params(
                  "method", "POST",
                  "path", "/api/tasks",
                  "body",
                      params(
                          "targetId", 1L,
                          "toolCode", "msf_scan",
                          "parameters", params("module", "evil/x"))),
              IndependentFixture.humanApproved());
      // 放行也符合预期（策略未装配 → L-C' 不介入）。
    } catch (CapabilityDeniedException denied) {
      org.junit.jupiter.api.Assertions.assertNotEquals(
          "ENDPOINT_PARAMETER_POLICY",
          denied.reasonCode(),
          "未装配策略时不应出现 ENDPOINT_PARAMETER_POLICY 拒绝（说明 L-C' 未按预期跳过）");
    }
  }
}
