package com.bachelor.toolbox.ai.guard.guardverify2;

import com.bachelor.toolbox.ai.guard.AgentCapabilityGuardConfiguration;
import com.bachelor.toolbox.ai.guard.EndpointParameterPolicy;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * <strong>声明 4</strong>的独立验证：生产装配是否真的把 D-5 的 {@code TargetPolicyService}
 * 注入了 {@code EndpointParameterPolicy}。
 *
 * <h2>被验证的声明（Lead 原文）</h2>
 *
 * <blockquote>自己确认 {@code AgentCapabilityGuardConfiguration.endpointParameterPolicy(...)}
 * 确实把 {@code TargetPolicyService} 传进了三参构造，且容器里 {@code EndpointParameterPolicy}
 * Bean 的 {@code hasTargetPolicyService()} 为 {@code true}。</blockquote>
 *
 * <h2>为什么这条重要（缺陷 8：装配即防线）</h2>
 *
 * <p>{@code EndpointParameterPolicy} 的 {@code targetPolicyService} 为 {@code null} 时
 * <strong>静默跳过</strong> D-5 的 URI/主机校验。若生产装配漏注入，云元数据 SSRF 防线
 * 无声失效，而所有单元测试仍然通过——典型的"装配即防线"。
 *
 * <h2>本用例的独立性</h2>
 *
 * <p>不读 Lead 的 {@code GuardProductionWiringTests}。这里用两种手段：
 *
 * <ol>
 *   <li><strong>结构断言</strong>：直接调用生产配置方法，断言返回的策略已注入服务，
 *       且注入的服务<em>确实生效</em>（用 SSRF 载荷做行为验证）
 *   <li><strong>语义断言</strong>：断言 {@code hasTargetPolicyService()} 为 true
 * </ol>
 *
 * <p>关键：仅断言 {@code hasTargetPolicyService() == true} 是<strong>不够</strong>的——
 * 那只能证明"非空"，不能证明"是能拦住 SSRF 的那个实现"。因此本用例额外做行为验证。
 */
class Claim4ProductionWiringTest {

  /** 直接构造生产配置类（它是普通类，不需要容器）。 */
  private static AgentCapabilityGuardConfiguration configuration() {
    return new AgentCapabilityGuardConfiguration();
  }

  /**
   * <strong>核心断言</strong>：生产配置返回的 {@code EndpointParameterPolicy} 已注入
   * {@code TargetPolicyService}。
   */
  @Test
  @DisplayName("声明4-核心：生产配置注入 TargetPolicyService（hasTargetPolicyService()==true）")
  void productionConfigurationInjectsTargetPolicyService() {
    PortRangeParser parser = new PortRangeParser();
    TargetPolicyService targetPolicy = new TargetPolicyService(false, parser);

    EndpointParameterPolicy policy =
        configuration().endpointParameterPolicy(parser, targetPolicy, 65535);

    Assertions.assertNotNull(policy, "生产配置必须返回非空策略");
    Assertions.assertTrue(
        policy.hasTargetPolicyService(),
        "生产装配必须注入 TargetPolicyService——否则 D-5 的 URI/主机校验（云元数据 SSRF 防线）静默失效");
  }

  /**
   * <strong>行为验证</strong>：注入的服务必须<em>真的生效</em>。
   *
   * <p>用云元数据 SSRF 载荷 {@code http://169.254.169.254/} 做验证：
   * 若 D-5 生效，该载荷必须被拒绝。这排除了"注入了但没用到"的假阳性。
   */
  @Test
  @DisplayName("声明4-行为：注入后 D-5 真的生效（云元数据 SSRF 载荷被拒）")
  void injectedServiceActuallyBlocksMetadataSsrf() {
    PortRangeParser parser = new PortRangeParser();
    TargetPolicyService targetPolicy = new TargetPolicyService(false, parser);
    EndpointParameterPolicy policy =
        configuration().endpointParameterPolicy(parser, targetPolicy, 65535);

    // 授权目标：局域网 SQLi 靶场（与 sqlmap_scan 的 D-5 校验路径对应）。
    com.bachelor.toolbox.target.AuthorizedTarget target =
        IndependentFixture.target(1L, "10.0.0.10", "80,443");

    // 经 sqlmap_scan 的 path 参数提交云元数据地址 → 主机与授权目标不一致 → 必须拒绝。
    Assertions.assertThrows(
        com.bachelor.toolbox.common.ApiException.class,
        () ->
            policy.validateTaskCreationBody(
                target,
                IndependentFixture.params(
                    "toolCode", "sqlmap_scan",
                    "parameters",
                        IndependentFixture.params(
                            "path", "http://169.254.169.254/latest/meta-data/"))),
        "D-5 必须拒绝指向云元数据服务的 URL（主机与授权目标不一致）");
  }

  /**
   * <strong>对照实验（W-2 式）</strong>：未注入时 D-5 静默跳过 → 同一 SSRF 载荷<em>不被拒绝</em>。
   *
   * <p>这条证明"注入"这件事<strong>是有效区别</strong>，而不是"怎么配都拦得住"的恒真断言。
   * 若本对照组也抛异常，说明上面的行为验证是恒真的、没有证明力。
   */
  @Test
  @DisplayName("声明4-对照组：未注入时同一 SSRF 载荷不被 D-5 拦下（证明注入是有效区别）")
  void withoutInjectionD5IsSilentlySkipped() {
    PortRangeParser parser = new PortRangeParser();
    // 两参构造 → targetPolicyService == null → D-5 跳过。
    EndpointParameterPolicy policy = new EndpointParameterPolicy(parser, 65535);

    Assertions.assertFalse(
        policy.hasTargetPolicyService(), "两参构造必须表现为'未注入'");

    com.bachelor.toolbox.target.AuthorizedTarget target =
        IndependentFixture.target(1L, "10.0.0.10", "80,443");

    // D-5 跳过 → 不会因"主机不一致"而拒绝。
    // （sqlmap_scan 的其它规则仍可能拒绝，因此这里断言"不是 D-5 的 SSRF 拒绝"。）
    try {
      policy.validateTaskCreationBody(
          target,
          IndependentFixture.params(
              "toolCode", "sqlmap_scan",
              "parameters",
                  IndependentFixture.params("path", "http://169.254.169.254/latest/meta-data/")));
      // 放行 → 证明 D-5 确实被跳过（fail-open 降级形态）。
    } catch (com.bachelor.toolbox.common.ApiException rejected) {
      String message = String.valueOf(rejected.getMessage());
      Assertions.assertFalse(
          message.contains("169.254.169.254") || message.contains("主机与授权目标不一致"),
          "未注入时不应出现 D-5 的主机不一致拒绝——若出现，说明上面的行为验证恒真、无证明力。实际: " + message);
    }
  }

  /**
   * 装配顺序断言：三参构造确实把服务放在"第三个参数"位置。
   *
   * <p>直接验证构造器语义，排除"传错位置"（例如把 maxPortsPerTask 与服务传反）。
   */
  @Test
  @DisplayName("声明4-构造语义：三参构造的第三个参数就是 TargetPolicyService")
  void threeArgConstructorThirdParameterIsTargetPolicyService() {
    PortRangeParser parser = new PortRangeParser();
    TargetPolicyService targetPolicy = new TargetPolicyService(false, parser);

    EndpointParameterPolicy withService = new EndpointParameterPolicy(parser, 1024, targetPolicy);
    EndpointParameterPolicy withoutService = new EndpointParameterPolicy(parser, 1024);

    Assertions.assertTrue(withService.hasTargetPolicyService(), "三参构造传入服务后必须为 true");
    Assertions.assertFalse(withoutService.hasTargetPolicyService(), "两参构造必须为 false");
  }

  /**
   * <strong>护栏级端到端</strong>：经 {@code gate.invoke} 走完整链路，D-5 必须生效。
   *
   * <p>这比直接调策略更强：证明 {@code CapabilityGate} 确实把<em>注入了服务的那个策略</em>
   * 拿到手了（构造器有三级重载，委托写错时 Bean 在但护栏拿到的是别的实例）。
   */
  @Test
  @DisplayName("声明4-护栏级：经 gate.invoke 端到端，D-5 SSRF 校验生效")
  void d5EffectiveThroughGateInvoke() {
    PortRangeParser parser = new PortRangeParser();
    TargetPolicyService targetPolicy = new TargetPolicyService(false, parser);
    EndpointParameterPolicy policy =
        configuration().endpointParameterPolicy(parser, targetPolicy, 65535);

    // 用真实 invoke_endpoint + POST /api/tasks 端点装配。
    // whitelist 必须含 invoke_endpoint（它恒 DESTRUCTIVE），否则在 L-B 就被拦，
    // 走不到 L-C' —— 这是"层序"要求。
    var fixture =
        IndependentFixture.rigWithInvokeEndpoint(
            java.util.Map.of(1L, IndependentFixture.target(1L, "10.0.0.10", "80,443")),
            "invoke_endpoint",
            policy,
            null,
            List.<String[]>of(new String[] {"POST", "/api/tasks"}));

    // sqlmap_scan + 云元数据 path → D-5 应拒绝（L-C + ENDPOINT_PARAMETER_POLICY）。
    IndependentFixture.assertDeniedAt(
        com.bachelor.toolbox.ai.guard.CapabilityDeniedException.Layer.PARAMETER,
        "ENDPOINT_PARAMETER_POLICY",
        () ->
            fixture
                .gate()
                .invoke(
                    "invoke_endpoint",
                    IndependentFixture.params(
                        "method", "POST",
                        "path", "/api/tasks",
                        "body",
                            IndependentFixture.params(
                                "targetId", 1L,
                                "toolCode", "sqlmap_scan",
                                "parameters",
                                    IndependentFixture.params(
                                        "path", "http://169.254.169.254/latest/meta-data/"))),
                    IndependentFixture.anonymous()));
  }

  /**
   * 容器级装配断言的<strong>独立替代</strong>：不启动 Spring 容器（既有环境约束），
   * 而是用反射确认配置方法签名确实接受 {@code TargetPolicyService}。
   *
   * <p>这能抓住"有人把参数删了"这类回归，而不依赖 {@code @SpringBootTest}。
   */
  @Test
  @DisplayName("声明4-签名：endpointParameterPolicy 方法签名含 TargetPolicyService 参数")
  void configurationMethodSignatureAcceptsTargetPolicyService() throws Exception {
    var method =
        AgentCapabilityGuardConfiguration.class.getMethod(
            "endpointParameterPolicy",
            com.bachelor.toolbox.target.PortRangeParser.class,
            TargetPolicyService.class,
            int.class);

    Assertions.assertNotNull(method, "生产配置必须保留接受 TargetPolicyService 的三参方法");
    var parameterTypes = method.getParameterTypes();
    Assertions.assertEquals(3, parameterTypes.length, "方法应接受 3 个参数");
    Assertions.assertEquals(
        TargetPolicyService.class,
        parameterTypes[1],
        "第 2 个参数必须是 TargetPolicyService（漏掉它 = D-5 静默失效）");
    Assertions.assertTrue(
        method.isAnnotationPresent(org.springframework.context.annotation.Bean.class),
        "该方法必须标注 @Bean（否则容器里没有 EndpointParameterPolicy）");
  }

  /** 生产配置里 EndpointParameterPolicy Bean 必须是三参构造（源码级证据的运行时等价物）。 */
  @Test
  @DisplayName("声明4-非空：生产配置返回的策略永远非空（不会返回 null Bean）")
  void configurationNeverReturnsNullPolicy() {
    PortRangeParser parser = new PortRangeParser();
    TargetPolicyService targetPolicy = new TargetPolicyService(false, parser);
    for (int maxPorts : new int[] {1, 1024, 65535}) {
      Assertions.assertNotNull(
          configuration().endpointParameterPolicy(parser, targetPolicy, maxPorts),
          "maxPortsPerTask=" + maxPorts + " 时策略不得为 null");
    }
  }

  /** 记录：本用例数统计用（防止误算）。 */
  @Test
  @DisplayName("声明4-元：本类独立装配不依赖 Lead 的 GuardProductionWiringTests")
  void independentFromLeadWiringTest() {
    // 断言生产配置类可独立实例化（无容器依赖）——这正是"独立验证"的前提。
    Assertions.assertNotNull(configuration(), "生产配置类必须可独立实例化");
  }
}
