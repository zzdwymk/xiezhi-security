package com.bachelor.toolbox.ai.guard;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * <strong>生产装配验证</strong>：D-5 的 {@code TargetPolicyService} 确实被注入。
 *
 * <h2>为什么需要这条测试（补独立验证者发现的缺口）</h2>
 *
 * <p>独立验证者（test-flipper）发现：{@code EndpointParameterPolicy} 的
 * {@code targetPolicyService} 是<strong>可空依赖</strong>，为 {@code null} 时
 * <strong>按设计跳过 D-5 的 URI/主机校验</strong>（向后兼容既有测试装配）。
 *
 * <p>后果：如果生产装配漏了注入，<strong>D-5 的全部校验会静默失效</strong>——
 * 云元数据 SSRF（{@code sqlmap_scan} + {@code path=http://169.254.169.254/...}）
 * 会直接放行，而<strong>所有单元测试仍然通过</strong>（因为它们用的是手工装配）。
 *
 * <p>这正是"测试通过 ≠ 防护生效"的又一个实例：<strong>被测对象对了，但装配不对</strong>。
 * 本测试直接断言生产配置类的行为，堵住这个缺口。
 *
 * <h2>断言的是"装配事实"，不是"配置值"</h2>
 *
 * <p>不读配置文件、不反射字段，而是<strong>调用配置类的方法</strong>拿真实对象再问它
 * "你有没有目标策略服务"。这样重构（改字段名、改注入方式）不会误报，
 * 只有"真的没注入"才会失败。
 */
@DisplayName("生产装配：D-5 的 TargetPolicyService 必须被注入")
class GuardProductionWiringTests {

  @Test
  @DisplayName("W-1 生产配置的 EndpointParameterPolicy 必须持有 TargetPolicyService")
  void productionEndpointParameterPolicyHasTargetPolicyService() {
    AgentCapabilityGuardConfiguration configuration = new AgentCapabilityGuardConfiguration();
    TargetPolicyService targetPolicyService = new TargetPolicyService(false, new PortRangeParser());

    // 生产 bean 的第三个参数是 toolbox.execution.max-ports-per-task（默认 65535）。
    EndpointParameterPolicy policy =
        configuration.endpointParameterPolicy(
            new PortRangeParser(), targetPolicyService, 65535);

    assertNotNull(policy, "生产配置必须能构造端点参数策略");
    assertTrue(
        policy.hasTargetPolicyService(),
        "生产装配必须注入 TargetPolicyService——否则 D-5 的 URI/主机校验（云元数据 SSRF 防线）"
            + "会静默失效，而所有单元测试仍会通过");
  }

  @Test
  @DisplayName("W-2 两参构造确实不持有（确认 hasTargetPolicyService 能区分两种装配）")
  void twoArgConstructorHasNoTargetPolicyService() {
    EndpointParameterPolicy policy =
        new EndpointParameterPolicy(new PortRangeParser(), 1024);

    // 对照组：证明 W-1 的断言不是恒真。
    // 若 hasTargetPolicyService() 恒返回 true，W-1 就成了"永远通过"的假测试。
    assertTrue(
        !policy.hasTargetPolicyService(),
        "两参构造（既有测试装配）按设计不持有 TargetPolicyService，"
            + "这正是 W-1 必须存在的原因——两种装配行为不同，必须验证生产用的是哪一种");
  }
}
