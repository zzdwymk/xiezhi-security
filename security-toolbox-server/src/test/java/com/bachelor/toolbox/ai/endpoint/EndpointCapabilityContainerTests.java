package com.bachelor.toolbox.ai.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * 端点派生与 {@code invoke_endpoint} 的<strong>容器装配</strong>验收。
 *
 * <p>单元测试全绿抓不到 Spring 装配错误（task-1 实测：{@code @Component} + {@code @Bean} 重复定义会抛
 * {@code No default constructor found}，只有容器测试暴露）。本测试因此覆盖三类装配风险：
 *
 * <ol>
 *   <li>{@link EndpointCapabilityScanner} 确实完成了扫描，且注册表非空
 *   <li><strong>task-1 的 13 个 SecurityTool 能力仍在注册表里</strong>——这是"不要定义自己的
 *       {@code CapabilityRegistry} Bean"这条硬约束的回归测试
 *   <li>{@link InvokeEndpointCapability} 已被装配，且其反向映射在真实端点上可用
 * </ol>
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:endpoint-scan-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.ai.api-key=",
      "toolbox.ai.enabled=false",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-ca-password=test-mitm-ca-password-1d6ad9b95b76490e",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.scanner-pocs.import-on-startup=false"
    })
class EndpointCapabilityContainerTests {

  @Autowired private EndpointCapabilityScanner scanner;
  @Autowired private EndpointRegistry endpointRegistry;
  @Autowired private InvokeEndpointCapability invokeEndpointCapability;
  @Autowired private CapabilityRegistry capabilityRegistry;
  @Autowired private SecurityToolRegistry toolRegistry;

  @Test
  void scannerDerivesEndpointsAtStartup() {
    assertTrue(scanner.isScanned(), "启动时应完成端点扫描");
    assertTrue(scanner.handlerMethodCount() > 100, "实际 MVC 映射数: " + scanner.handlerMethodCount());
    assertTrue(scanner.capabilityCount() > 100, "派生能力数: " + scanner.capabilityCount());
    assertEquals(scanner.capabilityCount(), endpointRegistry.size());
  }

  @Test
  void everySkippedMappingHasARecordedReason() {
    // 覆盖率审计（§10 局限 5）：被跳过的映射必须有原因，否则"漏判"会静默发生。
    scanner
        .skipped()
        .forEach(
            (info, reason) -> {
              assertNotNull(reason, info);
              assertFalse(reason.isBlank(), info);
            });
    scanner
        .conflicts()
        .forEach(
            (code, dropped) -> {
              assertNotNull(code);
              assertFalse(dropped.isEmpty(), code);
            });
  }

  @Test
  void taskOneSecurityToolCapabilitiesSurviveInTheRegistry() {
    // 回归测试：若有人定义了同名 CapabilityRegistry Bean，task-1 的默认实现会被替换，
    // 13 个 SecurityTool 能力将从注册表消失，护栏会把它们误判为"未知能力"。
    List<SecurityTool> tools = List.copyOf(toolRegistry.all());
    assertFalse(tools.isEmpty(), "SecurityTool 注册表不应为空");
    for (SecurityTool tool : tools) {
      assertTrue(
          capabilityRegistry.find(tool.code()).isPresent(),
          "SecurityTool 能力从注册表消失: " + tool.code());
    }
    assertEquals(tools.size(), tools.stream().filter(t -> capabilityRegistry.find(t.code()).isPresent()).count());
  }

  @Test
  void registryContainsBothRouteAAndRouteBCapabilities() {
    // 路线 A（SecurityTool）与路线 B（端点派生）必须共存，而不是互相覆盖。
    long endpointCapabilities =
        capabilityRegistry.all().stream()
            .filter(c -> c.code().startsWith(EndpointCapability.CODE_PREFIX))
            .count();

    // ⚠️ 关键断言：端点能力必须是**精确数量**，不能只断言 > 0。
    // 装配陷阱会让端点能力静默丢失，只有精确数量断言能抓住它。
    // 注意这里断言的是"扫描器派生了几个"与"注册表里有几个"**相等**，
    // 而不是写死 168 —— 端点数量由运行期 MVC 扫描决定，不是常量。
    assertEquals(
        scanner.capabilityCount(),
        endpointCapabilities,
        "端点能力未完整进入 CapabilityRegistry：期望 "
            + scanner.capabilityCount()
            + "，实际 "
            + endpointCapabilities);

    // SecurityTool 能力一个都不能丢（这是不变量，与端点数量无关）。
    for (SecurityTool tool : toolRegistry.all()) {
      assertTrue(
          capabilityRegistry.find(tool.code()).isPresent(),
          "SecurityTool 能力从注册表消失: " + tool.code());
    }
    assertTrue(endpointCapabilities > 0, "端点派生能力数应大于 0");
  }

  @Test
  void registrySizeIsTheSumOfAllThreeCapabilitySources() {
    // ⚠️ 断言"不变量"而不是"快照值"：
    //   - 端点数量由运行期 MVC 扫描决定（当前 168，但会随控制器增删而变）
    //   - 后续任务（task-4 的 ai/capability/core 等）会新增**其它**能力来源
    // 因此这里**不写死总数 182**，而是断言"端点能力全部入册 + 注册表不小于已知来源之和"。
    // 写死总数会让本测试在合法新增能力来源时失败 —— 那是测试脆性，不是回归。
    int tools = toolRegistry.all().size();
    int endpoints = scanner.capabilityCount();
    int primitive = capabilityRegistry.find(InvokeEndpointCapability.CODE).isPresent() ? 1 : 0;
    long endpointDerivedInRegistry =
        capabilityRegistry.all().stream()
            .filter(c -> c.code().startsWith(EndpointCapability.CODE_PREFIX))
            .count();

    System.out.printf(
        "[能力来源核对] SecurityTool=%d，端点派生=%d，invoke_endpoint=%d，注册表总数=%d%n",
        tools, endpoints, primitive, capabilityRegistry.size());

    // 不变量 1：扫描器派生的端点能力**全部**进入了注册表（这正是静默丢失的检测点）。
    assertEquals(
        endpoints,
        endpointDerivedInRegistry,
        "端点能力未完整进入 CapabilityRegistry —— 注入被静默丢弃");

    // 不变量 2：SecurityTool 能力**全部**仍在册（回归保护，防止被端点能力覆盖）。
    assertEquals(
        tools,
        toolRegistry.all().stream()
            .filter(t -> capabilityRegistry.find(t.code()).isPresent())
            .count(),
        "SecurityTool 能力被覆盖或丢失");

    // 不变量 3：注册表不小于已知来源之和（允许存在**其它**来源，如 task-4 的 core 能力）。
    assertTrue(
        capabilityRegistry.size() >= tools + endpoints + primitive,
        "注册表总数 "
            + capabilityRegistry.size()
            + " 小于已知来源之和 "
            + (tools + endpoints + primitive)
            + " —— 有能力的注入被静默丢弃");

    assertTrue(tools >= 13, "SecurityTool 能力数异常: " + tools);
    assertTrue(endpoints >= 160, "端点派生能力数异常: " + endpoints);
  }

  @Test
  void invokeEndpointPrimitiveIsWiredAndMapsRealEndpoints() {
    assertNotNull(invokeEndpointCapability);
    assertEquals("invoke_endpoint", invokeEndpointCapability.code());

    // 真实端点上的三重约束：已注册的只读端点可通过。
    assertTrue(invokeEndpointCapability.isReachable("GET", "/api/audits"));

    // 未注册端点被拒（第一重）。
    assertFalse(invokeEndpointCapability.isReachable("GET", "/api/definitely-not-registered"));
    // 路径遍历被拒（第三重）。
    assertFalse(invokeEndpointCapability.isReachable("GET", "/api/audits/../system/shutdown"));
    assertFalse(invokeEndpointCapability.isReachable("GET", "/api/%2e%2e/system/shutdown"));
  }

  @Test
  void invokeEndpointTargetBindingsIsTheSentinelInTheLiveContainer() {
    // 最关键的安全断言在真实装配下同样成立。
    assertEquals(
        Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
        invokeEndpointCapability.targetBindings(Map.of()));
  }

  @Test
  void riskyEndpointsAreNotInferredSafe() {
    // X-3：启动 MITM 代理的端点在真实扫描结果里必须不是 SAFE。
    endpointRegistry
        .capabilityFor("POST", "/api/traffic/proxy/start")
        .ifPresent(
            endpoint ->
                assertFalse(
                    endpoint.risk() == RiskLevel.SAFE,
                    "POST /api/traffic/proxy/start 被推断为 SAFE"));

    // X-5：审计查询在真实扫描结果里必须不是 SAFE。
    endpointRegistry
        .capabilityFor("GET", "/api/audits")
        .ifPresent(
            endpoint ->
                assertFalse(
                    endpoint.risk() == RiskLevel.SAFE,
                    "GET /api/audits 被推断为 SAFE"));
  }

  @Test
  void systemShutdownEndpointIsRegisteredAndDestructive() {
    // 黑名单端点必须能被反向映射到，否则 L-B 的"反向映射拒绝"就无从生效。
    EndpointCapability shutdown =
        endpointRegistry.capabilityFor("POST", "/api/system/shutdown").orElseThrow();
    assertEquals(RiskLevel.DESTRUCTIVE, shutdown.risk());
    assertTrue(shutdown.requiresApproval());
    // 无论黑名单由 task-2 是否已注入，反向映射都必须能取到该能力。
    assertEquals(shutdown, invokeEndpointCapability.requireUnderlying("POST", "/api/system/shutdown"));
  }

  @Test
  void invokeEndpointAppliesTheSameGovernanceToTheTaskCreationChannel() {
    // X-7 确认 POST /api/tasks 是一条真实的越权通道：它创建一个会去扫描目标的异步任务。
    // invoke_endpoint 必须对它套用与直接调用**同等**的治理，而不是放行。
    EndpointCapability tasks = endpointRegistry.capabilityFor("POST", "/api/tasks").orElseThrow();

    // 1) 底层能力本身要求显式 targetId（否则护栏 L-A 无从校验）。
    assertThrows(ApiException.class, () -> tasks.validateParams(Map.of()));

    // 2) 经原语调用时，同一约束必须同样生效 —— 这就是"原语不是特权通道"的具体体现。
    ApiException viaPrimitive =
        assertThrows(
            ApiException.class,
            () -> invokeEndpointCapability.validateParams(Map.of("method", "POST", "path", "/api/tasks")));
    assertTrue(viaPrimitive.getMessage().contains("targetId"), viaPrimitive.getMessage());

    // 3) 反向映射必须取回**同一个**底层能力对象，治理策略不得被稀释。
    assertEquals(tasks, invokeEndpointCapability.requireUnderlying("POST", "/api/tasks"));
    assertTrue(
        invokeEndpointCapability.riskFor("POST", "/api/tasks").ordinal() >= tasks.risk().ordinal(),
        "原语生效风险等级不得低于底层能力");
    assertTrue(
        invokeEndpointCapability.requiresApprovalFor("POST", "/api/tasks"),
        "间接执行类端点必须要求确认");

    // 4) 补齐 targetId 后放行 —— 治理是"同等"，不是"一律拒绝"（测误拦率）。
    invokeEndpointCapability.validateParams(
        Map.of("method", "POST", "path", "/api/tasks", "targetId", 7));
  }

  @Test
  void scanReportIsAvailableForAcceptanceEvidence() {
    // 把覆盖率数据打进测试日志，供验收报告引用（§10 局限 5 要求"启动时校验覆盖率"）。
    System.out.printf(
        "[端点派生报告] MVC 映射=%d，派生能力=%d，跳过=%d，能力码冲突=%d，注册表总数=%d%n",
        scanner.handlerMethodCount(),
        scanner.capabilityCount(),
        scanner.skipped().size(),
        scanner.conflicts().size(),
        capabilityRegistry.size());
    scanner.skipped().forEach((info, reason) -> System.out.printf("  跳过: %s -> %s%n", info, reason));
    assertTrue(scanner.capabilityCount() > 0);
  }
}
