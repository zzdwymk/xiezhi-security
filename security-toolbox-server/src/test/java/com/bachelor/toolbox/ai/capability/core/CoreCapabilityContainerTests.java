package com.bachelor.toolbox.ai.capability.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.discovery.BashProbeCapability;
import com.bachelor.toolbox.ai.capability.discovery.CapabilityLayers;
import com.bachelor.toolbox.ai.capability.discovery.SearchCapabilitiesCapability;
import com.bachelor.toolbox.ai.capability.discovery.UnlockCapabilityCapability;
import com.bachelor.toolbox.ai.endpoint.EndpointCapability;
import com.bachelor.toolbox.ai.endpoint.EndpointCapabilityScanner;
import com.bachelor.toolbox.ai.endpoint.EndpointRegistry;
import com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * 核心能力（路线 A）的<strong>容器装配</strong>验收。
 *
 * <h2>为什么必须是容器测试</h2>
 *
 * <p>task-1/task-3 的实测结论（设计文档附录 C.3、D.4）：Spring 装配缺陷<strong>单元测试全绿也抓不到</strong>。
 * 本测试专门覆盖三类"单测全绿但能力静默丢失"的装配风险：
 *
 * <ol>
 *   <li><strong>能力被包成集合 Bean 提交</strong>：Spring 对 {@code List<T>} 构造注入只汇总"类型为 {@code T} 的独立
 *       Bean"，不展开集合 Bean → 25 个能力静默丢失（附录 D.4 的 6 种装配方式实测表，前 5 种全失败）；
 *   <li><strong>定义了同名 {@code CapabilityRegistry} Bean</strong>：Spring Boot 2.1+ 默认禁止定义覆盖 →
 *       启动失败；改 {@code @Primary} → 循环依赖；
 *   <li><strong>能力码重复</strong>：{@code register()} 抛 {@code IllegalStateException} → 启动失败。
 * </ol>
 *
 * <h2>断言口径：断言不变量，不断言快照值</h2>
 *
 * <p>刻意<strong>不</strong>写 {@code assertEquals(182, size())}：总数是快照值，端点数量由运行期 MVC 扫描决定，
 * 核心能力数量由本任务决定，硬编码会在任何控制器增删时脆性失败（附录 D.5 记录的"断言过时 vs 代码回归"正是这个坑）。
 *
 * <p>这里断言三条<strong>不变量</strong>：
 *
 * <ol>
 *   <li>本任务新增的每个核心能力都<strong>实际入册</strong>（静默丢失的检测点）；
 *   <li>SecurityTool 能力<strong>一个都不丢</strong>（回归：护栏没有替换默认注册表）；
 *   <li>注册表大小 ≥ 各已知来源之和（有注入被静默丢弃时会立刻失败）。
 * </ol>
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:core-capability-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
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
class CoreCapabilityContainerTests {

  /**
   * 本任务交付的全部核心能力码（L1 手工封装 + 发现层 + bash_probe）。
   *
   * <p>刻意写成<strong>显式清单</strong>而不是"扫包"：清单本身就是验收依据——它让"少了一个能力"变成可见的失败，
   * 而不是被"扫到什么算什么"掩盖。
   */
  private static final Set<String> EXPECTED_CORE_CODES =
      Set.of(
          // 工作流域
          "create_workflow",
          "run_workflow",
          "get_workflow_status",
          // 任务域
          "create_task",
          "list_tasks",
          "get_task",
          "cancel_task",
          "retry_task",
          "get_task_control_status",
          // 发现域
          "list_findings",
          "retest_finding",
          "update_finding_status",
          // 流量域
          "query_traffic",
          "analyze_packet",
          "replay_request",
          // 资产域
          "list_assets",
          "get_topology",
          "list_projects",
          "list_targets",
          // 报告域
          "generate_report",
          // 审计域
          "query_audit",
          // 发现层（§5 L2 按需解锁）
          "search_capabilities",
          "unlock_capability",
          // Bash（§7）
          "bash_probe");

  @Autowired private CapabilityRegistry capabilityRegistry;
  @Autowired private SecurityToolRegistry toolRegistry;
  @Autowired private EndpointRegistry endpointRegistry;
  @Autowired private EndpointCapabilityScanner scanner;
  @Autowired private InvokeEndpointCapability invokeEndpointCapability;
  @Autowired private List<AgentCapability> allCapabilityBeans;

  // ---------------------------------------------------------------- 不变量 1：核心能力实际入册

  @Test
  void everyCoreCapabilityIsActuallyRegistered() {
    // 这是"能力静默丢失"的检测点。若能力被包成 List Bean 提交，注册表只会看到 SecurityTool 能力，
    // 而单元测试仍然全绿（附录 D.4）。
    List<String> missing = new ArrayList<>();
    for (String code : EXPECTED_CORE_CODES) {
      if (capabilityRegistry.find(code).isEmpty()) {
        missing.add(code);
      }
    }
    assertTrue(
        missing.isEmpty(),
        "以下核心能力未进入注册表（静默丢失）：" + missing
            + "；注册表实际总数=" + capabilityRegistry.size());
  }

  @Test
  void coreCapabilityCountMatchesTheDeclaredInventory() {
    // 用"前缀/清单"而不是"硬编码总数"：新增能力时这条断言自动扩展，不会脆性失败。
    long registered =
        EXPECTED_CORE_CODES.stream().filter(code -> capabilityRegistry.find(code).isPresent()).count();
    assertEquals(
        EXPECTED_CORE_CODES.size(),
        registered,
        "声明了 " + EXPECTED_CORE_CODES.size() + " 个核心能力，实际入册 " + registered + " 个");
  }

  @Test
  void coreCapabilitiesAreAlsoVisibleAsIndependentBeans() {
    // 根因验证：核心能力必须是"类型为 AgentCapability 的独立 Bean"，
    // 这样 Spring 的 List<T> 构造注入才会把它们汇总给 CapabilityRegistry。
    // 如果它们只以集合 Bean 形式存在，本断言会失败——这比"注册表少了几条"更早定位到根因。
    Set<String> beanCodes = new LinkedHashSet<>();
    for (AgentCapability capability : allCapabilityBeans) {
      beanCodes.add(capability.code());
    }
    List<String> notBeans = new ArrayList<>();
    for (String code : EXPECTED_CORE_CODES) {
      if (!beanCodes.contains(code)) {
        notBeans.add(code);
      }
    }
    assertTrue(
        notBeans.isEmpty(),
        "以下核心能力不是独立的 AgentCapability Bean（可能被包成了集合 Bean）：" + notBeans);
  }

  // ---------------------------------------------------------------- 不变量 2：SecurityTool 能力不丢

  @Test
  void securityToolCapabilitiesSurviveInTheRegistry() {
    // 回归测试：若有人定义了同名 CapabilityRegistry Bean，task-1 的默认实现会被替换，
    // SecurityTool 能力将从注册表消失，护栏会把它们误判为"未知能力"。
    List<SecurityTool> tools = List.copyOf(toolRegistry.all());
    assertFalse(tools.isEmpty(), "SecurityTool 注册表不应为空");
    List<String> missing = new ArrayList<>();
    for (SecurityTool tool : tools) {
      if (capabilityRegistry.find(tool.code()).isEmpty()) {
        missing.add(tool.code());
      }
    }
    assertTrue(missing.isEmpty(), "以下 SecurityTool 能力丢失（注册表被替换？）：" + missing);
  }

  // ---------------------------------------------------------------- 不变量 3：注册表 ≥ 各来源之和

  @Test
  void registryIsAtLeastTheSumOfKnownSources() {
    int tools = toolRegistry.all().size();
    int core = EXPECTED_CORE_CODES.size();
    int endpoints = endpointRegistry.size();
    assertTrue(
        capabilityRegistry.size() >= tools + core,
        "注册表小于已知来源之和 —— 有注入被静默丢弃。注册表="
            + capabilityRegistry.size()
            + "，SecurityTool="
            + tools
            + "，核心能力="
            + core
            + "，端点="
            + endpoints);
  }

  // ---------------------------------------------------------------- 三态语义在真实装配下成立

  @Test
  void indirectExecutionCapabilitiesDeclareRealTargetBindingsUnderRealAssembly() {
    // 单元测试无法证明"在真实装配下也是真实目标集"。这里对容器里的实例再断言一次。
    for (String code : List.of("create_task", "run_workflow", "retest_finding", "cancel_task")) {
      AgentCapability capability = capabilityRegistry.require(code);
      Set<String> bindings = capability.targetBindings(Map.of("targetId", 7));
      assertEquals(
          Set.of("7"),
          bindings,
          code + " 在真实装配下必须解析出真实目标 ID（间接执行类能力）");
      assertFalse(bindings.isEmpty(), code + " 绝不允许返回空集（那会跳过 L-A 授权校验）");
    }
  }

  @Test
  void bashProbeReturnsSentinelUnderRealAssembly() {
    // 单元测试只能证明"我 new 出来的实例返回哨兵"。这里证明**容器装配的那个实例**也返回哨兵。
    AgentCapability capability = capabilityRegistry.require("bash_probe");
    assertEquals(
        Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
        capability.targetBindings(Map.of()),
        "bash_probe 在真实装配下必须返回哨兵");
    assertEquals(
        Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
        capability.targetBindings(Map.of("command", "nmap 10.0.0.1")),
        "命令里的主机无法静态解析为授权目标，必须恒为哨兵");
    // §7 指定的元数据。
    assertEquals(com.bachelor.toolbox.ai.capability.CapabilityKind.EXECUTE, capability.kind());
    assertEquals(com.bachelor.toolbox.ai.capability.RiskLevel.SENSITIVE, capability.risk());
    assertTrue(capability.requiresApproval(), "bash_probe 必须逐次人工确认");
  }

  @Test
  void discoveryCapabilitiesReturnSentinelUnderRealAssembly() {
    for (String code : List.of("search_capabilities", "unlock_capability")) {
      AgentCapability capability = capabilityRegistry.require(code);
      assertEquals(
          Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
          capability.targetBindings(Map.of()),
          code + " 在真实装配下必须返回哨兵");
    }
  }

  @Test
  void readOnlyCapabilitiesReturnEmptySetUnderRealAssembly() {
    // 三态的第一态：只读能力必须返回空集，且必须被护栏认可为"显式声明不触及目标"。
    for (String code : List.of("query_audit", "list_findings", "query_traffic", "list_tasks")) {
      AgentCapability capability = capabilityRegistry.require(code);
      assertTrue(
          capability.targetBindings(Map.of()).isEmpty(),
          code + " 是只读能力，应返回真空集");
      assertTrue(
          com.bachelor.toolbox.ai.guard.TargetBindingProbe.emptyBindingAllowed(capability),
          code + " 必须显式声明不触及目标，否则护栏会拒绝它的空集（fail-closed）");
    }
  }

  // ---------------------------------------------------------------- 分层（§5）

  @Test
  void invokeEndpointIsDirectlyExposedAndEndpointsAreUnlockable() {
    // L1：invoke_endpoint 是路线 C 的兜底，必须常驻 prompt。
    assertEquals(
        AiCapabilityLayer.L1, CapabilityLayers.layerOf(invokeEndpointCapability));
    // L2：端点派生能力按需解锁。
    assertTrue(endpointRegistry.size() > 0, "端点注册表不应为空");
    for (EndpointCapability endpoint : endpointRegistry.all()) {
      assertEquals(
          AiCapabilityLayer.L2,
          CapabilityLayers.layerOf(endpoint),
          "端点派生能力应归 L2：" + endpoint.code());
    }
    // L1：核心能力。
    assertEquals(
        AiCapabilityLayer.L1, CapabilityLayers.layerOf(capabilityRegistry.require("create_task")));
  }

  @Test
  void searchCapabilitiesFindsEndpointCapabilities() {
    // 分层必须"全序无遗漏"：端点能力查不到就等于不可达（本方案要避免的"能力静默不可达"）。
    SearchCapabilitiesCapability search =
        (SearchCapabilitiesCapability) capabilityRegistry.require("search_capabilities");
    List<Map<String, Object>> hits = search.search("endpoint_", 10);
    assertFalse(hits.isEmpty(), "按 'endpoint_' 搜索应命中端点派生能力");
    for (Map<String, Object> hit : hits) {
      assertEquals(Boolean.TRUE, hit.get("unlockable"), "搜索结果应标记可解锁: " + hit);
      assertEquals("L2", hit.get("layer"), "端点能力应为 L2: " + hit);
    }
  }

  @Test
  void unlockCapabilityUnlocksOnlyRegisteredCapabilities() {
    UnlockCapabilityCapability unlock =
        (UnlockCapabilityCapability) capabilityRegistry.require("unlock_capability");
    // 未注册的能力码不得被"预先解锁"——否则解锁集合会变成比注册表更宽的清单。
    Map<String, Object> rejected = unlock.unlock("no_such_capability_xyz", "test-session");
    assertEquals(Boolean.FALSE, rejected.get("accepted"), "未注册能力不得被解锁: " + rejected);
    // 已注册的 L2 端点能力应可解锁。
    EndpointCapability endpoint = endpointRegistry.all().iterator().next();
    Map<String, Object> accepted = unlock.unlock(endpoint.code(), "test-session");
    assertEquals(Boolean.TRUE, accepted.get("accepted"), "L2 能力应可解锁: " + accepted);
  }

  // ---------------------------------------------------------------- 验收证据

  @Test
  void registryCompositionIsReportedForAcceptanceEvidence() {
    // 把实测数字打进测试日志，供验收报告引用（避免报告数字与实现不一致）。
    long coreRegistered =
        EXPECTED_CORE_CODES.stream().filter(code -> capabilityRegistry.find(code).isPresent()).count();
    long endpointLike =
        capabilityRegistry.all().stream()
            .filter(capability -> capability.code().startsWith(EndpointCapability.CODE_PREFIX))
            .count();
    System.out.printf(
        "[核心能力验收] 注册表总数=%d = SecurityTool %d + 核心能力 %d + 端点 %d + 原语 1（invoke_endpoint）%n",
        capabilityRegistry.size(),
        toolRegistry.all().size(),
        coreRegistered,
        endpointLike);
    System.out.printf(
        "[核心能力验收] 声明 %d 个核心能力，实际入册 %d 个；端点注册表 %d 个；扫描器派生 %d 个%n",
        EXPECTED_CORE_CODES.size(),
        coreRegistered,
        endpointRegistry.size(),
        scanner.capabilityCount());
    assertNotNull(capabilityRegistry);
  }
}
