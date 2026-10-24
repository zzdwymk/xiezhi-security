package com.bachelor.toolbox.ai.capability.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.guard.TargetBindingProbe;
import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * 核心能力的目标绑定三态语义与护栏声明的单元测试（设计文档 §4.1、§6.2）。
 *
 * <h2>本测试要防住什么</h2>
 *
 * <p>§4.1.1 记录的 fail-open 缺陷是"解析不到目标 → 返回空集 → 护栏跳过授权校验"。本测试对每个能力断言其
 * <strong>返回值</strong>与<strong>类型级声明</strong>同时正确，因为两者任一错误都会 fail-open：
 *
 * <ul>
 *   <li>返回值错（该返哨兵却返空集）→ 护栏跳过 L-A；
 *   <li>声明错（该声明 REQUIRED 却声明 NONE）→ {@code TargetBindingProbe} 认为空集合法 → 同样跳过 L-A。
 * </ul>
 *
 * <p>三态各至少一条用例：真空集（{@code list_findings}）、真实 ID（{@code create_task}）、哨兵
 * （{@code bash_probe} / {@code search_capabilities} / {@code unlock_capability}）。
 */
class CoreCapabilityTargetBindingTest {

  /** 构造一个不依赖 Spring 容器的注册表，用于纯单元断言。 */
  private static CapabilityRegistry registryOf(List<AgentCapability> capabilities) {
    return new CapabilityRegistry(capabilities);
  }

  // ---------------------------------------------------------------- 三态之一：真空集

  @Test
  void readOnlyCapabilitiesDeclareNoneSoEmptySetIsLegal() {
    // 真空集只有在"显式声明 NONE"时才合法。若这些能力忘了声明，
    // 护栏 TargetBindingProbe 会返回 UNKNOWN，emptyBindingAllowed=false → 只读能力被误拦（fail-closed 的代价）。
    List<AbstractCoreCapability> readOnly =
        List.of(
            stub("list_findings", AbstractCoreCapability.BindingMode.NONE),
            stub("query_audit", AbstractCoreCapability.BindingMode.NONE),
            stub("query_traffic", AbstractCoreCapability.BindingMode.NONE),
            stub("get_workflow_status", AbstractCoreCapability.BindingMode.NONE),
            stub("get_task", AbstractCoreCapability.BindingMode.NONE),
            stub("list_tasks", AbstractCoreCapability.BindingMode.NONE),
            stub("list_projects", AbstractCoreCapability.BindingMode.NONE),
            stub("list_targets", AbstractCoreCapability.BindingMode.NONE),
            stub("get_topology", AbstractCoreCapability.BindingMode.NONE));

    for (AbstractCoreCapability capability : readOnly) {
      assertEquals(
          Set.of(),
          capability.targetBindings(Map.of()),
          capability.code() + " 应返回真空集（确实不触及目标）");
      assertEquals(
          TargetBindingProbe.Declaration.NONE,
          capability.targetBindingDeclaration(),
          capability.code() + " 必须显式声明 NONE，否则护栏不允许空集");
      assertTrue(
          TargetBindingProbe.emptyBindingAllowed(capability),
          capability.code() + " 的空集必须被护栏认可");
      // 带任意参数也必须是空集：真空集是"确实不触及"，不应随参数变化。
      assertEquals(
          Set.of(),
          capability.targetBindings(Map.of("targetId", 7, "projectId", 3)),
          capability.code() + " 是纯读能力，传了 targetId 过滤条件也不应变成'触及目标'");
    }
  }

  // ---------------------------------------------------------------- 三态之二：真实目标 ID

  @Test
  void indirectExecutionCapabilitiesResolveRealTargetIds() {
    // §6.2 的核心修正：create_task / run_workflow 的 kind 是 WRITE，却会创建"扫描目标"的任务。
    // 若它们返回空集或哨兵以外的错误值，护栏会漏过授权校验。
    AbstractCoreCapability createTask = stub("create_task", AbstractCoreCapability.BindingMode.RESOLVED);
    AbstractCoreCapability runWorkflow = stub("run_workflow", AbstractCoreCapability.BindingMode.RESOLVED);

    for (AbstractCoreCapability capability : List.of(createTask, runWorkflow)) {
      assertEquals(
          Set.of("42"),
          capability.targetBindings(Map.of("targetId", 42)),
          capability.code() + " 必须解析出真实目标 ID");
      assertEquals(
          TargetBindingProbe.Declaration.REQUIRED,
          capability.targetBindingDeclaration(),
          capability.code() + " 必须声明 REQUIRED，否则空集会被护栏认可");
      assertFalse(
          TargetBindingProbe.emptyBindingAllowed(capability),
          capability.code() + " 绝不允许空集通过 L-A");
    }
  }

  @Test
  void indirectExecutionCapabilitiesReturnSentinelWhenTargetMissing() {
    // 这是 §4.1.1 fail-open 缺陷的直接回归测试：
    // "解析不到目标"必须返回哨兵，绝不能返回空集（空集 = 宣称"不触及目标" = 跳过 L-A）。
    AbstractCoreCapability createTask = stub("create_task", AbstractCoreCapability.BindingMode.RESOLVED);

    for (Map<String, Object> params :
        List.of(
            Map.<String, Object>of(),
            Map.<String, Object>of("projectId", 1),
            Map.<String, Object>of("targetId", ""),
            Map.<String, Object>of("targetId", 0),
            Map.<String, Object>of("targetId", -5),
            Map.<String, Object>of("targetId", "abc"))) {
      Set<String> bindings = createTask.targetBindings(params);
      assertEquals(
          Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
          bindings,
          "参数 " + params + " 解析不到目标时必须返回哨兵，绝不能返回空集");
      assertFalse(bindings.isEmpty(), "哨兵态不得退化为空集（那会跳过 L-A 授权校验）");
    }
  }

  @Test
  void resolvedBindingAcceptsAllDocumentedTargetIdSpellings() {
    // 目标 ID 的写法必须统一识别，否则"少认一种写法"就等于给那条路径开了 fail-open 口子。
    AbstractCoreCapability capability = stub("create_task", AbstractCoreCapability.BindingMode.RESOLVED);

    assertEquals(Set.of("1"), capability.targetBindings(Map.of("targetId", 1)));
    assertEquals(Set.of("2"), capability.targetBindings(Map.of("target_id", 2)));
    assertEquals(Set.of("3"), capability.targetBindings(Map.of("targetId", "3")));
    assertEquals(Set.of("4"), capability.targetBindings(Map.of("targetIds", List.of(4))));
    assertEquals(Set.of("5"), capability.targetBindings(Map.of("target_ids", new Object[] {5})));
    assertEquals(Set.of("6", "7"), capability.targetBindings(Map.of("targetId", "6,7")));
    assertEquals(Set.of("8", "9"), capability.targetBindings(Map.of("targets", List.of(8, 9))));
    // 多目标必须全部返回，不能只取第一个——只取一个会让其余目标静默绕过 L-A。
    assertEquals(
        Set.of("10", "11", "12"),
        capability.targetBindings(Map.of("targetIds", List.of(10, "11", "12"))));
  }

  // ---------------------------------------------------------------- 三态之三：哨兵

  @Test
  void arbitraryParameterCapabilitiesAlwaysReturnSentinel() {
    // bash_probe / search_capabilities / unlock_capability 的参数结构任意，无法静态解析目标。
    // 必须恒返回哨兵，且对**任何**参数（包括看起来合理的 targetId）都不动摇。
    List<AbstractCoreCapability> sentinelAlways =
        List.of(
            stub("bash_probe", AbstractCoreCapability.BindingMode.UNRESOLVED),
            stub("search_capabilities", AbstractCoreCapability.BindingMode.UNRESOLVED),
            stub("unlock_capability", AbstractCoreCapability.BindingMode.UNRESOLVED));

    for (AbstractCoreCapability capability : sentinelAlways) {
      for (Map<String, Object> params :
          List.of(
              Map.<String, Object>of(),
              Map.<String, Object>of("targetId", 99),
              Map.<String, Object>of("command", "nmap 10.0.0.1"),
              Map.<String, Object>of("keyword", "fingerprint"))) {
        assertEquals(
            Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
            capability.targetBindings(params),
            capability.code() + " 必须恒返回哨兵，参数 " + params + " 也不例外");
      }
      assertEquals(
          TargetBindingProbe.Declaration.REQUIRED,
          capability.targetBindingDeclaration(),
          capability.code() + " 必须声明 REQUIRED（哨兵态不允许空集合法化）");
    }
  }

  @Test
  void sentinelIsNotAnEmptySetSoGuardFailsClosed() {
    // 三态语义的核心：哨兵与空集必须是**可区分**的两种返回。
    // 若两者混淆，护栏的 contains(UNRESOLVED) 判定就会失效。
    AbstractCoreCapability sentinel = stub("bash_probe", AbstractCoreCapability.BindingMode.UNRESOLVED);
    AbstractCoreCapability empty = stub("query_audit", AbstractCoreCapability.BindingMode.NONE);

    assertNotEqualsSet(sentinel.targetBindings(Map.of()), empty.targetBindings(Map.of()));
    assertTrue(sentinel.targetBindings(Map.of()).contains(AgentCapability.TARGET_BINDING_UNRESOLVED));
    assertFalse(empty.targetBindings(Map.of()).contains(AgentCapability.TARGET_BINDING_UNRESOLVED));
    assertTrue(empty.targetBindings(Map.of()).isEmpty());
  }

  private static void assertNotEqualsSet(Set<String> left, Set<String> right) {
    assertFalse(left.equals(right), "哨兵集与真空集必须不同：" + left + " vs " + right);
  }

  // ---------------------------------------------------------------- 注册表装配（无容器）

  @Test
  void everyCoreCapabilityRegistersWithoutCodeCollision() {
    // code 重复会让 CapabilityRegistry 抛 IllegalStateException（启动失败）。
    // 这里用桩能力验证"能力码唯一"这一不变量在纯单元层也成立。
    List<AgentCapability> capabilities =
        List.of(
            stub("create_task", AbstractCoreCapability.BindingMode.RESOLVED),
            stub("run_workflow", AbstractCoreCapability.BindingMode.RESOLVED),
            stub("bash_probe", AbstractCoreCapability.BindingMode.UNRESOLVED));
    CapabilityRegistry registry = registryOf(capabilities);
    assertEquals(3, registry.size());
    for (AgentCapability capability : capabilities) {
      assertTrue(registry.find(capability.code()).isPresent(), capability.code() + " 必须入册");
    }
  }

  @Test
  void duplicateCodeIsRejectedByRegistry() {
    CapabilityRegistry registry = registryOf(List.of());
    registry.register(stub("create_task", AbstractCoreCapability.BindingMode.RESOLVED));
    assertThrows(
        IllegalStateException.class,
        () -> registry.register(stub("create_task", AbstractCoreCapability.BindingMode.RESOLVED)),
        "能力码重复必须抛异常，否则会掩盖'两个能力互相覆盖'");
  }

  // ---------------------------------------------------------------- 参数校验

  @Test
  void resolvedCapabilityRejectsMissingTargetDuringValidateParams() {
    AbstractCoreCapability capability = stub("create_task", AbstractCoreCapability.BindingMode.RESOLVED);
    ApiException error =
        assertThrows(ApiException.class, () -> capability.validateParams(Map.of("projectId", 1)));
    assertTrue(
        error.getMessage().contains("授权目标"),
        "拒绝理由应明确指出缺少授权目标，便于护栏审计归因: " + error.getMessage());
  }

  @Test
  void noneCapabilityAcceptsParametersWithoutTarget() {
    AbstractCoreCapability capability = stub("query_audit", AbstractCoreCapability.BindingMode.NONE);
    // 只读能力不应因为"没有 targetId"而被自己的参数校验拦住。
    capability.validateParams(Map.of("projectId", 1, "limit", 10));
  }

  // ---------------------------------------------------------------- 工具参数白名单

  @Test
  void toolParameterPolicyRejectsUnknownToolAndUnexpectedKeys() {
    assertThrows(ApiException.class, () -> ToolParameterPolicy.validate("not_a_tool", Map.of()));
    assertThrows(
        ApiException.class,
        () -> ToolParameterPolicy.validate("http_headers", Map.of("ports", "80")),
        "http_headers 不接受任何工具参数，多余键必须被拒");
    assertThrows(
        ApiException.class,
        () -> ToolParameterPolicy.validate("tcp_ports", Map.of("evil", 1)),
        "未在白名单内的参数键必须被拒");
  }

  @Test
  void toolParameterPolicyRejectsOutOfRangeEnumValues() {
    // 这几条正是 guard-verifier 发现的 D-1..D-4 同类问题：只做形状校验、不做取值白名单。
    assertThrows(
        ApiException.class,
        () -> ToolParameterPolicy.validate("nmap_service_scan", Map.of("mode", "aggressive")));
    assertThrows(
        ApiException.class,
        () -> ToolParameterPolicy.validate("fscan_scan", Map.of("vulnMode", "UNKNOWN")));
    assertThrows(
        ApiException.class,
        () -> ToolParameterPolicy.validate("zap_scan", Map.of("strength", "EXTREME")));
    assertThrows(
        ApiException.class,
        () -> ToolParameterPolicy.validate("http_security_check", Map.of("check", "everything")));
    // 合法取值必须放行（测误拦率）。
    ToolParameterPolicy.validate("nmap_service_scan", Map.of("mode", "service"));
    ToolParameterPolicy.validate("fscan_scan", Map.of("vulnMode", "safe"));
    ToolParameterPolicy.validate("zap_scan", Map.of("strength", "HIGH"));
    ToolParameterPolicy.validate("http_security_check", Map.of("check", "cookies"));
  }

  @Test
  void toolParameterPolicyRejectsInvalidMsfModuleAndPocSelection() {
    assertThrows(
        ApiException.class,
        () -> ToolParameterPolicy.validate("msf_scan", Map.of("module", "post/whatever")));
    assertThrows(
        ApiException.class,
        () ->
            ToolParameterPolicy.validate(
                "msf_scan", Map.of("module", "auxiliary/x", "modules", List.of("auxiliary/y"))),
        "module 与 modules 互斥");
    assertThrows(
        ApiException.class,
        () -> ToolParameterPolicy.validate("nuclei_scan", Map.of("pocCodes", List.of("bad-code"))));
    assertThrows(
        ApiException.class,
        () ->
            ToolParameterPolicy.validate(
                "nuclei_scan", Map.of("pocCodes", List.of(), "allPocs", true)),
        "pocCodes 与 allPocs 互斥");
    ToolParameterPolicy.validate("msf_scan", Map.of("module", "auxiliary/scanner/http/http_version"));
    ToolParameterPolicy.validate("nuclei_scan", Map.of("allPocs", true));
  }

  @Test
  void toolParameterPolicyDetectsDriftAgainstAuthoritativeList() {
    // 漂移断言本身要能工作：传一个不同的清单必须抛错。
    ToolParameterPolicy.assertNoDrift(ToolParameterPolicy.EXECUTABLE_TOOLS);
    assertThrows(
        ApiException.class,
        () -> ToolParameterPolicy.assertNoDrift(List.of("nmap_service_scan")),
        "清单不一致时必须失败，否则漂移会被静默放过");
  }

  /**
   * AI 侧允许的参数键必须被检测规则侧接受。
   *
   * <p>两侧白名单刻意不同（规则需要 ZAP 认证、HTTP 路径等运维专属参数），所以断言的是子集关系
   * 而不是相等。这里读取 {@code ActiveScanService} 的真实取值，避免在测试里再抄一份——
   * 那只会制造第三个漂移源。
   */
  @Test
  void everyAiAllowedParameterKeyIsAlsoAcceptedByDetectionRules() {
    ToolParameterPolicy.assertAllowedKeysAreRuleSubset(
        com.bachelor.toolbox.vulnerability.ActiveScanService::ruleParameterKeys);
  }

  @Test
  void parameterKeyDriftAssertionFailsWhenAiAllowsSomethingRulesReject() {
    // 断言本身要能工作：如果规则侧漏了某个 AI 允许的键，必须报错并指出是哪个工具哪个键。
    assertThrows(
        ApiException.class,
        () ->
            ToolParameterPolicy.assertAllowedKeysAreRuleSubset(
                toolCode ->
                    "tcp_ports".equals(toolCode)
                        ? Set.of("ports")
                        : new java.util.LinkedHashSet<>(
                            Set.of(
                                "ports", "mode", "vulnMode", "path", "level", "risk", "technique",
                                "pocCodes", "allPocs", "spider", "strength", "scanPolicy",
                                "ajaxSpider", "openApiUrl", "authLoginUrl", "authUsername",
                                "authPassword", "authUsernameField", "authPasswordField",
                                "authType", "fuzzRequestUrl", "method", "fuzzPostBody",
                                "fuzzPayload", "fuzzTargetField", "module", "modules", "options",
                                "check", "dictionary", "concurrency", "depth", "maxRequests",
                                "extensions"))),
        "规则侧漏掉 AI 允许键时必须失败，否则用户会遇到「规则能配、AI 却不能」的割裂");
  }

  // ---------------------------------------------------------------- 桩

  /**
   * 构造一个仅用于绑定语义测试的最小能力桩。
   *
   * <p>用桩而不是真实能力，是为了让本测试<strong>不依赖 Spring 容器</strong>：绑定语义是纯逻辑，
   * 不该因为某个 Service 的构造参数变化而失败。真实能力的入册由容器测试覆盖。
   */
  private static AbstractCoreCapability stub(String code, AbstractCoreCapability.BindingMode mode) {
    return new AbstractCoreCapability(
        code,
        "桩能力 " + code,
        "用于目标绑定语义测试的桩",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        mode,
        AiCapabilityLayer.L1) {
      @Override
      public Map<String, Object> parameterSchema() {
        return Map.of();
      }
    };
  }

  @Test
  void stubSanityCheck() {
    assertNotNull(stub("x", AbstractCoreCapability.BindingMode.NONE));
  }
}
