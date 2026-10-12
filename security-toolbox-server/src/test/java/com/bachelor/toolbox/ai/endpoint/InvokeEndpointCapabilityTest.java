package com.bachelor.toolbox.ai.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link InvokeEndpointCapability} 的三重约束（设计文档 §6.5）与 §9.5 越权用例。
 *
 * <p>本测试集对应论文验证方案的"越界拦截率"一栏：每条用例都显式验证"能做到但被拒"。
 */
class InvokeEndpointCapabilityTest {

  private static final String BLOCKED_CODE = "endpoint_post_api_system_shutdown";

  private EndpointRegistry endpointRegistry;
  private CapabilityRegistry capabilityRegistry;
  private InvokeEndpointCapability invoke;

  @BeforeEach
  void setUp() {
    endpointRegistry = new EndpointRegistry();
    endpointRegistry.register(EndpointCapability.derive("GET", "/api/audits", "AuditController#list()"));
    endpointRegistry.register(EndpointCapability.derive("GET", "/api/vulnerabilities", "x"));
    endpointRegistry.register(
        EndpointCapability.derive("GET", "/api/targets/{targetId}/discovered-paths", "x"));
    endpointRegistry.register(EndpointCapability.derive("POST", "/api/workflow-runs", "x"));
    endpointRegistry.register(EndpointCapability.derive("POST", "/api/tasks", "x"));
    endpointRegistry.register(EndpointCapability.derive("POST", "/api/system/shutdown", "x"));
    endpointRegistry.register(EndpointCapability.derive("DELETE", "/api/workflow-runs/{id}", "x"));

    // 黑名单：系统关机（§6.4 绝对禁止）
    capabilityRegistry =
        new CapabilityRegistry(
            List.copyOf(endpointRegistry.capabilities()), Set.of(BLOCKED_CODE));
    invoke = new InvokeEndpointCapability(endpointRegistry, capabilityRegistry);
  }

  private static Map<String, Object> call(String method, String path) {
    return Map.of("method", method, "path", path);
  }

  // ================================================================
  // P1-4 修复后的 targetBindings 语义：深度解析真实目标，解析不出才哨兵
  // ================================================================

  @Test
  void targetBindingsAlwaysReturnsTheUnresolvedSentinel() {
    // 无法从参数解析出任何目标时，仍必须返回哨兵（fail-closed）。
    // 这是本类最关键的断言：返回空集会让护栏以为"本能力不触及目标"而跳过 L-A 授权校验 → fail-open。
    Set<String> bindings = invoke.targetBindings(Map.of());
    assertEquals(Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED), bindings);
  }

  @Test
  void targetBindingsResolvesNestedTargetsAtEveryLevel() {
    // P1-4 修复（2026-10-12）：原实现恒返回哨兵，导致本原语对一切调用都不可用，
    // 且因 L-A 在 L-C' 之前而使 L-C' 成为死代码。
    //
    // 修复方式不是"放弃解析"，而是**深度解析**：在任意嵌套层级采集所有 targetId，
    // 从而消除原注释担心的"部分解析"风险（漏掉某个嵌套目标）。
    Map<String, Object> params =
        Map.of("method", "POST", "path", "/api/tasks", "targetId", 42, "body", Map.of("targetId", 43));

    Set<String> bindings = invoke.targetBindings(params);

    assertEquals(
        Set.of("42", "43"),
        bindings,
        "顶层与 body 内嵌的 targetId 都必须被采集——任一遗漏都会让该目标绕过 L-A 授权校验");
  }

  @Test
  void targetBindingsIsNeverAnEmptySet() {
    // 覆盖各种畸形输入，确保任何情况下都不会退化成空集。
    List<Map<String, Object>> samples =
        List.of(
            Map.of(),
            Map.of("method", "GET"),
            Map.of("path", "/api/audits"),
            Map.of("method", "GET", "path", "/api/audits"),
            Map.of("method", "POST", "path", "/api/system/shutdown", "body", Map.of("force", true)));
    for (Map<String, Object> params : samples) {
      Set<String> bindings = invoke.targetBindings(params);
      assertFalse(bindings.isEmpty(), "targetBindings 不得返回空集: " + params);
      assertTrue(bindings.contains(AgentCapability.TARGET_BINDING_UNRESOLVED));
    }
  }

  @Test
  void targetBindingsHandlesNullParams() {
    assertEquals(Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED), invoke.targetBindings(null));
  }

  @Test
  void sentinelDiffersFromARealTargetId() {
    // 哨兵必须不可能与真实目标 ID 冲突，否则护栏的 contains 判定会被伪造的目标 ID 骗过。
    assertFalse(AgentCapability.TARGET_BINDING_UNRESOLVED.matches("\\d+"));
    assertFalse(invoke.targetBindings(Map.of()).contains("1"));
  }

  // ================================================================
  // 第一重约束：端点白名单校验（§9.5「调用未注册端点 → 拒绝」）
  // ================================================================

  @Test
  void rejectsUnregisteredEndpoint() {
    ApiException error =
        assertThrows(ApiException.class, () -> invoke.validateParams(call("POST", "/api/nope")));
    assertTrue(error.getMessage().contains("未知端点"), error.getMessage());
  }

  @Test
  void rejectsRegisteredPathWithWrongMethod() {
    // GET /api/workflow-runs 未注册（只有 POST），必须拒绝而不是"路径对了就放行"。
    ApiException error =
        assertThrows(ApiException.class, () -> invoke.validateParams(call("GET", "/api/workflow-runs")));
    assertTrue(error.getMessage().contains("未知端点"));
  }

  @Test
  void rejectsEndpointNotCoveredByTheRegistry() {
    // §10 已知局限 5：端点注册表不完整时，未覆盖端点必须默认拒绝。
    assertThrows(ApiException.class, () -> invoke.validateParams(call("GET", "/api/secret/internal")));
    assertFalse(invoke.isReachable("GET", "/api/secret/internal"));
  }

  @Test
  void acceptsRegisteredEndpoint() {
    invoke.validateParams(call("GET", "/api/audits"));
    invoke.validateParams(Map.of("method", "POST", "path", "/api/workflow-runs", "targetId", 7));
    invoke.validateParams(Map.of("method", "GET", "path", "/api/targets/7/discovered-paths", "targetId", 7));
    assertTrue(invoke.isReachable("GET", "/api/audits"));
  }

  // ================================================================
  // 第二重约束：反向能力映射 + 黑名单（§9.5「调用黑名单端点 → 拒绝」）
  // ================================================================

  @Test
  void rejectsBlacklistedEndpointViaReverseMapping() {
    // 直接调用 POST /api/system/shutdown 会被 L-B 拒绝；经 invoke_endpoint 调用必须同样被拒。
    ApiException error =
        assertThrows(
            ApiException.class, () -> invoke.validateParams(call("POST", "/api/system/shutdown")));
    assertTrue(error.getMessage().contains("被禁止"), error.getMessage());
    assertTrue(error.getMessage().contains("黑名单"), error.getMessage());
  }

  @Test
  void blacklistIsCheckedAgainstTheUnderlyingCapabilityNotThePrimitive() {
    // 黑名单里放的是底层端点能力的 code，而不是 invoke_endpoint 自身；
    // 这证明拒绝来自"反向映射后套用底层能力策略"，而不是把原语整个禁掉。
    assertTrue(capabilityRegistry.isBlocked(BLOCKED_CODE));
    assertFalse(capabilityRegistry.isBlocked(InvokeEndpointCapability.CODE));

    // 非黑名单端点在同一个注册表下可正常通过，说明拒绝是精确的而非一刀切。
    invoke.validateParams(Map.of("method", "POST", "path", "/api/workflow-runs", "targetId", 7));
  }

  @Test
  void unblockedRegistryAllowsTheSameEndpointSoTheDenialIsCausedByTheBlacklist() {
    // 对照实验：同一端点，去掉黑名单后放行。证明上面的拒绝确实由黑名单引起。
    CapabilityRegistry permissive =
        new CapabilityRegistry(List.copyOf(endpointRegistry.capabilities()), Set.of());
    InvokeEndpointCapability openInvoke = new InvokeEndpointCapability(endpointRegistry, permissive);

    openInvoke.validateParams(
        Map.of("method", "POST", "path", "/api/system/shutdown", "targetId", 7));
    assertTrue(openInvoke.isReachable("POST", "/api/system/shutdown", 7));
  }

  @Test
  void requireUnderlyingReturnsTheMappedCapability() {
    AgentCapability underlying = invoke.requireUnderlying("POST", "/api/workflow-runs");
    assertEquals("endpoint_post_api_workflow_runs", underlying.code());
    assertThrows(ApiException.class, () -> invoke.requireUnderlying("POST", "/api/nope"));
  }

  // ================================================================
  // 第三重约束：路径规范化（§9.5「路径含 ../ → 拒绝」）
  // ================================================================

  @Test
  void rejectsPlainTraversal() {
    ApiException error =
        assertThrows(
            ApiException.class,
            () -> invoke.validateParams(call("POST", "/api/audits/../system/shutdown")));
    assertTrue(error.getMessage().contains("非法路径"), error.getMessage());
  }

  @Test
  void rejectsUrlEncodedTraversal() {
    ApiException error =
        assertThrows(
            ApiException.class,
            () -> invoke.validateParams(call("POST", "/api/%2e%2e/system/shutdown")));
    assertTrue(error.getMessage().contains("非法路径"), error.getMessage());
  }

  @Test
  void rejectsUppercaseEncodedTraversal() {
    assertThrows(
        ApiException.class, () -> invoke.validateParams(call("POST", "/api/%2E%2E/system/shutdown")));
  }

  @Test
  void rejectsDoubleEncodedTraversal() {
    assertThrows(
        ApiException.class,
        () -> invoke.validateParams(call("POST", "/api/%252e%252e/system/shutdown")));
  }

  @Test
  void rejectsMixedEncodingTraversal() {
    assertThrows(
        ApiException.class, () -> invoke.validateParams(call("POST", "/api/..%2f..%2fsystem")));
    assertThrows(
        ApiException.class, () -> invoke.validateParams(call("POST", "/api/%2e./system")));
  }

  @Test
  void rejectsEmptySegmentsTrailingSlashAndBackslash() {
    assertThrows(ApiException.class, () -> invoke.validateParams(call("GET", "/api//audits")));
    assertThrows(ApiException.class, () -> invoke.validateParams(call("GET", "/api/audits/")));
    assertThrows(ApiException.class, () -> invoke.validateParams(call("GET", "/api\\audits")));
    assertThrows(ApiException.class, () -> invoke.validateParams(call("GET", "/api%5caudits")));
  }

  @Test
  void rejectsEncodedNullByteAndNonAscii() {
    assertThrows(ApiException.class, () -> invoke.validateParams(call("GET", "/api/audits%00")));
    assertThrows(ApiException.class, () -> invoke.validateParams(call("GET", "/api／audits")));
    assertThrows(ApiException.class, () -> invoke.validateParams(call("GET", "/api/审计")));
  }

  @Test
  void rejectsQueryStringInPath() {
    // 查询串必须走 query 参数；写在 path 里会绕过注册表匹配。
    assertThrows(ApiException.class, () -> invoke.validateParams(call("GET", "/api/audits?page=1")));
  }

  @Test
  void rejectsPathWithoutLeadingSlashOrAbsoluteUrl() {
    assertThrows(ApiException.class, () -> invoke.validateParams(call("GET", "api/audits")));
    assertThrows(
        ApiException.class,
        () -> invoke.validateParams(call("GET", "http://evil.example.com/api/audits")));
  }

  // ================================================================
  // 第四重：参数结构校验
  // ================================================================

  @Test
  void rejectsMissingMethodOrPath() {
    ApiException missingMethod =
        assertThrows(ApiException.class, () -> invoke.validateParams(Map.of("path", "/api/audits")));
    assertTrue(missingMethod.getMessage().contains("method"));

    ApiException missingPath =
        assertThrows(ApiException.class, () -> invoke.validateParams(Map.of("method", "GET")));
    assertTrue(missingPath.getMessage().contains("path"));

    assertThrows(ApiException.class, () -> invoke.validateParams(Map.of()));
    assertThrows(ApiException.class, () -> invoke.validateParams(null));
  }

  @Test
  void rejectsUnsupportedHttpMethod() {
    assertThrows(ApiException.class, () -> invoke.validateParams(call("PROPFIND", "/api/audits")));
    assertThrows(ApiException.class, () -> invoke.validateParams(call("TRACE", "/api/audits")));
    assertThrows(ApiException.class, () -> invoke.validateParams(call("", "/api/audits")));
  }

  @Test
  void rejectsNonObjectBodyOrQuery() {
    assertThrows(
        ApiException.class,
        () -> invoke.validateParams(Map.of("method", "POST", "path", "/api/workflow-runs", "body", "text")));
    assertThrows(
        ApiException.class,
        () -> invoke.validateParams(Map.of("method", "GET", "path", "/api/audits", "query", List.of(1, 2))));
  }

  @Test
  void rejectsOversizedPath() {
    assertThrows(
        ApiException.class,
        () -> invoke.validateParams(call("GET", "/api/" + "a".repeat(PathNormalizer.MAX_LENGTH))));
  }

  // ================================================================
  // 与直接调用完全一致的治理策略（§6.5 核心思想）
  // ================================================================

  @Test
  void riskIsNeverLowerThanTheUnderlyingEndpoint() {
    for (String[] pair :
        List.of(
            new String[] {"GET", "/api/audits"},
            new String[] {"POST", "/api/workflow-runs"},
            new String[] {"DELETE", "/api/workflow-runs/9"},
            new String[] {"POST", "/api/tasks"},
            new String[] {"POST", "/api/system/shutdown"})) {
      RiskLevel underlyingRisk =
          endpointRegistry.capabilityFor(pair[0], pair[1]).orElseThrow().risk();
      RiskLevel effective = invoke.riskFor(pair[0], pair[1]);
      assertTrue(
          effective.ordinal() >= underlyingRisk.ordinal(),
          pair[0] + " " + pair[1] + " 生效等级 " + effective + " 低于底层 " + underlyingRisk);
    }
  }

  @Test
  void requiresApprovalIsNeverWeakerThanTheUnderlyingEndpoint() {
    for (String[] pair :
        List.of(
            new String[] {"GET", "/api/audits"},
            new String[] {"POST", "/api/workflow-runs"},
            new String[] {"DELETE", "/api/workflow-runs/9"},
            new String[] {"POST", "/api/tasks"})) {
      if (endpointRegistry.capabilityFor(pair[0], pair[1]).orElseThrow().requiresApproval()) {
        assertTrue(
            invoke.requiresApprovalFor(pair[0], pair[1]),
            pair[0] + " " + pair[1] + " 底层需确认，原语不得放行");
      }
    }
  }

  @Test
  void primitiveItselfIsAlwaysDestructiveAndAlwaysRequiresApproval() {
    // 静态视角下本原语可达任意端点，必须按最高等级对待；任何低于此的静态声明都是绕过通道。
    assertEquals(RiskLevel.DESTRUCTIVE, invoke.risk());
    assertTrue(invoke.requiresApproval());
  }

  @Test
  void unregisteredEndpointYieldsFailClosedPolicy() {
    assertEquals(RiskLevel.DESTRUCTIVE, invoke.riskFor("POST", "/api/nope"));
    assertTrue(invoke.requiresApprovalFor("POST", "/api/nope"));
  }

  @Test
  void underlyingCapabilityIsExposedForTheGuardToApplyItsPolicy() {
    Optional<EndpointCapability> underlying = invoke.underlyingEndpoint("POST", "/api/workflow-runs");
    assertTrue(underlying.isPresent());
    assertEquals(RiskLevel.SENSITIVE, underlying.get().risk());
    assertEquals("endpoint_post_api_workflow_runs", underlying.get().code());
  }

  // ================================================================
  // 底层能力参数校验同样生效（"经原语调用"与"直接调用"准入一致）
  // ================================================================

  @Test
  void underlyingParameterValidationIsAppliedThroughThePrimitive() {
    // 对照：直接调用底层能力会被拒（缺 targetId）……
    EndpointCapability underlying =
        endpointRegistry.capabilityFor("POST", "/api/workflow-runs").orElseThrow();
    ApiException direct = assertThrows(ApiException.class, () -> underlying.validateParams(Map.of()));
    assertTrue(direct.getMessage().contains("targetId"), direct.getMessage());

    // ……经 invoke_endpoint 调用时，同一约束必须同样生效——这正是"原语不是特权通道"的体现。
    ApiException viaPrimitive =
        assertThrows(
            ApiException.class, () -> invoke.validateParams(call("POST", "/api/workflow-runs")));
    assertTrue(viaPrimitive.getMessage().contains("targetId"), viaPrimitive.getMessage());

    // 补齐 targetId 后两者都放行。
    underlying.validateParams(Map.of("targetId", 7));
    invoke.validateParams(Map.of("method", "POST", "path", "/api/workflow-runs", "targetId", 7));
  }

  @Test
  void pathVariableTargetIsEnforcedThroughThePrimitive() {
    // /api/targets/{targetId}/discovered-paths 的 {targetId} 路径参数就是授权目标。
    ApiException error =
        assertThrows(
            ApiException.class,
            () -> invoke.validateParams(call("GET", "/api/targets/7/discovered-paths")));
    assertTrue(error.getMessage().contains("targetId"), error.getMessage());

    invoke.validateParams(
        Map.of(
            "method", "GET",
            "path", "/api/targets/7/discovered-paths",
            "targetId", 7,
            "body", Map.of()));
  }

  // ================================================================
  // 审计与诊断辅助
  // ================================================================

  @Test
  void rejectionReasonIsEmptyForAllowedCallsAndPopulatedForDeniedOnes() {
    assertTrue(invoke.rejectionReason("GET", "/api/audits").isEmpty());
    assertTrue(invoke.rejectionReason("POST", "/api/system/shutdown").isPresent());
    assertTrue(invoke.rejectionReason("POST", "/api/nope").isPresent());
    assertTrue(invoke.rejectionReason("POST", "/api/../x").isPresent());
  }

  @Test
  void governanceSnapshotCapturesTheEffectivePolicy() {
    Map<String, Object> snapshot = invoke.governanceSnapshot("POST", "/api/system/shutdown");
    assertEquals("POST", snapshot.get("method"));
    assertEquals("/api/system/shutdown", snapshot.get("path"));
    assertEquals(true, snapshot.get("registered"));
    assertEquals("DESTRUCTIVE", snapshot.get("risk"));
    assertEquals(true, snapshot.get("requiresApproval"));
    assertEquals(BLOCKED_CODE, snapshot.get("underlyingCode"));
    assertEquals(true, snapshot.get("blocked"));
    assertEquals(List.of(AgentCapability.TARGET_BINDING_UNRESOLVED), snapshot.get("targetBindings"));
  }

  @Test
  void governanceSnapshotForUnknownEndpointIsFailClosed() {
    Map<String, Object> snapshot = invoke.governanceSnapshot("POST", "/api/nope");
    assertEquals(false, snapshot.get("registered"));
    assertEquals("DESTRUCTIVE", snapshot.get("risk"));
    assertEquals(true, snapshot.get("requiresApproval"));
  }

  @Test
  void describeIntentIsSingleLineAndSafe() {
    assertEquals(
        "invoke_endpoint POST /api/workflow-runs",
        invoke.describeIntent(call("post", "/api/workflow-runs")));
    assertEquals("invoke_endpoint (无参数)", invoke.describeIntent(null));
  }

  // ================================================================
  // 能力元数据
  // ================================================================

  @Test
  void capabilityMetadataMatchesTheDesignDocument() {
    assertEquals("invoke_endpoint", invoke.code());
    assertEquals("通用端点调用", invoke.displayName());
    assertTrue(invoke.description().contains("不是特权通道"));
  }

  @Test
  void parameterSchemaRequiresMethodAndPath() {
    Map<String, Object> schema = invoke.parameterSchema();
    assertEquals("object", schema.get("type"));
    assertEquals(List.of("method", "path"), schema.get("required"));
    assertEquals(Boolean.FALSE, schema.get("additionalProperties"));

    @SuppressWarnings("unchecked")
    Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
    assertEquals(Set.of("method", "path", "body", "query"), properties.keySet());
  }

  @Test
  void allowedMethodsMatchTheDesignDocument() {
    assertEquals(
        Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"), InvokeEndpointCapability.ALLOWED_METHODS);
  }

  // ================================================================
  // 综合：§9.5 越权用例集
  // ================================================================

  @Test
  void privilegeEscalationCasesAreAllDenied() {
    // 对应 §9.5 表格中与 invoke_endpoint 相关的四行。
    assertFalse(invoke.isReachable("POST", "/api/nope"), "未注册端点应拒绝");
    assertFalse(invoke.isReachable("POST", "/api/system/shutdown"), "黑名单端点应拒绝");
    assertFalse(invoke.isReachable("POST", "/api/audits/../system/shutdown"), "路径遍历应拒绝");
    assertFalse(invoke.isReachable("POST", "/api/%2e%2e/system/shutdown"), "编码遍历应拒绝");
    assertFalse(invoke.isReachable("GET", "/api//audits"), "空路径段应拒绝");
    assertFalse(invoke.isReachable("PROPFIND", "/api/audits"), "未支持方法应拒绝");
    assertFalse(invoke.isReachable("GET", "/api/audits?page=1"), "路径含查询串应拒绝");

    // 误拦率对照：合法调用必须放行（护栏准确性）。
    assertTrue(invoke.isReachable("GET", "/api/audits"));
    assertTrue(invoke.isReachable("GET", "/api/vulnerabilities"));
    assertTrue(invoke.isReachable("POST", "/api/workflow-runs", 7));
  }
}
