package com.bachelor.toolbox.ai.capability;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.SecurityToolCapability.TargetScope;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.tool.SecurityTool;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * {@link SecurityToolCapability#targetBindings(Map)} 的提取正确性。
 *
 * <p>这是护栏 L-A 的唯一判定依据（设计文档 §6.2），提取错误会直接导致越权执行或误拦截，因此覆盖各种参数写法。
 */
class SecurityToolCapabilityTest {

  private static SecurityTool tool(String code) {
    return new StubTool(code);
  }

  private static SecurityToolCapability scanCapability() {
    return SecurityToolCapability.of(tool("nuclei_scan"));
  }

  // ------------------------------------------------------------ 正常提取

  @Test
  void extractsNumericTargetId() {
    assertEquals(Set.of("7"), scanCapability().targetBindings(Map.of("targetId", 7L)));
  }

  @Test
  void extractsIntegerTargetId() {
    assertEquals(Set.of("7"), scanCapability().targetBindings(Map.of("targetId", 7)));
  }

  @Test
  void extractsStringTargetId() {
    assertEquals(Set.of("42"), scanCapability().targetBindings(Map.of("targetId", "42")));
  }

  @Test
  void extractsSnakeCaseAndPluralKeys() {
    assertEquals(Set.of("3"), scanCapability().targetBindings(Map.of("target_id", "3")));
    assertEquals(Set.of("4"), scanCapability().targetBindings(Map.of("targetIds", List.of(4))));
    assertEquals(Set.of("5"), scanCapability().targetBindings(Map.of("target_ids", "5")));
  }

  @Test
  void extractsEveryTargetFromACollectionSoNoneEscapesAuthorization() {
    // 多目标调用必须逐个过授权校验，不能只取第一个。
    assertEquals(
        Set.of("1", "2", "3"),
        scanCapability().targetBindings(Map.of("targetIds", List.of(1, "2", 3))));
  }

  @Test
  void extractsTargetsFromCommaSeparatedText() {
    assertEquals(Set.of("11", "12"), scanCapability().targetBindings(Map.of("targets", "11,12")));
  }

  @Test
  void deduplicatesRepeatedTargetIds() {
    assertEquals(Set.of("9"), scanCapability().targetBindings(Map.of("targetIds", List.of(9, "9", 9L))));
  }

  @Test
  void ignoresNonTargetParameters() {
    Map<String, Object> params =
        Map.of("targetId", 7, "ports", "80,443", "pocCodes", List.of("AA-000000000000000000000000"));

    assertEquals(Set.of("7"), scanCapability().targetBindings(params));
  }

  // ------------------------------------------------------------ 空集 vs 哨兵

  @Test
  void returnsEmptySetForCapabilitiesThatDoNotTouchAnyTarget() {
    // 只有"确实不触及授权目标"的能力才允许返回真空集。
    SecurityToolCapability retrieval =
        SecurityToolCapability.of(
            tool("retrieve_project_context"), CapabilityKind.READ, RiskLevel.SAFE, TargetScope.NONE);

    assertEquals(Set.of(), retrieval.targetBindings(Map.of("query", "登录接口")));
    assertEquals(Set.of(), retrieval.targetBindings(null));
    assertEquals(Set.of(), retrieval.targetBindings(Map.of("targetId", 7)));
  }

  @Test
  void returnsUnresolvedSentinelWhenScanCapabilityHasNoTargetId() {
    // 关键 fail-closed 语义：扫描类能力解析不到目标时，绝不能返回空集冒充"不触及目标"。
    assertEquals(
        Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED), scanCapability().targetBindings(Map.of()));
    assertEquals(
        Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED), scanCapability().targetBindings(null));
  }

  @Test
  void returnsUnresolvedSentinelForBlankOrInvalidTargetId() {
    assertEquals(
        Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
        scanCapability().targetBindings(Map.of("targetId", "  ")));
    assertEquals(
        Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
        scanCapability().targetBindings(Map.of("targetId", "abc")));
    assertEquals(
        Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
        scanCapability().targetBindings(Map.of("targetId", 0)));
    assertEquals(
        Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
        scanCapability().targetBindings(Map.of("targetId", -5)));
  }

  @Test
  void returnsUnresolvedSentinelForEmptyCollection() {
    assertEquals(
        Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
        scanCapability().targetBindings(Map.of("targetIds", List.of())));
  }

  @Test
  void unresolvedSentinelIsDistinctFromEmptySet() {
    // 治理层依赖"空集 ≠ 哨兵"来区分"安全放行"与"必须 fail-closed"。
    assertFalse(AgentCapability.TARGET_BINDING_UNRESOLVED.isEmpty());
    assertTrue(scanCapability().targetBindings(Map.of()).contains(AgentCapability.TARGET_BINDING_UNRESOLVED));
  }

  // ------------------------------------------------- 三态语义（设计文档 §4.1 规范化）

  /** 态 1：真空集 = 确实不触及任何授权目标 → 护栏跳过 L-A。 */
  @Test
  void stateOneEmptySetMeansNoTargetTouchedAndGuardSkipsAuthorization() {
    SecurityToolCapability retrieval =
        SecurityToolCapability.of(
            tool("retrieve_project_context"), CapabilityKind.READ, RiskLevel.SAFE, TargetScope.NONE);

    Set<String> bindings = retrieval.targetBindings(Map.of("query", "x"));

    assertEquals(Set.of(), bindings);
    assertTrue(bindings.isEmpty(), "空集必须为真空白集，不能夹带哨兵");
    assertFalse(bindings.contains(AgentCapability.TARGET_BINDING_UNRESOLVED));
  }

  /** 态 2：含真实 targetId = 触及该目标 → 护栏逐个校验。 */
  @Test
  void stateTwoResolvedIdsMeanGuardMustValidateEachTarget() {
    Set<String> bindings = scanCapability().targetBindings(Map.of("targetId", 7));

    assertEquals(Set.of("7"), bindings);
    assertFalse(bindings.contains(AgentCapability.TARGET_BINDING_UNRESOLVED));
    assertTrue(bindings.stream().allMatch(id -> id.matches("\\d+")), "解析出的必须是真实目标 ID");
  }

  /** 态 3：含哨兵 = 无法解析目标 → 护栏必须 fail-closed 拒绝。 */
  @Test
  void stateThreeSentinelMeansGuardMustFailClosed() {
    Set<String> bindings = scanCapability().targetBindings(Map.of("ports", "80"));

    assertTrue(bindings.contains(AgentCapability.TARGET_BINDING_UNRESOLVED));
    assertFalse(bindings.isEmpty(), "含哨兵的集合绝不能是空集，否则护栏会误判为安全放行");
  }

  // ------------------------------------------------------------ validateParams

  @Test
  void validateParamsRejectsMissingTargetIdForScanCapability() {
    ApiException error =
        assertThrows(ApiException.class, () -> scanCapability().validateParams(Map.of()));

    assertTrue(error.getMessage().contains("nuclei_scan"));
  }

  @Test
  void validateParamsAcceptsValidPortExpression() {
    SecurityToolCapability ports = SecurityToolCapability.of(tool("tcp_ports"));

    ports.validateParams(Map.of("targetId", 7, "ports", "80,443,8000-8100"));
  }

  @Test
  void validateParamsRejectsInvalidPortExpression() {
    SecurityToolCapability ports = SecurityToolCapability.of(tool("tcp_ports"));

    assertThrows(
        ApiException.class, () -> ports.validateParams(Map.of("targetId", 7, "ports", "80-abc")));
    assertThrows(
        ApiException.class, () -> ports.validateParams(Map.of("targetId", 7, "ports", "70000")));
    assertThrows(
        ApiException.class, () -> ports.validateParams(Map.of("targetId", 7, "ports", "1-2-3")));
  }

  // ------------------------------------------------------------ 参数 schema

  @Test
  void scanCapabilitySchemaRequiresTargetId() {
    Map<String, Object> schema = scanCapability().parameterSchema();

    assertEquals("object", schema.get("type"));
    assertEquals(List.of("targetId"), schema.get("required"));
    @SuppressWarnings("unchecked")
    Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
    assertTrue(properties.containsKey("targetId"));
    assertTrue(properties.containsKey("pocCodes"));
  }

  @Test
  void nonTargetCapabilityWithoutParametersHasEmptySchema() {
    // retrieve_project_context 既不需要 targetId 也不接受任何参数，
    // 按 AgentCapability#parameterSchema 的约定返回空 Map（表示"无参数"）。
    SecurityToolCapability retrieval =
        SecurityToolCapability.of(
            tool("retrieve_project_context"), CapabilityKind.READ, RiskLevel.SAFE, TargetScope.NONE);

    assertEquals(Map.of(), retrieval.parameterSchema());
  }

  @Test
  void nonTargetCapabilitySchemaDoesNotRequireTargetId() {
    // 一个不接受 targetId 但有其他参数的非目标能力，其 required 里不应出现 targetId。
    SecurityToolCapability nonTarget =
        SecurityToolCapability.of(
            tool("tcp_ports"), CapabilityKind.READ, RiskLevel.SAFE, TargetScope.NONE);

    Map<String, Object> schema = nonTarget.parameterSchema();

    assertEquals(List.of(), schema.get("required"));
    @SuppressWarnings("unchecked")
    Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
    assertFalse(properties.containsKey("targetId"));
    assertTrue(properties.containsKey("ports"));
  }

  // ------------------------------------------------------------ 策略推导

  @Test
  void knownToolsGetKindRiskAndApprovalFromPolicy() {
    SecurityToolCapability nuclei = SecurityToolCapability.of(tool("nuclei_scan"));
    assertEquals(CapabilityKind.EXECUTE, nuclei.kind());
    assertEquals(RiskLevel.SENSITIVE, nuclei.risk());
    assertFalse(nuclei.requiresApproval());

    SecurityToolCapability sqlmap = SecurityToolCapability.of(tool("sqlmap_scan"));
    assertEquals(RiskLevel.DESTRUCTIVE, sqlmap.risk());
    assertTrue(sqlmap.requiresApproval());

    SecurityToolCapability retrieval = SecurityToolCapability.of(tool("retrieve_project_context"));
    assertEquals(CapabilityKind.READ, retrieval.kind());
    assertEquals(RiskLevel.SAFE, retrieval.risk());
    assertFalse(retrieval.requiresApproval());
    assertEquals(TargetScope.NONE, retrieval.targetScope());
  }

  @Test
  void unknownToolDefaultsToTheMostConservativePolicy() {
    SecurityToolCapability unknown = SecurityToolCapability.of(tool("brand_new_tool"));

    assertEquals(CapabilityKind.EXECUTE, unknown.kind());
    assertEquals(RiskLevel.SENSITIVE, unknown.risk());
    assertEquals(TargetScope.REQUIRED, unknown.targetScope());
    assertTrue(unknown.targetBindings(Map.of()).contains(AgentCapability.TARGET_BINDING_UNRESOLVED));
  }

  @Test
  void delegatesIdentityToUnderlyingTool() {
    SecurityToolCapability capability = SecurityToolCapability.of(tool("nuclei_scan"));

    assertEquals("nuclei_scan", capability.code());
    assertEquals("nuclei_scan 中文名", capability.displayName());
    assertEquals("nuclei_scan 描述", capability.description());
    assertEquals("nuclei_scan", capability.tool().code());
  }

  /** 最小 SecurityTool 实现，只提供身份信息。 */
  private static final class StubTool implements SecurityTool {
    private final String code;

    private StubTool(String code) {
      this.code = code;
    }

    @Override
    public String code() {
      return code;
    }

    @Override
    public String displayName() {
      return code + " 中文名";
    }

    @Override
    public String description() {
      return code + " 描述";
    }

    @Override
    public com.bachelor.toolbox.tool.ToolExecutionResult execute(
        com.bachelor.toolbox.target.AuthorizedTarget target, Map<String, Object> parameters) {
      throw new UnsupportedOperationException("测试桩不执行");
    }
  }
}
