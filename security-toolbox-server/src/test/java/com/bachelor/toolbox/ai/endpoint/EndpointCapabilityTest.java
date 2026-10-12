package com.bachelor.toolbox.ai.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** {@link EndpointCapability} 的能力码生成、schema 与三态目标绑定。 */
class EndpointCapabilityTest {

  // ------------------------------------------------------------ 能力码

  @ParameterizedTest
  @CsvSource({
    "GET,/api/audits,endpoint_get_api_audits",
    "POST,/api/workflow-runs,endpoint_post_api_workflow_runs",
    "GET,/api/targets/{targetId}/discovered-paths,endpoint_get_api_targets_by_targetid_discovered_paths",
    "DELETE,/api/workflow-runs/{id},endpoint_delete_api_workflow_runs_by_id",
    "POST,/api/system/shutdown,endpoint_post_api_system_shutdown"
  })
  void generatesReadableStableCodes(String method, String path, String expected) {
    assertEquals(expected, EndpointCapability.codeOf(method, path));
  }

  @Test
  void codeGenerationIsInjective() {
    // 能力码必须单射，否则 CapabilityRegistry 会因 code 重复而启动失败。
    Set<String> codes = new java.util.HashSet<>();
    for (String method : List.of("GET", "POST", "PUT", "PATCH", "DELETE")) {
      for (String path :
          List.of(
              "/api/audits",
              "/api/audits/{id}",
              "/api/targets/{targetId}/discovered-paths",
              "/api/workflow-runs",
              "/api/workflow-runs/{id}",
              "/api/workflow-runs/{id}/stop")) {
        assertTrue(codes.add(EndpointCapability.codeOf(method, path)), method + " " + path + " 能力码冲突");
      }
    }
    assertEquals(30, codes.size());
  }

  @Test
  void codeUsesCodePrefixSoRouteBCapabilitiesAreDistinguishable() {
    assertTrue(EndpointCapability.codeOf("GET", "/api/audits").startsWith(EndpointCapability.CODE_PREFIX));
  }

  // ------------------------------------------------------------ 三态目标绑定

  @Test
  void readOnlyEndpointWithoutTargetParameterReturnsEmptySet() {
    // 三态中的第一态：确实不触及目标 → 护栏跳过 L-A，这是唯一合法的"空集"。
    EndpointCapability capability = EndpointCapability.derive("GET", "/api/vulnerabilities", "x");
    assertFalse(capability.isTargetBound());
    assertEquals(Set.of(), capability.targetBindings(Map.of()));
    assertEquals(Set.of(), capability.targetBindings(null));
  }

  @Test
  void readOnlyEndpointWithTargetParameterReturnsSentinel() {
    EndpointCapability capability =
        EndpointCapability.derive("GET", "/api/targets/{targetId}/discovered-paths", "x");
    assertTrue(capability.isTargetBound());
    assertEquals(Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED), capability.targetBindings(Map.of()));
  }

  @Test
  void readOnlyEndpointUnderTargetsPathIsTargetBound() {
    // 路径以 /api/targets 开头即视为触及授权目标，即使方法是只读的。
    assertTrue(EndpointCapability.derive("GET", "/api/targets", "x").isTargetBound());
    assertTrue(EndpointCapability.derive("GET", "/api/targets/1/findings", "x").isTargetBound());
    assertFalse(EndpointCapability.derive("GET", "/api/findings", "x").isTargetBound());
  }

  @Test
  void everyMutatingEndpointReturnsSentinel() {
    // 三态中的第三态：写/执行类端点可能触及目标但无法静态解析 → fail-closed。
    for (String method : List.of("POST", "PUT", "PATCH", "DELETE")) {
      EndpointCapability capability = EndpointCapability.derive(method, "/api/notifications", "x");
      assertEquals(
          Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
          capability.targetBindings(Map.of()),
          method + " 必须返回哨兵");
    }
  }

  @Test
  void sentinelIsNotWeakenedByCallerSuppliedTargetId() {
    EndpointCapability capability = EndpointCapability.derive("POST", "/api/tasks", "x");
    assertEquals(
        Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
        capability.targetBindings(Map.of("targetId", 7)));
  }

  // ------------------------------------------------------------ schema

  @Test
  void schemaListsPathVariablesAndMarksTargetIdRequiredWhenTargetBound() {
    EndpointCapability capability =
        EndpointCapability.derive("GET", "/api/targets/{targetId}/discovered-paths", "x");
    Map<String, Object> schema = capability.parameterSchema();

    @SuppressWarnings("unchecked")
    Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
    // 路径参数 {targetId} 本身就是授权目标，schema 里不应再出现第二个同名属性。
    assertTrue(properties.containsKey("targetId"));
    assertTrue(properties.containsKey("body"));
    assertTrue(properties.containsKey("query"));

    @SuppressWarnings("unchecked")
    List<String> required = (List<String>) schema.get("required");
    assertTrue(required.contains("targetId"), "§4.1.1 要求 targetId 标为 required");
    assertEquals(1, required.stream().filter("targetId"::equals).count());
  }

  @Test
  void schemaDeclaresTopLevelTargetIdForTargetBoundEndpointsWithoutOneInThePath() {
    EndpointCapability capability = EndpointCapability.derive("POST", "/api/tasks", "x");
    @SuppressWarnings("unchecked")
    Map<String, Object> properties = (Map<String, Object>) capability.parameterSchema().get("properties");
    assertTrue(properties.containsKey("targetId"));

    @SuppressWarnings("unchecked")
    List<String> required = (List<String>) capability.parameterSchema().get("required");
    assertTrue(required.contains("targetId"));
  }

  @Test
  void schemaOmitsTargetIdForReadOnlyNonTargetEndpoint() {
    EndpointCapability capability = EndpointCapability.derive("GET", "/api/vulnerabilities", "x");
    @SuppressWarnings("unchecked")
    Map<String, Object> properties = (Map<String, Object>) capability.parameterSchema().get("properties");
    assertFalse(properties.containsKey("targetId"));
  }

  // ------------------------------------------------------------ 参数校验

  @Test
  void validateParamsRequiresTargetIdForTargetBoundEndpoints() {
    EndpointCapability capability = EndpointCapability.derive("POST", "/api/tasks", "x");
    ApiException error = assertThrows(ApiException.class, () -> capability.validateParams(Map.of()));
    assertTrue(error.getMessage().contains("targetId"));
    assertTrue(error.getMessage().contains("fail-closed"));
  }

  @Test
  void validateParamsRejectsNonPositiveTargetId() {
    EndpointCapability capability = EndpointCapability.derive("POST", "/api/tasks", "x");
    assertThrows(ApiException.class, () -> capability.validateParams(Map.of("targetId", 0)));
    assertThrows(ApiException.class, () -> capability.validateParams(Map.of("targetId", -3)));
    assertThrows(ApiException.class, () -> capability.validateParams(Map.of("targetId", "abc")));
    capability.validateParams(Map.of("targetId", 7));
    capability.validateParams(Map.of("targetId", "7"));
  }

  @Test
  void validateParamsRequiresPathVariables() {
    EndpointCapability capability = EndpointCapability.derive("GET", "/api/audits/{id}", "x");
    ApiException error = assertThrows(ApiException.class, () -> capability.validateParams(Map.of()));
    assertTrue(error.getMessage().contains("id"));
  }

  @Test
  void validateParamsRejectsPathVariablesContainingInjectionCharacters() {
    EndpointCapability capability = EndpointCapability.derive("GET", "/api/audits/{id}", "x");
    for (String bad : List.of("../1", "1/2", "a%2e", "a\\b")) {
      assertThrows(
          ApiException.class,
          () -> capability.validateParams(Map.of("id", bad)),
          "应拒绝路径参数 " + bad);
    }
    capability.validateParams(Map.of("id", "42"));
  }

  // ------------------------------------------------------------ 元数据

  @Test
  void displayNameAndDescriptionAreHumanReadable() {
    EndpointCapability capability =
        EndpointCapability.derive("POST", "/api/workflow-runs/1/stop", "WorkflowRunController#stop()");
    assertEquals("POST /api/workflow-runs/1/stop", capability.displayName());
    assertTrue(capability.description().contains("POST /api/workflow-runs/1/stop"));
    assertTrue(capability.description().contains("WorkflowRunController#stop()"));
  }

  @Test
  void pathVariablesAreExtractedInOrder() {
    EndpointCapability capability =
        EndpointCapability.derive("GET", "/api/a/{first}/b/{second}", "x");
    assertEquals(List.of("first", "second"), capability.pathVariables());
  }

  @Test
  void methodIsNormalizedToUpperCase() {
    EndpointCapability capability = EndpointCapability.derive("post", "/api/tasks", "x");
    assertEquals("POST", capability.method());
    assertEquals(CapabilityKind.EXECUTE, capability.kind());
  }

  @Test
  void riskOverrideReplacesInferredValues() {
    EndpointCapability original = EndpointCapability.derive("GET", "/api/vulnerabilities", "x");
    assertEquals(RiskLevel.SAFE, original.risk());
    assertFalse(original.requiresApproval());

    EndpointCapability calibrated = original.withRisk(RiskLevel.DESTRUCTIVE, true);
    assertEquals(RiskLevel.DESTRUCTIVE, calibrated.risk());
    assertTrue(calibrated.requiresApproval());
    assertEquals(original.code(), calibrated.code());
    assertEquals(original.pathTemplate(), calibrated.pathTemplate());
  }

  @Test
  void toStringIsCompactAndInformative() {
    EndpointCapability capability = EndpointCapability.derive("GET", "/api/vulnerabilities", "x");
    assertEquals("GET /api/vulnerabilities [endpoint_get_api_vulnerabilities, SAFE]", capability.toString());
  }
}
