package com.bachelor.toolbox.ai.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** {@link EndpointRegistry} 的登记、精确匹配与反向映射（设计文档 §6.5 第一、二重约束）。 */
class EndpointRegistryTest {

  private EndpointRegistry registry;

  @BeforeEach
  void setUp() {
    registry = new EndpointRegistry();
    registry.register(EndpointCapability.derive("GET", "/api/audits", "AuditController#list()"));
    registry.register(EndpointCapability.derive("GET", "/api/audits/{id}", "AuditController#get()"));
    registry.register(EndpointCapability.derive("GET", "/api/vulnerabilities", "x"));
    registry.register(EndpointCapability.derive("GET", "/api/targets/{targetId}/discovered-paths", "x"));
    registry.register(EndpointCapability.derive("POST", "/api/workflow-runs", "x"));
    registry.register(EndpointCapability.derive("POST", "/api/workflow-runs/{id}/stop", "x"));
    registry.register(EndpointCapability.derive("DELETE", "/api/workflow-runs/{id}", "x"));
    registry.register(EndpointCapability.derive("POST", "/api/system/shutdown", "x"));
  }

  // ------------------------------------------------------------ 精确匹配

  @Test
  void containsMatchesLiteralPaths() {
    assertTrue(registry.contains("GET", "/api/audits"));
    assertTrue(registry.contains("POST", "/api/workflow-runs"));
    assertFalse(registry.contains("POST", "/api/audits"));
    assertFalse(registry.contains("GET", "/api/workflow-runs"));
  }

  @Test
  void containsMatchesTemplateSegments() {
    assertTrue(registry.contains("GET", "/api/audits/42"));
    assertTrue(registry.contains("GET", "/api/targets/7/discovered-paths"));
    assertTrue(registry.contains("POST", "/api/workflow-runs/9/stop"));
    assertTrue(registry.contains("DELETE", "/api/workflow-runs/9"));
  }

  @Test
  void literalWinsOverTemplateWhenBothCouldMatch() {
    // /api/audits 同时可能被 /api/audits 与 /api/audits/{id} 的"前缀思维"命中；
    // 精确匹配下只有字面模板 /api/audits 段数相同，因此不会歧义。
    Optional<EndpointCapability> exact = registry.capabilityFor("GET", "/api/audits");
    assertTrue(exact.isPresent());
    assertEquals("/api/audits", exact.get().pathTemplate());

    Optional<EndpointCapability> templated = registry.capabilityFor("GET", "/api/audits/42");
    assertTrue(templated.isPresent());
    assertEquals("/api/audits/{id}", templated.get().pathTemplate());
  }

  @Test
  void doesNotMatchByPrefixOrSuffix() {
    assertFalse(registry.contains("GET", "/api"));
    assertFalse(registry.contains("GET", "/api/audits/42/extra"));
    assertFalse(registry.contains("GET", "/api/audits-extra"));
    assertFalse(registry.contains("GET", "/API/AUDITS"));
  }

  @Test
  void rejectsTrailingSlashAndDuplicateSlash() {
    // 结尾斜杠与 // 都属于"需要改写才能匹配"的形式，一律不匹配（fail-closed）。
    assertFalse(registry.contains("GET", "/api/audits/"));
    assertFalse(registry.contains("GET", "/api//audits"));
  }

  @Test
  void rejectsTraversalPathsEvenWhenSuffixMatchesARegisteredEndpoint() {
    // 这是最关键的用例：/api/audits/../system/shutdown 在 HTTP 层会被解析成 /api/system/shutdown。
    // 若注册表按"包含"或"前缀"匹配，它就会命中黑名单端点；若不校验遍历，它又可能因字符串不等而判为"未知端点"。
    // 正确行为是明确判为未注册，由 invoke_endpoint 抛出"未知端点"。
    assertFalse(registry.contains("POST", "/api/audits/../system/shutdown"));
    assertFalse(registry.contains("POST", "/api/%2e%2e/system/shutdown"));
    assertFalse(registry.contains("POST", "/api/workflow-runs/../system/shutdown"));
  }

  @Test
  void rejectsTemplateValueContainingEncodingOrTraversal() {
    assertFalse(registry.contains("GET", "/api/audits/%2e%2e"));
    assertFalse(registry.contains("GET", "/api/audits/.."));
    assertFalse(registry.contains("GET", "/api/audits/a b"));
    assertFalse(registry.contains("GET", "/api/audits/审计"));
  }

  @Test
  void nullMethodOrPathIsNotRegistered() {
    assertFalse(registry.contains(null, "/api/audits"));
    assertFalse(registry.contains("GET", null));
    assertFalse(registry.contains("", "/api/audits"));
    assertFalse(registry.contains("   ", "/api/audits"));
  }

  @Test
  void methodMatchingIsCaseInsensitiveOnLookupButRegistryStoresUpperCase() {
    assertTrue(registry.contains("get", "/api/audits"));
    assertTrue(registry.contains("Delete", "/api/workflow-runs/1"));
  }

  // ------------------------------------------------------------ 反向能力映射

  @Test
  void capabilityForReturnsUnderlyingCapabilityWithItsRisk() {
    EndpointCapability vulnerabilities = registry.capabilityFor("GET", "/api/vulnerabilities").orElseThrow();
    assertEquals(RiskLevel.SAFE, vulnerabilities.risk());
    assertFalse(vulnerabilities.requiresApproval());

    EndpointCapability stop = registry.capabilityFor("POST", "/api/workflow-runs/9/stop").orElseThrow();
    assertEquals(RiskLevel.SENSITIVE, stop.risk());
    assertTrue(stop.requiresApproval());

    EndpointCapability delete = registry.capabilityFor("DELETE", "/api/workflow-runs/9").orElseThrow();
    assertEquals(RiskLevel.DESTRUCTIVE, delete.risk());
    assertTrue(delete.requiresApproval());
  }

  @Test
  void sensitiveDataReadsAreSensitiveButNotIndividuallyConfirmed() {
    // X-5 + §6.6：审计类只读端点提级为 SENSITIVE，但归 BATCH 批量确认，不做逐次确认。
    EndpointCapability audits = registry.capabilityFor("GET", "/api/audits").orElseThrow();
    assertEquals(RiskLevel.SENSITIVE, audits.risk());
    assertFalse(audits.requiresApproval());
  }

  @Test
  void capabilityForIsEmptyForUnknownEndpoint() {
    assertTrue(registry.capabilityFor("POST", "/api/nope").isEmpty());
    assertTrue(registry.capabilityFor("POST", "/api/system/shutdown/../audits").isEmpty());
  }

  // ------------------------------------------------------------ 登记与统计

  @Test
  void sizeCountsRegisteredMethodPathPairs() {
    assertEquals(8, registry.size());
    assertEquals(8, registry.all().size());
  }

  @Test
  void capabilitiesViewIsASnapshot() {
    List<com.bachelor.toolbox.ai.capability.AgentCapability> capabilities = registry.capabilities();
    assertEquals(8, capabilities.size());
    registry.register(EndpointCapability.derive("GET", "/api/new", "x"));
    assertEquals(8, capabilities.size());
    assertEquals(9, registry.size());
  }

  @Test
  void duplicateRegistrationIsIdempotentAndKeepsTheFirstEntry() {
    // 端点是外部事实（Spring MVC 的映射表），重复喂入不构成安全风险，幂等忽略即可；
    // 但必须保留先登记者，否则"谁覆盖谁"会变成不可预期的行为。
    EndpointCapability first = registry.capabilityFor("GET", "/api/audits").orElseThrow();
    registry.register(EndpointCapability.derive("GET", "/api/audits", "dup"));
    assertEquals(8, registry.size());
    assertSame(first, registry.capabilityFor("GET", "/api/audits").orElseThrow());
  }

  @Test
  void rejectsInvalidEndpointDefinition() {
    assertThrows(IllegalArgumentException.class, () -> registry.register(null));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            registry.register(
                new EndpointCapability(
                    "GET", "api/no-leading-slash", CapabilityKind.READ, RiskLevel.SAFE, false, false, "")));
  }

  @Test
  void methodsByPathGroupsMethods() {
    Map<String, Set<String>> grouped = registry.methodsByPath();
    assertEquals(Set.of("GET"), grouped.get("/api/audits"));
    // /api/workflow-runs/{id} 上只登记了 DELETE；POST 挂在 /api/workflow-runs/{id}/stop。
    assertEquals(Set.of("DELETE"), grouped.get("/api/workflow-runs/{id}"));
    assertEquals(Set.of("POST"), grouped.get("/api/workflow-runs/{id}/stop"));
  }

  @Test
  void byPathReturnsAllMethodsForTemplate() {
    assertEquals(1, registry.byPath("/api/workflow-runs/{id}").size());
    assertTrue(registry.byPath("/api/nope").isEmpty());
  }

  @Test
  void exactLookupIgnoresTemplateMatching() {
    assertTrue(registry.exact("GET", "/api/audits/{id}").isPresent());
    assertTrue(registry.exact("GET", "/api/audits/42").isEmpty());
  }

  // ------------------------------------------------------------ 缓存正确性

  @Test
  void cacheReturnsConsistentResultsAcrossRepeatedLookups() {
    for (int round = 0; round < 3; round++) {
      assertTrue(registry.contains("GET", "/api/audits/42"));
      assertTrue(registry.capabilityFor("GET", "/api/audits/42").isPresent());
      assertFalse(registry.contains("GET", "/api/audits/42/extra"));
      assertFalse(registry.contains("GET", "/api/%2e%2e"));
    }
  }

  @Test
  void cacheIsInvalidatedWhenNewEndpointIsRegistered() {
    assertFalse(registry.contains("GET", "/api/late"));
    registry.register(EndpointCapability.derive("GET", "/api/late", "x"));
    assertTrue(registry.contains("GET", "/api/late"));
  }

  @Test
  void cacheEvictionKeepsBehaviourCorrect() {
    registry.setMaxCacheSize(1);
    for (int index = 0; index < 20; index++) {
      assertTrue(registry.contains("GET", "/api/audits/" + index));
      assertTrue(registry.contains("GET", "/api/audits"));
      assertFalse(registry.contains("GET", "/api/unknown/" + index));
    }
  }

  @Test
  void explicitCacheInvalidationDoesNotChangeResults() {
    boolean before = registry.contains("GET", "/api/audits");
    registry.invalidateCache();
    assertEquals(before, registry.contains("GET", "/api/audits"));
  }

  @Test
  void describeMentionsCounts() {
    String description = registry.describe();
    assertTrue(description.contains("8 个端点"));
  }
}
