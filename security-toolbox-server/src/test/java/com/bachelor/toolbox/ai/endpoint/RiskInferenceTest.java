package com.bachelor.toolbox.ai.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** {@link RiskInference} 的推断表（设计文档 §4.2）。 */
class RiskInferenceTest {

  // ------------------------------------------------------------ 方法推断表

  @ParameterizedTest
  @CsvSource({
    "GET,/api/vulnerabilities,SAFE",
    "HEAD,/api/fingerprints,SAFE",
    "POST,/api/workflows,SENSITIVE",
    "PUT,/api/findings/9,SENSITIVE",
    "PATCH,/api/findings/9,SENSITIVE",
    "DELETE,/api/workflow-runs/9,DESTRUCTIVE"
  })
  void infersRiskFromHttpMethod(String method, String path, RiskLevel expected) {
    assertEquals(expected, RiskInference.inferRisk(method, path));
  }

  @Test
  void methodIsCaseInsensitive() {
    assertEquals(RiskLevel.SAFE, RiskInference.inferRisk("get", "/api/vulnerabilities"));
    assertEquals(RiskLevel.SAFE, RiskInference.inferRisk("  Get  ", "/api/fingerprints"));
    assertEquals(RiskLevel.DESTRUCTIVE, RiskInference.inferRisk("delete", "/api/notifications/1"));
  }

  @Test
  void unknownMethodIsTreatedAsDestructive() {
    // §10 保守优先：无法识别的信号一律按最坏情况处理，而不是默认放行。
    assertEquals(RiskLevel.DESTRUCTIVE, RiskInference.inferRisk("PROPFIND", "/api/vulnerabilities"));
    assertEquals(RiskLevel.DESTRUCTIVE, RiskInference.inferRisk(null, "/api/vulnerabilities"));
    assertEquals(RiskLevel.DESTRUCTIVE, RiskInference.inferRisk("", "/api/vulnerabilities"));
  }

  // ------------------------------------------------------------ 路径关键词表

  @ParameterizedTest
  @CsvSource({
    "POST,/api/system/shutdown,DESTRUCTIVE",
    "POST,/api/settings/reset,DESTRUCTIVE",
    "POST,/api/cache/cleanup,DESTRUCTIVE",
    "GET,/api/system/shutdown,DESTRUCTIVE",
    "POST,/api/traffic/purge,DESTRUCTIVE"
  })
  void destructivePathKeywordsWinOverMethod(String method, String path, RiskLevel expected) {
    assertEquals(expected, RiskInference.inferRisk(method, path));
  }

  @ParameterizedTest
  @CsvSource({
    "GET,/api/scans,SENSITIVE",
    "GET,/api/execute/probe,SENSITIVE",
    "POST,/api/workflow-runs/1/run,SENSITIVE",
    "GET,/api/traffic/scans/3,SENSITIVE",
    "POST,/api/traffic/fuzz-batches,SENSITIVE"
  })
  void executionPathKeywordsRaiseToSensitive(String method, String path, RiskLevel expected) {
    assertEquals(expected, RiskInference.inferRisk(method, path));
  }

  @Test
  void keywordsAreMatchedPerPathSegmentNotAsSubstring() {
    // "runtime" 里含 "run"，但按段/分词匹配不应把它当作执行类端点；
    // 若用子串匹配，这个只读端点会被误升级并弹出无意义的确认。
    assertEquals(RiskLevel.SAFE, RiskInference.inferRisk("GET", "/api/runtime"));

    // "resetting" 含 "reset"，同样不应命中。
    assertEquals(RiskLevel.SAFE, RiskInference.inferRisk("GET", "/api/resetting-status"));

    // 反向确认：以 - 分隔的复合段能被拆开命中。
    assertEquals(RiskLevel.SENSITIVE, RiskInference.inferRisk("GET", "/api/traffic/active-scans"));
  }

  @Test
  void destructiveBeatsExecutionWhenBothKeywordsPresent() {
    // /api/scans/cleanup 同时命中 scan（SENSITIVE）与 cleanup（DESTRUCTIVE），取更严的。
    assertEquals(RiskLevel.DESTRUCTIVE, RiskInference.inferRisk("POST", "/api/scans/cleanup"));
  }

  // ------------------------------------------------------------ 确认要求

  @Test
  void destructiveEndpointsAlwaysRequireApproval() {
    assertTrue(RiskInference.inferRequiresApproval("DELETE", "/api/notifications/1"));
    assertTrue(RiskInference.inferRequiresApproval("POST", "/api/system/shutdown"));
  }

  @Test
  void executionEndpointsRequireApproval() {
    assertTrue(RiskInference.inferRequiresApproval("GET", "/api/traffic/scans"));
    assertTrue(RiskInference.inferRequiresApproval("POST", "/api/workflow-runs/1/run"));
  }

  @Test
  void indirectExecutionPostRequiresApproval() {
    // §6.6：POST /api/tasks 创建的对象会去扫描目标，属于对目标发起实际执行 → REQUIRED。
    // 仅按 HTTP 方法推断会把它归为 BATCH，从而漏掉必要确认。
    assertTrue(RiskInference.inferRequiresApproval("POST", "/api/tasks"));
    assertTrue(RiskInference.inferRequiresApproval("POST", "/api/workflow-runs"));
    assertTrue(RiskInference.inferRequiresApproval("POST", "/api/active-scans"));
    assertTrue(RiskInference.inferRequiresApproval("POST", "/api/ai/dispatches"));
  }

  @Test
  void mutatingEndpointsTouchingATargetRequireApproval() {
    assertTrue(RiskInference.inferRequiresApproval("POST", "/api/targets/{targetId}/discovered-paths"));
    assertTrue(RiskInference.inferRequiresApproval("PUT", "/api/targets/{id}"));
  }

  @Test
  void plainReadEndpointsDoNotRequireApproval() {
    // 防确认疲劳：常规只读查询不弹确认。
    assertFalse(RiskInference.inferRequiresApproval("GET", "/api/audits"));
    assertFalse(RiskInference.inferRequiresApproval("GET", "/api/vulnerabilities"));
    assertFalse(RiskInference.inferRequiresApproval("GET", "/api/dashboard/summary"));
  }

  @Test
  void plainCrudWriteWithoutTargetDoesNotRequireApproval() {
    // 可逆的常规写操作归 BATCH，不逐次确认（§6.6）。
    assertFalse(RiskInference.inferRequiresApproval("POST", "/api/notifications/read"));
    assertFalse(RiskInference.inferRequiresApproval("PUT", "/api/settings/theme"));
  }

  // ================================================================
  // X-3：服务生命周期 / 流量拦截 / 数据进出必须提级
  // ================================================================

  @Test
  void mitmProxyStartIsNotSafe() {
    // X-3 关键用例：TrafficProxyService.start() 不做目标/项目授权校验，
    // 若推断为 SAFE，Agent 就能零确认启动 MITM 代理并解密记录流量。
    RiskLevel risk = RiskInference.inferRisk("POST", "/api/traffic/proxy/start");
    assertNotEquals(RiskLevel.SAFE, risk, "启动 MITM 代理绝不能推断为 SAFE");
    assertTrue(RiskInference.inferRequiresApproval("POST", "/api/traffic/proxy/start"));
  }

  @ParameterizedTest
  @CsvSource({
    "POST,/api/traffic/proxy/start",
    "POST,/api/traffic/proxy/stop",
    "POST,/api/traffic/proxy/restart",
    "POST,/api/traffic/proxy/capture",
    "POST,/api/traffic/mitm/start",
    "POST,/api/scans/enable",
    "POST,/api/scans/disable",
    "POST,/api/fingerprints/import",
    "GET,/api/reports/export",
    "POST,/api/pocs/upload",
    "GET,/api/nuclei-templates/download"
  })
  void lifecycleInterceptionAndDataTransferActionsRequireApproval(String method, String path) {
    assertNotEquals(RiskLevel.SAFE, RiskInference.inferRisk(method, path), path);
    assertTrue(RiskInference.inferRequiresApproval(method, path), path);
  }

  @ParameterizedTest
  @CsvSource({
    "POST,/api/projects/1/members/grant",
    "POST,/api/users/1/roles/assign",
    "POST,/api/users/1/permissions/revoke",
    "DELETE,/api/projects/1/members/unassign"
  })
  void permissionChangesAreDestructive(String method, String path) {
    // 权限变更影响授权边界（§6.6 REQUIRED 判定条件之一），必须按不可逆操作处理。
    assertEquals(RiskLevel.DESTRUCTIVE, RiskInference.inferRisk(method, path), path);
    assertTrue(RiskInference.inferRequiresApproval(method, path), path);
    assertTrue(RiskInference.isWhitelisted(method, path), path);
  }

  @Test
  void startKeywordIsMatchedPerSegmentNotAsSubstring() {
    // "restart" 与 "start" 是不同 token，但都属于生命周期动作，两者都要提级。
    assertTrue(RiskInference.inferRequiresApproval("POST", "/api/traffic/proxy/restart"));
    // 而 "starting-point" 会被拆成 starting / point，不命中 start，保持只读判定。
    assertEquals(RiskLevel.SAFE, RiskInference.inferRisk("GET", "/api/starting-point"));
  }

  // ================================================================
  // X-5：只读不等于无风险（跨项目数据读取）
  // ================================================================

  @Test
  void sensitiveDataReadsAreNotSafe() {
    // X-5 关键用例：GET /api/audits 无项目归属过滤，按"GET → SAFE"放行即可跨项目读取审计日志。
    RiskLevel risk = RiskInference.inferRisk("GET", "/api/audits");
    assertNotEquals(RiskLevel.SAFE, risk, "无归属过滤的审计查询绝不能推断为 SAFE");
    assertEquals(RiskLevel.SENSITIVE, risk);
  }

  @ParameterizedTest
  @CsvSource({
    "GET,/api/audits",
    "GET,/api/audits/1",
    "GET,/api/ledger",
    "GET,/api/system/logs",
    "GET,/api/settings",
    "GET,/api/users",
    "GET,/api/auth/me",
    "GET,/api/projects/1/permissions"
  })
  void sensitiveDataDomainsRaiseReadsToSensitive(String method, String path) {
    assertEquals(RiskLevel.SENSITIVE, RiskInference.inferRisk(method, path), path);
    assertTrue(RiskInference.isSensitiveDataRead(method, path), path);
  }

  @Test
  void sensitiveDataReadsStayBatchAndDoNotRequirePerCallApproval() {
    // §6.6 防确认疲劳：敏感域只读查询归 BATCH 批量确认，不做 REQUIRED 逐次确认，
    // 否则审计/设置这类常规查询会把确认弹窗刷爆，用户迅速麻木反而削弱护栏。
    assertFalse(RiskInference.inferRequiresApproval("GET", "/api/audits"));
    assertFalse(RiskInference.inferRequiresApproval("GET", "/api/settings"));
    assertFalse(RiskInference.inferRequiresApproval("GET", "/api/users"));
  }

  @Test
  void sensitiveDataEscalationAppliesToReadsOnly() {
    // 写方法本来就至少 SENSITIVE，敏感域提级不应改变它们既有语义。
    assertFalse(RiskInference.isSensitiveDataRead("POST", "/api/audits"));
    assertFalse(RiskInference.isSensitiveDataRead("DELETE", "/api/users/1"));
  }

  @Test
  void ordinaryReadsRemainSafe() {
    // 误拦率对照：不含敏感域关键词的常规只读端点仍是 SAFE，保持零确认。
    for (String path :
        List.of(
            "/api/vulnerabilities",
            "/api/dashboard/summary",
            "/api/fingerprints",
            "/api/traffic/sessions",
            "/api/path-dictionary")) {
      assertEquals(RiskLevel.SAFE, RiskInference.inferRisk("GET", path), path);
      assertFalse(RiskInference.isSensitiveDataRead("GET", path), path);
    }
  }

  @Test
  void keywordSnapshotsAreExposedReadOnly() {
    assertTrue(RiskInference.sensitiveDataKeywords().contains("audit"));
    assertTrue(RiskInference.executionKeywords().contains("start"));
    assertThrows(
        UnsupportedOperationException.class,
        () -> RiskInference.sensitiveDataKeywords().add("extra"));
  }

  // ------------------------------------------------------------ 类别推断

  @Test
  void infersKindFromMethodAndKeywords() {
    assertEquals(CapabilityKind.READ, RiskInference.inferKind("GET", "/api/vulnerabilities"));
    assertEquals(CapabilityKind.WRITE, RiskInference.inferKind("POST", "/api/findings"));
    assertEquals(CapabilityKind.ADMIN, RiskInference.inferKind("DELETE", "/api/notifications/1"));
    assertEquals(CapabilityKind.ADMIN, RiskInference.inferKind("POST", "/api/system/shutdown"));
    assertEquals(CapabilityKind.ADMIN, RiskInference.inferKind("POST", "/api/projects/1/members/grant"));
    assertEquals(CapabilityKind.EXECUTE, RiskInference.inferKind("POST", "/api/tasks"));
    assertEquals(CapabilityKind.EXECUTE, RiskInference.inferKind("GET", "/api/traffic/scans"));
    // X-3：启动 MITM 代理属于对目标发起实际动作。
    assertEquals(CapabilityKind.EXECUTE, RiskInference.inferKind("POST", "/api/traffic/proxy/start"));
  }

  // ------------------------------------------------------------ 白名单（§6.4）

  @Test
  void destructiveAndAdminEndpointsAreWhitelisted() {
    assertTrue(RiskInference.isWhitelisted("POST", "/api/system/shutdown"));
    assertTrue(RiskInference.isWhitelisted("DELETE", "/api/notifications/1"));
    assertTrue(RiskInference.isWhitelisted("POST", "/api/users/1/roles/assign"));
    assertFalse(RiskInference.isWhitelisted("GET", "/api/vulnerabilities"));
    assertFalse(RiskInference.isWhitelisted("POST", "/api/findings"));
    // 敏感域 GET 只是 SENSITIVE（BATCH），不进白名单。
    assertFalse(RiskInference.isWhitelisted("GET", "/api/audits"));
  }

  // ------------------------------------------------------------ 分词

  @Test
  void pathTokensKeepWholeAndSplitForms() {
    Set<String> tokens = RiskInference.pathTokens("/api/workflow-runs/{id}/stop");
    assertTrue(tokens.contains("workflow-runs"));
    assertTrue(tokens.contains("workflow"));
    assertTrue(tokens.contains("runs"));
    assertTrue(tokens.contains("id"));
    assertTrue(tokens.contains("stop"));
    assertFalse(tokens.contains("{id}"));
  }

  @Test
  void nullAndBlankPathsProduceNoTokensAndSafeDefaults() {
    assertTrue(RiskInference.pathTokens(null).isEmpty());
    assertTrue(RiskInference.pathTokens("  ").isEmpty());
    assertEquals(RiskLevel.SAFE, RiskInference.inferRisk("GET", null));
    assertEquals(RiskLevel.SENSITIVE, RiskInference.inferRisk("POST", null));
  }

  @Test
  void pathTokensAreImmutableSet() {
    Set<String> tokens = RiskInference.pathTokens("/api/audits");
    assertEquals(Set.of("api", "audits"), tokens);
    assertThrows(UnsupportedOperationException.class, () -> tokens.add("extra"));
  }

  @Test
  void emptyTokenSetIsAlsoImmutable() {
    assertThrows(UnsupportedOperationException.class, () -> RiskInference.pathTokens(null).add("x"));
  }
}
