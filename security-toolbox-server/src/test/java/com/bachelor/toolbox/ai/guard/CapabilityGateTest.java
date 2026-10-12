package com.bachelor.toolbox.ai.guard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.capability.SecurityToolCapability;
import com.bachelor.toolbox.ai.capability.SecurityToolCapability.TargetScope;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * 护栏四层越权用例集（设计文档 §9.5 表）。
 *
 * <p>论文 §9.5 的"越界拦截率"必须可复现，因此每条用例都断言<strong>具体是哪一层拦下的</strong>（{@link
 * CapabilityDeniedException#layer()}）以及拒绝原因码，而不是笼统地断言"抛异常"。
 *
 * <p>刻意<strong>不</strong>使用 Spring 容器：护栏是安全边界，必须能在最小依赖下被独立验证。装配正确性由 {@code
 * SecurityToolboxApplicationTests} 另行覆盖（task-1 的教训：单元测试全绿也抓不到装配错误）。
 */
class CapabilityGateTest {

  private static final long AUTHORIZED_TARGET_ID = 12L;
  private static final long FOREIGN_TARGET_ID = 999L;

  // ================================================================ 测试夹具

  /** 内存审计，用于断言"被拒绝的调用也被记录"。 */
  private static final class RecordingAudit implements CapabilityAuditSink {
    final List<Map<String, Object>> entries = new ArrayList<>();

    @Override
    public void record(String action, String capabilityCode, Map<String, Object> detail, String result) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("action", action);
      entry.put("capability", capabilityCode);
      entry.put("result", result);
      entry.putAll(detail);
      entries.add(entry);
    }

    List<Map<String, Object>> denied() {
      return entries.stream().filter(e -> "DENIED".equals(e.get("result"))).toList();
    }
  }

  /** 授权目标：127.0.0.1，仅允许 8080。 */
  private static AuthorizedTarget authorizedTarget() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(AUTHORIZED_TARGET_ID);
    target.setName("授权目标");
    target.setTargetValue("http://127.0.0.1:8080");
    target.setTargetType("URL");
    target.setAuthorizationNote("单元测试授权");
    target.setAllowedPorts("8080");
    target.setEnabled(true);
    target.setAuthorizationValidFrom(Instant.now().minusSeconds(3600));
    target.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    return target;
  }

  /** 授权已过期的目标（§9.5："授权过期后执行 → 拒绝"）。 */
  private static AuthorizedTarget expiredTarget() {
    AuthorizedTarget target = authorizedTarget();
    target.setAuthorizationExpiresAt(Instant.now().minusSeconds(60));
    return target;
  }

  private static TargetPolicyService targetPolicy() {
    return new TargetPolicyService(false, new PortRangeParser());
  }

  /** 构造护栏：默认 WARN 模式、空白名单，可指定目标解析结果。 */
  private static CapabilityGate gate(
      List<AgentCapability> capabilities,
      RecordingAudit audit,
      Map<Long, AuthorizedTarget> targets) {
    return gate(capabilities, audit, targets, "warn", "");
  }

  private static CapabilityGate gate(
      List<AgentCapability> capabilities,
      RecordingAudit audit,
      Map<Long, AuthorizedTarget> targets,
      String schemaMode,
      String whitelist) {
    return gate(capabilities, audit, targets, schemaMode, whitelist, null);
  }

  private static CapabilityGate gate(
      List<AgentCapability> capabilities,
      RecordingAudit audit,
      Map<Long, AuthorizedTarget> targets,
      String schemaMode,
      String whitelist,
      EndpointParameterPolicy endpointParameterPolicy) {
    CapabilityRegistry registry =
        new CapabilityRegistry(capabilities, CapabilityBlacklist.defaults().blockedCodes());
    return new CapabilityGate(
        registry,
        targetPolicy(),
        CapabilityBlacklist.defaults(),
        new ApprovalPolicy(),
        audit,
        targetId -> Optional.ofNullable(targets.get(targetId)),
        schemaMode,
        whitelist,
        "",
        endpointParameterPolicy);
  }

  private static Map<Long, AuthorizedTarget> targets(AuthorizedTarget... items) {
    Map<Long, AuthorizedTarget> map = new LinkedHashMap<>();
    for (AuthorizedTarget item : items) {
      map.put(item.getId(), item);
    }
    return map;
  }

  private static CapabilityDeniedException denied(
      CapabilityGate gate, String code, Map<String, Object> params, CapabilityContext ctx) {
    return assertThrows(CapabilityDeniedException.class, () -> gate.invoke(code, params, ctx));
  }

  // ================================================ 用例 1：扫描授权范围外目标

  /** §9.5：扫描授权范围外目标 → 拒绝（L-A）。 */
  @Test
  void case01RejectsScanAgainstTargetOutsideAuthorizedScope() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(scanCapability("nuclei_scan")), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(gate, "nuclei_scan", Map.of("targetId", FOREIGN_TARGET_ID), CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.AUTHORIZATION, error.layer());
    assertEquals("TARGET_NOT_FOUND", error.reasonCode());
    assertFalse(audit.denied().isEmpty(), "被拒绝的调用也必须进入审计");
  }

  /** 对照组（测误拦率）：合法范围内的常规扫描 → 放行（已获人工确认，§6.6 对目标实际执行属 REQUIRED）。 */
  @Test
  void case01bAllowsScanInsideAuthorizedScope() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(scanCapability("nuclei_scan")), audit, targets(authorizedTarget()));

    CapabilityOutcome outcome =
        gate.invoke(
            "nuclei_scan",
            Map.of("targetId", AUTHORIZED_TARGET_ID),
            CapabilityContext.anonymous().approved(1L));

    assertEquals(Set.of(Long.toString(AUTHORIZED_TARGET_ID)), outcome.targetBindings());
    assertTrue(outcome.touchesTargets());
  }

  // ================================================ 用例 2：使用授权范围外端口

  /** §9.5：使用授权范围外端口 → 拒绝（L-A）。 */
  @Test
  void case02RejectsPortOutsideAuthorizedPortRange() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(scanCapability("tcp_ports")), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "tcp_ports",
            Map.of("targetId", AUTHORIZED_TARGET_ID, "ports", "22,3306"),
            CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.AUTHORIZATION, error.layer());
    assertEquals("PORT_OUT_OF_SCOPE", error.reasonCode());
  }

  /** 端口在授权范围内（8080）→ 放行，证明上一条不是"凡带 ports 就拒绝"的误拦。 */
  @Test
  void case02bAllowsPortInsideAuthorizedPortRange() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(scanCapability("tcp_ports")), audit, targets(authorizedTarget()));

    CapabilityOutcome outcome =
        gate.invoke(
            "tcp_ports",
            Map.of("targetId", AUTHORIZED_TARGET_ID, "ports", "8080"),
            CapabilityContext.anonymous().approved(1L));

    assertNotNull(outcome.capability());
  }

  /**
   * 端口区间<strong>部分越界</strong>必须被发现。
   *
   * <p>这是"只取区间两端点"这个近似会漏判的形态：授权 {@code 8080,8085}，请求 {@code 8080-8085}。两端点 8080/8085 都在
   * 授权集合内，但区间中间还有 8081..8084 未经授权——只比端点会放行，完整展开才能拦住。
   */
  @Test
  void case02cRejectsPartiallyOutOfScopePortRange() {
    RecordingAudit audit = new RecordingAudit();
    AuthorizedTarget sparse = authorizedTarget();
    sparse.setAllowedPorts("8080,8085");
    CapabilityGate gate = gate(List.of(scanCapability("tcp_ports")), audit, targets(sparse));

    CapabilityDeniedException error =
        denied(
            gate,
            "tcp_ports",
            Map.of("targetId", AUTHORIZED_TARGET_ID, "ports", "8080-8085"),
            CapabilityContext.anonymous().approved(1L));

    assertEquals(CapabilityDeniedException.Layer.AUTHORIZATION, error.layer());
    assertEquals("PORT_OUT_OF_SCOPE", error.reasonCode());
  }

  /** 区间完全落在授权范围内 → 放行（测误拦率，证明上一条不是"凡区间就拒"）。 */
  @Test
  void case02dAllowsFullyAuthorizedPortRange() {
    RecordingAudit audit = new RecordingAudit();
    AuthorizedTarget ranged = authorizedTarget();
    ranged.setAllowedPorts("8080-8090");
    CapabilityGate gate = gate(List.of(scanCapability("tcp_ports")), audit, targets(ranged));

    CapabilityOutcome outcome =
        gate.invoke(
            "tcp_ports",
            Map.of("targetId", AUTHORIZED_TARGET_ID, "ports", "8082-8088"),
            CapabilityContext.anonymous().approved(1L));

    assertNotNull(outcome.capability());
  }

  // ================================================ 用例 3：授权过期后执行

  /** §9.5：授权过期后执行 → 拒绝（L-A）。 */
  @Test
  void case03RejectsExecutionAfterAuthorizationExpired() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(scanCapability("nuclei_scan")), audit, targets(expiredTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "nuclei_scan",
            Map.of("targetId", AUTHORIZED_TARGET_ID),
            CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.AUTHORIZATION, error.layer());
  }

  // ============ 用例 4（核心）：通过 POST /api/tasks 间接扫描越界目标必须被拒绝

  /**
   * §9.5 + §9.2 论点二：{@code POST /api/tasks} 的 {@code kind()} 是 {@code WRITE}，但它创建出的任务会真正扫描目标。
   *
   * <p>这正是 §6.2 要防住的绕过：若护栏写成 {@code if (kind == EXECUTE) validateAuthorization(...)}，本用例会<strong>放行</strong>，
   * 护栏立即 fail-open。因此本用例断言：拒绝，且拒绝层是 <strong>L-A</strong>（不是 L-B、不是 L-C）。
   */
  @Test
  void case04RejectsIndirectScanViaTaskCreationAgainstOutOfScopeTarget() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability createTask = indirectExecutionCapability();
    CapabilityGate gate = gate(List.of(createTask), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "create_task",
            Map.of("targetId", FOREIGN_TARGET_ID, "tool", "nuclei", "projectId", 1),
            CapabilityContext.anonymous());

    assertEquals(
        CapabilityDeniedException.Layer.AUTHORIZATION,
        error.layer(),
        "间接执行能力（kind=WRITE）必须走 L-A；按 kind 判定会导致 fail-open");
    assertEquals("TARGET_NOT_FOUND", error.reasonCode());
  }

  /** kind 伪装：声明成 WRITE 但 targetBindings 非空 → 仍被 L-A 校验（不是"放行"）。 */
  @Test
  void case04bWriteKindWithTargetBindingsIsStillAuthorizationChecked() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(indirectExecutionCapability()), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "create_task",
            Map.of("targetId", AUTHORIZED_TARGET_ID, "ports", "9999"),
            CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.AUTHORIZATION, error.layer());
    assertEquals("PORT_OUT_OF_SCOPE", error.reasonCode());
  }

  // ================================================ 用例 5：调用黑名单能力

  /** §9.5：调用 {@code POST /api/system/shutdown} → 拒绝（L-B 黑名单）。 */
  @Test
  void case05RejectsBlacklistedShutdownCapability() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability shutdown =
        new StubCapability(
            "shutdown_system",
            CapabilityKind.ADMIN,
            RiskLevel.DESTRUCTIVE,
            true,
            Set.of(),
            TargetBindingProbe.Declaration.NONE,
            Map.of());
    CapabilityGate gate = gate(List.of(shutdown), audit, targets(authorizedTarget()), "warn", "shutdown_system");

    CapabilityDeniedException error =
        denied(gate, "shutdown_system", Map.of(), CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.ADMISSION, error.layer());
    assertEquals(
        "BLOCKED_CAPABILITY",
        error.reasonCode(),
        "黑名单必须由 L-B 拦下；若由 L-A 拦下说明 §6.1 图的顺序未被修正，且黑名单可被绕过");
  }

  /**
   * 黑名单绕过尝试：{@code shutdown} 带一个<strong>完全合法</strong>的 {@code targetId}。
   *
   * <p>若护栏按 §6.1 图先跑 L-A，这次调用会通过 L-A（目标合法），黑名单随即失效。本用例是"L-B 必须先于 L-A"的直接证据。
   */
  @Test
  void case05bBlacklistCannotBeBypassedBySupplyingAValidTargetId() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability shutdown =
        new StubCapability(
            "shutdown_system",
            CapabilityKind.ADMIN,
            RiskLevel.DESTRUCTIVE,
            true,
            Set.of(Long.toString(AUTHORIZED_TARGET_ID)),
            TargetBindingProbe.Declaration.NONE,
            Map.of());
    CapabilityGate gate = gate(List.of(shutdown), audit, targets(authorizedTarget()), "warn", "shutdown_system");

    CapabilityDeniedException error =
        denied(
            gate,
            "shutdown_system",
            Map.of("targetId", AUTHORIZED_TARGET_ID),
            CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.ADMISSION, error.layer());
    assertEquals("BLOCKED_CAPABILITY", error.reasonCode());
  }

  /** §6.4：{@code /api/auth/*} 全部禁止（人类专属操作）。 */
  @Test
  void case05cRejectsAuthDomainCapabilities() {
    RecordingAudit audit = new RecordingAudit();
    List<AgentCapability> authCaps =
        List.of(
            new StubCapability("auth_login", CapabilityKind.READ, RiskLevel.SAFE, false, Set.of(),
                TargetBindingProbe.Declaration.NONE, Map.of()),
            new StubCapability("change_password", CapabilityKind.WRITE, RiskLevel.SENSITIVE, true, Set.of(),
                TargetBindingProbe.Declaration.NONE, Map.of()));
    CapabilityGate gate = gate(authCaps, audit, targets(authorizedTarget()));

    for (String code : List.of("auth_login", "change_password")) {
      CapabilityDeniedException error = denied(gate, code, Map.of(), CapabilityContext.anonymous());
      assertEquals(CapabilityDeniedException.Layer.ADMISSION, error.layer(), code);
      assertEquals("BLOCKED_CAPABILITY", error.reasonCode(), code);
    }
  }

  /** §6.4：业务数据重置类（不可逆破坏）直接拒绝。 */
  @Test
  void case05dRejectsBusinessDataResetCapabilities() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(
            List.of(
                new StubCapability("reset_business_data", CapabilityKind.WRITE, RiskLevel.DESTRUCTIVE, true,
                    Set.of(), TargetBindingProbe.Declaration.NONE, Map.of())),
            audit,
            targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(gate, "reset_business_data", Map.of(), CapabilityContext.anonymous());

    assertEquals("BLOCKED_CAPABILITY", error.reasonCode());
  }

  // ============================== 用例 6/7：invoke_endpoint 的未注册端点与黑名单端点

  /** §9.5：{@code invoke_endpoint} 调用未注册端点 → 拒绝（L-D）。 */
  @Test
  void case06RejectsInvokeEndpointForUnregisteredCapability() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate = gate(List.of(scanCapability("nuclei_scan")), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "invoke_endpoint",
            Map.of("method", "POST", "path", "/api/does-not-exist", "body", Map.of()),
            CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.ENTRYPOINT, error.layer());
    assertEquals("UNKNOWN_CAPABILITY", error.reasonCode());
  }

  /** §9.5：{@code invoke_endpoint} 调用黑名单端点 → 拒绝（L-B 反向映射）。 */
  @Test
  void case07RejectsInvokeEndpointForBlacklistedPath() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability invokeEndpoint = invokeEndpointCapability();
    CapabilityGate gate = gate(List.of(invokeEndpoint), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "invoke_endpoint",
            Map.of("method", "POST", "path", "/api/system/shutdown", "body", Map.of()),
            CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.ADMISSION, error.layer());
    assertEquals("BLOCKED_CAPABILITY", error.reasonCode());
  }

  /** §6.4：{@code /api/auth/*} 经端点原语调用同样被拒（前缀模式生效）。 */
  @Test
  void case07bRejectsInvokeEndpointUnderAuthPrefix() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(invokeEndpointCapability()), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "invoke_endpoint",
            Map.of("method", "POST", "path", "/api/auth/change-password", "body", Map.of()),
            CapabilityContext.anonymous());

    assertEquals("BLOCKED_CAPABILITY", error.reasonCode());
  }

  // ================================================ 用例 8：路径穿越

  /** §9.5：路径含 {@code ../} 的端点调用 → 拒绝（L-C 路径规范化）。 */
  @Test
  void case08RejectsPathTraversalInEndpointPath() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(invokeEndpointCapability()), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "invoke_endpoint",
            Map.of("method", "GET", "path", "/api/findings/../../etc/passwd"),
            CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.PARAMETER, error.layer());
    assertEquals("PATH_TRAVERSAL", error.reasonCode());
  }

  /** URL 编码的路径穿越同样被拒。 */
  @Test
  void case08bRejectsEncodedPathTraversal() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(invokeEndpointCapability()), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "invoke_endpoint",
            Map.of("method", "GET", "path", "/api/findings/%2e%2e/%2e%2e/etc/passwd"),
            CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.PARAMETER, error.layer());
    assertEquals("PATH_TRAVERSAL", error.reasonCode());
  }

  // ================================================ 用例 9：未分级能力（fail-closed）

  /** §9.5：未分级的新增能力 → 拒绝（fail-closed）。 */
  @Test
  void case09RejectsUnclassifiedCapability() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability unclassified =
        new StubCapability("brand_new_capability", null, null, false, Set.of(),
            TargetBindingProbe.Declaration.NONE, Map.of());
    CapabilityGate gate = gate(List.of(unclassified), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(gate, "brand_new_capability", Map.of(), CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.ADMISSION, error.layer());
    assertEquals("UNCLASSIFIED_CAPABILITY", error.reasonCode());
  }

  // ================================================ 用例 10：哨兵态必须被拒绝

  /**
   * <strong>哨兵态</strong>：{@code targetBindings} 返回 {@code TARGET_BINDING_UNRESOLVED} → 必须拒绝，绝不能当成"不触及目标"放行。
   *
   * <p>这是 task-1 §4.1.1 修订的核心：扫描类能力的 {@code targetId} 由请求级字段注入，参数里解析不到是常态，一旦折叠成空集，
   * 全部扫描能力都会跳过 L-A。
   *
   * <p>本用例刻意用一个"自身 {@code validateParams} 不做目标检查"的能力，把哨兵判定隔离出来测：真实扫描能力（{@code
   * SecurityToolCapability}）的 {@code validateParams} 也会拦缺目标的情况，那属于 L-C 的拒绝，会掩盖 L-A 的哨兵分支。
   * 两条路径都必须拒绝，但归因不同，因此分开断言（见 {@link #case10c}）。
   */
  @Test
  void case10RejectsSentinelTargetBindingInsteadOfAllowingIt() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability sentinelOnly =
        new StubCapability(
            "sentinel_scan", CapabilityKind.EXECUTE, RiskLevel.SENSITIVE, false, Set.of(),
            TargetBindingProbe.Declaration.REQUIRED, Map.of()) {
          @Override
          public Set<String> targetBindings(Map<String, Object> params) {
            // 模拟"应触及目标但参数里解析不到"的扫描能力。
            return Set.of(TARGET_BINDING_UNRESOLVED);
          }
        };
    CapabilityGate gate = gate(List.of(sentinelOnly), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(gate, "sentinel_scan", Map.of("ports", "8080"), CapabilityContext.anonymous());

    assertEquals(
        CapabilityDeniedException.Layer.AUTHORIZATION,
        error.layer(),
        "哨兵态必须由 L-A 以 fail-closed 拒绝");
    assertEquals("TARGET_BINDING_UNRESOLVED", error.reasonCode());
  }

  /** 真实扫描能力缺 {@code targetId}：同样必须被拒绝（此路径由 L-C 的能力自定义校验拦下，结论一致）。 */
  @Test
  void case10cRealScanCapabilityWithoutTargetIdIsDenied() {
    RecordingAudit audit = new RecordingAudit();
    SecurityToolCapability scan = scanCapability("nuclei_scan");
    CapabilityGate gate = gate(List.of(scan), audit, targets(authorizedTarget()));

    // 先确认底层能力确实返回哨兵（而不是空集），否则本用例测的是空气。
    assertTrue(
        scan.targetBindings(Map.of("ports", "8080")).contains(AgentCapability.TARGET_BINDING_UNRESOLVED));

    CapabilityDeniedException error =
        denied(gate, "nuclei_scan", Map.of("ports", "8080"), CapabilityContext.anonymous());

    assertTrue(
        error.layer() == CapabilityDeniedException.Layer.AUTHORIZATION
            || error.layer() == CapabilityDeniedException.Layer.PARAMETER,
        "缺目标必须被拒绝，实际层: " + error.layer());
  }

  /** 哨兵态与空集必须被区分对待：空集（显式声明 NONE）放行，哨兵拒绝。 */
  @Test
  void case10bEmptySetIsAllowedOnlyForExplicitlyDeclaredNonTargetCapability() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability retrieval =
        SecurityToolCapability.of(
            stubTool("retrieve_project_context"),
            CapabilityKind.READ,
            RiskLevel.SAFE,
            TargetScope.NONE);
    CapabilityGate gate = gate(List.of(retrieval), audit, targets(authorizedTarget()));

    CapabilityOutcome outcome =
        gate.invoke("retrieve_project_context", Map.of("query", "登录接口"), CapabilityContext.anonymous());

    assertFalse(outcome.touchesTargets());
  }

  // ====================== 用例 11：空集兜底（防止"漏声明 targetBindings"的 fail-open）

  /**
   * 一个<strong>没有显式声明</strong>目标绑定语义的能力返回空集 → 拒绝（MISSING_TARGET_BINDING）。
   *
   * <p>这是 §10 失败模式表"能力漏声明 {@code targetBindings} → 授权校验被跳过"的堵漏点。注意判定依据是<strong>声明状态</strong>，
   * 不是 {@code risk()}/{@code requiresApproval()} 的推导值——否则一个被误判为 {@code SAFE} 的扫描能力就能用空集溜过 L-A。
   */
  @Test
  void case11RejectsEmptyBindingWhenCapabilityDidNotDeclareTargetScope() {
    RecordingAudit audit = new RecordingAudit();
    // 注意：risk 故意标成 SAFE、requiresApproval=false，模拟"风险推断错误"。
    AgentCapability silentlyEmpty =
        new StubCapability("legacy_silent_scan", CapabilityKind.EXECUTE, RiskLevel.SAFE, false, Set.of(),
            TargetBindingProbe.Declaration.UNKNOWN, Map.of());
    CapabilityGate gate = gate(List.of(silentlyEmpty), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(gate, "legacy_silent_scan", Map.of(), CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.AUTHORIZATION, error.layer());
    assertEquals("MISSING_TARGET_BINDING", error.reasonCode());
  }

  /** 即使被误判为 SAFE，只要没声明"不触及目标"，空集就不合法。 */
  @Test
  void case11bMisclassifiedSafeCapabilityCannotEscapeViaEmptySet() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability misclassified =
        new StubCapability("mislabelled_scanner", CapabilityKind.READ, RiskLevel.SAFE, false, Set.of(),
            TargetBindingProbe.Declaration.REQUIRED, Map.of());
    CapabilityGate gate = gate(List.of(misclassified), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(gate, "mislabelled_scanner", Map.of(), CapabilityContext.anonymous());

    assertEquals("MISSING_TARGET_BINDING", error.reasonCode());
  }

  // ================================================ 白名单（§6.4 默认拒绝）

  /** §6.4：DESTRUCTIVE 能力未显式开启 → 拒绝（默认拒绝，而非默认放行）。 */
  @Test
  void case12RejectsDestructiveCapabilityWhenWhitelistNotEnabled() {
    RecordingAudit audit = new RecordingAudit();
    SecurityToolCapability sqlmap = SecurityToolCapability.of(stubTool("sqlmap_scan"));
    CapabilityGate gate = gate(List.of(sqlmap), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "sqlmap_scan",
            Map.of("targetId", AUTHORIZED_TARGET_ID),
            CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.ADMISSION, error.layer());
    assertEquals("CAPABILITY_NOT_ENABLED", error.reasonCode());
  }

  /** §6.4：ADMIN 能力未显式开启 → 拒绝。 */
  @Test
  void case12bRejectsAdminCapabilityWhenWhitelistNotEnabled() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability admin =
        new StubCapability("update_system_settings", CapabilityKind.ADMIN, RiskLevel.SENSITIVE, true, Set.of(),
            TargetBindingProbe.Declaration.NONE, Map.of());
    CapabilityGate gate = gate(List.of(admin), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(gate, "update_system_settings", Map.of(), CapabilityContext.anonymous());

    assertEquals("CAPABILITY_NOT_ENABLED", error.reasonCode());
  }

  /** §6.4：显式开启后，DESTRUCTIVE 能力可通过 L-B（随后仍需 L-A/L-C 与人工确认）。 */
  @Test
  void case12cDestructiveCapabilityPassesAdmissionOnceExplicitlyEnabled() {
    RecordingAudit audit = new RecordingAudit();
    SecurityToolCapability sqlmap = SecurityToolCapability.of(stubTool("sqlmap_scan"));
    CapabilityGate gate =
        gate(List.of(sqlmap), audit, targets(authorizedTarget()), "warn", "sqlmap_scan");

    // 未带人工批准 → 被 REQUIRED 拦住（这是正确行为，说明 L-B 已放行、确认层生效）。
    CapabilityDeniedException error =
        denied(
            gate,
            "sqlmap_scan",
            Map.of("targetId", AUTHORIZED_TARGET_ID),
            CapabilityContext.anonymous());
    assertEquals("APPROVAL_REQUIRED", error.reasonCode());

    // 带上人工批准 → 放行。
    CapabilityOutcome outcome =
        gate.invoke(
            "sqlmap_scan",
            Map.of("targetId", AUTHORIZED_TARGET_ID),
            CapabilityContext.anonymous().approved(1L));
    assertEquals(ApprovalLevel.REQUIRED, outcome.approvalLevel());
  }

  // ================================================ 参数 schema（L-C）

  /** L-C：schema 违规在 ENFORCE 模式下拒绝。 */
  @Test
  void case13EnforceModeRejectsSchemaViolation() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability strict =
        new StubCapability("strict_capability", CapabilityKind.READ, RiskLevel.SAFE, false, Set.of(),
            TargetBindingProbe.Declaration.NONE,
            Map.of(
                "type", "object",
                "properties", Map.of("mode", Map.of("type", "string", "enum", List.of("quick", "full"))),
                "required", List.of("mode"),
                "additionalProperties", false));
    CapabilityGate gate = gate(List.of(strict), audit, targets(authorizedTarget()), "enforce", "");

    CapabilityDeniedException error =
        denied(gate, "strict_capability", Map.of("mode", "illegal"), CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.PARAMETER, error.layer());
    assertEquals("SCHEMA_VIOLATION", error.reasonCode());

    // 缺少必填参数同样被拒。
    CapabilityDeniedException missing =
        denied(gate, "strict_capability", Map.of(), CapabilityContext.anonymous());
    assertEquals("SCHEMA_VIOLATION", missing.reasonCode());
  }

  /** L-C：WARN 模式不因 schema 违规拦截（默认行为，避免误拦现有 13 条执行链路）。 */
  @Test
  void case13bWarnModeDoesNotBlockOnSchemaViolationButRecordsIt() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability lenient =
        new StubCapability("lenient_capability", CapabilityKind.READ, RiskLevel.SAFE, false, Set.of(),
            TargetBindingProbe.Declaration.NONE,
            Map.of("type", "object", "properties", Map.of(), "additionalProperties", false));
    CapabilityGate gate = gate(List.of(lenient), audit, targets(authorizedTarget()), "warn", "");

    CapabilityOutcome outcome =
        gate.invoke("lenient_capability", Map.of("unexpected", "value"), CapabilityContext.anonymous());

    assertNotNull(outcome);
    assertEquals(
        SchemaModeWarnExpectation.RECORDED,
        outcome.auditDetail().containsKey("schemaViolations")
            ? SchemaModeWarnExpectation.RECORDED
            : SchemaModeWarnExpectation.MISSING);
  }

  private enum SchemaModeWarnExpectation {
    RECORDED,
    MISSING
  }

  /** L-C：能力自定义 {@code validateParams} 抛错 → 拒绝。 */
  @Test
  void case13cCapabilityCustomValidationFailureIsDenied() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability custom =
        new StubCapability("custom_validated", CapabilityKind.READ, RiskLevel.SAFE, false, Set.of(),
            TargetBindingProbe.Declaration.NONE, Map.of()) {
          @Override
          public void validateParams(Map<String, Object> params) {
            throw new ApiException("端口范围格式无效");
          }
        };
    CapabilityGate gate = gate(List.of(custom), audit, targets(authorizedTarget()), "enforce", "");

    CapabilityDeniedException error =
        denied(gate, "custom_validated", Map.of(), CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.PARAMETER, error.layer());
    assertEquals("INVALID_PARAMETER", error.reasonCode());
  }

  // ================================================ 人工确认（§6.6）

  /** §6.6：对目标实际执行 → REQUIRED；无人工批准 → 拒绝。 */
  @Test
  void case14RequiresHumanApprovalForActualExecutionAgainstTarget() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(scanCapability("nuclei_scan")), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "nuclei_scan",
            Map.of("targetId", AUTHORIZED_TARGET_ID),
            CapabilityContext.anonymous());
    assertEquals("APPROVAL_REQUIRED", error.reasonCode());

    CapabilityOutcome outcome =
        gate.invoke(
            "nuclei_scan",
            Map.of("targetId", AUTHORIZED_TARGET_ID),
            CapabilityContext.anonymous().approved(7L));
    assertEquals(ApprovalLevel.REQUIRED, outcome.approvalLevel());
  }

  /** §6.6 防确认疲劳：不触及目标的只读查询 → NONE，不打扰用户。 */
  @Test
  void case14bReadOnlyNonTargetCapabilityNeedsNoApproval() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability retrieval =
        SecurityToolCapability.of(
            stubTool("retrieve_project_context"),
            CapabilityKind.READ,
            RiskLevel.SAFE,
            TargetScope.NONE);
    CapabilityGate gate = gate(List.of(retrieval), audit, targets(authorizedTarget()));

    CapabilityOutcome outcome =
        gate.invoke("retrieve_project_context", Map.of("query", "x"), CapabilityContext.anonymous());

    assertEquals(ApprovalLevel.NONE, outcome.approvalLevel());
  }

  /** §6.6：删除类操作 → REQUIRED。 */
  @Test
  void case14cDeleteLikeOperationRequiresApproval() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability deleteFinding =
        new StubCapability("delete_finding", CapabilityKind.WRITE, RiskLevel.SENSITIVE, false, Set.of(),
            TargetBindingProbe.Declaration.NONE, Map.of());
    CapabilityGate gate = gate(List.of(deleteFinding), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(gate, "delete_finding", Map.of(), CapabilityContext.anonymous());

    assertEquals("APPROVAL_REQUIRED", error.reasonCode());
  }

  // ================================================ 审计完整性（§9.5）

  /** 审计完整性：放行与拒绝都要入账，且拒绝条目带层与原因。 */
  @Test
  void case15AuditRecordsBothAllowedAndDeniedInvocations() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(scanCapability("nuclei_scan")), audit, targets(authorizedTarget()));

    gate.invoke("nuclei_scan", Map.of("targetId", AUTHORIZED_TARGET_ID), CapabilityContext.anonymous().approved(1L));
    assertThrows(
        CapabilityDeniedException.class,
        () -> gate.invoke("nuclei_scan", Map.of("targetId", FOREIGN_TARGET_ID), CapabilityContext.anonymous()));

    List<Map<String, Object>> denied = audit.denied();
    assertEquals(1, denied.size());
    assertEquals("L-A", denied.get(0).get("deniedLayer"));
    assertEquals("TARGET_NOT_FOUND", denied.get(0).get("deniedReason"));
    assertEquals("nuclei_scan", denied.get(0).get("capability"));
  }

  /** 审计通道故障不得改变护栏结论（放行仍放行，拒绝仍拒绝）。 */
  @Test
  void case15bAuditFailureDoesNotChangeGuardDecision() {
    CapabilityAuditSink broken =
        (action, capabilityCode, detail, result) -> {
          throw new IllegalStateException("审计通道故障");
        };
    CapabilityRegistry registry =
        new CapabilityRegistry(
            List.of(scanCapability("nuclei_scan")), CapabilityBlacklist.defaults().blockedCodes());
    CapabilityGate gate =
        new CapabilityGate(
            registry,
            targetPolicy(),
            CapabilityBlacklist.defaults(),
            new ApprovalPolicy(),
            broken,
            targetId -> Optional.ofNullable(targets(authorizedTarget()).get(targetId)),
            "warn",
            "",
            "",
            null);

    // 拒绝仍是拒绝。
    assertThrows(
        CapabilityDeniedException.class,
        () -> gate.invoke("nuclei_scan", Map.of("targetId", FOREIGN_TARGET_ID), CapabilityContext.anonymous()));
    // 放行仍是放行。
    assertNotNull(
        gate.invoke(
            "nuclei_scan",
            Map.of("targetId", AUTHORIZED_TARGET_ID),
            CapabilityContext.anonymous().approved(1L)));
  }

  // ================================================ 防 TOCTOU（§6.7）

  /** §6.7：审批时的目标快照与本次调用不一致 → 拒绝。 */
  @Test
  void case16RejectsWhenTargetBindingChangedSinceApproval() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(scanCapability("nuclei_scan")), audit, targets(authorizedTarget(), secondTarget()));

    CapabilityDeniedException error =
        denied(
            gate,
            "nuclei_scan",
            Map.of("targetId", AUTHORIZED_TARGET_ID),
            CapabilityContext.anonymous()
                .approved(1L)
                .withApprovedTargetBindings(Map.of("13", "snapshot")));

    assertEquals(CapabilityDeniedException.Layer.AUTHORIZATION, error.layer());
    assertEquals("AUTHORIZATION_SNAPSHOT_CHANGED", error.reasonCode());
  }

  /** §6.7：快照一致 → 放行。 */
  @Test
  void case16bAllowsWhenTargetBindingMatchesApprovalSnapshot() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(List.of(scanCapability("nuclei_scan")), audit, targets(authorizedTarget()));

    CapabilityOutcome outcome =
        gate.invoke(
            "nuclei_scan",
            Map.of("targetId", AUTHORIZED_TARGET_ID),
            CapabilityContext.anonymous()
                .approved(1L)
                .withApprovedTargetBindings(Map.of(Long.toString(AUTHORIZED_TARGET_ID), "snapshot")));

    assertNotNull(outcome);
  }

  // ================================================ 端点透传参数（X-7）

  /**
   * X-7 端到端：{@code invoke_endpoint} 直达 {@code POST /api/tasks}，外层 schema 合法但内层 {@code parameters} 越权。
   *
   * <p>外层看不出来——{@code parameters} 的类型确实是合法对象；危险在内容里（MSF 模块前缀、端口子集等）。本用例断言护栏
   * 在 L-C' 层拦下它，而不是放行到执行器。
   */
  @Test
  void case18RejectsEndpointPrimitiveSmugglingPrivilegedTaskParameters() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(
            List.of(resolvingInvokeEndpointCapability()),
            audit,
            targets(authorizedTarget()),
            "warn",
            "",
            new EndpointParameterPolicy(new PortRangeParser(), 65535));

    CapabilityDeniedException error =
        denied(
            gate,
            "invoke_endpoint",
            Map.of(
                "method",
                "POST",
                "path",
                "/api/tasks",
                "body",
                Map.of(
                    "projectId",
                    1,
                    "targetId",
                    AUTHORIZED_TARGET_ID,
                    "toolCode",
                    "msf_scan",
                    "parameters",
                    Map.of("module", "post/multi/gather/env"))),
            CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.PARAMETER, error.layer());
    assertEquals("ENDPOINT_PARAMETER_POLICY", error.reasonCode());
  }

  /** X-7 端到端：端口越权经端点透传同样被拦（外层 schema 看不出问题）。 */
  @Test
  void case18bRejectsEndpointPrimitiveSmugglingOutOfScopePorts() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(
            List.of(resolvingInvokeEndpointCapability()),
            audit,
            targets(authorizedTarget()),
            "warn",
            "",
            new EndpointParameterPolicy(new PortRangeParser(), 65535));

    CapabilityDeniedException error =
        denied(
            gate,
            "invoke_endpoint",
            Map.of(
                "method",
                "POST",
                "path",
                "/api/tasks",
                "body",
                Map.of(
                    "projectId",
                    1,
                    "targetId",
                    AUTHORIZED_TARGET_ID,
                    "toolCode",
                    "tcp_ports",
                    "parameters",
                    Map.of("ports", "22,3306"))),
            CapabilityContext.anonymous());

    assertEquals("ENDPOINT_PARAMETER_POLICY", error.reasonCode());
  }

  /** 合法载荷经端点透传 → 放行（测误拦率）。 */
  @Test
  void case18cAllowsLegitimateEndpointPrimitiveTaskCreation() {
    RecordingAudit audit = new RecordingAudit();
    CapabilityGate gate =
        gate(
            List.of(resolvingInvokeEndpointCapability()),
            audit,
            targets(authorizedTarget()),
            "warn",
            "",
            new EndpointParameterPolicy(new PortRangeParser(), 65535));

    CapabilityOutcome outcome =
        gate.invoke(
            "invoke_endpoint",
            Map.of(
                "method",
                "POST",
                "path",
                "/api/tasks",
                "body",
                Map.of(
                    "projectId",
                    1,
                    "targetId",
                    AUTHORIZED_TARGET_ID,
                    "toolCode",
                    "tcp_ports",
                    "parameters",
                    Map.of("ports", "8080"))),
            CapabilityContext.anonymous().approved(1L));

    assertNotNull(outcome);
  }

  // ================================================ 多目标逐个校验

  /** 多目标调用必须逐个校验，任何一个越界都拒绝（防止"只校验第一个"）。 */
  @Test
  void case17RejectsWhenAnyOfMultipleTargetsIsOutOfScope() {
    RecordingAudit audit = new RecordingAudit();
    AgentCapability multi =
        new StubCapability("multi_target_scan", CapabilityKind.EXECUTE, RiskLevel.SENSITIVE, false,
            Set.of(Long.toString(AUTHORIZED_TARGET_ID), Long.toString(FOREIGN_TARGET_ID)),
            TargetBindingProbe.Declaration.REQUIRED, Map.of());
    CapabilityGate gate = gate(List.of(multi), audit, targets(authorizedTarget()));

    CapabilityDeniedException error =
        denied(gate, "multi_target_scan", Map.of(), CapabilityContext.anonymous());

    assertEquals(CapabilityDeniedException.Layer.AUTHORIZATION, error.layer());
    assertEquals("TARGET_NOT_FOUND", error.reasonCode());
  }

  // ================================================ 辅助构造

  private static SecurityToolCapability scanCapability(String code) {
    return SecurityToolCapability.of(stubTool(code));
  }

  /** 模拟 {@code POST /api/tasks}：kind=WRITE，但会真正扫描目标。 */
  private static AgentCapability indirectExecutionCapability() {
    return new StubCapability(
        "create_task",
        CapabilityKind.WRITE,
        RiskLevel.SENSITIVE,
        false,
        Set.of(),
        TargetBindingProbe.Declaration.UNKNOWN,
        Map.of()) {
      @Override
      public Set<String> targetBindings(Map<String, Object> params) {
        Object targetId = params == null ? null : params.get("targetId");
        if (targetId == null) {
          // 漏传目标：必须返回哨兵而不是空集（§4.1.1）。
          return Set.of(TARGET_BINDING_UNRESOLVED);
        }
        return Set.of(String.valueOf(targetId));
      }
    };
  }

  /** 模拟 {@code invoke_endpoint}：参数任意，目标无法静态解析。 */
  private static AgentCapability invokeEndpointCapability() {
    return new StubCapability(
        "invoke_endpoint",
        CapabilityKind.WRITE,
        RiskLevel.SENSITIVE,
        true,
        Set.of(),
        TargetBindingProbe.Declaration.UNKNOWN,
        Map.of()) {
      @Override
      public Set<String> targetBindings(Map<String, Object> params) {
        // 通用端点原语无法从任意 body 中可靠解析目标 → 一律返回哨兵，由护栏 fail-closed。
        return Set.of(TARGET_BINDING_UNRESOLVED);
      }
    };
  }

  /**
   * 模拟"能解析出目标"的 {@code invoke_endpoint}。
   *
   * <p>真实实现（§6.5 反向能力映射）会把端点还原为底层能力，从而知道该端点触及哪个目标。这里用一个简化版：从 {@code body}
   * 里取 {@code targetId}。它用于测试 X-7——<strong>目标合法但内层 parameters 越权</strong>那条路径，此时 L-A 会放行，
   * 必须由 L-C' 拦下。
   */
  private static AgentCapability resolvingInvokeEndpointCapability() {
    return new StubCapability(
        "invoke_endpoint",
        CapabilityKind.WRITE,
        RiskLevel.SENSITIVE,
        true,
        Set.of(),
        TargetBindingProbe.Declaration.UNKNOWN,
        Map.of()) {
      @Override
      public Set<String> targetBindings(Map<String, Object> params) {
        if (params == null) {
          return Set.of(TARGET_BINDING_UNRESOLVED);
        }
        Object body = params.get("body");
        Object targetId = body instanceof Map<?, ?> map ? map.get("targetId") : params.get("targetId");
        if (targetId == null) {
          return Set.of(TARGET_BINDING_UNRESOLVED);
        }
        return Set.of(String.valueOf(targetId));
      }
    };
  }

  private static AuthorizedTarget secondTarget() {
    AuthorizedTarget target = authorizedTarget();
    target.setId(AUTHORIZED_TARGET_ID + 1);
    return target;
  }

  private static SecurityTool stubTool(String code) {
    return new SecurityTool() {
      @Override
      public String code() {
        return code;
      }

      @Override
      public String displayName() {
        return code;
      }

      @Override
      public String description() {
        return code + " 描述";
      }

      @Override
      public ToolExecutionResult execute(AuthorizedTarget target, Map<String, Object> parameters) {
        throw new UnsupportedOperationException("测试桩不执行");
      }
    };
  }

  /** 可配置的能力桩，用于构造越权场景。 */
  private static class StubCapability
      implements AgentCapability, TargetBindingProbe.TargetBindingDeclaration {
    private final String code;
    private final CapabilityKind kind;
    private final RiskLevel risk;
    private final boolean requiresApproval;
    private final Set<String> bindings;
    private final TargetBindingProbe.Declaration declaration;
    private final Map<String, Object> schema;

    StubCapability(
        String code,
        CapabilityKind kind,
        RiskLevel risk,
        boolean requiresApproval,
        Set<String> bindings,
        TargetBindingProbe.Declaration declaration,
        Map<String, Object> schema) {
      this.code = code;
      this.kind = kind;
      this.risk = risk;
      this.requiresApproval = requiresApproval;
      this.bindings = bindings;
      this.declaration = declaration;
      this.schema = schema;
    }

    @Override
    public String code() {
      return code;
    }

    @Override
    public String displayName() {
      return code;
    }

    @Override
    public String description() {
      return code + " 描述";
    }

    @Override
    public Map<String, Object> parameterSchema() {
      return schema;
    }

    @Override
    public CapabilityKind kind() {
      return kind;
    }

    @Override
    public RiskLevel risk() {
      return risk;
    }

    @Override
    public boolean requiresApproval() {
      return requiresApproval;
    }

    @Override
    public Set<String> targetBindings(Map<String, Object> params) {
      return bindings;
    }

    @Override
    public TargetBindingProbe.Declaration targetBindingDeclaration() {
      return declaration;
    }
  }
}
