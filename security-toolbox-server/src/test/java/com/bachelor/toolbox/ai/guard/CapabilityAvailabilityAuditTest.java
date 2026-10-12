package com.bachelor.toolbox.ai.guard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.endpoint.EndpointCapability;
import com.bachelor.toolbox.ai.endpoint.RiskInference;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 实测 P1-3 修复的收益：模拟端点能力的可用性统计（不依赖 Spring 容器）。
 *
 * <p>判定"可通过 L-A"的条件与 {@code CapabilityGate.resolveAndValidateAuthorization} 严格一致：
 *
 * <ul>
 *   <li>返回真实 targetId → 可用（需目标授权）</li>
 *   <li>返回空集 <strong>且</strong> {@code emptyBindingAllowed} → 可用（跳过 L-A）</li>
 *   <li>返回哨兵 → 拒绝</li>
 *   <li>返回空集但未声明 NONE → 拒绝</li>
 * </ul>
 *
 * <p><strong>为什么不注入容器</strong>：完整 {@code @SpringBootTest} 需要
 * {@code MitmCertificateAuthority} 的 CA 路径与密码配置，在无该配置的测试环境下会启动失败
 * （与本补丁无关的既有环境约束）。本测试用真实的 {@link EndpointCapability} 构造覆盖典型端点形态，
 * 足以验证判定链本身。
 */
class CapabilityAvailabilityAuditTest {

  /** 真实项目的典型端点形态（取自各 Controller 的实际映射）。 */
  private static List<String[]> endpointCases() {
    return List.of(
        // ---- 只读、无 target 段（P1-3 修复后应可用）----
        new String[] {"GET", "/api/vulnerabilities"},
        new String[] {"GET", "/api/vulnerabilities/{code}"},
        new String[] {"GET", "/api/tools"},
        new String[] {"GET", "/api/audits"},
        new String[] {"GET", "/api/ledger"},
        new String[] {"GET", "/api/projects"},
        new String[] {"GET", "/api/projects/{projectId}"},
        new String[] {"GET", "/api/projects/{projectId}/findings"},
        new String[] {"GET", "/api/tasks"},
        new String[] {"GET", "/api/tasks/{id}"},
        new String[] {"GET", "/api/scan-schedules"},
        new String[] {"GET", "/api/reports/projects/{projectId}"},
        new String[] {"GET", "/api/traffic/proxies"},
        new String[] {"HEAD", "/api/health"},
        new String[] {"OPTIONS", "/api/cors"},
        // ---- 只读、含 target 段（仍哨兵 → 拒绝）----
        new String[] {"GET", "/api/targets"},
        new String[] {"GET", "/api/targets/{targetId}"},
        new String[] {"GET", "/api/projects/{projectId}/targets"},
        // ---- 写方法（一律哨兵 → 拒绝，需 P1-4 才可用）----
        new String[] {"POST", "/api/tasks"},
        new String[] {"POST", "/api/tasks/{id}/retry"},
        new String[] {"PUT", "/api/projects/{projectId}"},
        new String[] {"PATCH", "/api/findings/{id}"},
        new String[] {"DELETE", "/api/targets/{targetId}"});
  }

  private static EndpointCapability build(String method, String path) {
    return new EndpointCapability(
        method,
        path,
        RiskInference.inferKind(method, path),
        RiskInference.inferRisk(method, path),
        RiskInference.inferRequiresApproval(method, path),
        EndpointCapability.isTargetBound(method, path),
        "审计端点");
  }

  /** 与护栏 L-A 判定一致。 */
  private static boolean passesAuthorizationLayer(EndpointCapability capability) {
    var bindings = capability.targetBindings(Map.of());
    if (bindings == null || bindings.isEmpty()) {
      return TargetBindingProbe.emptyBindingAllowed(capability);
    }
    return !bindings.contains(AgentCapability.TARGET_BINDING_UNRESOLVED);
  }

  @Test
  @DisplayName("P1-3 收益：只读端点能力从'全部被拒'变为'可通行'")
  void readOnlyEndpointsBecomeUsable() {
    List<String> usable = new ArrayList<>();
    List<String> blocked = new ArrayList<>();

    for (String[] c : endpointCases()) {
      EndpointCapability capability = build(c[0], c[1]);
      if (passesAuthorizationLayer(capability)) {
        usable.add(c[0] + " " + c[1]);
      } else {
        blocked.add(c[0] + " " + c[1]);
      }
    }

    System.out.println("============ P1-3 修复收益实测 ============");
    System.out.println("样例端点总数        = " + endpointCases().size());
    System.out.println("可通过 L-A（可用）   = " + usable.size());
    System.out.println("仍被拒绝            = " + blocked.size());
    System.out.println("--- 可用 ---");
    usable.forEach(s -> System.out.println("  ✅ " + s));
    System.out.println("--- 仍被拒绝（需 P1-4 或本就该拒）---");
    blocked.forEach(s -> System.out.println("  🔒 " + s));
    System.out.println("==========================================");

    // 核心断言：可用数必须精确匹配。
    //
    // ⚠️ 独立验证者 fix-verifier 指出（2026-10-12）：本用例原先只断言 `usable.size() > 0`，
    // 导致报告里的"15/23"这个数字**没有任何断言保护**——只要 ≥1 个可用就通过，
    // 若计数逻辑退化（例如误把哨兵算作可用）用例仍然绿。现改为精确锁定。
    assertEquals(
        15,
        usable.size(),
        "可通过 L-A 的只读端点必须恰好 15 个（修复前为 0/8）；"
            + "数字变化说明 P1-3 声明逻辑或判定逻辑被改动，需重新评估");
    assertEquals(
        23,
        endpointCases().size(),
        "样本数变化会使上面的 15 失去意义——若增删样本，请同步更新期望值");
    assertEquals(8, blocked.size(), "仍被拒绝的必须是 8 个（3 个 target 段只读 + 5 个写方法）");
    assertFalse(usable.isEmpty(), "至少只读无 target 段的端点必须可用");
  }

  @Test
  @DisplayName("P1-3 不放开写操作：所有写方法仍被 L-A 拒绝")
  void writeMethodsRemainBlocked() {
    for (String[] c : endpointCases()) {
      String method = c[0];
      if (List.of("GET", "HEAD", "OPTIONS", "TRACE").contains(method)) {
        continue;
      }
      EndpointCapability capability = build(method, c[1]);
      assertFalse(
          passesAuthorizationLayer(capability),
          method + " " + c[1] + " 是写方法，修复后仍必须被 L-A 拒绝（补丁不得放开写操作）");
    }
  }

  @Test
  @DisplayName("P1-3 含 target 段的只读端点仍被拒绝（不放行目标读取）")
  void targetSegmentReadsRemainBlocked() {
    for (String path :
        List.of("/api/targets", "/api/targets/{targetId}", "/api/projects/{projectId}/targets")) {
      EndpointCapability capability = build("GET", path);
      assertFalse(
          passesAuthorizationLayer(capability),
          "GET " + path + " 含 target 段，仍必须被 L-A 拒绝");
      assertEquals(
          TargetBindingProbe.Declaration.REQUIRED,
          TargetBindingProbe.declarationOf(capability),
          "GET " + path + " 必须声明 REQUIRED");
    }
  }
}
