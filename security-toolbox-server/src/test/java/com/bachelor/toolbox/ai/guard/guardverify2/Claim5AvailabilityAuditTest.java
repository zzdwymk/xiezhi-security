package com.bachelor.toolbox.ai.guard.guardverify2;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.endpoint.EndpointCapability;
import com.bachelor.toolbox.ai.endpoint.RiskInference;
import com.bachelor.toolbox.ai.guard.TargetBindingProbe;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * <strong>声明 5</strong>的独立验证：能力可用性是否真的从 8/23 提升到 15/23，
 * 且"可用"的判定标准确实是<strong>通过 L-A</strong>（而不是放宽了判定）。
 *
 * <h2>被验证的声明（Lead 原文）</h2>
 *
 * <blockquote>复核 {@code CapabilityAvailabilityAuditTest} 的样本与计数逻辑，确认"可用"的判定标准是
 * <strong>通过 L-A</strong>（而非放宽了判定）。</blockquote>
 *
 * <h2>复核 Lead 用例后发现的问题（本类的动机）</h2>
 *
 * <p>Lead 的 {@code CapabilityAvailabilityAuditTest} 有一个<strong>严重弱点</strong>：
 * 它的核心断言只有
 *
 * <pre>
 *   assertTrue(usable.size() &gt; 0, "修复后只读端点应可通过 L-A（修复前为 0）");
 * </pre>
 *
 * <p>这条断言<strong>根本没有锁定 15/23</strong>——只要"至少 1 个可用"就通过。
 * 报告 §4.2 里写的"15 / 23"<strong>没有被任何断言保护</strong>：计数逻辑若退化（例如
 * 误把哨兵也算可用），用例仍会通过。这正是本项目"伪通过"规则的同类形态。
 *
 * <p>因此本类<strong>自己实现</strong>判定与计数，并断言<strong>精确数字</strong>，
 * 同时用独立手段交叉验证判定标准的严格性。
 *
 * <h2>判定标准的严格性验证</h2>
 *
 * <p>关键风险：如果 {@code passesAuthorizationLayer} 被写成"返回空集就算可用"，
 * 那么 <em>未声明</em> 的空集能力（应当 fail-closed 被拒）会被误算为可用 → 数字虚高。
 * 本类用 {@code TargetBindingProbe.emptyBindingAllowed} 显式检查这一点，并用
 * "未声明的空集能力"做反例。
 */
class Claim5AvailabilityAuditTest {

  /**
   * 与 Lead 完全相同的 23 个样本端点（取自 {@code CapabilityAvailabilityAuditTest}）。
   *
   * <p>刻意复制样本，以便独立复现 15/23 这个数字。
   */
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
        "独立可用性审计端点");
  }

  /**
   * <strong>独立实现</strong>的"是否通过 L-A"判定——严格镜像
   * {@code CapabilityGate.resolveAndValidateAuthorization} 的三态逻辑。
   *
   * <p>与 Lead 的实现对照（两者语义应等价）：
   *
   * <ul>
   *   <li>哨兵 → false（L-A 拒绝）
   *   <li>空集 → 仅当 {@code emptyBindingAllowed} 为 true 才 true（显式声明 NONE）
   *   <li>含真实 ID → true（本样本中 EndpointCapability 不会出现这种情况）
   * </ul>
   */
  private static boolean passesAuthorizationLayer(EndpointCapability capability) {
    var bindings = capability.targetBindings(Map.of());
    if (bindings == null || bindings.isEmpty()) {
      // 关键：空集不是无条件可用——必须显式声明 NONE，否则 L-A 以 MISSING_TARGET_BINDING 拒绝。
      return TargetBindingProbe.emptyBindingAllowed(capability);
    }
    return !bindings.contains(AgentCapability.TARGET_BINDING_UNRESOLVED);
  }

  /** 统计可用数。 */
  private static int countUsable() {
    int usable = 0;
    for (String[] c : endpointCases()) {
      if (passesAuthorizationLayer(build(c[0], c[1]))) {
        usable++;
      }
    }
    return usable;
  }

  /**
   * <strong>核心断言</strong>：可用数必须<strong>精确等于 15</strong>（样本 23）。
   *
   * <p>这是 Lead 报告 §4.2 声称的数字。Lead 自己的用例只断言 {@code > 0}，
   * 因此这个数字此前<strong>没有被任何断言保护</strong>——本用例补上。
   */
  @Test
  @DisplayName("声明5-核心：可用数精确为 15/23（不是 >0 的弱断言）")
  void usableCountIsExactlyFifteen() {
    int total = endpointCases().size();
    int usable = countUsable();

    Assertions.assertEquals(23, total, "样本数应为 23（与 Lead 报告一致）");
    Assertions.assertEquals(
        15,
        usable,
        "可用数必须精确为 15/23。实际 " + usable + "/" + total + "。明细:\n" + describe());
  }

  /**
   * <strong>严格性验证</strong>：判定标准不得放宽——未声明的空集能力必须<strong>不可用</strong>。
   *
   * <p>若有人把 {@code passesAuthorizationLayer} 放宽成"空集即可用"，
   * 数字会虚高，而"未声明能力 fail-closed"这条安全性质会被静默破坏。
   */
  @Test
  @DisplayName("声明5-严格性：未声明空集的能力必须不可用（判定未放宽）")
  void undeclaredEmptyBindingIsNotUsable() {
    // 构造一个"返回空集但未声明 NONE"的端点能力（模拟声明访问器缺失）。
    EndpointCapability endpoint = build("GET", "/api/tasks");

    // 先确认它是"声明 NONE"的正常形态 → 可用。
    Assertions.assertEquals(
        TargetBindingProbe.Declaration.NONE,
        TargetBindingProbe.declarationOf(endpoint),
        "GET /api/tasks 不含 target 段，应声明 NONE");
    Assertions.assertTrue(
        passesAuthorizationLayer(endpoint), "声明 NONE 的空集端点应可用");

    // 再构造"未声明"的等价物：一个返回空集但不实现声明接口的能力。
    AgentCapability undeclared =
        new IndependentFixture.DeclaredParamsDriven(
                "undeclared_empty", com.bachelor.toolbox.ai.capability.CapabilityKind.READ,
                com.bachelor.toolbox.ai.capability.RiskLevel.SAFE, null) {
          @Override
          public java.util.Set<String> targetBindings(Map<String, Object> params) {
            return java.util.Set.of();
          }
        };

    // 未声明 + 空集 → emptyBindingAllowed 必须为 false → L-A 拒绝。
    Assertions.assertFalse(
        TargetBindingProbe.emptyBindingAllowed(undeclared),
        "未声明 NONE 的空集能力必须被 emptyBindingAllowed 拒绝（fail-closed）——"
            + "若这里为 true，说明判定被放宽，可用数会虚高");
  }

  /**
   * <strong>反例：写方法一律不可用</strong>。
   *
   * <p>P1-3 的修复<strong>不得</strong>放开写操作。若这条失败，说明修复过头了。
   */
  @Test
  @DisplayName("声明5-反例：所有写方法（POST/PUT/PATCH/DELETE）仍不可用")
  void writeMethodsRemainUnusable() {
    List<String> writable = new ArrayList<>();
    for (String[] c : endpointCases()) {
      if (List.of("GET", "HEAD", "OPTIONS", "TRACE").contains(c[0])) {
        continue;
      }
      if (passesAuthorizationLayer(build(c[0], c[1]))) {
        writable.add(c[0] + " " + c[1]);
      }
    }
    Assertions.assertTrue(
        writable.isEmpty(),
        "写方法必须全部不可用（P1-3 不得放开写操作），但以下被判定为可用: " + writable);
  }

  /**
   * <strong>反例：含 target 段的只读端点仍不可用</strong>。
   *
   * <p>这些端点必须保持 {@code REQUIRED} 声明（返回哨兵），不得因为"是 GET"就放行。
   */
  @Test
  @DisplayName("声明5-反例：含 target 段的只读端点仍不可用且声明 REQUIRED")
  void targetSegmentReadsRemainUnusable() {
    for (String path : List.of("/api/targets", "/api/targets/{targetId}", "/api/projects/{projectId}/targets")) {
      EndpointCapability endpoint = build("GET", path);
      Assertions.assertFalse(
          passesAuthorizationLayer(endpoint), "GET " + path + " 含 target 段，必须仍不可用");
      Assertions.assertEquals(
          TargetBindingProbe.Declaration.REQUIRED,
          TargetBindingProbe.declarationOf(endpoint),
          "GET " + path + " 必须声明 REQUIRED");
    }
  }

  /**
   * <strong>声明一致性</strong>：{@code targetBindingsDeclared()} 必须与
   * {@code targetBindings()} 的实际行为严格一致。
   *
   * <p>二者不一致会重新引入 fail-open（声明"不触及目标"却返回哨兵，或反之）。
   */
  @Test
  @DisplayName("声明5-一致性：targetBindingsDeclared() 与 targetBindings() 行为严格一致")
  void declarationMatchesBindingBehaviour() {
    for (String[] c : endpointCases()) {
      EndpointCapability endpoint = build(c[0], c[1]);
      boolean declared = endpoint.targetBindingsDeclared();
      boolean returnsSentinel =
          endpoint.targetBindings(Map.of()).contains(AgentCapability.TARGET_BINDING_UNRESOLVED);

      Assertions.assertEquals(
          declared,
          returnsSentinel,
          c[0] + " " + c[1] + "：声明(" + declared + ") 与实际返回哨兵(" + returnsSentinel + ") 必须一致");
    }
  }

  /**
   * <strong>P1-3 的收益量化</strong>：只读无 target 段的端点应<strong>全部</strong>可用。
   *
   * <p>这一组是修复的直接受益者；若有一个不可用，说明声明访问器仍有缺口。
   */
  @Test
  @DisplayName("声明5-收益：只读且无 target 段的端点全部可用")
  void readOnlyNonTargetEndpointsAllUsable() {
    List<String[]> readOnlyNonTarget =
        List.of(
            new String[] {"GET", "/api/vulnerabilities"},
            new String[] {"GET", "/api/tools"},
            new String[] {"GET", "/api/audits"},
            new String[] {"GET", "/api/ledger"},
            new String[] {"GET", "/api/projects"},
            new String[] {"GET", "/api/tasks"},
            new String[] {"GET", "/api/scan-schedules"},
            new String[] {"GET", "/api/traffic/proxies"},
            new String[] {"HEAD", "/api/health"},
            new String[] {"OPTIONS", "/api/cors"});

    List<String> unusable = new ArrayList<>();
    for (String[] c : readOnlyNonTarget) {
      if (!passesAuthorizationLayer(build(c[0], c[1]))) {
        unusable.add(c[0] + " " + c[1]);
      }
    }
    Assertions.assertTrue(
        unusable.isEmpty(), "只读且无 target 段的端点应全部可用，但以下不可用: " + unusable);
  }

  /** 明细输出（断言失败时便于定位）。 */
  private static String describe() {
    StringBuilder builder = new StringBuilder();
    for (String[] c : endpointCases()) {
      boolean usable = passesAuthorizationLayer(build(c[0], c[1]));
      builder
          .append(usable ? "  ✅ " : "  🔒 ")
          .append(c[0])
          .append(' ')
          .append(c[1])
          .append("  [声明=")
          .append(TargetBindingProbe.declarationOf(build(c[0], c[1])))
          .append("]\n");
    }
    return builder.toString();
  }

  /** 打印明细（供人工核对报告数字）。 */
  @Test
  @DisplayName("声明5-明细：打印 23 样本的可用性判定")
  void printDetail() {
    Map<String, Boolean> detail = new LinkedHashMap<>();
    for (String[] c : endpointCases()) {
      detail.put(c[0] + " " + c[1], passesAuthorizationLayer(build(c[0], c[1])));
    }
    long usable = detail.values().stream().filter(Boolean::booleanValue).count();
    System.out.println("===== fix-verifier 独立可用性复核 =====");
    System.out.println("样本总数 = " + detail.size());
    System.out.println("可用     = " + usable);
    System.out.println(describe());
    System.out.println("=======================================");
    Assertions.assertEquals(23, detail.size());
    Assertions.assertEquals(15L, usable);
  }
}
