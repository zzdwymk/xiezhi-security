package com.bachelor.toolbox.ai.guard;

import static com.bachelor.toolbox.ai.guard.GuardSupport.assertAllowed;
import static com.bachelor.toolbox.ai.guard.GuardSupport.assertDeniedAt;
import static com.bachelor.toolbox.ai.guard.GuardSupport.declaredNone;
import static com.bachelor.toolbox.ai.guard.GuardSupport.declaredWithBindings;
import static com.bachelor.toolbox.ai.guard.GuardSupport.params;
import static com.bachelor.toolbox.ai.guard.GuardSupport.target;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.guard.ApprovalLevel;
import com.bachelor.toolbox.ai.guard.ApprovalPolicy;
import com.bachelor.toolbox.ai.guard.CapabilityContext;
import com.bachelor.toolbox.ai.guard.CapabilityDeniedException;
import com.bachelor.toolbox.ai.guard.CapabilityGate;
import com.bachelor.toolbox.ai.guard.TargetBindingProbe;
import com.bachelor.toolbox.target.AuthorizedTarget;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * fail-closed 与 TOCTOU 的独立验证（清单 B-43..B-48、B-58..B-65）。
 *
 * <h2>本类要证伪的实现者声明与已知局限</h2>
 *
 * <ol>
 *   <li><strong>TOCTOU 部分实现（实现者已诚实报告）</strong>：比对逻辑已实现，但快照获取/注入依赖调用方传
 *       {@code approvedTargetBindings}；{@code ApprovalResolver} 已装配但未被 {@code invoke} 调用。
 *       → <strong>调用方不传则该校验静默跳过</strong>。本类量化这个 fail-open 的实际形态。
 *   <li><strong>schemaMode 默认 WARN</strong>：形状校验不拦截。本类验证"兜底是否真的与 schema 模式无关"。
 *   <li><strong>TargetBindingProbe 用反射</strong>：异常收敛为 {@code UNKNOWN} → 拒绝。本类验证"反射失败时确实拒绝而非放行"。
 * </ol>
 */
@DisplayName("fail-closed 与 TOCTOU 对抗验证")
class GuardFailClosedTests {

  private static final Map<Long, AuthorizedTarget> TARGETS =
      Map.of(
          1L, target(1L, "192.168.10.10", "80,443"),
          2L, target(2L, "192.168.10.99", "80"));

  private static CapabilityContext approved() {
    return CapabilityContext.of("ai-agent", 7L).approved(1L);
  }

  // ==================================================================
  // B-43..B-48 TOCTOU
  // ==================================================================

  @Nested
  @DisplayName("B-43..B-48 TOCTOU：审批后授权变化")
  class Toctou {

    /**
     * <strong>传入快照且目标一致 → 放行</strong>（对照组）。
     *
     * <p>先证明比对逻辑本身能跑通，才能把后续的"跳过"归因为"没传快照"而非"逻辑坏了"。
     */
    @Test
    @DisplayName("B-43a 传入一致快照 → 放行（对照组）")
    void matchingSnapshotIsAllowed() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("toctou_ok", Set.of("1"))), TARGETS);
      CapabilityContext ctx =
          approved().withApprovedTargetBindings(Map.of("1", "192.168.10.10"));

      assertAllowed(() -> fixture.gate().invoke("toctou_ok", Map.of(), ctx));
    }

    /**
     * <strong>核心 TOCTOU 用例</strong>：审批时记录目标 1，但本次调用绑定目标 2（换靶）。
     *
     * <p>预期：拒绝 {@code AUTHORIZATION_SNAPSHOT_CHANGED}。这是"审批的是 A、打的是 B"的直接防护。
     */
    @Test
    @DisplayName("B-43b 快照记录目标 1、本次绑定目标 2 → 必须拒绝 AUTHORIZATION_SNAPSHOT_CHANGED")
    void changedTargetBindingIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("toctou_swap", Set.of("2"))), TARGETS);
      CapabilityContext ctx =
          approved().withApprovedTargetBindings(Map.of("1", "192.168.10.10"));

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "AUTHORIZATION_SNAPSHOT_CHANGED",
          () -> fixture.gate().invoke("toctou_swap", Map.of(), ctx));
    }

    /**
     * <strong>关键 fail-open 量化用例</strong>：调用方<strong>不传</strong> {@code approvedTargetBindings} 时，
     * 同一个"换靶"调用是否被放行？
     *
     * <p>实现者已诚实报告"不传则静默跳过"。本用例把这个行为<strong>固化为可执行断言</strong>，用于在报告里给出精确结论：
     * TOCTOU 防护的<strong>有效性完全依赖调用方</strong>，护栏自身无法保证。
     *
     * <p>本用例不断言"必须拒绝"（那会失败，因为实现确实跳过），而是断言"确实被放行"——把 fail-open 的形态记录下来，
     * 并让它在实现补上 {@code ApprovalResolver} 接线后<strong>立即失败</strong>，提示验证者更新结论。
     */
    @Test
    @DisplayName("B-43c 【fail-open 量化】不传快照 → 换靶调用被放行（TOCTOU 防护可被调用方静默关闭）")
    void missingSnapshotSilentlySkipsToctouCheck() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("toctou_skip", Set.of("2"))), TARGETS);
      // 已批准但未携带快照 —— 这正是"调用方忘记传"的真实形态。
      CapabilityContext ctx = approved();

      org.junit.jupiter.api.Assertions.assertDoesNotThrow(
          () -> fixture.gate().invoke("toctou_skip", Map.of(), ctx),
          "若此处开始抛异常，说明护栏已自行解析审批快照（ApprovalResolver 已接入 invoke）："
              + "请把本用例改为断言拒绝，并更新报告的 TOCTOU 结论");
    }

    /**
     * 空 Map 快照（而非 {@code null}）：与"不传"等价——同样跳过。
     *
     * <p>{@code CapabilityGate:422} 的条件是 {@code !approvedTargetBindings().isEmpty()}。空 Map 也走跳过分支。
     * 这意味着"审批未记录目标"与"审批记录了目标但恰好为空"无法区分。
     */
    @Test
    @DisplayName("B-43d 空 Map 快照同样跳过校验（空快照 ≠ 无目标）")
    void emptySnapshotAlsoSkipsCheck() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("toctou_empty", Set.of("2"))), TARGETS);
      CapabilityContext ctx = approved().withApprovedTargetBindings(Map.of());

      org.junit.jupiter.api.Assertions.assertDoesNotThrow(
          () -> fixture.gate().invoke("toctou_empty", Map.of(), ctx),
          "若此处开始抛异常，说明空快照已被视为『必须拒绝』：请更新本用例与报告");
    }

    /**
     * 快照比实际绑定<strong>多</strong>一个目标 → 必须拒绝。
     *
     * <p>方向性检查：实现遍历的是 {@code recorded} 并验证其每个键都在 {@code validated} 里。快照记录 {1,2}、实际只绑定 {1}
     * 时会拒绝（因为 2 不在 validated 里）——这是正确的保守方向。
     */
    @Test
    @DisplayName("B-43e 快照含实际未绑定的目标 → 必须拒绝（保守方向）")
    void snapshotSupersetIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("toctou_super", Set.of("1"))), TARGETS);
      CapabilityContext ctx =
          approved().withApprovedTargetBindings(Map.of("1", "a", "2", "b"));

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "AUTHORIZATION_SNAPSHOT_CHANGED",
          () -> fixture.gate().invoke("toctou_super", Map.of(), ctx));
    }

    /**
     * <strong>目标授权窗口过期但快照一致</strong>：仍然必须拒绝。
     *
     * <p>TOCTOU 防的是"审批后授权变化"，而授权有效期是另一条独立规则（{@code validateTargetValidity}）。本用例确认
     * 过期检查不会被"快照一致"短路。
     */
    @Test
    @DisplayName("B-43f 快照一致但目标已过期 → 仍必须拒绝（有效期独立于快照）")
    void expiredTargetStillDeniedEvenWithMatchingSnapshot() {
      Map<Long, AuthorizedTarget> expired =
          Map.of(1L, GuardSupport.expiredTarget(1L, "192.168.10.10", "80,443"));
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("toctou_expired", Set.of("1"))), expired);
      CapabilityContext ctx =
          approved().withApprovedTargetBindings(Map.of("1", "192.168.10.10"));

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "AUTHORIZATION_EXPIRED",
          () -> fixture.gate().invoke("toctou_expired", Map.of(), ctx));
    }
  }

  // ==================================================================
  // B-58..B-65 异常路径必须拒绝
  // ==================================================================

  @Nested
  @DisplayName("B-58..B-65 异常路径一律 fail-closed")
  class ExceptionPaths {

    /** 能力自定义校验抛非 ApiException（如 NPE）→ 必须拒绝，不能因"异常类型不对"而放行。 */
    @Test
    @DisplayName("B-58a validateParams 抛 NPE → 必须拒绝")
    void runtimeExceptionInValidateParamsIsDenied() {
      AgentCapability thrower =
          GuardSupport.DeclaredStub.of(
              "param_thrower",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of("1"),
              TargetBindingProbe.Declaration.REQUIRED);
      AgentCapability realThrower =
          new GuardSupport.StubCapability(
              "param_thrower",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              false,
              Set.of("1"),
              Map.of(),
              p -> {
                throw new NullPointerException("模拟内部故障");
              },
              TargetBindingProbe.Declaration.REQUIRED) {};
      // 用匿名子类实现声明接口，确保声明可被探测。
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(realThrower), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.PARAMETER,
          "INVALID_PARAMETER",
          () -> fixture.gate().invoke("param_thrower", Map.of(), approved()));
    }

    /** 能力声明访问器抛异常 → 必须收敛为 UNKNOWN（拒绝），不能放行。 */
    @Test
    @DisplayName("B-58b 声明访问器抛异常 → 必须拒绝（不能放行）")
    void throwingDeclarationAccessorFailsClosed() {
      AgentCapability broken =
          new GuardSupport.StubCapability(
              "broken_declaration",
              CapabilityKind.READ,
              RiskLevel.SAFE,
              false,
              Set.of(),
              Map.of(),
              null,
              null) {
            @SuppressWarnings("unused")
            public Object targetScope() {
              throw new IllegalStateException("模拟反射读取失败");
            }
          };
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(broken), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "MISSING_TARGET_BINDING",
          () -> fixture.gate().invoke("broken_declaration", Map.of(), approved()));
    }

    /**
     * {@link TargetBindingProbe} 单元级：反射拿到<strong>未知枚举名</strong>时必须收敛为 UNKNOWN。
     *
     * <p>攻击设想：能力返回一个护栏不认识的 {@code targetScope} 值（如 {@code "MAYBE"}），若实现把它当成"不是 REQUIRED"
     * 而放行空集，就是 fail-open。
     */
    @Test
    @DisplayName("B-58c TargetBindingProbe：未知 targetScope 取值 → UNKNOWN（拒绝）")
    void unknownTargetScopeValueBecomesUnknown() {
      AgentCapability weird =
          new GuardSupport.StubCapability(
              "weird_scope",
              CapabilityKind.READ,
              RiskLevel.SAFE,
              false,
              Set.of(),
              Map.of(),
              null,
              null) {
            @SuppressWarnings("unused")
            public String targetScope() {
              return "MAYBE";
            }
          };

      org.junit.jupiter.api.Assertions.assertEquals(
          TargetBindingProbe.Declaration.UNKNOWN,
          TargetBindingProbe.declarationOf(weird),
          "未知取值必须收敛为 UNKNOWN（fail-closed），不能当成 NONE");
      org.junit.jupiter.api.Assertions.assertFalse(
          TargetBindingProbe.emptyBindingAllowed(weird),
          "UNKNOWN 时空集必须不合法");
    }

    /** {@code TargetBindingProbe} 对 {@code null} 能力必须返回 UNKNOWN。 */
    @Test
    @DisplayName("B-58d TargetBindingProbe：null 能力 → UNKNOWN")
    void nullCapabilityIsUnknown() {
      org.junit.jupiter.api.Assertions.assertEquals(
          TargetBindingProbe.Declaration.UNKNOWN, TargetBindingProbe.declarationOf(null));
    }

    /**
     * <strong>B-58e【真实缺陷】目标访问器抛异常 → 异常<u>原样冒泡</u>，未被归一化为护栏拒绝。</strong>
     *
     * <p>我原本断言"必须拒绝（{@code TARGET_NOT_FOUND}）"，<strong>实测得到
     * {@code IllegalStateException}</strong>——异常直接穿透护栏。
     *
     * <p><strong>根因</strong>（{@code CapabilityGate:437-447}）：
     *
     * <pre>
     * private AuthorizedTarget requireTarget(long targetId, AgentCapability capability) {
     *   return targetAccessResolver
     *       .find(targetId)                    // ← 无 try/catch
     *       .orElseThrow(() -&gt; deny(..., "TARGET_NOT_FOUND", ...));
     * }
     * </pre>
     *
     * <p>对比：<strong>同一文件的 {@code :350} 对 {@code targetBindings()} 的异常做了 catch</strong>
     * 并转为 {@code TARGET_BINDING_UNRESOLVED}；而 {@code find()} 的异常<strong>没有</strong>对应处理。
     * <strong>同一层内的两种访问器，异常处理不一致。</strong>
     *
     * <p><strong>为什么这是缺陷而不是"无害的"</strong>：
     *
     * <ol>
     *   <li><strong>审计缺失</strong>：{@code invoke} 的 catch（{@code :175}）只捕获
     *       {@code CapabilityDeniedException}。{@code IllegalStateException} 会绕过审计落库，
     *       导致"护栏因故障未拦截"这一事件<strong>无记录</strong>。
     *   <li><strong>行为不可预测</strong>：调用方若按"护栏要么放行要么抛 {@code CapabilityDeniedException}"编写，
     *       遇到裸异常可能落入自己的 catch-all → <strong>可能被当成"内部错误"而重试或降级放行</strong>。
     *   <li><strong>信息泄露</strong>：底层异常消息（可能含 SQL/连接串）直接返回给调用方。
     * </ol>
     *
     * <p><strong>安全方向是"拒绝"</strong>（因为异常导致 {@code find} 未成功），所以不是 fail-open；
     * 但它是 <strong>fail-closed 的"非受控形态"</strong>——结论对、过程失控。
     *
     * <p><strong>✅ 已修复（2026-10-12）</strong>：{@code requireTarget} 现在用 try/catch 包裹
     * {@code find()}，把任何 {@link RuntimeException} 归一化为
     * {@code CapabilityDeniedException(TARGET_ACCESS_FAILED)}，并带审计详情
     * {@code guardInternalFailure=true} + {@code failureType}（<strong>不含</strong>底层异常消息）。
     *
     * <p>本用例原断言"裸异常"（缺陷行为），现改为断言<strong>归一化拒绝</strong>：
     * 层 = L-A，原因码 = {@code TARGET_ACCESS_FAILED}，且消息<strong>不含</strong>底层异常文本。
     */
    @Test
    @DisplayName("B-58e 【已修复】目标访问器抛异常 → 归一化为 TARGET_ACCESS_FAILED（不泄露底层消息）")
    void throwingTargetResolverIsNormalizedToDenial() {
      CapabilityGate.TargetAccessResolver throwing =
          GuardSupport.failingResolver(new IllegalStateException("模拟目标库故障"));
      CapabilityGate gate =
          GuardSupport.gateWithResolver(
              List.of(declaredWithBindings("resolver_fail", Set.of("1"))), throwing);

      CapabilityDeniedException denied =
          org.junit.jupiter.api.Assertions.assertThrows(
              CapabilityDeniedException.class,
              () -> gate.invoke("resolver_fail", Map.of(), approved()),
              "访问器故障必须归一化为护栏拒绝，而不是裸异常冒泡");

      org.junit.jupiter.api.Assertions.assertEquals(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          denied.layer(),
          "归一化后应来自 L-A");
      org.junit.jupiter.api.Assertions.assertEquals(
          "TARGET_ACCESS_FAILED", denied.reasonCode(), "应使用专门的内部故障原因码");

      // 信息泄露面：拒绝消息不得包含底层异常文本。
      org.junit.jupiter.api.Assertions.assertFalse(
          denied.getMessage().contains("模拟目标库故障"),
          "拒绝消息不得泄露底层异常消息，实际: " + denied.getMessage());

      // 审计留痕：护栏自身故障必须可追溯。
      org.junit.jupiter.api.Assertions.assertEquals(
          Boolean.TRUE,
          denied.auditDetails().get("guardInternalFailure"),
          "护栏自身故障必须在审计中标记");
      org.junit.jupiter.api.Assertions.assertEquals(
          "IllegalStateException",
          denied.auditDetails().get("failureType"),
          "审计应记录异常类型（内部可见），但不记录其消息");
    }

    /** 目标访问器返回空（目标不存在）→ 拒绝。 */
    @Test
    @DisplayName("B-58f 目标不存在 → 拒绝 TARGET_NOT_FOUND")
    void missingTargetFailsClosed() {
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(), TARGETS);
      CapabilityGate gate =
          GuardSupport.gateWithResolver(
              List.of(declaredWithBindings("missing_target", Set.of("777"))),
              GuardSupport.emptyResolver());
      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_NOT_FOUND",
          () -> gate.invoke("missing_target", Map.of(), approved()));
    }

    /**
     * <strong>审计通道故障不得改变护栏结论</strong>。
     *
     * <p>两个方向都要正确：审计抛异常时，<strong>拒绝仍是拒绝</strong>（安全），且<strong>放行仍是放行</strong>（可用性）。
     * 若实现写成"审计失败 → 拒绝"，护栏会在审计故障时变成拒绝一切（可用性事故）；若"审计失败 → 放行"，则拒绝会变成放行
     * （安全事故）。本用例锁住前者：拒绝不因审计故障而消失。
     */
    @Test
    @DisplayName("B-62 审计抛异常时，拒绝结论不变（不得变成放行）")
    void auditFailureDoesNotTurnDenialIntoAllow() {
      CapabilityGate gate =
          GuardSupport.gateWithAudit(
              List.of(GuardSupport.declaredRequiredEmpty("audit_fail")),
              TARGETS,
              (action, code, detail, result) -> {
                throw new IllegalStateException("模拟审计通道故障");
              });

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "MISSING_TARGET_BINDING",
          () -> gate.invoke("audit_fail", Map.of(), approved()));
    }

    /** 审计抛异常时，放行结论也不变（可用性方向）。 */
    @Test
    @DisplayName("B-62b 审计抛异常时，放行结论不变（不得变成拒绝）")
    void auditFailureDoesNotTurnAllowIntoDenial() {
      CapabilityGate gate =
          GuardSupport.gateWithAudit(
              List.of(declaredNone("audit_fail_allow")),
              TARGETS,
              (action, code, detail, result) -> {
                throw new IllegalStateException("模拟审计通道故障");
              });

      assertAllowed(() -> gate.invoke("audit_fail_allow", Map.of(), approved()));
    }
  }

  // ==================================================================
  // B-39..B-42 白名单默认行为
  // ==================================================================

  @Nested
  @DisplayName("B-39..B-42 白名单未开启时的默认行为")
  class WhitelistDefaults {

    /** DESTRUCTIVE 能力在白名单未开启时必须拒绝（§6.4 fail-closed）。 */
    @Test
    @DisplayName("B-39a DESTRUCTIVE 能力未显式开启 → 拒绝 CAPABILITY_NOT_ENABLED")
    void destructiveCapabilityNeedsExplicitEnable() {
      AgentCapability destructive =
          GuardSupport.DeclaredStub.of(
              "destructive_op",
              CapabilityKind.EXECUTE,
              RiskLevel.DESTRUCTIVE,
              Set.of("1"),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(destructive), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.ADMISSION,
          "CAPABILITY_NOT_ENABLED",
          () -> fixture.gate().invoke("destructive_op", Map.of(), approved()));
    }

    /** ADMIN 类能力在白名单未开启时必须拒绝。 */
    @Test
    @DisplayName("B-39b ADMIN 类能力未显式开启 → 拒绝")
    void adminCapabilityNeedsExplicitEnable() {
      AgentCapability admin =
          GuardSupport.DeclaredStub.of(
              "admin_op",
              CapabilityKind.ADMIN,
              RiskLevel.SENSITIVE,
              Set.of("1"),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(admin), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.ADMISSION,
          "CAPABILITY_NOT_ENABLED",
          () -> fixture.gate().invoke("admin_op", Map.of(), approved()));
    }

    /** 显式开启后 DESTRUCTIVE 能力可放行（对照组，证明上面的拒绝不是"一律拒绝"）。 */
    @Test
    @DisplayName("B-39c 对照组：显式开启白名单后 DESTRUCTIVE 能力放行")
    void explicitlyEnabledDestructiveCapabilityIsAllowed() {
      AgentCapability destructive =
          GuardSupport.DeclaredStub.of(
              "destructive_enabled",
              CapabilityKind.EXECUTE,
              RiskLevel.DESTRUCTIVE,
              Set.of("1"),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(
              List.of(destructive),
              TARGETS,
              com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
              "destructive_enabled",
              "",
              CapabilityGate.SchemaMode.WARN,
              true);

      assertAllowed(() -> fixture.gate().invoke("destructive_enabled", Map.of(), approved()));
    }

    /**
     * <strong>B-40 白名单开关自身可被 Agent 修改？</strong>
     *
     * <p>护栏的白名单来自 Spring 配置（{@code toolbox.agent.guard.whitelist}），不是运行期可变状态。本用例验证
     * {@code enabledWhitelist()} 返回的是构造时的快照，调用 {@code invoke} 不会改变它——即"调用能力不能给自己开后门"。
     */
    @Test
    @DisplayName("B-40 白名单是构造期快照，调用能力不能自我提权")
    void whitelistIsImmutableSnapshot() {
      AgentCapability destructive =
          GuardSupport.DeclaredStub.of(
              "self_promote",
              CapabilityKind.EXECUTE,
              RiskLevel.DESTRUCTIVE,
              Set.of("1"),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(destructive), TARGETS);

      Set<String> before = fixture.gate().enabledWhitelist();
      assertDeniedAt(
          CapabilityDeniedException.Layer.ADMISSION,
          "CAPABILITY_NOT_ENABLED",
          () -> fixture.gate().invoke("self_promote", Map.of(), approved()));

      org.junit.jupiter.api.Assertions.assertEquals(
          before, fixture.gate().enabledWhitelist(), "白名单不得因调用而改变");
      org.junit.jupiter.api.Assertions.assertTrue(
          fixture.gate().enabledWhitelist().isEmpty(), "默认白名单必须为空");
    }

    /** 白名单通配符（{@code prefix*}）不得意外匹配到不该开的能力。 */
    @Test
    @DisplayName("B-42 白名单通配符只按前缀匹配，不得越界")
    void whitelistWildcardRespectsPrefix() {
      AgentCapability allowed =
          GuardSupport.DeclaredStub.of(
              "scan_one",
              CapabilityKind.EXECUTE,
              RiskLevel.DESTRUCTIVE,
              Set.of("1"),
              TargetBindingProbe.Declaration.REQUIRED);
      AgentCapability notAllowed =
          GuardSupport.DeclaredStub.of(
              "scanXtwo",
              CapabilityKind.EXECUTE,
              RiskLevel.DESTRUCTIVE,
              Set.of("1"),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(
              List.of(allowed, notAllowed),
              TARGETS,
              com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
              "scan_one",
              "",
              CapabilityGate.SchemaMode.WARN,
              true);

      assertAllowed(() -> fixture.gate().invoke("scan_one", Map.of(), approved()));
      assertDeniedAt(
          CapabilityDeniedException.Layer.ADMISSION,
          "CAPABILITY_NOT_ENABLED",
          () -> fixture.gate().invoke("scanXtwo", Map.of(), approved()));
    }

    /** 黑名单能力即使显式加入白名单也必须被拒（黑名单绝对优先）。 */
    @Test
    @DisplayName("B-41 黑名单优先级高于白名单（显式开启也不能放行）")
    void blacklistBeatsWhitelist() {
      AgentCapability shutdown =
          GuardSupport.DeclaredStub.of(
              "shutdown_system",
              CapabilityKind.ADMIN,
              RiskLevel.DESTRUCTIVE,
              Set.of(),
              TargetBindingProbe.Declaration.NONE);
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(
              List.of(shutdown),
              TARGETS,
              com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
              "shutdown_system",
              "shutdown_system",
              CapabilityGate.SchemaMode.WARN,
              true);

      assertDeniedAt(
          CapabilityDeniedException.Layer.ADMISSION,
          "BLOCKED_CAPABILITY",
          () -> fixture.gate().invoke("shutdown_system", Map.of(), approved()));
    }
  }

  // ==================================================================
  // 确认策略（§6.6）
  // ==================================================================

  @Nested
  @DisplayName("确认策略 §6.6")
  class Approval {

    /** 触及目标 + 非只读 → REQUIRED；未批准 → 拒绝 APPROVAL_REQUIRED。 */
    @Test
    @DisplayName("触及目标 + 非只读 + 未批准 → 拒绝 APPROVAL_REQUIRED")
    void executionOnTargetRequiresApproval() {
      AgentCapability scan =
          GuardSupport.DeclaredStub.of(
              "exec_scan",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of("1"),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(scan), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.ADMISSION,
          "APPROVAL_REQUIRED",
          () -> fixture.gate().invoke("exec_scan", Map.of(), CapabilityContext.of("ai-agent", 7L)));
    }

    /** 已批准后同一调用放行（对照组）。 */
    @Test
    @DisplayName("对照组：已批准 → 放行")
    void approvedExecutionIsAllowed() {
      AgentCapability scan =
          GuardSupport.DeclaredStub.of(
              "exec_scan_ok",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of("1"),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(scan), TARGETS);

      assertAllowed(() -> fixture.gate().invoke("exec_scan_ok", Map.of(), approved()));
    }

    /**
     * {@link ApprovalPolicy} 单元级：{@code requiresApproval()} 声明的能力必须 REQUIRED。
     *
     * <p>绕过设想：能力自己声明"需要确认"，但 {@code kind=READ}、{@code risk=SAFE}，若策略先判"READ+SAFE → NONE"，
     * 声明就被覆盖了。本用例验证声明的优先级。
     */
    @Test
    @DisplayName("ApprovalPolicy：requiresApproval 声明优先于 READ+SAFE 推断")
    void declaredApprovalBeatsReadSafeInference() {
      AgentCapability declared =
          new GuardSupport.StubCapability(
              "declared_approval", CapabilityKind.READ, RiskLevel.SAFE, true, Set.of(), Map.of(), null, null);
      ApprovalPolicy policy = new ApprovalPolicy();
      org.junit.jupiter.api.Assertions.assertEquals(
          ApprovalLevel.REQUIRED,
          policy.levelFor(declared, Map.of(), Set.of()),
          "能力显式声明需要确认时，不得因 READ+SAFE 而降级为 NONE");
    }

    /** {@link ApprovalPolicy} 单元级：null 能力按最严处理。 */
    @Test
    @DisplayName("ApprovalPolicy：null 能力 → REQUIRED（保守优先）")
    void nullCapabilityIsMostStrict() {
      org.junit.jupiter.api.Assertions.assertEquals(
          ApprovalLevel.REQUIRED, new ApprovalPolicy().levelFor(null, Map.of(), Set.of()));
    }
  }
}
