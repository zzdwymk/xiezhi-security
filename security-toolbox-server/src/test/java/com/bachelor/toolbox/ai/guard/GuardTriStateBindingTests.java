package com.bachelor.toolbox.ai.guard;

import static com.bachelor.toolbox.ai.guard.GuardSupport.assertDeniedAt;
import static com.bachelor.toolbox.ai.guard.GuardSupport.declaredNone;
import static com.bachelor.toolbox.ai.guard.GuardSupport.declaredRequiredEmpty;
import static com.bachelor.toolbox.ai.guard.GuardSupport.declaredWithBindings;
import static com.bachelor.toolbox.ai.guard.GuardSupport.disguisedWrite;
import static com.bachelor.toolbox.ai.guard.GuardSupport.params;
import static com.bachelor.toolbox.ai.guard.GuardSupport.target;
import static com.bachelor.toolbox.ai.guard.GuardSupport.undeclaredEmpty;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
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
 * S-01..S-05：{@code targetBindings} 三态语义的独立验证（设计文档 §4.1.1 修订）。
 *
 * <h2>背景</h2>
 *
 * <p>§4.1 初版签名 {@code default Set<String> targetBindings(params) { return Set.of(); }} 在本平台的真实布局下会让
 * <strong>全部扫描类能力返回空集 → 跳过 L-A → fail-open</strong>（目标 ID 是请求级字段，不在工具 params 里）。修订为三态：
 * 真空集 / 真实 ID / 哨兵 {@code TARGET_BINDING_UNRESOLVED}。
 *
 * <p>但仅有三态还不够：能力可以<strong>什么都没声明</strong>就返回空集（default 方法）。因此还需要第四种判定——
 * {@link TargetBindingProbe} 的"是否显式声明不触及目标"。本类验证这个"第四态"。
 *
 * <h2>本类要证伪的声明</h2>
 *
 * <blockquote>
 * "实现者称有独立于 schema 模式的无条件兜底：空集 + 未显式声明不触及目标 → 拒绝 MISSING_TARGET_BINDING。"
 * </blockquote>
 *
 * <p>关键词是<strong>无条件</strong>：兜底不能受 {@code schemaMode}（默认 WARN）影响，也不能被 {@code risk()} /
 * {@code requiresApproval()} / {@code kind()} 这些推导值绕过。
 */
@DisplayName("S-01..S-05 三态语义对抗验证")
class GuardTriStateBindingTests {

  private static final Map<Long, AuthorizedTarget> TARGETS =
      Map.of(1L, target(1L, "192.168.10.10", "80,443"), 2L, target(2L, "192.168.10.99", "80"));

  private static CapabilityContext approved() {
    return CapabilityContext.of("ai-agent", 7L).approved(1L);
  }

  // ==================================================================
  // S-01 哨兵态必须被拒绝
  // ==================================================================

  @Nested
  @DisplayName("S-01 哨兵态必须 fail-closed")
  class Sentinel {

    /** 哨兵 → 拒绝，且拒因码是 {@code TARGET_BINDING_UNRESOLVED}、层是 L-A。 */
    @Test
    @DisplayName("S-01a 返回哨兵的能力必须被 L-A 拒绝")
    void sentinelIsDeniedAtAuthorizationLayer() {
      AgentCapability sentinel =
          GuardSupport.DeclaredStub.of(
              "sentinel_scan",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(sentinel), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_BINDING_UNRESOLVED",
          () -> fixture.gate().invoke("sentinel_scan", params("ports", "80"), approved()));
    }

    /**
     * <strong>反事实断言（清单 S-01 的核心）</strong>：同一个能力，若把返回值从哨兵改成空集，行为必须<strong>不同</strong>。
     *
     * <p>两条都拒绝 → 说明哨兵没有独立语义（退化成"空集也拒"，会误拦 {@code retrieve_project_context}）；
     * 两条都放行 → 哨兵未实现（fail-open）。必须"一拒一放"。
     */
    @Test
    @DisplayName("S-01b 反事实：哨兵拒绝 而 显式声明 NONE 的空集放行 —— 两者行为必须不同")
    void sentinelAndDeclaredNoneBehaveDifferently() {
      AgentCapability sentinel =
          GuardSupport.DeclaredStub.of(
              "same_shape",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
              TargetBindingProbe.Declaration.REQUIRED);
      AgentCapability none = declaredNone("same_shape_none");
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(sentinel, none), TARGETS);

      // 哨兵 → 拒
      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_BINDING_UNRESOLVED",
          () -> fixture.gate().invoke("same_shape", Map.of(), approved()));

      // 显式 NONE 的空集 → 放
      GuardSupport.assertAllowed(() -> fixture.gate().invoke("same_shape_none", Map.of(), approved()));
    }

    /**
     * 哨兵<strong>与真实 ID 混在同一个集合里</strong>：必须拒绝。
     *
     * <p>攻击设想：返回 {@code {1, "__UNRESOLVED__"}}，若实现"只要有一个能解析就继续"，未解析的那部分就被静默丢弃。
     */
    @Test
    @DisplayName("S-01c 哨兵与真实 ID 混合 → 仍必须拒绝")
    void sentinelMixedWithRealIdIsStillDenied() {
      AgentCapability mixed =
          GuardSupport.DeclaredStub.of(
              "mixed_binding",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of("1", AgentCapability.TARGET_BINDING_UNRESOLVED),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(mixed), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_BINDING_UNRESOLVED",
          () -> fixture.gate().invoke("mixed_binding", Map.of(), approved()));
    }

    /**
     * 能力自己抛异常（而非返回哨兵）：必须 fail-closed 拒绝。
     *
     * <p>攻击设想：让 {@code targetBindings} 在畸形输入下抛 NPE，若护栏 {@code catch (Exception) { return allow; }}
     * 就放行了。{@code CapabilityGate:350-357} 声称会转成拒绝——这里验证。
     */
    @Test
    @DisplayName("S-01d targetBindings 抛异常 → 必须 fail-closed 拒绝")
    void throwingTargetBindingsFailsClosed() {
      AgentCapability thrower =
          new GuardSupport.StubCapability(
              "throwing_scan",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              false,
              null,
              Map.of(),
              null,
              null) {
            @Override
            public Set<String> targetBindings(Map<String, Object> params) {
              throw new IllegalStateException("模拟解析失败");
            }
          };
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(thrower), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_BINDING_UNRESOLVED",
          () -> fixture.gate().invoke("throwing_scan", Map.of(), approved()));
    }

    /** 返回 {@code null} 而非集合：必须拒绝，不能当成"空集=不触及"。 */
    @Test
    @DisplayName("S-01e targetBindings 返回 null → 必须拒绝")
    void nullBindingsIsDenied() {
      AgentCapability nullReturner =
          new GuardSupport.StubCapability(
              "null_binding_scan",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              false,
              null,
              Map.of(),
              null,
              null) {
            @Override
            public Set<String> targetBindings(Map<String, Object> params) {
              return null;
            }
          };
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(nullReturner), TARGETS);

      // 返回 null → 被当成空集 → 因为未显式声明 NONE，应被 MISSING_TARGET_BINDING 拒绝。
      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "MISSING_TARGET_BINDING",
          () -> fixture.gate().invoke("null_binding_scan", Map.of(), approved()));
    }
  }

  // ==================================================================
  // S-02 空集与哨兵不可混淆
  // ==================================================================

  @Nested
  @DisplayName("S-02 空集与哨兵语义二分")
  class EmptyVersusSentinel {

    /** 显式声明 NONE 的空集（如 retrieve_project_context）→ 放行。 */
    @Test
    @DisplayName("S-02a 显式声明 NONE 的空集能力放行（模拟 retrieve_project_context）")
    void declaredNoneIsAllowed() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredNone("retrieve_project_context")), TARGETS);
      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("retrieve_project_context", Map.of(), approved()));
    }

    /** 声明 REQUIRED 但返回空集 → 必须拒绝（开发者忘了解析，不能当"不触及"）。 */
    @Test
    @DisplayName("S-02b 声明 REQUIRED 却返回空集 → 必须拒绝")
    void declaredRequiredButEmptyIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredRequiredEmpty("forgot_to_resolve")), TARGETS);
      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "MISSING_TARGET_BINDING",
          () -> fixture.gate().invoke("forgot_to_resolve", Map.of(), approved()));
    }
  }

  // ==================================================================
  // S-03 kind 伪装
  // ==================================================================

  @Nested
  @DisplayName("S-03 kind 伪装：声明为 WRITE 仍必须按 targetBindings 校验")
  class KindDisguise {

    /**
     * <strong>核心用例</strong>：能力 {@code kind=WRITE}、{@code risk=SAFE}，但返回一个<strong>不存在的</strong> targetId。
     *
     * <p>必须被 L-A 拒绝。若因为 {@code kind=WRITE} / {@code risk=SAFE} 而跳过授权校验，即证明"判定依赖 kind"——正是 §6.2
     * 要防的错误。
     */
    @Test
    @DisplayName("S-03a WRITE + SAFE 但绑定不存在的目标 → 仍必须被 L-A 拒绝")
    void writeKindWithNonexistentTargetIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(disguisedWrite("sneaky_write", Set.of("999"))), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_NOT_FOUND",
          () -> fixture.gate().invoke("sneaky_write", Map.of(), approved()));
    }

    /**
     * <strong>反向断言</strong>：把同一个能力的 {@code kind} 从 WRITE 改成 EXECUTE，结果必须<strong>不变</strong>。
     *
     * <p>两条断言合起来才证明"判定与 kind 无关"——单看一条无法排除"恰好 WRITE 也被校验了"。
     */
    @Test
    @DisplayName("S-03b 反向断言：kind 改为 EXECUTE 后拒绝结果不变（判定不依赖 kind）")
    void changingKindDoesNotChangeOutcome() {
      AgentCapability asWrite =
          GuardSupport.DeclaredStub.of(
              "kind_probe_write",
              CapabilityKind.WRITE,
              RiskLevel.SAFE,
              Set.of("999"),
              TargetBindingProbe.Declaration.REQUIRED);
      AgentCapability asExecute =
          GuardSupport.DeclaredStub.of(
              "kind_probe_execute",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of("999"),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(asWrite, asExecute), TARGETS);

      CapabilityDeniedException writeError =
          assertDeniedAt(
              CapabilityDeniedException.Layer.AUTHORIZATION,
              "TARGET_NOT_FOUND",
              () -> fixture.gate().invoke("kind_probe_write", Map.of(), approved()));
      CapabilityDeniedException executeError =
          assertDeniedAt(
              CapabilityDeniedException.Layer.AUTHORIZATION,
              "TARGET_NOT_FOUND",
              () -> fixture.gate().invoke("kind_probe_execute", Map.of(), approved()));

      org.junit.jupiter.api.Assertions.assertEquals(
          writeError.reasonCode(),
          executeError.reasonCode(),
          "kind 不同但拒绝原因必须相同，否则判定依赖了 kind");
    }

    /**
     * READ + SAFE 的空集但<strong>未声明</strong> NONE → 仍必须拒绝。
     *
     * <p>这是最隐蔽的一档：只读且 SAFE 的能力"看起来"确实不触及目标，但"看起来"不是声明。若护栏用 {@code kind==READ &&
     * risk==SAFE} 来推断"空集合法"，那么一个被误判为 READ/SAFE 的扫描能力就能溜过 L-A（§10 失败模式表）。
     */
    @Test
    @DisplayName("S-03c READ+SAFE 但未显式声明 NONE 的空集 → 仍必须拒绝")
    void readSafeWithoutDeclarationIsStillDenied() {
      AgentCapability readSafeUndeclared =
          new GuardSupport.StubCapability(
              "looks_harmless", CapabilityKind.READ, RiskLevel.SAFE, false, Set.of(), Map.of(), null, null);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(readSafeUndeclared), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "MISSING_TARGET_BINDING",
          () -> fixture.gate().invoke("looks_harmless", Map.of(), approved()));
    }
  }

  // ==================================================================
  // S-04 漏声明（已知无法在运行期自动防住）
  // ==================================================================

  @Nested
  @DisplayName("S-04 漏声明：运行期兜底是否真的生效")
  class MissingDeclaration {

    /**
     * 漏声明（不实现声明接口、无反射访问器）+ 空集 → 护栏必须拒绝。
     *
     * <p>这是"无条件兜底"的直接验证。若放行，则 §4.1.1 的修订只完成了一半：三态有了，但"未声明"仍等于"不触及"。
     */
    @Test
    @DisplayName("S-04a 漏声明 + 空集 → 必须拒绝 MISSING_TARGET_BINDING")
    void undeclaredEmptySetIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(undeclaredEmpty("forgot_declaration")), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "MISSING_TARGET_BINDING",
          () -> fixture.gate().invoke("forgot_declaration", Map.of(), approved()));
    }

    /**
     * <strong>兜底必须与 schemaMode 无关</strong>：在默认 WARN 模式下，兜底仍须生效。
     *
     * <p>这是实现者声明的"独立于 schema 模式的无条件兜底"。若兜底挂在 schema 校验里，WARN 模式下就会静默放行。
     */
    @Test
    @DisplayName("S-04b 兜底在 schemaMode=WARN（默认）下仍必须生效")
    void fallbackWorksEvenInWarnMode() {
      AgentCapability undeclared = undeclaredEmpty("forgot_declaration_warn");
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(
              List.of(undeclared),
              TARGETS,
              com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
              "",
              "",
              CapabilityGate.SchemaMode.WARN,
              true);
      org.junit.jupiter.api.Assertions.assertEquals(
          CapabilityGate.SchemaMode.WARN, fixture.gate().schemaMode(), "前置条件：本用例必须是 WARN 模式");

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "MISSING_TARGET_BINDING",
          () -> fixture.gate().invoke("forgot_declaration_warn", Map.of(), approved()));
    }

    /**
     * 漏声明<strong>且带真实绑定</strong> → 正常走逐个校验（声明缺失不影响"有绑定"的情形）。
     *
     * <p>对照组：证明上面的拒绝是"针对空集"，而不是"针对未声明能力一律拒绝"。
     */
    @Test
    @DisplayName("S-04c 对照组：漏声明但返回真实有效绑定 → 应放行")
    void undeclaredButWithRealBindingIsAllowed() {
      AgentCapability undeclaredWithBinding =
          new GuardSupport.StubCapability(
              "undeclared_but_bound",
              CapabilityKind.WRITE,
              RiskLevel.SAFE,
              false,
              Set.of("1"),
              Map.of(),
              null,
              null);
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(undeclaredWithBinding), TARGETS);
      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("undeclared_but_bound", Map.of(), approved()));
    }

    /**
     * <strong>注册期规则 R-1 的可执行形式</strong>：扫描/执行类语义的能力，不得在"参数缺 targetId"时返回空集。
     *
     * <p>这条不是护栏的运行期行为，而是对<strong>能力声明本身</strong>的静态检查——因为运行期无法区分"真的不触及"与"忘了写"。
     * 本用例把它表达为对一批"看起来像扫描能力"的桩的断言，供注册期交叉校验复用。
     */
    @Test
    @DisplayName("S-04d 注册期规则 R-1：EXECUTE 类能力返回空集时必须显式声明 NONE 才合法")
    void registrationRuleRejectsExecuteCapabilityWithEmptyBinding() {
      for (String code :
          new String[] {"nuclei_scan", "sqlmap_scan", "port_scan", "start_probe", "run_workflow"}) {
        AgentCapability offender =
            new GuardSupport.StubCapability(
                code, CapabilityKind.EXECUTE, RiskLevel.SENSITIVE, false, Set.of(), Map.of(), null, null);
        GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(offender), TARGETS);
        assertDeniedAt(
            CapabilityDeniedException.Layer.AUTHORIZATION,
            "MISSING_TARGET_BINDING",
            () -> fixture.gate().invoke(code, Map.of(), approved()));
      }
    }
  }

  // ==================================================================
  // S-05 fail-closed 全链路（三种"不确定"）
  // ==================================================================

  @Nested
  @DisplayName("S-05 三种『不确定』必须全部拒绝，且拒因可区分")
  class FailClosedFullChain {

    /** ① 未分级能力（kind/risk 为空）→ L-B 拒绝。 */
    @Test
    @DisplayName("S-05a 未分级能力（kind=null）→ L-B 拒绝 UNCLASSIFIED_CAPABILITY")
    void unclassifiedCapabilityIsDenied() {
      AgentCapability unclassified =
          new GuardSupport.StubCapability(
              "unclassified", null, null, false, Set.of("1"), Map.of(), null, null);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(unclassified), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.ADMISSION,
          "UNCLASSIFIED_CAPABILITY",
          () -> fixture.gate().invoke("unclassified", Map.of(), approved()));
    }

    /** ② 未注册端点/能力 → L-D 拒绝。 */
    @Test
    @DisplayName("S-05b 未注册能力 → L-D 拒绝 UNKNOWN_CAPABILITY")
    void unregisteredCapabilityIsDenied() {
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.ENTRYPOINT,
          "UNKNOWN_CAPABILITY",
          () -> fixture.gate().invoke("no_such_capability", Map.of(), approved()));
    }

    /** ③ 哨兵未解析 → L-A 拒绝。 */
    @Test
    @DisplayName("S-05c 哨兵未解析 → L-A 拒绝 TARGET_BINDING_UNRESOLVED")
    void unresolvedSentinelIsDenied() {
      AgentCapability sentinel =
          GuardSupport.DeclaredStub.of(
              "unresolved",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(sentinel), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_BINDING_UNRESOLVED",
          () -> fixture.gate().invoke("unresolved", Map.of(), approved()));
    }

    /**
     * <strong>拒因必须可区分</strong>：三种"不确定"的原因码两两不同。
     *
     * <p>若三者都退化成同一个原因码（或都抛 NPE 被上层吞掉），审计就无法归因，论文 §9.5 的"越界拦截率"也就无从统计。
     */
    @Test
    @DisplayName("S-05d 三种不确定的拒绝原因码两两不同（可归因）")
    void threeUncertaintyReasonsAreDistinguishable() {
      AgentCapability unclassified =
          new GuardSupport.StubCapability("u1", null, null, false, Set.of("1"), Map.of(), null, null);
      AgentCapability sentinel =
          GuardSupport.DeclaredStub.of(
              "u2",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(unclassified, sentinel), TARGETS);

      String a =
          assertDeniedAt(
                  CapabilityDeniedException.Layer.ADMISSION,
                  "UNCLASSIFIED_CAPABILITY",
                  () -> fixture.gate().invoke("u1", Map.of(), approved()))
              .reasonCode();
      String b =
          assertDeniedAt(
                  CapabilityDeniedException.Layer.ENTRYPOINT,
                  "UNKNOWN_CAPABILITY",
                  () -> fixture.gate().invoke("u3", Map.of(), approved()))
              .reasonCode();
      String c =
          assertDeniedAt(
                  CapabilityDeniedException.Layer.AUTHORIZATION,
                  "TARGET_BINDING_UNRESOLVED",
                  () -> fixture.gate().invoke("u2", Map.of(), approved()))
              .reasonCode();

      org.junit.jupiter.api.Assertions.assertEquals(
          3, Set.of(a, b, c).size(), "三种不确定必须产生三个不同的原因码，实际: " + Set.of(a, b, c));
    }

    /**
     * <strong>拒绝必须留痕</strong>：被拒绝的调用也要写审计（设计 §6.1 末段"审计入账（全量）"）。
     *
     * <p>若拒绝路径不写审计，攻击者可以反复试探而不留痕——"被拒绝的越权尝试"恰恰是最有价值的审计信号。
     */
    @Test
    @DisplayName("S-05e 拒绝必须写审计（deniedReason 可查）")
    void denialsAreAudited() {
      AgentCapability sentinel =
          GuardSupport.DeclaredStub.of(
              "audited_sentinel",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(sentinel), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_BINDING_UNRESOLVED",
          () -> fixture.gate().invoke("audited_sentinel", Map.of(), approved()));

      org.junit.jupiter.api.Assertions.assertTrue(
          fixture.audit().hasDenial("TARGET_BINDING_UNRESOLVED"),
          "拒绝必须写入审计，实际记录: " + fixture.audit().entries);
    }
  }

  // ==================================================================
  // 目标解析与端口
  // ==================================================================

  @Nested
  @DisplayName("目标绑定解析与端口校验")
  class BindingResolution {

    /** 绑定真实且有效 → 放行（对照组，证明前面的拒绝不是"一律拒绝"）。 */
    @Test
    @DisplayName("真实有效绑定 → 放行")
    void validBindingIsAllowed() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("ok_scan", Set.of("1"))), TARGETS);
      GuardSupport.assertAllowed(() -> fixture.gate().invoke("ok_scan", Map.of(), approved()));
    }

    /** 绑定非数字字符串 → 必须拒绝（不能猜、不能静默忽略）。 */
    @Test
    @DisplayName("绑定非数字（\"T1\"）→ 必须拒绝 INVALID_TARGET_BINDING")
    void nonNumericBindingIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("bad_binding", Set.of("T1"))), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "INVALID_TARGET_BINDING",
          () -> fixture.gate().invoke("bad_binding", Map.of(), approved()));
    }

    /** 绑定空白字符串 → 必须拒绝。 */
    @Test
    @DisplayName("绑定空白字符串 → 必须拒绝")
    void blankBindingIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("blank_binding", Set.of("   "))), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "INVALID_TARGET_BINDING",
          () -> fixture.gate().invoke("blank_binding", Map.of(), approved()));
    }

    /** 已停用目标 → L-A 拒绝（G-03 家族）。 */
    @Test
    @DisplayName("已停用目标 → 拒绝 TARGET_DISABLED")
    void disabledTargetIsDenied() {
      Map<Long, AuthorizedTarget> targets =
          Map.of(1L, GuardSupport.disabledTarget(1L, "192.168.10.10", "80"));
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("scan_disabled", Set.of("1"))), targets);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_DISABLED",
          () -> fixture.gate().invoke("scan_disabled", Map.of(), approved()));
    }

    /** 授权已过期 → L-A 拒绝（G-03）。 */
    @Test
    @DisplayName("授权已过期目标 → 拒绝 AUTHORIZATION_EXPIRED")
    void expiredTargetIsDenied() {
      Map<Long, AuthorizedTarget> targets =
          Map.of(1L, GuardSupport.expiredTarget(1L, "192.168.10.10", "80"));
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("scan_expired", Set.of("1"))), targets);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "AUTHORIZATION_EXPIRED",
          () -> fixture.gate().invoke("scan_expired", Map.of(), approved()));
    }

    /** 公网目标（默认策略下）→ L-A 拒绝。 */
    @Test
    @DisplayName("公网目标（默认 allow-public-targets=false）→ 拒绝 TARGET_OUT_OF_SCOPE")
    void publicTargetIsDenied() {
      Map<Long, AuthorizedTarget> targets = Map.of(1L, target(1L, "8.8.8.8", "80"));
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("scan_public", Set.of("1"))), targets);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_OUT_OF_SCOPE",
          () -> fixture.gate().invoke("scan_public", Map.of(), approved()));
    }

    /** 请求端口超出授权端口 → L-A 拒绝（G-02）。 */
    @Test
    @DisplayName("请求端口超出授权范围 → 拒绝 PORT_OUT_OF_SCOPE")
    void portOutOfScopeIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("scan_ports", Set.of("1"))), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_OUT_OF_SCOPE",
          () -> fixture.gate().invoke("scan_ports", params("ports", "80,22"), approved()));
    }

    /**
     * <strong>区间部分越权</strong>（授权 80,443、请求 80-443）：必须拒绝。
     *
     * <p>这是"只取区间两端点"实现的经典漏检：80 与 443 都在授权集内，但中间的端口不在。护栏的
     * {@code requestedPorts} 声称会完整展开——本用例验证。
     */
    @Test
    @DisplayName("端口区间部分越权（授权 80,443、请求 80-443）→ 必须拒绝")
    void partiallyOutOfScopePortRangeIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("scan_range", Set.of("1"))), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_OUT_OF_SCOPE",
          () -> fixture.gate().invoke("scan_range", params("ports", "80-443"), approved()));
    }

    /** 对照组：区间完全落在授权范围内（授权 80,443、请求 80,80-80）→ 放行。 */
    @Test
    @DisplayName("对照组：区间完全在授权范围内 → 放行")
    void inScopePortRangeIsAllowed() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("scan_range_ok", Set.of("1"))), TARGETS);
      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("scan_range_ok", params("ports", "80,80-80"), approved()));
    }

    /** 极大区间（1-65535）→ 必须拒绝（要么端口越权，要么区间过大 fail-closed）。 */
    @Test
    @DisplayName("极大区间 1-65535 → 必须拒绝")
    void hugePortRangeIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("scan_huge", Set.of("1"))), TARGETS);

      CapabilityDeniedException error =
          org.junit.jupiter.api.Assertions.assertThrows(
              CapabilityDeniedException.class,
              () -> fixture.gate().invoke("scan_huge", params("ports", "1-65535"), approved()));
      org.junit.jupiter.api.Assertions.assertEquals(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          error.layer(),
          "极大区间必须在 L-A 被拦，实际层 " + error.layer().label() + " 原因 " + error.reasonCode());
    }
  }
}
