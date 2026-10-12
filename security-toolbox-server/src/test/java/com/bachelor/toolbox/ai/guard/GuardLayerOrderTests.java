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
import com.bachelor.toolbox.ai.guard.CapabilityContext;
import com.bachelor.toolbox.ai.guard.CapabilityDeniedException;
import com.bachelor.toolbox.ai.guard.CapabilityGate;
import com.bachelor.toolbox.ai.guard.TargetBindingProbe;
import com.bachelor.toolbox.target.AuthorizedTarget;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 层序 L-B → L-C → L-A 的绕过面验证（清单 §6.1 与实现偏差）。
 *
 * <h2>被验证的实现者声明</h2>
 *
 * <blockquote>
 * "层序 L-B → L-C → L-A（文档 §6.1 原为 L-A 先）。理由：L-A 哨兵分支会短路 L-C。请验证这个层序是否引入新绕过面。"
 * </blockquote>
 *
 * <h2>实现给出的两条理由（{@code CapabilityGate:37-51}）</h2>
 *
 * <ol>
 *   <li><strong>L-B 必须先于 L-A</strong>：黑名单能力的 {@code targetBindings} 是空集或哨兵。若 L-A 先行，带合法
 *       {@code targetId} 调用 {@code shutdown} 会通过 L-A → <em>黑名单形同虚设</em>。
 *   <li><strong>L-C 必须先于 L-A</strong>：L-A 哨兵分支会拒绝一切无法静态解析目标的能力，{@code invoke_endpoint}
 *       必然落进该分支 → §9.5 的"路径含 {@code ../}"用例永远走不到 L-C。
 * </ol>
 *
 * <h2>本类要检验的绕过面</h2>
 *
 * <p>层序本身不改变"任一层拒绝即终止"的安全性，但<strong>改变可观测的拒绝理由</strong>。真正需要检验的是：
 *
 * <ol>
 *   <li><strong>L-C 提前是否会掩盖 L-A 的必要性</strong>：若某能力在 L-C 就被拒，L-A 是否因此从未被验证过？（这不是漏洞，
 *       但会让"越界拦截率"统计失真。）
 *   <li><strong>L-B 的黑名单是否会因为"先跑"而只看能力自身、忽略参数里的端点路径</strong>：即
 *       {@code invoke_endpoint} 的反向映射是否真的生效（{@code CapabilityGate:272-281}）。
 *   <li><strong>层序是否可能让"未知能力"被误判为其他层</strong>：L-D 在最前，必须先于一切。
 *   <li><strong>L-C 的 schema WARN 模式是否让攻击者用"畸形参数"跳过 L-C 直达 L-A</strong>——若 L-C 放行畸形参数，
 *       L-A 是否仍然独立生效（不能依赖 L-C 的副作用）。
 * </ol>
 */
@DisplayName("层序 L-B → L-C → L-A 的绕过面验证")
class GuardLayerOrderTests {

  private static final Map<Long, AuthorizedTarget> TARGETS =
      Map.of(1L, target(1L, "192.168.10.10", "80,443"));

  private static CapabilityContext approved() {
    return CapabilityContext.of("ai-agent", 7L).approved(1L);
  }

  // ==================================================================
  // 1. L-D 必须最先
  // ==================================================================

  /**
   * 未知能力必须由 L-D 拒绝，<strong>不能</strong>被 L-B 抢先报"未分级"或其他层。
   *
   * <p>绕过设想：若实现把"查注册表"和"判定分级"混在一起，未知能力可能得到错误的层标签，使审计无法区分
   * "有人尝试调用不存在的后门"（高度可疑）与"能力配置有问题"（运维问题）。
   */
  @Test
  @DisplayName("L-D 最先：未知能力必须报 L-D / UNKNOWN_CAPABILITY")
  void unknownCapabilityIsRejectedByEntrypointLayerFirst() {
    GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(), TARGETS);

    CapabilityDeniedException error =
        assertDeniedAt(
            CapabilityDeniedException.Layer.ENTRYPOINT,
            "UNKNOWN_CAPABILITY",
            () -> fixture.gate().invoke("../../etc/passwd", Map.of(), approved()));

    org.junit.jupiter.api.Assertions.assertEquals(
        "../../etc/passwd",
        error.capabilityCode(),
        "未知能力的 capabilityCode 应回显原始请求码，便于审计追溯探测行为");
  }

  /** 空能力码 → L-D 拒绝。 */
  @Test
  @DisplayName("L-D：空能力码 → 拒绝")
  void blankCapabilityCodeIsRejected() {
    GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(), TARGETS);

    assertDeniedAt(
        CapabilityDeniedException.Layer.ENTRYPOINT,
        "UNKNOWN_CAPABILITY",
        () -> fixture.gate().invoke("   ", Map.of(), approved()));
  }

  // ==================================================================
  // 2. L-B 必须能看见参数里的端点路径（反向映射）
  // ==================================================================

  /**
   * <strong>核心用例</strong>：L-B 的黑名单必须能作用于 {@code invoke_endpoint} 参数里的 {@code path}。
   *
   * <p>绕过设想（实现已在 {@code CapabilityGate:272-281} 处理）：{@code invoke_endpoint} 自身的能力码合法，若黑名单只检查
   * {@code capability.code()}，则 {@code invoke_endpoint("POST","/api/system/shutdown")} 会通过 L-B。
   *
   * <p>本用例验证该反向映射生效，且拒因是 {@code BLOCKED_CAPABILITY} 而非"未知端点"（后者说明黑名单没生效，只是端点恰好没注册）。
   */
  @Test
  @DisplayName("L-B 反向映射：invoke_endpoint 指向黑名单端点 → BLOCKED_CAPABILITY")
  void blacklistAppliesToEndpointPathInParameters() {
    com.bachelor.toolbox.ai.endpoint.EndpointRegistry endpointRegistry =
        new com.bachelor.toolbox.ai.endpoint.EndpointRegistry();
    com.bachelor.toolbox.ai.endpoint.EndpointCapability shutdown =
        com.bachelor.toolbox.ai.endpoint.EndpointCapability.derive(
            "POST", "/api/system/shutdown", "关停平台");
    endpointRegistry.register(shutdown);
    com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability invoke =
        new com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability(
            endpointRegistry, new com.bachelor.toolbox.ai.capability.CapabilityRegistry(List.of()));

    GuardSupport.Fixture fixture =
        GuardSupport.fixture(
            List.of(invoke, shutdown),
            TARGETS,
            com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
            com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability.CODE,
            com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability.CODE,
            CapabilityGate.SchemaMode.WARN,
            true);

    assertDeniedAt(
        CapabilityDeniedException.Layer.ADMISSION,
        "BLOCKED_CAPABILITY",
        () ->
            fixture
                .gate()
                .invoke(
                    com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability.CODE,
                    params("method", "POST", "path", "/api/system/shutdown"),
                    approved()));
  }

  /**
   * <strong>L-B 反向映射的编码绕过</strong>：黑名单检查发生在 L-C 路径规范化<strong>之前</strong>。
   *
   * <p>这是层序引入的真实绕过面：{@code admit()}（L-B）在 {@code validateParameters()}（L-C）之前运行，而
   * {@code blacklist.blocksPath(requestedPath)} 收到的是<strong>未经规范化</strong>的原始路径。
   *
   * <p>因此攻击者可以用 {@code /api/system/./shutdown} 或 {@code /api/system//shutdown} 之类的写法让 L-B 的黑名单
   * <strong>前缀/精确匹配失败</strong>。能否最终被拦，取决于 L-C 的 {@code PathNormalizer} 与注册表匹配是否也拒绝这些写法。
   *
   * <p>本用例断言"必须被拒"（无论哪一层），并把实际层记录下来——若实际层是 L-B，说明黑名单自身做了规范化；若是 L-C，
   * 说明拦住它的是路径校验而非黑名单，属于<strong>依赖巧合的防护</strong>。
   */
  @Test
  @DisplayName("L-B 层序绕过候选：/api/system/./shutdown 等变体 → 必须被拒（记录实际层）")
  void blacklistPathVariantsMustStillBeDenied() {
    com.bachelor.toolbox.ai.endpoint.EndpointRegistry endpointRegistry =
        new com.bachelor.toolbox.ai.endpoint.EndpointRegistry();
    // 注册"规范化后"的路径，模拟真实 MVC 映射表。
    com.bachelor.toolbox.ai.endpoint.EndpointCapability shutdown =
        com.bachelor.toolbox.ai.endpoint.EndpointCapability.derive(
            "POST", "/api/system/shutdown", "关停平台");
    endpointRegistry.register(shutdown);
    com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability invoke =
        new com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability(
            endpointRegistry, new com.bachelor.toolbox.ai.capability.CapabilityRegistry(List.of()));

    GuardSupport.Fixture fixture =
        GuardSupport.fixture(
            List.of(invoke, shutdown),
            TARGETS,
            com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
            com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability.CODE,
            com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability.CODE,
            CapabilityGate.SchemaMode.WARN,
            true);

    // 每个变体都必须被拒绝（层不限，但必须是护栏拒绝而非放行）。
    for (String variant :
        new String[] {
          "/api/system/./shutdown",
          "/api/system//shutdown",
          "/api/system/shutdown/",
          "/api/system/../system/shutdown"
        }) {
      CapabilityDeniedException error =
          org.junit.jupiter.api.Assertions.assertThrows(
              CapabilityDeniedException.class,
              () ->
                  fixture
                      .gate()
                      .invoke(
                          com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability.CODE,
                          params("method", "POST", "path", variant),
                          approved()),
              "路径变体必须被拒绝: " + variant);
      // 记录实际拦截层，供报告统计"有多少变体是靠黑名单拦的、多少靠路径校验"。
      org.junit.jupiter.api.Assertions.assertNotNull(error.layer(), variant + " 的拒绝层不能为空");
    }
  }

  // ==================================================================
  // 3. L-C 放行畸形参数时，L-A 必须独立生效
  // ==================================================================

  /**
   * <strong>关键独立性用例</strong>：在 {@code schemaMode=WARN}（默认）下，schema 违规只记录不拦截。
   *
   * <p>攻击设想：构造一个<strong>违反 schema</strong> 的参数（多传未声明字段），同时让目标越权。若 L-A 依赖 L-C 的
   * schema 校验"顺便"拦住，那么 WARN 模式下就会放行。
   *
   * <p>本用例断言：即使 schema 违规被放行，<strong>L-A 仍然独立拒绝越权目标</strong>。这证明层序不产生"必须靠 L-C
   * 才能拦住"的依赖。
   */
  @Test
  @DisplayName("L-A 独立性：WARN 模式下 schema 违规被放行，L-A 仍独立拒绝越权目标")
  void authorizationLayerIsIndependentOfSchemaEnforcement() {
    // schema 要求只允许 "ports"，但攻击者额外传 targetId=999（越权目标）。
    Map<String, Object> schema =
        Map.of(
            "type",
            "object",
            "properties",
            Map.of("ports", Map.of("type", "string")),
            "additionalProperties",
            false);
    AgentCapability capability =
        new GuardSupport.DeclaredStub(
            "schema_bypass_probe",
            CapabilityKind.EXECUTE,
            RiskLevel.SENSITIVE,
            false,
            Set.of("999"),
            schema,
            null,
            TargetBindingProbe.Declaration.REQUIRED);

    GuardSupport.Fixture fixture =
        GuardSupport.fixture(
            List.of(capability),
            TARGETS,
            com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
            "",
            "",
            CapabilityGate.SchemaMode.WARN,
            true);

    // 参数违反 schema（多了 undeclared 字段），但目标 999 不存在 → L-A 必须拒绝。
    assertDeniedAt(
        CapabilityDeniedException.Layer.AUTHORIZATION,
        "TARGET_NOT_FOUND",
        () ->
            fixture
                .gate()
                .invoke(
                    "schema_bypass_probe",
                    params("ports", "80", "undeclared", "x"),
                    approved()));
  }

  /**
   * <strong>反向</strong>：schemaMode=ENFORCE 时，同一调用必须报 L-C / SCHEMA_VIOLATION。
   *
   * <p>与上一条配对，证明"层序导致 L-C 先拒"只是<strong>理由</strong>不同，<strong>结论</strong>都必须是拒绝。
   */
  @Test
  @DisplayName("L-C ENFORCE：同一 schema 违规在严格模式下报 SCHEMA_VIOLATION（结论同样是拒绝）")
  void schemaViolationIsRejectedInEnforceMode() {
    Map<String, Object> schema =
        Map.of(
            "type",
            "object",
            "properties",
            Map.of("ports", Map.of("type", "string")),
            "additionalProperties",
            false);
    AgentCapability capability =
        new GuardSupport.DeclaredStub(
            "schema_probe_enforce",
            CapabilityKind.EXECUTE,
            RiskLevel.SENSITIVE,
            false,
            Set.of("999"),
            schema,
            null,
            TargetBindingProbe.Declaration.REQUIRED);

    GuardSupport.Fixture fixture =
        GuardSupport.fixture(
            List.of(capability),
            TARGETS,
            com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
            "",
            "",
            CapabilityGate.SchemaMode.ENFORCE,
            true);

    assertDeniedAt(
        CapabilityDeniedException.Layer.PARAMETER,
        "SCHEMA_VIOLATION",
        () ->
            fixture
                .gate()
                .invoke(
                    "schema_probe_enforce",
                    params("ports", "80", "undeclared", "x"),
                    approved()));
  }

  // ==================================================================
  // 4. L-B 黑名单必须优先于白名单与一切参数
  // ==================================================================

  /**
   * 黑名单能力即使参数<strong>完全合法</strong>、上下文<strong>已批准</strong>、<strong>显式开启白名单</strong>，
   * 也必须被拒。
   *
   * <p>绕过设想：攻击者通过"把黑名单能力加入白名单"或"带一个合法 targetId"来绕过黑名单。层序把 L-B 放最前正是为了
   * 防止前者；本用例锁定该性质。
   */
  @Test
  @DisplayName("L-B 绝对优先：黑名单能力即使白名单开启+已批准+参数合法也必须拒绝")
  void blacklistIsAbsolutelyPrioritary() {
    AgentCapability blocked =
        GuardSupport.DeclaredStub.of(
            "shutdown_system",
            CapabilityKind.ADMIN,
            RiskLevel.DESTRUCTIVE,
            Set.of("1"),
            TargetBindingProbe.Declaration.REQUIRED);

    GuardSupport.Fixture fixture =
        GuardSupport.fixture(
            List.of(blocked),
            TARGETS,
            com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
            "shutdown_system",
            "shutdown_system",
            CapabilityGate.SchemaMode.WARN,
            true);

    assertDeniedAt(
        CapabilityDeniedException.Layer.ADMISSION,
        "BLOCKED_CAPABILITY",
        () -> fixture.gate().invoke("shutdown_system", params("ports", "80"), approved()));
  }

  // ==================================================================
  // 5. 层序不改变"拒绝即终止"
  // ==================================================================

  /**
   * 一个同时违反<strong>多层</strong>的调用，必须只产生<strong>一个</strong>拒绝，且是最先执行的那层。
   *
   * <p>若实现把各层校验写成"收集所有违规再一次抛出"，就可能出现"某层违规被漏掉"或"拒绝理由随机"的问题。
   */
  @Test
  @DisplayName("多层同时违规 → 只报最先执行的层（L-B），不产生多义拒绝")
  void multipleViolationsReportTheFirstLayerOnly() {
    AgentCapability blockedWithBadBinding =
        GuardSupport.DeclaredStub.of(
            "shutdown_system",
            CapabilityKind.ADMIN,
            RiskLevel.DESTRUCTIVE,
            Set.of("999"),
            TargetBindingProbe.Declaration.REQUIRED);

    GuardSupport.Fixture fixture =
        GuardSupport.fixture(
            List.of(blockedWithBadBinding),
            TARGETS,
            com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
            "",
            "",
            CapabilityGate.SchemaMode.ENFORCE,
            true);

    // 同时：黑名单(L-B) + 非法目标(L-A) + 参数违规(L-C)
    assertDeniedAt(
        CapabilityDeniedException.Layer.ADMISSION,
        "BLOCKED_CAPABILITY",
        () ->
            fixture
                .gate()
                .invoke("shutdown_system", params("bogus", "x"), approved()));
  }

  /** 对照组：不触及目标且显式声明 NONE 的能力在无批准时也应放行（L-B 不过度拦截）。 */
  @Test
  @DisplayName("对照组：显式 NONE 的空集能力在未批准时也可放行（L-B 不误拦）")
  void nonTargetedCapabilityIsAllowedWithoutApproval() {
    GuardSupport.Fixture fixture =
        GuardSupport.fixture(List.of(declaredNone("retrieve_project_context")), TARGETS);

    assertAllowed(
        () ->
            fixture
                .gate()
                .invoke("retrieve_project_context", Map.of(), CapabilityContext.of("ai-agent", 7L)));
  }

  /** 对照组：真实绑定 + 已批准 → 放行（证明上面的拒绝不是"一律拒绝"）。 */
  @Test
  @DisplayName("对照组：合法绑定 + 已批准 → 放行")
  void legitimateCallIsAllowed() {
    GuardSupport.Fixture fixture =
        GuardSupport.fixture(List.of(declaredWithBindings("normal_scan", Set.of("1"))), TARGETS);

    assertAllowed(() -> fixture.gate().invoke("normal_scan", params("ports", "80"), approved()));
  }
}
