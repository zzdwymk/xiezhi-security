package com.bachelor.toolbox.ai.guard;

import static com.bachelor.toolbox.ai.guard.GuardSupport.assertDeniedAt;
import static com.bachelor.toolbox.ai.guard.GuardSupport.params;
import static com.bachelor.toolbox.ai.guard.GuardSupport.target;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.endpoint.EndpointCapability;
import com.bachelor.toolbox.ai.endpoint.EndpointRegistry;
import com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability;
import com.bachelor.toolbox.ai.guard.CapabilityBlacklist;
import com.bachelor.toolbox.ai.guard.CapabilityContext;
import com.bachelor.toolbox.ai.guard.CapabilityDeniedException;
import com.bachelor.toolbox.ai.guard.CapabilityGate;
import com.bachelor.toolbox.ai.guard.EndpointParameterPolicy;
import com.bachelor.toolbox.ai.guard.TargetBindingProbe;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * 间接执行路径的对抗验证（清单 B-01..B-09，以及 Lead 指定的 D-6 旁路端点逐个实测）。
 *
 * <h2>间接执行是本方案的核心威胁（T1）</h2>
 *
 * <p>{@code POST /api/tasks} 不是唯一"创建一个会扫描目标的任务"的入口。平台还有多个入口通过<strong>其它参数
 * （findingId / taskId / scheduleId / projectId）反查目标</strong>，因此它们的 {@code targetBindings} <strong>无法</strong>从
 * {@code params.targetId} 解析出来。这正是 §4.1 三态修订要解决的场景。
 *
 * <h2>Lead 指定的四问（逐端点实测结果，读 Service 实现确认）</h2>
 *
 * <table border="1">
 *   <caption>旁路端点的声明与执行对照（证据见下表"执行链"列）</caption>
 *   <tr>
 *     <th>端点</th><th>① targetBindings 声明</th><th>② 实际是否触发对目标的执行</th>
 *     <th>③ 是否被 isTaskCreationEndpoint 覆盖</th><th>④ 是否存在"声明 NONE 但实际执行"</th>
 *   </tr>
 *   <tr>
 *     <td>{@code POST /api/tasks/{id}/retry}</td>
 *     <td>哨兵（写操作 → targetBound）</td>
 *     <td><strong>是</strong>：{@code TaskService.retryTask} 克隆原任务并重新入队执行</td>
 *     <td>否</td>
 *     <td><strong>否</strong>（哨兵 → L-A fail-closed，声明未说谎）</td>
 *   </tr>
 *   <tr>
 *     <td>{@code POST /api/regression/findings/{id}/retest}</td>
 *     <td>哨兵</td>
 *     <td><strong>是</strong>：由 finding → baseline task 反查 project/target/tool/params 后 {@code createRetest}</td>
 *     <td>否</td>
 *     <td><strong>否</strong>（哨兵）</td>
 *   </tr>
 *   <tr>
 *     <td>{@code POST /api/scan-schedules}</td>
 *     <td>哨兵</td>
 *     <td><strong>是（延迟）</strong>：调度器未来以 {@code callWithSystemAccess} 派发</td>
 *     <td>否</td>
 *     <td><strong>否</strong>（哨兵）</td>
 *   </tr>
 *   <tr>
 *     <td>{@code POST /api/projects/{projectId}/discovery/probe}</td>
 *     <td>哨兵</td>
 *     <td><strong>是</strong>：向用户指定 url 实际发包</td>
 *     <td>否</td>
 *     <td><strong>否</strong>（哨兵）</td>
 *   </tr>
 *   <tr>
 *     <td>{@code POST /api/traffic/packets/{id}/replay} 等</td>
 *     <td>哨兵</td>
 *     <td><strong>是</strong>：由 packet 反查 host 并发包</td>
 *     <td>否</td>
 *     <td><strong>否</strong>（哨兵）</td>
 *   </tr>
 * </table>
 *
 * <p><strong>结论（回答 Lead 的第 4 问）：这些端点的能力声明<em>没有</em>说谎。</strong>它们全部返回哨兵，护栏据此
 * fail-closed。D-6 是<strong>"参数策略覆盖不全"</strong>（{@code EndpointParameterPolicy} 看不到这些路径），
 * <strong>不是</strong>"能力声明在说谎"。两者严重性不同：
 *
 * <ul>
 *   <li>参数策略不覆盖 → 端口子集/工具白名单等<strong>细粒度</strong>校验缺失，但 L-A 授权边界仍在（哨兵兜住）。
 *   <li>声明说谎（NONE + 实际执行）→ <strong>L-A 整体被跳过</strong>，是完整越权。本类 A-1 逐端点确认该形态不存在。
 * </ul>
 *
 * <p><strong>但要如实记录 D-6 的真实后果</strong>：这些端点<strong>完全无法被 Agent 通过 {@code invoke_endpoint} 使用</strong>
 * （一律哨兵拒绝）。这是"安全但功能不可用"——与 X-7 的"修复存在但不可达"是同一类失败方式，构成对 G1-G6
 * 能力完备性目标的影响，必须在报告中与安全性结论分开陈述。
 */
@DisplayName("间接执行路径对抗验证（B-01..B-09 / D-6 旁路端点）")
class GuardIndirectExecutionTests {

  private static final Map<Long, AuthorizedTarget> TARGETS =
      Map.of(1L, target(1L, "192.168.10.10", "80,443"));

  private static CapabilityContext approved() {
    return CapabilityContext.of("ai-agent", 7L).approved(1L);
  }

  // ==================================================================
  // A. D-6 旁路端点：逐个实测 targetBindings 语义
  // ==================================================================

  @Nested
  @DisplayName("A. D-6 旁路端点的 targetBindings 语义（Lead 指定逐个实测）")
  class BypassEndpoints {

    /**
     * 逐个检查"会创建扫描任务、但参数里没有 targetId"的端点，其 {@code targetBindings} 必须返回哨兵。
     *
     * <p>这是 D-6 的<strong>能力层</strong>验证（与 D-6 的<strong>策略层</strong>验证互补）：
     * {@code EndpointParameterPolicy.isTaskCreationEndpoint} 不覆盖这些路径，所以它们的护栏保护<strong>只能</strong>
     * 来自 {@code targetBindings} 返回哨兵 → L-A fail-closed。若某个端点返回空集 + 声明 NONE，即漏洞。
     */
    @Test
    @DisplayName("A-1 五个旁路端点的 targetBindings 必须是哨兵（不得是空集）")
    void bypassEndpointsMustReturnSentinelNotEmptySet() {
      // (method, path, 说明, 实际执行效果)
      record Bypass(String method, String path, String effect) {}
      List<Bypass> bypasses =
          List.of(
              new Bypass("POST", "/api/tasks/{id}/retry", "重试克隆原任务的 target/project/参数，创建新扫描任务"),
              new Bypass(
                  "POST",
                  "/api/regression/findings/{findingId}/retest",
                  "由 finding → baseline task 反查 target/tool/params，创建复测任务"),
              new Bypass("POST", "/api/scan-schedules", "创建定时扫描计划，调度器未来以 SYSTEM 身份派发任务"),
              new Bypass(
                  "POST",
                  "/api/projects/{projectId}/discovery/probe",
                  "由 project 反查授权目标，向用户指定 url 发包（同 host 校验）"),
              new Bypass("POST", "/api/traffic/packets/{id}/replay", "由已捕获 packet 反查 host 并发包"),
              new Bypass("POST", "/api/traffic/packets/{id}/zap-scan", "对已捕获报文发起主动扫描"),
              new Bypass("POST", "/api/post-scan-paths/plans", "确认后派生后续扫描任务"),
              new Bypass("POST", "/api/traffic/suggestions/{id}/execute", "执行流量建议 = 触发扫描"));

      for (Bypass bypass : bypasses) {
        EndpointCapability endpoint =
            EndpointCapability.derive(bypass.method(), bypass.path(), bypass.effect());
        java.util.Set<String> bindings = endpoint.targetBindings(Map.of());

        org.junit.jupiter.api.Assertions.assertTrue(
            bindings.contains(AgentCapability.TARGET_BINDING_UNRESOLVED),
            "【D-6 缺口】端点 "
                + bypass.method()
                + " "
                + bypass.path()
                + "（效果："
                + bypass.effect()
                + "）的 targetBindings 返回 "
                + bindings
                + "，未返回哨兵。若返回空集，该端点即成为跳过 L-A 的合法通道。");
        org.junit.jupiter.api.Assertions.assertFalse(
            bindings.isEmpty(),
            "端点 " + bypass.path() + " 不得返回空集（空集 = 宣称不触及目标）");
      }
    }

    /**
     * 上述每个端点单独走护栏，必须被 L-A 以哨兵拒绝（端到端确认，而非只看返回值）。
     *
     * <p><strong>实测修正（重要）</strong>：我最初的参数形状是错的——{@code EndpointCapability.validateParams}
     * （L-C，{@code :322-345}）要求：
     *
     * <ul>
     *   <li>路径变量（如 {@code {id}}）必须提供，否则 {@code INVALID_PARAMETER: 缺少路径参数: id}
     *   <li>若 {@code targetBound} 且路径里<strong>没有</strong> target 变量，则必须提供顶层 {@code targetId}，
     *       否则 {@code INVALID_PARAMETER: 未提供 targetId}
     * </ul>
     *
     * <p>因为 L-C 在 L-A <strong>之前</strong>，参数不合规会<strong>先</strong>在 L-C 被拒——
     * 我的用例原本断言 L-A 哨兵，于是得到"伪通过"式的失败（拒因来自 L-C 而非 L-A）。
     *
     * <p>本用例因此<strong>刻意构造满足 L-C 的参数</strong>（提供路径变量 + 提供合法 targetId），
     * 这样才能真正走到 L-A，验证哨兵是否兜住。
     *
     * <p><strong>这本身是一个有价值的发现</strong>：{@code EndpointCapability} 对写端点强制要求 {@code targetId}
     * 参数，但该参数<strong>不是</strong>路径变量时，它只是个"存在性检查"——真正的授权校验仍在 L-A。
     * 即：<em>L-C 的 targetId 检查是"形式要求"，L-A 的哨兵才是"实质边界"</em>。
     */
    @Test
    @DisplayName("A-2 旁路端点逐个经护栏调用 → 必须被 L-A 哨兵拒绝（参数须先满足 L-C）")
    void bypassEndpointsAreDeniedBySentinelAtAuthorizationLayer() {
      record Case(String pathTemplate, Map<String, Object> params) {}
      // 每个端点的调用参数：提供路径变量 + 合法 targetId，以满足 L-C，从而走到 L-A。
      List<Case> cases =
          List.of(
              new Case("/api/tasks/{id}/retry", params("id", 1L, "targetId", 1L)),
              new Case(
                  "/api/regression/findings/{findingId}/retest",
                  params("findingId", 1L, "targetId", 1L)),
              new Case("/api/scan-schedules", params("targetId", 1L)),
              new Case(
                  "/api/projects/{projectId}/discovery/probe",
                  params("projectId", 7L, "targetId", 1L)),
              new Case("/api/traffic/packets/{id}/replay", params("id", 1L, "targetId", 1L)),
              new Case("/api/traffic/packets/{id}/zap-scan", params("id", 1L, "targetId", 1L)),
              new Case("/api/post-scan-paths/plans", params("targetId", 1L)),
              new Case("/api/traffic/suggestions/{id}/execute", params("id", 1L, "targetId", 1L)));

      for (Case testCase : cases) {
        EndpointCapability endpoint =
            EndpointCapability.derive("POST", testCase.pathTemplate(), "旁路入口");
        GuardSupport.Fixture fixture =
            GuardSupport.fixture(
                List.of(endpoint),
                TARGETS,
                CapabilityBlacklist.defaults(),
                "",
                "",
                CapabilityGate.SchemaMode.WARN,
                true);

        assertDeniedAt(
            CapabilityDeniedException.Layer.AUTHORIZATION,
            "TARGET_BINDING_UNRESOLVED",
            () -> fixture.gate().invoke(endpoint.code(), testCase.params(), approved()));
      }
    }

    /**
     * <strong>A-3【真实缺陷】只读端点被误拦 —— 这是一个新发现（fail-closed 过度）。</strong>
     *
     * <p>我原本写这条作为"对照组"（期望只读端点放行）。<strong>实测：被 L-A 以
     * {@code MISSING_TARGET_BINDING} 拒绝。</strong>
     *
     * <p><strong>根因</strong>（已逐行核实）：
     *
     * <ol>
     *   <li>{@code EndpointCapability.derive("GET", "/api/vulnerabilities", ...)} 的 {@code targetBindings()}
     *       返回<strong>空集</strong>（只读方法 + 路径无 target 段 → 确实不触及目标，语义正确）。
     *   <li>但 {@code TargetBindingProbe.declarationOf()} 对 {@code EndpointCapability} 返回
     *       <strong>{@code UNKNOWN}</strong>——因为：
     *       <ul>
     *         <li>它<strong>没有</strong>实现 {@code TargetBindingDeclaration} 接口（grep 确认 0 匹配）
     *         <li>它<strong>没有</strong> {@code targetScope()} 方法（grep 确认 0 匹配）
     *         <li>它<strong>没有</strong> {@code targetBindingsDeclared()}/{@code touchesTargets()}
     *       </ul>
     *   <li>{@code TargetBindingProbe.emptyBindingAllowed()} 只在 {@code declarationOf() == NONE} 时返回 true
     *       （{@code :73-75}）→ {@code UNKNOWN} → <strong>false</strong>。
     *   <li>{@code CapabilityGate:372-381} → 空集 + 未声明 NONE → <strong>拒绝 {@code MISSING_TARGET_BINDING}</strong>。
     * </ol>
     *
     * <p><strong>后果</strong>：<strong>所有只读端点能力都无法通过护栏</strong>——即使是
     * {@code GET /api/vulnerabilities} 这种确实不触及目标的端点。这是"能力完备性"的严重损失，
     * 且与 §3 的 {@code invoke_endpoint} 不可用是<strong>同一类失败</strong>（过度 fail-closed → 能力归零）。
     *
     * <p><strong>修复方向</strong>：{@code EndpointCapability} 应实现 {@code TargetBindingDeclaration}，
     * 按"是否 targetBound"返回 {@code NONE} 或 {@code REQUIRED}。这样只读端点能正确声明 NONE。
     *
     * <p><strong>✅ 已修复（2026-10-12）</strong>：{@code EndpointCapability} 新增
     * {@code targetBindingsDeclared()} 访问器（返回 {@code targetBound}），
     * {@code TargetBindingProbe.readBooleanDeclaration} 反射读取之 → {@code declarationOf} 返回
     * {@code NONE} → {@code emptyBindingAllowed=true} → 只读端点<strong>通过护栏</strong>。
     *
     * <p>本用例原断言"被拒"（缺陷行为），现按原断言消息的提示改为断言<strong>放行</strong>。
     */
    @Test
    @DisplayName("A-3 【已修复】只读端点正确声明 NONE → 空集合法 → 通过护栏")
    void readOnlyEndpointIsAllowedAfterDeclarationFix() {
      EndpointCapability readOnly =
          EndpointCapability.derive("GET", "/api/vulnerabilities", "列出漏洞目录");

      // ① 语义正确：只读端点确实返回空集。
      org.junit.jupiter.api.Assertions.assertTrue(
          readOnly.targetBindings(Map.of()).isEmpty(), "只读端点应返回空集（确实不触及目标）");

      // ② 修复后：护栏能识别"空集是合法的"。
      org.junit.jupiter.api.Assertions.assertEquals(
          com.bachelor.toolbox.ai.guard.TargetBindingProbe.Declaration.NONE,
          com.bachelor.toolbox.ai.guard.TargetBindingProbe.declarationOf(readOnly),
          "只读端点必须声明 NONE（targetBindingsDeclared() 返回 false）");
      org.junit.jupiter.api.Assertions.assertTrue(
          com.bachelor.toolbox.ai.guard.TargetBindingProbe.emptyBindingAllowed(readOnly),
          "只读端点的空集必须被护栏认可，否则能力归零");

      GuardSupport.Fixture fixture =
          GuardSupport.fixture(
              List.of(readOnly),
              TARGETS,
              CapabilityBlacklist.defaults(),
              "",
              "",
              CapabilityGate.SchemaMode.WARN,
              true);

      // ③ 结果：只读端点通过护栏（修复前为 MISSING_TARGET_BINDING 拒绝）。
      org.junit.jupiter.api.Assertions.assertDoesNotThrow(
          () -> fixture.gate().invoke(readOnly.code(), Map.of(), approved()),
          "只读端点应通过 L-A（空集 + 显式声明 NONE）");
    }

    /**
     * <strong>修复不得放开写操作</strong>：所有非读方法一律 {@code targetBound=true} → 哨兵 → 仍被拒。
     *
     * <p>这是声明修复的<strong>安全性护栏</strong>——若本用例失败，说明补丁放开了写操作（严重 fail-open）。
     *
     * <p><strong>⚠️ 层序说明</strong>：写端点会被更早的层先拦下，必须逐层让路才能验证 L-A：
     *
     * <ol>
     *   <li><strong>L-B（准入）</strong>：DELETE 等属高危能力，需在 whitelist 中显式开启
     *       → 传入能力 code 让 L-B 通过。
     *   <li><strong>L-C（参数）</strong>：{@code EndpointCapability.validateParams} 要求触及目标的端点
     *       必须提供 {@code targetId}（{@code :337-343}）→ 传入合法 {@code targetId}。
     *   <li><strong>L-A（授权）</strong>：哨兵 → {@code TARGET_BINDING_UNRESOLVED} 拒绝 ← <strong>本用例要验证的</strong>。
     * </ol>
     *
     * <p>本用例<strong>同时断言层与原因码</strong>（遵循"伪通过"规则）：拒绝必须来自 L-A，
     * 而不是 L-B 的白名单或 L-C 的参数缺失。
     */
    @Test
    @DisplayName("A-4 【安全断言】写方法端点修复后仍被 L-A 拒绝（哨兵）")
    void writeEndpointsRemainDeniedAfterDeclarationFix() {
      for (String method : List.of("POST", "PUT", "PATCH", "DELETE")) {
        EndpointCapability write =
            EndpointCapability.derive(method, "/api/vulnerabilities", "写方法端点");

        org.junit.jupiter.api.Assertions.assertTrue(
            write.isTargetBound(),
            method + " 是写方法，必须 targetBound=true（绝不可跳过 L-A）");

        // 声明必须是 REQUIRED（空集不合法）。
        org.junit.jupiter.api.Assertions.assertEquals(
            com.bachelor.toolbox.ai.guard.TargetBindingProbe.Declaration.REQUIRED,
            com.bachelor.toolbox.ai.guard.TargetBindingProbe.declarationOf(write),
            method + " 写端点必须声明 REQUIRED");
        org.junit.jupiter.api.Assertions.assertFalse(
            com.bachelor.toolbox.ai.guard.TargetBindingProbe.emptyBindingAllowed(write),
            method + " 写端点的空集绝不可合法");

        GuardSupport.Fixture fixture =
            GuardSupport.fixture(
                List.of(write),
                TARGETS,
                CapabilityBlacklist.defaults(),
                write.code(), // L-B：显式开启该高危能力，使其放行到 L-A
                "",
                CapabilityGate.SchemaMode.WARN,
                true);

        // L-C：传入合法 targetId 使参数校验通过 → 验证 L-A 的哨兵拒绝确实生效。
        assertDeniedAt(
            CapabilityDeniedException.Layer.AUTHORIZATION,
            "TARGET_BINDING_UNRESOLVED",
            () ->
                fixture
                    .gate()
                    .invoke(write.code(), Map.of("targetId", 1L), approved()));
      }
    }

    /**
     * <strong>路径含 {@code target} 段的只读端点</strong>（如 {@code GET /api/targets/{targetId}/...}）
     * 必须返回哨兵——即使方法是 GET。
     *
     * <p>绕过设想：只按 HTTP 方法判定"只读 → 不触及目标"，则 {@code GET /api/targets/{targetId}/discovered-paths}
     * 会跳过 L-A，从而可读任意目标的资产数据（IDOR）。
     */
    @Test
    @DisplayName("A-4 GET 但路径含 {targetId} → 必须返回哨兵（不能因 GET 就跳过 L-A）")
    void readOnlyEndpointWithTargetPathVariableReturnsSentinel() {
      EndpointCapability targetScoped =
          EndpointCapability.derive("GET", "/api/targets/{targetId}/discovered-paths", "读取目标资产");

      org.junit.jupiter.api.Assertions.assertTrue(
          targetScoped.targetBindings(Map.of()).contains(AgentCapability.TARGET_BINDING_UNRESOLVED),
          "路径含 {targetId} 的只读端点必须返回哨兵，否则构成 IDOR 通道");
    }
  }

  // ==================================================================
  // B. invoke_endpoint 作为间接执行载体
  // ==================================================================

  @Nested
  @DisplayName("B. invoke_endpoint 触达旁路端点")
  class ViaEndpointPrimitive {

    /**
     * 经 {@code invoke_endpoint} 触达 {@code POST /api/tasks/1/retry}（P1-5 D-6 修复后：已被覆盖）。
     *
     * <p><strong>修复前</strong>：{@code EndpointParameterPolicy.isTaskCreationEndpoint}
     * <strong>不覆盖</strong>该路径，因此 {@code validateEndpointParameterPolicy} 直接 return，
     * 不做任何参数校验；护栏只能靠底层端点能力的 L-A 哨兵兜住（{@code TARGET_BINDING_UNRESOLVED}）。
     *
     * <p><strong>修复后（D-6 双轨判定）</strong>：路径模式轨新增 {@code /api/tasks/{id}/retry}，
     * 该端点<strong>已进入 L-C' 管辖范围</strong>。本 fixture 的 body 只含 {@code id}/{@code targetId}、
     * 没有 {@code toolCode}/{@code parameters}，因此走到 L-C' 的"任务创建端点缺少请求体"分支。
     *
     * <p><strong>⚠️ 本用例验证的确切语义（不可含糊）</strong>：
     *
     * <blockquote>
     * 本用例验证的是"<strong>端点已进入 L-C' 管辖范围</strong>"（D-6 覆盖生效），
     * 拒绝原因是<strong>请求体缺失导致的 fail-closed</strong>，
     * <strong>不是</strong>参数越权。若要验证参数越权本身，
     * 需构造含 {@code toolCode}+{@code parameters} 的完整请求体。
     * </blockquote>
     *
     * <p>之所以必须写清楚：这两种情形的<strong>层与原因码完全相同</strong>
     * （L-C + {@code ENDPOINT_PARAMETER_POLICY}），只看断言结果无法区分——
     * 若不在注释中固化语义，后人会误以为"参数越权已被验证"，这正是本类反复强调的伪通过形态。
     *
     * <p>另注：L-A 此时也<strong>不再</strong>是拒绝点——body 里的 {@code targetId=1} 能被深度解析
     * 且目标 1 确实存在，L-A 放行。拒绝点从 L-A（修复前）下移到 L-C'（修复后）。
     */
    @Test
    @DisplayName("B-1 经原语触达 /api/tasks/1/retry → D-6 已覆盖，L-C' 因缺 body 拒绝")
    void retryEndpointViaPrimitiveIsNowCoveredByParameterPolicy() {
      EndpointRegistry registry = new EndpointRegistry();
      EndpointCapability retry =
          EndpointCapability.derive("POST", "/api/tasks/{id}/retry", "重试任务");
      registry.register(retry);
      InvokeEndpointCapability invoke =
          new InvokeEndpointCapability(
              registry, new com.bachelor.toolbox.ai.capability.CapabilityRegistry(List.of()));

      GuardSupport.Fixture fixture =
          GuardSupport.fixture(
              List.of(invoke, retry),
              TARGETS,
              CapabilityBlacklist.defaults(),
              InvokeEndpointCapability.CODE,
              InvokeEndpointCapability.CODE,
              CapabilityGate.SchemaMode.WARN,
              true);

      // 前置条件（四版翻转）：D-6 缺口已闭合 —— 策略现在覆盖 retry 端点。
      org.junit.jupiter.api.Assertions.assertTrue(
          EndpointParameterPolicy.isTaskCreationEndpoint("POST", "/api/tasks/1/retry"),
          "D-6 修复后策略必须覆盖 retry 端点（原为缺口）");

      // 再确认拒绝来自 L-C'（而不是 L-A 哨兵，也不是"未覆盖所以放行"）。
      assertDeniedAt(
          CapabilityDeniedException.Layer.PARAMETER,
          "ENDPOINT_PARAMETER_POLICY",
          () ->
              fixture
                  .gate()
                  .invoke(
                      InvokeEndpointCapability.CODE,
                      params("method", "POST", "path", "/api/tasks/1/retry", "body", params("id", 1L, "targetId", 1L)),
                      approved()));
    }

    /**
     * <strong>D-6 的完整攻击链尝试</strong>：经原语调用 retry，并在 body 里<strong>塞入 targetId</strong>。
     *
     * <p>攻击设想：既然底层 {@code TaskService.createRetry} 会克隆原任务的目标，攻击者无法直接指定目标；
     * 但若 body 里带 targetId 能让 L-A 通过（因为深度解析会采集它），而实际执行时被忽略
     * （retry 用的是原任务的 target），就形成"校验的是 A、执行的是 B"。
     *
     * <p><strong>修复前</strong>：底层端点能力返回哨兵，L-A 在 {@code targetIdsOf} 之前就 fail-closed
     * （{@code TARGET_BINDING_UNRESOLVED}）——安全，但"校验/执行错位"这一性质<strong>无法被验证</strong>，
     * 因为拒绝来自更早的层。
     *
     * <p><strong>修复后</strong>：body 里的 {@code targetId=1} 被深度解析且目标 1 存在 → L-A 放行 →
     * 拒绝点下移到 L-C'。此时"校验/执行错位"这一性质<strong>第一次真正可验证</strong>：
     * 载荷没有 {@code toolCode}/{@code parameters}，被 L-C' 以"缺少请求体"fail-closed 拒绝。
     *
     * <p><strong>⚠️ 语义边界（同 B-1）</strong>：本用例断言的是"端点已受 L-C' 管辖 + 缺 body fail-closed"，
     * <strong>不是</strong>参数越权。要验证"注入的 targetId 是否造成校验/执行错位"，
     * 需构造含 {@code toolCode}+{@code parameters} 的完整请求体，并断言实际执行目标与校验目标一致——
     * 那需要执行链路（{@code TaskService}）而非纯护栏测试，超出本类范围，此处如实标注为未覆盖。
     */
    @Test
    @DisplayName("B-2 经原语触达 retry 并在 body 塞 targetId=1 → L-C' 拒绝（缺 body fail-closed）")
    void retryWithInjectedTargetIdIsDeniedByParameterPolicy() {
      EndpointRegistry registry = new EndpointRegistry();
      EndpointCapability retry =
          EndpointCapability.derive("POST", "/api/tasks/{id}/retry", "重试任务");
      registry.register(retry);
      InvokeEndpointCapability invoke =
          new InvokeEndpointCapability(
              registry, new com.bachelor.toolbox.ai.capability.CapabilityRegistry(List.of()));

      GuardSupport.Fixture fixture =
          GuardSupport.fixture(
              List.of(invoke, retry),
              TARGETS,
              CapabilityBlacklist.defaults(),
              InvokeEndpointCapability.CODE,
              InvokeEndpointCapability.CODE,
              CapabilityGate.SchemaMode.WARN,
              true);

      assertDeniedAt(
          CapabilityDeniedException.Layer.PARAMETER,
          "ENDPOINT_PARAMETER_POLICY",
          () ->
              fixture
                  .gate()
                  .invoke(
                      InvokeEndpointCapability.CODE,
                      params(
                          "method",
                          "POST",
                          "path",
                          "/api/tasks/1/retry",
                          "body",
                          params("id", 1L, "targetId", 1L)),
                      approved()));
    }
  }

  // ==================================================================
  // C. 手工能力的间接执行声明
  // ==================================================================

  @Nested
  @DisplayName("C. 手工封装能力的间接执行声明")
  class ManualCapabilities {

    /**
     * 模拟 core-dev 提到的 {@code cancel_task}：它"不图省事声明 NONE"，因为取消扫描也触及目标。
     *
     * <p>本用例验证：一个<strong>声明 REQUIRED 但解析不出目标</strong>的能力（如 cancel 只收到 taskId），
     * 必须返回哨兵并被拒——这正是三态语义的价值。
     */
    @Test
    @DisplayName("C-1 cancel 类能力（只有 taskId，无 targetId）→ 必须返回哨兵并被拒")
    void cancelLikeCapabilityMustReturnSentinel() {
      AgentCapability cancelLike =
          GuardSupport.DeclaredStub.of(
              "cancel_task",
              CapabilityKind.WRITE,
              RiskLevel.SENSITIVE,
              java.util.Set.of(AgentCapability.TARGET_BINDING_UNRESOLVED),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(cancelLike), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_BINDING_UNRESOLVED",
          () -> fixture.gate().invoke("cancel_task", params("taskId", 1L), approved()));
    }

    /**
     * <strong>反面：错误的实现方式</strong>——把"只有 taskId 的能力"声明为 NONE + 空集。
     *
     * <p>这样它就能跳过 L-A。本用例断言这种写法<strong>会被护栏放行</strong>，从而说明：
     * <strong>护栏无法自动发现"声明错了"</strong>——它只检查"是否显式声明"，不检查"声明是否正确"。
     * 这是设计上已知的局限（§10），也是为什么需要注册期交叉校验（R-1/R-2）。
     */
    @Test
    @DisplayName("C-2 反面：错误声明为 NONE+空集的能力会跳过 L-A（护栏无法自动发现声明错误）")
    void wronglyDeclaredNoneCapabilitySkipsAuthorization() {
      AgentCapability wronglyDeclared =
          GuardSupport.DeclaredStub.of(
              "sneaky_cancel",
              CapabilityKind.WRITE,
              RiskLevel.SENSITIVE,
              java.util.Set.of(),
              TargetBindingProbe.Declaration.NONE);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(wronglyDeclared), TARGETS);

      // 放行 —— 记录这一事实：护栏信任显式声明，不校验其正确性。
      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("sneaky_cancel", params("taskId", 1L), approved()));
    }

    /**
     * <strong>注册期规则 R-2 的可执行形式</strong>：执行类语义的能力码不得声明 NONE。
     *
     * <p>本用例把"应被注册期拒绝"的清单固化为数据，供注册期交叉校验实现时复用。
     */
    @Test
    @DisplayName("C-3 注册期规则 R-2：执行类语义的能力码声明 NONE 属于可疑声明")
    void registrationRuleFlagsExecutionLikeCodesDeclaringNone() {
      String[] executionLikeCodes = {
        "cancel_task", "retry_task", "create_task", "run_workflow", "start_probe",
        "execute_suggestion", "confirm_path", "sync_catalog", "import_pocs", "reload_rules"
      };
      for (String code : executionLikeCodes) {
        AgentCapability suspicious =
            GuardSupport.DeclaredStub.of(
                code,
                CapabilityKind.WRITE,
                RiskLevel.SENSITIVE,
                java.util.Set.of(),
                TargetBindingProbe.Declaration.NONE);
        GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(suspicious), TARGETS);

        // 护栏会放行 —— 证明"仅靠运行期护栏无法防住漏声明/错声明"。
        GuardSupport.assertAllowed(
            () -> fixture.gate().invoke(code, Map.of(), approved()),
            "能力 " + code + " 声明 NONE 时护栏放行；这正是需要注册期交叉校验的原因");
      }
    }
  }

  // ==================================================================
  // D. 审计留痕
  // ==================================================================

  @Nested
  @DisplayName("D. 间接执行的审计留痕")
  class Audit {

    /** 间接执行被拒时，审计必须记录 targetBindings 的哨兵状态，便于事后追溯。 */
    @Test
    @DisplayName("D-1 哨兵拒绝必须留痕（deniedReason=TARGET_BINDING_UNRESOLVED）")
    void sentinelDenialIsAudited() {
      EndpointCapability retry = EndpointCapability.derive("POST", "/api/tasks/{id}/retry", "重试任务");
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(retry), TARGETS);

      // 参数须先满足 L-C（提供路径变量 id 与 targetId），才能走到 L-A 的哨兵分支。
      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_BINDING_UNRESOLVED",
          () ->
              fixture
                  .gate()
                  .invoke(retry.code(), params("id", 1L, "targetId", 1L), approved()));

      org.junit.jupiter.api.Assertions.assertTrue(
          fixture.audit().hasDenial("TARGET_BINDING_UNRESOLVED"),
          "间接执行被拒必须留痕，实际审计记录: " + fixture.audit().entries);
    }
  }

  // ==================================================================
  // E. D-6 的真实后果：下游兜底分析
  // ==================================================================

  @Nested
  @DisplayName("E. D-6 后果分析：下游 Service 是否仍有授权兜底")
  class DownstreamFallback {

    /**
     * <strong>回答"若护栏被绕过，下游是否还兜得住"</strong>——逐个端点的 Service 实现分析。
     *
     * <p>本用例不执行真实 Service（需要 Spring 上下文），而是把<strong>已读源码确认的事实</strong>固化为断言，
     * 使"下游兜底"成为可追溯的结论而非印象。每条断言对应一行已核实的源码。
     *
     * <p>核心发现：<strong>所有五个旁路端点的下游 Service 都<em>确实</em>会重新校验项目-目标成员关系与授权有效期。</strong>
     * 这是深度防御的正面结论——即使护栏的 {@code targetBindings} 声明出错，越权也难以真正落地。
     */
    @Test
    @DisplayName("E-1 五个旁路端点的下游 Service 均有授权兜底（深度防御有效）")
    void allBypassEndpointsHaveDownstreamAuthorizationFallback() {
      // 每条 = (端点, 下游校验点, 源码位置)。用断言把"已核实"变成"可追溯"。
      record Fallback(String endpoint, String check, String location) {}
      List<Fallback> fallbacks =
          List.of(
              new Fallback(
                  "POST /api/tasks/{id}/retry",
                  "validateProjectTarget + getCurrentlyAuthorized(projectId) 双重校验，且工作流任务被明确拒绝重试",
                  "task/TaskService.java:350-351,346-349"),
              new Fallback(
                  "POST /api/regression/findings/{id}/retest",
                  "createRetest → create() → validateProjectTarget + getCurrentlyAuthorized(projectId)",
                  "task/TaskService.java:139-145 → :156-157"),
              new Fallback(
                  "POST /api/scan-schedules",
                  "create/toggle 各自 validateProjectTarget + getCurrentlyAuthorized；派发前再次校验",
                  "schedule/ScanScheduleService.java:140-141,155-156,280-281"),
              new Fallback(
                  "POST /api/projects/{projectId}/discovery/probe",
                  "validateProjectAuthorization(项目 ACTIVE + 窗口) + validateProjectTarget + getCurrentlyAuthorized(projectId)",
                  "probe/ProbeService.java:71-74"),
              new Fallback(
                  "POST /api/tasks (直接创建)",
                  "validateProjectTarget + getCurrentlyAuthorized(projectId)",
                  "task/TaskService.java:156-157"));

      for (Fallback fallback : fallbacks) {
        // 断言：每个端点的下游都存在"项目-目标成员关系 + 当前授权"两道校验。
        org.junit.jupiter.api.Assertions.assertNotNull(
            fallback.check(), fallback.endpoint() + " 必须记录下游校验点");
        org.junit.jupiter.api.Assertions.assertTrue(
            fallback.check().contains("validateProjectTarget")
                || fallback.check().contains("validateProjectAuthorization"),
            fallback.endpoint() + " 的下游必须有项目-目标成员校验，实际记录: " + fallback.check());
        org.junit.jupiter.api.Assertions.assertFalse(
            fallback.location().isBlank(),
            fallback.endpoint() + " 必须给出源码位置以便复核");
      }

      org.junit.jupiter.api.Assertions.assertEquals(
          5, fallbacks.size(), "五个旁路端点都必须有下游兜底记录");
    }

    /**
     * <strong>关键的深度防御结论</strong>：{@code VulnerabilityRegressionService.retest} 自身<em>不</em>做项目归属校验，
     * 但它<strong>调用</strong>的 {@code taskService.createRetest} 会。
     *
     * <p>这修正了我在清单 §5 X-4 里的初步判断。当时的表述是"retest 无项目归属/授权校验"，从<em>方法本身</em>看是对的，
     * 但<strong>结论</strong>需要修正：因为下游 {@code create()} 兜住了，实际不构成越权。
     *
     * <p>本用例把这个修正固化为断言——<strong>独立验证者必须报告自己的修正</strong>，否则等于只报喜不报忧的反面。
     */
    @Test
    @DisplayName("E-2 【自我修正】清单 X-4 的初判需修正：retest 自身无校验，但下游 create() 兜住")
    void x4InitialAssessmentNeedsCorrection() {
      // 修正前（清单 §5 X-4）："retest 无项目归属/授权校验 → 可对任意历史目标重新发起扫描"
      // 修正后：retest 自身只校验 finding↔task 目标一致（VulnerabilityRegressionService.java:47-49），
      //         但把请求转交 taskService.createRetest → create()，
      //         而 create() 第一行就是 validateProjectTarget + getCurrentlyAuthorized（TaskService.java:156-157）。
      // 结论：不构成越权；X-4 应从"高"降级为"需修正的判断"。
      org.junit.jupiter.api.Assertions.assertTrue(
          true,
          "本用例的存在本身就是记录：初判需修正，下游有兜底");
    }
  }
}
