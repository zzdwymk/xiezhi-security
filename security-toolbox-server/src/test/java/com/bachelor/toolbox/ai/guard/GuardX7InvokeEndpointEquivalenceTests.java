package com.bachelor.toolbox.ai.guard;

import static com.bachelor.toolbox.ai.guard.GuardSupport.assertAllowed;
import static com.bachelor.toolbox.ai.guard.GuardSupport.assertDeniedAt;
import static com.bachelor.toolbox.ai.guard.GuardSupport.params;
import static com.bachelor.toolbox.ai.guard.GuardSupport.target;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.endpoint.EndpointCapability;
import com.bachelor.toolbox.ai.endpoint.EndpointRegistry;
import com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability;
import com.bachelor.toolbox.ai.guard.CapabilityDeniedException;
import com.bachelor.toolbox.ai.guard.CapabilityOutcome;
import com.bachelor.toolbox.ai.guard.EndpointParameterPolicy;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * X-7 独立验证：{@code invoke_endpoint("POST", "/api/tasks", ...)} 是否真的套用了与直接调用<strong>同等</strong>的治理。
 *
 * <h2>被验证的实现者声明</h2>
 *
 * <blockquote>
 * "EndpointParameterPolicy（guard-dev）负责参数级校验（白名单/端口子集/MSF 模块前缀/PoC 正则），InvokeEndpointCapability
 * （endpoint-dev）负责反向映射：capabilityFor("POST","/api/tasks") → 取回底层能力 → 套用其 risk()/requiresApproval()
 * → 黑名单检查 → 调底层 validateParams。两者合起来等价于直接调用的治理。"
 * </blockquote>
 *
 * <h2>本轮实测的第一个结论：修复存在但<strong>不可达</strong></h2>
 *
 * <p>初次运行本类时，10 个攻击用例的拒绝理由全部是：
 *
 * <pre>
 * 拒绝层错误（伪通过）：预期 L-A，实际 L-C，原因码 SCHEMA_VIOLATION
 * 消息: 参数不符合能力声明的 schema: $.body包含未声明参数 projectId; ...
 * </pre>
 *
 * <p>根因：{@code InvokeEndpointCapability.parameterSchema()}（{@code InvokeEndpointCapability.java:118-143}）把
 * {@code body}/{@code query} 声明为裸 {@code "type":"object"}（<strong>没有 properties</strong>），同时顶层
 * {@code additionalProperties=false}。而 {@code SchemaValidator:191-192} 对未声明属性一律拒绝<strong>且对嵌套对象递归生效</strong>，
 * 于是 {@code body} 里的任何键都被判为"未声明参数"。
 *
 * <p><strong>后果</strong>：生产默认配置（{@code schemaMode=WARN} 只记录不拦截，但 {@code ENFORCE} 下会拒）下，
 * <em>凡带 body 的 {@code invoke_endpoint} 调用都在 L-C 被拦</em>，{@code CapabilityGate.validateEndpointParameterPolicy}
 * （X-7 的修复点，{@code CapabilityGate:466-508}）<strong>永远执行不到</strong>。
 *
 * <h2>结论演进史（四版）：从"伪通过"到"死代码"到"修复生效"</h2>
 *
 * <p>本类的结论经历过<strong>三次</strong>修正，最终由<strong>实测</strong>确定。完整过程如实记录如下
 * （<strong>方法论价值高于结论本身</strong>——这正是本类保留历史版本的原因）：
 *
 * <table border="1">
 *   <caption>四次结论的演进</caption>
 *   <tr><th>阶段</th><th>当时的结论</th><th>为何被推翻 / 后续</th></tr>
 *   <tr>
 *     <td>初版（ENFORCE 测量）</td>
 *     <td>"10 个攻击用例全被拒 → 护栏有效"</td>
 *     <td>伪通过：拒因是 L-C 的 <code>SCHEMA_VIOLATION</code>，<strong>不是</strong> L-A 授权边界</td>
 *   </tr>
 *   <tr>
 *     <td>二版（WARN 测量）</td>
 *     <td>"WARN 下 body 可达 L-C' → D-1..D-5 真实可利用"</td>
 *     <td><strong>漏看层序</strong>：L-A（<code>:145</code>）排在 L-C'（<code>:150</code>）<em>之前</em></td>
 *   </tr>
 *   <tr>
 *     <td>三版（实测）</td>
 *     <td><strong>L-A 哨兵短路 → L-C' 永不可达 → X-7 修复是死代码</strong></td>
 *     <td>结论正确但<strong>是缺陷报告，不是终局</strong>：它把"死代码"定位为根因，直接催生了 P1-4 修复</td>
 *   </tr>
 *   <tr>
 *     <td><strong>四版（当前 · P1-4/P1-5 修复后）</strong></td>
 *     <td><strong>已修复：L-C' 从死代码变为可达</strong></td>
 *     <td>—（本版）</td>
 *   </tr>
 * </table>
 *
 * <h2>四版结论（当前）：L-A 不再无条件短路，L-C' 可达</h2>
 *
 * <p>三版结论的根因是 {@code InvokeEndpointCapability.targetBindings()} <strong>恒返回哨兵</strong>。
 * <strong>P1-4 修复</strong>把它改为用 {@link com.bachelor.toolbox.ai.capability.TargetIdExtractor#extractDeep}
 * 在<strong>任意嵌套层级</strong>采集真实 {@code targetId}；<strong>解析不出时仍返回哨兵</strong>（fail-closed 语义不变）。
 * 配套的 <strong>P1-5 修复</strong>补齐了 D-1..D-6 规则。
 *
 * <p><strong>关键副作用</strong>：目标一旦能解析出来，L-A 的哨兵分支就不再触发 →
 * 层序上排在 L-A 之后的 {@code validateEndpointParameterPolicy}（L-C'，X-7 的修复点）
 * <strong>第一次真正被执行</strong>。也就是说，三版报告的"死代码"已被激活。
 *
 * <h3>决定性证据（修复后的真实层序与走向）</h3>
 *
 * <pre>
 * // CapabilityGate.java —— 真实层序（未变）
 * capability = requireRegistered(...);                          // L-D
 * ApprovalLevel admissionLevel = admit(...);                    // L-B
 * validateParameters(capability, safeParams, ...);              // L-C
 * Set&lt;String&gt; bindings = resolveAndValidateAuthorization(...);  // L-A  ← 不再无条件短路
 * validateEndpointParameterPolicy(capability, ...);             // L-C' ← 现在可达
 *
 * // InvokeEndpointCapability.targetBindings()（P1-4 修复后）
 * ids.addAll(TargetIdExtractor.extractDeep(safe.get(PARAM_BODY)));
 * ids.addAll(TargetIdExtractor.extractDeep(safe.get(PARAM_QUERY)));
 * ids.addAll(TargetIdExtractor.extractDeep(safe));
 * if (ids.isEmpty()) {
 *   return Set.of(TARGET_BINDING_UNRESOLVED);   // 解析不出 → 仍 fail-closed（未变）
 * }
 * return Set.copyOf(ids);                        // 解析出 → 交给 L-A 逐个校验
 * </pre>
 *
 * <h3>修复后的拒绝归属（本类全部用例的断言依据）</h3>
 *
 * <table border="1">
 *   <caption>载荷形态 → 拒绝层 → 原因码</caption>
 *   <tr><th>载荷形态</th><th>拒绝层</th><th>原因码</th></tr>
 *   <tr>
 *     <td>目标解析不出（body 里没有 targetId）</td>
 *     <td>L-A</td><td>{@code TARGET_BINDING_UNRESOLVED}</td>
 *   </tr>
 *   <tr>
 *     <td>目标解析出来了，但 fixture 里不存在该 ID</td>
 *     <td>L-A</td><td>{@code TARGET_NOT_FOUND}</td>
 *   </tr>
 *   <tr>
 *     <td>目标合法，但透传参数越权（工具白名单/端口/MSF/枚举）</td>
 *     <td><strong>L-C'</strong></td><td>{@code ENDPOINT_PARAMETER_POLICY}</td>
 *   </tr>
 *   <tr>
 *     <td>目标合法、参数合法</td>
 *     <td colspan="2"><strong>放行</strong>（对照组，证明修复未误伤）</td>
 *   </tr>
 * </table>
 *
 * <h3>仍然成立的教训（本类的长期价值）</h3>
 *
 * <ol>
 *   <li><strong>"伪通过"规则</strong>：只看"抛了异常"会得到错误层的拒绝。必须同时断言<strong>层</strong>与<strong>原因码</strong>
 *       ——三版正是靠这条规则才发现"拒因是 schema 而非授权边界"。本类所有断言都走
 *       {@link GuardSupport#assertDeniedAt}。
 *   <li><strong>单元级验证无法发现"被测代码不在调用链上"</strong>：D 组 8 个用例直接单测
 *       {@code EndpointParameterPolicy} 时全 PASS，却完全看不到它当时是死代码。因此 D 组保留为
 *       "规则本身正确性"的单元验证，<strong>而"规则确实在调用链上"必须由 F 组经完整 {@code gate.invoke} 证明</strong>。
 *   <li><strong>层序即语义</strong>：L-A 排在 L-C' 之前，意味着"目标解析失败"永远优先于"参数越权"被观测到。
 *       因此要验证 L-C'，必须<strong>先让更早的层放行</strong>（提供可解析且存在的 targetId）。
 *   <li><strong>修复的副作用必须被回归覆盖</strong>：三版的"死代码"结论是修复的直接输入；四版把这些用例
 *       翻转为"断言修复后行为"，使 L-C' 可达性成为<strong>受测事实</strong>而非一次性观测。
 * </ol>
 *
 * <h3>⚠️ 翻转说明（P1-4/P1-5 修复后）</h3>
 *
 * <p>本类此前的多个用例刻意<strong>断言缺陷行为</strong>（"漂移存在 → 护栏侧放行"、"哨兵短路 → 全部被拒"）。
 * 修复后这些断言按设计失败，已<strong>逐一翻转</strong>为断言修复后行为。每个翻转后的用例都：
 * ①同时断言层与原因码；②配套保留对照组证明合法输入仍放行。
 */
@DisplayName("X-7 对抗验证：invoke_endpoint 与直接调用的治理等价性")
class GuardX7InvokeEndpointEquivalenceTests {

  /** 与 {@code EndpointParameterPolicy} 同源的白名单工具集。 */
  private static final Map<Long, AuthorizedTarget> TARGETS =
      Map.of(
          1L, target(1L, "192.168.10.10", "8080,8085"),
          2L, target(2L, "192.168.10.99", "80,443"));

  /**
   * 构造 {@code invoke_endpoint} + 底层 {@code POST /api/tasks} 端点能力的完整装置。
   *
   * <p>{@code invoke_endpoint} 的 {@code risk()} 是 DESTRUCTIVE，因此护栏会要求白名单显式开启（{@code CAPABILITY_NOT_ENABLED}）
   * 且人工确认（{@code APPROVAL_REQUIRED}）。这里显式开启并批准，把观测点推到参数/授权层。
   *
   * <p><strong>schemaMode 用 WARN（= 生产默认）</strong>：这样 schema 违规只记录不拦截，才能观测到
   * {@code EndpointParameterPolicy} 与 L-A 的<strong>真实</strong>行为。若用 ENFORCE，所有带 body 的调用都会在 L-C 被
   * schema 拒掉，从而把"护栏有效"与"通道是死的"混为一谈（伪通过）。可达性另有专门的 ENFORCE 用例。
   */
  private GuardSupport.Fixture invokeEndpointFixture() {
    return invokeEndpointFixture(com.bachelor.toolbox.ai.guard.CapabilityGate.SchemaMode.WARN);
  }

  private GuardSupport.Fixture invokeEndpointFixture(
      com.bachelor.toolbox.ai.guard.CapabilityGate.SchemaMode schemaMode) {
    EndpointRegistry endpointRegistry = new EndpointRegistry();
    // 底层端点能力：POST /api/tasks（写操作 → 派生为 targetBound，targetBindings 返回哨兵）。
    EndpointCapability underlying = EndpointCapability.derive("POST", "/api/tasks", "创建扫描任务");
    endpointRegistry.register(underlying);
    InvokeEndpointCapability invoke =
        new InvokeEndpointCapability(
            endpointRegistry,
            new com.bachelor.toolbox.ai.capability.CapabilityRegistry(List.of()));

    return GuardSupport.fixture(
        List.of(invoke, underlying),
        TARGETS,
        com.bachelor.toolbox.ai.guard.CapabilityBlacklist.defaults(),
        InvokeEndpointCapability.CODE,
        InvokeEndpointCapability.CODE,
        schemaMode,
        true);
  }

  /** 已批准的调用上下文（绕过 L-B 的确认要求，把观测点推到参数层）。 */
  private static com.bachelor.toolbox.ai.guard.CapabilityContext approved() {
    return com.bachelor.toolbox.ai.guard.CapabilityContext.of("ai-agent", 7L).approved(1L);
  }

  // ==================================================================
  // A. 端口子集校验（实现者称"已修：旧实现只取区间两端点"）
  // ==================================================================

  @Nested
  @DisplayName("A. 端口子集：授权 8080,8085、请求 8080-8085（中间 8081-8084 未授权）")
  class PortSubset {

    /**
     * <strong>核心回归用例</strong>：授权端口 {@code 8080,8085}，请求 {@code 8080-8085}。
     *
     * <p>若实现"只取区间两端点"（比较 8080 与 8085 是否在授权集内），本用例会<strong>放行</strong>——因为两个端点确实都在。
     * 完整展开才能发现 8081-8084 越权。
     *
     * <p>直接调用 {@code tcp_ports} 能力时应被拒。经 {@code invoke_endpoint} 调用时必须同样被拒，且拒因是
     * {@code ENDPOINT_PARAMETER_POLICY}（参数层），而不是"端点未注册"之类。
     */
    @Test
    @DisplayName("A-1 端到端：ports=8080-8085 → L-A 放行后由 L-C' 以 ENDPOINT_PARAMETER_POLICY 拒绝")
    void endpointPrimitiveRejectsPartiallyOutOfScopePortRange() {
      GuardSupport.Fixture fixture = invokeEndpointFixture();
      // 四版翻转：P1-4 修复后 targetBindings() 能深度解析出 body.targetId=1，L-A 不再无条件短路；
      // 目标 1 存在且合法 → L-A 放行 → 层序上排在其后的 L-C' 第一次真正执行，由端口子集规则拒绝。
      // 注意：拒绝层是 L-C'（Layer.PARAMETER），不再是 L-A —— 这正是"死代码已激活"的证据。
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
                          "/api/tasks",
                          "body",
                          params(
                              "projectId",
                              7L,
                              "targetId",
                              1L,
                              "toolCode",
                              "tcp_ports",
                              "parameters",
                              params("ports", "8080-8085"))),
                      approved()));
    }

    /**
     * <strong>对照组（四版翻转）：完全落在授权范围内的载荷<strong>放行</strong>。</strong>
     *
     * <p>三版时本用例断言"连合法载荷也被哨兵拒绝"，用来说明 {@code invoke_endpoint} 整体不可用。
     * P1-4 修复后哨兵不再无条件触发，这条载荷（授权目标 1 + 授权端口 8080,8085 + 合法工具码）走完全部
     * 五层校验并放行——<strong>这正是修复的目标：恢复能力可用性</strong>。
     *
     * <p>本用例是 A-1 的对照组：A-1 证明越权端口被 L-C' 拒绝，A-2 证明同一路径上的合法端口不被误伤。
     * 两者同时成立才说明"拒绝来自参数越权"，而不是"通道又坏了"。
     */
    @Test
    @DisplayName("A-2 对照组：ports=8080,8085（完全授权）→ 放行（修复未误伤合法输入）")
    void endpointPrimitiveAllowsFullyAuthorizedPorts() {
      GuardSupport.Fixture fixture = invokeEndpointFixture();
      assertAllowed(
          () ->
              fixture
                  .gate()
                  .invoke(
                      InvokeEndpointCapability.CODE,
                      params(
                          "method",
                          "POST",
                          "path",
                          "/api/tasks",
                          "body",
                          params(
                              "projectId",
                              7L,
                              "targetId",
                              1L,
                              "toolCode",
                              "tcp_ports",
                              "parameters",
                              params("ports", "8080,8085"))),
                      approved()),
          "完全授权的载荷必须放行；若被拒，说明修复误伤了合法输入");
    }

    /**
     * 直接用 {@link EndpointParameterPolicy} 验证"完整展开"语义，与上面的端到端用例互补。
     *
     * <p>这条断言刻意不走护栏：它把 {@code EndpointParameterPolicy} 当作被测单元，若它本身只比端点，这里就会失败——
     * 从而把"是策略错了还是接线错了"区分开。
     */
    @Test
    @DisplayName("A-3 EndpointParameterPolicy 单元级：8080-8085 相对授权 8080,8085 必须拒绝")
    void policyExpandsPortRangesCompletely() {
      EndpointParameterPolicy policy = new EndpointParameterPolicy(new PortRangeParser(), 1024);
      AuthorizedTarget t = target(1L, "192.168.10.10", "8080,8085");
      com.bachelor.toolbox.common.ApiException error =
          org.junit.jupiter.api.Assertions.assertThrows(
              com.bachelor.toolbox.common.ApiException.class,
              () ->
                  policy.validateTaskCreationBody(
                      t,
                      params(
                          "toolCode",
                          "tcp_ports",
                          "parameters",
                          params("ports", "8080-8085"))));
      org.junit.jupiter.api.Assertions.assertTrue(
          error.getMessage().contains("超出目标授权范围"),
          "拒绝理由应是端口越权，实际: " + error.getMessage());
    }
  }

  // ==================================================================
  // B. 换 toolCode：其它扫描工具是否同样被治理
  // ==================================================================

  @Nested
  @DisplayName("B. 换 toolCode：治理是否对所有白名单工具生效（修复后：全部由 L-C' 拒绝）")
  class ToolCodeSwap {

    /**
     * 本组原意：检验"换不同 toolCode 时，四条参数规则是否都生效"。
     *
     * <p><strong>三版结论（历史）</strong>：全部无效——不是因为规则没写，而是因为 L-C' 不可达。
     * 四种不同的非法载荷得到<strong>完全相同</strong>的拒绝理由（{@code TARGET_BINDING_UNRESOLVED}），
     * 这本身就说明拒绝与载荷内容<strong>无关</strong>。
     *
     * <p><strong>四版结论（当前）</strong>：P1-4 修复后 body 里的 {@code targetId=1} 能被深度解析出来，
     * L-A 放行（目标存在且合法），于是载荷<strong>真的走到了 L-C'</strong>。
     * 现在四种不同的非法载荷得到<strong>各不相同但都指向参数层</strong>的拒绝——这正是"规则生效"的标志：
     * 拒绝重新变得<strong>与载荷内容相关</strong>。
     *
     * <p>本辅助方法因此从 {@code assertSentinelShortCircuit} 改名为 {@code assertParameterPolicyDenied}，
     * 并同时断言层（L-C'）与原因码（{@code ENDPOINT_PARAMETER_POLICY}）。
     */
    private void assertParameterPolicyDenied(String toolCode, Map<String, Object> toolParameters) {
      GuardSupport.Fixture fixture = invokeEndpointFixture();
      Map<String, Object> body = new java.util.LinkedHashMap<>();
      body.put("projectId", 7L);
      body.put("targetId", 1L);
      body.put("toolCode", toolCode);
      body.put("parameters", toolParameters);
      assertDeniedAt(
          CapabilityDeniedException.Layer.PARAMETER,
          "ENDPOINT_PARAMETER_POLICY",
          () ->
              fixture
                  .gate()
                  .invoke(
                      InvokeEndpointCapability.CODE,
                      params("method", "POST", "path", "/api/tasks", "body", body),
                      approved()));
    }

    /** B-1：{@code msf_scan} + 越权模块前缀 → L-C' 拒绝（MSF 规则已可达且生效）。 */
    @Test
    @DisplayName("B-1 toolCode=msf_scan，module 非法 → L-C' ENDPOINT_PARAMETER_POLICY 拒绝")
    void msfModulePrefixIsRejectedByPolicy() {
      assertParameterPolicyDenied(
          "msf_scan", params("module", "payload/windows/x64/meterpreter"));
    }

    /** B-2：{@code sqlmap_scan} 夹带未允许字段 → L-C' 拒绝（工具参数白名单已可达且生效）。 */
    @Test
    @DisplayName("B-2 toolCode=sqlmap_scan 夹带未允许字段 → L-C' ENDPOINT_PARAMETER_POLICY 拒绝")
    void unknownToolParameterIsRejectedByPolicy() {
      assertParameterPolicyDenied(
          "sqlmap_scan",
          params("path", "http://192.168.10.10/?id=1", "extraFlags", "--os-shell"));
    }

    /** B-3：不在策略白名单里的工具码 → L-C' 拒绝（工具白名单已可达且生效）。 */
    @Test
    @DisplayName("B-3 toolCode=zap_fuzz（未在策略白名单）→ L-C' ENDPOINT_PARAMETER_POLICY 拒绝")
    void toolOutsideSafeWhitelistIsRejectedByPolicy() {
      assertParameterPolicyDenied("zap_fuzz", params("fuzzRequestUrl", "http://192.168.10.10/"));
    }

    /**
     * B-4：省略 {@code toolCode} → L-C' 拒绝。
     *
     * <p>三版时这条被 L-A 哨兵拒绝，因此"省略 toolCode 是否 fail-closed"这一性质
     * <strong>无法被验证</strong>（拒因来自 L-A，与 toolCode 无关）。
     *
     * <p>四版修复后该性质<strong>第一次真正可验证</strong>：body 里有合法 {@code targetId=1}，
     * L-A 放行；进入 L-C' 后 {@code EndpointParameterPolicy.validateTaskCreationBody}
     * 因取不到 {@code toolCode} 而拒绝（{@code "任务创建必须指定工具（toolCode）"}）。
     * 断言层与原因码同时成立，才证明 fail-closed 确实来自<strong>参数策略自身</strong>。
     */
    @Test
    @DisplayName("B-4 省略 toolCode → L-C' ENDPOINT_PARAMETER_POLICY 拒绝（fail-closed 来自策略自身）")
    void missingToolCodeIsRejectedByPolicy() {
      assertParameterPolicyDenied(null, params("ports", "1-65535"));
    }
  }

  // ==================================================================
  // C. 补 targetId 后是否真的按底层能力的授权边界校验
  // ==================================================================

  @Nested
  @DisplayName("C. 目标授权边界：经原语调用时 targetId 是否真的被校验（修复后：真实逐个校验）")
  class TargetAuthorization {

    /**
     * <strong>本组用例的结论（四版翻转）：L-A 不再短路，per-target 校验第一次真正执行。</strong>
     *
     * <p><strong>三版（历史）</strong>：我最初写这一组时期望"body 里的越权 targetId 会被 L-A 的逐个目标校验
     * 拦下"，断言 {@code TARGET_NOT_FOUND}；实测全部返回 {@code TARGET_BINDING_UNRESOLVED}，
     * 因为 {@code invoke_endpoint.targetBindings()} 恒返回哨兵，而哨兵分支在"逐个目标校验"<strong>之前</strong>就抛异常。
     *
     * <p><strong>四版（当前）</strong>：P1-4 修复后 {@code targetBindings()} 用
     * {@link com.bachelor.toolbox.ai.capability.TargetIdExtractor#extractDeep} 深度解析真实目标，
     * 于是：
     *
     * <ul>
     *   <li>解析<strong>不出</strong>任何目标 → 仍返回哨兵 → {@code TARGET_BINDING_UNRESOLVED}（fail-closed 未变）
     *   <li>解析<strong>出</strong>目标但 fixture 里不存在该 ID → L-A 的逐个校验拒绝，原因码
     *       <strong>{@code TARGET_NOT_FOUND}</strong>
     * </ul>
     *
     * <p>因此本组用例回到最初的设计意图：<strong>断言 {@code TARGET_NOT_FOUND}</strong>。
     * 关键区别在于——现在必须<strong>先让 L-C 放行</strong>（提供顶层合法 {@code targetId}），
     * 否则会在 L-C 被 {@code INVALID_PARAMETER} 拒绝，产生"拒因来自错误层"的伪通过。
     */
    /**
     * 辅助：构造经原语调用 {@code POST /api/tasks} 的载荷并断言 L-A 的"目标不存在"拒绝。
     *
     * <p><strong>关键细节（伪通过陷阱）</strong>：{@code EndpointCapability.validateParams}
     * （L-C）对"targetBound 但路径无 target 变量"的端点<strong>强制要求顶层 {@code targetId}</strong>。
     * 因为 L-C 排在 L-A 之前，若载荷缺 {@code targetId}，会在 L-C 被 {@code INVALID_PARAMETER} 拒绝
     * ——<strong>根本走不到 L-A</strong>。
     *
     * <p>所以本辅助方法<strong>总是补一个顶层 {@code targetId=1}</strong>（合法值），
     * 让 L-C 放行；随后 L-A 会用<strong>深度解析</strong>（而非只看顶层）采集到的目标集合逐个校验，
     * 从而真正观测到"body 里的非法 targetId 是否被校验"。
     *
     * <p>这本身是一个值得记录的层次交互：{@code EndpointCapability} 在 L-C 做了
     * "targetId 必须存在"的<strong>形式检查</strong>，而 L-A 的逐个校验才是<strong>实质边界</strong>。
     * 两者职责不同，不能互相替代。
     */
    private void assertTargetNotFound(String caseName, Map<String, Object> body) {
      GuardSupport.Fixture fixture = invokeEndpointFixture();
      Map<String, Object> callParams = new java.util.LinkedHashMap<>();
      callParams.put("method", "POST");
      callParams.put("path", "/api/tasks");
      callParams.put("targetId", 1L); // 满足 L-C 的形式要求
      callParams.put("body", body);
      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_NOT_FOUND",
          () ->
              fixture
                  .gate()
                  .invoke(InvokeEndpointCapability.CODE, callParams, approved()));
      org.junit.jupiter.api.Assertions.assertNotNull(caseName);
    }

    /** C-1：body 里补一个<strong>不存在的</strong> targetId=999 → L-A 逐个校验拒绝 {@code TARGET_NOT_FOUND}。 */
    @Test
    @DisplayName("C-1 body.targetId=999（不存在）→ L-A TARGET_NOT_FOUND（逐个校验已生效）")
    void nonexistentTargetInBodyIsDeniedByTargetNotFound() {
      assertTargetNotFound(
          "C-1",
          params(
              "projectId", 7L, "targetId", 999L, "toolCode", "tcp_ports", "parameters",
              params("ports", "80")));
    }

    /**
     * C-2：<strong>下划线变体 {@code target_id}</strong>。
     *
     * <p>检验"两套解析器对键名变体的处理是否一致"。修复后深度解析识别
     * {@code targetId}/{@code target_id}/{@code targetIds}/{@code target_ids} 四种写法，
     * 因此 {@code target_id=999} 同样被采集 → 同样 {@code TARGET_NOT_FOUND}。
     * 与 C-1 结果一致，说明<strong>键名变体不会造成校验缺口</strong>。
     */
    @Test
    @DisplayName("C-2 body.target_id=999（下划线变体）→ 同样被采集 → L-A TARGET_NOT_FOUND")
    void underscoreTargetKeyIsAlsoDeniedByTargetNotFound() {
      assertTargetNotFound(
          "C-2",
          params(
              "projectId", 7L, "target_id", 999L, "toolCode", "tcp_ports", "parameters",
              params("ports", "80")));
    }

    /**
     * C-3：<strong>顶层 targetId</strong>（与 method/path 同级，而非在 body 内）。
     *
     * <p>{@code InvokeEndpointCapability.targetBindings} 在扫描 {@code body}/{@code query} 之外
     * <strong>也会扫描外层参数本身</strong>，因此顶层 {@code targetId=999} 同样被采集。
     * L-C 也恰好需要这个顶层 targetId，所以本用例天然满足"让更早的层放行"这一前提。
     */
    @Test
    @DisplayName("C-3 顶层 targetId=999 → 同样被采集 → L-A TARGET_NOT_FOUND")
    void outerLevelTargetIdIsAlsoDeniedByTargetNotFound() {
      GuardSupport.Fixture fixture = invokeEndpointFixture();
      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_NOT_FOUND",
          () ->
              fixture
                  .gate()
                  .invoke(
                      InvokeEndpointCapability.CODE,
                      params(
                          "method",
                          "POST",
                          "path",
                          "/api/tasks",
                          "targetId",
                          999L,
                          "body",
                          params(
                              "projectId", 7L, "targetId", 1L, "toolCode", "tcp_ports",
                              "parameters", params("ports", "80"))),
                      approved()));
    }

    /**
     * C-4：<strong>外层与 body 的 targetId 冲突</strong>（外层 999 / body 1）。
     *
     * <p>这是 Lead 最初关心的问题："哪个 targetId 会赢？"。
     *
     * <p><strong>四版答案：都不"赢"——深度解析采集的是并集 {@code {999, 1}}，逐个校验时 999 不存在即拒绝。</strong>
     *
     * <p>这正是修复后期望的 fail-closed 语义：冲突<strong>不会静默选一个</strong>，而是把两个目标
     * <strong>都</strong>纳入授权校验；只要其中任何一个不合法就整体拒绝。
     * 这比"按优先级取一个"更严格——攻击者无法用"合法 targetId 打掩护"的方式隐藏越权目标。
     *
     * <p>（三版时本用例断言"哨兵短路，两套解析均不可达"；修复后该断言失效，已翻转。）
     */
    @Test
    @DisplayName("C-4 外层/body targetId 冲突（999 vs 1）→ 并集逐个校验 → TARGET_NOT_FOUND")
    void conflictingTargetIdsAreDeniedByTargetNotFound() {
      GuardSupport.Fixture fixture = invokeEndpointFixture();
      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_NOT_FOUND",
          () ->
              fixture
                  .gate()
                  .invoke(
                      InvokeEndpointCapability.CODE,
                      params(
                          "method",
                          "POST",
                          "path",
                          "/api/tasks",
                          "targetId",
                          999L,
                          "body",
                          params(
                              "projectId", 7L, "targetId", 1L, "toolCode", "tcp_ports",
                              "parameters", params("ports", "80"))),
                      approved()));
    }

    /**
     * C-5：<strong>端口越权 + 目标越权同时存在</strong>。
     *
     * <p>原意是检验"目标解析失败时端口策略是否被跳过"。
     *
     * <p><strong>四版答案：L-A 先拒绝（{@code TARGET_NOT_FOUND}），L-C' 确实没机会执行。</strong>
     * 但这与三版的"不可达"有本质区别：三版是因为 L-A <strong>无条件</strong>短路（死代码）；
     * 现在是因为<strong>这条特定载荷的目标本身就非法</strong>——L-A 排在 L-C' 之前，
     * 目标非法时先拒目标是正确的层序语义。
     *
     * <p>要观测"端口策略是否生效"，必须让目标合法（见 A-1）。
     * 本用例保留为<strong>层序对照</strong>：证明"目标层优先于参数层"这一优先级没有被修复打乱。
     */
    @Test
    @DisplayName("C-5 端口+目标双重越权 → L-A 目标层先拒（TARGET_NOT_FOUND），层序未被修复打乱")
    void portPolicyIsPreemptedByAuthorizationLayer() {
      assertTargetNotFound(
          "C-5",
          params(
              "projectId", 7L, "targetId", 999L, "toolCode", "tcp_ports", "parameters",
              params("ports", "22")));
    }

    /**
     * C-6：{@code parameters} 内嵌 targetId 作为干扰项 → 仍被 L-A 采集并拒绝。
     *
     * <p>{@code CreateTaskRequest} 的字段是顶层 {@code targetId}；写在 {@code parameters} 里不会被
     * {@code TaskService.create} 当目标用。<strong>但深度解析会把它也采集进来</strong>——
     * 这正是 P1-4 注释里说的"多解析一个目标 = 多一次授权校验（安全）"。
     *
     * <p>所以本用例从"干扰项不影响结论"变成"<strong>干扰项也必须合法</strong>"：
     * 内嵌的 {@code targetId=1} 合法，但 body 顶层的 999 不存在 → 仍然拒绝。
     * 这证明深度解析<strong>不会</strong>因为"找到了一个合法目标"就放过其余目标。
     */
    @Test
    @DisplayName("C-6 parameters 内嵌 targetId 干扰项 → 深度解析采集全部目标 → 仍 TARGET_NOT_FOUND")
    void nestedTargetIdDoesNotMaskOtherTargets() {
      assertTargetNotFound(
          "C-6",
          params(
              "projectId", 7L, "targetId", 999L, "toolCode", "tcp_ports", "parameters",
              params("targetId", 1L, "ports", "8080")));
    }

    /**
     * <strong>C-7【四版翻转 · 能力可用性证据】完全合法的 body <u>放行</u>。</strong>
     *
     * <p>三版时本用例断言"即使 body 完全合法（授权目标 + 授权端口 + 合法工具），
     * {@code invoke_endpoint} 仍在 L-A 被哨兵拒绝"，用它作为 {@code invoke_endpoint} 整体不可用的
     * <strong>判决性证据</strong>。
     *
     * <p>P1-4 修复后该断言按设计失败，翻转如下：这条载荷走完 L-D → L-B → L-C → L-A → L-C'
     * 全部五层并<strong>放行</strong>。这证明修复确实恢复了能力可用性，而不是"把拒绝理由换了个层"。
     *
     * <p>与 A-1 配对：A-1（端口越权）被 L-C' 拒绝，C-7（全合法）放行。
     * 两条同时成立，才能排除"L-C' 变成无条件拒绝"这种新的伪通过。
     */
    @Test
    @DisplayName("C-7【四版翻转】完全合法的 body → 放行（invoke_endpoint 恢复可用）")
    void fullyLegitimateBodyIsAllowed() {
      GuardSupport.Fixture fixture = invokeEndpointFixture();

      // 一切合法：授权目标 1（授权端口 8080,8085）、授权端口 8080,8085、合法工具码。
      // ⚠️ 端口必须真的落在该目标的授权端口集内，否则被 L-C' 的端口子集规则拒绝——
      // 那是"载荷确实越权"，不能拿来证明"修复误伤"。
      CapabilityOutcome outcome =
          org.junit.jupiter.api.Assertions.assertDoesNotThrow(
              () ->
                  fixture
                      .gate()
                      .invoke(
                          InvokeEndpointCapability.CODE,
                          params(
                              "method",
                              "POST",
                              "path",
                              "/api/tasks",
                              "body",
                              params(
                                  "projectId", 7L, "targetId", 1L, "toolCode", "tcp_ports",
                                  "parameters", params("ports", "8080,8085"))),
                          approved()),
              "完全合法的载荷必须放行；若仍被拒，说明 P1-4 修复未真正恢复能力可用性");

      // 同时确认放行时 L-C' <确实执行过> —— 证明"放行"是走完校验后的放行，
      // 而不是因为 L-C' 被跳过（那将是 fail-open）。
      //
      // ⚠️ 观测点是返回的 CapabilityOutcome 而不是审计 sink：invoke 只在"拒绝"与"申请授权"
      // 两条路径写审计，成功路径把 auditDetail 装在 CapabilityOutcome 里返回、不落库。
      // 若去查 audit().entries 会得到空列表，从而误判为"L-C' 没执行"——这是观测点选错，不是行为错误。
      org.junit.jupiter.api.Assertions.assertEquals(
          "APPLIED",
          outcome.auditDetail().get("endpointParameterPolicy"),
          "放行必须经过 L-C' 并留痕 endpointParameterPolicy=APPLIED；"
              + "若为 null 说明 L-C' 被跳过（fail-open）或观测点选错，实际 auditDetail: "
              + outcome.auditDetail());
    }
  }

  // ==================================================================
  // D. 规则覆盖差异（EndpointParameterPolicy vs AiTaskDispatchService）
  // ==================================================================

  @Nested
  @DisplayName("D. 两份实现的规则覆盖差异（P1-5 修复后：漂移已闭合）")
  class RuleCoverageDrift {

    /**
     * 辅助：断言策略<strong>拒绝</strong>某条载荷，并把 {@code ApiException} 的失败消息一并带上，
     * 便于定位是"哪条规则"生效。
     *
     * <p>⚠️ 注意本组的层次定位：D 组<strong>直接单测</strong> {@code EndpointParameterPolicy}，
     * <strong>不</strong>经 {@code gate.invoke}。因此它只能证明"规则本身正确"，
     * <strong>不能</strong>证明"规则在调用链上"。后者由 F 组经完整 {@code gate.invoke} 负责。
     * 这个区分是本类三版结论最重要的方法论遗产。
     */
    private void assertPolicyRejects(Map<String, Object> body) {
      EndpointParameterPolicy policy = new EndpointParameterPolicy(new PortRangeParser(), 1024);
      AuthorizedTarget t = target(1L, "192.168.10.10", "8080,8085");
      com.bachelor.toolbox.common.ApiException error =
          org.junit.jupiter.api.Assertions.assertThrows(
              com.bachelor.toolbox.common.ApiException.class,
              () -> policy.validateTaskCreationBody(t, body),
              "P1-5 修复后该漂移应已闭合：策略必须拒绝此载荷");
      org.junit.jupiter.api.Assertions.assertNotNull(
          error.getMessage(), "拒绝必须给出可归因的理由");
    }

    /**
     * <strong>D-1（已修复）</strong>：{@code http_security_check} 的 {@code check} 取值白名单。
     *
     * <p>修复前 {@code EndpointParameterPolicy} 完全没有这条规则，因此经 {@code invoke_endpoint}
     * 传 {@code check="anything"} 会通过护栏，而直接调用会被拒（漂移）。
     *
     * <p>P1-5 D-1 修复后，策略调用 {@code ToolParameterSpec.requireHttpCheck} 校验取值枚举
     * ——<strong>与执行侧共用同一份常量</strong>，因此不存在"两份字面量再次漂移"的可能。
     * 本用例由"断言放行"翻转为"断言拒绝"。
     */
    @Test
    @DisplayName("D-1 已修复：http_security_check 的 check 取值白名单在护栏侧生效（拒绝）")
    void driftHttpSecurityCheckValueIsNowValidatedByPolicy() {
      assertPolicyRejects(
          params(
              "toolCode",
              "http_security_check",
              "parameters",
              params("check", "NOT_A_SUPPORTED_CHECK")));
    }

    /**
     * <strong>D-2（已修复）</strong>：{@code nmap_service_scan} 的 {@code mode} 取值白名单
     * （执行侧限制 quick/service）。P1-5 D-2 修复后由 {@code ToolParameterSpec.requireNmapMode} 校验。
     */
    @Test
    @DisplayName("D-2 已修复：nmap mode 取值白名单在护栏侧生效（拒绝）")
    void driftNmapModeIsNowValidatedByPolicy() {
      assertPolicyRejects(
          params(
              "toolCode",
              "nmap_service_scan",
              "parameters",
              params("ports", "8080", "mode", "NOT_A_SUPPORTED_MODE")));
    }

    /**
     * <strong>D-3（已修复）</strong>：{@code fscan_scan} 的 {@code vulnMode} 取值白名单
     * （执行侧限制 SAFE/FINGERPRINT/FULL）。
     *
     * <p>这条不只是"取值不规范"：{@code FULL} 会启用漏洞利用类检测，而 {@code SAFE} 不会。
     * 修复前允许任意取值意味着 Agent 可以请求比"直接调用"更激进的扫描模式。
     * P1-5 D-3 修复后由 {@code ToolParameterSpec.requireFscanVulnMode} 校验。
     */
    @Test
    @DisplayName("D-3 已修复：fscan vulnMode 取值白名单在护栏侧生效（拒绝任意模式）")
    void driftFscanVulnModeIsNowValidatedByPolicy() {
      assertPolicyRejects(
          params(
              "toolCode",
              "fscan_scan",
              "parameters",
              params("ports", "8080", "vulnMode", "ARBITRARY_MODE")));
    }

    /**
     * <strong>D-4（已修复）</strong>：{@code zap_scan} 的 {@code spider}/{@code strength} 类型与取值校验。
     *
     * <p>P1-5 D-4 修复后：{@code strength} 由 {@code ToolParameterSpec.requireZapStrength} 校验枚举，
     * {@code spider} 必须是布尔。本载荷两个条件同时违反，任一条件生效都会拒绝。
     */
    @Test
    @DisplayName("D-4 已修复：zap_scan 的 spider 类型与 strength 取值校验在护栏侧生效（拒绝）")
    void driftZapScanParametersAreNowValidatedByPolicy() {
      assertPolicyRejects(
          params(
              "toolCode",
              "zap_scan",
              "parameters",
              params("spider", "not-a-boolean", "strength", "NOT_A_LEVEL")));
    }

    /**
     * <strong>D-5（已修复 · 安全级差异）</strong>：{@code sqlmap_scan} 的
     * {@code TargetPolicyService.validatedHttpUri(target, path)} 主机/端口一致性校验。
     *
     * <p>修复前：直接调用 {@code sqlmap_scan} 时 {@code path} 的主机必须与授权目标一致
     * （防 SSRF 到第三方主机），经 {@code invoke_endpoint} 调用时这条校验不存在。
     *
     * <p>P1-5 D-5 修复后，{@code EndpointParameterPolicy} 注入 {@code TargetPolicyService}
     * 并对其 10 处调用逐工具对齐。本载荷 {@code path} 指向 {@code 169.254.169.254}
     * 而授权目标是 {@code 192.168.10.10} → 主机不一致 → 拒绝。
     *
     * <p>⚠️ 注意装配前提：本用例显式用<strong>三参构造</strong>注入 {@code TargetPolicyService}
     * （见 {@link #assertUriPolicyRejects}），因为 D-5 是<strong>可空依赖</strong>——
     * 未注入时该项校验按设计跳过（向后兼容的降级）。生产装配必须注入。
     */
    @Test
    @DisplayName("D-5 已修复：sqlmap path 的主机一致性校验在护栏侧生效（SSRF 面已关闭）")
    void driftSqlmapPathHostConsistencyIsNowValidatedByPolicy() {
      assertUriPolicyRejects(
          params(
              "toolCode",
              "sqlmap_scan",
              "parameters",
              params("path", "http://169.254.169.254/latest/meta-data/?x=1")));
    }

    /**
     * 辅助：用<strong>注入了 {@code TargetPolicyService}</strong> 的策略断言拒绝（D-5 专用）。
     *
     * <p>与 {@link #assertPolicyRejects} 的区别：后者用两参构造（{@code targetPolicyService == null}），
     * 会<strong>跳过</strong> URI/主机校验。要验证 D-5 必须显式注入。
     */
    private void assertUriPolicyRejects(Map<String, Object> body) {
      EndpointParameterPolicy policy =
          new EndpointParameterPolicy(
              new PortRangeParser(),
              1024,
              new com.bachelor.toolbox.target.TargetPolicyService(false, new PortRangeParser()));
      org.junit.jupiter.api.Assertions.assertTrue(
          policy.hasTargetPolicyService(), "前置条件：D-5 校验需要注入 TargetPolicyService");
      AuthorizedTarget t = target(1L, "192.168.10.10", "8080,8085");
      org.junit.jupiter.api.Assertions.assertThrows(
          com.bachelor.toolbox.common.ApiException.class,
          () -> policy.validateTaskCreationBody(t, body),
          "注入了 TargetPolicyService 后，主机不一致的 path 必须被拒绝");
    }

    /**
     * <strong>D-6（已修复 · 结构性）</strong>：{@code isTaskCreationEndpoint} 从"单端点硬编码"
     * 改为<strong>双轨判定</strong>。
     *
     * <p>修复前只认 {@code POST /api/tasks} 与 {@code POST /api/tasks/}，导致实测的 13 个
     * 同类"参数透传型/触发执行型"端点全部不受管。
     *
     * <p>P1-5 D-6 修复后采用双轨：
     *
     * <ol>
     *   <li><strong>语义特征轨</strong>（主）：请求体含 {@code toolCode} + {@code parameters}/{@code targetId}
     *       → 一定是工具执行，<strong>新增端点自动被覆盖，无需维护列表</strong>
     *   <li><strong>路径模式轨</strong>（兜底）：覆盖"不通过 body 传 toolCode 但确实触发执行"的端点
     * </ol>
     *
     * <p>本用例由"断言缺口存在"翻转为"断言缺口已闭合"，并<strong>同时验证两轨都生效</strong>：
     * 用带 {@code toolCode} 的 body 验证语义轨（路径故意用一个<strong>不在任何模式表里</strong>的新端点，
     * 证明覆盖不依赖硬编码列表）；再用 {@code body=null} 验证路径模式轨。
     */
    @Test
    @DisplayName("D-6 已修复：策略覆盖从单端点扩展为双轨（语义特征 + 路径模式）")
    void policyNowCoversAllTaskCreationPaths() {
      // 基线：原有两个写法仍必须覆盖（不回归）。
      org.junit.jupiter.api.Assertions.assertTrue(
          EndpointParameterPolicy.isTaskCreationEndpoint("POST", "/api/tasks"));
      org.junit.jupiter.api.Assertions.assertTrue(
          EndpointParameterPolicy.isTaskCreationEndpoint("POST", "/api/tasks/"));

      // 轨 ②（路径模式）：修复前不覆盖、修复后必须覆盖的端点。
      for (String nowCovered :
          new String[] {
            "/api/tasks/1/retry",
            "/api/regression/findings/1/retest",
            "/api/scan-schedules",
            "/api/projects/7/discovery/probe",
            "/api/post-scan-paths/plans"
          }) {
        org.junit.jupiter.api.Assertions.assertTrue(
            EndpointParameterPolicy.isTaskCreationEndpoint("POST", nowCovered),
            nowCovered + " 修复后必须被路径模式轨覆盖");
      }

      // 轨 ①（语义特征）：路径<strong>不在任何模式表</strong>里，但 body 是工具执行三元组 → 必须覆盖。
      // 这证明覆盖能力来自"语义识别"而非"枚举更多路径"，因此未来新增端点自动受管。
      org.junit.jupiter.api.Assertions.assertTrue(
          EndpointParameterPolicy.isTaskCreationEndpoint(
              "POST",
              "/api/brand-new-endpoint-nobody-listed",
              params("toolCode", "tcp_ports", "parameters", params("ports", "80"))),
          "语义特征轨必须覆盖任意新端点（body 含 toolCode + parameters）");

      // 反面对照：GET 不触发（避免把只读端点误判为任务创建），且空 body 的非执行路径不触发。
      org.junit.jupiter.api.Assertions.assertFalse(
          EndpointParameterPolicy.isTaskCreationEndpoint(
              "GET",
              "/api/tasks",
              params("toolCode", "tcp_ports", "parameters", params("ports", "80"))),
          "GET 不应被判定为任务创建端点");
      org.junit.jupiter.api.Assertions.assertFalse(
          EndpointParameterPolicy.isTaskCreationEndpoint(
              "POST", "/api/settings/theme", params("theme", "dark")),
          "非工具执行的 POST 不应被误判（避免误触发只导致多校验，但错误分类仍需避免）");
    }

    /**
     * <strong>漂移 D-5 的攻击面实测（Lead 指定：云元数据 SSRF）—— 修复后已关闭</strong>。
     *
     * <p>载荷：{@code sqlmap_scan} 的 {@code path} 指向云元数据服务 {@code http://169.254.169.254/...}，
     * 而授权目标是 {@code 192.168.10.10}。
     *
     * <p><strong>修复前</strong>：护栏侧完全没有这条规则 → 经原语调用可穿透（这是本用例最初的断言）。
     *
     * <p><strong>修复后（P1-5 D-5）</strong>：护栏侧注入 {@code TargetPolicyService}，
     * 与 dispatch 层做同样的"path 的主机必须等于授权目标主机"校验 → <strong>拒绝</strong>。
     * 本用例翻转为断言拒绝，并<strong>保留原有的反向证明</strong>：
     * 用同一个 {@code TargetPolicyService} 直接验证语义，说明两份实现现在行为一致（漂移闭合）。
     */
    @Test
    @DisplayName("D-5 攻击面已关闭：sqlmap path 指向云元数据 169.254.169.254 → 护栏侧拒绝")
    void driftSqlmapPathCloudMetadataSsrfIsNowRejected() {
      AuthorizedTarget t = target(1L, "192.168.10.10", "8080,8085");
      String metadataUrl = "http://169.254.169.254/latest/meta-data/iam/security-credentials/?x=1";

      // 护栏侧：注入 TargetPolicyService 后必须拒绝（这是 D-5 修复的核心）。
      assertUriPolicyRejects(
          params("toolCode", "sqlmap_scan", "parameters", params("path", metadataUrl)));

      // 反向证明：dispatch 层一直有这条规则（两份实现现在行为一致 = 漂移闭合）。
      com.bachelor.toolbox.target.TargetPolicyService policyService =
          new com.bachelor.toolbox.target.TargetPolicyService(false, new PortRangeParser());
      org.junit.jupiter.api.Assertions.assertThrows(
          com.bachelor.toolbox.common.ApiException.class,
          () -> policyService.validatedHttpUri(t, metadataUrl),
          "TargetPolicyService 必须拒绝与授权目标主机不一致的 path（护栏侧现在也套用了这条规则）");

      // 对照组：path 主机与授权目标一致时，同一策略必须放行 —— 证明不是"一律拒绝"。
      // 注意：TargetPolicyService.validatedHttpUri(target, path) 会先校验授权目标自身基址的端口
      // （targetValue 不带端口时默认 80），因此这里必须用一个端口确实被授权的目标，
      // 否则失败原因是"目标基址端口未授权"而非"路径主机不一致"——那是错误层/错误原因的伪通过。
      // 且 targetValue 必须带 scheme（URI.create("192.168.10.10:8080") 会把 IP 当成 scheme）。
      AuthorizedTarget targetWithPort = target(3L, "http://192.168.10.10:8080", "8080,8085");
      EndpointParameterPolicy policy =
          new EndpointParameterPolicy(
              new PortRangeParser(),
              1024,
              new com.bachelor.toolbox.target.TargetPolicyService(false, new PortRangeParser()));
      org.junit.jupiter.api.Assertions.assertDoesNotThrow(
          () ->
              policy.validateTaskCreationBody(
                  targetWithPort,
                  params(
                      "toolCode",
                      "sqlmap_scan",
                      "parameters",
                      params("path", "http://192.168.10.10:8080/?id=1"))),
          "path 主机与授权目标一致时必须放行，否则是误伤合法输入");
    }

    /**
     * <strong>漂移 D-3 的攻击面实测 —— 修复后已关闭</strong>：{@code fscan_scan} 的 {@code vulnMode}
     * 取值枚举。
     *
     * <p>修复前护栏侧对任意非法取值（如 {@code ARBITRARY_MODE}）也不拒绝。
     * P1-5 D-3 修复后由 {@code ToolParameterSpec.requireFscanVulnMode} 校验。
     *
     * <p>本用例<strong>拆成两条断言</strong>，这正是"规则生效"与"规则写死"的分水岭：
     *
     * <ul>
     *   <li>{@code FULL} 是执行侧<strong>允许</strong>的取值 → 必须<strong>放行</strong>
     *   <li>{@code ARBITRARY_MODE} 是<strong>非法</strong>取值 → 必须<strong>拒绝</strong>
     * </ul>
     *
     * <p>如果只断言"任意取值都被拒"，就会把"枚举校验生效"与"护栏无条件拒绝"混为一谈（新的伪通过）。
     */
    @Test
    @DisplayName("D-3 攻击面已关闭：fscan vulnMode 枚举生效（FULL 放行 / ARBITRARY 拒绝）")
    void driftFscanVulnModeIsNowEnumerated() {
      EndpointParameterPolicy policy = new EndpointParameterPolicy(new PortRangeParser(), 1024);
      AuthorizedTarget t = target(1L, "192.168.10.10", "8080,8085");

      // 合法取值 FULL：执行侧允许 → 护栏侧必须同样放行（对照组，证明没有误伤）。
      org.junit.jupiter.api.Assertions.assertDoesNotThrow(
          () ->
              policy.validateTaskCreationBody(
                  t,
                  params(
                      "toolCode", "fscan_scan", "parameters",
                      params("ports", "8080", "vulnMode", "FULL"))),
          "FULL 是执行侧允许的取值，护栏侧必须放行（否则是过度拦截）");

      // 非法取值：必须拒绝。
      org.junit.jupiter.api.Assertions.assertThrows(
          com.bachelor.toolbox.common.ApiException.class,
          () ->
              policy.validateTaskCreationBody(
                  t,
                  params(
                      "toolCode", "fscan_scan", "parameters",
                      params("ports", "8080", "vulnMode", "ARBITRARY_MODE"))),
          "非法 vulnMode 必须被拒绝（D-3 修复的核心）");
    }
  }

  // ==================================================================
  // E. 端点原语的三重约束（§6.5）
  // ==================================================================

  @Nested
  @DisplayName("E. 端点原语三重约束")
  class TripleConstraint {

    /** 未注册端点：必须拒绝，且拒因是"未知端点"。 */
    @Test
    @DisplayName("E-1 未注册端点 → 拒绝")
    void unregisteredEndpointIsDenied() {
      GuardSupport.Fixture fixture = invokeEndpointFixture();
      assertDeniedAt(
          CapabilityDeniedException.Layer.PARAMETER,
          "INVALID_PARAMETER",
          () ->
              fixture
                  .gate()
                  .invoke(
                      InvokeEndpointCapability.CODE,
                      params("method", "GET", "path", "/api/definitely-not-exist"),
                      approved()));
    }

    /** 黑名单端点（系统关机）：必须拒绝，且拒因是黑名单而非"未注册"。 */
    @Test
    @DisplayName("E-2 黑名单端点 POST /api/system/shutdown → 拒绝")
    void blacklistedEndpointIsDenied() {
      GuardSupport.Fixture fixture = invokeEndpointFixture();
      CapabilityDeniedException error =
          assertDeniedAt(
              CapabilityDeniedException.Layer.ADMISSION,
              "BLOCKED_CAPABILITY",
              () ->
                  fixture
                      .gate()
                      .invoke(
                          InvokeEndpointCapability.CODE,
                          params("method", "POST", "path", "/api/system/shutdown"),
                          approved()));
      org.junit.jupiter.api.Assertions.assertTrue(
          error.getMessage().contains("/api/system/shutdown"),
          "拒绝消息应指明被禁端点，实际: " + error.getMessage());
    }

    /** 路径穿越：必须拒绝，且拒因是路径（L-C）。 */
    @Test
    @DisplayName("E-3 路径含 ../ → 拒绝（L-C）")
    void pathTraversalIsDenied() {
      GuardSupport.Fixture fixture = invokeEndpointFixture();
      assertDeniedAt(
          CapabilityDeniedException.Layer.PARAMETER,
          "PATH_TRAVERSAL",
          () ->
              fixture
                  .gate()
                  .invoke(
                      InvokeEndpointCapability.CODE,
                      params("method", "GET", "path", "/api/tasks/../settings/data"),
                      approved()));
    }

    /**
     * <strong>路径穿越的编码变体</strong>：{@code %2e%2e} 必须同样被拦。
     *
     * <p>这是清单 B-25 的核心：若只检查字面 {@code ..}，编码变体会穿透到 PathNormalizer；虽然 PathNormalizer 也会拒绝，
     * 但那时拒因是"非法路径"而非"路径穿越"——两者都拒绝，属于可接受。本用例断言"拒绝"并记录实际层。
     */
    @Test
    @DisplayName("E-4 路径含 %2e%2e 编码变体 → 必须拒绝")
    void encodedPathTraversalIsDenied() {
      GuardSupport.Fixture fixture = invokeEndpointFixture();
      CapabilityDeniedException error =
          org.junit.jupiter.api.Assertions.assertThrows(
              CapabilityDeniedException.class,
              () ->
                  fixture
                      .gate()
                      .invoke(
                          InvokeEndpointCapability.CODE,
                          params("method", "GET", "path", "/api/tasks/%2e%2e/settings/data"),
                          approved()));
      org.junit.jupiter.api.Assertions.assertEquals(
          CapabilityDeniedException.Layer.PARAMETER,
          error.layer(),
          "编码变体必须在 L-C 被拦，实际层 " + error.layer().label());
    }
  }

  // ==================================================================
  // F. 可达性：body 通道在生产配置下是否真的能走通
  // ==================================================================

  @Nested
  @DisplayName("F. 可达性：L-C' 在两种配置下都真正被执行（修复后）")
  class Reachability {

    /**
     * <strong>F-1：{@code ENFORCE} 下带 body 的调用能过 schema，直达 L-C'。</strong>
     *
     * <p><strong>修复前</strong>：{@code InvokeEndpointCapability.parameterSchema()} 把 {@code body} 声明为
     * 裸 {@code "type":"object"}（无 {@code properties}），而顶层 {@code additionalProperties=false}；
     * {@code SchemaValidator} 对嵌套对象的未声明属性同样拒绝 → ENFORCE 下<strong>任何</strong>带 body 的调用
     * 都在 L-C 被 {@code SCHEMA_VIOLATION} 拒掉，根本到不了 L-C'。
     *
     * <p><strong>修复后（P1-4 配套）</strong>：{@code body}/{@code query} 的 schema 增加
     * {@code "additionalProperties": true}，因此 ENFORCE 下 body 内的自由键<strong>不再</strong>被判为
     * "未声明参数"。本用例翻转为断言"ENFORCE 下 body 可过 schema"——但<strong>不是断言放行</strong>：
     * 该载荷仍会因参数越权被 L-C' 拒绝（{@code ENDPOINT_PARAMETER_POLICY}）。
     *
     * <p><strong>关键区分</strong>：修复前的拒因是 L-C 的 {@code SCHEMA_VIOLATION}（形状问题），
     * 修复后的拒因是 L-C' 的 {@code ENDPOINT_PARAMETER_POLICY}（内容问题）。
     * 两者都"拒绝了"，但<strong>只有后者说明参数策略真的生效</strong>。
     * 本用例同时断言层与原因码，正是为了锁死这一区分。
     */
    @Test
    @DisplayName("F-1 ENFORCE 下：body 过 schema，由 L-C' ENDPOINT_PARAMETER_POLICY 拒绝")
    void bodyIsNoLongerRejectedBySchemaInEnforceMode() {
      GuardSupport.Fixture fixture =
          invokeEndpointFixture(com.bachelor.toolbox.ai.guard.CapabilityGate.SchemaMode.ENFORCE);

      // 载荷：合法目标 1，但 toolCode 不在策略白名单（definitely_not_a_tool）→ L-C' 必须拒绝。
      CapabilityDeniedException error =
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
                              "/api/tasks",
                              "body",
                              params(
                                  "projectId", 7L, "targetId", 1L, "toolCode",
                                  "definitely_not_a_tool", "parameters", params())),
                          approved()));

      // 判决性断言：拒因<必须>来自 L-C'（端点参数策略），而<不是> L-C 的 schema 校验。
      // 若这里变成 SCHEMA_VIOLATION，说明 additionalProperties:true 的修复回退了。
      org.junit.jupiter.api.Assertions.assertNotEquals(
          "SCHEMA_VIOLATION",
          error.reasonCode(),
          "ENFORCE 下 body 不应再被 schema 拦下；若为 SCHEMA_VIOLATION，说明 schema 修复已回退");
    }

    /**
     * F-2 对照：{@code ENFORCE} 下<strong>不带 body</strong> 的调用同样能通过 schema。
     *
     * <p>与 F-1 配对，说明 ENFORCE 模式本身没有"拒绝一切"，也说明 F-1 的载荷确实越过了 schema 这一层。
     */
    @Test
    @DisplayName("F-2 对照：ENFORCE 下不带 body 可通过 schema（走到 validateParams）")
    void withoutBodyPassesSchemaInEnforceMode() {
      GuardSupport.Fixture fixture =
          invokeEndpointFixture(com.bachelor.toolbox.ai.guard.CapabilityGate.SchemaMode.ENFORCE);

      // 用不存在的端点，确保拒绝来自"未知端点"（L-C 的 validateParams）而非 schema。
      CapabilityDeniedException error =
          org.junit.jupiter.api.Assertions.assertThrows(
              CapabilityDeniedException.class,
              () ->
                  fixture
                      .gate()
                      .invoke(
                          InvokeEndpointCapability.CODE,
                          params("method", "GET", "path", "/api/does-not-exist"),
                          approved()));
      org.junit.jupiter.api.Assertions.assertEquals(
          "INVALID_PARAMETER",
          error.reasonCode(),
          "不带 body 时应走到 validateParams（未知端点），而不是被 schema 拦下；实际 " + error.reasonCode());
    }

    /**
     * <strong>F-3【四版翻转】{@code WARN}（生产默认）下 body 过 schema 后<u>直达 L-C'</u>。</strong>
     *
     * <p><strong>三版结论（历史）</strong>：WARN 下 body 能过 schema，但紧接着在 L-A 被哨兵
     * {@code TARGET_BINDING_UNRESOLVED} 拒绝——因为 L-A 排在 L-C' 之前，而 {@code targetBindings()}
     * 恒返回哨兵。
     *
     * <p><strong>四版结论（当前）</strong>：P1-4 修复后 body 里的 {@code targetId=1} 被深度解析出来，
     * L-A 放行（目标存在且合法），载荷<strong>第一次真正到达 L-C'</strong>，并由 MSF 模块前缀规则拒绝。
     *
     * <p>本用例的断言从"拒因是 L-A 哨兵"翻转为"拒因是 L-C' 的 {@code ENDPOINT_PARAMETER_POLICY}"。
     * 这直接证明 X-7 的修复点<strong>不再是死代码</strong>。
     */
    @Test
    @DisplayName("F-3【四版翻转】WARN 下 body 过 schema 并直达 L-C'（ENDPOINT_PARAMETER_POLICY）")
    void bodyPassesSchemaAndReachesEndpointParameterPolicyInWarnMode() {
      GuardSupport.Fixture fixture =
          invokeEndpointFixture(com.bachelor.toolbox.ai.guard.CapabilityGate.SchemaMode.WARN);

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
                          "/api/tasks",
                          "body",
                          params(
                              "projectId",
                              7L,
                              "targetId",
                              1L,
                              "toolCode",
                              "msf_scan",
                              "parameters",
                              params("module", "payload/windows/x64/meterpreter"))),
                      approved()));
    }

    /**
     * <strong>F-4【四版翻转 · 本类最重要的用例】{@code WARN}（生产默认）下的端到端链路。</strong>
     *
     * <p><strong>三版结论（历史）</strong>：用完整 {@code gate.invoke} 实测三条载荷，
     * 三条<strong>全部</strong>在 L-A 被哨兵拒绝——包括对照组。三条得到<strong>完全相同</strong>的拒绝理由，
     * 这正是"L-C' 不可达 / 死代码"的判决性证据。
     *
     * <p><strong>四版结论（当前）</strong>：P1-4 修复后 L-A 不再无条件短路，三条载荷
     * <strong>各自得到与其内容相符的拒绝理由</strong>。这恰恰是三版判决的镜像：
     *
     * <table border="1">
     *   <tr><th>载荷</th><th>三版（死代码）</th><th>四版（修复后）</th></tr>
     *   <tr>
     *     <td>① D-3 fscan 任意 vulnMode</td>
     *     <td>L-A 哨兵</td>
     *     <td><strong>L-C' ENDPOINT_PARAMETER_POLICY</strong>（枚举非法）</td>
     *   </tr>
     *   <tr>
     *     <td>② D-1 http_security_check 非法 check</td>
     *     <td>L-A 哨兵</td>
     *     <td><strong>L-C' ENDPOINT_PARAMETER_POLICY</strong>（枚举非法）</td>
     *   </tr>
     *   <tr>
     *     <td>③ 不在白名单的工具码（对照组）</td>
     *     <td>L-A 哨兵</td>
     *     <td><strong>L-C' ENDPOINT_PARAMETER_POLICY</strong>（工具白名单）</td>
     *   </tr>
     * </table>
     *
     * <p>三版说"三条理由完全相同 ⇒ 与载荷无关 ⇒ 策略未执行"；
     * 四版三条理由<strong>仍然相同</strong>，但相同的原因变了——现在它们相同是因为
     * <strong>三条都真的被参数策略拒绝</strong>，而不是因为都被哨兵挡在门外。
     *
     * <p><strong>⚠️ 关于 D-5（云元数据 SSRF）为何不在此处作为载荷</strong>：
     * 本类的 {@code invokeEndpointFixture} 经 {@code GuardSupport.fixture(...)} 装配，其中的
     * {@code EndpointParameterPolicy} 用的是<strong>两参构造</strong>（{@code targetPolicyService == null}）。
     * 按实现约定，此时 D-5 的 URI/主机校验<strong>按设计跳过</strong>（向后兼容的降级），
     * 因此 sqlmap SSRF 载荷在<strong>本夹具下不会被拒绝</strong>。
     *
     * <p>这不是缺陷，而是"夹具未按生产装配"——生产装配由 {@code AgentCapabilityGuardConfiguration}
     * 注入非空的 {@code TargetPolicyService}。因此：
     *
     * <ul>
     *   <li>D-5 的<strong>单元级</strong>验证在 D 组用显式注入三参构造完成（见 {@code assertUriPolicyRejects}）
     *   <li>本用例<strong>不</strong>把 D-5 载荷写成"必须被拒"，否则会得到一个因错误原因失败的用例
     *   <li><strong>遗留缺口（如实记录）</strong>：D-5 在"经完整 {@code gate.invoke}"这一层<strong>尚无</strong>覆盖，
     *       需要一个在夹具里注入 {@code TargetPolicyService} 的端到端用例
     * </ul>
     *
     * <p><strong>这正是"伪通过"规则的又一次应用</strong>：若我照搬三版的载荷清单而不检查夹具装配，
     * 就会把一个"因校验未装配而放行"的载荷误报成"修复失败"，或者反过来放宽断言掩盖缺口。
     * 正确做法是<strong>记录缺口</strong>而不是掩盖它。
     *
     * <p>所以本用例改用<strong>与装配无关</strong>的三条载荷（枚举非法 ×2 + 工具白名单），
     * 它们都只依赖 {@code EndpointParameterPolicy} 自身、不依赖可选的 {@code TargetPolicyService}。
     *
     * <p><strong>这正是"伪通过"规则的价值所在</strong>：只看"是否被拒"永远无法区分这两种情形，
     * 必须看<strong>层与原因码</strong>。所以本用例的关键断言是
     * {@code layer == PARAMETER && reasonCode == ENDPOINT_PARAMETER_POLICY}
     * <strong>且</strong> {@code layer != AUTHORIZATION}。
     */
    @Test
    @DisplayName("F-4【四版翻转】WARN 下三条载荷各自被 L-C' 按内容拒绝 → L-C' 已可达")
    void endToEndChainProvesParameterPolicyIsReachable() {
      GuardSupport.Fixture fixture =
          invokeEndpointFixture(com.bachelor.toolbox.ai.guard.CapabilityGate.SchemaMode.WARN);
      org.junit.jupiter.api.Assertions.assertEquals(
          com.bachelor.toolbox.ai.guard.CapabilityGate.SchemaMode.WARN,
          fixture.gate().schemaMode(),
          "前置条件：本用例必须是生产默认的 WARN 模式");

      // ---- 载荷 1：D-1 http_security_check 非法 check 取值（目标 1 合法，但枚举非法）----
      CapabilityDeniedException e1 =
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
                              "/api/tasks",
                              "body",
                              params(
                                  "projectId",
                                  7L,
                                  "targetId",
                                  1L,
                                  "toolCode",
                                  "http_security_check",
                                  "parameters",
                                  params("check", "NOT_A_SUPPORTED_CHECK"))),
                          approved()));

      // ---- 载荷 2：D-3 fscan 任意 vulnMode（目标 1 合法，但枚举非法）----
      CapabilityDeniedException e2 =
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
                              "/api/tasks",
                              "body",
                              params(
                                  "projectId",
                                  7L,
                                  "targetId",
                                  1L,
                                  "toolCode",
                                  "fscan_scan",
                                  "parameters",
                                  params("ports", "8080", "vulnMode", "ARBITRARY_MODE"))),
                          approved()));

      // ---- 载荷 3（对照组）：不在白名单里的工具码 ----
      CapabilityDeniedException e3 =
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
                              "/api/tasks",
                              "body",
                              params(
                                  "projectId",
                                  7L,
                                  "targetId",
                                  1L,
                                  "toolCode",
                                  "definitely_not_a_tool",
                                  "parameters",
                                  params())),
                          approved()));

      // 判决性断言：三条载荷的拒绝层<必须>是 L-C'（参数层），而<绝不是> L-A 授权层。
      // 三版时这三条全部是 L-A/TARGET_BINDING_UNRESOLVED；现在全部翻转。
      for (CapabilityDeniedException error : java.util.List.of(e1, e2, e3)) {
        org.junit.jupiter.api.Assertions.assertNotEquals(
            CapabilityDeniedException.Layer.AUTHORIZATION,
            error.layer(),
            "L-A 不应再无条件短路；若这里回到 AUTHORIZATION，说明 P1-4 修复已回退（L-C' 重新变成死代码）");
        org.junit.jupiter.api.Assertions.assertEquals(
            CapabilityDeniedException.Layer.PARAMETER,
            error.layer(),
            "拒绝必须来自 L-C'（参数层）");
        org.junit.jupiter.api.Assertions.assertEquals(
            "ENDPOINT_PARAMETER_POLICY",
            error.reasonCode(),
            "必须是端点参数策略原因码，证明 validateEndpointParameterPolicy 真的执行了");
      }

      // 对照组 e3 报的正是三版期待却拿不到的 ENDPOINT_PARAMETER_POLICY —— 死代码判决已被推翻。
      org.junit.jupiter.api.Assertions.assertEquals(
          "ENDPOINT_PARAMETER_POLICY",
          e3.reasonCode(),
          "【判决性证据】对照组已报参数层原因码 → validateEndpointParameterPolicy 确实执行");
    }

    /**
     * <strong>F-5【对照 · 证明 L-C' 本身没坏】</strong>直接单测 {@code EndpointParameterPolicy}，
     * 证明它的规则<strong>确实能拒绝</strong>这些载荷。
     *
     * <p><strong>三版时</strong>这条与 F-4 配对构成最重要的方法论对照：
     * "F-4 说经护栏调用时策略不生效，F-5 说策略单独调用时生效 → 策略不在调用链上"。
     *
     * <p><strong>四版（修复后）</strong>：F-4 已翻转为"经护栏调用时策略<strong>生效</strong>"，
     * 因此 F-5 的角色从"证明策略不在链上"变为<strong>"证明策略单元行为未回退"</strong>——
     * 即"修复是通过接线完成的，而不是通过放松策略完成的"。
     *
     * <p>这个配对关系依然有价值：若 F-4 通过而 F-5 失败，说明策略被改坏了；
     * 若 F-5 通过而 F-4 失败，说明策略又掉出了调用链。两条必须<strong>同时</strong>通过。
     */
    @Test
    @DisplayName("F-5 对照：直接单测 EndpointParameterPolicy → 规则本身有效（防策略侧回退）")
    void parameterPolicyItselfWorksWhenCalledDirectly() {
      EndpointParameterPolicy policy = new EndpointParameterPolicy(new PortRangeParser(), 1024);
      AuthorizedTarget t = target(1L, "192.168.10.10", "8080,8085");

      // 不在白名单里的工具码 → 策略单独调用时<确实>拒绝。
      org.junit.jupiter.api.Assertions.assertThrows(
          com.bachelor.toolbox.common.ApiException.class,
          () ->
              policy.validateTaskCreationBody(
                  t,
                  params(
                      "toolCode", "definitely_not_a_tool", "parameters", params("ports", "8080"))),
          "策略单独调用时必须拒绝未知工具码；若不拒绝，说明策略本身也有缺陷");

      // MSF 非法模块前缀 → 策略单独调用时<确实>拒绝。
      org.junit.jupiter.api.Assertions.assertThrows(
          com.bachelor.toolbox.common.ApiException.class,
          () ->
              policy.validateTaskCreationBody(
                  t,
                  params(
                      "toolCode",
                      "msf_scan",
                      "parameters",
                      params("module", "payload/windows/x64/meterpreter"))),
          "策略单独调用时必须拒绝非法 MSF 模块前缀");
    }

    /**
     * <strong>F-6【补缺口】D-5 云元数据 SSRF 的<u>端到端</u>验证：经完整 {@code gate.invoke} 必须被 L-C' 拒绝。</strong>
     *
     * <h3>为什么需要这条用例</h3>
     *
     * <p>D-5 的 URI/主机校验依赖 {@code EndpointParameterPolicy} 的
     * {@code targetPolicyService} 字段，而该字段是<strong>可空的</strong>：
     * {@code null} 时按设计<strong>跳过</strong> URI/主机校验（向后兼容的降级）。
     *
     * <p>{@code GuardSupport.fixture(...)}（本类其余用例使用的装配）用的是<strong>两参构造</strong>
     * → {@code targetPolicyService == null} → <strong>D-5 在端到端路径上不生效</strong>。
     * 因此修复后 D-5 一度<strong>只有单元级覆盖</strong>（D 组用三参构造显式注入），
     * <strong>没有</strong>"经完整 {@code gate.invoke}"的端到端覆盖——这是一个真实的验证缺口。
     *
     * <p>本用例用 {@code GuardSupport.fixtureWithTargetPolicy(...)}（三参构造、注入
     * {@code TargetPolicyService}）补上该缺口。<strong>这就是本用例存在的全部意义。</strong>
     *
     * <h3>为什么必须在端到端层再验一遍</h3>
     *
     * <p>单元级（D 组）只能证明"策略对象在收到正确参数时会拒绝"。
     * 端到端额外证明了：① 生产装配路径上 {@code TargetPolicyService} <strong>确实被注入</strong>；
     * ② L-A 放行后 L-C' <strong>确实被执行</strong>（层序未被打乱）。
     * 三版报告的教训正是"单元级验证无法发现被测代码不在调用链上"。
     */
    @Test
    @DisplayName("F-6【补缺口】D-5 端到端：sqlmap 云元数据 SSRF 经 gate.invoke 被 L-C' 拒绝")
    void sqlmapCloudMetadataSsrfIsDeniedEndToEnd() {
      // 装配差异说明：fixtureWithTargetPolicy 与 fixture 的唯一区别是 EndpointParameterPolicy
      // 用三参构造注入 TargetPolicyService → D-5 生效。
      EndpointRegistry endpointRegistry = new EndpointRegistry();
      EndpointCapability underlying = EndpointCapability.derive("POST", "/api/tasks", "创建扫描任务");
      endpointRegistry.register(underlying);
      InvokeEndpointCapability invoke =
          new InvokeEndpointCapability(
              endpointRegistry,
              new com.bachelor.toolbox.ai.capability.CapabilityRegistry(List.of()));

      // ⚠️ 必须用一个"基址端口确实被授权"的目标，否则失败原因会是
      // TargetPolicyService.validatedHttpUri(target) 对**基址**的端口校验（targetValue 不带端口时
      // 默认 80，而目标 1 只授权 8080,8085）——那是"目标基址端口未授权"，
      // **不是** D-5 的"路径主机与授权目标不一致"。两者层与原因码相同（都是 L-C' +
      // ENDPOINT_PARAMETER_POLICY），只看断言无法区分 —— 这正是本类反复强调的伪通过形态。
      Map<Long, AuthorizedTarget> targetsWithPort =
          Map.of(1L, target(1L, "http://192.168.10.10:8080", "8080,8085"));

      GuardSupport.Fixture fixture =
          GuardSupport.fixtureWithTargetPolicy(
              List.of(invoke, underlying), targetsWithPort, InvokeEndpointCapability.CODE);

      // 攻击载荷：授权目标 1（192.168.10.10:8080），但 sqlmap 实际请求云元数据服务 169.254.169.254。
      // 这是 SSRF：授权校验只比对 targetId 对应的主机，而工具真正请求的 URL 由 parameters 决定。
      CapabilityDeniedException error =
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
                              "/api/tasks",
                              "body",
                              params(
                                  "projectId",
                                  7L,
                                  "targetId",
                                  1L,
                                  "toolCode",
                                  "sqlmap_scan",
                                  "parameters",
                                  params(
                                      "path",
                                      "http://169.254.169.254/latest/meta-data/iam/security-credentials/"))),
                          approved()));

      // 伪通过防线：拒绝必须来自 L-C'（参数层），而不是 L-A 授权层。
      // 若这里是 AUTHORIZATION，说明目标解析或授权环节出了问题，D-5 本身并未被验证到。
      org.junit.jupiter.api.Assertions.assertNotEquals(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          error.layer(),
          "拒绝必须来自 L-C'（D-5 主机校验），而不是 L-A —— 否则本用例并未验证到 D-5");
      // 精确断言拒绝理由<就是>主机不一致，而不是碰巧同层同码的其它规则（如基址端口）。
      org.junit.jupiter.api.Assertions.assertTrue(
          error.getMessage().contains("主机"),
          "拒绝理由必须是'路径主机与授权目标不一致'（D-5），实际: " + error.getMessage());

      // ---- 对照组：同一能力 + 合法 path（主机与授权目标一致）必须放行 ----
      // 证明 D-5 不是"一律拒绝"，即修复未误伤合法输入。
      CapabilityOutcome allowed =
          org.junit.jupiter.api.Assertions.assertDoesNotThrow(
              () ->
                  fixture
                      .gate()
                      .invoke(
                          InvokeEndpointCapability.CODE,
                          params(
                              "method",
                              "POST",
                              "path",
                              "/api/tasks",
                              "body",
                              params(
                                  "projectId",
                                  7L,
                                  "targetId",
                                  1L,
                                  "toolCode",
                                  "sqlmap_scan",
                                  "parameters",
                                  params("path", "http://192.168.10.10:8080/?id=1"))),
                          approved()),
              "path 主机与授权目标一致时必须放行，否则 D-5 误伤了合法输入");

      org.junit.jupiter.api.Assertions.assertEquals(
          "APPLIED",
          allowed.auditDetail().get("endpointParameterPolicy"),
          "对照组必须真的经过 L-C'（endpointParameterPolicy=APPLIED），"
              + "否则'放行'可能只是因为 L-C' 被跳过");
    }
  }
}
