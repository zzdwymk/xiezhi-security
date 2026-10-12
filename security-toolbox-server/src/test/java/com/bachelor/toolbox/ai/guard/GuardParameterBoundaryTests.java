package com.bachelor.toolbox.ai.guard;

import static com.bachelor.toolbox.ai.guard.GuardSupport.assertAllowed;
import static com.bachelor.toolbox.ai.guard.GuardSupport.assertDeniedAt;
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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * 参数越权与路径绕过的对抗验证（清单 B-24..B-34、B-49..B-57、G-08）。
 *
 * <h2>本类关注的绕过面</h2>
 *
 * <ol>
 *   <li><strong>路径穿越的全部编码变体</strong>：{@code ../}、{@code %2e%2e}、{@code //}、大小写、分号路径参数、
 *       Unicode 同形字、空字节。{@code CapabilityGate.rejectPathTraversal}（{@code :745-765}）只匹配字面
 *       {@code ".."} / {@code "%2e"} / {@code "%2E"}，其余变体依赖 {@code PathNormalizer}。
 *   <li><strong>端口表达歧义</strong>：{@code "80-443"} vs {@code "80,443"}、带空格、前导零、起止倒置、空串。
 *   <li><strong>参数键名混淆</strong>：{@code port}/{@code ports}/{@code portRange}/{@code port_range}，
 *       以及大小写与下划线变体——护栏的 {@code requestedPorts} 声称识别这些（{@code :632-645}）。
 * </ol>
 *
 * <h2>为什么必须区分"哪一层拒绝"</h2>
 *
 * <p>路径穿越用例最容易产生<strong>伪通过</strong>：护栏可能在 L-C 因为"参数含 ../"拒绝，也可能因为"端点未注册"拒绝，
 * 还可能在 L-A 因为"无法解析目标"拒绝。三者结论相同、安全含义完全不同。本类逐条断言具体层与原因码。
 */
@DisplayName("参数越权与路径绕过对抗验证")
class GuardParameterBoundaryTests {

  private static final Map<Long, AuthorizedTarget> TARGETS =
      Map.of(1L, target(1L, "192.168.10.10", "80,443"));

  private static CapabilityContext approved() {
    return CapabilityContext.of("ai-agent", 7L).approved(1L);
  }

  // ==================================================================
  // 路径穿越
  // ==================================================================

  @Nested
  @DisplayName("路径穿越（B-24..B-34）")
  class PathTraversal {

    /** 能力桩：绑定目标 1，参数里带 {@code path} 键（触发 {@code rejectPathTraversal}）。 */
    private AgentCapability pathCapability(String code) {
      return GuardSupport.DeclaredStub.of(
          code,
          CapabilityKind.EXECUTE,
          RiskLevel.SENSITIVE,
          Set.of("1"),
          TargetBindingProbe.Declaration.REQUIRED);
    }

    /**
     * 字面 {@code ../} → 必须由 L-C 的 {@code PATH_TRAVERSAL} 拒绝。
     *
     * <p>这是 §9.5 的原始用例（G-08）。
     */
    @Test
    @DisplayName("B-24a 字面 ../ → L-C / PATH_TRAVERSAL")
    void literalDotDotSlashIsRejected() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(pathCapability("path_probe")), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.PARAMETER,
          "PATH_TRAVERSAL",
          () ->
              fixture
                  .gate()
                  .invoke("path_probe", params("path", "/api/tasks/../settings/data"), approved()));
    }

    /** Windows 反斜杠 {@code ..\}：{@code rejectPathTraversal} 只看 {@code ".."}，因此仍应命中。 */
    @Test
    @DisplayName("B-24b 反斜杠 ..\\ → 必须拒绝（PATH_TRAVERSAL）")
    void backslashTraversalIsRejected() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(pathCapability("path_probe_bs")), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.PARAMETER,
          "PATH_TRAVERSAL",
          () ->
              fixture
                  .gate()
                  .invoke(
                      "path_probe_bs",
                      params("path", "/api/..\\..\\settings\\data"),
                      approved()));
    }

    /**
     * 百分号编码 {@code %2e%2e} → {@code rejectPathTraversal} 的标记集包含 {@code "%2e"}/{@code "%2E"}，
     * 因此应报 {@code PATH_TRAVERSAL}。
     */
    @Test
    @DisplayName("B-25a %2e%2e 编码 → 拒绝（PATH_TRAVERSAL）")
    void percentEncodedTraversalIsRejected() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(pathCapability("path_probe_enc")), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.PARAMETER,
          "PATH_TRAVERSAL",
          () ->
              fixture
                  .gate()
                  .invoke(
                      "path_probe_enc", params("path", "/api/%2e%2e/settings/data"), approved()));
    }

    /**
     * <strong>双重编码 {@code %252e%252e}</strong>：{@code rejectPathTraversal} 的字面匹配
     * <strong>不会</strong>命中（因为字符串里是 {@code %252e} 而非 {@code %2e}）。
     *
     * <p><strong>实测结果：放行。</strong> 但必须准确界定其含义——本夹具的能力桩<strong>没有端点注册表</strong>，
     * 参数 {@code path} 只是被当作普通字符串。因此本用例证明的是：
     *
     * <blockquote>
     * {@code rejectPathTraversal} 是<strong>启发式</strong>检查（只匹配字面 {@code ..} / {@code %2e} / {@code %2E}），
     * 它<strong>不是</strong>路径穿越的完备防线。
     * </blockquote>
     *
     * <p><strong>这不等于"可穿透到系统"</strong>：真实路径穿越能否成功取决于下游是否二次解码、以及
     * {@code PathNormalizer} / 端点注册表是否拒绝该写法。那需要端点注册表在场的测试（见
     * {@link GuardLayerOrderTests#blacklistPathVariantsMustStillBeDenied}）。
     * 本用例<strong>不</strong>声称"存在可穿透的漏洞"，只声称"该规则覆盖不全"。
     */
    @Test
    @DisplayName("B-25b 双重编码 %252e%252e → rejectPathTraversal 不命中（启发式边界，非可穿透证明）")
    void doubleEncodedTraversalEscapesTheHeuristic() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(pathCapability("path_probe_dbl")), TARGETS);

      GuardSupport.assertAllowed(
          () ->
              fixture
                  .gate()
                  .invoke(
                      "path_probe_dbl",
                      params("path", "/api/%252e%252e/settings/data"),
                      approved()),
          "字面匹配不覆盖双重编码；这不等于可穿透（下游可能二次解码后拒绝）");
    }

    /** 重复斜杠 {@code //}：字面匹配不命中 → 放行（启发式边界）。 */
    @Test
    @DisplayName("B-26a 重复斜杠 //api//settings//data → 启发式不命中 → 放行")
    void doubleSlashEscapesTheHeuristic() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(pathCapability("path_probe_ds")), TARGETS);

      GuardSupport.assertAllowed(
          () ->
              fixture
                  .gate()
                  .invoke("path_probe_ds", params("path", "//api//settings//data"), approved()));
    }

    /** 单点段 {@code /./}：字面匹配不命中 → 放行（启发式边界）。 */
    @Test
    @DisplayName("B-26b 单点段 /./ → 启发式不命中 → 放行")
    void singleDotSegmentEscapesTheHeuristic() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(pathCapability("path_probe_dot")), TARGETS);

      GuardSupport.assertAllowed(
          () ->
              fixture
                  .gate()
                  .invoke("path_probe_dot", params("path", "/api/./settings/data"), approved()));
    }

    /** 空字节 {@code %00}：{@code rejectPathTraversal} 不检查它 → 放行（启发式边界）。 */
    @Test
    @DisplayName("B-34 空字节 %00 → 启发式不检查 → 放行")
    void nullByteEscapesTheHeuristic() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(pathCapability("path_probe_nul")), TARGETS);

      GuardSupport.assertAllowed(
          () ->
              fixture
                  .gate()
                  .invoke(
                      "path_probe_nul", params("path", "/api/settings/data%00.html"), approved()));
    }

    /**
     * <strong>键名逃逸（B-31）</strong>：{@code rejectPathTraversal} 只检查键名含
     * {@code path}/{@code url}/{@code uri} 的参数。
     *
     * <p>绕过设想：把穿越载荷放在<strong>键名不含这三个词</strong>的参数里（如 {@code target}、{@code dest}），
     * 该规则就看不到它。本用例断言该载荷<strong>不被 PATH_TRAVERSAL 拦下</strong>——把规则的覆盖边界固化为事实。
     *
     * <p>这不必然是漏洞（载荷最终能否生效取决于下游是否把它当路径用），但它说明
     * {@code rejectPathTraversal} 是<strong>启发式</strong>而非完备检查，报告里应如此陈述。
     */
    @Test
    @DisplayName("B-31 键名逃逸：载荷放在非 path/url/uri 键里 → PATH_TRAVERSAL 规则看不到")
    void traversalInNonPathKeyEscapesTheHeuristic() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(pathCapability("path_probe_key")), TARGETS);

      // 键名 "dest" 不含 path/url/uri → rejectPathTraversal 跳过；绑定合法且无端口问题 → 放行。
      GuardSupport.assertAllowed(
          () ->
              fixture
                  .gate()
                  .invoke(
                      "path_probe_key",
                      params("dest", "/api/tasks/../settings/data"),
                      approved()));
    }
  }

  // ==================================================================
  // 端口表达
  // ==================================================================

  @Nested
  @DisplayName("端口表达歧义（B-49..B-50）")
  class PortExpressions {

    private AgentCapability portCapability(String code) {
      return GuardSupport.DeclaredStub.of(
          code,
          CapabilityKind.EXECUTE,
          RiskLevel.SENSITIVE,
          Set.of("1"),
          TargetBindingProbe.Declaration.REQUIRED);
    }

    /** 授权 {@code 80,443}，请求 {@code "80,22"} → 22 越权，必须拒绝。 */
    @Test
    @DisplayName("B-49a 请求 80,22（授权 80,443）→ PORT_OUT_OF_SCOPE")
    void partiallyAuthorizedPortListIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe")), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_OUT_OF_SCOPE",
          () -> fixture.gate().invoke("port_probe", params("ports", "80,22"), approved()));
    }

    /** 前导零 {@code "080"}：{@code Integer.parseInt("080")} = 80 → 在授权范围内，应放行。 */
    @Test
    @DisplayName("B-50a 前导零 080 → 解析为 80，应放行（等价写法）")
    void leadingZeroPortIsParsed() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe_zero")), TARGETS);

      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("port_probe_zero", params("ports", "080"), approved()));
    }

    /** 带空格 {@code "80, 443"}：按 {@code [,;\s]+} 切分 → 应放行。 */
    @Test
    @DisplayName("B-50b 带空格 80, 443 → 应放行")
    void whitespaceSeparatedPortsAreParsed() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe_ws")), TARGETS);

      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("port_probe_ws", params("ports", "80, 443"), approved()));
    }

    /** 分号分隔 {@code "80;443"}：按 {@code [,;\s]+} 切分 → 应放行。 */
    @Test
    @DisplayName("B-50c 分号分隔 80;443 → 应放行")
    void semicolonSeparatedPortsAreParsed() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe_semi")), TARGETS);

      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("port_probe_semi", params("ports", "80;443"), approved()));
    }

    /**
     * <strong>起止倒置 {@code "443-80"}（P0-1 修复后：拒绝）</strong>。
     *
     * <p>修复前 {@code collectPorts} 要求 {@code from <= to}，否则该 token 被<strong>静默跳过</strong>，
     * 导致 {@code requestedPorts} 返回空集 → 端口校验"无事可做"→ <strong>放行</strong>（fail-open）。
     *
     * <p>P0-1 修复后 {@code collectPorts} 对无法解析的 token <strong>抛 {@code ApiException}</strong>，
     * {@code validateRequestedPorts} 把它归一化为 <strong>L-A + {@code PORT_UNPARSEABLE}</strong>。
     *
     * <p>⚠️ 本类此前断言"当前放行"以固化漏洞状态，现已翻转为断言拒绝。
     * 详细机制与端到端证明见 {@link GuardPortFailOpenTests}。
     */
    @Test
    @DisplayName("B-49b 起止倒置 443-80 → L-A PORT_UNPARSEABLE 拒绝（fail-open 已闭合）")
    void invertedPortRangeIsRejected() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe_inv")), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_UNPARSEABLE",
          () -> fixture.gate().invoke("port_probe_inv", params("ports", "443-80"), approved()));
    }

    /** 越界单端口 {@code 65536}（P0-1 修复后：L-A {@code PORT_UNPARSEABLE} 拒绝）。 */
    @Test
    @DisplayName("B-49c 越界端口 65536 → L-A PORT_UNPARSEABLE 拒绝（fail-open 已闭合）")
    void outOfRangeSinglePortIsRejected() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe_big")), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_UNPARSEABLE",
          () -> fixture.gate().invoke("port_probe_big", params("ports", "65536"), approved()));
    }

    /** 端口 0（P0-1 修复后：L-A {@code PORT_UNPARSEABLE} 拒绝）。 */
    @Test
    @DisplayName("B-49d 端口 0 → L-A PORT_UNPARSEABLE 拒绝（fail-open 已闭合）")
    void zeroPortIsRejected() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe_zero2")), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_UNPARSEABLE",
          () -> fixture.gate().invoke("port_probe_zero2", params("ports", "0"), approved()));
    }

    /** 非数字端口 {@code "abc"}（P0-1 修复后：L-A {@code PORT_UNPARSEABLE} 拒绝）。 */
    @Test
    @DisplayName("B-49e 非数字端口 abc → L-A PORT_UNPARSEABLE 拒绝（fail-open 已闭合）")
    void nonNumericPortIsRejected() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe_abc")), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_UNPARSEABLE",
          () -> fixture.gate().invoke("port_probe_abc", params("ports", "abc"), approved()));
    }

    /**
     * 注入式端口串 {@code "80;rm -rf"}（P0-1 修复后：L-A {@code PORT_UNPARSEABLE} 拒绝）。
     *
     * <p>修复前：分号切分后 {@code rm -rf} 非数字 → 静默丢弃，只剩 80 合法 → 放行。
     * 这是最危险的一种：攻击载荷 {@code "80,3306-"} 只保留 {@code {80}}，
     * <strong>越权端口被伪装隐藏</strong>。修复后任何一个无法解析的 token 都会导致整体拒绝。
     */
    @Test
    @DisplayName("B-49f 注入式端口串 80;rm -rf → L-A PORT_UNPARSEABLE 拒绝（fail-open 已闭合）")
    void injectionStylePortStringIsRejected() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe_inj")), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_UNPARSEABLE",
          () -> fixture.gate().invoke("port_probe_inj", params("ports", "80;rm -rf"), approved()));
    }

    /**
     * <strong>对照组（P0-1 修复不得误伤合法输入）</strong>：合法端口表达必须仍然放行。
     *
     * <p>P0-1 把"无法解析"改为 fail-closed 拒绝，风险是<strong>误伤</strong>：
     * 若实现把"空段"（如 {@code "80,,"} 的尾随逗号）也当作解析失败，合法输入就会被拒。
     * 因此本用例逐条验证任务描述中明确列为"行为不变"的四种写法。
     *
     * <p>与上面五条配对：上面证明越权/畸形输入被拒，本条证明合法输入不被误伤。
     * 两者同时成立才说明修复方向正确（而不是"把端口校验变成一律拒绝"）。
     */
    @Test
    @DisplayName("B-49g 对照组：合法端口表达（80,443 / 80-82 / 缺失 / 80,,）仍放行")
    void legitimatePortExpressionsAreStillAllowed() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe_ok")), TARGETS);

      // "80,443" → {80,443}，全部在授权范围 {80,443} 内。
      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("port_probe_ok", params("ports", "80,443"), approved()),
          "合法端口列表 80,443 必须放行");

      // "80-82" → {80,81,82}，其中 81/82 越权 → 必须被 PORT_OUT_OF_SCOPE 拒绝（这是子集语义，不是解析失败）。
      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_OUT_OF_SCOPE",
          () -> fixture.gate().invoke("port_probe_ok", params("ports", "80-82"), approved()));

      // 缺失端口 → 空集 → 合法（回落授权端口），不得因"没有端口"而拒绝。
      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("port_probe_ok", Map.of(), approved()),
          "缺失端口必须放行（空集合法，回落授权端口）");

      // "80,," → 尾随空段被忽略 → {80}，合法 → 必须放行（空段不是"无法解析"）。
      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("port_probe_ok", params("ports", "80,,"), approved()),
          "尾随逗号产生的空段必须被忽略，不得判为无法解析");
    }

    /**
     * <strong>键名变体</strong>：{@code portRange} / {@code port_range} / {@code PORT} 是否都被识别。
     *
     * <p>绕过设想：若护栏只识别 {@code ports}，攻击者用 {@code portRange} 传越权端口即可绕过端口校验。
     * 护栏的 {@code requestedPorts}（{@code :632-645}）声称识别四种写法且大小写不敏感——本用例逐条验证。
     */
    @Test
    @DisplayName("B-50d 端口键名变体（port/portRange/port_range/PORTS）都必须被识别")
    void allPortKeyVariantsAreRecognized() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe_keys")), TARGETS);

      for (String key : new String[] {"port", "ports", "portRange", "port_range", "PORTS", "PORT"}) {
        assertDeniedAt(
            CapabilityDeniedException.Layer.AUTHORIZATION,
            "PORT_OUT_OF_SCOPE",
            () ->
                fixture
                    .gate()
                    .invoke("port_probe_keys", params(key, "22"), approved()));
      }
    }

    /**
     * <strong>键名逃逸</strong>：把端口放在护栏不认识的键名里（如 {@code targetPorts}）。
     *
     * <p>护栏的键名白名单是 {@code {port, ports, portrange, port_range}}（去掉下划线后比较）。
     * {@code targetPorts} 去掉下划线是 {@code targetports}，不在集合内 → <strong>不被识别</strong>。
     *
     * <p>本用例断言该载荷<strong>放行</strong>，把覆盖边界固化为事实。这是"端口校验依赖键名约定"的固有局限：
     * 只要下游工具读取的键名与护栏识别的不一致，护栏就看不到端口。
     */
    @Test
    @DisplayName("B-50e 键名逃逸：targetPorts 不被护栏识别 → 端口校验看不到")
    void unrecognizedPortKeyEscapesPortValidation() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(portCapability("port_probe_escape")), TARGETS);

      GuardSupport.assertAllowed(
          () ->
              fixture
                  .gate()
                  .invoke("port_probe_escape", params("targetPorts", "22"), approved()));
    }
  }

  // ==================================================================
  // 大整数与类型混淆
  // ==================================================================

  @Nested
  @DisplayName("类型混淆（B-11/B-12）")
  class TypeConfusion {

    /** 端口用 JSON 数字（Integer）而非字符串 → 必须同样被识别。 */
    @Test
    @DisplayName("B-11a 端口为数字类型（22）→ 必须被识别并拒绝")
    void numericPortIsRecognized() {
      AgentCapability capability =
          GuardSupport.DeclaredStub.of(
              "port_num",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of("1"),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(capability), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_OUT_OF_SCOPE",
          () -> fixture.gate().invoke("port_num", params("ports", 22), approved()));
    }

    /** 端口用集合 → 必须同样被识别。 */
    @Test
    @DisplayName("B-11b 端口为集合 [80, 22] → 必须被识别并拒绝")
    void collectionPortIsRecognized() {
      AgentCapability capability =
          GuardSupport.DeclaredStub.of(
              "port_coll",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of("1"),
              TargetBindingProbe.Declaration.REQUIRED);
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(capability), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_OUT_OF_SCOPE",
          () -> fixture.gate().invoke("port_coll", params("ports", List.of(80, 22)), approved()));
    }

    /** 目标 ID 绑定用带空格的数字字符串 {@code " 1 "} → {@code trim()} 后应能解析。 */
    @Test
    @DisplayName("B-12a 绑定 \" 1 \"（带空格）→ trim 后可解析，应放行")
    void paddedTargetIdIsTrimmed() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("padded", Set.of(" 1 "))), TARGETS);

      GuardSupport.assertAllowed(() -> fixture.gate().invoke("padded", Map.of(), approved()));
    }

    /** 目标 ID 用前导零 {@code "01"} → {@code Long.parseLong} 解析为 1，应放行（等价写法）。 */
    @Test
    @DisplayName("B-12b 绑定 \"01\"（前导零）→ 解析为 1，应放行")
    void leadingZeroTargetIdIsParsed() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("leading_zero", Set.of("01"))), TARGETS);

      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("leading_zero", Map.of(), approved()));
    }

    /**
     * 目标 ID 用全角数字 {@code "１"} → <strong>放行</strong>（实测）。
     *
     * <p><strong>我最初期望"必须拒绝"，实测后发现该期望是错的</strong>，原因已用独立 Java 程序确认：
     * {@code Long.parseLong("１")} <strong>返回 1</strong>——Java 的 {@code parseLong} 通过
     * {@code Character.digit()} 接受<strong>所有 Unicode 数字</strong>（含全角、阿拉伯-印度数字）。
     *
     * <p>因此 {@code "１"} 被规范化为目标 1，而目标 1 <strong>确实在授权范围内</strong> → 放行是
     * <strong>正确行为</strong>，不是漏洞。本用例改为断言放行，并记录这一"看起来像绕过、实则等价"的情形。
     *
     * <p>⚠️ <strong>但这里有一个值得注意的规范化问题</strong>：绑定值被 {@code Long.parseLong} 规范化后以
     * {@code Long.toString(targetId)} 存入审计（{@code :412}），因此审计里记录的是 {@code "1"} 而非原始的
     * {@code "１"}。若安全团队事后按原始绑定值排查，可能无法复现攻击者的实际输入。<strong>这是审计保真度
     * 问题，不是授权绕过。</strong>
     */
    @Test
    @DisplayName("B-12c 绑定全角数字 \"１\" → parseLong 接受 Unicode 数字，解析为 1 → 放行（正确行为）")
    void fullWidthDigitTargetIdResolvesToOneAndIsAllowed() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("fullwidth", Set.of("１"))), TARGETS);

      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("fullwidth", Map.of(), approved()),
          "全角 １ 被 Long.parseLong 解析为 1（授权范围内），放行是正确的");
    }

    /**
     * <strong>同类但真正需要关注的情形</strong>：用全角数字绑定一个<u>未授权</u>的目标。
     *
     * <p>{@code "２"} → 解析为 2 → 目标 2 存在但端口/授权范围不同 → 必须拒绝。
     *
     * <p>这条用来证明：Unicode 数字被规范化<strong>不会</strong>造成绕过——因为规范化之后仍要经过完整的
     * 目标授权校验。即"规范化"与"授权判定"是分离的，前者不削弱后者。
     */
    @Test
    @DisplayName("B-12c' 绑定全角 \"２\"（解析为未授权目标 2）→ 必须拒绝")
    void fullWidthDigitForUnauthorizedTargetIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("fullwidth2", Set.of("２"))), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_NOT_FOUND",
          () -> fixture.gate().invoke("fullwidth2", Map.of(), approved()));
    }

    /**
     * <strong>Lead 指定的实测：全角 targetId + 显式声明 NONE 的能力</strong>。
     *
     * <p>Lead 的推理链是：{@code addId}（{@code CapabilityGate:529-541}）里
     * {@code Long.parseLong("１")} 抛异常 → 被 catch 静默丢弃 → {@code targetBindings} 返回空集 →
     * 若能力<strong>显式声明 NONE</strong>，空集合法 → <strong>放行</strong> → 构成漏洞。
     *
     * <p><strong>实测结果：Lead 的前提不成立，但结论值得记录。</strong>
     *
     * <p>我用独立 Java 程序验证了前提：
     *
     * <pre>
     * Long.parseLong("\uFF11")  // 全角 1 → 返回 1（不抛异常！）
     * Long.parseLong("\u0661")  // 阿拉伯-印度 1 → 返回 1
     * Long.parseLong("0x1")     // → NumberFormatException
     * </pre>
     *
     * <p>Java 的 {@code Long.parseLong} 通过 {@code Character.digit()} 接受<strong>所有 Unicode 数字</strong>，
     * 因此全角 {@code "１"} <strong>不会</strong>被 {@code addId} 丢弃，而是被规范化为 {@code "1"}。
     *
     * <p>但 Lead 指出的<strong>真实缺陷仍然成立</strong>，只是触发条件不同：
     *
     * <ol>
     *   <li><strong>真正会被 {@code addId} 丢弃的</strong>是 {@code "0x1"}、{@code "1.0"}、{@code "1e3"}、
     *       {@code "abc"} 这类 {@code parseLong} 确实抛异常的写法（见下一条用例）。
     *   <li><strong>注释与实现不符</strong>（Lead 指出的缺陷，已确认）：
     *       {@code :539} 的注释说"非数字目标 ID 由 L-A 的 INVALID_TARGET_BINDING 分支处理"，
     *       但 {@code addId} <strong>已经把非法值丢掉了</strong>，L-A 永远看不到它。
     *       实际结果是 {@code MISSING_TARGET_BINDING}（若未声明 NONE）或<strong>放行</strong>（若声明了 NONE）——
     *       <strong>永远不可能是 {@code INVALID_TARGET_BINDING}</strong>。注释误导后续维护者。
     * </ol>
     *
     * <p>本用例断言：全角 {@code "１"} 的能力桩返回真实绑定 {@code "1"}（规范化后的值），
     * <strong>而非空集</strong>——这直接证伪了"全角数字导致空集"的前提。
     */
    @Test
    @DisplayName("B-12c'' 【Lead 指定】全角 targetId 不会导致空集：parseLong 接受 Unicode 数字")
    void fullWidthTargetIdIsNormalizedNotDropped() {
      AgentCapability capability =
          GuardSupport.DeclaredStub.of(
              "fullwidth_probe",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of("１"),
              TargetBindingProbe.Declaration.REQUIRED);

      // 关键：目标 1 是授权目标 → 若全角被规范化成 "1" 则放行；若被丢弃成空集则会 MISSING_TARGET_BINDING。
      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(capability), TARGETS);

      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("fullwidth_probe", Map.of(), approved()),
          "全角 １ 被 parseLong 规范化为 1（授权目标）→ 放行。若此处被 MISSING_TARGET_BINDING 拒绝，"
              + "说明 Java 行为与我的实测不符，请复核");
    }

    /**
     * <strong>真正会被 {@code addId} 静默丢弃的写法</strong>（Lead 缺陷的真实触发条件）。
     *
     * <p>{@code "0x1"}、{@code "1.0"}、{@code "1e3"}、{@code "abc"} 都会让 {@code Long.parseLong}
     * 抛 {@code NumberFormatException} → 被 {@code addId:538} 的 catch 吞掉 → {@code targetBindings} 返回<strong>空集</strong>。
     *
     * <p>此时按 L-A（{@code :372-381}）：
     *
     * <ul>
     *   <li>能力<strong>未</strong>声明 NONE → {@code MISSING_TARGET_BINDING} 拒绝（fail-closed，安全但拒因不精确）
     *   <li>能力<strong>声明了</strong> NONE → 空集合法 → <strong>放行</strong>（fail-open，真漏洞）
     * </ul>
     *
     * <p>本用例验证<strong>后者</strong>：一个声明 NONE 的能力，若其 {@code targetBindings} 因解析失败返回空集，
     * 护栏会放行。<strong>这是"能力自己的解析 bug 被护栏当成合法声明"的真实风险。</strong>
     */
    @Test
    @DisplayName("B-12e 【真漏洞形态】声明 NONE 的能力 + 不可解析的 targetId → 空集被当成合法声明 → 放行")
    void declaredNoneCapabilityWithUnparsableIdFailsOpen() {
      // 模拟"能力声明了 NONE，但实际想绑定一个非法目标 ID"的情形。
      // DeclaredStub 的 targetBindings 直接返回构造时给定的集合，这里给空集以复现 addId 丢弃后的效果。
      AgentCapability capability =
          GuardSupport.DeclaredStub.of(
              "none_but_unparsable",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of(),
              TargetBindingProbe.Declaration.NONE);

      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(capability), TARGETS);

      GuardSupport.assertAllowed(
          () -> fixture.gate().invoke("none_but_unparsable", params("targetId", "0x1"), approved()),
          "【风险】显式 NONE + 空集 → 跳过 L-A。若该能力实际会执行，即为 fail-open");
    }

    /**
     * <strong>对照</strong>：同样不可解析的 targetId，但能力<strong>未</strong>声明 NONE →
     * 必须被 {@code MISSING_TARGET_BINDING} 拒绝。
     *
     * <p>与上一条配对，证明护栏的兜底（S-04）确实生效：<strong>只有"显式声明 NONE"才让空集合法</strong>。
     */
    @Test
    @DisplayName("B-12f 对照：不可解析 targetId + 未声明 NONE → MISSING_TARGET_BINDING 拒绝")
    void undeclaredCapabilityWithUnparsableIdIsDenied() {
      AgentCapability capability =
          GuardSupport.DeclaredStub.of(
              "undeclared_unparsable",
              CapabilityKind.EXECUTE,
              RiskLevel.SENSITIVE,
              Set.of(),
              TargetBindingProbe.Declaration.REQUIRED);

      GuardSupport.Fixture fixture = GuardSupport.fixture(List.of(capability), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "MISSING_TARGET_BINDING",
          () ->
              fixture
                  .gate()
                  .invoke("undeclared_unparsable", params("targetId", "0x1"), approved()));
    }

    /**
     * 目标 ID 用十六进制 {@code "0x1"} → {@code Long.parseLong} 抛 {@code NumberFormatException}
     * （已用独立程序确认）→ 必须拒绝 {@code INVALID_TARGET_BINDING}。
     */
    @Test
    @DisplayName("B-12d 绑定十六进制 \"0x1\" → parseLong 失败 → 拒绝")
    void hexTargetIdIsDenied() {
      GuardSupport.Fixture fixture =
          GuardSupport.fixture(List.of(declaredWithBindings("hex", Set.of("0x1"))), TARGETS);

      assertDeniedAt(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "INVALID_TARGET_BINDING",
          () -> fixture.gate().invoke("hex", Map.of(), approved()));
    }
  }
}
