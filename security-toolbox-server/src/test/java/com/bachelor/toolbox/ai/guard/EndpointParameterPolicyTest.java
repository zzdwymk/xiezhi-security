package com.bachelor.toolbox.ai.guard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * 端点透传参数策略测试（设计文档 §6.5 反向能力映射；X-7 漏洞的回归用例）。
 *
 * <p>X-7 的攻击形态：目标在授权范围内时，{@code invoke_endpoint("POST","/api/tasks", {toolCode:"msf_scan",
 * parameters:{...}})} 可以绕过 {@code AiTaskDispatchService} 上的全部四道参数护栏，直达执行器。本测试逐条覆盖这四道护栏。
 */
class EndpointParameterPolicyTest {

  private static final int MAX_PORTS = 65535;

  private static EndpointParameterPolicy policy() {
    return new EndpointParameterPolicy(new PortRangeParser(), MAX_PORTS);
  }

  /** 授权目标：仅允许 8080。 */
  private static AuthorizedTarget target(String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(1L);
    target.setName("t");
    target.setTargetValue("http://127.0.0.1:8080");
    target.setTargetType("URL");
    target.setAuthorizationNote("n");
    target.setAllowedPorts(allowedPorts);
    target.setEnabled(true);
    return target;
  }

  private static Map<String, Object> taskBody(String toolCode, Map<String, Object> parameters) {
    return Map.of("projectId", 1, "targetId", 1, "toolCode", toolCode, "parameters", parameters);
  }

  // ================================================ X-7 四条护栏

  /** 护栏①：工具参数白名单——未允许的字段被拒（来源：AiTaskDispatchService:238-253）。 */
  @Test
  void rejectsToolParameterOutsideWhitelist() {
    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                policy()
                    .validateTaskCreationBody(
                        target("8080"),
                        taskBody("http_headers", Map.of("extraFlag", "--dangerous"))));

    assertTrue(error.getMessage().contains("未允许"), error.getMessage());
  }

  /** 护栏①：工具本身不在安全白名单内 → 拒绝。 */
  @Test
  void rejectsToolOutsideSafetyWhitelist() {
    ApiException error =
        assertThrows(
            ApiException.class,
            () -> policy().validateTaskCreationBody(target("8080"), taskBody("rm_rf", Map.of())));

    assertTrue(error.getMessage().contains("安全白名单"), error.getMessage());
  }

  /** 护栏②：端口必须全部落在授权端口范围内——部分越权同样被拒（来源：AiTaskDispatchService:288-297）。 */
  @Test
  void rejectsPortsOutsideAuthorizedRange() {
    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                policy()
                    .validateTaskCreationBody(
                        target("8080"), taskBody("tcp_ports", Map.of("ports", "8080,22,3306"))));

    assertTrue(error.getMessage().contains("超出目标授权范围"), error.getMessage());
  }

  /** 护栏②：合法端口子集 → 放行（测误拦率）。 */
  @Test
  void allowsPortSubsetInsideAuthorizedRange() {
    policy().validateTaskCreationBody(target("80,443,8080"), taskBody("tcp_ports", Map.of("ports", "80,8080")));
  }

  /** 护栏②：端口区间展开后逐个比对（containsAll 语义，而非只看区间端点）。 */
  @Test
  void rejectsPortRangePartiallyOutsideAuthorization() {
    // 授权只有 8080-8090，请求 8085-8095：区间端点 8085 在范围内、8095 不在 → 必须拒绝。
    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                policy()
                    .validateTaskCreationBody(
                        target("8080-8090"), taskBody("nmap_service_scan", Map.of("ports", "8085-8095"))));

    assertTrue(error.getMessage().contains("超出目标授权范围"), error.getMessage());
  }

  /** 护栏③：MSF 模块前缀必须是 auxiliary/ 或 exploit/（来源：AiTaskDispatchService:351,359）。 */
  @Test
  void rejectsMsfModuleWithoutRequiredPrefix() {
    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                policy()
                    .validateTaskCreationBody(
                        target("8080"),
                        taskBody("msf_scan", Map.of("module", "post/multi/gather/env"))));

    assertTrue(error.getMessage().contains("auxiliary/ 或 exploit/"), error.getMessage());
  }

  /** 护栏③：合法 MSF 模块 → 放行。 */
  @Test
  void allowsLegitimateMsfModule() {
    policy()
        .validateTaskCreationBody(
            target("8080"), taskBody("msf_scan", Map.of("module", "auxiliary/scanner/portscan/tcp")));
    policy()
        .validateTaskCreationBody(
            target("8080"), taskBody("msf_scan", Map.of("modules", List.of("exploit/multi/handler"))));
  }

  /** 护栏③：module 与 modules 互斥（来源：AiTaskDispatchService:341-342）。 */
  @Test
  void rejectsMsfModuleAndModulesTogether() {
    assertThrows(
        ApiException.class,
        () ->
            policy()
                .validateTaskCreationBody(
                    target("8080"),
                    taskBody(
                        "msf_scan",
                        Map.of(
                            "module", "auxiliary/a",
                            "modules", List.of("auxiliary/b")))));
  }

  /** 护栏④：PoC 编号格式与数量 1..50（来源：AiTaskDispatchService:370-395）。 */
  @Test
  void rejectsInvalidPocCode() {
    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                policy()
                    .validateTaskCreationBody(
                        target("8080"), taskBody("nuclei_scan", Map.of("pocCodes", List.of("not-a-poc")))));

    assertTrue(error.getMessage().contains("PoC"), error.getMessage());
  }

  /** 护栏④：PoC 数量上限 50。 */
  @Test
  void rejectsTooManyPocCodes() {
    List<String> tooMany =
        java.util.stream.IntStream.range(0, 51)
            .mapToObj(index -> String.format("AA-%024X", index))
            .toList();

    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                policy()
                    .validateTaskCreationBody(
                        target("8080"), taskBody("nuclei_scan", Map.of("pocCodes", tooMany))));

    assertTrue(error.getMessage().contains("1 到 50"), error.getMessage());
  }

  /** 护栏④：合法 PoC 列表 → 放行。 */
  @Test
  void allowsValidPocCodes() {
    policy()
        .validateTaskCreationBody(
            target("8080"),
            taskBody("nuclei_scan", Map.of("pocCodes", List.of("AA-000000000000000000000001"))));
    policy().validateTaskCreationBody(target("8080"), taskBody("nuclei_scan", Map.of("allPocs", true)));
  }

  /** 护栏④：pocCodes 与 allPocs 互斥，且必须二选一（来源：AiTaskDispatchService:373）。 */
  @Test
  void rejectsAmbiguousPocSelection() {
    assertThrows(
        ApiException.class,
        () -> policy().validateTaskCreationBody(target("8080"), taskBody("nuclei_scan", Map.of())));
    assertThrows(
        ApiException.class,
        () ->
            policy()
                .validateTaskCreationBody(
                    target("8080"),
                    taskBody(
                        "nuclei_scan",
                        Map.of("allPocs", true, "pocCodes", List.of("AA-000000000000000000000001")))));
  }

  // ================================================ 端点识别

  /** 只有 POST /api/tasks 被识别为参数透传端点。 */
  @Test
  void identifiesTaskCreationEndpointOnly() {
    assertTrue(EndpointParameterPolicy.isTaskCreationEndpoint("POST", "/api/tasks"));
    assertTrue(EndpointParameterPolicy.isTaskCreationEndpoint("post", "/api/tasks"));
    assertFalse(EndpointParameterPolicy.isTaskCreationEndpoint("GET", "/api/tasks"));
    assertFalse(EndpointParameterPolicy.isTaskCreationEndpoint("POST", "/api/tasks/1/stop"));
    assertFalse(EndpointParameterPolicy.isTaskCreationEndpoint("POST", "/api/targets"));
    assertFalse(EndpointParameterPolicy.isTaskCreationEndpoint(null, "/api/tasks"));
  }

  // ================================================ 防漂移（Lead 要求）

  /**
   * 防漂移回归：把 X-7 的完整攻击载荷作为参数化用例表，逐条断言策略拒绝。
   *
   * <p>这份表刻意与 {@code AiTaskDispatchService.validateAndNormalize} 的四道护栏一一对应（每条注明来源行号）。若将来
   * dispatch 层新增护栏而本类未同步，本表不会自动失败——因此额外提供 {@link #guardRulesMirrorDispatchSourceLines()} 把
   * "覆盖了哪几条规则、来源在哪"固化成断言，改动时强制复核。
   */
  @Test
  void x7AttackPayloadsAreAllRejected() {
    List<Map<String, Object>> attacks =
        List.of(
            // 护栏① 工具参数白名单
            taskBody("http_headers", Map.of("unknownFlag", "x")),
            // 护栏② 端口越权
            taskBody("tcp_ports", Map.of("ports", "22")),
            // 护栏③ MSF 模块前缀
            taskBody("msf_scan", Map.of("module", "post/exploit")),
            // 护栏④ PoC 编号
            taskBody("nuclei_scan", Map.of("pocCodes", List.of("../../etc/passwd"))));

    for (Map<String, Object> attack : attacks) {
      assertThrows(
          ApiException.class,
          () -> policy().validateTaskCreationBody(target("8080"), attack),
          "X-7 载荷必须被拒绝: " + attack);
    }
  }

  /** 把"覆盖了 dispatch 层哪几条规则"固化为断言，避免静默漂移。 */
  @Test
  void guardRulesMirrorDispatchSourceLines() {
    // 本类覆盖的四条规则及其在 AiTaskDispatchService 中的来源（改动任一侧都应复核这里）。
    Set<String> coveredRules =
        Set.of(
            "allowedKeys:AiTaskDispatchService:238-253",
            "portSubset:AiTaskDispatchService:288-297",
            "msfModulePrefix:AiTaskDispatchService:351,359",
            "pocCodes:AiTaskDispatchService:370-395");

    assertEquals(4, coveredRules.size(), "护栏规则数应为 4，若 dispatch 层新增规则请同步本类");
    assertTrue(coveredRules.stream().allMatch(rule -> rule.contains("AiTaskDispatchService")));
  }

  /** 未指定端口时不构成越权（执行层会回落到授权端口）。 */
  @Test
  void missingPortsIsNotAnEscalation() {
    policy().validateTaskCreationBody(target("8080"), taskBody("tcp_ports", Map.of()));
  }

  /** 缺少 toolCode → 拒绝（fail-closed）。 */
  @Test
  void rejectsMissingToolCode() {
    ApiException error =
        assertThrows(
            ApiException.class,
            () -> policy().validateTaskCreationBody(target("8080"), Map.of("projectId", 1)));

    assertTrue(error.getMessage().contains("toolCode"), error.getMessage());
  }
}
