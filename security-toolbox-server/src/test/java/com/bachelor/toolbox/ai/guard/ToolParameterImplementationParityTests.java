package com.bachelor.toolbox.ai.guard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.tool.ToolParameterPolicy;
import com.bachelor.toolbox.vulnerability.ActiveScanService;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第372轮：工具实现读取的参数键在三处白名单中缺失，导致已实现能力在唯一执行入口被整体拒绝。
 *
 * <p>逐工具核对 {@code parameters.get(...)} 后确认以下键被实现读取、但在能力层与护栏白名单
 * （以及部分规则白名单）中都不存在：
 *
 * <ul>
 *   <li>{@code zap_scan}：{@code openApiUrl}/{@code authLoginUrl}/{@code authUsername}/{@code authPassword}/
 *       {@code authUsernameField}/{@code authPasswordField}/{@code authType}/{@code scanPolicy}/
 *       {@code ajaxSpider}/{@code mode} —— 工具内部已做授权范围校验（{@code assertZapUrlWithinScope}）、
 *       枚举校验（mode/scanPolicy/strength）与类型校验（ajaxSpider）；
 *   <li>{@code sqlmap_scan}：{@code data}（POST 体）；
 *   <li>{@code dir_scan}：{@code timeoutSeconds}。
 * </ul>
 *
 * <p>后果：经任务接口提交这些参数被拒「不接受参数」，对应功能不可用；检测规则侧还声明 zap 支持它们，
 * 造成"规则能配、执行入口拒绝"的割裂。
 */
@DisplayName("工具实现参数与白名单一致性（第372轮）")
class ToolParameterImplementationParityTests {

  private static Map<String, Object> of(Object... pairs) {
    Map<String, Object> map = new LinkedHashMap<>();
    for (int i = 0; i < pairs.length; i += 2) map.put((String) pairs[i], pairs[i + 1]);
    return map;
  }

  @Test
  @DisplayName("zap_scan 的规则侧选项必须在唯一执行入口被接受（不再整体拒绝）")
  void zapScanRuleOptionsAreAcceptedAtExecutionEntry() {
    Map<String, Object> parameters = of(
        "spider", Boolean.TRUE,
        "strength", "LOW",
        "mode", "passive",
        "scanPolicy", "Default Policy",
        "ajaxSpider", Boolean.FALSE,
        "openApiUrl", "http://192.168.222.155/openapi.json",
        "authLoginUrl", "http://192.168.222.155/login",
        "authUsername", "tester",
        "authPassword", "secret-value",
        "authUsernameField", "user",
        "authPasswordField", "pass",
        "authType", "form");
    assertThatCode(() -> ToolParameterPolicy.validateAtExecutionEntry("zap_scan", parameters))
        .as("zap 规则选项必须在执行入口被接受")
        .doesNotThrowAnyException();
  }

  @Test
  @DisplayName("sqlmap_scan 的 data（POST 体）必须可用")
  void sqlmapDataParameterIsAccepted() {
    assertThatCode(() -> ToolParameterPolicy.validateAtExecutionEntry(
        "sqlmap_scan", of("path", "/item?id=1", "data", "id=1&name=x", "level", 2)))
        .doesNotThrowAnyException();
  }

  @Test
  @DisplayName("dir_scan 的 timeoutSeconds 必须可用")
  void dirScanTimeoutIsAccepted() {
    assertThatCode(() -> ToolParameterPolicy.validateAtExecutionEntry(
        "dir_scan", of("dictionary", "common", "timeoutSeconds", 30)))
        .doesNotThrowAnyException();
  }

  @Test
  @DisplayName("收紧仍然有效：未知键依旧被拒绝（白名单没有变成全开）")
  void unknownKeysAreStillRejected() {
    assertThatThrownBy(() -> ToolParameterPolicy.validateAtExecutionEntry(
        "zap_scan", of("definitelyNotAllowed", "x")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不接受参数");
    assertThatThrownBy(() -> ToolParameterPolicy.validateAtExecutionEntry(
        "sqlmap_scan", of("definitelyNotAllowed", "x")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不接受参数");
  }

  @Test
  @DisplayName("三处白名单继续一致：护栏=能力层，规则侧为超集")
  @SuppressWarnings("unchecked")
  void whitelistsStayConsistent() throws Exception {
    Field field = EndpointParameterPolicy.class.getDeclaredField("ALLOWED_TOOL_PARAMETERS");
    field.setAccessible(true);
    Map<String, Set<String>> endpoint = (Map<String, Set<String>>) field.get(null);
    for (String tool : ToolParameterPolicy.EXECUTABLE_TOOLS) {
      assertThat(endpoint.get(tool)).as("工具 " + tool + " 护栏白名单与能力层不一致").isEqualTo(
          ToolParameterPolicy.allowedKeys(tool));
    }
    ToolParameterPolicy.assertAllowedKeysAreRuleSubset(ActiveScanService::ruleParameterKeys);
    Set<String> capability = new LinkedHashSet<>(ToolParameterPolicy.allowedKeys("sqlmap_scan"));
    capability.removeAll(Set.of("allPocs", "pocCodes"));
    assertThat(ActiveScanService.ruleParameterKeys("sqlmap_scan"))
        .as("规则侧必须接受 sqlmap data")
        .containsAll(capability);
  }
}
