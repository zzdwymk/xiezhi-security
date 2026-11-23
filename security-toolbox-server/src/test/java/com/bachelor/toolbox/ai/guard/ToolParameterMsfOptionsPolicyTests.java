package com.bachelor.toolbox.ai.guard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.tool.ToolParameterPolicy;
import com.bachelor.toolbox.vulnerability.ActiveScanService;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第371轮：msf_scan 的 {@code msfOptions}（按模块下发选项）被参数白名单整体拒绝。
 *
 * <p>{@code MsfScanTool.sanitizedPerModuleOptions} 与 {@code ToolParameterPolicy.validateMsfOptionMaps}
 * 都实现了 {@code msfOptions} 的处理与注入防护（Round 15），但三处白名单
 * （能力层 {@code ALLOWED_KEYS}、护栏 {@code EndpointParameterPolicy}、检测规则侧
 * {@code ruleParameterKeys}）都没有该键，因此：
 *
 * <ol>
 *   <li>用户在唯一执行入口提交 {@code msfOptions} 直接被拒「不接受参数」——已实现的功能不可用；
 *   <li>Round 15 的嵌套注入防护成为<strong>不可达代码</strong>，RHOSTS 越界、分号注入等校验实际从未生效。
 * </ol>
 *
 * <p>修复应让白名单与实现一致，并保证嵌套防护真正可达（仍然拒绝越界与注入）。
 */
@DisplayName("msf_scan msfOptions 白名单一致性（第371轮）")
class ToolParameterMsfOptionsPolicyTests {

  private static Map<String, Object> perModule() {
    Map<String, Object> options = new LinkedHashMap<>();
    options.put("THREADS", "4");
    Map<String, Object> byModule = new LinkedHashMap<>();
    byModule.put("auxiliary/gather/http_version", options);
    Map<String, Object> parameters = new LinkedHashMap<>();
    parameters.put("module", "auxiliary/gather/http_version");
    parameters.put("msfOptions", byModule);
    return parameters;
  }

  @Test
  @DisplayName("能力层白名单必须允许 msfOptions（否则已实现的功能不可用）")
  void capabilityWhitelistAcceptsPerModuleOptions() {
    assertThat(ToolParameterPolicy.allowedKeys("msf_scan")).contains("msfOptions");
    ToolParameterPolicy.validate("msf_scan", perModule());
  }

  @Test
  @DisplayName("护栏白名单必须与能力层一致（否则 invoke_endpoint 误拒合法请求）")
  @SuppressWarnings("unchecked")
  void endpointWhitelistMatchesCapability() throws Exception {
    Field field = EndpointParameterPolicy.class.getDeclaredField("ALLOWED_TOOL_PARAMETERS");
    field.setAccessible(true);
    Map<String, Set<String>> allowed = (Map<String, Set<String>>) field.get(null);
    assertThat(allowed.get("msf_scan")).isEqualTo(ToolParameterPolicy.allowedKeys("msf_scan"));
  }

  @Test
  @DisplayName("检测规则侧白名单必须是能力层的超集（漂移断言）")
  void ruleWhitelistIsSupersetOfCapability() {
    Set<String> capability = new java.util.LinkedHashSet<>(ToolParameterPolicy.allowedKeys("msf_scan"));
    capability.removeAll(Set.of("allPocs", "pocCodes"));
    assertThat(ActiveScanService.ruleParameterKeys("msf_scan")).containsAll(capability);
    ToolParameterPolicy.assertAllowedKeysAreRuleSubset(ActiveScanService::ruleParameterKeys);
  }

  @Test
  @DisplayName("放开白名单后嵌套注入防护必须真正生效：不得覆盖 RHOSTS")
  void nestedHostOverrideIsRejected() {
    Map<String, Object> byModule = new LinkedHashMap<>();
    byModule.put("auxiliary/gather/http_version", Map.of("RHOSTS", "8.8.8.8"));
    Map<String, Object> parameters = new LinkedHashMap<>();
    parameters.put("module", "auxiliary/gather/http_version");
    parameters.put("msfOptions", byModule);
    assertThatThrownBy(() -> ToolParameterPolicy.validate("msf_scan", parameters))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不允许覆盖 MSF 选项");
  }

  @Test
  @DisplayName("放开白名单后嵌套注入防护必须真正生效：值不得含命令分隔符")
  void nestedCommandInjectionIsRejected() {
    Map<String, Object> byModule = new LinkedHashMap<>();
    byModule.put("auxiliary/gather/http_version", Map.of("THREADS", "4;setg RHOSTS 8.8.8.8"));
    Map<String, Object> parameters = new LinkedHashMap<>();
    parameters.put("module", "auxiliary/gather/http_version");
    parameters.put("msfOptions", byModule);
    assertThatThrownBy(() -> ToolParameterPolicy.validate("msf_scan", parameters))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("MSF 模块参数不合法");
  }
}
