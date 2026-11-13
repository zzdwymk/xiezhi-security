package com.bachelor.toolbox.ai.guard;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.tool.ToolParameterPolicy;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 参数规格漂移检测——Round 9。
 *
 * <p>护栏侧 L-C'（{@code EndpointParameterPolicy}）与能力侧（{@code ToolParameterPolicy}）
 * 的工具/参数白名单必须与权威工具清单 {@code AiToolCatalog.EXECUTABLE_TOOLS} 及 dispatch 层
 * 保持一致。此前 {@code EndpointParameterPolicy.ALLOWED_TOOL_PARAMETERS} 漏了
 * {@code tcp_ports.udp}、{@code nmap_service_scan.consumeOpenPorts}、整个 {@code dir_scan}/{@code zap_fuzz} 条目，
 * 造成"护栏比执行侧更严"的漂移。本类把这份漂移变成可执行断言。
 */
@DisplayName("工具参数白名单漂移检测（Round 9）")
class ToolParameterPolicyDriftTests {

  @SuppressWarnings("unchecked")
  private static Map<String, Set<String>> endpointAllowed() throws Exception {
    Field f = EndpointParameterPolicy.class.getDeclaredField("ALLOWED_TOOL_PARAMETERS");
    f.setAccessible(true);
    return (Map<String, Set<String>>) f.get(null);
  }

  @Test
  @DisplayName("D-DRIFT-1 能力层工具清单非空且包含关键工具")
  void capabilityToolListSane() {
    assertThat(ToolParameterPolicy.EXECUTABLE_TOOLS)
        .contains("tcp_ports", "nmap_service_scan", "dir_scan", "zap_fuzz", "sqlmap_scan");
  }

  @Test
  @DisplayName("D-DRIFT-2 护栏侧白名单覆盖所有可执行工具（不得漏条目）")
  void endpointPolicyCoversAllExecutableTools() throws Exception {
    Map<String, Set<String>> allowed = endpointAllowed();
    for (String tool : ToolParameterPolicy.EXECUTABLE_TOOLS) {
      assertThat(allowed)
          .as("护栏 L-C' 白名单缺少工具 " + tool + "（会导致 invoke_endpoint 误拒合法请求）")
          .containsKey(tool);
    }
  }

  @Test
  @DisplayName("D-DRIFT-3 两套白名单的同名工具键完全一致")
  void endpointPolicyKeysMatchCapabilityPolicy() throws Exception {
    Map<String, Set<String>> endpoint = endpointAllowed();
    for (String tool : ToolParameterPolicy.EXECUTABLE_TOOLS) {
      Set<String> capabilityKeys = ToolParameterPolicy.allowedKeys(tool);
      Set<String> endpointKeys = endpoint.get(tool);
      assertThat(endpointKeys)
          .as("工具 " + tool + " 的护栏白名单键与能力层不一致（漂移）")
          .isEqualTo(capabilityKeys);
    }
  }

  @Test
  @DisplayName("D-DRIFT-4 专项：此前遗漏的键已补齐（udp / consumeOpenPorts / dir_scan / zap_fuzz）")
  void previouslyMissingKeysArePresent() throws Exception {
    Map<String, Set<String>> allowed = endpointAllowed();
    assertThat(allowed.get("tcp_ports")).contains("udp");
    assertThat(allowed.get("nmap_service_scan")).contains("consumeOpenPorts");
    assertThat(allowed).containsKey("dir_scan");
    assertThat(allowed.get("dir_scan"))
        .containsExactlyInAnyOrder("dictionary", "concurrency", "depth", "maxRequests", "extensions");
    assertThat(allowed).containsKey("zap_fuzz");
    assertThat(allowed.get("zap_fuzz"))
        .containsExactlyInAnyOrder(
            "fuzzRequestUrl", "method", "fuzzPostBody", "fuzzPayload", "fuzzTargetField");
  }
}
