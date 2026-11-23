package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.tool.ToolParameterPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第385轮：AI 派发侧的工具参数白名单必须与唯一事实来源一致。
 *
 * <p>第371/372 轮修好了三处白名单（能力层 / 护栏 / 检测规则侧），但 {@code AiTaskDispatchService}
 * 里还藏着**第四份** switch 副本，且未同步：AI 计划里的 {@code msf_scan.msfOptions}、
 * {@code sqlmap_scan.data}、{@code dir_scan.timeoutSeconds}、{@code zap_scan} 的
 * {@code mode/scanPolicy/ajaxSpider/openApiUrl/auth*} 都会被判为「AI 计划包含未允许的工具参数」，
 * 即同一批功能在 AI 通道上仍然不可用。
 *
 * <p>本测试锁定：AI 侧允许键集合等于 {@link ToolParameterPolicy#allowedKeys(String)}。
 */
@DisplayName("AI 派发参数白名单与唯一事实来源一致（第385轮）")
class AiDispatchParameterWhitelistParityTests {

  @Test
  @DisplayName("每个可执行工具的 AI 允许键必须等于能力层白名单")
  void aiAllowedKeysMatchSingleSourceOfTruth() {
    for (String toolCode : ToolParameterPolicy.EXECUTABLE_TOOLS) {
      assertThat(AiTaskDispatchService.allowedAiParameterKeys(toolCode))
          .as("工具 %s 的 AI 参数键与能力层白名单不一致（漂移）", toolCode)
          .isEqualTo(ToolParameterPolicy.allowedKeys(toolCode));
    }
  }

  @Test
  @DisplayName("此前缺失的键在 AI 侧必须可用（msfOptions/data/timeoutSeconds/zap 全部选项）")
  void previouslyMissingKeysAreAllowedForAiPlans() {
    assertThat(AiTaskDispatchService.allowedAiParameterKeys("msf_scan")).contains("msfOptions");
    assertThat(AiTaskDispatchService.allowedAiParameterKeys("sqlmap_scan")).contains("data");
    assertThat(AiTaskDispatchService.allowedAiParameterKeys("dir_scan")).contains("timeoutSeconds");
    assertThat(AiTaskDispatchService.allowedAiParameterKeys("zap_scan"))
        .contains("mode", "scanPolicy", "ajaxSpider", "openApiUrl", "authLoginUrl",
            "authUsername", "authPassword", "authUsernameField", "authPasswordField", "authType");
  }

  @Test
  @DisplayName("未知工具在 AI 侧不产生任何允许键（fail-closed）")
  void unknownToolHasNoAllowedKeys() {
    assertThat(AiTaskDispatchService.allowedAiParameterKeys("bash_probe")).isEmpty();
    assertThat(AiTaskDispatchService.allowedAiParameterKeys(null)).isEmpty();
  }
}
