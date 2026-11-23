package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第383轮：{@code bash_probe} 不得经任务执行入口可达。
 *
 * <p>{@code bash_probe} 是 AI 能力层通道（{@code requiresApproval=true}，默认关闭、逐次人工确认），
 * 其固有局限是"外部工具的网络出口不受授权边界约束"。若它能被当作普通任务工具提交
 * （{@code POST /api/tasks}），就绕过了能力层的审批与黑名单，因此唯一执行入口必须拒绝它。
 *
 * <p>本测试锁定：能力层的命令执行通道不会出现在可执行工具白名单里。
 */
@DisplayName("bash_probe 不得作为任务工具执行（第383轮）")
class BashProbeNotATaskToolTests {

  @Test
  @DisplayName("可执行工具白名单不含 bash_probe（能力通道不被当作任务工具）")
  void bashProbeIsNotAnExecutableTaskTool() {
    assertThat(ToolParameterPolicy.EXECUTABLE_TOOLS)
        .as("bash_probe 只能走能力层审批通道")
        .doesNotContain("bash_probe");
    assertThat(ToolParameterPolicy.isKnownTool("bash_probe")).isFalse();
  }

  @Test
  @DisplayName("严格校验入口拒绝 bash_probe")
  void bashProbeIsRejectedByStrictValidation() {
    // validateAtExecutionEntry 对"策略未覆盖的工具"是刻意 fail-open 的（交由注册表存在性校验），
    // 因此这里断言严格入口 validate 的拒绝语义；执行入口的实际拦截由注册表 + 下方端到端验证保证。
    assertThatThrownBy(() -> ToolParameterPolicy.validate(
        "bash_probe", java.util.Map.of("command", "id")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("未知或未授权的安全工具");
  }

  @Test
  @DisplayName("近似名称也不会被误当作可执行工具（防拼写绕过）")
  void similarlyNamedCodesAreNotExecutable() {
    for (String code : java.util.List.of("BASH_PROBE", "bash-probe", "bashprobe", "bash_probe ")) {
      assertThat(ToolParameterPolicy.isKnownTool(code))
          .as("变体 %s 不应被识别为已知工具", code)
          .isFalse();
    }
  }
}
