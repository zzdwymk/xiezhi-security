package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 拒绝用户/模型自带的框架内部信道键——Round 28（SSRF / 授权范围绕过防护）。
 *
 * <p>{@code __resolvedWebBases} 是服务端派发前注入的"预解析 Web 基址"。若用户在请求体里自带该键，
 * {@code validateAtExecutionEntry} 会把它当"框架键"跳过校验并原样落库，随后被工具读走对任意 URL（如内网）
 * 发起请求。此处锁定边界拒绝行为。
 */
@DisplayName("框架内部信道键拒绝（Round 28）")
class FrameworkKeyRejectionTests {

  @Test
  @DisplayName("FK-1 用户自带 __resolvedWebBases → 拒绝")
  void rejectsResolvedWebBases() {
    assertThatThrownBy(() ->
        ToolParameterPolicy.rejectUserSuppliedFrameworkKeys(
            Map.of("__resolvedWebBases", java.util.List.of("http://169.254.169.254/"),
                "ports", "80")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("保留键");
  }

  @Test
  @DisplayName("FK-2 用户自带任意 __ 前缀键 → 拒绝")
  void rejectsAnyDoubleUnderscoreKey() {
    assertThatThrownBy(() ->
        ToolParameterPolicy.rejectUserSuppliedFrameworkKeys(Map.of("__secret", "x")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("保留键");
  }

  @Test
  @DisplayName("FK-3 普通用户参数 → 放行（不误伤）")
  void allowsNormalParameters() {
    assertThatCode(() ->
        ToolParameterPolicy.rejectUserSuppliedFrameworkKeys(
            Map.of("ports", "80,443", "check", "tls")))
        .doesNotThrowAnyException();
    assertThatCode(() -> ToolParameterPolicy.rejectUserSuppliedFrameworkKeys(null))
        .doesNotThrowAnyException();
  }
}
