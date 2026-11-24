package com.bachelor.toolbox.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;

/**
 * 第390轮：CORS 默认允许来源的回归守卫。
 *
 * <p>本类曾用 {@code allowedOriginPatterns("*")}：任何网页都能读取本地 API 的响应
 * （本地服务上典型的 CORS 过宽配置）。修复后的默认值限定为桌面 {@code file://}/{@code null}
 * 与本机开发服务器。
 *
 * <p>本测试直接读取 {@code @Value} 注解里的**默认值**做断言：任何人把默认改回通配符，
 * 全量回归立即失败——避免"配置默认值被悄悄放宽"这类无代码 diff 的退化。
 */
@DisplayName("CORS 默认来源守卫（第390轮）")
class WebConfigCorsDefaultsTests {

  private List<String> defaultPatterns() throws Exception {
    Field field = WebConfig.class.getDeclaredField("allowedOriginPatterns");
    Value value = field.getAnnotation(Value.class);
    assertThat(value).as("allowedOriginPatterns 必须通过 @Value 提供默认值").isNotNull();
    String expression = value.value();
    // 形如 ${toolbox.cors.allowed-origin-patterns:http://localhost:*,...}
    int separator = expression.indexOf(':');
    assertThat(separator)
        .as("表达式应带默认值（冒号分隔）: %s", expression)
        .isGreaterThan(0);
    String defaults = expression.substring(separator + 1, expression.length() - 1);
    return Arrays.stream(defaults.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
  }

  @Test
  @DisplayName("默认来源不得包含任意来源通配符")
  void defaultsNeverAllowAnyOrigin() throws Exception {
    List<String> patterns = defaultPatterns();
    assertThat(patterns)
        .as("默认允许来源绝不能包含 * 或 http://* 这类通配")
        .doesNotContain("*", "http://*", "https://*", "http://*:*", "https://*:*");
    assertThat(patterns)
        .as("每个模式都必须限定到本机/桌面来源")
        .allSatisfy(
            pattern ->
                assertThat(pattern)
                    .as("可疑来源模式: %s", pattern)
                    .containsAnyOf("http://localhost", "http://127.0.0.1", "file://", "null"));
  }

  @Test
  @DisplayName("桌面(file:// 或 null)与本机开发来源仍然被允许（功能不回退）")
  void desktopAndLocalDevOriginsRemainAllowed() throws Exception {
    List<String> patterns = defaultPatterns();
    assertThat(patterns).anySatisfy(pattern -> assertThat(pattern).startsWith("http://localhost"));
    assertThat(patterns).anySatisfy(pattern -> assertThat(pattern).startsWith("http://127.0.0.1"));
    assertThat(patterns)
        .as("Electron 渲染进程的 file:// 与 sandbox 的 null 来源必须可用")
        .contains("file://", "null");
  }
}
