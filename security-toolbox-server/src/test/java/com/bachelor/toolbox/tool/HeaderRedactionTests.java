package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第377轮：响应头脱敏必须覆盖会话与凭据类头，同时保留可分析结构。
 *
 * <p>修复前 {@code http_headers} 原样保存响应头，{@code Set-Cookie} 的会话值被持久化进任务结果。
 * 本测试锁定脱敏契约：值被替换、头名与属性保留。
 */
@DisplayName("响应头脱敏（第377轮）")
class HeaderRedactionTests {

  private static Map<String, List<String>> headers() {
    Map<String, List<String>> map = new LinkedHashMap<>();
    map.put("Set-Cookie", List.of(
        "session=SUPERSECRETVALUE; Path=/; HttpOnly",
        "tomcat=abc123; Path=/"));
    map.put("Authorization", List.of("Bearer SUPERSECRETVALUE"));
    map.put("X-Powered-By", List.of("Express"));
    map.put("Content-Type", List.of("text/html"));
    return map;
  }

  @Test
  @DisplayName("Set-Cookie 只脱敏值，保留 Cookie 名与安全属性")
  void cookieValueIsRedactedButAttributesRemain() {
    Map<String, List<String>> sanitized = HeaderRedaction.sanitize(headers());
    List<String> cookies = sanitized.get("Set-Cookie");
    assertThat(cookies).hasSize(2);
    assertThat(cookies.get(0)).isEqualTo("session=<redacted>; Path=/; HttpOnly");
    assertThat(cookies.get(1)).isEqualTo("tomcat=<redacted>; Path=/");
    assertThat(cookies).noneMatch(v -> v.contains("SUPERSECRETVALUE"));
  }

  @Test
  @DisplayName("凭据类响应头整体脱敏，普通头保持不变")
  void credentialHeadersAreFullyRedacted() {
    Map<String, List<String>> sanitized = HeaderRedaction.sanitize(headers());
    assertThat(sanitized.get("Authorization")).containsExactly(HeaderRedaction.REDACTED);
    assertThat(sanitized.get("X-Powered-By")).containsExactly("Express");
    assertThat(sanitized.get("Content-Type")).containsExactly("text/html");
    assertThat(sanitized.toString()).doesNotContain("SUPERSECRETVALUE");
  }

  @Test
  @DisplayName("头名与顺序保留（安全检查仍需判断是否存在某头）")
  void headerNamesAndOrderArePreserved() {
    Map<String, List<String>> sanitized = HeaderRedaction.sanitize(headers());
    assertThat(sanitized.keySet())
        .containsExactly("Set-Cookie", "Authorization", "X-Powered-By", "Content-Type");
  }

  @Test
  @DisplayName("异常输入不抛异常：无 '=' 的 Cookie、空映射")
  void degenerateInputsAreHandled() {
    assertThat(HeaderRedaction.redactCookie("novalue")).isEqualTo(HeaderRedaction.REDACTED);
    assertThat(HeaderRedaction.redactCookie(null)).isEqualTo(HeaderRedaction.REDACTED);
    assertThat(HeaderRedaction.sanitize(null)).isEmpty();
    Map<String, List<String>> empty = new LinkedHashMap<>();
    empty.put("Set-Cookie", List.of());
    assertThat(HeaderRedaction.sanitize(empty).get("Set-Cookie")).isEmpty();
  }
}
