package com.bachelor.toolbox.tool;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * HTTP 响应头脱敏（第377轮）。
 *
 * <p>{@code http_headers} 曾把响应头**原样**写进任务结果，于是 {@code Set-Cookie} 里的会话值被
 * 持久化到 {@code security_tasks.result_json}，并经任务详情接口与界面"原始输出"回传——
 * 而姊妹工具 {@code http_security_check} 早已对 {@code Set-Cookie} 脱敏。两处实现不一致造成泄露。
 *
 * <p>本类作为单一实现：保留头名与结构（安全检查仍需判断"是否存在某头"），只把**值**替换为
 * {@code <redacted>}；同时覆盖常见凭据类响应头。
 */
public final class HeaderRedaction {

  public static final String REDACTED = "<redacted>";

  /** 值必须整体脱敏的响应头（凭据/令牌类）。 */
  private static final List<String> FULLY_REDACTED_HEADERS =
      List.of("authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate",
          "x-api-key", "x-auth-token", "api-key", "cookie", "set-cookie2");

  private HeaderRedaction() {}

  /** 返回脱敏后的头映射（保持原有顺序与头名）。 */
  public static Map<String, List<String>> sanitize(Map<String, List<String>> headers) {
    Map<String, List<String>> sanitized = new LinkedHashMap<>();
    if (headers == null) return sanitized;
    headers.forEach(
        (name, values) -> {
          if (name == null) return;
          String lower = name.toLowerCase(Locale.ROOT);
          if (FULLY_REDACTED_HEADERS.contains(lower)) {
            sanitized.put(name, values == null ? List.of() : values.stream().map(v -> REDACTED).toList());
          } else if ("set-cookie".equals(lower)) {
            sanitized.put(
                name,
                values == null ? List.of() : values.stream().map(HeaderRedaction::redactCookie).toList());
          } else {
            sanitized.put(name, values);
          }
        });
    return sanitized;
  }

  /**
   * 只脱敏 {@code name=value} 中的值，保留 Cookie 名与其余属性（Secure/HttpOnly/SameSite 等），
   * 这样安全分析结论（"缺少 Secure" 之类）仍可复核。
   */
  public static String redactCookie(String rawCookie) {
    if (rawCookie == null) return REDACTED;
    int equals = rawCookie.indexOf('=');
    if (equals < 0) return REDACTED;
    int semicolon = rawCookie.indexOf(';', equals + 1);
    if (semicolon < 0) return rawCookie.substring(0, equals + 1) + REDACTED;
    return rawCookie.substring(0, equals + 1) + REDACTED + rawCookie.substring(semicolon);
  }
}
