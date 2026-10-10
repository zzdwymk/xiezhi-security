package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.tool.zap.ZapDaemon;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** One literal field mutation only; no file, dictionary, script or command expansion. */
final class ZapFuzzAiParameters {
  private ZapFuzzAiParameters() {}

  static final Set<String> KEYS =
      Set.of("fuzzRequestUrl", "method", "fuzzPostBody", "fuzzPayload", "fuzzTargetField");

  static Map<String, Object> normalize(Map<String, Object> input, boolean defaults) {
    Map<String, Object> result = new LinkedHashMap<>(input);
    if (!KEYS.containsAll(result.keySet())) throw new ApiException("AI ZAP 参数包含未允许的选项");
    String url = text(result, "fuzzRequestUrl", 1, 2000, true);
    URI uri;
    try {
      uri = URI.create(url);
      if (uri.getScheme() == null || !Set.of("http", "https").contains(uri.getScheme().toLowerCase(java.util.Locale.ROOT)) || uri.getHost() == null
          || uri.getRawUserInfo() != null || uri.getRawFragment() != null
          || uri.getPort() == 0 || uri.getPort() > 65535) throw new IllegalArgumentException();
    } catch (RuntimeException invalid) {
      throw new ApiException("AI ZAP fuzzRequestUrl 必须是无凭据和片段的授权 HTTP(S) URL");
    }
    String field = text(result, "fuzzTargetField", 1, 128, true);
    if (field.isBlank()) throw new ApiException("AI ZAP fuzzTargetField 不能为空白");
    text(result, "fuzzPayload", 1, 1000, true);
    String body = text(result, "fuzzPostBody", 0, 4000, false);
    String method = text(result, "method", 1, 4, false);
    if (method == null) method = "POST";
    if (!Set.of("GET", "POST").contains(method)) throw new ApiException("AI ZAP method 仅支持 GET 或 POST");
    if ("GET".equals(method) && body != null && !body.isEmpty()) {
      throw new ApiException("AI ZAP GET 请求不能携带 fuzzPostBody");
    }
    new ZapDaemon.FuzzSpec(uri, url, method, body, (String) result.get("fuzzPayload"), field)
        .requestMessage();
    if (defaults) result.putIfAbsent("method", "POST");
    return result;
  }

  private static String text(Map<String, Object> values, String key, int min, int max, boolean required) {
    if (!values.containsKey(key) && !required) return null;
    Object value = values.get(key);
    if (!(value instanceof String text) || text.length() < min || text.length() > max
        || text.codePoints().anyMatch(Character::isISOControl)) {
      throw new ApiException("AI ZAP " + key + " 格式或长度无效");
    }
    return text;
  }
}
