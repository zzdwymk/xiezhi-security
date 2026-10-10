package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Detection-only parameter boundary shared by model decoding and task dispatch. */
final class SqlmapAiParameters {
  private SqlmapAiParameters() {}

  static Map<String, Object> normalize(Map<String, Object> input, boolean defaults) {
    Map<String, Object> result = new LinkedHashMap<>(input);
    if (!Set.of("path", "level", "risk", "technique").containsAll(result.keySet())) {
      throw new ApiException("AI SQLMap 仅允许 path、level、risk、technique 检测参数");
    }
    if (result.containsKey("path")) {
      Object value = result.get("path");
      if (!(value instanceof String path) || path.isBlank() || !path.equals(path.trim())
          || path.length() > 2000 || path.codePoints().anyMatch(Character::isISOControl)) {
        throw new ApiException("AI SQLMap path 格式无效");
      }
      try {
        URI uri = URI.create(path);
        if (path.startsWith("//") || uri.getRawUserInfo() != null || uri.getRawFragment() != null
            || (uri.isAbsolute() && !Set.of("http", "https").contains(uri.getScheme().toLowerCase(java.util.Locale.ROOT)))) {
          throw new IllegalArgumentException();
        }
      } catch (IllegalArgumentException invalid) {
        throw new ApiException("AI SQLMap path 必须是授权 HTTP 路径，不能包含凭据或片段");
      }
    }
    integer(result, "level", 1, 5);
    integer(result, "risk", 1, 1);
    if (result.containsKey("technique")) {
      Object value = result.get("technique");
      if (!(value instanceof String technique) || !technique.matches("[BEUT]{1,4}")
          || technique.chars().distinct().count() != technique.length()) {
        throw new ApiException("AI SQLMap technique 仅允许不重复的 B、E、U、T 检测技术");
      }
    }
    if (defaults) {
      result.putIfAbsent("level", 1);
      result.putIfAbsent("risk", 1);
      result.putIfAbsent("technique", "BEUT");
    }
    return result;
  }

  private static void integer(Map<String, Object> values, String key, int min, int max) {
    if (!values.containsKey(key)) return;
    Object value = values.get(key);
    if (!(value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long)
        || ((Number) value).longValue() < min || ((Number) value).longValue() > max) {
      throw new ApiException("AI SQLMap " + key + " 必须为 " + min + " 到 " + max + " 的整数");
    }
    values.put(key, ((Number) value).intValue());
  }
}
