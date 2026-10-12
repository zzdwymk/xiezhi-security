package com.bachelor.toolbox.ai.guard;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * L-C 参数校验：逐字段 JSON Schema 校验（设计文档 §6.1、§9.5"路径含 ../ 的端点调用"）。
 *
 * <p>只实现护栏真正需要的子集：{@code type} / {@code required} / {@code additionalProperties} / {@code enum} /
 * {@code minimum} / {@code maximum} / {@code minLength} / {@code maxLength} / {@code pattern} / {@code items} /
 * {@code properties}。刻意不引入 JSON Schema 库——护栏是安全边界，依赖越少、行为越可预测越好，而且本项目的 schema 由我们自己
 * 生成，不需要完整规范。
 *
 * <p><strong>fail-closed</strong>：schema 里出现无法识别的约束关键字时<strong>不</strong>视为通过，而是记一条违规（"无法校验即拒绝"）。
 * 唯一例外是纯注释类关键字（{@code description}/{@code title} 等），它们不承载约束语义。
 */
public final class SchemaValidator {

  /** 无约束语义的注释类关键字，出现时忽略。 */
  private static final Set<String> ANNOTATION_KEYWORDS =
      Set.of("description", "title", "$schema", "$id", "examples", "default", "x-order", "deprecated");

  private static final Set<String> KNOWN_KEYWORDS =
      Set.of(
          "type",
          "required",
          "additionalProperties",
          "enum",
          "minimum",
          "maximum",
          "exclusiveMinimum",
          "exclusiveMaximum",
          "minLength",
          "maxLength",
          "minItems",
          "maxItems",
          "pattern",
          "items",
          "properties",
          "const");

  private SchemaValidator() {}

  /**
   * 校验参数。
   *
   * @param schema 能力的 {@code parameterSchema()}；空 Map 表示"不接受任何参数"
   * @param params 实际参数；允许为 {@code null}
   * @return 违规描述列表；空列表表示通过
   */
  public static List<String> validate(Map<String, Object> schema, Map<String, Object> params) {
    List<String> violations = new ArrayList<>();
    if (schema == null || schema.isEmpty()) {
      // 约定：空 schema = 不接受任何参数。传了参数即视为违规（否则参数会成为绕过校验的暗通道）。
      if (params != null && !params.isEmpty()) {
        violations.add("该能力不接受任何参数，但收到: " + params.keySet());
      }
      return violations;
    }
    validateNode(schema, params, "", violations);
    return violations;
  }

  @SuppressWarnings("unchecked")
  private static void validateNode(
      Map<String, Object> schema, Object value, String path, List<String> violations) {
    if (schema == null) {
      return;
    }
    for (String keyword : schema.keySet()) {
      if (!KNOWN_KEYWORDS.contains(keyword) && !ANNOTATION_KEYWORDS.contains(keyword)) {
        violations.add(at(path) + "schema 使用了无法校验的约束关键字: " + keyword + "（fail-closed）");
      }
    }

    String type = schema.get("type") instanceof String text ? text : null;
    if (type != null && !matchesType(type, value)) {
      violations.add(at(path) + "类型应为 " + type + "，实际为 " + describe(value));
      return;
    }

    if (schema.containsKey("const") && !java.util.Objects.equals(schema.get("const"), value)) {
      violations.add(at(path) + "取值必须为 " + schema.get("const"));
    }

    Object enumValues = schema.get("enum");
    if (enumValues instanceof Collection<?> allowed && !allowed.contains(value)) {
      violations.add(at(path) + "取值 " + value + " 不在允许集合 " + allowed + " 内");
    }

    if (value instanceof String text) {
      validateString(schema, text, path, violations);
    }
    if (value instanceof Number number) {
      validateNumber(schema, number, path, violations);
    }
    if (value instanceof Collection<?> items) {
      validateCollection(schema, items, path, violations);
    }
    if (value instanceof Map<?, ?> map) {
      validateObject(schema, (Map<String, Object>) map, path, violations);
    }
  }

  private static void validateString(
      Map<String, Object> schema, String value, String path, List<String> violations) {
    Object minLength = schema.get("minLength");
    if (minLength instanceof Number bound && value.length() < bound.intValue()) {
      violations.add(at(path) + "长度不得小于 " + bound.intValue());
    }
    Object maxLength = schema.get("maxLength");
    if (maxLength instanceof Number bound && value.length() > bound.intValue()) {
      violations.add(at(path) + "长度不得超过 " + bound.intValue());
    }
    Object pattern = schema.get("pattern");
    if (pattern instanceof String regex && !regex.isEmpty()) {
      try {
        if (!java.util.regex.Pattern.compile(regex).matcher(value).find()) {
          violations.add(at(path) + "不匹配约束 " + regex);
        }
      } catch (java.util.regex.PatternSyntaxException exception) {
        violations.add(at(path) + "schema 正则无法编译: " + regex + "（fail-closed）");
      }
    }
  }

  private static void validateNumber(
      Map<String, Object> schema, Number value, String path, List<String> violations) {
    double actual = value.doubleValue();
    Object minimum = schema.get("minimum");
    if (minimum instanceof Number bound && actual < bound.doubleValue()) {
      violations.add(at(path) + "不得小于 " + bound);
    }
    Object maximum = schema.get("maximum");
    if (maximum instanceof Number bound && actual > bound.doubleValue()) {
      violations.add(at(path) + "不得大于 " + bound);
    }
    Object exclusiveMinimum = schema.get("exclusiveMinimum");
    if (exclusiveMinimum instanceof Number bound && actual <= bound.doubleValue()) {
      violations.add(at(path) + "必须大于 " + bound);
    }
    Object exclusiveMaximum = schema.get("exclusiveMaximum");
    if (exclusiveMaximum instanceof Number bound && actual >= bound.doubleValue()) {
      violations.add(at(path) + "必须小于 " + bound);
    }
  }

  private static void validateCollection(
      Map<String, Object> schema, Collection<?> items, String path, List<String> violations) {
    Object minItems = schema.get("minItems");
    if (minItems instanceof Number bound && items.size() < bound.intValue()) {
      violations.add(at(path) + "元素个数不得少于 " + bound.intValue());
    }
    Object maxItems = schema.get("maxItems");
    if (maxItems instanceof Number bound && items.size() > bound.intValue()) {
      violations.add(at(path) + "元素个数不得超过 " + bound.intValue());
    }
    Object itemSchema = schema.get("items");
    if (itemSchema instanceof Map<?, ?> nested) {
      int index = 0;
      for (Object item : items) {
        validateNode(castSchema(nested), item, path + "[" + index + "]", violations);
        index++;
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static void validateObject(
      Map<String, Object> schema, Map<String, Object> value, String path, List<String> violations) {
    Object required = schema.get("required");
    if (required instanceof Collection<?> names) {
      for (Object name : names) {
        String key = String.valueOf(name);
        if (!value.containsKey(key)) {
          violations.add(at(path) + "缺少必填参数 " + key);
        }
      }
    }
    Object properties = schema.get("properties");
    Map<String, Object> declared = properties instanceof Map<?, ?> map ? castSchema(map) : Map.of();
    for (Map.Entry<String, Object> entry : value.entrySet()) {
      Object propertySchema = declared.get(entry.getKey());
      if (propertySchema instanceof Map<?, ?> nested) {
        validateNode(castSchema(nested), entry.getValue(), path + "." + entry.getKey(), violations);
        continue;
      }
      // 未声明的参数：除非显式允许 additionalProperties，否则拒绝（防止参数成为绕过校验的暗通道）。
      boolean additionalAllowed = Boolean.TRUE.equals(schema.get("additionalProperties"));
      if (!additionalAllowed) {
        violations.add(at(path) + "包含未声明参数 " + entry.getKey());
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> castSchema(Map<?, ?> map) {
    return (Map<String, Object>) map;
  }

  private static boolean matchesType(String type, Object value) {
    return switch (type) {
      case "object" -> value instanceof Map;
      case "array" -> value instanceof Collection || value instanceof Object[];
      case "string" -> value instanceof String;
      case "integer" -> value instanceof Byte
          || value instanceof Short
          || value instanceof Integer
          || value instanceof Long
          || value instanceof java.math.BigInteger
          || (value instanceof Number number && number.doubleValue() == Math.rint(number.doubleValue()));
      case "number" -> value instanceof Number;
      case "boolean" -> value instanceof Boolean;
      case "null" -> value == null;
      default -> false; // 未知类型名 → 不通过（fail-closed）
    };
  }

  private static String describe(Object value) {
    return value == null ? "null" : value.getClass().getSimpleName();
  }

  private static String at(String path) {
    return path == null || path.isEmpty() ? "$" : "$" + path;
  }
}
