package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Round 274：Fuzz 请求必须在反序列化层面限定 payload 规模，不能只依赖服务层裁剪。 */
class TrafficFuzzRequestValidationTests {
  private final jakarta.validation.Validator validator =
      Validation.buildDefaultValidatorFactory().getValidator();

  @Test
  void rejectsTooManyPayloads() {
    var violations =
        validator.validate(
            new TrafficFuzzService.FuzzRequest(
                null, null, "http://192.168.222.158/§name§", null, null, null,
                java.util.Collections.nCopies(201, "x"), null, null));
    assertThat(violations)
        .anyMatch(value -> value.getPropertyPath().toString().startsWith("payloads"));
  }

  @Test
  void rejectsOverlongSinglePayload() {
    var violations =
        validator.validate(
            new TrafficFuzzService.FuzzRequest(
                null, null, "http://192.168.222.158/§name§", null, null, null,
                List.of("p".repeat(4097)), null, null));
    assertThat(violations)
        .anyMatch(value -> value.getPropertyPath().toString().startsWith("payloads"));
  }

  @Test
  void rejectsOversizedMultiPayloadGroups() {
    Map<String, List<String>> groups = new HashMap<>();
    for (int i = 0; i < 33; i++) {
      groups.put("v" + i, List.of("x"));
    }
    var violations =
        validator.validate(
            new TrafficFuzzService.FuzzRequest(
                null, null, "http://192.168.222.158/§v0§", null, null, groups, null, null,
                "PITCHFORK"));
    assertThat(violations)
        .anyMatch(value -> value.getPropertyPath().toString().startsWith("multiPayloads"));
  }

  @Test
  void rejectsTooManyPayloadsInsideOneGroup() {
    Map<String, List<String>> groups =
        Map.of("name", java.util.Collections.nCopies(201, "x"));
    var violations =
        validator.validate(
            new TrafficFuzzService.FuzzRequest(
                null, null, "http://192.168.222.158/§name§", null, null, groups, null, null,
                "SNIPER"));
    assertThat(violations)
        .anyMatch(value -> value.getPropertyPath().toString().startsWith("multiPayloads"));
  }

  @Test
  void rejectsOverlongUrlAndBody() {
    var violations =
        validator.validate(
            new TrafficFuzzService.FuzzRequest(
                null, null, "u".repeat(4097), "h".repeat(64 * 1024 + 1),
                "b".repeat(1024 * 1024 + 1), null, List.of("x"), null, null));
    assertThat(violations)
        .anyMatch(value -> value.getPropertyPath().toString().equals("url"))
        .anyMatch(value -> value.getPropertyPath().toString().equals("headers"))
        .anyMatch(value -> value.getPropertyPath().toString().equals("body"));
  }

  @Test
  void acceptsPayloadAtDesignLimits() {
    assertThat(
            validator.validate(
                new TrafficFuzzService.FuzzRequest(
                    null, "GET", "http://192.168.222.158/§name§", null, null, null,
                    java.util.Collections.nCopies(200, "x".repeat(4096)), null, null)))
        .isEmpty();
  }
}
