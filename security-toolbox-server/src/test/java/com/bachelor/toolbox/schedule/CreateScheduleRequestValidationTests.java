package com.bachelor.toolbox.schedule;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Round 247：创建计划的 toolCode/cronExpression 必须匹配实体列宽。 */
class CreateScheduleRequestValidationTests {
  private final jakarta.validation.Validator validator =
      Validation.buildDefaultValidatorFactory().getValidator();

  @Test
  void rejectsOverlongToolCodeAndCron() {
    var violations =
        validator.validate(
            new CreateScheduleRequest(
                1L, 2L, "t".repeat(51), Map.of(), "c".repeat(121), 60L, true));
    assertThat(violations)
        .anyMatch(value -> value.getPropertyPath().toString().equals("toolCode"))
        .anyMatch(value -> value.getPropertyPath().toString().equals("cronExpression"));
  }

  @Test
  void acceptsValuesAtColumnLimits() {
    var violations =
        validator.validate(
            new CreateScheduleRequest(
                1L, 2L, "t".repeat(50), Map.of(), "c".repeat(120), 60L, true));
    assertThat(violations).isEmpty();
  }
}
