package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Round 248：任务创建/批量请求的 toolCode 必须匹配 SecurityTask 列宽 50。 */
class TaskDtoValidationTests {
  private final jakarta.validation.Validator validator =
      Validation.buildDefaultValidatorFactory().getValidator();

  @Test
  void rejectsOverlongToolCodeForSingleTask() {
    var violations =
        validator.validate(new CreateTaskRequest(1L, 2L, "t".repeat(51), Map.of()));
    assertThat(violations).anyMatch(value -> value.getPropertyPath().toString().equals("toolCode"));
  }

  @Test
  void rejectsOverlongToolCodeForBatchTask() {
    var violations =
        validator.validate(
            new ProjectBatchTaskRequest(1L, "t".repeat(51), Map.of(), List.of()));
    assertThat(violations).anyMatch(value -> value.getPropertyPath().toString().equals("toolCode"));
  }

  @Test
  void acceptsToolCodeAtColumnLimit() {
    assertThat(validator.validate(new CreateTaskRequest(1L, 2L, "t".repeat(50), Map.of())))
        .isEmpty();
  }
}
