package com.bachelor.toolbox.project;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import org.junit.jupiter.api.Test;

/** Round 246：项目更新请求的 owner 不能超过实体列宽 100。 */
class ProjectDtoValidationTests {
  @Test
  void rejectsOverlongOwnerOnUpdate() {
    var validator = Validation.buildDefaultValidatorFactory().getValidator();
    var violations =
        validator.validate(
            new ProjectDtos.Update(null, null, null, null, null, "o".repeat(101)));
    assertThat(violations).anyMatch(value -> value.getPropertyPath().toString().equals("owner"));
  }

  @Test
  void acceptsOwnerAtColumnLimit() {
    var validator = Validation.buildDefaultValidatorFactory().getValidator();
    var violations =
        validator.validate(
            new ProjectDtos.Update(null, null, null, null, null, "o".repeat(100)));
    assertThat(violations).isEmpty();
  }
}
