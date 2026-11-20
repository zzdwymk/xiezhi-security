package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Round 264：侦察请求不能携带超大字典列表绕过服务层 limit 的内存边界。 */
class ReconRequestValidationTests {
  private final jakarta.validation.Validator validator =
      Validation.buildDefaultValidatorFactory().getValidator();

  @Test
  void rejectsOversizedWordLists() {
    var violations =
        validator.validate(
            new ReconRequest(
                1L, true, true, true, new ArrayList<>(java.util.Collections.nCopies(2001, "a")),
                true, new ArrayList<>(java.util.Collections.nCopies(10001, "p")),
                false, false, false, "PASSIVE", false, null, 4, false));
    assertThat(violations)
        .anyMatch(value -> value.getPropertyPath().toString().equals("subdomainWords"))
        .anyMatch(value -> value.getPropertyPath().toString().equals("pathWords"));
  }
}
