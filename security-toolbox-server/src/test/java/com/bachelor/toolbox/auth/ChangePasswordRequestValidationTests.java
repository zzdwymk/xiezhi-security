package com.bachelor.toolbox.auth;

import static org.assertj.core.api.Assertions.assertThat;
import jakarta.validation.Validation;
import org.junit.jupiter.api.Test;

class ChangePasswordRequestValidationTests {
  @Test void rejectsOversizedCurrentPasswordBeforeAuthenticationWork() {
    try (var factory = Validation.buildDefaultValidatorFactory()) {
      assertThat(factory.getValidator().validate(new ChangePasswordRequest("x".repeat(129), "valid-new-password")))
          .isNotEmpty();
    }
  }

  @Test void bcryptEncodingRejectsTheUnsupportedByteLength() {
    org.assertj.core.api.Assertions.assertThatThrownBy(() ->
        new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode("中".repeat(25)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test void rejectsNewPasswordOverBcryptUtf8ByteLimit() {
    try (var factory = Validation.buildDefaultValidatorFactory()) {
      var validator = factory.getValidator();
      assertThat(validator.validate(new ChangePasswordRequest("current", "中".repeat(25))))
          .isNotEmpty();
      assertThat(validator.validate(new ChangePasswordRequest("current", "a".repeat(73))))
          .isNotEmpty();
    }
  }

  @Test void acceptsPasswordsAtTheSupportedByteBoundary() {
    try (var factory = Validation.buildDefaultValidatorFactory()) {
      var validator = factory.getValidator();
      assertThat(validator.validate(new ChangePasswordRequest("current", "中".repeat(24)))).isEmpty();
      assertThat(validator.validate(new ChangePasswordRequest("current", "a".repeat(72)))).isEmpty();
    }
  }
}
