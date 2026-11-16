package com.bachelor.toolbox.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class UserSerializationTests {
  @Test
  void userEntitySerializationNeverIncludesPasswordHashOrPasswordAlias() throws Exception {
    User user = new User();
    user.setId(1L); user.setUsername("qa-member"); user.setRole("USER");
    user.setPasswordHash("QA_ONLY_PASSWORD_HASH_MARKER");
    var mapper = new ObjectMapper().findAndRegisterModules();
    var json = mapper.readTree(mapper.writeValueAsString(user));
    assertThat(json.has("passwordHash")).isFalse();
    assertThat(json.has("password")).isFalse();
    assertThat(json.toString()).doesNotContain("QA_ONLY_PASSWORD_HASH_MARKER");
    assertThat(json.path("username").asText()).isEqualTo("qa-member");
    assertThat(user.getPassword()).isEqualTo("QA_ONLY_PASSWORD_HASH_MARKER");
  }
}
