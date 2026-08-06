package com.bachelor.toolbox.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ProcessEnvironmentSanitizerTests {
  @Test
  void removesApplicationSecretsAndKeepsRequiredToolEnvironment() {
    ProcessBuilder builder = new ProcessBuilder("tool", "--version");
    Map<String, String> environment = builder.environment();
    environment.put("PATH", "safe-tool-path");
    environment.put("TOOLBOX_TOOLS_DIR", "safe-tools-directory");
    environment.put("ADMIN_PASSWORD", "must-not-leak");
    environment.put("JWT_SECRET", "must-not-leak");
    environment.put("TRAFFIC_MITM_CA_PASSWORD", "must-not-leak");
    environment.put("AI_API_KEY", "must-not-leak");
    environment.put("AI_RUNTIME_TOKEN", "must-not-leak");
    environment.put("AI_RUNTIME_SIGNING_SECRET", "must-not-leak");
    environment.put("OPENAI_API_KEY", "must-not-leak");

    ProcessEnvironmentSanitizer.sanitize(builder);

    assertThat(environment)
        .containsEntry("PATH", "safe-tool-path")
        .containsEntry("TOOLBOX_TOOLS_DIR", "safe-tools-directory")
        .doesNotContainKeys(
            "ADMIN_PASSWORD",
            "JWT_SECRET",
            "TRAFFIC_MITM_CA_PASSWORD",
            "AI_API_KEY",
            "AI_RUNTIME_TOKEN",
            "AI_RUNTIME_SIGNING_SECRET",
            "OPENAI_API_KEY");
  }

  @Test
  void matchesSensitiveNamesWithoutDependingOnEnvironmentCase() {
    assertThat(ProcessEnvironmentSanitizer.isSensitive("jwt_secret")).isTrue();
    assertThat(ProcessEnvironmentSanitizer.isSensitive("Ai_Runtime_Api_Key")).isTrue();
    assertThat(ProcessEnvironmentSanitizer.isSensitive("PATH")).isFalse();
  }
}
